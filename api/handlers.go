package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	"github.com/conor/wiffy/database"
	"github.com/conor/wiffy/scanner"
)

type Server struct {
	db      *database.DB
	scanner *scanner.Scanner
	router  *mux.Router

	// WebSocket connections for scan progress
	wsConnsMux sync.RWMutex
	wsConns    map[*websocket.Conn]bool
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for development
	},
}

func NewServer(db *database.DB) *Server {
	s := &Server{
		db:      db,
		scanner: scanner.NewScanner(db),
		router:  mux.NewRouter(),
		wsConns: make(map[*websocket.Conn]bool),
	}

	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	// API routes
	api := s.router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/hosts", s.handleGetHosts).Methods("GET")
	api.HandleFunc("/hosts/{hostname}", s.handleGetHost).Methods("GET")
	api.HandleFunc("/scans", s.handleStartScan).Methods("POST")
	api.HandleFunc("/scans", s.handleGetScans).Methods("GET")
	api.HandleFunc("/stats", s.handleGetStats).Methods("GET")
	api.HandleFunc("/ws", s.handleWebSocket)

	// Serve static files and frontend
	s.router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

// API Handlers

func (s *Server) handleGetHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.db.GetAllHosts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}

func (s *Server) handleGetHost(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hostname := vars["hostname"]

	host, err := s.db.GetHost(hostname)
	if err != nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(host)
}

type ScanRequest struct {
	ScanType    string `json:"scan_type"`    // "quick" or "deep"
	TargetRange string `json:"target_range"` // e.g., "192.168.1.0/24"
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ScanType != "quick" && req.ScanType != "deep" {
		http.Error(w, "scan_type must be 'quick' or 'deep'", http.StatusBadRequest)
		return
	}

	if req.TargetRange == "" {
		http.Error(w, "target_range is required", http.StatusBadRequest)
		return
	}

	// Create scan record
	scanID, err := s.db.CreateScan(req.ScanType, req.TargetRange)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Start scan in background
	go s.runScan(scanID, req.ScanType, req.TargetRange)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id": scanID,
		"status":  "started",
	})
}

func (s *Server) runScan(scanID int64, scanType, targetRange string) {
	progressChan := make(chan string, 100)

	// Forward progress messages to WebSocket clients
	go func() {
		for msg := range progressChan {
			s.broadcastMessage(map[string]interface{}{
				"type":    "scan_progress",
				"scan_id": scanID,
				"message": msg,
			})
		}
	}()

	var err error
	if scanType == "quick" {
		err = s.scanner.QuickScan(targetRange, scanID, progressChan)
	} else {
		err = s.scanner.DeepScan(targetRange, scanID, progressChan)
	}

	close(progressChan)

	if err != nil {
		s.db.UpdateScan(scanID, "failed", 0, err.Error())
		s.broadcastMessage(map[string]interface{}{
			"type":    "scan_complete",
			"scan_id": scanID,
			"status":  "failed",
			"error":   err.Error(),
		})
	} else {
		s.broadcastMessage(map[string]interface{}{
			"type":    "scan_complete",
			"scan_id": scanID,
			"status":  "completed",
		})
	}
}

func (s *Server) handleGetScans(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 20
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil {
			limit = l
		}
	}

	scans, err := s.db.GetRecentScans(limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	stats, err := s.db.GetStats()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

// WebSocket handling

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("WebSocket upgrade error:", err)
		return
	}

	s.wsConnsMux.Lock()
	s.wsConns[conn] = true
	s.wsConnsMux.Unlock()

	// Send welcome message
	conn.WriteJSON(map[string]string{
		"type":    "connected",
		"message": "Connected to Wiffy scanner",
	})

	// Keep connection alive and handle disconnect
	defer func() {
		s.wsConnsMux.Lock()
		delete(s.wsConns, conn)
		s.wsConnsMux.Unlock()
		conn.Close()
	}()

	// Read messages (ping/pong for keepalive)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func (s *Server) broadcastMessage(msg interface{}) {
	s.wsConnsMux.RLock()
	defer s.wsConnsMux.RUnlock()

	for conn := range s.wsConns {
		if err := conn.WriteJSON(msg); err != nil {
			// Connection probably closed, will be cleaned up
			continue
		}
	}
}

