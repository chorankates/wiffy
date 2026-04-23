package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
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
	wsConns    map[*websocket.Conn]*wsClient
}

type wsClient struct {
	conn      *websocket.Conn
	writeMux  sync.Mutex
	writeChan chan interface{}
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
		wsConns: make(map[*websocket.Conn]*wsClient),
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
	api.HandleFunc("/suggest-range", s.handleSuggestRange).Methods("GET")
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
	ScanType    string `json:"scan_type"`    // "quick", "deep", or "mac"
	TargetRange string `json:"target_range"` // e.g., "192.168.1.0/24"; optional for "mac" (limits to CIDR; empty = all known IPs)
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.ScanType != "quick" && req.ScanType != "deep" && req.ScanType != "mac" {
		http.Error(w, "scan_type must be 'quick', 'deep', or 'mac'", http.StatusBadRequest)
		return
	}

	if req.ScanType != "mac" && req.TargetRange == "" {
		http.Error(w, "target_range is required", http.StatusBadRequest)
		return
	}

	displayRange := req.TargetRange
	if req.ScanType == "mac" && displayRange == "" {
		displayRange = "known hosts"
	}

	// Create scan record
	scanID, err := s.db.CreateScan(req.ScanType, displayRange)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Start scan in background (MAC scan uses raw target_range for optional CIDR filter)
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
	switch scanType {
	case "quick":
		err = s.scanner.QuickScan(targetRange, scanID, progressChan)
	case "deep":
		err = s.scanner.DeepScan(targetRange, scanID, progressChan)
	case "mac":
		err = s.scanner.MacScan(targetRange, scanID, progressChan)
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

func (s *Server) handleSuggestRange(w http.ResponseWriter, r *http.Request) {
	// Get client IP address
	clientIP := r.RemoteAddr
	
	// Handle X-Forwarded-For if behind proxy
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		clientIP = realIP
	}
	
	// Remove port if present
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}
	
	// Calculate /24 network
	suggestedRange := calculateNetwork24(clientIP)
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"client_ip":       clientIP,
		"suggested_range": suggestedRange,
	})
}

func calculateNetwork24(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		// Default for localhost or invalid IP
		return "192.168.1.0/24"
	}
	
	// Return first three octets with .0/24
	return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
}

// WebSocket handling

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("WebSocket upgrade error:", err)
		return
	}

	client := &wsClient{
		conn:      conn,
		writeChan: make(chan interface{}, 100),
	}

	s.wsConnsMux.Lock()
	s.wsConns[conn] = client
	s.wsConnsMux.Unlock()

	// Start write pump for this client
	go s.writePump(client)

	// Send welcome message
	client.writeChan <- map[string]string{
		"type":    "connected",
		"message": "Connected to Wiffy scanner",
	}

	// Keep connection alive and handle disconnect
	defer func() {
		s.wsConnsMux.Lock()
		delete(s.wsConns, conn)
		s.wsConnsMux.Unlock()
		close(client.writeChan)
		conn.Close()
	}()

	// Read messages (ping/pong for keepalive)
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}
}

func (s *Server) writePump(client *wsClient) {
	for msg := range client.writeChan {
		client.writeMux.Lock()
		err := client.conn.WriteJSON(msg)
		client.writeMux.Unlock()
		
		if err != nil {
			// Connection probably closed, stop writing
			return
		}
	}
}

func (s *Server) broadcastMessage(msg interface{}) {
	s.wsConnsMux.RLock()
	defer s.wsConnsMux.RUnlock()

	for _, client := range s.wsConns {
		select {
		case client.writeChan <- msg:
			// Message queued successfully
		default:
			// Channel full, skip this message for this client
		}
	}
}

