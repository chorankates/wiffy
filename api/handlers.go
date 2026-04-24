package api

import (
	"encoding/json"
	"fmt"
	"net"
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
	api.HandleFunc("/host-labels", s.handlePutHostLabel).Methods("PUT")
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

const maxHostLabelLen = 256

type hostLabelRequest struct {
	MACAddress string `json:"mac_address"`
	Label      string `json:"label"`
}

func (s *Server) handlePutHostLabel(w http.ResponseWriter, r *http.Request) {
	var req hostLabelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	mac := strings.TrimSpace(req.MACAddress)
	if _, err := net.ParseMAC(mac); err != nil {
		http.Error(w, "invalid mac_address", http.StatusBadRequest)
		return
	}
	key := database.NormalizeMACKey(mac)
	if key == "" {
		http.Error(w, "invalid mac_address", http.StatusBadRequest)
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		if err := s.db.DeleteHostLabel(key); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		if len(label) > maxHostLabelLen {
			http.Error(w, fmt.Sprintf("label too long (max %d characters)", maxHostLabelLen), http.StatusBadRequest)
			return
		}
		if err := s.db.UpsertHostLabel(key, label); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
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
	TargetRange string `json:"target_range"` // e.g., "192.168.1.0/24"; required for "quick"; optional CIDR filter for "mac" and "deep" (same semantics: empty = all stored IPs; non-empty = limit to CIDR)
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

	if req.ScanType == "quick" && req.TargetRange == "" {
		http.Error(w, "target_range is required", http.StatusBadRequest)
		return
	}

	displayRange := req.TargetRange
	if (req.ScanType == "mac" || req.ScanType == "deep") && displayRange == "" {
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
	clientIP := extractClientIP(r)
	suggestedRange := serverSuggestedSlash24()
	if suggestedRange == "" {
		suggestedRange = calculateNetwork24(clientIP)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"client_ip":       clientIP,
		"suggested_range": suggestedRange,
	})
}

func extractClientIP(r *http.Request) string {
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		clientIP = realIP
	}
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		return host
	}
	return clientIP
}

// serverSuggestedSlash24 returns the server's IPv4 /24 on a non-loopback interface,
// preferring RFC1918 addresses and skipping common virtual bridges.
func serverSuggestedSlash24() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var candidates []net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isProbablyVirtualInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || !ip4.IsGlobalUnicast() {
				continue
			}
			ipCopy := make(net.IP, 4)
			copy(ipCopy, ip4)
			candidates = append(candidates, ipCopy)
		}
	}
	for _, ip := range candidates {
		if isRFC1918(ip) {
			return ipv4ToSlash24(ip)
		}
	}
	if len(candidates) > 0 {
		return ipv4ToSlash24(candidates[0])
	}
	return ""
}

func isRFC1918(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	switch {
	case ip4[0] == 10:
		return true
	case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		return true
	case ip4[0] == 192 && ip4[1] == 168:
		return true
	default:
		return false
	}
}

func ipv4ToSlash24(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	mask := net.CIDRMask(24, 32)
	return fmt.Sprintf("%s/24", ip4.Mask(mask).String())
}

func calculateNetwork24(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil {
		if s := ipv4ToSlash24(parsed); s != "" {
			return s
		}
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return "192.168.1.0/24"
	}
	return fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
}

func isProbablyVirtualInterface(name string) bool {
	n := strings.ToLower(name)
	switch {
	case n == "docker0":
		return true
	case strings.HasPrefix(n, "br-"):
		return true
	case strings.HasPrefix(n, "veth"):
		return true
	case strings.HasPrefix(n, "virbr"):
		return true
	case strings.HasPrefix(n, "vmnet"):
		return true
	default:
		return false
	}
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

