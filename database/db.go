package database

import (
	"database/sql"
	"embed"
	"fmt"
	"net"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var schemaSQL embed.FS

type DB struct {
	*sql.DB
}

type Host struct {
	Hostname    string    `json:"hostname"`
	DisplayName string    `json:"display_name,omitempty"` // user label for this MAC; UI prefers over Hostname
	MacAddress  string    `json:"mac_address,omitempty"`
	IPAddress   string    `json:"ip_address,omitempty"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Ports       string    `json:"ports,omitempty"` // JSON array
}

// NormalizeMACKey returns canonical uppercase MAC for DB keys and lookups, or "" if invalid/empty.
func NormalizeMACKey(mac string) string {
	mac = strings.TrimSpace(mac)
	if mac == "" {
		return ""
	}
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return ""
	}
	return strings.ToUpper(hw.String())
}

type Scan struct {
	ID           int64      `json:"id"`
	ScanType     string     `json:"scan_type"`
	TargetRange  string     `json:"target_range"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	Status       string     `json:"status"`
	HostsFound   int        `json:"hosts_found"`
	ErrorMessage string     `json:"error_message,omitempty"`
}

func NewDB(dbPath string) (*DB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable WAL mode for better concurrency
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}

	// Read and execute schema
	schema, err := schemaSQL.ReadFile("schema.sql")
	if err != nil {
		return nil, fmt.Errorf("failed to read schema: %w", err)
	}

	if _, err := db.Exec(string(schema)); err != nil {
		return nil, fmt.Errorf("failed to execute schema: %w", err)
	}

	return &DB{db}, nil
}

// UpsertHost inserts or updates a host record
func (db *DB) UpsertHost(host Host) error {
	now := time.Now()
	if host.FirstSeen.IsZero() {
		host.FirstSeen = now
	}
	if host.LastSeen.IsZero() {
		host.LastSeen = now
	}

	query := `
		INSERT INTO hosts (hostname, mac_address, ip_address, first_seen, last_seen, ports)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(hostname) DO UPDATE SET
			mac_address = COALESCE(excluded.mac_address, hosts.mac_address),
			ip_address = COALESCE(excluded.ip_address, hosts.ip_address),
			last_seen = excluded.last_seen,
			ports = COALESCE(excluded.ports, hosts.ports)
	`

	_, err := db.Exec(query, host.Hostname, host.MacAddress, host.IPAddress,
		host.FirstSeen, host.LastSeen, host.Ports)
	return err
}

// GetAllHosts retrieves all hosts from the database
func (db *DB) GetAllHosts() ([]Host, error) {
	query := `SELECT hostname, mac_address, ip_address, first_seen, last_seen, ports 
			  FROM hosts ORDER BY last_seen DESC`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		var mac, ip, ports sql.NullString
		err := rows.Scan(&h.Hostname, &mac, &ip, &h.FirstSeen, &h.LastSeen, &ports)
		if err != nil {
			return nil, err
		}
		if mac.Valid {
			h.MacAddress = mac.String
		}
		if ip.Valid {
			h.IPAddress = ip.String
		}
		if ports.Valid {
			h.Ports = ports.String
		}
		hosts = append(hosts, h)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := db.attachDisplayNames(hosts); err != nil {
		return nil, err
	}
	return hosts, nil
}

// GetHostsWithIPAddresses returns hosts that have a stored IP (for MAC resolution, etc.).
func (db *DB) GetHostsWithIPAddresses() ([]Host, error) {
	query := `SELECT hostname, mac_address, ip_address, first_seen, last_seen, ports 
			  FROM hosts 
			  WHERE ip_address IS NOT NULL AND TRIM(ip_address) != ''
			  ORDER BY last_seen DESC`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var h Host
		var mac, ip, ports sql.NullString
		err := rows.Scan(&h.Hostname, &mac, &ip, &h.FirstSeen, &h.LastSeen, &ports)
		if err != nil {
			return nil, err
		}
		if mac.Valid {
			h.MacAddress = mac.String
		}
		if ip.Valid {
			h.IPAddress = ip.String
		}
		if ports.Valid {
			h.Ports = ports.String
		}
		hosts = append(hosts, h)
	}

	return hosts, rows.Err()
}

func (db *DB) allHostLabelsMap() (map[string]string, error) {
	rows, err := db.Query(`SELECT mac_address, label FROM host_labels`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	m := make(map[string]string)
	for rows.Next() {
		var mac, label string
		if err := rows.Scan(&mac, &label); err != nil {
			return nil, err
		}
		m[mac] = label
	}
	return m, rows.Err()
}

func (db *DB) attachDisplayNames(hosts []Host) error {
	if len(hosts) == 0 {
		return nil
	}
	labels, err := db.allHostLabelsMap()
	if err != nil {
		return err
	}
	for i := range hosts {
		key := NormalizeMACKey(hosts[i].MacAddress)
		if key == "" {
			continue
		}
		if lbl, ok := labels[key]; ok {
			hosts[i].DisplayName = lbl
		}
	}
	return nil
}

func (db *DB) attachDisplayNameOne(h *Host) error {
	key := NormalizeMACKey(h.MacAddress)
	if key == "" {
		return nil
	}
	var label string
	err := db.QueryRow(`SELECT label FROM host_labels WHERE mac_address = ?`, key).Scan(&label)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	h.DisplayName = label
	return nil
}

// UpsertHostLabel stores or updates the user-visible name for a MAC address (mac must parse with net.ParseMAC).
func (db *DB) UpsertHostLabel(macKey, label string) error {
	_, err := db.Exec(`
		INSERT INTO host_labels (mac_address, label, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(mac_address) DO UPDATE SET
			label = excluded.label,
			updated_at = excluded.updated_at
	`, macKey, label, time.Now())
	return err
}

// DeleteHostLabel removes a custom name for the given canonical MAC key.
func (db *DB) DeleteHostLabel(macKey string) error {
	_, err := db.Exec(`DELETE FROM host_labels WHERE mac_address = ?`, macKey)
	return err
}

// GetHost retrieves a single host by hostname
func (db *DB) GetHost(hostname string) (*Host, error) {
	query := `SELECT hostname, mac_address, ip_address, first_seen, last_seen, ports 
			  FROM hosts WHERE hostname = ?`

	var h Host
	var mac, ip, ports sql.NullString
	err := db.QueryRow(query, hostname).Scan(&h.Hostname, &mac, &ip, &h.FirstSeen, &h.LastSeen, &ports)
	if err != nil {
		return nil, err
	}

	if mac.Valid {
		h.MacAddress = mac.String
	}
	if ip.Valid {
		h.IPAddress = ip.String
	}
	if ports.Valid {
		h.Ports = ports.String
	}

	if err := db.attachDisplayNameOne(&h); err != nil {
		return nil, err
	}
	return &h, nil
}

// CreateScan creates a new scan record
func (db *DB) CreateScan(scanType, targetRange string) (int64, error) {
	query := `INSERT INTO scans (scan_type, target_range, started_at, status, hosts_found)
			  VALUES (?, ?, ?, 'running', 0)`

	result, err := db.Exec(query, scanType, targetRange, time.Now())
	if err != nil {
		return 0, err
	}

	return result.LastInsertId()
}

// UpdateScan updates a scan record
func (db *DB) UpdateScan(scanID int64, status string, hostsFound int, errorMsg string) error {
	now := time.Now()
	query := `UPDATE scans SET status = ?, hosts_found = ?, completed_at = ?, error_message = ?
			  WHERE id = ?`

	_, err := db.Exec(query, status, hostsFound, now, errorMsg, scanID)
	return err
}

// GetRecentScans retrieves the most recent scans
func (db *DB) GetRecentScans(limit int) ([]Scan, error) {
	query := `SELECT id, scan_type, target_range, started_at, completed_at, status, hosts_found, error_message
			  FROM scans ORDER BY started_at DESC LIMIT ?`

	rows, err := db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []Scan
	for rows.Next() {
		var s Scan
		var completedAt sql.NullTime
		var errorMsg sql.NullString

		err := rows.Scan(&s.ID, &s.ScanType, &s.TargetRange, &s.StartedAt,
			&completedAt, &s.Status, &s.HostsFound, &errorMsg)
		if err != nil {
			return nil, err
		}

		if completedAt.Valid {
			s.CompletedAt = &completedAt.Time
		}
		if errorMsg.Valid {
			s.ErrorMessage = errorMsg.String
		}

		scans = append(scans, s)
	}

	return scans, rows.Err()
}

// GetStats returns basic statistics
func (db *DB) GetStats() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total hosts
	var totalHosts int
	err := db.QueryRow("SELECT COUNT(*) FROM hosts").Scan(&totalHosts)
	if err != nil {
		return nil, err
	}
	stats["total_hosts"] = totalHosts

	// Hosts seen in last 24 hours
	var recentHosts int
	err = db.QueryRow("SELECT COUNT(*) FROM hosts WHERE last_seen > datetime('now', '-24 hours')").Scan(&recentHosts)
	if err != nil {
		return nil, err
	}
	stats["recent_hosts"] = recentHosts

	// Total scans
	var totalScans int
	err = db.QueryRow("SELECT COUNT(*) FROM scans").Scan(&totalScans)
	if err != nil {
		return nil, err
	}
	stats["total_scans"] = totalScans

	return stats, nil
}

