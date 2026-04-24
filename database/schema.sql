-- Hosts table with hostname as the primary key
CREATE TABLE IF NOT EXISTS hosts (
    hostname TEXT PRIMARY KEY,
    mac_address TEXT,
    ip_address TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    ports TEXT  -- JSON array: [{"port":80,"protocol":"tcp","service":"http","product":"nginx"}, ...] or legacy [80,443]
);

-- Index for faster lookups by IP and MAC
CREATE INDEX IF NOT EXISTS idx_ip_address ON hosts(ip_address);
CREATE INDEX IF NOT EXISTS idx_mac_address ON hosts(mac_address);
CREATE INDEX IF NOT EXISTS idx_last_seen ON hosts(last_seen);

-- User-defined names keyed by MAC (stable on home LANs where DNS hostnames are often missing)
CREATE TABLE IF NOT EXISTS host_labels (
    mac_address TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    updated_at DATETIME NOT NULL
);

-- Scans table to track scan history
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,  -- 'quick' or 'deep'
    target_range TEXT NOT NULL,
    started_at DATETIME NOT NULL,
    completed_at DATETIME,
    status TEXT NOT NULL,  -- 'running', 'completed', 'failed'
    hosts_found INTEGER DEFAULT 0,
    error_message TEXT
);

