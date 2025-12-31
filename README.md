# 📡 Wiffy

> pretty sure it's pronounced 'wiffy', right?

A modern network scanner with a beautiful web UI built in Go. Discover hosts on your network, track MAC addresses, hostnames, IP addresses, and monitor network activity over time.

## ✨ Features

- **Quick Scans**: Fast network discovery using nmap ping scans
- **Deep Scans**: Comprehensive scanning with port discovery
- **Modern Web UI**: Beautiful, responsive interface with real-time updates
- **SQLite Database**: Persistent storage of all discovered hosts
- **Real-time Updates**: WebSocket-based live scan progress
- **Host Tracking**: Automatic tracking of first seen/last seen timestamps
- **Port Discovery**: Deep scans discover and track open ports
- **Network History**: View all past scans and their results

## 🚀 Quick Start

### Prerequisites

- Go 1.21 or later
- nmap installed on your system
  - macOS: `brew install nmap`
  - Linux: `apt-get install nmap` or `yum install nmap`
  - Windows: Download from [nmap.org](https://nmap.org/download.html)

### Installation

```bash
# Clone the repository
git clone https://github.com/conor/wiffy.git
cd wiffy

# Download dependencies
go mod download

# Build the application
make build

# Run the server
./wiffy
```

Or simply:

```bash
make run
```

### Development

```bash
# Run without building
make dev

# Clean build artifacts and database
make clean
```

## 📖 Usage

1. **Start the server**:
   ```bash
   ./wiffy
   ```
   The server will start on `http://localhost:8080` by default.

2. **Open your browser** to `http://localhost:8080`

3. **Start a scan**:
   - Enter a target range (e.g., `192.168.1.0/24`)
   - Choose scan type:
     - **Quick Scan**: Fast ping scan to discover hosts
     - **Deep Scan**: Comprehensive scan with port discovery

4. **View results** in real-time as they appear in the table

## 🎯 API Endpoints

### GET /api/hosts
Get all discovered hosts
```bash
curl http://localhost:8080/api/hosts
```

### GET /api/hosts/{hostname}
Get a specific host by hostname
```bash
curl http://localhost:8080/api/hosts/192.168.1.1
```

### POST /api/scans
Start a new scan
```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "scan_type": "quick",
    "target_range": "192.168.1.0/24"
  }'
```

### GET /api/scans
Get recent scans
```bash
curl http://localhost:8080/api/scans?limit=10
```

### GET /api/stats
Get statistics
```bash
curl http://localhost:8080/api/stats
```

### WebSocket /api/ws
Real-time scan progress updates
```javascript
const ws = new WebSocket('ws://localhost:8080/api/ws');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data);
};
```

## 🗄️ Database Schema

### Hosts Table
- `hostname` (TEXT, PRIMARY KEY) - Unique identifier
- `mac_address` (TEXT) - MAC address of the host
- `ip_address` (TEXT) - IP address of the host
- `first_seen` (DATETIME) - When the host was first discovered
- `last_seen` (DATETIME) - Last time the host was seen
- `ports` (TEXT) - JSON array of open ports (from deep scans)

### Scans Table
- `id` (INTEGER, PRIMARY KEY) - Scan ID
- `scan_type` (TEXT) - 'quick' or 'deep'
- `target_range` (TEXT) - Network range scanned
- `started_at` (DATETIME) - Scan start time
- `completed_at` (DATETIME) - Scan completion time
- `status` (TEXT) - 'running', 'completed', or 'failed'
- `hosts_found` (INTEGER) - Number of hosts discovered
- `error_message` (TEXT) - Error details if failed

## ⚙️ Configuration

Environment variables:

- `PORT` - Server port (default: 8080)
- `WIFFY_DB_PATH` - Database file path (default: ./wiffy.db)

Example:
```bash
PORT=3000 WIFFY_DB_PATH=/var/lib/wiffy.db ./wiffy
```

## 🏗️ Architecture

```
wiffy/
├── main.go              # Application entry point
├── api/                 # API server and handlers
│   └── handlers.go
├── database/            # Database layer
│   ├── db.go
│   └── schema.sql
├── scanner/             # Network scanning logic
│   └── nmap.go
└── static/              # Web UI
    ├── index.html
    └── app.js
```

## 🔒 Security Notes

- **Root Privileges**: Some nmap features (like OS detection) require root privileges. The scanner works fine without them for basic host discovery.
- **Network Access**: This tool performs active network scanning. Make sure you have permission to scan the networks you target.
- **Local Access**: By default, the web server listens on all interfaces. Consider firewall rules if running on a public network.

## 🛠️ Development

### Building

```bash
go build -o wiffy .
```

### Running Tests

```bash
go test ./...
```

### Code Structure

- **database**: SQLite database operations and models
- **scanner**: Nmap integration and scan orchestration
- **api**: HTTP/WebSocket API handlers
- **static**: Frontend HTML/CSS/JavaScript

## 📝 License

MIT License - feel free to use this project however you'd like!

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## 💡 Future Ideas

- [ ] Network topology visualization
- [ ] Alert notifications for new hosts
- [ ] Export data to CSV/JSON
- [ ] Custom port ranges for deep scans
- [ ] Integration with other scanning tools
- [ ] Docker container support
- [ ] Authentication/user management
- [ ] Scheduled automatic scans
