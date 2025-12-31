# Quick Start Guide

## Get Running in 60 Seconds

### 1. Install nmap (if not already installed)

**macOS:**
```bash
brew install nmap
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get update && sudo apt-get install -y nmap
```

**Linux (RedHat/CentOS):**
```bash
sudo yum install -y nmap
```

### 2. Run Wiffy

```bash
# Option A: Build and run
make run

# Option B: Run directly with Go
go run main.go

# Option C: Build first, then run
make build
./wiffy
```

### 3. Open your browser

Navigate to: **http://localhost:8080**

### 4. Start your first scan

1. Enter your network range (e.g., `192.168.1.0/24`)
2. Click "Quick Scan" for fast discovery
3. Watch the hosts appear in real-time!

## Common Network Ranges

- Home network: `192.168.1.0/24` or `192.168.0.0/24`
- Corporate: `10.0.0.0/24` or `172.16.0.0/24`
- Single IP: `192.168.1.100/32`

## Troubleshooting

### "nmap not found"
Make sure nmap is installed and in your PATH:
```bash
which nmap
nmap --version
```

### "Permission denied" during scans
Some nmap features require elevated privileges. Try:
```bash
sudo ./wiffy
```

### Port 8080 already in use
Change the port:
```bash
PORT=3000 ./wiffy
```

## API Examples

**Start a quick scan:**
```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -d '{"scan_type":"quick","target_range":"192.168.1.0/24"}'
```

**Get all hosts:**
```bash
curl http://localhost:8080/api/hosts
```

**Get statistics:**
```bash
curl http://localhost:8080/api/stats
```

## Docker

```bash
# Build and run with Docker
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Tips

- **Quick scans** are fast but only discover hosts
- **Deep scans** take longer but find open ports
- The database persists all discoveries automatically
- Scans run in the background - you can start multiple scans
- Real-time updates via WebSocket keep the UI fresh

## Example Workflow

```bash
# 1. Start the server
./wiffy

# 2. In another terminal, trigger a scan
./examples/scan.sh quick 192.168.1.0/24

# 3. View the results
./examples/scan.sh hosts

# 4. Check stats
./examples/scan.sh stats
```

## Need Help?

Check the full [README.md](README.md) for detailed documentation!

