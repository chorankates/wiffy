# wiffy

> pretty sure it's pronounced 'wiffy', right?

network scanner frontend for keeping track of devices on your local wifi networks - because dnsmasq is too hard

## prerequisites

- Go 1.21 or later
- nmap installed on your system
- for MAC scans to work, you'll need a sudoers entry like
`<username> ALL=(root) NOPASSWD: /path/to/nmap`

## API

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

## Future Ideas

- [ ] Network topology visualization
- [ ] Alert notifications for new hosts
- [ ] Custom port ranges for deep scans
- [ ] Integration with other scanning tools
- [ ] Scheduled automatic scans
