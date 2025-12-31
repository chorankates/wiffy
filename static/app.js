// WebSocket connection
let ws = null;
let reconnectInterval = null;

function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}/api/ws`);

    ws.onopen = () => {
        console.log('WebSocket connected');
        updateConnectionStatus(true);
        clearInterval(reconnectInterval);
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleWebSocketMessage(data);
    };

    ws.onclose = () => {
        console.log('WebSocket disconnected');
        updateConnectionStatus(false);
        // Attempt to reconnect every 3 seconds
        reconnectInterval = setInterval(connectWebSocket, 3000);
    };

    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
    };
}

function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connectionStatus');
    const dot = statusEl.querySelector('.status-dot');
    const text = statusEl.querySelector('span');

    if (connected) {
        dot.className = 'status-dot status-connected';
        text.textContent = 'Connected';
    } else {
        dot.className = 'status-dot status-disconnected';
        text.textContent = 'Disconnected';
    }
}

function handleWebSocketMessage(data) {
    if (data.type === 'scan_progress') {
        addActivityItem(data.message);
    } else if (data.type === 'scan_complete') {
        addActivityItem(`Scan completed: ${data.status}`);
        refreshAll();
    } else if (data.type === 'connected') {
        addActivityItem(data.message);
    }
}

function addActivityItem(message) {
    const feed = document.getElementById('activityFeed');
    const item = document.createElement('div');
    item.className = 'activity-item';
    const timestamp = new Date().toLocaleTimeString();
    item.textContent = `[${timestamp}] ${message}`;
    
    // Remove "waiting" message if exists
    if (feed.children.length === 1 && feed.children[0].textContent.includes('Waiting')) {
        feed.innerHTML = '';
    }
    
    feed.insertBefore(item, feed.firstChild);
    
    // Keep only last 50 items
    while (feed.children.length > 50) {
        feed.removeChild(feed.lastChild);
    }
}

// API calls
async function fetchStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        document.getElementById('totalHosts').textContent = stats.total_hosts || 0;
        document.getElementById('recentHosts').textContent = stats.recent_hosts || 0;
        document.getElementById('totalScans').textContent = stats.total_scans || 0;
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

async function fetchHosts() {
    try {
        const response = await fetch('/api/hosts');
        const hosts = await response.json();
        
        const tbody = document.getElementById('hostsTableBody');
        
        if (!hosts || hosts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No hosts discovered yet. Start a scan!</td></tr>';
            return;
        }
        
        tbody.innerHTML = hosts.map(host => {
            const ports = host.ports ? JSON.parse(host.ports) : [];
            const portsBadges = ports.length > 0 
                ? ports.slice(0, 10).map(p => `<span class="port-badge">${p}</span>`).join('') 
                    + (ports.length > 10 ? ` <span class="port-badge">+${ports.length - 10} more</span>` : '')
                : '-';
            
            const lastSeen = new Date(host.last_seen);
            const hoursSince = (Date.now() - lastSeen.getTime()) / (1000 * 60 * 60);
            const statusClass = hoursSince < 24 ? 'status-online' : 'status-offline';
            const statusText = hoursSince < 1 ? 'Just now' : 
                              hoursSince < 24 ? `${Math.floor(hoursSince)}h ago` : 
                              lastSeen.toLocaleDateString();
            
            return `
                <tr>
                    <td><strong>${escapeHtml(host.hostname)}</strong></td>
                    <td>${escapeHtml(host.ip_address || '-')}</td>
                    <td><code>${escapeHtml(host.mac_address || '-')}</code></td>
                    <td>${portsBadges}</td>
                    <td>
                        <span class="status-badge ${statusClass}">${statusText}</span>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Error fetching hosts:', error);
    }
}

async function fetchRecentScans() {
    try {
        const response = await fetch('/api/scans?limit=5');
        const scans = await response.json();
        
        const container = document.getElementById('recentScans');
        const header = container.querySelector('h3');
        container.innerHTML = '';
        container.appendChild(header);
        
        if (!scans || scans.length === 0) {
            return;
        }
        
        scans.forEach(scan => {
            const scanItem = document.createElement('div');
            scanItem.className = 'scan-item';
            
            const startTime = new Date(scan.started_at);
            const statusColor = scan.status === 'completed' ? '#28a745' : 
                               scan.status === 'failed' ? '#dc3545' : '#ffc107';
            
            scanItem.innerHTML = `
                <div class="scan-item-header">
                    <span class="scan-type" style="color: ${statusColor}">${scan.scan_type}</span>
                    <span class="scan-time">${startTime.toLocaleString()}</span>
                </div>
                <div style="font-size: 0.9em; color: #666;">
                    ${scan.target_range} - ${scan.hosts_found} hosts found
                </div>
            `;
            
            container.appendChild(scanItem);
        });
    } catch (error) {
        console.error('Error fetching scans:', error);
    }
}

async function startScan(scanType, targetRange) {
    try {
        const response = await fetch('/api/scans', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                scan_type: scanType,
                target_range: targetRange,
            }),
        });
        
        if (!response.ok) {
            const error = await response.text();
            throw new Error(error);
        }
        
        const result = await response.json();
        addActivityItem(`Started ${scanType} scan on ${targetRange} (ID: ${result.scan_id})`);
        
        return result;
    } catch (error) {
        console.error('Error starting scan:', error);
        addActivityItem(`Error: ${error.message}`);
        alert(`Failed to start scan: ${error.message}`);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function refreshAll() {
    fetchStats();
    fetchHosts();
    fetchRecentScans();
}

// Event listeners
document.getElementById('scanForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const button = e.submitter;
    const scanType = button.dataset.scanType;
    const targetRange = document.getElementById('targetRange').value;
    
    // Disable buttons during scan
    const buttons = document.querySelectorAll('#scanForm button');
    buttons.forEach(btn => btn.disabled = true);
    
    await startScan(scanType, targetRange);
    
    // Re-enable buttons
    buttons.forEach(btn => btn.disabled = false);
});

// Initialize
connectWebSocket();
refreshAll();

// Refresh data every 5 seconds
setInterval(refreshAll, 5000);

