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
        const msg = data.message;
        // Detect console-style output
        if (msg.startsWith('$') || msg.startsWith('[nmap]') || msg.startsWith('[stderr]')) {
            addConsoleOutput(msg);
        } else {
            addActivityItem(msg, 'scan-progress');
        }
    } else if (data.type === 'scan_complete') {
        const status = data.status === 'completed' ? 'scan-completed' : 'scan-failed';
        const statusText = data.status === 'completed' ? 'COMPLETED' : 'FAILED';
        addActivityItem(`Scan ${statusText}: ${data.error || 'Successfully finished'}`, status, statusText);
        refreshAll();
    } else if (data.type === 'scan_started') {
        addActivityItem(data.message, 'scan-started', 'STARTED');
    } else if (data.type === 'connected') {
        addActivityItem(data.message, 'info');
    }
}

function addActivityItem(message, type = 'info', statusLabel = null) {
    const feed = document.getElementById('activityFeed');
    const item = document.createElement('div');
    item.className = `activity-item ${type}`;
    
    const timestamp = new Date().toLocaleTimeString();
    
    let content = `<span class="activity-timestamp">${timestamp}</span>`;
    
    if (statusLabel) {
        const statusClass = statusLabel === 'STARTED' ? 'status-running' :
                          statusLabel === 'COMPLETED' ? 'status-complete' :
                          statusLabel === 'FAILED' ? 'status-error' : '';
        content += `<span class="activity-status ${statusClass}">${statusLabel}</span>`;
    }
    
    content += message;
    item.innerHTML = content;
    
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

function addConsoleOutput(message) {
    const console = document.getElementById('consoleOutput');
    const line = document.createElement('div');
    
    const timestamp = new Date().toLocaleTimeString();
    
    // Determine line type and styling
    let lineClass = 'console-line';
    let displayMessage = message;
    
    if (message.startsWith('$')) {
        lineClass += ' command';
    } else if (message.startsWith('[nmap]')) {
        lineClass += ' nmap';
        displayMessage = message.substring(7); // Remove [nmap] prefix
    } else if (message.startsWith('[stderr]')) {
        lineClass += ' error';
        displayMessage = message.substring(9); // Remove [stderr] prefix
    } else if (message.includes('complete') || message.includes('Found')) {
        lineClass += ' success';
    }
    
    line.className = lineClass;
    line.innerHTML = `<span class="console-timestamp">${timestamp}</span>${escapeHtml(displayMessage)}`;
    
    // Remove "ready" message if exists
    if (console.children.length === 1 && console.children[0].textContent.includes('Ready')) {
        console.innerHTML = '';
    }
    
    console.appendChild(line);
    
    // Auto-scroll to bottom
    console.scrollTop = console.scrollHeight;
    
    // Keep only last 200 lines
    while (console.children.length > 200) {
        console.removeChild(console.firstChild);
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
                <tr onclick="showHostDetail('${escapeHtml(host.hostname)}')">
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
        const rangeLabel = targetRange.trim() || (scanType === 'quick' ? '(none)' : 'known hosts');
        addActivityItem(`${scanType.toUpperCase()} scan on ${rangeLabel} (ID: ${result.scan_id})`, 'scan-started', 'STARTED');
        
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
    const targetRange = document.getElementById('targetRange').value.trim();
    
    if (scanType === 'quick' && !targetRange) {
        alert('Target range is required for quick scans.');
        return;
    }
    
    // Disable buttons during scan
    const buttons = document.querySelectorAll('#scanForm button');
    buttons.forEach(btn => btn.disabled = true);
    
    await startScan(scanType, targetRange);
    
    // Re-enable buttons
    buttons.forEach(btn => btn.disabled = false);
});

// Load suggested network range
async function loadSuggestedRange() {
    try {
        const response = await fetch('/api/suggest-range');
        const data = await response.json();
        document.getElementById('targetRange').placeholder = data.suggested_range;
        document.getElementById('targetRange').value = data.suggested_range;
    } catch (error) {
        console.error('Error loading suggested range:', error);
    }
}

// Initialize
connectWebSocket();
refreshAll();
loadSuggestedRange();

// Refresh data every 5 seconds
setInterval(refreshAll, 5000);

// Host detail modal functions
async function showHostDetail(hostname) {
    try {
        const response = await fetch(`/api/hosts/${encodeURIComponent(hostname)}`);
        if (!response.ok) {
            throw new Error('Host not found');
        }
        
        const host = await response.json();
        
        // Populate modal
        document.getElementById('modalHostname').textContent = host.hostname;
        document.getElementById('detailHostname').textContent = host.hostname || '-';
        
        const ipEl = document.getElementById('detailIP');
        ipEl.textContent = host.ip_address || 'Not available';
        ipEl.className = host.ip_address ? 'detail-value' : 'detail-value empty';
        
        const macEl = document.getElementById('detailMAC');
        macEl.textContent = host.mac_address || 'Not available';
        macEl.className = host.mac_address ? 'detail-value' : 'detail-value empty';
        
        const firstSeen = new Date(host.first_seen);
        document.getElementById('detailFirstSeen').textContent = 
            firstSeen.toLocaleString();
        
        const lastSeen = new Date(host.last_seen);
        const hoursSince = (Date.now() - lastSeen.getTime()) / (1000 * 60 * 60);
        const lastSeenText = hoursSince < 1 ? 'Just now' :
                            hoursSince < 24 ? `${Math.floor(hoursSince)} hours ago` :
                            `${Math.floor(hoursSince / 24)} days ago`;
        document.getElementById('detailLastSeen').textContent = 
            `${lastSeen.toLocaleString()} (${lastSeenText})`;
        
        // Ports
        const portsContainer = document.getElementById('detailPorts');
        if (host.ports) {
            const ports = JSON.parse(host.ports);
            if (ports.length > 0) {
                portsContainer.innerHTML = ports
                    .map(p => `<span class="port-badge">${p}</span>`)
                    .join('');
            } else {
                portsContainer.innerHTML = '<div class="detail-value empty">No open ports discovered</div>';
            }
        } else {
            portsContainer.innerHTML = '<div class="detail-value empty">No port scan performed</div>';
        }
        
        // Show modal
        document.getElementById('hostModal').classList.add('active');
    } catch (error) {
        console.error('Error loading host details:', error);
        alert('Failed to load host details');
    }
}

function closeHostModal() {
    document.getElementById('hostModal').classList.remove('active');
}

// Close modal when clicking outside
document.getElementById('hostModal').addEventListener('click', (e) => {
    if (e.target.id === 'hostModal') {
        closeHostModal();
    }
});

// Close modal on Escape key
document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        closeHostModal();
    }
});

