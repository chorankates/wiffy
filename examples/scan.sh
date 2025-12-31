#!/bin/bash
# Example script to trigger scans via the API

API_BASE="http://localhost:8080/api"

# Function to start a scan
start_scan() {
    local scan_type=$1
    local target_range=$2
    
    echo "Starting $scan_type scan on $target_range..."
    
    curl -X POST "$API_BASE/scans" \
        -H "Content-Type: application/json" \
        -d "{
            \"scan_type\": \"$scan_type\",
            \"target_range\": \"$target_range\"
        }" | jq '.'
}

# Function to get all hosts
get_hosts() {
    echo "Fetching all discovered hosts..."
    curl -s "$API_BASE/hosts" | jq '.'
}

# Function to get stats
get_stats() {
    echo "Fetching statistics..."
    curl -s "$API_BASE/stats" | jq '.'
}

# Function to get recent scans
get_scans() {
    echo "Fetching recent scans..."
    curl -s "$API_BASE/scans?limit=10" | jq '.'
}

# Main menu
case "$1" in
    quick)
        start_scan "quick" "${2:-192.168.1.0/24}"
        ;;
    deep)
        start_scan "deep" "${2:-192.168.1.0/24}"
        ;;
    hosts)
        get_hosts
        ;;
    stats)
        get_stats
        ;;
    scans)
        get_scans
        ;;
    *)
        echo "Usage: $0 {quick|deep|hosts|stats|scans} [target_range]"
        echo ""
        echo "Examples:"
        echo "  $0 quick 192.168.1.0/24    # Quick scan"
        echo "  $0 deep 10.0.0.0/24         # Deep scan"
        echo "  $0 hosts                     # List all hosts"
        echo "  $0 stats                     # Show statistics"
        echo "  $0 scans                     # Show recent scans"
        exit 1
        ;;
esac

