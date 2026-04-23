package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/conor/wiffy/database"
)

type Scanner struct {
	db *database.DB
}

type ScanResult struct {
	Hostname   string
	IPAddress  string
	MacAddress string
	Ports      []int
}

func NewScanner(db *database.DB) *Scanner {
	return &Scanner{db: db}
}

// macScanExec runs nmap with the privileges needed for ARP-based MAC resolution.
// On Unix, nmap is invoked via sudo; configure sudoers for passwordless nmap (exact path), e.g.:
//
//	youruser ALL=(root) NOPASSWD: /usr/bin/nmap
func macScanExec(nmapArgs []string) (*exec.Cmd, string) {
	if runtime.GOOS == "windows" {
		return exec.Command("nmap", nmapArgs...),
			fmt.Sprintf("$ nmap %s", strings.Join(nmapArgs, " "))
	}
	cmdArgs := append([]string{"nmap"}, nmapArgs...)
	return exec.Command("sudo", cmdArgs...),
		fmt.Sprintf("$ sudo nmap %s", strings.Join(nmapArgs, " "))
}

// QuickScan performs a quick ping scan to discover hosts
func (s *Scanner) QuickScan(targetRange string, scanID int64, progressChan chan<- string) error {
	progressChan <- "Starting quick scan..."

	// Use nmap with -sn (ping scan, no port scan) for quick discovery
	args := []string{"-sn", "-oG", "-", targetRange}
	cmd := exec.Command("nmap", args...)
	
	// Show the actual command
	cmdStr := fmt.Sprintf("$ nmap %s", strings.Join(args, " "))
	progressChan <- cmdStr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start nmap: %w", err)
	}
	
	// Read stderr in background
	go func() {
		stderrScanner := bufio.NewScanner(stderr)
		for stderrScanner.Scan() {
			line := stderrScanner.Text()
			if line != "" {
				progressChan <- fmt.Sprintf("[stderr] %s", line)
			}
		}
	}()

	scanner := bufio.NewScanner(stdout)
	hostsFound := 0

	// Regex patterns for parsing nmap output
	hostRegex := regexp.MustCompile(`Host: (\S+) \(([^)]*)\)`)
	macRegex := regexp.MustCompile(`MAC Address: ([0-9A-F:]+)`)

	for scanner.Scan() {
		line := scanner.Text()
		
		// Show raw output for debugging
		if line != "" {
			progressChan <- fmt.Sprintf("[nmap] %s", line)
		}

		// Parse host information
		if strings.Contains(line, "Host:") && strings.Contains(line, "Status: Up") {
			result := ScanResult{}

			// Extract IP and hostname
			if matches := hostRegex.FindStringSubmatch(line); len(matches) > 2 {
				result.IPAddress = matches[1]
				result.Hostname = matches[2]
				if result.Hostname == "" || result.Hostname == result.IPAddress {
					result.Hostname = result.IPAddress
				}
			}

			// Extract MAC address
			if matches := macRegex.FindStringSubmatch(line); len(matches) > 1 {
				result.MacAddress = matches[1]
			}

			// Save to database
			if result.IPAddress != "" {
				host := database.Host{
					Hostname:   result.Hostname,
					IPAddress:  result.IPAddress,
					MacAddress: result.MacAddress,
					LastSeen:   time.Now(),
				}

				if err := s.db.UpsertHost(host); err == nil {
					hostsFound++
					progressChan <- fmt.Sprintf("Found: %s (%s)", result.Hostname, result.IPAddress)
				}
			}
		}
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("nmap command failed: %w", err)
	}

	// Update scan record
	s.db.UpdateScan(scanID, "completed", hostsFound, "")
	progressChan <- fmt.Sprintf("Quick scan complete. Found %d hosts.", hostsFound)

	return nil
}

// MacScan resolves MAC addresses for hosts already stored with an IP address.
// targetRange may be empty (all known hosts) or a CIDR such as 192.168.1.0/24 to limit which stored IPs are probed.
//
// On Unix, nmap is run under sudo so only that process is privileged; sudoers should allow NOPASSWD for nmap.
func (s *Scanner) MacScan(targetRange string, scanID int64, progressChan chan<- string) error {
	progressChan <- "Starting MAC scan for known IP addresses..."

	hosts, err := s.db.GetHostsWithIPAddresses()
	if err != nil {
		return fmt.Errorf("failed to list hosts: %w", err)
	}

	if targetRange != "" {
		_, ipNet, err := net.ParseCIDR(targetRange)
		if err != nil {
			return fmt.Errorf("invalid target_range for MAC scan (use CIDR like 192.168.1.0/24, or leave empty): %w", err)
		}
		var filtered []database.Host
		for _, h := range hosts {
			if ip := net.ParseIP(h.IPAddress); ip != nil && ipNet.Contains(ip) {
				filtered = append(filtered, h)
			}
		}
		hosts = filtered
	}

	if len(hosts) == 0 {
		progressChan <- "No known hosts with IP addresses match this scan."
		s.db.UpdateScan(scanID, "completed", 0, "")
		return nil
	}

	ipToHost := make(map[string]database.Host, len(hosts))
	nmapArgs := []string{"-sP"}
	for _, h := range hosts {
		ipToHost[h.IPAddress] = h
		nmapArgs = append(nmapArgs, h.IPAddress)
	}

	cmd, cmdStr := macScanExec(nmapArgs)
	progressChan <- cmdStr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start MAC scan: %w", err)
	}

	go func() {
		stderrScanner := bufio.NewScanner(stderr)
		for stderrScanner.Scan() {
			line := stderrScanner.Text()
			if line != "" {
				progressChan <- fmt.Sprintf("[stderr] %s", line)
			}
		}
	}()

	// Default (non-greppable) -sP output: "Nmap scan report for …" then optional "MAC Address: …" lines.
	reportWithName := regexp.MustCompile(`^Nmap scan report for .+ \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s*$`)
	reportIPOnly := regexp.MustCompile(`^Nmap scan report for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$`)
	macRegex := regexp.MustCompile(`MAC Address: ([0-9A-Fa-f:]+)`)

	sc := bufio.NewScanner(stdout)
	hostsFound := 0
	var pendingIP string

	for sc.Scan() {
		line := sc.Text()
		if line != "" {
			progressChan <- fmt.Sprintf("[nmap] %s", line)
		}

		if m := reportWithName.FindStringSubmatch(line); len(m) == 2 {
			pendingIP = m[1]
			continue
		}
		if m := reportIPOnly.FindStringSubmatch(line); len(m) == 2 {
			pendingIP = m[1]
			continue
		}

		if m := macRegex.FindStringSubmatch(line); len(m) > 1 && pendingIP != "" {
			macAddr := m[1]
			known, ok := ipToHost[pendingIP]
			if !ok {
				pendingIP = ""
				continue
			}

			macToStore := macAddr
			if macToStore == "" {
				macToStore = known.MacAddress
			}

			host := database.Host{
				Hostname:   known.Hostname,
				IPAddress:  known.IPAddress,
				MacAddress: macToStore,
				LastSeen:   time.Now(),
				Ports:      known.Ports,
			}

			if err := s.db.UpsertHost(host); err == nil {
				hostsFound++
				progressChan <- fmt.Sprintf("Updated: %s (%s) MAC %s", known.Hostname, pendingIP, macAddr)
			}
			pendingIP = ""
		}
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("nmap command failed: %w", err)
	}

	s.db.UpdateScan(scanID, "completed", hostsFound, "")
	progressChan <- fmt.Sprintf("MAC scan complete. Updated %d host(s).", hostsFound)

	return nil
}

// DeepScan performs a deep scan with port scanning
func (s *Scanner) DeepScan(targetRange string, scanID int64, progressChan chan<- string) error {
	progressChan <- "Starting deep scan with port discovery..."

	// Use nmap with port scanning (-T4 for faster timing, -F for fast/common ports)
	// Add -O for OS detection if running as root, but don't require it
	args := []string{"-T4", "-F", "-sV", "-oG", "-", targetRange}
	cmd := exec.Command("nmap", args...)
	
	// Show the actual command
	cmdStr := fmt.Sprintf("$ nmap %s", strings.Join(args, " "))
	progressChan <- cmdStr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start nmap: %w", err)
	}
	
	// Read stderr in background
	go func() {
		stderrScanner := bufio.NewScanner(stderr)
		for stderrScanner.Scan() {
			line := stderrScanner.Text()
			if line != "" {
				progressChan <- fmt.Sprintf("[stderr] %s", line)
			}
		}
	}()

	scanner := bufio.NewScanner(stdout)
	hostsFound := 0

	// Regex patterns
	hostRegex := regexp.MustCompile(`Host: (\S+) \(([^)]*)\)`)
	portsRegex := regexp.MustCompile(`Ports: (.+?)(?:\s+Ignored|$)`)
	macRegex := regexp.MustCompile(`MAC Address: ([0-9A-F:]+)`)

	currentHost := &ScanResult{}

	for scanner.Scan() {
		line := scanner.Text()
		
		// Show raw output for debugging
		if line != "" {
			progressChan <- fmt.Sprintf("[nmap] %s", line)
		}

		// Parse host information
		if strings.Contains(line, "Host:") && strings.Contains(line, "Status: Up") {
			// Save previous host if exists
			if currentHost.IPAddress != "" {
				s.saveHostResult(currentHost)
				hostsFound++
				progressChan <- fmt.Sprintf("Found: %s (%s) - %d open ports",
					currentHost.Hostname, currentHost.IPAddress, len(currentHost.Ports))
			}

			currentHost = &ScanResult{}

			// Extract IP and hostname
			if matches := hostRegex.FindStringSubmatch(line); len(matches) > 2 {
				currentHost.IPAddress = matches[1]
				currentHost.Hostname = matches[2]
				if currentHost.Hostname == "" || currentHost.Hostname == currentHost.IPAddress {
					currentHost.Hostname = currentHost.IPAddress
				}
			}

			// Extract MAC address
			if matches := macRegex.FindStringSubmatch(line); len(matches) > 1 {
				currentHost.MacAddress = matches[1]
			}

			// Extract ports
			if matches := portsRegex.FindStringSubmatch(line); len(matches) > 1 {
				currentHost.Ports = parsePorts(matches[1])
			}
		}
	}

	// Save last host
	if currentHost.IPAddress != "" {
		s.saveHostResult(currentHost)
		hostsFound++
		progressChan <- fmt.Sprintf("Found: %s (%s) - %d open ports",
			currentHost.Hostname, currentHost.IPAddress, len(currentHost.Ports))
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("nmap command failed: %w", err)
	}

	// Update scan record
	s.db.UpdateScan(scanID, "completed", hostsFound, "")
	progressChan <- fmt.Sprintf("Deep scan complete. Found %d hosts.", hostsFound)

	return nil
}

func (s *Scanner) saveHostResult(result *ScanResult) error {
	var portsJSON string
	if len(result.Ports) > 0 {
		data, _ := json.Marshal(result.Ports)
		portsJSON = string(data)
	}

	host := database.Host{
		Hostname:   result.Hostname,
		IPAddress:  result.IPAddress,
		MacAddress: result.MacAddress,
		LastSeen:   time.Now(),
		Ports:      portsJSON,
	}

	return s.db.UpsertHost(host)
}

// parsePorts extracts port numbers from nmap greppable output
// Format: "22/open/tcp//ssh///, 80/open/tcp//http///"
func parsePorts(portsStr string) []int {
	var ports []int
	portEntries := strings.Split(portsStr, ",")

	for _, entry := range portEntries {
		entry = strings.TrimSpace(entry)
		parts := strings.Split(entry, "/")
		if len(parts) > 0 {
			var port int
			if _, err := fmt.Sscanf(parts[0], "%d", &port); err == nil {
				ports = append(ports, port)
			}
		}
	}

	return ports
}

// ValidateNmap checks if nmap is installed
func ValidateNmap() error {
	cmd := exec.Command("nmap", "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nmap not found - please install nmap to use this scanner")
	}
	return nil
}

