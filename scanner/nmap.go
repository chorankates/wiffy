package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
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

