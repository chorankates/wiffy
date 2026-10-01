// Package oui maps MAC addresses to hardware vendors using nmap's bundled IEEE registry (nmap-mac-prefixes).
package oui

import (
	"bufio"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// RandomizedVendor is reported for locally administered MACs that aren't in the registry
// (typically phones/laptops using per-network private addresses).
const RandomizedVendor = "Randomized (private MAC)"

var (
	loadOnce sync.Once
	prefixes map[string]string // uppercase hex prefix (6, 7 or 9 digits) -> vendor
	lengths  []int             // prefix lengths present, longest first
)

// Lookup returns the vendor for mac, or "" if unknown or mac is invalid.
func Lookup(mac string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil || len(hw) < 3 {
		return ""
	}
	loadOnce.Do(load)

	hex := strings.ToUpper(strings.ReplaceAll(hw.String(), ":", ""))
	for _, n := range lengths {
		if n <= len(hex) {
			if v, ok := prefixes[hex[:n]]; ok {
				return v
			}
		}
	}
	if hw[0]&0x02 != 0 {
		return RandomizedVendor
	}
	return ""
}

func load() {
	prefixes = make(map[string]string)
	path := findPrefixFile()
	if path == "" {
		log.Println("oui: nmap-mac-prefixes not found; MAC vendor lookup disabled")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		log.Printf("oui: %v; MAC vendor lookup disabled", err)
		return
	}
	defer f.Close()

	seen := make(map[int]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		prefix, vendor, ok := strings.Cut(line, " ")
		vendor = strings.TrimSpace(vendor)
		if !ok || vendor == "" {
			continue
		}
		prefix = strings.ToUpper(prefix)
		prefixes[prefix] = vendor
		seen[len(prefix)] = true
	}
	if err := sc.Err(); err != nil {
		log.Printf("oui: reading %s: %v", path, err)
	}
	for n := range seen {
		lengths = append(lengths, n)
	}
	// Longest prefix wins (MA-S/MA-M blocks are carved out of larger OUIs).
	for i := 1; i < len(lengths); i++ {
		for j := i; j > 0 && lengths[j] > lengths[j-1]; j-- {
			lengths[j], lengths[j-1] = lengths[j-1], lengths[j]
		}
	}
	log.Printf("oui: loaded %d MAC vendor prefixes from %s", len(prefixes), path)
}

// findPrefixFile locates nmap-mac-prefixes: $NMAPDIR, then <nmap prefix>/share/nmap, then common install paths.
func findPrefixFile() string {
	var dirs []string
	if d := os.Getenv("NMAPDIR"); d != "" {
		dirs = append(dirs, d)
	}
	if bin, err := exec.LookPath("nmap"); err == nil {
		if resolved, err := filepath.EvalSymlinks(bin); err == nil {
			bin = resolved
		}
		dirs = append(dirs, filepath.Join(filepath.Dir(filepath.Dir(bin)), "share", "nmap"))
	}
	dirs = append(dirs, "/usr/share/nmap", "/usr/local/share/nmap", "/opt/homebrew/share/nmap")
	for _, d := range dirs {
		p := filepath.Join(d, "nmap-mac-prefixes")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
