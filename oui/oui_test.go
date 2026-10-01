package oui

import "testing"

func TestLookup(t *testing.T) {
	loadOnce.Do(func() {
		prefixes = map[string]string{
			"001A11":    "Google",
			"70B3D5":    "IEEE Registration Authority",
			"70B3D5123": "Some MA-S Device Maker",
		}
		lengths = []int{9, 6}
	})

	tests := []struct{ mac, want string }{
		{"00:1a:11:aa:bb:cc", "Google"},
		{"70:B3:D5:12:3F:00", "Some MA-S Device Maker"}, // longest prefix wins
		{"70:B3:D5:99:00:00", "IEEE Registration Authority"},
		{"DA:A1:19:00:00:01", RandomizedVendor}, // locally administered bit set
		{"00:00:00:00:00:01", ""},
		{"not-a-mac", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := Lookup(tt.mac); got != tt.want {
			t.Errorf("Lookup(%q) = %q, want %q", tt.mac, got, tt.want)
		}
	}
}
