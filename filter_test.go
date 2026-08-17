package tunless

import (
	"net/netip"
	"testing"
)

func TestFilter(t *testing.T) {
	flow := Flow{OrigDst: netip.MustParseAddrPort("203.0.113.7:443"), Process: ProcessInfo{Path: "/usr/bin/curl"}}
	tests := []struct {
		name   string
		filter Filter
		want   bool
	}{
		{"empty captures", Filter{}, true},
		{"included process", Filter{IncludeProcesses: []string{"curl"}}, true},
		{"other process", Filter{IncludeProcesses: []string{"firefox"}}, false},
		{"excluded wins", Filter{IncludeProcesses: []string{"*"}, ExcludeProcesses: []string{"curl"}}, false},
		{"included network", Filter{IncludeDestinations: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}, true},
		{"excluded network", Filter{ExcludeDestinations: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.filter.Capture(flow); got != tt.want {
				t.Fatalf("Capture()=%v, want %v", got, tt.want)
			}
		})
	}
}
