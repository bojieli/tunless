package dnsobserver

import (
	"net/netip"
	"testing"
	"time"
)

func TestLookupRejectsAmbiguity(t *testing.T) {
	o := &Observer{records: map[netip.Addr]map[string]time.Time{netip.MustParseAddr("203.0.113.1"): {"a.example.": time.Now().Add(time.Minute)}}}
	if got := o.Lookup(netip.MustParseAddr("203.0.113.1")); got != "a.example." {
		t.Fatalf("got %q", got)
	}
	o.records[netip.MustParseAddr("203.0.113.1")]["b.example."] = time.Now().Add(time.Minute)
	if got := o.Lookup(netip.MustParseAddr("203.0.113.1")); got != "" {
		t.Fatalf("ambiguous lookup returned %q", got)
	}
}
