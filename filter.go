package tunless

import (
	"fmt"
	"net/netip"
	"path/filepath"
)

type Filter struct {
	IncludeProcesses    []string
	ExcludeProcesses    []string
	IncludeDestinations []netip.Prefix
	ExcludeDestinations []netip.Prefix
}

func (f Filter) Validate() error {
	processGroups := []struct {
		kind     string
		patterns []string
	}{
		{"include-process", f.IncludeProcesses},
		{"exclude-process", f.ExcludeProcesses},
	}
	for _, group := range processGroups {
		for _, pattern := range group.patterns {
			if _, err := filepath.Match(pattern, ""); err != nil {
				return fmt.Errorf("invalid %s pattern %q: %w", group.kind, pattern, err)
			}
		}
	}
	prefixGroups := []struct {
		kind     string
		prefixes []netip.Prefix
	}{
		{"include-destination", f.IncludeDestinations},
		{"exclude-destination", f.ExcludeDestinations},
	}
	for _, group := range prefixGroups {
		for _, prefix := range group.prefixes {
			if !prefix.IsValid() {
				return fmt.Errorf("invalid %s prefix", group.kind)
			}
		}
	}
	return nil
}

func (f Filter) Capture(flow Flow) bool {
	if matchesProcess(f.ExcludeProcesses, flow.Process) || matchesAddr(f.ExcludeDestinations, flow.OrigDst.Addr()) {
		return false
	}
	if len(f.IncludeProcesses) > 0 && !matchesProcess(f.IncludeProcesses, flow.Process) {
		return false
	}
	if len(f.IncludeDestinations) > 0 && !matchesAddr(f.IncludeDestinations, flow.OrigDst.Addr()) {
		return false
	}
	return true
}

func matchesProcess(patterns []string, p ProcessInfo) bool {
	for _, pattern := range patterns {
		if ok, _ := filepath.Match(pattern, p.Path); ok {
			return true
		}
		if ok, _ := filepath.Match(pattern, filepath.Base(p.Path)); ok {
			return true
		}
		if ok, _ := filepath.Match(pattern, p.SigningID); ok {
			return true
		}
	}
	return false
}

func matchesAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ReservedCapturePrefixes are the destinations no backend captures, whatever
// the filters say.
//
// Loopback and the unspecified address mean nothing on the far side of a
// proxy. Link-local carries DHCP fallback, router discovery, and on a cloud
// instance the metadata service at 169.254.169.254, which answers about the
// machine asking and cannot answer for a proxy somewhere else. Multicast and
// broadcast are not routable through SOCKS5 at all. Sending any of them
// upstream does not reroute them, it loses them.
//
// This is the floor rather than a default because a filter wide enough to want
// -- this project's own README suggests --include-destination 0.0.0.0/0 -- is
// wide enough to swallow all of them, and the failure shows up as a machine
// that stopped finding printers, or an instance that stopped knowing its own
// identity.
//
// It lives here rather than in one backend because every backend needs the
// same floor, and a second copy is a second thing to forget.
func ReservedCapturePrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("0.0.0.0/32"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("255.255.255.255/32"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
}

// IsReservedDestination reports whether an address is under the capture floor.
func IsReservedDestination(addr netip.Addr) bool {
	probe := addr
	if probe.Is4In6() {
		probe = probe.Unmap()
	}
	for _, prefix := range ReservedCapturePrefixes() {
		if prefix.Contains(probe) || prefix.Contains(addr) {
			return true
		}
	}
	return false
}
