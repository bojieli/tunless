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
