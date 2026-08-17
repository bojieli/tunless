package tunless

import (
	"net/netip"
	"path/filepath"
)

type Filter struct {
	IncludeProcesses    []string
	ExcludeProcesses    []string
	IncludeDestinations []netip.Prefix
	ExcludeDestinations []netip.Prefix
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
