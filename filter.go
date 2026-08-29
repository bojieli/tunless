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
	// ReservedDestinations are the addresses tunless itself relays through and
	// must never send back into: the SOCKS5 upstream. They are excluded from
	// capture whatever else the configuration says, and unlike
	// ExcludeDestinations they keep applying to port-53 flows.
	ReservedDestinations []netip.Prefix
	// TrustedResolver is the address captured port-53 flows are rewritten to.
	//
	// It is reserved like the upstream, with one exception: a captured datagram
	// carries the transaction ID capture assigned it, so the upstream's own
	// forwarded copy of a query is recognisable and sent direct, which leaves an
	// application's query to that same resolver free to be claimed like any
	// other. Reserving it by address instead meant that anyone who had already
	// configured a good resolver got no override at all. A stream carries nothing
	// to recognise at connect time, so it stays reserved.
	TrustedResolver netip.AddrPort
	// DNSOverride reports whether captured port-53 flows are rewritten to a
	// trusted resolver. When they are, operator destination rules stop applying
	// to them; see Capture.
	DNSOverride bool
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
	if matchesProcess(f.ExcludeProcesses, flow.Process) {
		return false
	}
	if len(f.IncludeProcesses) > 0 && !matchesProcess(f.IncludeProcesses, flow.Process) {
		return false
	}
	if matchesAddr(f.ReservedDestinations, flow.OrigDst.Addr()) {
		return false
	}
	if f.reservesResolver(flow) {
		return false
	}
	// A stream to a resolver on this network is declined, and the reason is that
	// the route has to be chosen before the name is visible. A datagram carries
	// its question in the first packet, so a name only the local network can
	// answer is recognised and sent to the resolver that has it. A DNS-over-TCP
	// connection announces nothing at connect time, so capturing it means
	// committing to the trusted resolver for whatever it turns out to ask, which
	// breaks exactly the names the local resolver exists for.
	if f.DNSOverride && flow.Proto == TCP && flow.OrigDst.Port() == 53 && isNetworkResolver(flow.OrigDst.Addr()) {
		return false
	}
	if f.destinationRulesApply(flow) {
		if matchesAddr(f.ExcludeDestinations, flow.OrigDst.Addr()) {
			return false
		}
		if len(f.IncludeDestinations) > 0 && !matchesAddr(f.IncludeDestinations, flow.OrigDst.Addr()) {
			return false
		}
	}
	return true
}

// reservesResolver reports whether this flow is aimed at the trusted resolver on
// a transport where the loop guard cannot tell the upstream's own forwarded
// query from an application's. See Filter.TrustedResolver.
func (f Filter) reservesResolver(flow Flow) bool {
	if !f.TrustedResolver.IsValid() {
		return false
	}
	if flow.OrigDst.Port() != f.TrustedResolver.Port() {
		return false
	}
	if flow.OrigDst.Addr().Unmap() != f.TrustedResolver.Addr().Unmap() {
		return false
	}
	return !(flow.Proto == UDP && flow.OrigDst.Port() == 53)
}

// isNetworkResolver reports whether an address is where a resolver handed out by
// this network lives: private space, carrier-grade NAT, loopback, or link-local.
func isNetworkResolver(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		cgnat.Contains(addr)
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// destinationRulesApply reports whether the operator's destination selection
// governs this flow.
//
// It governs every flow but one. A resolver's address is not a destination the
// application chose to reach — it is a resolver the network handed out, and
// rewriting it to a trusted one is the entire point of the DNS override. So
// judging a port-53 flow by that address asks the wrong question, and answers
// it in the direction that silently breaks: a home network hands out the router
// as the resolver, the router is inside 192.168.0.0/16, an operator excludes
// private space so that a proxy is not put in front of their own LAN, and the
// override is then structurally unable to see the one flow it exists for. What
// makes that failure hard to find is that nothing reports an error. Queries go
// out on the network's own path, come back with whatever that path decided to
// answer, and every name on the host resolves to it.
//
// Process rules still apply. They are how the upstream proxy is kept out of its
// own datapath, and a port-53 flow from the upstream is exactly the flow that
// must not be handed back to it.
func (f Filter) destinationRulesApply(flow Flow) bool {
	return !f.DNSOverride || flow.OrigDst.Port() != 53
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
