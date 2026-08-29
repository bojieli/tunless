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

func TestFilterValidateRejectsMalformedPatternsAndPrefixes(t *testing.T) {
	for _, filter := range []Filter{
		{IncludeProcesses: []string{"["}},
		{ExcludeProcesses: []string{"path["}},
		{IncludeDestinations: []netip.Prefix{{}}},
		{ExcludeDestinations: []netip.Prefix{{}}},
	} {
		if err := filter.Validate(); err == nil {
			t.Fatalf("accepted invalid filter: %+v", filter)
		}
	}
	if err := (Filter{IncludeProcesses: []string{"/usr/bin/*"}, IncludeDestinations: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}).Validate(); err != nil {
		t.Fatalf("rejected valid filter: %v", err)
	}
}

func TestDNSOverrideExemptsPortFiftyThreeFromDestinationRules(t *testing.T) {
	// A home network hands out the router as the resolver, and an operator who
	// excludes private space so their LAN is not proxied would otherwise make
	// the DNS override structurally unable to see the query it exists for.
	private := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	resolver := Flow{OrigDst: netip.MustParseAddrPort("192.168.3.1:53"), Process: ProcessInfo{Path: "/usr/bin/curl"}}
	web := Flow{OrigDst: netip.MustParseAddrPort("192.168.3.1:443"), Process: ProcessInfo{Path: "/usr/bin/curl"}}

	withOverride := Filter{ExcludeDestinations: private, DNSOverride: true}
	if !withOverride.Capture(resolver) {
		t.Fatal("port-53 flow to an excluded resolver was declined")
	}
	if withOverride.Capture(web) {
		t.Fatal("the exemption leaked to a flow that is not DNS")
	}

	// Without an override there is nothing to rewrite the query to, so the
	// operator's exclusion is the only instruction there is.
	withoutOverride := Filter{ExcludeDestinations: private}
	if withoutOverride.Capture(resolver) {
		t.Fatal("port-53 flow was captured with no override configured")
	}

	// An explicit allowlist narrows capture by address, and DNS is likewise not
	// what that allowlist is about.
	allowlist := Filter{IncludeDestinations: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, DNSOverride: true}
	if !allowlist.Capture(resolver) {
		t.Fatal("port-53 flow outside an include list was declined")
	}
}

func TestReservedDestinationsAndProcessRulesStillApplyToDNS(t *testing.T) {
	resolver := netip.MustParseAddrPort("1.1.1.1:53")
	// The upstream proxy dialing the trusted resolver is the loop the
	// reservation exists to prevent, and port 53 is the only port it happens
	// on, so the exemption must not reach it.
	reserved := Filter{
		ReservedDestinations: []netip.Prefix{netip.MustParsePrefix("1.1.1.1/32")},
		DNSOverride:          true,
	}
	if reserved.Capture(Flow{OrigDst: resolver, Process: ProcessInfo{Path: "/usr/bin/curl"}}) {
		t.Fatal("reserved resolver was captured")
	}
	// Naming the upstream process is the other half of the same protection.
	excluded := Filter{ExcludeProcesses: []string{"verge-mihomo"}, DNSOverride: true}
	if excluded.Capture(Flow{OrigDst: resolver, Process: ProcessInfo{Path: "/usr/local/bin/verge-mihomo"}}) {
		t.Fatal("excluded process had its DNS captured")
	}
	if !excluded.Capture(Flow{OrigDst: resolver, Process: ProcessInfo{Path: "/usr/bin/curl"}}) {
		t.Fatal("an unrelated process was declined")
	}
}

func TestAnApplicationsQueryToTheTrustedResolverIsCaptured(t *testing.T) {
	// Reserving the trusted resolver by address also declined every application
	// that had configured the same resolver — and 1.1.1.1 is both this project's
	// default and one of the most commonly configured resolvers there is, so the
	// people most likely to be protected were the ones who got nothing.
	resolver := netip.MustParseAddrPort("1.1.1.1:53")
	f := Filter{DNSOverride: true, TrustedResolver: resolver}
	datagram := Flow{Proto: UDP, OrigDst: resolver, Process: ProcessInfo{Path: "/usr/bin/curl"}}
	if !f.Capture(datagram) {
		t.Fatal("an application's own query to the trusted resolver was declined")
	}
	// A stream carries nothing to identify at connect time, so the loop guard
	// cannot police it and it stays reserved.
	stream := Flow{Proto: TCP, OrigDst: resolver, Process: ProcessInfo{Path: "/usr/bin/curl"}}
	if f.Capture(stream) {
		t.Fatal("a stream to the trusted resolver was captured")
	}
	// Another port on the same address is not the resolver at all.
	other := Flow{Proto: UDP, OrigDst: netip.MustParseAddrPort("1.1.1.1:443"), Process: ProcessInfo{Path: "/usr/bin/curl"}}
	if !other.OrigDst.IsValid() || !f.Capture(other) {
		t.Fatal("an unrelated port on the resolver's address was declined")
	}
	// The upstream itself is reserved on every transport.
	upstream := Filter{
		DNSOverride:          true,
		TrustedResolver:      resolver,
		ReservedDestinations: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	}
	if upstream.Capture(Flow{Proto: UDP, OrigDst: netip.MustParseAddrPort("127.0.0.1:53"), Process: ProcessInfo{Path: "/usr/bin/curl"}}) {
		t.Fatal("the upstream's address was captured")
	}
}

func TestDNSOverTCPToANetworkResolverIsLeftAlone(t *testing.T) {
	// The route has to be chosen before the name is visible, so capturing this
	// means committing to the trusted resolver for whatever it turns out to ask
	// — which breaks exactly the names the local resolver exists for.
	f := Filter{DNSOverride: true}
	for _, host := range []string{"192.168.3.1:53", "10.0.0.1:53", "100.64.0.1:53", "169.254.1.1:53"} {
		flow := Flow{Proto: TCP, OrigDst: netip.MustParseAddrPort(host), Process: ProcessInfo{Path: "/usr/bin/curl"}}
		if f.Capture(flow) {
			t.Errorf("DNS over TCP to %s was captured", host)
		}
		// The datagram carries its question, so it is still claimed and the
		// name-based split decides where it goes.
		datagram := Flow{Proto: UDP, OrigDst: netip.MustParseAddrPort(host), Process: ProcessInfo{Path: "/usr/bin/curl"}}
		if !f.Capture(datagram) {
			t.Errorf("DNS over UDP to %s was declined", host)
		}
	}
	// A public resolver has no local names to lose, so its streams are captured.
	public := Flow{Proto: TCP, OrigDst: netip.MustParseAddrPort("8.8.8.8:53"), Process: ProcessInfo{Path: "/usr/bin/curl"}}
	if !f.Capture(public) {
		t.Fatal("DNS over TCP to a public resolver was declined")
	}
}
