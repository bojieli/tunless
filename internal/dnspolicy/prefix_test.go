package dnspolicy

import (
	"net/netip"
	"testing"
)

func prefixes(t *testing.T, values ...string) []netip.Prefix {
	t.Helper()
	parsed := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := ParsePrefix(value)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", value, err)
		}
		parsed = append(parsed, prefix)
	}
	return parsed
}

func TestPrefixSetCoversTheAddressesItWasGiven(t *testing.T) {
	set := NewPrefixSet(prefixes(t, "10.0.0.0/8", "203.0.113.0/24", "2001:db8::/32"))
	for _, addr := range []string{"10.0.0.1", "10.255.255.255", "203.0.113.7", "2001:db8::1"} {
		if !set.Contains(netip.MustParseAddr(addr)) {
			t.Errorf("Contains(%s) = false", addr)
		}
	}
	for _, addr := range []string{"11.0.0.1", "9.255.255.255", "203.0.114.1", "203.0.112.255", "2001:db9::1"} {
		if set.Contains(netip.MustParseAddr(addr)) {
			t.Errorf("Contains(%s) = true", addr)
		}
	}
}

func TestAdjacentAndOverlappingPrefixesCollapse(t *testing.T) {
	// Supplied lists routinely carry both. Collapsing them is not only cheaper:
	// it keeps the bisection from landing between two entries that jointly
	// cover the address it was asked about.
	// 10.0.0.0/16 ends at 10.0.255.255 and 10.1.0.0/24 begins at the next
	// address, so all four collapse into one range with nothing between them.
	set := NewPrefixSet(prefixes(t, "10.0.1.0/24", "10.0.0.0/24", "10.0.0.0/16", "10.1.0.0/24"))
	if got := set.Len(); got != 1 {
		t.Fatalf("Len() = %d, want the four to collapse into 1 range", got)
	}
	for _, addr := range []string{"10.0.0.1", "10.0.1.1", "10.0.255.255", "10.1.0.1", "10.1.0.255"} {
		if !set.Contains(netip.MustParseAddr(addr)) {
			t.Errorf("Contains(%s) = false after merging", addr)
		}
	}
	if set.Contains(netip.MustParseAddr("10.1.1.0")) {
		t.Error("merging ran past the end of the last prefix")
	}

	// A real gap survives, and the bisection has to cross it correctly.
	gapped := NewPrefixSet(prefixes(t, "10.0.0.0/24", "10.9.0.0/24", "10.5.0.0/24"))
	if got := gapped.Len(); got != 3 {
		t.Fatalf("Len() = %d, want 3 disjoint ranges", got)
	}
	for _, addr := range []string{"10.0.0.1", "10.5.0.1", "10.9.0.1"} {
		if !gapped.Contains(netip.MustParseAddr(addr)) {
			t.Errorf("Contains(%s) = false in a disjoint set", addr)
		}
	}
	for _, addr := range []string{"10.1.0.1", "10.4.255.255", "10.6.0.0", "10.8.255.255", "10.9.1.0"} {
		if gapped.Contains(netip.MustParseAddr(addr)) {
			t.Errorf("Contains(%s) = true inside a gap", addr)
		}
	}
}

func TestTheBoundariesOfEveryRangeAreIncluded(t *testing.T) {
	// An off-by-one at a range edge is the defect this structure is most likely
	// to have and the least likely to be noticed: it misroutes exactly one
	// network out of thousands.
	set := NewPrefixSet(prefixes(t, "192.0.2.0/24"))
	for _, addr := range []string{"192.0.2.0", "192.0.2.255"} {
		if !set.Contains(netip.MustParseAddr(addr)) {
			t.Errorf("Contains(%s) = false at a range boundary", addr)
		}
	}
	for _, addr := range []string{"192.0.1.255", "192.0.3.0"} {
		if set.Contains(netip.MustParseAddr(addr)) {
			t.Errorf("Contains(%s) = true just outside a range", addr)
		}
	}
}

func TestTheAddressFamiliesAreSeparate(t *testing.T) {
	// An IPv4-mapped IPv6 address is judged as the IPv4 address it carries,
	// because that is the address a connection to it would use.
	set := NewPrefixSet(prefixes(t, "203.0.113.0/24"))
	if !set.Contains(netip.MustParseAddr("::ffff:203.0.113.7")) {
		t.Error("a mapped address was not judged as the address it carries")
	}
	if set.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Error("a v6 address matched a v4-only set")
	}
	v6 := NewPrefixSet(prefixes(t, "2001:db8::/32"))
	if v6.Contains(netip.MustParseAddr("203.0.113.7")) {
		t.Error("a v4 address matched a v6-only set")
	}
}

func TestABareAddressIsAHostRoute(t *testing.T) {
	set := NewPrefixSet(prefixes(t, "203.0.113.7", "2001:db8::1"))
	if !set.Contains(netip.MustParseAddr("203.0.113.7")) || !set.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Error("a bare address did not become a host route")
	}
	if set.Contains(netip.MustParseAddr("203.0.113.8")) {
		t.Error("a bare address covered its neighbour")
	}
}

func TestTheWholeAddressSpaceDoesNotOverflowTheUpperBound(t *testing.T) {
	// The last address of a family has no successor, and the merge asks for one
	// when it tests adjacency.
	set := NewPrefixSet(prefixes(t, "0.0.0.0/0", "255.255.255.255/32"))
	if !set.Contains(netip.MustParseAddr("255.255.255.255")) {
		t.Error("the last address of the family was excluded")
	}
	v6 := NewPrefixSet(prefixes(t, "::/0"))
	if !v6.Contains(netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")) {
		t.Error("the last v6 address was excluded")
	}
}

func TestAnEmptySetContainsNothing(t *testing.T) {
	var nilSet *PrefixSet
	if !nilSet.Empty() || nilSet.Len() != 0 || nilSet.Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Error("a nil set behaved as though it covered something")
	}
	if !NewPrefixSet(nil).Empty() {
		t.Error("a set built from nothing was not empty")
	}
}

func TestInvalidPrefixesAreRejectedRatherThanIgnored(t *testing.T) {
	for _, value := range []string{"", "nonsense", "10.0.0.0/33", "10.0.0.0/-1", "2001:db8::/129"} {
		if _, err := ParsePrefix(value); err == nil {
			t.Errorf("ParsePrefix(%q) accepted an invalid entry", value)
		}
	}
}

func TestAnUnmaskedPrefixIsAcceptedAsTheNetworkItNames(t *testing.T) {
	// Lists written by hand carry 10.1.2.3/24 constantly. Rejecting it would be
	// pedantry; misreading it as a host route would silently shrink the set.
	prefix, err := ParsePrefix("10.1.2.3/24")
	if err != nil {
		t.Fatalf("ParsePrefix: %v", err)
	}
	set := NewPrefixSet([]netip.Prefix{prefix})
	if !set.Contains(netip.MustParseAddr("10.1.2.200")) {
		t.Error("an unmasked prefix did not cover its network")
	}
}

func BenchmarkPrefixSetContains(b *testing.B) {
	// Sized like a national address allocation, which is what operators
	// actually load here, and consulted once per address in every adjudicated
	// answer.
	var entries []netip.Prefix
	for i := range 9000 {
		addr := netip.AddrFrom4([4]byte{byte(i >> 8), byte(i), 0, 0})
		entries = append(entries, netip.PrefixFrom(addr, 24))
	}
	set := NewPrefixSet(entries)
	probe := netip.MustParseAddr("17.35.0.1")
	b.ResetTimer()
	for range b.N {
		set.Contains(probe)
	}
}
