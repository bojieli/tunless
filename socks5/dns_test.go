package socks5

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/bojieli/tunless/internal/dnspolicy"
)

func dnsMessage(id uint16) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[:2], id)
	return message
}

func TestDNSTransactionIDsDisambiguateConcurrentResolvers(t *testing.T) {
	m := newDNSTransactionMap(8, time.Minute)
	override := netip.MustParseAddrPort("1.1.1.1:53")
	firstOriginal := netip.MustParseAddrPort("223.6.6.6:53")
	secondOriginal := netip.MustParseAddrPort("8.8.8.8:53")
	first, firstDestination, _, _ := m.prepare(dnsMessage(0x1234), firstOriginal, override)
	second, secondDestination, _, _ := m.prepare(dnsMessage(0x1234), secondOriginal, override)
	if firstDestination != override || secondDestination != override {
		t.Fatal("DNS queries were not routed to the override")
	}
	if binary.BigEndian.Uint16(first[:2]) == binary.BigEndian.Uint16(second[:2]) {
		t.Fatal("concurrent queries reused a translated transaction ID")
	}

	secondReply, secondSource := m.restore(second, override)
	firstReply, firstSource := m.restore(first, override)
	if secondSource != secondOriginal || firstSource != firstOriginal {
		t.Fatalf("restored sources = %s, %s", secondSource, firstSource)
	}
	if binary.BigEndian.Uint16(secondReply[:2]) != 0x1234 || binary.BigEndian.Uint16(firstReply[:2]) != 0x1234 {
		t.Fatal("original DNS transaction ID was not restored")
	}
}

func TestDNSTransactionMapExpiresAndBoundsEntries(t *testing.T) {
	now := time.Unix(100, 0)
	m := newDNSTransactionMap(2, time.Second)
	m.now = func() time.Time { return now }
	override := netip.MustParseAddrPort("1.1.1.1:53")
	original := netip.MustParseAddrPort("223.6.6.6:53")
	first, _, _, _ := m.prepare(dnsMessage(1), original, override)
	_, _, _, _ = m.prepare(dnsMessage(2), original, override)
	_, _, _, _ = m.prepare(dnsMessage(3), original, override)
	if len(m.entries) != 2 {
		t.Fatalf("entries = %d, want bounded size 2", len(m.entries))
	}
	now = now.Add(2 * time.Second)
	if _, source := m.restore(first, override); source != override {
		t.Fatalf("expired response source = %s, want untouched override", source)
	}
	if len(m.entries) != 0 {
		t.Fatalf("expired entries were not pruned: %d", len(m.entries))
	}
}

func TestDNSOverrideLeavesOtherTrafficUntouched(t *testing.T) {
	m := newDNSTransactionMap(8, time.Minute)
	override := netip.MustParseAddrPort("1.1.1.1:53")
	original := netip.MustParseAddrPort("203.0.113.1:443")
	payload := dnsMessage(7)
	got, destination, _, _ := m.prepare(payload, original, override)
	if destination != original || &got[0] != &payload[0] {
		t.Fatal("non-DNS traffic was modified")
	}
}

func TestTranslatedTransactionIDsAreUnpredictable(t *testing.T) {
	m := newDNSTransactionMap(4096, time.Minute)
	override := netip.MustParseAddrPort("1.1.1.1:53")
	original := netip.MustParseAddrPort("223.6.6.6:53")
	seen := make(map[uint16]struct{})
	var previous uint16
	consecutive := 0
	const queries = 256
	for i := range queries {
		translated, _, _, _ := m.prepare(dnsMessage(0x1234), original, override)
		id := binary.BigEndian.Uint16(translated[:2])
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("translated transaction ID %#04x was handed out twice", id)
		}
		seen[id] = struct{}{}
		if i > 0 && id == previous+1 {
			consecutive++
		}
		previous = id
	}
	// A counter scores queries-1 here. Independent draws land on their
	// predecessor's successor about once in 65,536, so anything above a couple
	// of hits means the IDs are being counted out rather than drawn.
	if consecutive > 4 {
		t.Fatalf("%d of %d translated IDs followed their predecessor; the allocator looks sequential", consecutive, queries-1)
	}
}

func TestTransactionIDAllocationSurvivesCollidingDraws(t *testing.T) {
	m := newDNSTransactionMap(8, time.Minute)
	m.random = func() uint16 { return 0x2000 }
	override := netip.MustParseAddrPort("1.1.1.1:53")
	first := netip.MustParseAddrPort("223.6.6.6:53")
	second := netip.MustParseAddrPort("8.8.8.8:53")
	one, _, _, _ := m.prepare(dnsMessage(0x1111), first, override)
	two, _, _, _ := m.prepare(dnsMessage(0x2222), second, override)
	if got := binary.BigEndian.Uint16(one[:2]); got != 0x2000 {
		t.Fatalf("first translated ID = %#04x, want %#04x", got, 0x2000)
	}
	if got := binary.BigEndian.Uint16(two[:2]); got != 0x2001 {
		t.Fatalf("second translated ID = %#04x, want the next free ID %#04x", got, 0x2001)
	}
	reply, source := m.restore(two, override)
	if source != second || binary.BigEndian.Uint16(reply[:2]) != 0x2222 {
		t.Fatalf("restored = %s/%#04x, want %s/%#04x", source, binary.BigEndian.Uint16(reply[:2]), second, 0x2222)
	}
}

// dnsQuery builds a query carrying one question, so the local-name split has
// something to read.
func dnsQuery(id uint16, labels ...string) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[:2], id)
	message[2] = 0x01                           // recursion desired
	binary.BigEndian.PutUint16(message[4:6], 1) // one question
	for _, label := range labels {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	return append(message, 0x00, 0x00, 0x01, 0x00, 0x01)
}

func TestLocalNamesKeepTheApplicationsOwnResolver(t *testing.T) {
	m := newDNSTransactionMap(8, time.Minute)
	override := netip.MustParseAddrPort("1.1.1.1:53")
	router := netip.MustParseAddrPort("192.168.3.1:53")

	// Only the resolver on this network knows what printer.local is.
	payload, destination, route := prepareRoute(m, dnsQuery(0x1234, "printer", "local"), router, override)
	if destination != router {
		t.Fatalf("local name was redirected to %s", destination)
	}
	// Not through the proxy either: a private resolver reached through a remote
	// node is as unanswerable as a public resolver that never heard of the name.
	if route != dnsRouteDirect {
		t.Fatal("local name was not routed around the proxy")
	}
	if binary.BigEndian.Uint16(payload[:2]) != 0x1234 {
		t.Fatal("local query had its transaction ID rewritten")
	}

	// A public name from the same resolver still takes the trusted path.
	_, destination, route = prepareRoute(m, dnsQuery(0x1234, "www", "google", "com"), router, override)
	if destination != override {
		t.Fatalf("public name was left with the network's resolver (%s)", destination)
	}
	if route == dnsRouteDirect {
		t.Fatal("public name bypassed the proxy")
	}

	// An operator-supplied split-horizon zone joins the local half.
	m.policy = &dnspolicy.Policy{LocalDomains: []string{"corp.example.com"}}
	_, destination, route = prepareRoute(m, dnsQuery(0x5678, "wiki", "corp", "example", "com"), router, override)
	if destination != router || route != dnsRouteDirect {
		t.Fatalf("operator local domain was redirected to %s (route=%v)", destination, route)
	}
}

func TestObservationSeesOnlyTrustedExchanges(t *testing.T) {
	m := newDNSTransactionMap(8, time.Minute)
	override := netip.MustParseAddrPort("1.1.1.1:53")
	router := netip.MustParseAddrPort("192.168.3.1:53")
	var pairs [][2][]byte
	m.observe = func(query, reply []byte) {
		pairs = append(pairs, [2][]byte{append([]byte(nil), query...), append([]byte(nil), reply...)})
	}

	// A rewritten query is remembered, and its answer is paired with it under
	// the translated ID the reply actually carries.
	sent, destination, _, _ := m.prepare(dnsQuery(0x1234, "www", "google", "com"), router, override)
	if destination != override {
		t.Fatal("query was not routed to the trusted resolver")
	}
	if _, source := m.restore(sent, override); source != router {
		t.Fatalf("reply source was restored to %s", source)
	}
	if len(pairs) != 1 {
		t.Fatalf("observed %d exchanges, want 1", len(pairs))
	}
	if binary.BigEndian.Uint16(pairs[0][0][:2]) != binary.BigEndian.Uint16(pairs[0][1][:2]) {
		t.Fatal("observed query and reply do not share a transaction ID")
	}

	// A local query never reaches the trusted resolver, so nothing about its
	// answer is learned: an address named by the network's own resolver must
	// not be able to decide what a later flow is proxied as.
	local, destination, _, _ := m.prepare(dnsQuery(0x4321, "printer", "local"), router, override)
	if destination != router {
		t.Fatal("local query was redirected")
	}
	m.restore(local, router)
	if len(pairs) != 1 {
		t.Fatalf("observed %d exchanges after a local query, want 1", len(pairs))
	}
}

func TestOversizedQueriesAreNotRetainedForObservation(t *testing.T) {
	m := newDNSTransactionMap(8, time.Minute)
	m.observe = func(query, reply []byte) { t.Fatal("oversized query was observed") }
	override := netip.MustParseAddrPort("1.1.1.1:53")
	original := netip.MustParseAddrPort("8.8.8.8:53")
	oversized := append(dnsQuery(0x1234, "www", "google", "com"), make([]byte, maxRememberedQuery)...)
	sent, destination, _, _ := m.prepare(oversized, original, override)
	if destination != override {
		t.Fatal("oversized query was not routed to the trusted resolver")
	}
	if _, source := m.restore(sent, override); source != original {
		t.Fatal("oversized query lost its reply mapping")
	}
}

func TestTheUpstreamsForwardedQueryIsRecognisedAndNotRelayedAgain(t *testing.T) {
	// Capture rewrites the transaction ID of every query it relays. The upstream
	// forwards that query verbatim, so the dial that would close the loop is
	// carrying an ID capture is still holding open, while an application's own
	// query to the same resolver is not.
	guard := newResolverLoopGuard()
	m := newDNSTransactionMap(8, time.Minute)
	m.loopGuard = guard
	override := netip.MustParseAddrPort("1.1.1.1:53")

	sent, destination, route := prepareRoute(m, dnsQuery(0x1234, "www", "google", "com"), override, override)
	if destination != override || route == dnsRouteDirect {
		t.Fatalf("query was not relayed to the trusted resolver (dst=%s route=%v)", destination, route)
	}
	// The upstream's forwarded copy carries the ID capture assigned.
	if !guard.relaying(sent) {
		t.Fatal("a query in flight was not recognised")
	}
	// An application's own query, with an ID capture never issued, is not.
	var unrelated uint16 = binary.BigEndian.Uint16(sent[:2]) + 1
	if guard.relaying(dnsQuery(unrelated, "www", "example", "com")) {
		t.Fatal("an unrelated query was mistaken for one in flight")
	}
	// Once the answer comes back the ID is no longer in flight.
	m.restore(sent, override)
	if guard.relaying(sent) {
		t.Fatal("a completed exchange still counted as in flight")
	}
}

func TestTheLoopGuardExpiresAndIsBounded(t *testing.T) {
	guard := newResolverLoopGuard()
	now := time.Now()
	guard.now = func() time.Time { return now }
	query := dnsQuery(0x4242, "www", "example", "com")
	guard.register(0x4242)
	if !guard.relaying(query) {
		t.Fatal("registered ID was not in flight")
	}
	// An entry outlives its exchange only when a reply never came, and the
	// lifetime is what bounds that.
	now = now.Add(guard.lifetime + time.Second)
	if guard.relaying(query) {
		t.Fatal("an expired entry still counted as in flight")
	}
	// A full table stops registering rather than evicting: dropping an entry to
	// make room would let the query it belonged to close the loop.
	guard.max = 2
	guard.register(1)
	guard.register(2)
	guard.register(3)
	if len(guard.inFlight) > 2 {
		t.Fatalf("guard held %d entries, want at most 2", len(guard.inFlight))
	}
}

// prepareRoute is prepare without the transaction identifier, which most of
// these tests do not need.
func prepareRoute(m *dnsTransactionMap, payload []byte, original, override netip.AddrPort) ([]byte, netip.AddrPort, dnsRoute) {
	prepared, destination, route, _ := m.prepare(payload, original, override)
	return prepared, destination, route
}

func adjudicatingMap(t *testing.T) (*dnsTransactionMap, *dnspolicy.Policy) {
	t.Helper()
	prefix, err := dnspolicy.ParsePrefix("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	suffixes := dnspolicy.NewSuffixSet()
	if err := suffixes.Add("direct.example", dnspolicy.RouteDirect); err != nil {
		t.Fatal(err)
	}
	if err := suffixes.Add("tunnel.example", dnspolicy.RouteTrusted); err != nil {
		t.Fatal(err)
	}
	policy := &dnspolicy.Policy{
		Suffixes:       suffixes,
		Prefixes:       dnspolicy.NewPrefixSet([]netip.Prefix{prefix}),
		DirectResolver: netip.MustParseAddrPort("223.5.5.5:53"),
	}
	m := newDNSTransactionMap(8, time.Minute)
	m.policy = policy
	m.stats = &DNSStats{}
	return m, policy
}

func TestADirectListedNameGoesToTheDirectResolverWithItsAddressesTracked(t *testing.T) {
	// The reply comes back from an address the application never wrote to, so
	// the identifier and the apparent source both have to be restored or the
	// kernel discards it on the connected socket every resolver client uses.
	m, policy := adjudicatingMap(t)
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")
	sent, destination, route, _ := m.prepare(dnsQuery(0x1234, "www", "direct", "example"), appResolver, netip.MustParseAddrPort("1.1.1.1:53"))
	if route != dnsRouteDirect {
		t.Fatalf("route = %v, want direct", route)
	}
	if destination != policy.DirectResolver {
		t.Fatalf("destination = %s, want the direct resolver", destination)
	}
	if binary.BigEndian.Uint16(sent[:2]) == 0x1234 {
		t.Error("the query kept the application's transaction ID on a rewritten destination")
	}
	restored, source := m.restore(sent, policy.DirectResolver)
	if binary.BigEndian.Uint16(restored[:2]) != 0x1234 {
		t.Error("the reply did not carry the application's transaction ID back")
	}
	if source != appResolver {
		t.Errorf("reply source = %s, want the resolver the application wrote to", source)
	}
}

func TestADirectAnswerIsNeverLearnedFrom(t *testing.T) {
	// The address-to-name associations this feeds decide which hostname a later
	// flow is proxied under. Learning one from an answer that arrived on the
	// network's own path lets whoever supplied that answer choose that name,
	// which is the poisoning the override exists to route around re-entering
	// one layer up.
	m, policy := adjudicatingMap(t)
	var observed int
	m.observe = func(query, reply []byte) { observed++ }
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")

	direct, _, route, _ := m.prepare(dnsQuery(0x1234, "www", "direct", "example"), appResolver, netip.MustParseAddrPort("1.1.1.1:53"))
	if route != dnsRouteDirect {
		t.Fatalf("route = %v, want direct", route)
	}
	m.restore(direct, policy.DirectResolver)
	if observed != 0 {
		t.Fatal("an answer from the direct resolver was recorded")
	}

	// The trusted path still feeds it, which is what name recovery runs on.
	trusted, _, route, _ := m.prepare(dnsQuery(0x5678, "www", "tunnel", "example"), appResolver, netip.MustParseAddrPort("1.1.1.1:53"))
	if route != dnsRouteProxy {
		t.Fatalf("route = %v, want proxy", route)
	}
	m.restore(trusted, netip.MustParseAddrPort("1.1.1.1:53"))
	if observed != 1 {
		t.Fatalf("trusted exchanges observed = %d, want 1", observed)
	}
}

func TestAnAdjudicatedExchangeIsNotLearnedFromEither(t *testing.T) {
	// The arbiter decides which half wins, and this map is not the arbiter. An
	// association recorded here would be recorded before that decision exists.
	m, _ := adjudicatingMap(t)
	var observed int
	m.observe = func(query, reply []byte) { observed++ }
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")
	sent, destination, route, id := m.prepare(dnsQuery(0x1234, "unlisted", "example", "net"), appResolver, netip.MustParseAddrPort("1.1.1.1:53"))
	if route != dnsRouteAdjudicate {
		t.Fatalf("route = %v, want adjudicate", route)
	}
	if destination != netip.MustParseAddrPort("1.1.1.1:53") {
		t.Fatalf("the trusted half was not aimed at the trusted resolver (%s)", destination)
	}
	if !m.adjudicating(id) {
		t.Fatal("the identifier was not marked as an adjudication")
	}
	// restore declines it, so the datapath hands it to the arbiter instead of
	// delivering it to the application.
	restored, source := m.restore(sent, netip.MustParseAddrPort("1.1.1.1:53"))
	if source != netip.MustParseAddrPort("1.1.1.1:53") || binary.BigEndian.Uint16(restored[:2]) != id {
		t.Error("restore delivered an adjudicated reply instead of leaving it to the arbiter")
	}
	if observed != 0 {
		t.Fatal("an adjudicated exchange was recorded")
	}
	m.finish(id)
	if m.adjudicating(id) {
		t.Fatal("the identifier survived being finished")
	}
}

func TestASaturatedMapStillProducesAnAnswerableQuery(t *testing.T) {
	// Running out of identifiers must not turn into a lookup nobody can answer.
	m, _ := adjudicatingMap(t)
	m.maxEntries = 0
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")
	sent, destination, route, _ := m.prepare(dnsQuery(0x1234, "www", "direct", "example"), appResolver, netip.MustParseAddrPort("1.1.1.1:53"))
	if route != dnsRouteDirect || destination != appResolver {
		t.Fatalf("route/destination = %v/%s, want the application's own resolver", route, destination)
	}
	if binary.BigEndian.Uint16(sent[:2]) != 0x1234 {
		t.Error("a query sent to the application's own resolver had its ID rewritten")
	}
}

func TestExpiryReleasesTheLoopGuardWithTheEntry(t *testing.T) {
	// The guard is what tells the upstream's forwarded copy apart from an
	// application's own query. An entry that expires without releasing it
	// leaves an identifier permanently claimed, and the guard's table is
	// deliberately small.
	guard := newResolverLoopGuard()
	m := newDNSTransactionMap(8, time.Nanosecond)
	m.loopGuard = guard
	override := netip.MustParseAddrPort("1.1.1.1:53")
	sent, _, _, _ := m.prepare(dnsQuery(0x1234, "www", "example", "com"), override, override)
	if !guard.relaying(sent) {
		t.Fatal("a query in flight was not registered")
	}
	time.Sleep(time.Millisecond)
	// Any later call prunes the expired entry.
	m.prepare(dnsQuery(0x5678, "other", "example", "com"), override, override)
	if guard.relaying(sent) {
		t.Error("an expired entry left its identifier claimed in the loop guard")
	}
}
