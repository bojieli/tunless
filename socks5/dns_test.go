package socks5

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
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
	first, firstDestination, _ := m.prepare(dnsMessage(0x1234), firstOriginal, override)
	second, secondDestination, _ := m.prepare(dnsMessage(0x1234), secondOriginal, override)
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
	first, _, _ := m.prepare(dnsMessage(1), original, override)
	_, _, _ = m.prepare(dnsMessage(2), original, override)
	_, _, _ = m.prepare(dnsMessage(3), original, override)
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
	got, destination, _ := m.prepare(payload, original, override)
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
		translated, _, _ := m.prepare(dnsMessage(0x1234), original, override)
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
	one, _, _ := m.prepare(dnsMessage(0x1111), first, override)
	two, _, _ := m.prepare(dnsMessage(0x2222), second, override)
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
	payload, destination, direct := m.prepare(dnsQuery(0x1234, "printer", "local"), router, override)
	if destination != router {
		t.Fatalf("local name was redirected to %s", destination)
	}
	// Not through the proxy either: a private resolver reached through a remote
	// node is as unanswerable as a public resolver that never heard of the name.
	if !direct {
		t.Fatal("local name was not routed around the proxy")
	}
	if binary.BigEndian.Uint16(payload[:2]) != 0x1234 {
		t.Fatal("local query had its transaction ID rewritten")
	}

	// A public name from the same resolver still takes the trusted path.
	_, destination, direct = m.prepare(dnsQuery(0x1234, "www", "google", "com"), router, override)
	if destination != override {
		t.Fatalf("public name was left with the network's resolver (%s)", destination)
	}
	if direct {
		t.Fatal("public name bypassed the proxy")
	}

	// An operator-supplied split-horizon zone joins the local half.
	m.localDomains = []string{"corp.example.com"}
	_, destination, direct = m.prepare(dnsQuery(0x5678, "wiki", "corp", "example", "com"), router, override)
	if destination != router || !direct {
		t.Fatalf("operator local domain was redirected to %s (direct=%v)", destination, direct)
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
	sent, destination, _ := m.prepare(dnsQuery(0x1234, "www", "google", "com"), router, override)
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
	local, destination, _ := m.prepare(dnsQuery(0x4321, "printer", "local"), router, override)
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
	sent, destination, _ := m.prepare(oversized, original, override)
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

	sent, destination, direct := m.prepare(dnsQuery(0x1234, "www", "google", "com"), override, override)
	if destination != override || direct {
		t.Fatalf("query was not relayed to the trusted resolver (dst=%s direct=%v)", destination, direct)
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
