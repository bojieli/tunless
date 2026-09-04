package socks5

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/bojieli/tunless/internal/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
)

// dnsAnswer builds a reply to query carrying the given addresses.
func dnsAnswer(t *testing.T, query []byte, name string, addresses ...string) []byte {
	t.Helper()
	encoded := dnsmessage.MustNewName(name)
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 binary.BigEndian.Uint16(query[:2]),
		Response:           true,
		RecursionAvailable: true,
	})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: encoded, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := builder.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, value := range addresses {
		addr := netip.MustParseAddr(value)
		if err := builder.AResource(
			dnsmessage.ResourceHeader{Name: encoded, Class: dnsmessage.ClassINET, TTL: 300},
			dnsmessage.AResource{A: addr.As4()},
		); err != nil {
			t.Fatal(err)
		}
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

type arbiterHarness struct {
	arbiter   *dnsArbiter
	delivered chan deliveredReply
	released  chan uint16
	// sentDirect counts queries actually put on the wire toward the direct
	// resolver, so a breaker that stops asking is observable.
	sentDirect chan []byte
}

type deliveredReply struct {
	payload []byte
	from    netip.AddrPort
}

func newArbiterHarness(t *testing.T, policy *dnspolicy.Policy) *arbiterHarness {
	t.Helper()
	h := &arbiterHarness{
		delivered:  make(chan deliveredReply, 8),
		released:   make(chan uint16, 8),
		sentDirect: make(chan []byte, 8),
	}
	// A relay aimed at a loopback port nothing is listening on: the send
	// succeeds because UDP has nothing to fail against, and no reply ever
	// arrives, so every direct answer in these tests is the one the test hands
	// over deliberately.
	relay := newDirectDatagramRelay(func([]byte, netip.AddrPort) {})
	t.Cleanup(relay.close)
	h.arbiter = newDNSArbiter(
		policy,
		relay,
		func(payload []byte, from netip.AddrPort) {
			h.delivered <- deliveredReply{payload, from}
		},
		func(id uint16) { h.released <- id },
		newDirectBreaker(),
		&DNSStats{},
	)
	// Timers are driven by the test rather than by the clock, so a deadline can
	// be reached without waiting for one.
	h.arbiter.afterFunc = func(time.Duration, func()) *time.Timer {
		timer := time.NewTimer(time.Hour)
		timer.Stop()
		return timer
	}
	return h
}

func (h *arbiterHarness) await(t *testing.T) deliveredReply {
	t.Helper()
	select {
	case reply := <-h.delivered:
		return reply
	case <-time.After(2 * time.Second):
		t.Fatal("nothing was delivered to the application")
		return deliveredReply{}
	}
}

func adjudicatingPolicy(t *testing.T) *dnspolicy.Policy {
	t.Helper()
	prefix, err := dnspolicy.ParsePrefix("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	return &dnspolicy.Policy{
		Prefixes:       dnspolicy.NewPrefixSet([]netip.Prefix{prefix}),
		DirectResolver: netip.MustParseAddrPort("127.0.0.1:15353"),
	}
}

func TestTheApplicationGetsItsOwnTransactionIDAndResolverBack(t *testing.T) {
	// The application never saw the identifier this process minted, and it
	// wrote to its own resolver rather than to either of ours. A reply carrying
	// the wrong one of either is a reply the client discards.
	policy := adjudicatingPolicy(t)
	h := newArbiterHarness(t, policy)
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")

	rewritten := dnsQuery(0x9999, "www", "example", "com")
	if !h.arbiter.begin(0x9999, 0x1234, appResolver, rewritten) {
		t.Fatal("begin declined a query")
	}
	h.arbiter.deliverDirect(dnsAnswer(t, rewritten, "www.example.com.", "203.0.113.7"), policy.DirectResolver)

	got := h.await(t)
	if id := binary.BigEndian.Uint16(got.payload[:2]); id != 0x1234 {
		t.Errorf("delivered ID = %#x, want the application's %#x", id, 0x1234)
	}
	if got.from != appResolver {
		t.Errorf("delivered from %s, want the resolver the application wrote to", got.from)
	}
	select {
	case id := <-h.released:
		if id != 0x9999 {
			t.Errorf("released %#x, want %#x", id, 0x9999)
		}
	case <-time.After(time.Second):
		t.Error("the transaction identifier was never released")
	}
}

func TestALateTrustedHalfIsDroppedAfterTheVerdict(t *testing.T) {
	// Both halves are asked, so the losing one is still in flight when the
	// verdict is reached. It carries the answer adjudication just rejected. If
	// the arbiter disowns it, the datapath treats it as an ordinary forwarded
	// reply and the application receives a second datagram — the rejected one.
	policy := adjudicatingPolicy(t)
	h := newArbiterHarness(t, policy)
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")

	rewritten := dnsQuery(0x9999, "www", "example", "com")
	if !h.arbiter.begin(0x9999, 0x1234, appResolver, rewritten) {
		t.Fatal("begin declined a query")
	}
	h.arbiter.deliverDirect(dnsAnswer(t, rewritten, "www.example.com.", "203.0.113.7"), policy.DirectResolver)
	served := h.await(t)
	if addresses := dnspolicy.ReplyAddresses(served.payload); len(addresses) != 1 || addresses[0].String() != "203.0.113.7" {
		t.Fatalf("served %v, want the direct answer", addresses)
	}

	late := dnsAnswer(t, rewritten, "www.example.com.", "192.0.2.9")
	if !h.arbiter.deliverTrusted(late, 0x9999) {
		t.Fatal("the late trusted half was disowned and would reach the application raw")
	}
	select {
	case extra := <-h.delivered:
		t.Fatalf("a second reply reached the application: %v", dnspolicy.ReplyAddresses(extra.payload))
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTheDeadlineRetiresASettledExchange(t *testing.T) {
	// The tombstone is what recognises a late half, but it must not outlive the
	// deadline: a long-lived flow would otherwise accumulate one per query. The
	// identifier went back at the verdict and must not go back a second time,
	// or a later exchange that has since been given it would lose it.
	policy := adjudicatingPolicy(t)
	h := newArbiterHarness(t, policy)
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")

	rewritten := dnsQuery(0x9999, "www", "example", "com")
	if !h.arbiter.begin(0x9999, 0x1234, appResolver, rewritten) {
		t.Fatal("begin declined a query")
	}
	h.arbiter.deliverDirect(dnsAnswer(t, rewritten, "www.example.com.", "203.0.113.7"), policy.DirectResolver)
	h.await(t)
	select {
	case id := <-h.released:
		if id != 0x9999 {
			t.Fatalf("released %#x, want %#x", id, 0x9999)
		}
	case <-time.After(time.Second):
		t.Fatal("the identifier was never released")
	}

	h.arbiter.expire(0x9999, true)
	if h.arbiter.deliverTrusted(dnsAnswer(t, rewritten, "www.example.com.", "192.0.2.9"), 0x9999) {
		t.Error("a retired exchange still claimed a datagram")
	}
	select {
	case id := <-h.released:
		t.Errorf("identifier %#x was released twice", id)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestTheTrustedHalfIsHeldUntilTheDirectHalfSettles(t *testing.T) {
	policy := adjudicatingPolicy(t)
	h := newArbiterHarness(t, policy)
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")
	rewritten := dnsQuery(0x4444, "www", "example", "com")
	h.arbiter.begin(0x4444, 0x1111, appResolver, rewritten)

	if !h.arbiter.deliverTrusted(dnsAnswer(t, rewritten, "www.example.com.", "192.0.2.9"), 0x4444) {
		t.Fatal("the arbiter did not claim its own trusted reply")
	}
	select {
	case <-h.delivered:
		t.Fatal("the trusted half was served before the direct half settled")
	case <-time.After(50 * time.Millisecond):
	}

	// The direct answer is outside the set, so the trusted one now wins.
	h.arbiter.deliverDirect(dnsAnswer(t, rewritten, "www.example.com.", "198.51.100.1"), policy.DirectResolver)
	got := h.await(t)
	addresses := dnspolicy.ReplyAddresses(got.payload)
	if len(addresses) != 1 || addresses[0].String() != "192.0.2.9" {
		t.Fatalf("delivered %v, want the trusted answer", addresses)
	}
}

func TestASuspectAnswerIsDeliveredAsAServerFailure(t *testing.T) {
	policy := adjudicatingPolicy(t)
	h := newArbiterHarness(t, policy)
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")
	rewritten := dnsQuery(0x5555, "www", "example", "com")
	h.arbiter.begin(0x5555, 0x2222, appResolver, rewritten)

	h.arbiter.deliverDirect(dnsAnswer(t, rewritten, "www.example.com.", "198.51.100.1"), policy.DirectResolver)
	// The trusted half never answers and the exchange runs out of time.
	h.arbiter.expire(0x5555, true)

	got := h.await(t)
	if binary.BigEndian.Uint16(got.payload[:2]) != 0x2222 {
		t.Error("the refusal did not carry the application's transaction ID")
	}
	if code := got.payload[3] & 0x0f; code != 2 {
		t.Errorf("rcode = %d, want 2 (SERVFAIL) rather than the suspect answer", code)
	}
}

func TestADatagramThatDoesNotAnswerTheQuestionDoesNotConsumeTheExchange(t *testing.T) {
	// Forging one is cheap for anyone who can guess the identifier. Letting it
	// settle the exchange would discard the real answer arriving behind it.
	policy := adjudicatingPolicy(t)
	h := newArbiterHarness(t, policy)
	rewritten := dnsQuery(0x6666, "www", "example", "com")
	h.arbiter.begin(0x6666, 0x3333, netip.MustParseAddrPort("192.168.1.1:53"), rewritten)

	// Right identifier, but not marked as a response.
	forged := dnsAnswer(t, rewritten, "www.example.com.", "203.0.113.7")
	forged[2] &^= 0x80
	h.arbiter.deliverDirect(forged, policy.DirectResolver)
	select {
	case <-h.delivered:
		t.Fatal("a datagram that is not a response settled the exchange")
	case <-time.After(50 * time.Millisecond):
	}

	h.arbiter.deliverDirect(dnsAnswer(t, rewritten, "www.example.com.", "203.0.113.7"), policy.DirectResolver)
	if got := h.await(t); binary.BigEndian.Uint16(got.payload[:2]) != 0x3333 {
		t.Error("the real answer was not delivered after the forged one")
	}
}

func TestADatagramFromSomewhereElseIsNotTakenAsTheDirectHalf(t *testing.T) {
	policy := adjudicatingPolicy(t)
	h := newArbiterHarness(t, policy)
	rewritten := dnsQuery(0x7777, "www", "example", "com")
	h.arbiter.begin(0x7777, 0x4444, netip.MustParseAddrPort("192.168.1.1:53"), rewritten)

	elsewhere := netip.MustParseAddrPort("198.51.100.53:53")
	if h.arbiter.deliverDirect(dnsAnswer(t, rewritten, "www.example.com.", "203.0.113.7"), elsewhere) {
		t.Fatal("a datagram from an address that is not the direct resolver was claimed")
	}
	select {
	case <-h.delivered:
		t.Fatal("a datagram from elsewhere settled the exchange")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestAnUnknownIdentifierIsDeclinedSoOrdinaryRepliesStillFlow(t *testing.T) {
	// The same relay carries answers to queries the name lists routed direct.
	// The arbiter has to hand those back rather than swallow them.
	policy := adjudicatingPolicy(t)
	h := newArbiterHarness(t, policy)
	stray := dnsAnswer(t, dnsQuery(0x0001, "www", "example", "com"), "www.example.com.", "203.0.113.7")
	if h.arbiter.deliverDirect(stray, policy.DirectResolver) {
		t.Fatal("the arbiter claimed a reply that belongs to no adjudication")
	}
	if h.arbiter.deliverTrusted(stray, 0x0001) {
		t.Fatal("the arbiter claimed a trusted reply that belongs to no adjudication")
	}
}

func TestClosingAbandonsEverythingOutstanding(t *testing.T) {
	policy := adjudicatingPolicy(t)
	h := newArbiterHarness(t, policy)
	rewritten := dnsQuery(0x8888, "www", "example", "com")
	h.arbiter.begin(0x8888, 0x5555, netip.MustParseAddrPort("192.168.1.1:53"), rewritten)
	h.arbiter.close()

	select {
	case <-h.released:
	case <-time.After(time.Second):
		t.Error("closing did not release the outstanding identifier")
	}
	if h.arbiter.begin(0x9999, 0x6666, netip.MustParseAddrPort("192.168.1.1:53"), rewritten) {
		t.Error("a closed arbiter accepted a new query")
	}
	// Nothing is delivered: the socket that asked has gone away.
	select {
	case <-h.delivered:
		t.Error("a closed arbiter delivered a reply")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestADirectResolverThatStopsAnsweringIsTakenOutOfThePath(t *testing.T) {
	// Without this, an unreachable direct resolver is not a degraded feature
	// but a host-wide slowdown: every unlisted name waits the full direct
	// window for an answer that is not coming.
	breaker := newDirectBreaker()
	now := time.Now()
	for range breaker.failuresBeforeOpen - 1 {
		breaker.fail(now)
		if !breaker.allow(now) {
			t.Fatal("the breaker opened before its budget was spent")
		}
	}
	breaker.fail(now)
	if breaker.allow(now) {
		t.Fatal("the breaker did not open after the failure budget")
	}
	if !breaker.open(now) {
		t.Error("open() disagrees with allow()")
	}
	// It closes again on its own, so a resolver that comes back is found
	// without a restart.
	later := now.Add(breaker.cooldown + time.Second)
	if !breaker.allow(later) {
		t.Fatal("the breaker never reopened")
	}
	if breaker.open(later) {
		t.Error("open() still reports a closed path")
	}
	// One success clears the count entirely.
	breaker.fail(later)
	breaker.succeed()
	for range breaker.failuresBeforeOpen - 1 {
		breaker.fail(later)
	}
	if !breaker.allow(later) {
		t.Error("a success did not clear the accumulated failures")
	}
}

func TestAnOpenBreakerSettlesTheExchangeOnTheTrustedHalfAlone(t *testing.T) {
	policy := adjudicatingPolicy(t)
	h := newArbiterHarness(t, policy)
	now := time.Now()
	for range h.arbiter.breaker.failuresBeforeOpen {
		h.arbiter.breaker.fail(now)
	}
	rewritten := dnsQuery(0xaaaa, "www", "example", "com")
	h.arbiter.begin(0xaaaa, 0x7777, netip.MustParseAddrPort("192.168.1.1:53"), rewritten)
	// The direct half is already settled, so the trusted answer decides on its
	// own with nothing to wait for.
	h.arbiter.deliverTrusted(dnsAnswer(t, rewritten, "www.example.com.", "192.0.2.9"), 0xaaaa)
	got := h.await(t)
	addresses := dnspolicy.ReplyAddresses(got.payload)
	if len(addresses) != 1 || addresses[0].String() != "192.0.2.9" {
		t.Fatalf("delivered %v, want the trusted answer served without waiting", addresses)
	}
	if h.arbiter.stats.directSkipped.Load() != 1 {
		t.Error("skipping the direct resolver was not counted")
	}
}

func TestANilArbiterIsInert(t *testing.T) {
	// The flow builds one only when the policy adjudicates, so every call site
	// has to tolerate its absence.
	var nilArbiter *dnsArbiter
	if !nilArbiter.begin(1, 2, netip.MustParseAddrPort("192.168.1.1:53"), nil) {
		t.Error("a nil arbiter refused to let the caller proceed")
	}
	if nilArbiter.deliverDirect(nil, netip.AddrPort{}) {
		t.Error("a nil arbiter claimed a datagram")
	}
	if nilArbiter.deliverTrusted(nil, 0) {
		t.Error("a nil arbiter claimed a trusted datagram")
	}
	nilArbiter.close()
}
