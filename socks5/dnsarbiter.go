package socks5

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/bojieli/tunless/internal/dnspolicy"
	"github.com/bojieli/tunless/internal/dnswire"
)

// dnsArbiter runs the exchanges that answer-based selection needs.
//
// Every other DNS path in this file forwards: a datagram arrives, it is
// rewritten, it leaves, and the reply is rewritten back. Adjudication cannot be
// expressed that way. It has one question, two answers, and a decision that
// belongs to neither of them, so the query has to be held while both resolvers
// are asked and a single reply synthesised for the application afterwards. That
// is the whole reason this type exists, and it is deliberately the only place
// in the datapath that holds a query.
//
// It is bounded in every direction that matters. An adjudication occupies one
// transaction ID, which is the same ceiling forwarding already has; it is
// abandoned at a deadline whether or not anyone answered; and a direct resolver
// that stops answering is taken out of the path entirely rather than being
// waited on once per lookup for as long as it stays down.
type dnsArbiter struct {
	policy *dnspolicy.Policy
	// direct sends to the direct resolver and delivers what comes back here,
	// rather than to the application the way the flow's own relay does.
	direct *directDatagramRelay
	// deliver hands the concluded reply to the application, addressed from the
	// resolver it believed it was asking.
	deliver func(payload []byte, from netip.AddrPort)
	// release frees the transaction ID and its loop-guard registration once an
	// adjudication can no longer receive anything.
	release func(id uint16)
	breaker *directBreaker
	stats   *DNSStats
	now     func() time.Time
	// afterFunc is time.AfterFunc, replaced in tests so a deadline can be
	// reached without waiting for one.
	afterFunc func(time.Duration, func()) *time.Timer

	mu      sync.Mutex
	pending map[uint16]*adjudication
	closed  bool
}

// adjudication is one query held while both resolvers are asked.
type adjudication struct {
	originalID uint16
	// original is the resolver address the application wrote to, which the
	// concluded reply has to appear to come from. A datagram arriving from
	// anywhere else is discarded by the kernel on a connected socket, which is
	// every resolver client worth naming.
	original netip.AddrPort
	query    []byte
	exchange dnspolicy.Exchange
	timers   []*time.Timer
	settled  bool
}

func newDNSArbiter(
	policy *dnspolicy.Policy,
	direct *directDatagramRelay,
	deliver func([]byte, netip.AddrPort),
	release func(uint16),
	breaker *directBreaker,
	stats *DNSStats,
) *dnsArbiter {
	return &dnsArbiter{
		policy:    policy,
		direct:    direct,
		deliver:   deliver,
		release:   release,
		breaker:   breaker,
		stats:     stats,
		now:       time.Now,
		afterFunc: time.AfterFunc,
		pending:   make(map[uint16]*adjudication),
	}
}

// begin holds a query and asks both resolvers.
//
// The query handed here has already had its transaction ID rewritten, and the
// same rewritten query goes to both resolvers. One identifier for both halves
// keeps the two replies matchable by the socket they arrived on rather than by
// anything a third party could arrange to collide with, and it keeps the
// unpredictable identifier the rewrite exists to preserve in front of both.
//
// It reports whether the trusted half should be sent by the caller. It always
// should, unless the arbiter is shutting down: the direct half is this type's
// business, the trusted half travels on the flow's own SOCKS association and
// stays the caller's.
func (a *dnsArbiter) begin(id, originalID uint16, original netip.AddrPort, query []byte) bool {
	if a == nil {
		return true
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return false
	}
	entry := &adjudication{
		originalID: originalID,
		original:   original,
		query:      append([]byte(nil), query...),
	}
	a.pending[id] = entry
	// A direct resolver that has stopped answering is not asked. Without this a
	// resolver that is merely unreachable costs every single lookup the whole
	// direct window before the trusted answer is served, which turns one
	// misconfiguration into a host-wide latency floor that looks like the proxy
	// being slow.
	askDirect := a.breaker.allow(a.now())
	if askDirect {
		entry.timers = append(entry.timers, a.afterFunc(dnspolicy.DirectReplyWindow, func() {
			a.expire(id, false)
		}))
	} else {
		entry.exchange.DirectDone = true
		a.stats.directSkipped.Add(1)
	}
	entry.timers = append(entry.timers, a.afterFunc(dnspolicy.AdjudicationDeadline, func() {
		a.expire(id, true)
	}))
	a.mu.Unlock()
	if askDirect && !a.direct.send(query, a.policy.DirectResolver) {
		a.stats.directSendFailed.Add(1)
		a.completeDirect(id, nil)
	}
	return true
}

// deliverDirect offers a datagram that arrived from the direct resolver,
// reporting whether it belonged to an adjudication. A datagram this declines is
// the answer to a query the name lists routed here, and the caller delivers it
// the ordinary way.
func (a *dnsArbiter) deliverDirect(payload []byte, from netip.AddrPort) bool {
	if a == nil || len(payload) < 2 || !sameAddrPort(from, a.policy.DirectResolver) {
		return false
	}
	return a.completeDirect(binary.BigEndian.Uint16(payload[:2]), payload)
}

// deliverTrusted offers a datagram that came back through the proxy, reporting
// whether it belonged to an adjudication. A datagram this declines is an
// ordinary forwarded reply and the caller delivers it the usual way.
func (a *dnsArbiter) deliverTrusted(payload []byte, id uint16) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	entry, ok := a.pending[id]
	if !ok || entry.settled {
		a.mu.Unlock()
		return ok
	}
	if !dnswire.AnswersQuery(entry.query, payload) {
		// Not an answer to the question that is outstanding. Claimed anyway,
		// because the identifier is one this process minted and nothing else on
		// the host is entitled to it, and dropping it here keeps a forged
		// datagram from consuming the exchange the real answer belongs to.
		a.mu.Unlock()
		return true
	}
	entry.exchange.Trusted = append([]byte(nil), payload...)
	entry.exchange.TrustedDone = true
	a.evaluateLocked(id, entry)
	a.mu.Unlock()
	return true
}

// completeDirect records the direct half's result, whether an answer or a
// failure, reporting whether the identifier belonged to an adjudication.
func (a *dnsArbiter) completeDirect(id uint16, payload []byte) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.pending[id]
	if !ok {
		return false
	}
	if entry.settled || entry.exchange.DirectDone {
		return true
	}
	if payload != nil && !dnswire.AnswersQuery(entry.query, payload) {
		// Claimed but not believed. The identifier is one this process minted,
		// so nothing else on the host is entitled to it, and dropping a
		// mismatched datagram here keeps a forged one from consuming the
		// exchange the real answer belongs to.
		return true
	}
	if payload != nil {
		entry.exchange.Direct = append([]byte(nil), payload...)
		a.breaker.succeed()
	} else {
		a.breaker.fail(a.now())
	}
	entry.exchange.DirectDone = true
	a.evaluateLocked(id, entry)
	return true
}

// expire marks a window or the deadline as reached.
func (a *dnsArbiter) expire(id uint16, deadline bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, ok := a.pending[id]
	if !ok || entry.settled {
		return
	}
	if deadline {
		entry.exchange.DeadlineReached = true
	} else {
		entry.exchange.DirectWindowClosed = true
		if !entry.exchange.DirectDone {
			// A direct resolver that missed its window on this query is one
			// step closer to being taken out of the path. Counted here rather
			// than at the deadline so a resolver that is slow rather than dead
			// is still measured as failing.
			a.breaker.fail(a.now())
		}
	}
	a.evaluateLocked(id, entry)
}

// evaluateLocked asks the policy whether the exchange has settled, and
// concludes it when it has. The caller holds a.mu.
func (a *dnsArbiter) evaluateLocked(id uint16, entry *adjudication) {
	verdict, reason := a.policy.Adjudicate(entry.exchange)
	if verdict == dnspolicy.VerdictWait {
		return
	}
	entry.settled = true
	delete(a.pending, id)
	for _, timer := range entry.timers {
		timer.Stop()
	}
	a.stats.recordVerdict(verdict, reason)
	var reply []byte
	switch verdict {
	case dnspolicy.VerdictServeDirect:
		reply = entry.exchange.Direct
	case dnspolicy.VerdictServeTrusted:
		reply = entry.exchange.Trusted
	case dnspolicy.VerdictRefuse:
		reply = dnspolicy.Refusal(entry.query)
	}
	if a.release != nil {
		a.release(id)
	}
	if len(reply) < 2 {
		return
	}
	// The application is owed its own transaction ID back. It never saw the one
	// this process minted, and a reply carrying an identifier the client did not
	// choose is a reply the client discards.
	final := append([]byte(nil), reply...)
	binary.BigEndian.PutUint16(final[:2], entry.originalID)
	original := entry.original
	deliver := a.deliver
	// Delivered outside the lock: the application's packet port can block, and
	// blocking here would stall every other adjudication on this flow behind
	// one slow consumer.
	go func() { deliver(final, original) }()
}

// close abandons everything outstanding. Nothing is delivered, which is what a
// flow going away means: the socket that asked is gone.
func (a *dnsArbiter) close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closed = true
	for id, entry := range a.pending {
		for _, timer := range entry.timers {
			timer.Stop()
		}
		if a.release != nil {
			a.release(id)
		}
		delete(a.pending, id)
	}
}

// directBreaker takes a direct resolver that has stopped answering out of the
// adjudication path, and puts it back when it starts answering again.
//
// Without it, an unreachable direct resolver is not a degraded feature but a
// host-wide slowdown: every unlisted name waits the full direct window before
// the trusted answer it was always going to get is served. With it the cost is
// paid a handful of times and then stops, and a resolver that comes back is
// found by the next probe rather than by a restart.
//
// It is shared across flows on purpose. Reachability is a property of the
// resolver and the network, not of the socket that happened to ask, and a
// per-flow breaker would relearn the same outage once per application.
type directBreaker struct {
	failuresBeforeOpen int
	cooldown           time.Duration

	mu          sync.Mutex
	consecutive int
	openUntil   time.Time
}

func newDirectBreaker() *directBreaker {
	return &directBreaker{
		// More than one, because a single lookup can lose a race with a network
		// change. Not many more, because every one of them costs a lookup the
		// full direct window.
		failuresBeforeOpen: 5,
		// Long enough that a resolver which is genuinely down is not probed once
		// per lookup, short enough that one which came back is used again before
		// anybody thinks to restart anything.
		cooldown: 30 * time.Second,
	}
}

// allow reports whether the direct resolver should be asked, and lets exactly
// one query through when the cooldown has elapsed so recovery is observed
// rather than assumed.
func (b *directBreaker) allow(now time.Time) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.IsZero() || now.After(b.openUntil) {
		b.openUntil = time.Time{}
		return true
	}
	return false
}

func (b *directBreaker) fail(now time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecutive++
	if b.consecutive >= b.failuresBeforeOpen {
		b.openUntil = now.Add(b.cooldown)
		b.consecutive = 0
	}
}

func (b *directBreaker) succeed() {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecutive = 0
	b.openUntil = time.Time{}
}

// open reports whether the direct resolver is currently out of the path.
func (b *directBreaker) open(now time.Time) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.openUntil.IsZero() && !now.After(b.openUntil)
}
