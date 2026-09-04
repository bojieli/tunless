package socks5

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/bojieli/tunless/internal/dnspolicy"
)

// dnsRoute is how one captured datagram leaves.
type dnsRoute uint8

const (
	// dnsRouteProxy sends the datagram through the SOCKS5 association to the
	// returned destination. Everything that is not DNS takes this route too,
	// addressed where the application addressed it.
	dnsRouteProxy dnsRoute = iota
	// dnsRouteDirect sends the datagram straight out of this process, bypassing
	// the proxy. See directDatagramRelay.
	dnsRouteDirect
	// dnsRouteAdjudicate sends the datagram through the proxy to the trusted
	// resolver and hands the transaction to the arbiter, which asks the direct
	// resolver in parallel and decides between the two answers.
	dnsRouteAdjudicate
)

// dnsTransactionMap translates DNS IDs while a UDP query is routed away from
// the resolver the application chose. Allocating a private ID for each
// outstanding query avoids ambiguous FIFO matching when applications reuse a
// 16-bit ID, send the same query to multiple resolvers, or receive replies out
// of order.
type dnsTransactionMap struct {
	mu         sync.Mutex
	entries    map[uint16]dnsTransaction
	maxEntries int
	ttl        time.Duration
	now        func() time.Time
	random     func() uint16
	// policy decides which resolver answers each query. A nil policy routes
	// every captured query to the trusted resolver, which is what this datapath
	// did before the policy existed.
	policy *dnspolicy.Policy
	// observe receives each query and the answer that came back for it, but
	// only for exchanges the trusted resolver answered. See rememberQuery.
	observe func(query, reply []byte)
	// loopGuard records the transaction IDs currently relayed, so the
	// upstream's own forwarded copy can be told apart from an application's
	// query to that same resolver. See resolverLoopGuard.
	loopGuard *resolverLoopGuard
	// stats counts what the policy decided.
	stats *DNSStats
}

type dnsTransaction struct {
	originalID uint16
	original   netip.AddrPort
	routed     netip.AddrPort
	expires    time.Time
	// query is the outbound message, retained only while an observer is
	// attached, only for trusted-path exchanges, and only up to
	// maxRememberedQuery bytes.
	query []byte
	// adjudicating marks an entry whose reply belongs to the arbiter rather
	// than to the application. The entry exists only to reserve the identifier
	// and its loop-guard registration; see dnsArbiter.
	adjudicating bool
}

// maxRememberedQuery bounds the copy of a query held for observation. A
// question section large enough to exceed this is not one whose answer is worth
// remembering an address for, and the bound keeps a saturated map from holding
// megabytes of pending queries.
const maxRememberedQuery = 512

func newDNSTransactionMap(maxEntries int, ttl time.Duration) *dnsTransactionMap {
	return &dnsTransactionMap{
		entries:    make(map[uint16]dnsTransaction),
		maxEntries: maxEntries,
		ttl:        ttl,
		now:        time.Now,
		random:     randomTransactionID,
	}
}

// prepare picks how one datagram leaves and rewrites it if it has to.
//
// The returned identifier is meaningful only for dnsRouteAdjudicate, where the
// caller hands it to the arbiter so both halves of the exchange can be matched
// back to the application that asked.
func (m *dnsTransactionMap) prepare(payload []byte, original, override netip.AddrPort) ([]byte, netip.AddrPort, dnsRoute, uint16) {
	if !override.IsValid() || original.Port() != 53 || len(payload) < 12 {
		return payload, original, dnsRouteProxy, 0
	}
	decision := m.decide(payload)
	m.stats.RecordDecision(decision)
	switch decision.Route {
	case dnspolicy.RouteLocal:
		// A name the local network owns has to reach the resolver that can
		// answer it, and has to get there without the proxy: redirecting it to
		// a trusted public resolver produces no answer, and relaying it to a
		// private address through a remote node produces no answer either. The
		// printer, the NAS and the router's own name exist only on this network.
		return payload, original, dnsRouteDirect, 0
	case dnspolicy.RouteDirect:
		return m.prepareDirect(payload, original)
	case dnspolicy.RouteAdjudicate:
		return m.prepareTracked(payload, original, override, true)
	default:
		prepared, destination, route, id := m.prepareTracked(payload, original, override, false)
		return prepared, destination, route, id
	}
}

// defaultDNSPolicy is what an unconfigured datapath uses: the trusted resolver
// for everything a public resolver can answer, and the application's own for
// everything only the local network can.
//
// The empty policy rather than a short-circuit, because the local-name split is
// not one of the preferences this package added. It is the difference between a
// working DNS override and one that breaks the printer, it predates every other
// layer here, and routing around it when nobody configured a name list would
// take a working behaviour away from operators who never asked for any of this.
var defaultDNSPolicy = &dnspolicy.Policy{}

// decide asks the policy, falling back to the default when none is set.
func (m *dnsTransactionMap) decide(payload []byte) dnspolicy.Decision {
	if m.policy == nil {
		return defaultDNSPolicy.Decide(payload)
	}
	return m.policy.Decide(payload)
}

// prepareDirect routes a query the operator sent down the direct path.
//
// With no direct resolver configured the query goes to the resolver the
// application already chose, unchanged, which is what makes the name lists
// usable without opting into answer-based selection at all. With one
// configured the destination changes, and so the identifier and the reply's
// apparent source have to be tracked: a datagram arriving from an address the
// application never wrote to is discarded by the kernel on the connected
// socket every resolver client uses.
func (m *dnsTransactionMap) prepareDirect(payload []byte, original netip.AddrPort) ([]byte, netip.AddrPort, dnsRoute, uint16) {
	resolver := m.policy.DirectResolver
	if !resolver.IsValid() || sameAddrPort(resolver, original) {
		return payload, original, dnsRouteDirect, 0
	}
	prepared, id, ok := m.track(payload, original, resolver, false, false)
	if !ok {
		// The map is saturated. Sending the query unrewritten to the resolver
		// the application chose is the one outcome that still produces an
		// answer it can use.
		return payload, original, dnsRouteDirect, 0
	}
	return prepared, resolver, dnsRouteDirect, id
}

// prepareTracked rewrites a query bound for the trusted resolver.
func (m *dnsTransactionMap) prepareTracked(payload []byte, original, override netip.AddrPort, adjudicating bool) ([]byte, netip.AddrPort, dnsRoute, uint16) {
	prepared, id, ok := m.track(payload, original, override, adjudicating, !adjudicating)
	if !ok {
		return payload, override, dnsRouteProxy, 0
	}
	if adjudicating {
		return prepared, override, dnsRouteAdjudicate, id
	}
	return prepared, override, dnsRouteProxy, id
}

// track allocates an identifier, records the exchange, and returns the
// rewritten query.
func (m *dnsTransactionMap) track(payload []byte, original, routed netip.AddrPort, adjudicating, observable bool) ([]byte, uint16, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.prune(now)
	if m.maxEntries <= 0 {
		return nil, 0, false
	}
	if len(m.entries) >= m.maxEntries {
		m.evictOldest()
	}
	translated, ok := m.allocateID()
	if !ok {
		return nil, 0, false
	}
	copyPayload := append([]byte(nil), payload...)
	originalID := binary.BigEndian.Uint16(copyPayload[:2])
	binary.BigEndian.PutUint16(copyPayload[:2], translated)
	entry := dnsTransaction{
		originalID:   originalID,
		original:     original,
		routed:       routed,
		expires:      now.Add(m.ttl),
		adjudicating: adjudicating,
	}
	if observable {
		// The translated copy, not the application's original: the reply will
		// come back carrying the translated ID, and the observer pairs a query
		// with a reply by matching it.
		entry.query = m.rememberQuery(copyPayload)
	}
	m.entries[translated] = entry
	// Registered before the datagram leaves, so the upstream's forwarded copy
	// can never arrive ahead of the record that identifies it.
	m.loopGuard.register(translated)
	return copyPayload, translated, true
}

// rememberQuery keeps the outbound message when an observer is attached, so the
// answer can be paired with the question that produced it.
//
// Only queries the trusted resolver answered are remembered, and therefore only
// their answers are ever observed. That is deliberate, and it is what keeps
// answer-based selection from weakening the guarantee it was added underneath.
// The address-to-name associations this feeds decide which hostname a later
// flow is proxied under, so learning one from an answer that arrived on the
// network's own path would let whoever supplied that answer choose the name —
// which is the poisoning this whole path exists to route around, re-entering
// one layer up. An adjudicated exchange is excluded for the same reason even
// when the trusted half is the one that won, because the arbiter is what
// decided that and the arbiter is not this map.
func (m *dnsTransactionMap) rememberQuery(payload []byte) []byte {
	if m.observe == nil || len(payload) > maxRememberedQuery {
		return nil
	}
	return append([]byte(nil), payload...)
}

// adjudicating reports whether an outstanding identifier belongs to the
// arbiter.
func (m *dnsTransactionMap) adjudicating(id uint16) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.entries[id]
	return ok && entry.adjudicating
}

// finish releases an identifier the arbiter is done with.
func (m *dnsTransactionMap) finish(id uint16) {
	m.mu.Lock()
	delete(m.entries, id)
	m.mu.Unlock()
	m.loopGuard.release(id)
}

func (m *dnsTransactionMap) restore(payload []byte, source netip.AddrPort) ([]byte, netip.AddrPort) {
	if len(payload) < 12 {
		return payload, source
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.prune(now)
	translated := binary.BigEndian.Uint16(payload[:2])
	entry, ok := m.entries[translated]
	if !ok || entry.adjudicating || !sameAddrPort(entry.routed, source) {
		return payload, source
	}
	delete(m.entries, translated)
	m.loopGuard.release(translated)
	copyPayload := append([]byte(nil), payload...)
	binary.BigEndian.PutUint16(copyPayload[:2], entry.originalID)
	if m.observe != nil && entry.query != nil {
		// The reply still carries the translated ID here, which is the ID the
		// remembered query carries too, so the observer's own matching check
		// sees the pair as the exchange it was.
		m.observe(entry.query, payload)
	}
	return copyPayload, entry.original
}

// allocateID picks the private transaction ID a rewritten query will carry.
//
// The ID has to be drawn at random, not counted out. A resolver client picks
// its own ID unpredictably so that an attacker who cannot see the query cannot
// forge an answer to it (RFC 5452); rewriting replaces that ID with this one,
// so anything less than the same unpredictability hands every captured lookup
// on the machine a weaker answer than it would have had unproxied.
func (m *dnsTransactionMap) allocateID() (uint16, bool) {
	// Outstanding queries are bounded far below the 16-bit space, so the first
	// draw is almost always free.
	for range 8 {
		candidate := m.random()
		if _, exists := m.entries[candidate]; !exists {
			return candidate, true
		}
	}
	// Reached only when the space is unusually crowded. Walk upward from a
	// random start rather than from zero, so even the fallback does not settle
	// into a sequence someone can follow.
	candidate := m.random()
	for range 1 << 16 {
		if _, exists := m.entries[candidate]; !exists {
			return candidate, true
		}
		candidate++
	}
	return 0, false
}

func randomTransactionID() uint16 {
	var buffer [2]byte
	// crypto/rand.Read fills the buffer or stops the program; it cannot come
	// back short or with an error. Failing loudly is the right outcome for a
	// draw whose only job is being unguessable.
	_, _ = rand.Read(buffer[:])
	return binary.BigEndian.Uint16(buffer[:])
}

func (m *dnsTransactionMap) prune(now time.Time) {
	for id, entry := range m.entries {
		if !now.Before(entry.expires) {
			delete(m.entries, id)
			m.loopGuard.release(id)
		}
	}
}

func (m *dnsTransactionMap) evictOldest() {
	var oldestID uint16
	var oldest time.Time
	found := false
	for id, entry := range m.entries {
		if !found || entry.expires.Before(oldest) {
			oldestID, oldest, found = id, entry.expires, true
		}
	}
	if found {
		delete(m.entries, oldestID)
		m.loopGuard.release(oldestID)
	}
}
