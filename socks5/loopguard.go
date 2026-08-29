package socks5

import (
	"encoding/binary"
	"sync"
	"time"
)

// resolverLoopGuard breaks the one loop that stops capture from claiming an
// application's own query to the trusted resolver.
//
// The trusted resolver used to be reserved by address: capture declined every
// port-53 flow addressed to it, whatever asked. That is a real protection —
// capture rewrites port-53 flows to that resolver and relays them to the
// upstream, the upstream then dials the resolver itself, and if that dial were
// captured too the query would be handed back to the upstream waiting on it.
// Nothing errors. Every lookup on the host recurses until it times out, which
// reads as a dead network rather than as a proxy loop.
//
// Doing it by address costs coverage. An application configured to use that same
// resolver — and 1.1.1.1 is both this project's default and one of the most
// commonly configured resolvers there is — was declined for the same reason, so
// the override never saw the queries of anyone who had already chosen well.
//
// The two flows are distinguishable without reserving the address. Capture
// rewrites the transaction ID of every query it relays, to an ID drawn at random
// that the application never chose. The upstream forwards that query verbatim,
// so the dial that would close the loop carries an ID capture is still holding
// open, while an application's own query to the same resolver does not.
//
// A false positive costs one query the override: an application whose own
// transaction ID collides with one in flight, while querying the resolver
// capture relays to, has that datagram sent direct. That is what every such
// query did before this existed, it lasts one datagram, and the client retries.
type resolverLoopGuard struct {
	mu       sync.Mutex
	inFlight map[uint16]time.Time
	lifetime time.Duration
	max      int
	now      func() time.Time
}

func newResolverLoopGuard() *resolverLoopGuard {
	return &resolverLoopGuard{
		inFlight: make(map[uint16]time.Time),
		// Longer than the response map's own timeout, so the guard is never the
		// first thing to forget an exchange that is still outstanding.
		lifetime: time.Minute,
		max:      8192,
		now:      time.Now,
	}
}

func (g *resolverLoopGuard) register(id uint16) {
	if g == nil {
		return
	}
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.prune(now)
	// A full table stops registering rather than evicting. Dropping an entry to
	// make room would let the query it belonged to close the loop, and a guard
	// that forgets under load forgets exactly when a loop is running.
	if _, exists := g.inFlight[id]; !exists && len(g.inFlight) >= g.max {
		return
	}
	g.inFlight[id] = now.Add(g.lifetime)
}

func (g *resolverLoopGuard) release(id uint16) {
	if g == nil {
		return
	}
	g.mu.Lock()
	delete(g.inFlight, id)
	g.mu.Unlock()
}

// relaying reports whether the first bytes of payload carry a transaction ID
// belonging to a query capture is currently relaying, which makes the datagram
// the upstream's own forwarded copy rather than somebody's lookup.
func (g *resolverLoopGuard) relaying(payload []byte) bool {
	if g == nil || len(payload) < 12 {
		return false
	}
	id := binary.BigEndian.Uint16(payload[:2])
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	expires, ok := g.inFlight[id]
	if !ok {
		return false
	}
	if !now.Before(expires) {
		delete(g.inFlight, id)
		return false
	}
	return true
}

func (g *resolverLoopGuard) prune(now time.Time) {
	if len(g.inFlight) < g.max/2 {
		return
	}
	for id, expires := range g.inFlight {
		if !now.Before(expires) {
			delete(g.inFlight, id)
		}
	}
}
