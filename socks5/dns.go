package socks5

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

// dnsTransactionMap translates DNS IDs while a UDP query is routed to a
// trusted resolver. Allocating a private ID for each outstanding query avoids
// ambiguous FIFO matching when applications reuse a 16-bit ID, send the same
// query to multiple resolvers, or receive replies out of order.
type dnsTransactionMap struct {
	mu         sync.Mutex
	entries    map[uint16]dnsTransaction
	maxEntries int
	ttl        time.Duration
	now        func() time.Time
	random     func() uint16
}

type dnsTransaction struct {
	originalID uint16
	original   netip.AddrPort
	routed     netip.AddrPort
	expires    time.Time
}

func newDNSTransactionMap(maxEntries int, ttl time.Duration) *dnsTransactionMap {
	return &dnsTransactionMap{
		entries:    make(map[uint16]dnsTransaction),
		maxEntries: maxEntries,
		ttl:        ttl,
		now:        time.Now,
		random:     randomTransactionID,
	}
}

func (m *dnsTransactionMap) prepare(payload []byte, original, override netip.AddrPort) ([]byte, netip.AddrPort) {
	if !override.IsValid() || original.Port() != 53 {
		return payload, original
	}
	if len(payload) < 12 {
		return payload, original
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	m.prune(now)
	if m.maxEntries <= 0 {
		return payload, override
	}
	if len(m.entries) >= m.maxEntries {
		m.evictOldest()
	}
	translated, ok := m.allocateID()
	if !ok {
		return payload, override
	}
	copyPayload := append([]byte(nil), payload...)
	originalID := binary.BigEndian.Uint16(copyPayload[:2])
	binary.BigEndian.PutUint16(copyPayload[:2], translated)
	m.entries[translated] = dnsTransaction{
		originalID: originalID,
		original:   original,
		routed:     override,
		expires:    now.Add(m.ttl),
	}
	return copyPayload, override
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
	if !ok || !sameAddrPort(entry.routed, source) {
		return payload, source
	}
	delete(m.entries, translated)
	copyPayload := append([]byte(nil), payload...)
	binary.BigEndian.PutUint16(copyPayload[:2], entry.originalID)
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
	}
}
