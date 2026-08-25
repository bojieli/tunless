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
	first, firstDestination := m.prepare(dnsMessage(0x1234), firstOriginal, override)
	second, secondDestination := m.prepare(dnsMessage(0x1234), secondOriginal, override)
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
	first, _ := m.prepare(dnsMessage(1), original, override)
	_, _ = m.prepare(dnsMessage(2), original, override)
	_, _ = m.prepare(dnsMessage(3), original, override)
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
	got, destination := m.prepare(payload, original, override)
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
		translated, _ := m.prepare(dnsMessage(0x1234), original, override)
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
	one, _ := m.prepare(dnsMessage(0x1111), first, override)
	two, _ := m.prepare(dnsMessage(0x2222), second, override)
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
