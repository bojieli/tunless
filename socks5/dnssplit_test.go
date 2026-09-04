package socks5

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/bojieli/tunless"
	"github.com/bojieli/tunless/internal/dnspolicy"
)

// splitHarness runs the whole datapath: a SOCKS5 upstream whose UDP relay
// answers as the trusted resolver, a real resolver on loopback answering as the
// direct one, and a captured UDP flow carrying queries between them.
//
// The unit tests around it check the decision. This checks that the decision
// reaches the application, through a real association, with the identifier and
// the source address a resolver client will accept.
type splitHarness struct {
	client  *Client
	port    *scriptedPacketPort
	policy  *dnspolicy.Policy
	trusted netip.AddrPort
}

// answerFunc produces the reply a resolver gives, or nil to stay silent.
type answerFunc func(query []byte) []byte

func newSplitHarness(t *testing.T, directAnswer, trustedAnswer answerFunc) *splitHarness {
	t.Helper()

	direct, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { direct.Close() })
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, readErr := direct.ReadFromUDPAddrPort(buffer)
			if readErr != nil {
				return
			}
			if reply := directAnswer(append([]byte(nil), buffer[:n]...)); reply != nil {
				_, _ = direct.WriteToUDPAddrPort(reply, peer)
			}
		}
	}()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { relay.Close() })

	go func() {
		control, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer control.Close()
		var greeting [3]byte
		_, _ = io.ReadFull(control, greeting[:])
		_, _ = control.Write([]byte{5, 0})
		var request [10]byte
		_, _ = io.ReadFull(control, request[:])
		bound := relay.LocalAddr().(*net.UDPAddr).AddrPort()
		reply := []byte{5, 0, 0, 1}
		reply = append(reply, bound.Addr().AsSlice()...)
		reply = append(reply, byte(bound.Port()>>8), byte(bound.Port()))
		_, _ = control.Write(reply)
		_, _ = io.Copy(io.Discard, control)
	}()

	trusted := netip.MustParseAddrPort("1.1.1.1:53")
	go func() {
		buffer := make([]byte, 65535)
		for {
			n, peer, readErr := relay.ReadFromUDPAddrPort(buffer)
			if readErr != nil {
				return
			}
			if n < 4 {
				continue
			}
			destination, used, parseErr := parseAddr(context.Background(), buffer[3:n])
			if parseErr != nil || destination != trusted {
				continue
			}
			query := append([]byte(nil), buffer[3+used:n]...)
			answer := trustedAnswer(query)
			if answer == nil {
				continue
			}
			frame := []byte{0, 0, 0}
			frame = append(frame, encodeAddr(trusted)...)
			frame = append(frame, answer...)
			_, _ = relay.WriteToUDPAddrPort(frame, peer)
		}
	}()

	prefix, err := dnspolicy.ParsePrefix("203.0.113.0/24")
	if err != nil {
		t.Fatal(err)
	}
	policy := &dnspolicy.Policy{
		Prefixes:       dnspolicy.NewPrefixSet([]netip.Prefix{prefix}),
		DirectResolver: direct.LocalAddr().(*net.UDPAddr).AddrPort(),
	}
	return &splitHarness{
		client: &Client{
			Address:     listener.Addr().String(),
			DNSOverride: trusted,
			DNSPolicy:   policy,
			DNSStats:    &DNSStats{},
		},
		port:    &scriptedPacketPort{reads: make(chan tunless.Packet, 4), writes: make(chan tunless.Packet, 4), done: make(chan struct{})},
		policy:  policy,
		trusted: trusted,
	}
}

// ask sends one query through the flow and returns the reply the application
// receives.
func (h *splitHarness) ask(t *testing.T, query []byte, from netip.AddrPort) tunless.Packet {
	t.Helper()
	h.port.reads <- tunless.Packet{Payload: query, Dst: from}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	emitDone := make(chan error, 1)
	go func() {
		emitDone <- h.client.Emit(ctx, tunless.Flow{
			Proto:   tunless.UDP,
			OrigDst: from,
			Packets: h.port,
		})
	}()
	select {
	case written := <-h.port.writes:
		return written
	case <-time.After(10 * time.Second):
		t.Fatal("the application never received a reply")
		return tunless.Packet{}
	}
}

func TestAdjudicationServesTheNearAnswerThroughTheWholeDatapath(t *testing.T) {
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")
	query := dnsQuery(0x1234, "www", "example", "net")
	h := newSplitHarness(t,
		func(q []byte) []byte { return dnsAnswer(t, q, "www.example.net.", "203.0.113.7") },
		func(q []byte) []byte { return dnsAnswer(t, q, "www.example.net.", "192.0.2.9") },
	)
	written := h.ask(t, query, appResolver)

	if id := binary.BigEndian.Uint16(written.Payload[:2]); id != 0x1234 {
		t.Errorf("reply carried ID %#x, want the application's %#x", id, 0x1234)
	}
	if written.Dst != appResolver {
		t.Errorf("reply came from %s, want the resolver the application wrote to", written.Dst)
	}
	addresses := dnspolicy.ReplyAddresses(written.Payload)
	if len(addresses) != 1 || addresses[0].String() != "203.0.113.7" {
		t.Fatalf("delivered %v, want the direct answer inside the credible set", addresses)
	}
	if got := h.client.DNSSnapshot(); got.ServedDirect != 1 || got.Adjudicated != 1 {
		t.Errorf("counters = %+v, want one adjudication served direct", got)
	}
}

func TestAdjudicationFallsBackToTheTunnelForAnAnswerOutsideTheSet(t *testing.T) {
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")
	query := dnsQuery(0x2345, "www", "example", "net")
	h := newSplitHarness(t,
		func(q []byte) []byte { return dnsAnswer(t, q, "www.example.net.", "198.51.100.1") },
		func(q []byte) []byte { return dnsAnswer(t, q, "www.example.net.", "192.0.2.9") },
	)
	written := h.ask(t, query, appResolver)

	addresses := dnspolicy.ReplyAddresses(written.Payload)
	if len(addresses) != 1 || addresses[0].String() != "192.0.2.9" {
		t.Fatalf("delivered %v, want the trusted answer", addresses)
	}
	if got := h.client.DNSSnapshot(); got.ServedTrusted != 1 {
		t.Errorf("counters = %+v, want one adjudication served trusted", got)
	}
}

func TestASuspectAnswerReachesTheApplicationAsAServerFailure(t *testing.T) {
	// The tunnel is down and the only answer available names an address the
	// operator did not vouch for. Serving it is the one thing this path exists
	// not to do.
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")
	query := dnsQuery(0x3456, "www", "example", "net")
	h := newSplitHarness(t,
		func(q []byte) []byte { return dnsAnswer(t, q, "www.example.net.", "198.51.100.1") },
		func([]byte) []byte { return nil },
	)
	written := h.ask(t, query, appResolver)

	if code := written.Payload[3] & 0x0f; code != 2 {
		t.Fatalf("rcode = %d, want 2 (SERVFAIL)", code)
	}
	if binary.BigEndian.Uint16(written.Payload[:2]) != 0x3456 {
		t.Error("the refusal did not carry the application's transaction ID")
	}
	if written.Dst != appResolver {
		t.Errorf("the refusal came from %s, want the resolver the application wrote to", written.Dst)
	}
}

func TestANearNameResolvesWithTheTunnelCompletelyDown(t *testing.T) {
	// The availability property, end to end: an answer the set covers is served
	// without the trusted resolver contributing anything at all.
	appResolver := netip.MustParseAddrPort("192.168.1.1:53")
	query := dnsQuery(0x4567, "www", "example", "net")
	h := newSplitHarness(t,
		func(q []byte) []byte { return dnsAnswer(t, q, "www.example.net.", "203.0.113.7") },
		func([]byte) []byte { return nil },
	)
	started := time.Now()
	written := h.ask(t, query, appResolver)
	if elapsed := time.Since(started); elapsed > dnspolicy.DirectReplyWindow {
		t.Errorf("a near name took %s, so it waited on the tunnel", elapsed)
	}
	addresses := dnspolicy.ReplyAddresses(written.Payload)
	if len(addresses) != 1 || addresses[0].String() != "203.0.113.7" {
		t.Fatalf("delivered %v, want the direct answer with no tunnel at all", addresses)
	}
}
