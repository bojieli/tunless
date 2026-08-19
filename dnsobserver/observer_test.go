package dnsobserver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestLookupRejectsAmbiguity(t *testing.T) {
	o := &Observer{records: map[netip.Addr]map[string]time.Time{netip.MustParseAddr("203.0.113.1"): {"a.example.": time.Now().Add(time.Minute)}}}
	if got := o.Lookup(netip.MustParseAddr("203.0.113.1")); got != "a.example." {
		t.Fatalf("got %q", got)
	}
	o.records[netip.MustParseAddr("203.0.113.1")]["b.example."] = time.Now().Add(time.Minute)
	if got := o.Lookup(netip.MustParseAddr("203.0.113.1")); got != "" {
		t.Fatalf("ambiguous lookup returned %q", got)
	}
}

func TestConfiguredProxyExchangesReplaceDirectResolverSockets(t *testing.T) {
	want := []byte{1, 2, 3}
	udpCalled, tcpCalled := false, false
	observer := &Observer{
		Upstream: "192.0.2.1:53",
		UDPExchange: func(context.Context, []byte) ([]byte, error) {
			udpCalled = true
			return want, nil
		},
		TCPExchange: func(context.Context, []byte) ([]byte, error) {
			tcpCalled = true
			return want, nil
		},
	}
	udpReply, err := observer.exchangeUDP(context.Background(), []byte{0})
	if err != nil || !udpCalled || string(udpReply) != string(want) {
		t.Fatalf("UDP proxy exchange = %v, %v, called=%v", udpReply, err, udpCalled)
	}
	tcpReply, err := observer.exchangeTCP(context.Background(), []byte{0})
	if err != nil || !tcpCalled || string(tcpReply) != string(want) {
		t.Fatalf("TCP proxy exchange = %v, %v, called=%v", tcpReply, err, tcpCalled)
	}
}

func TestProxyExchangeErrorsAreReturned(t *testing.T) {
	want := errors.New("proxy unavailable")
	observer := &Observer{UDPExchange: func(context.Context, []byte) ([]byte, error) { return nil, want }}
	if _, err := observer.exchangeUDP(context.Background(), []byte{0}); !errors.Is(err, want) {
		t.Fatalf("exchange error = %v, want %v", err, want)
	}
}

type shortWriter struct{ builder strings.Builder }

func (w *shortWriter) Write(payload []byte) (int, error) {
	if len(payload) > 2 {
		payload = payload[:2]
	}
	return w.builder.Write(payload)
}

func TestWriteAllHandlesShortWrites(t *testing.T) {
	writer := &shortWriter{}
	if err := writeAll(writer, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	if got := writer.builder.String(); got != "complete" {
		t.Fatalf("writeAll output = %q", got)
	}
}

func TestProxyExchangesRejectOversizedMessages(t *testing.T) {
	oversized := make([]byte, 65536)
	observer := &Observer{
		UDPExchange: func(context.Context, []byte) ([]byte, error) { return oversized, nil },
		TCPExchange: func(context.Context, []byte) ([]byte, error) { return oversized, nil },
	}
	if _, err := observer.exchangeUDP(context.Background(), []byte{0}); err == nil {
		t.Fatal("oversized UDP reply was accepted")
	}
	if _, err := observer.exchangeTCP(context.Background(), []byte{0}); err == nil {
		t.Fatal("oversized TCP reply was accepted")
	}
	if _, err := observer.exchangeUDP(context.Background(), oversized); err == nil {
		t.Fatal("oversized UDP query was accepted")
	}
	if _, err := observer.exchangeTCP(context.Background(), oversized); err == nil {
		t.Fatal("oversized TCP query was accepted")
	}
}

func TestObserveRequiresMatchingDNSResponse(t *testing.T) {
	name := dnsmessage.MustNewName("example.test.")
	question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	queryMessage := dnsmessage.Message{Header: dnsmessage.Header{ID: 7}, Questions: []dnsmessage.Question{question}}
	query, err := queryMessage.Pack()
	if err != nil {
		t.Fatal(err)
	}
	reply := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 8, Response: true},
		Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 9}},
		}},
	}
	packedReply, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	observer := &Observer{records: make(map[netip.Addr]map[string]time.Time)}
	observer.observe(query, packedReply)
	address := netip.MustParseAddr("203.0.113.9")
	if got := observer.Lookup(address); got != "" {
		t.Fatalf("recorded a mismatched DNS transaction as %q", got)
	}
	reply.Header.ID = 7
	packedReply, err = reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	observer.observe(query, packedReply)
	if got := observer.Lookup(address); got != "example.test." {
		t.Fatalf("matching response lookup = %q", got)
	}
}

func TestObserveFollowsCNAMEAndRejectsUnrelatedAnswers(t *testing.T) {
	alias := dnsmessage.MustNewName("alias.test.")
	target := dnsmessage.MustNewName("target.test.")
	unrelated := dnsmessage.MustNewName("unrelated.test.")
	question := dnsmessage.Question{Name: alias, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 9}, Questions: []dnsmessage.Question{question}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 9, Response: true},
		Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: target}},
			{Header: dnsmessage.ResourceHeader{Name: target, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 10}}},
			{Header: dnsmessage.ResourceHeader{Name: unrelated, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 11}}},
			{Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 13}}},
		},
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	observer := &Observer{records: make(map[netip.Addr]map[string]time.Time)}
	observer.observe(query, reply)
	if got := observer.Lookup(netip.MustParseAddr("203.0.113.10")); got != "alias.test." {
		t.Fatalf("CNAME address lookup = %q", got)
	}
	if got := observer.Lookup(netip.MustParseAddr("203.0.113.11")); got != "" {
		t.Fatalf("unrelated address was attributed as %q", got)
	}
	if got := observer.Lookup(netip.MustParseAddr("203.0.113.13")); got != "" {
		t.Fatalf("address attached to CNAME owner was attributed as %q", got)
	}
}

func TestObserveRequiresQuestionTypeAndCapsCNAMEExpiry(t *testing.T) {
	alias := dnsmessage.MustNewName("alias-ttl.test.")
	target := dnsmessage.MustNewName("target-ttl.test.")
	question := dnsmessage.Question{Name: alias, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 11}, Questions: []dnsmessage.Question{question}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr("203.0.113.14")
	reply := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 11, Response: true},
		Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.CNAMEResource{CNAME: target}},
			{Header: dnsmessage.ResourceHeader{Name: target, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}},
		},
	}
	packedReply, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	observer := &Observer{records: make(map[netip.Addr]map[string]time.Time)}
	observer.observe(query, packedReply)
	if got := observer.Lookup(netip.MustParseAddr("2001:db8::1")); got != "" {
		t.Fatalf("A query attributed an AAAA answer as %q", got)
	}
	reply.Answers[1] = dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: target, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
		Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, 14}},
	}
	packedReply, err = reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	observer.observe(query, packedReply)
	expires, ok := observer.records[address][alias.String()]
	if !ok {
		t.Fatal("matching A record was not attributed")
	}
	remaining := time.Until(expires)
	if remaining <= 0 || remaining > 2*time.Second {
		t.Fatalf("CNAME-capped expiry remaining = %v, want approximately one second", remaining)
	}
}

func TestObserveRejectsCNAMECycle(t *testing.T) {
	first := dnsmessage.MustNewName("first.test.")
	second := dnsmessage.MustNewName("second.test.")
	question := dnsmessage.Question{Name: first, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 10}, Questions: []dnsmessage.Question{question}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := (&dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 10, Response: true},
		Questions: []dnsmessage.Question{question},
		Answers: []dnsmessage.Resource{
			{Header: dnsmessage.ResourceHeader{Name: first, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: second}},
			{Header: dnsmessage.ResourceHeader{Name: second, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: first}},
			{Header: dnsmessage.ResourceHeader{Name: second, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{203, 0, 113, 12}}},
		},
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	observer := &Observer{records: make(map[netip.Addr]map[string]time.Time)}
	observer.observe(query, reply)
	if got := observer.Lookup(netip.MustParseAddr("203.0.113.12")); got != "" {
		t.Fatalf("cyclic CNAME was attributed as %q", got)
	}
}

func TestObserveBoundsCache(t *testing.T) {
	observer := &Observer{MaxRecords: 2, records: make(map[netip.Addr]map[string]time.Time)}
	for index := byte(1); index <= 5; index++ {
		name := dnsmessage.MustNewName("bounded.test.")
		question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
		query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: uint16(index)}, Questions: []dnsmessage.Question{question}}).Pack()
		if err != nil {
			t.Fatal(err)
		}
		reply, err := (&dnsmessage.Message{
			Header:    dnsmessage.Header{ID: uint16(index), Response: true},
			Questions: []dnsmessage.Question{question},
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: [4]byte{203, 0, 113, index}},
			}},
		}).Pack()
		if err != nil {
			t.Fatal(err)
		}
		observer.observe(query, reply)
	}
	actual := 0
	for _, names := range observer.records {
		actual += len(names)
	}
	if actual != 2 || observer.recordCount != 2 {
		t.Fatalf("cached associations = %d (counter %d), want 2", actual, observer.recordCount)
	}
}

func TestServeRejectsNegativeRecordLimit(t *testing.T) {
	observer := &Observer{Listen: "127.0.0.1:0", MaxRecords: -1}
	if err := observer.Serve(context.Background()); err == nil {
		t.Fatal("negative DNS record limit was accepted")
	}
}

func TestValidateAddressRejectsNonLoopbackListeners(t *testing.T) {
	for _, address := range []string{"", ":5353", "0.0.0.0:5353", "localhost:5353", "192.0.2.1:5353", "127.0.0.1:dns", "127.0.0.1:65536"} {
		if _, err := ValidateAddress(address); err == nil {
			t.Fatalf("accepted DNS observer address %q", address)
		}
	}
	for _, address := range []string{"127.0.0.1:0", "127.0.0.1:5353", "[::1]:5353"} {
		if _, err := ValidateAddress(address); err != nil {
			t.Fatalf("rejected DNS observer address %q: %v", address, err)
		}
	}
}

func TestServeReadinessAndCoordinatedEphemeralPort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	observer := &Observer{Listen: "127.0.0.1:0"}
	done := make(chan error, 1)
	go func() { done <- observer.Serve(ctx) }()
	for deadline := time.Now().Add(time.Second); !observer.Ready(); {
		if time.Now().After(deadline) {
			t.Fatal("DNS observer did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	udpPort := observer.udp.LocalAddr().(*net.UDPAddr).Port
	tcpPort := observer.tcp.Addr().(*net.TCPAddr).Port
	if udpPort == 0 || udpPort != tcpPort {
		t.Fatalf("DNS observer ports: UDP=%d TCP=%d", udpPort, tcpPort)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if observer.Ready() {
		t.Fatal("DNS observer remained ready after shutdown")
	}
}

func TestCloseBeforeServePreventsStart(t *testing.T) {
	observer := &Observer{Listen: "127.0.0.1:0"}
	if err := observer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := observer.Serve(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve after Close = %v, want net.ErrClosed", err)
	}
}
