package dnsobserver

import (
	"context"
	"errors"
	"net/netip"
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
