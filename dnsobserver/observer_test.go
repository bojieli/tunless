package dnsobserver

import (
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
