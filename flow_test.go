package tunless

import (
	"net"
	"net/netip"
	"testing"
)

func TestFlowValidate(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if err := (Flow{Proto: TCP, OrigDst: netip.MustParseAddrPort("127.0.0.1:1"), Conn: a}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Flow{Proto: TCP, OrigDst: netip.MustParseAddrPort("127.0.0.1:1")}).Validate(); err == nil {
		t.Fatal("expected missing connection error")
	}
}

func TestFlowRejectsZeroDestinationPort(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	flow := Flow{Proto: TCP, OrigDst: netip.MustParseAddrPort("192.0.2.1:0"), Conn: a}
	if err := flow.Validate(); err == nil {
		t.Fatal("accepted a destination with port zero")
	}
}
