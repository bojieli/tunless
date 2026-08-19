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

func TestPacketValidateRejectsInvalidDestinationAndOversizedPayload(t *testing.T) {
	if err := (Packet{Dst: netip.AddrPort{}, Payload: []byte("x")}).Validate(); err == nil {
		t.Fatal("accepted an invalid packet destination")
	}
	if err := (Packet{Dst: netip.MustParseAddrPort("192.0.2.1:53"), Payload: make([]byte, 65528)}).Validate(); err == nil {
		t.Fatal("accepted a payload larger than the UDP protocol limit")
	}
	if err := (Packet{Dst: netip.MustParseAddrPort("192.0.2.1:53"), Payload: make([]byte, 65527)}).Validate(); err != nil {
		t.Fatalf("rejected a protocol-sized UDP payload: %v", err)
	}
}

func TestFlowAndPacketRejectIPv6Zones(t *testing.T) {
	destination := netip.MustParseAddrPort("[fe80::1%en0]:53")
	if err := (Packet{Dst: destination}).Validate(); err == nil {
		t.Fatal("accepted a scoped packet destination that SOCKS5 cannot encode")
	}
	if err := (Flow{Proto: TCP, OrigDst: destination, DatapathOwned: true}).Validate(); err == nil {
		t.Fatal("accepted a scoped flow destination that SOCKS5 cannot encode")
	}
}

func TestFlowRejectsNegativePID(t *testing.T) {
	flow := Flow{
		Proto:         TCP,
		OrigDst:       netip.MustParseAddrPort("192.0.2.1:443"),
		Process:       ProcessInfo{PID: -1},
		DatapathOwned: true,
	}
	if err := flow.Validate(); err == nil {
		t.Fatal("accepted a negative process PID")
	}
}

func TestFlowRejectsOversizedRedirectRecords(t *testing.T) {
	flow := Flow{
		Proto:           TCP,
		OrigDst:         netip.MustParseAddrPort("192.0.2.1:443"),
		RedirectRecords: make([]byte, maxRedirectRecords+1),
		DatapathOwned:   true,
	}
	if err := flow.Validate(); err == nil {
		t.Fatal("accepted redirect records larger than the bounded WFP query limit")
	}
}
