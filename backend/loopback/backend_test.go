package loopback

import (
	"context"
	"net/netip"
	"testing"
)

func TestResolveHostPortRejectsTrailingData(t *testing.T) {
	if _, _, err := resolveHostPort(context.Background(), "127.0.0.1", "80junk"); err == nil {
		t.Fatal("accepted a port with trailing data")
	}
}

func TestParseDomainDatagram(t *testing.T) {
	frame := []byte{0, 0, 0, 3, 9}
	frame = append(frame, "localhost"...)
	frame = append(frame, 0, 53, 1, 2, 3)
	address, used, err := parseDatagram(context.Background(), frame)
	if err != nil {
		t.Fatal(err)
	}
	if address.Port() != 53 || !address.Addr().IsLoopback() || used != len(frame)-3 {
		t.Fatalf("address = %s, used = %d", address, used)
	}
}

func TestSameAddrPortUnmapsIPv4(t *testing.T) {
	v4 := netip.MustParseAddrPort("127.0.0.1:53000")
	mapped := netip.MustParseAddrPort("[::ffff:127.0.0.1]:53000")
	if !sameAddrPort(v4, mapped) {
		t.Fatal("IPv4 and IPv4-mapped UDP peers should compare equal")
	}
}
