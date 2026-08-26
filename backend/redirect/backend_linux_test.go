//go:build linux

package redirect

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/bojieli/tunless"
)

// The kernel hands back a sockaddr and the family byte says which one. Reading
// a v6 sockaddr as v4, or the port with the wrong endianness, produces an
// address that looks plausible and points somewhere else.
func TestDecodeSockaddrReadsBothFamilies(t *testing.T) {
	// sockaddr_in: family 2 little-endian, port 443 big-endian, 93.184.216.34
	v4 := []byte{2, 0, 0x01, 0xbb, 93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0}
	got, ok := decodeSockaddr(v4)
	if !ok {
		t.Fatal("v4 sockaddr rejected")
	}
	if got.String() != "93.184.216.34:443" {
		t.Errorf("v4 decoded as %s", got)
	}

	// sockaddr_in6: family 10, port 8080, 2001:db8::1
	v6 := make([]byte, 28)
	v6[0], v6[1] = 10, 0
	v6[2], v6[3] = 0x1f, 0x90
	copy(v6[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())
	got, ok = decodeSockaddr(v6)
	if !ok {
		t.Fatal("v6 sockaddr rejected")
	}
	if got.String() != "[2001:db8::1]:8080" {
		t.Errorf("v6 decoded as %s", got)
	}
}

// A dual-stack listener receives IPv4 connections as v4-mapped. Reporting the
// mapped form would not match any rule an operator wrote against an IPv4
// prefix.
func TestV4MappedIsReportedAsV4(t *testing.T) {
	b := make([]byte, 28)
	b[0], b[1] = 10, 0
	b[2], b[3] = 0, 80
	copy(b[8:24], netip.MustParseAddr("::ffff:10.0.0.7").AsSlice())
	got, ok := decodeSockaddr(b)
	if !ok {
		t.Fatal("v4-mapped sockaddr rejected")
	}
	if got.String() != "10.0.0.7:80" {
		t.Errorf("v4-mapped decoded as %s, want 10.0.0.7:80", got)
	}
}

// Anything short or of an unknown family is refused rather than guessed at.
func TestDecodeSockaddrRefusesNonsense(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		{2, 0},
		{2, 0, 0, 80, 1, 2},           // AF_INET, too short for an address
		{10, 0, 0, 80, 1, 2, 3, 4},    // AF_INET6, too short
		{99, 0, 0, 80, 1, 2, 3, 4, 5}, // unknown family
	} {
		if _, ok := decodeSockaddr(b); ok {
			t.Errorf("accepted %v", b)
		}
	}
}

// The listener has to be loopback. A routable one would accept traffic from
// off-host, which this backend has no way to tell apart from a redirect and
// would forward as though it were one.
func TestStartRefusesARoutableListener(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:1080", "192.168.1.5:1080", "[::]:1080"} {
		b := &Backend{Address: addr}
		if _, err := b.Start(context.Background()); err == nil {
			t.Errorf("accepted %q as a listen address", addr)
			_ = b.Close()
		}
	}
	b := &Backend{Address: "127.0.0.1:0"}
	flows, err := b.Start(context.Background())
	if err != nil {
		t.Fatalf("loopback listener refused: %v", err)
	}
	if flows == nil {
		t.Error("no flow channel")
	}
	_ = b.Close()
}

// Process filters are refused rather than silently matching nothing, since an
// operator who excluded a process would otherwise believe it was excluded.
func TestStartRefusesProcessFilters(t *testing.T) {
	for _, f := range []tunless.Filter{
		{IncludeProcesses: []string{"/usr/bin/curl"}},
		{ExcludeProcesses: []string{"/usr/bin/curl"}},
	} {
		b := &Backend{Address: "127.0.0.1:0", Filter: f}
		_, err := b.Start(context.Background())
		if err == nil {
			t.Error("a process filter was accepted by a backend that cannot fill Process")
			_ = b.Close()
			continue
		}
		if !strings.Contains(err.Error(), "cannot attribute processes") {
			t.Errorf("error does not say why: %v", err)
		}
	}
}

// Destination filters do work, because OrigDst is exactly what this backend
// recovers.
func TestStartAcceptsDestinationFilters(t *testing.T) {
	b := &Backend{Address: "127.0.0.1:0", Filter: tunless.Filter{
		ExcludeDestinations: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}}
	if _, err := b.Start(context.Background()); err != nil {
		t.Fatalf("destination filter refused: %v", err)
	}
	_ = b.Close()
}

// The capture floor is shared with every other backend rather than copied.
func TestTheCaptureFloorIsTheSharedOne(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "169.254.169.254", "224.0.0.1", "::1", "fe80::1"} {
		if !tunless.IsReservedDestination(netip.MustParseAddr(addr)) {
			t.Errorf("%s is not under the capture floor", addr)
		}
	}
	for _, addr := range []string{"93.184.216.34", "10.0.0.1", "2001:db8::1"} {
		if tunless.IsReservedDestination(netip.MustParseAddr(addr)) {
			t.Errorf("%s was treated as reserved", addr)
		}
	}
	// The mapped form of a reserved v4 address is reserved too, since a
	// dual-stack socket reaches it that way.
	if !tunless.IsReservedDestination(netip.MustParseAddr("::ffff:169.254.169.254")) {
		t.Error("the v4-mapped metadata service is not under the floor")
	}
}
