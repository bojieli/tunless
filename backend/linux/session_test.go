package linux

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/bojieli/tunless"
)

func TestUDPSessionKeySeparatesReusedEndpointsByCookie(t *testing.T) {
	peer := netip.MustParseAddrPort("[::ffff:127.0.0.1]:53000")
	first := makeUDPSessionKey("udp4", peer, 100)
	second := makeUDPSessionKey("udp4", peer, 101)
	if first == second {
		t.Fatal("distinct socket cookies produced the same UDP session key")
	}
	if first.peer != netip.MustParseAddrPort("127.0.0.1:53000") {
		t.Fatalf("session peer = %s, want unmapped IPv4", first.peer)
	}
}

func TestParseRedirectListenPortRequiresNumericLoopback(t *testing.T) {
	for _, value := range []string{"localhost:1080", "0.0.0.0:1080", "192.0.2.1:1080", "127.0.0.1:http", "127.0.0.1:65536"} {
		if _, err := parseRedirectListenPort(value); err == nil {
			t.Fatalf("accepted redirect address %q", value)
		}
	}
	for _, value := range []string{"", "127.0.0.1:0", "127.0.0.1:1080", "[::1]:1080"} {
		if _, err := parseRedirectListenPort(value); err != nil {
			t.Fatalf("rejected redirect address %q: %v", value, err)
		}
	}
}

func TestDecodeOriginalRecordValidatesKernelABI(t *testing.T) {
	value := make([]byte, 32)
	copy(value, netip.MustParseAddr("203.0.113.7").AsSlice())
	binary.BigEndian.PutUint16(value[16:18], 443)
	value[18] = 2
	value[19] = 6
	binary.LittleEndian.PutUint32(value[20:24], 4242)
	binary.LittleEndian.PutUint64(value[24:32], 99)
	destination, pid, cgroupID, err := decodeOriginalRecord(value)
	if err != nil {
		t.Fatal(err)
	}
	if destination != netip.MustParseAddrPort("203.0.113.7:443") || pid != 4242 || cgroupID != 99 {
		t.Fatalf("decoded record = %s pid=%d cgroup=%d", destination, pid, cgroupID)
	}

	invalid := [][]byte{
		value[:31],
		append([]byte(nil), value...),
		append([]byte(nil), value...),
		append([]byte(nil), value...),
		append([]byte(nil), value...),
	}
	invalid[1][18] = 99
	invalid[2][19] = 99
	binary.LittleEndian.PutUint32(invalid[3][20:24], ^uint32(0))
	invalid[4][19] = originalProtocolTCP | originalProtocolConnected
	for index, record := range invalid {
		if _, _, _, err = decodeOriginalRecord(record); err == nil {
			t.Fatalf("invalid record %d was accepted", index)
		}
	}
}

func TestConnectedUDPMarkerAndResponseValidation(t *testing.T) {
	value := make([]byte, 32)
	copy(value, netip.MustParseAddr("203.0.113.7").AsSlice())
	binary.BigEndian.PutUint16(value[16:18], 53)
	value[18] = 2
	value[19] = originalProtocolUDP | originalProtocolConnected
	binary.LittleEndian.PutUint32(value[20:24], 4242)

	protocol, connected, err := decodeOriginalProtocol(value)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != originalProtocolUDP || !connected {
		t.Fatalf("decoded protocol = %d connected=%t", protocol, connected)
	}
	if err = validateUDPResponseRecord(value, netip.MustParseAddrPort("[::ffff:203.0.113.7]:53")); err != nil {
		t.Fatalf("matching mapped response source was rejected: %v", err)
	}
	if err = validateUDPResponseRecord(value, netip.MustParseAddrPort("198.51.100.8:53")); err == nil {
		t.Fatal("response from a different source was accepted")
	}
}

func TestReservedCapturePrefixesCoverWhatSOCKSCannotCarry(t *testing.T) {
	reserved := reservedCapturePrefixes()
	contains := func(value string) bool {
		addr := netip.MustParseAddr(value)
		for _, prefix := range reserved {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, value := range []string{
		"127.0.0.1", "127.9.9.9", "0.0.0.0",
		"169.254.1.1", "169.254.169.254", // link-local, including cloud metadata
		"224.0.0.251", "239.255.255.250", "255.255.255.255",
		"::1", "::", "fe80::1", "ff02::fb",
	} {
		if !contains(value) {
			t.Fatalf("%s is not reserved from capture", value)
		}
	}
	for _, value := range []string{"1.1.1.1", "192.168.1.5", "203.0.113.7", "2001:db8::1", "fc00::1"} {
		if contains(value) {
			t.Fatalf("%s is reserved from capture, but only the datapath and unroutable paths belong in the floor", value)
		}
	}
	for _, prefix := range reserved {
		if prefix != prefix.Masked() {
			t.Fatalf("reserved prefix %s is not in canonical masked form", prefix)
		}
	}
}

func TestWithMappedFormsCoversDualStackSockets(t *testing.T) {
	got := withMappedForms([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("::ffff:192.0.2.0/120"),
	})
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("::ffff:10.0.0.0/104"),
		netip.MustParsePrefix("2001:db8::/32"),
		// Already in mapped form: mapping it again would run past 128 bits.
		netip.MustParsePrefix("::ffff:192.0.2.0/120"),
	}
	if len(got) != len(want) {
		t.Fatalf("withMappedForms = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("withMappedForms[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	// The mapped form has to match what an IPv6 hook is handed for an IPv4
	// destination, and nothing else.
	mapped := got[1]
	if !mapped.Contains(netip.MustParseAddr("::ffff:10.1.2.3")) {
		t.Fatal("mapped prefix does not contain the mapped form of an address it covers")
	}
	if mapped.Contains(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("mapped prefix reaches a native IPv6 address")
	}
}

func TestReservedPrefixesReachDualStackSockets(t *testing.T) {
	reserved := withMappedForms(reservedCapturePrefixes())
	contains := func(value string) bool {
		addr := netip.MustParseAddr(value)
		for _, prefix := range reserved {
			if prefix.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, value := range []string{"::ffff:169.254.169.254", "::ffff:224.0.0.251", "::ffff:127.0.0.1", "::ffff:255.255.255.255"} {
		if !contains(value) {
			t.Fatalf("%s is not reserved from capture", value)
		}
	}
	if contains("::ffff:203.0.113.7") {
		t.Fatal("an ordinary destination is reserved in mapped form")
	}
}

func TestDualStackUDPResponseMatchesItsRecord(t *testing.T) {
	// What the IPv6 connect hook writes for a dual-stack socket reaching an
	// IPv4 destination: family AF_INET6, address in mapped form.
	value := make([]byte, 32)
	copy(value, netip.MustParseAddr("::ffff:203.0.113.7").AsSlice())
	binary.BigEndian.PutUint16(value[16:18], 9001)
	value[18] = 10
	value[19] = originalProtocolUDP | originalProtocolConnected
	binary.LittleEndian.PutUint32(value[20:24], 4242)

	original, _, _, err := decodeOriginalRecord(value)
	if err != nil {
		t.Fatal(err)
	}
	if original != netip.MustParseAddrPort("203.0.113.7:9001") {
		t.Fatalf("decoded destination = %s, want the IPv4 address it is", original)
	}
	// The proxy answers about the address it dialed, which is the IPv4 one. A
	// reply rejected here is a reply the application never receives.
	if err = validateUDPResponseRecord(value, netip.MustParseAddrPort("203.0.113.7:9001")); err != nil {
		t.Fatalf("reply to a dual-stack UDP flow was rejected: %v", err)
	}
	if err = validateUDPResponseRecord(value, netip.MustParseAddrPort("[::ffff:203.0.113.7]:9001")); err != nil {
		t.Fatalf("reply named in mapped form was rejected: %v", err)
	}
	if err = validateUDPResponseRecord(value, netip.MustParseAddrPort("198.51.100.8:9001")); err == nil {
		t.Fatal("a reply from somewhere else was accepted")
	}
}

func TestDualStackRecordIsFilteredByAnIPv4Prefix(t *testing.T) {
	// The userspace filter runs on the decoded destination, and an IPv4 prefix
	// does not contain a mapped address. Left mapped, an exclusion the operator
	// wrote would apply to a single-family program and quietly skip the
	// dual-stack one beside it.
	value := make([]byte, 32)
	copy(value, netip.MustParseAddr("::ffff:10.1.2.3").AsSlice())
	binary.BigEndian.PutUint16(value[16:18], 443)
	value[18] = 10
	value[19] = originalProtocolTCP
	binary.LittleEndian.PutUint32(value[20:24], 4242)

	destination, _, _, err := decodeOriginalRecord(value)
	if err != nil {
		t.Fatal(err)
	}
	filter := tunless.Filter{ExcludeDestinations: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if filter.Capture(tunless.Flow{OrigDst: destination}) {
		t.Fatal("an excluded destination reached over a dual-stack socket was captured")
	}
}
