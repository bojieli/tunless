package linux

import (
	"encoding/binary"
	"net/netip"
	"testing"
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
	}
	invalid[1][18] = 99
	invalid[2][19] = 99
	binary.LittleEndian.PutUint32(invalid[3][20:24], ^uint32(0))
	for index, record := range invalid {
		if _, _, _, err = decodeOriginalRecord(record); err == nil {
			t.Fatalf("invalid record %d was accepted", index)
		}
	}
}
