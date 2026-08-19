package linux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

const (
	originalProtocolConnected byte = 0x80
	originalProtocolMask      byte = 0x7f
	originalProtocolTCP       byte = 6
	originalProtocolUDP       byte = 17
)

// udpSessionKey includes the kernel socket cookie, not just the source
// endpoint. UDP ports can be reused while an older SOCKS association is still
// draining, and SO_REUSEPORT permits the same endpoint to be shared. Treating
// those sockets as one session can cross-wire process identity and replies.
type udpSessionKey struct {
	network string
	peer    netip.AddrPort
	cookie  uint64
}

func parseRedirectListenPort(address string) (uint16, error) {
	if address == "" {
		return 0, nil
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return 0, errors.New("linux redirect listen address must be loopback IP:port")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() {
		return 0, errors.New("linux redirect listeners may use only a numeric loopback address")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return 0, errors.New("linux redirect listen port must be between 0 and 65535")
	}
	return uint16(port), nil
}

func makeUDPSessionKey(network string, peer netip.AddrPort, cookie uint64) udpSessionKey {
	return udpSessionKey{
		network: network,
		peer:    netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port()),
		cookie:  cookie,
	}
}

// decodeOriginalRecord parses the fixed userspace ABI shared with the eBPF
// original_map. Keep the bounds and range checks outside the Linux-only file so
// malformed-record regressions run on every development platform.
func decodeOriginalRecord(value []byte) (netip.AddrPort, int32, uint64, error) {
	if len(value) < 32 {
		return netip.AddrPort{}, 0, 0, errors.New("original-destination record is truncated")
	}
	var addr netip.Addr
	switch value[18] {
	case 2:
		var raw [4]byte
		copy(raw[:], value[:4])
		addr = netip.AddrFrom4(raw)
	case 10:
		var raw [16]byte
		copy(raw[:], value[:16])
		addr = netip.AddrFrom16(raw)
	default:
		return netip.AddrPort{}, 0, 0, fmt.Errorf("unknown address family %d", value[18])
	}
	protocol, connected, err := decodeOriginalProtocol(value)
	if err != nil {
		return netip.AddrPort{}, 0, 0, err
	}
	if connected && protocol != originalProtocolUDP {
		return netip.AddrPort{}, 0, 0, errors.New("connected marker is valid only for UDP records")
	}
	port := binary.BigEndian.Uint16(value[16:18])
	if port == 0 {
		return netip.AddrPort{}, 0, 0, errors.New("original destination has port zero")
	}
	pid := binary.LittleEndian.Uint32(value[20:24])
	if pid == 0 || pid > ^uint32(0)>>1 {
		return netip.AddrPort{}, 0, 0, errors.New("original-destination record has an invalid PID")
	}
	return netip.AddrPortFrom(addr, port), int32(pid), binary.LittleEndian.Uint64(value[24:32]), nil // #nosec G115 -- PID range is checked above
}

func decodeOriginalProtocol(value []byte) (protocol byte, connected bool, err error) {
	if len(value) < 20 {
		return 0, false, errors.New("original-destination record is truncated")
	}
	raw := value[19]
	protocol = raw & originalProtocolMask
	if protocol != originalProtocolTCP && protocol != originalProtocolUDP {
		return 0, false, fmt.Errorf("unknown transport protocol %d", raw)
	}
	return protocol, raw&originalProtocolConnected != 0, nil
}

func validateUDPResponseRecord(value []byte, destination netip.AddrPort) error {
	original, _, _, err := decodeOriginalRecord(value)
	if err != nil {
		return err
	}
	protocol, _, err := decodeOriginalProtocol(value)
	if err != nil {
		return err
	}
	if protocol != originalProtocolUDP {
		return errors.New("original-destination record is not UDP")
	}
	destination = netip.AddrPortFrom(destination.Addr().Unmap(), destination.Port())
	if original != destination {
		return fmt.Errorf("UDP response source %s does not match original destination %s", destination, original)
	}
	return nil
}
