package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/bojieli/tunless"
)

func TestCredentialsRequireUserPasswordMethod(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	seen := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		header := make([]byte, 2)
		_, _ = io.ReadFull(conn, header)
		methods := make([]byte, int(header[1]))
		_, _ = io.ReadFull(conn, methods)
		seen <- methods
		_, _ = conn.Write([]byte{5, 2})
		_, _ = io.ReadFull(conn, header)
		auth := make([]byte, int(header[1])+1)
		_, _ = io.ReadFull(conn, auth)
		password := make([]byte, int(auth[len(auth)-1]))
		_, _ = io.ReadFull(conn, password)
		_, _ = conn.Write([]byte{1, 0})
		request := make([]byte, 10)
		_, _ = io.ReadFull(conn, request)
		_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	}()
	client := &Client{Address: listener.Addr().String()}
	conn, _, cleanup, err := client.connect(context.Background(), 1, netip.MustParseAddrPort("192.0.2.1:443"), "", "pid=42", "secret", tunless.ProcessInfo{PID: 42}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	_ = conn.Close()
	methods := <-seen
	if len(methods) != 1 || methods[0] != 2 {
		t.Fatalf("offered methods %v, want username/password only", methods)
	}
}

func TestHandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		_, _ = io.Copy(io.Discard, conn)
	}()
	client := &Client{Address: listener.Addr().String(), HandshakeTimeout: 25 * time.Millisecond}
	conn, _, cleanup, err := client.connect(context.Background(), 1, netip.MustParseAddrPort("192.0.2.1:443"), "", "", "", tunless.ProcessInfo{}, nil)
	cleanup()
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("SOCKS5 handshake without a reply did not time out")
	}
	<-accepted
}

func TestReadAddrRejectsEmptyDomain(t *testing.T) {
	_, err := readAddr(context.Background(), bytes.NewReader([]byte{3, 0, 0, 80}))
	if err == nil {
		t.Fatal("accepted an empty SOCKS5 domain address")
	}
}

func TestParseUDPDomainAddressDoesNotUseSystemResolver(t *testing.T) {
	frame := []byte{3, 9}
	frame = append(frame, "localhost"...)
	frame = append(frame, 0, 53)
	if _, _, err := parseAddr(context.Background(), frame); err == nil {
		t.Fatal("accepted a UDP domain address that would require system DNS")
	}
}

func TestReadDomainBoundAddressUsesNumericPeerFallback(t *testing.T) {
	frame := []byte{3, 10}
	frame = append(frame, "relay.test"...)
	frame = append(frame, 0x12, 0x34)
	address, err := readAddr(context.Background(), bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if !address.Addr().IsUnspecified() || address.Port() != 0x1234 {
		t.Fatalf("bound address = %s", address)
	}
}

func TestSameAddrPortUnmapsIPv4(t *testing.T) {
	v4 := netip.MustParseAddrPort("127.0.0.1:53")
	mapped := netip.MustParseAddrPort("[::ffff:127.0.0.1]:53")
	if !sameAddrPort(v4, mapped) {
		t.Fatal("IPv4 and IPv4-mapped relay endpoints should compare equal")
	}
}

func TestTCPDNSOverrideAndDisableSemantics(t *testing.T) {
	flow := tunless.Flow{OrigDst: netip.MustParseAddrPort("223.6.6.6:53"), Hostname: "polluted.example"}
	client := &Client{DNSOverride: netip.MustParseAddrPort("1.1.1.1:53")}
	destination, hostname := client.routedTCPDestination(flow)
	if destination != client.DNSOverride || hostname != "" {
		t.Fatalf("routed DNS destination = %s, %q", destination, hostname)
	}
	client.DNSOverride = netip.AddrPort{}
	destination, hostname = client.routedTCPDestination(flow)
	if destination != flow.OrigDst || hostname != flow.Hostname {
		t.Fatalf("disabled override destination = %s, %q", destination, hostname)
	}
	flow.OrigDst = netip.MustParseAddrPort("203.0.113.1:853")
	client.DNSOverride = netip.MustParseAddrPort("1.1.1.1:53")
	destination, _ = client.routedTCPDestination(flow)
	if destination != flow.OrigDst {
		t.Fatalf("non-port-53 traffic was rewritten to %s", destination)
	}
}

type contextPacketPort struct{}

func (contextPacketPort) ReadPacket(ctx context.Context) (tunless.Packet, error) {
	<-ctx.Done()
	return tunless.Packet{}, ctx.Err()
}

func (contextPacketPort) WritePacket(context.Context, tunless.Packet) error { return nil }
func (contextPacketPort) Close() error                                      { return nil }

type scriptedPacketPort struct {
	reads  chan tunless.Packet
	writes chan tunless.Packet
	done   chan struct{}
	once   sync.Once
}

type shortWriter struct {
	bytes.Buffer
	limit int
}

func (w *shortWriter) Write(payload []byte) (int, error) {
	if len(payload) > w.limit {
		payload = payload[:w.limit]
	}
	return w.Buffer.Write(payload)
}

func TestWriteAllHandlesShortWrites(t *testing.T) {
	writer := &shortWriter{limit: 2}
	if err := writeAll(writer, []byte("complete")); err != nil {
		t.Fatal(err)
	}
	if writer.String() != "complete" {
		t.Fatalf("written payload = %q", writer.String())
	}
}

func (p *scriptedPacketPort) ReadPacket(ctx context.Context) (tunless.Packet, error) {
	select {
	case packet := <-p.reads:
		return packet, nil
	case <-p.done:
		return tunless.Packet{}, net.ErrClosed
	case <-ctx.Done():
		return tunless.Packet{}, ctx.Err()
	}
}

func (p *scriptedPacketPort) WritePacket(ctx context.Context, packet tunless.Packet) error {
	select {
	case p.writes <- packet:
		return nil
	case <-p.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *scriptedPacketPort) Close() error {
	p.once.Do(func() { close(p.done) })
	return nil
}

func TestUDPAssociationEndsWithControlConnection(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var greeting [3]byte
		_, _ = io.ReadFull(conn, greeting[:])
		_, _ = conn.Write([]byte{5, 0})
		var request [10]byte
		_, _ = io.ReadFull(conn, request[:])
		bound := relay.LocalAddr().(*net.UDPAddr).AddrPort()
		reply := []byte{5, 0, 0, 1}
		reply = append(reply, bound.Addr().AsSlice()...)
		reply = append(reply, byte(bound.Port()>>8), byte(bound.Port()))
		_, _ = conn.Write(reply)
	}()
	done := make(chan error, 1)
	go func() {
		done <- (&Client{Address: listener.Addr().String()}).Emit(context.Background(), tunless.Flow{
			Proto:   tunless.UDP,
			OrigDst: netip.MustParseAddrPort("1.1.1.1:53"),
			Packets: contextPacketPort{},
		})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("UDP association ended without reporting the closed control connection")
		}
	case <-time.After(time.Second):
		t.Fatal("UDP association ignored its closed control connection")
	}
}

func TestUDPAssociationIdleTimeoutCompletesWorkers(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		var greeting [3]byte
		_, _ = io.ReadFull(conn, greeting[:])
		_, _ = conn.Write([]byte{5, 0})
		var request [10]byte
		_, _ = io.ReadFull(conn, request[:])
		bound := relay.LocalAddr().(*net.UDPAddr).AddrPort()
		reply := []byte{5, 0, 0, 1}
		reply = append(reply, bound.Addr().AsSlice()...)
		reply = append(reply, byte(bound.Port()>>8), byte(bound.Port()))
		_, _ = conn.Write(reply)
		_, _ = io.Copy(io.Discard, conn)
	}()
	err = (&Client{Address: listener.Addr().String(), UDPIdleTimeout: 20 * time.Millisecond}).Emit(context.Background(), tunless.Flow{
		Proto:   tunless.UDP,
		OrigDst: netip.MustParseAddrPort("1.1.1.1:53"),
		Packets: contextPacketPort{},
	})
	if !errors.Is(err, ErrUDPIdleTimeout) {
		t.Fatalf("UDP association error = %v, want idle timeout", err)
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("SOCKS control worker did not finish after idle timeout")
	}
}

func TestUDPTrustedDNSOverrideRestoresOutOfOrderResponses(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	override := netip.MustParseAddrPort("1.1.1.1:53")
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		control, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer control.Close()
		var greeting [3]byte
		_, _ = io.ReadFull(control, greeting[:])
		_, _ = control.Write([]byte{5, 0})
		var request [10]byte
		_, _ = io.ReadFull(control, request[:])
		bound := relay.LocalAddr().(*net.UDPAddr).AddrPort()
		reply := []byte{5, 0, 0, 1}
		reply = append(reply, bound.Addr().AsSlice()...)
		reply = append(reply, byte(bound.Port()>>8), byte(bound.Port()))
		_, _ = control.Write(reply)
		_, _ = io.Copy(io.Discard, control)
	}()
	relayErr := make(chan error, 1)
	go func() {
		buffer := make([]byte, 65535)
		type received struct {
			frame []byte
			peer  netip.AddrPort
		}
		packets := make([]received, 0, 2)
		for len(packets) < 2 {
			n, peer, readErr := relay.ReadFromUDPAddrPort(buffer)
			if readErr != nil {
				relayErr <- readErr
				return
			}
			if n < 4 {
				relayErr <- errors.New("truncated SOCKS UDP frame")
				return
			}
			destination, _, parseErr := parseAddr(context.Background(), buffer[3:n])
			if parseErr != nil || destination != override {
				relayErr <- errors.New("DNS query did not use trusted resolver override")
				return
			}
			packets = append(packets, received{frame: append([]byte(nil), buffer[:n]...), peer: peer})
		}
		for index := len(packets) - 1; index >= 0; index-- {
			if _, writeErr := relay.WriteToUDPAddrPort(packets[index].frame, packets[index].peer); writeErr != nil {
				relayErr <- writeErr
				return
			}
		}
		relayErr <- nil
	}()

	port := &scriptedPacketPort{reads: make(chan tunless.Packet, 2), writes: make(chan tunless.Packet, 2), done: make(chan struct{})}
	firstOriginal := netip.MustParseAddrPort("223.6.6.6:53")
	secondOriginal := netip.MustParseAddrPort("8.8.8.8:53")
	query := dnsMessage(0x1234)
	port.reads <- tunless.Packet{Payload: query, Dst: firstOriginal}
	port.reads <- tunless.Packet{Payload: query, Dst: secondOriginal}
	ctx, cancel := context.WithCancel(context.Background())
	emitDone := make(chan error, 1)
	go func() {
		emitDone <- (&Client{Address: listener.Addr().String(), DNSOverride: override}).Emit(ctx, tunless.Flow{
			Proto:   tunless.UDP,
			OrigDst: firstOriginal,
			Packets: port,
		})
	}()
	var responses []tunless.Packet
	for len(responses) < 2 {
		select {
		case response := <-port.writes:
			responses = append(responses, response)
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for restored DNS responses")
		}
	}
	if responses[0].Dst != secondOriginal || responses[1].Dst != firstOriginal {
		t.Fatalf("restored response order/sources = %s, %s", responses[0].Dst, responses[1].Dst)
	}
	for _, response := range responses {
		if !bytes.Equal(response.Payload[:2], query[:2]) {
			t.Fatalf("response transaction ID = %x, want %x", response.Payload[:2], query[:2])
		}
	}
	if err = <-relayErr; err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err = <-emitDone:
		if err != nil {
			t.Fatalf("cancelled UDP emitter returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("UDP emitter did not join workers after cancellation")
	}
	select {
	case <-serverDone:
	case <-time.After(time.Second):
		t.Fatal("SOCKS control connection remained open")
	}
}

func TestRejectsAuthenticationMethodThatWasNotOffered(t *testing.T) {
	tests := []struct {
		name     string
		username string
		selected byte
	}{
		{name: "server selects auth for anonymous client", selected: 2},
		{name: "server discards configured credentials", username: "identity", selected: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				defer conn.Close()
				var header [2]byte
				if _, readErr := io.ReadFull(conn, header[:]); readErr != nil {
					return
				}
				methods := make([]byte, int(header[1]))
				_, _ = io.ReadFull(conn, methods)
				_, _ = conn.Write([]byte{5, tt.selected})
			}()
			client := &Client{Address: listener.Addr().String()}
			conn, _, cleanup, err := client.connect(context.Background(), 1, netip.MustParseAddrPort("192.0.2.1:443"), "", tt.username, "", tunless.ProcessInfo{}, nil)
			cleanup()
			if conn != nil {
				_ = conn.Close()
			}
			if err == nil {
				t.Fatal("accepted a SOCKS5 authentication method that was not offered")
			}
		})
	}
}

func TestReachableRelayAddress(t *testing.T) {
	tests := []struct {
		name   string
		relay  string
		server string
		want   string
	}{
		{"unspecified reply", "0.0.0.0:53000", "192.168.65.254:7890", "192.168.65.254:53000"},
		{"remote loopback reply", "127.0.0.1:53000", "192.168.65.254:7890", "192.168.65.254:53000"},
		{"local loopback reply", "127.0.0.1:53000", "127.0.0.1:7890", "127.0.0.1:53000"},
		{"routable reply", "192.0.2.20:53000", "192.0.2.10:7890", "192.0.2.20:53000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := reachableRelayAddress(netip.MustParseAddrPort(tt.relay), netip.MustParseAddrPort(tt.server))
			if got.String() != tt.want {
				t.Fatalf("relay = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCheckValidatesTCPAndUDPCommands(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	commands := make(chan byte, 2)
	go func() {
		for range 2 {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			func() {
				defer conn.Close()
				var greeting [2]byte
				if _, acceptErr = io.ReadFull(conn, greeting[:]); acceptErr != nil {
					return
				}
				methods := make([]byte, greeting[1])
				_, _ = io.ReadFull(conn, methods)
				_, _ = conn.Write([]byte{5, 0})
				var request [3]byte
				if _, acceptErr = io.ReadFull(conn, request[:]); acceptErr != nil {
					return
				}
				commands <- request[1]
				_, _ = readAddr(context.Background(), conn)
				_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0xcf, 0x08})
			}()
		}
	}()
	client := &Client{Address: listener.Addr().String()}
	result, err := client.Check(context.Background(), netip.MustParseAddrPort("192.0.2.1:443"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.TCP || !result.UDP || result.UDPRelay.Port() != 53000 {
		t.Fatalf("unexpected check result: %+v", result)
	}
	if first, second := <-commands, <-commands; first != 1 || second != 3 {
		t.Fatalf("commands = %d, %d", first, second)
	}
}
