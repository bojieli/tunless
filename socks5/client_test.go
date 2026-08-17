package socks5

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
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

func TestParseUDPDomainAddress(t *testing.T) {
	frame := []byte{3, 9}
	frame = append(frame, "localhost"...)
	frame = append(frame, 0, 53)
	address, used, err := parseAddr(context.Background(), frame)
	if err != nil {
		t.Fatal(err)
	}
	if used != len(frame) || address.Port() != 53 || !address.Addr().IsLoopback() {
		t.Fatalf("address = %s, used = %d", address, used)
	}
}

func TestSameAddrPortUnmapsIPv4(t *testing.T) {
	v4 := netip.MustParseAddrPort("127.0.0.1:53")
	mapped := netip.MustParseAddrPort("[::ffff:127.0.0.1]:53")
	if !sameAddrPort(v4, mapped) {
		t.Fatal("IPv4 and IPv4-mapped relay endpoints should compare equal")
	}
}

type contextPacketPort struct{}

func (contextPacketPort) ReadPacket(ctx context.Context) (tunless.Packet, error) {
	<-ctx.Done()
	return tunless.Packet{}, ctx.Err()
}

func (contextPacketPort) WritePacket(context.Context, tunless.Packet) error { return nil }
func (contextPacketPort) Close() error                                      { return nil }

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
