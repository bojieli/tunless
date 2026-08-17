package socks5

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"

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
