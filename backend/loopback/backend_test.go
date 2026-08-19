package loopback

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
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

func TestParseDatagramRejectsZeroPort(t *testing.T) {
	frame := []byte{0, 0, 0, 1, 192, 0, 2, 1, 0, 0}
	if _, _, err := parseDatagram(context.Background(), frame); err == nil {
		t.Fatal("accepted a UDP destination with port zero")
	}
}

func TestSameAddrPortUnmapsIPv4(t *testing.T) {
	v4 := netip.MustParseAddrPort("127.0.0.1:53000")
	mapped := netip.MustParseAddrPort("[::ffff:127.0.0.1]:53000")
	if !sameAddrPort(v4, mapped) {
		t.Fatal("IPv4 and IPv4-mapped UDP peers should compare equal")
	}
}

func TestRejectsNonLoopbackListener(t *testing.T) {
	for _, address := range []string{"", ":1080", "0.0.0.0:1080", "localhost:1080", "192.0.2.1:1080", "127.0.0.1:socks", "127.0.0.1:65536"} {
		if address == "" {
			continue // The empty value intentionally selects the secure default.
		}
		if err := validateListenAddress(address); err == nil {
			t.Fatalf("accepted loopback backend address %q", address)
		}
	}
	for _, address := range []string{"127.0.0.1:0", "127.0.0.1:1080", "[::1]:1080"} {
		if err := validateListenAddress(address); err != nil {
			t.Fatalf("rejected loopback backend address %q: %v", address, err)
		}
	}
}

func TestRejectsNegativeConnectionLimit(t *testing.T) {
	backend := &Backend{Address: "127.0.0.1:0", MaxConnections: -1}
	if _, err := backend.Start(context.Background()); err == nil {
		t.Fatal("accepted a negative connection limit")
	}
}

func TestUnexpectedAcceptFailureCancelsPendingHandshakes(t *testing.T) {
	backend := &Backend{Address: "127.0.0.1:0", HandshakeTimeout: -1}
	flows, err := backend.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	address := backend.Addr().String()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	backend.mu.Lock()
	listener := backend.listener
	backend.mu.Unlock()
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-flows:
		if ok {
			t.Fatal("backend emitted a flow while stopping")
		}
	case <-time.After(time.Second):
		t.Fatal("pending handshake survived an unexpected listener failure")
	}
}

func TestLoopbackBackendCannotRestartAfterClose(t *testing.T) {
	backend := &Backend{Address: "127.0.0.1:0"}
	if _, err := backend.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Start(context.Background()); err == nil {
		t.Fatal("restarted a one-shot backend with stale lifecycle state")
	}
}

func TestHTTPHeaderLimitAndHopByHopRemoval(t *testing.T) {
	t.Run("oversized", func(t *testing.T) {
		backend, address := startTestBackend(t)
		defer backend.Close()
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "GET http://example.test/ HTTP/1.1\r\nX-Large: "+strings.Repeat("a", maxHTTPHeaderBytes)+"\r\n\r\n")
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(line, "400 Bad Request") {
			t.Fatalf("response status = %q", strings.TrimSpace(line))
		}
	})

	t.Run("hop-by-hop", func(t *testing.T) {
		backend, address := startTestBackend(t)
		defer backend.Close()
		conn, err := net.Dial("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "GET http://127.0.0.1:8080/path HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nConnection: X-Secret, keep-alive\r\nX-Secret: remove-me\r\nProxy-Authorization: secret\r\n\r\n")
		select {
		case flow := <-backend.flows:
			defer flow.Conn.Close()
			_ = flow.Conn.SetReadDeadline(time.Now().Add(time.Second))
			reader := bufio.NewReader(flow.Conn)
			header, readErr := reader.ReadString('\n')
			if readErr != nil {
				t.Fatal(readErr)
			}
			all := header
			for {
				line, lineErr := reader.ReadString('\n')
				all += line
				if lineErr != nil || line == "\r\n" {
					break
				}
			}
			lower := strings.ToLower(all)
			if strings.Contains(lower, "x-secret") || strings.Contains(lower, "proxy-authorization") || !strings.Contains(lower, "connection: close") {
				t.Fatalf("forwarded headers were not sanitized:\n%s", all)
			}
		case <-time.After(time.Second):
			t.Fatal("HTTP flow was not emitted")
		}
	})
}

func startTestBackend(t *testing.T) (*Backend, string) {
	t.Helper()
	backend := &Backend{Address: "127.0.0.1:0"}
	if _, err := backend.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	address := backend.Addr()
	if address == nil {
		t.Fatal("backend did not publish its listener address")
	}
	return backend, address.String()
}
