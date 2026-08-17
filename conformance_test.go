package tunless_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bojieli/tunless"
	"github.com/bojieli/tunless/backend/loopback"
	"github.com/bojieli/tunless/socks5"
)

type directEmitter struct{}

func (directEmitter) Emit(ctx context.Context, f tunless.Flow) error {
	if f.Proto == tunless.TCP {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", f.OrigDst.String())
		if err != nil {
			return err
		}
		defer conn.Close()
		return tunless.Relay(f.Conn, conn)
	}
	for {
		packet, err := f.Packets.ReadPacket(ctx)
		if err != nil {
			return err
		}
		conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(packet.Dst))
		if err != nil {
			return err
		}
		if _, err = conn.Write(packet.Payload); err != nil {
			conn.Close()
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			return err
		}
		if err = f.Packets.WritePacket(ctx, tunless.Packet{Dst: packet.Dst, Payload: buf[:n]}); err != nil {
			return err
		}
	}
}

type stack struct {
	cancel   context.CancelFunc
	backends []*loopback.Backend
	wg       sync.WaitGroup
	addr     string
}

func startStack(t *testing.T) *stack {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &stack{cancel: cancel}
	down := &loopback.Backend{Address: "127.0.0.1:0"}
	s.backends = append(s.backends, down)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = (&tunless.Core{Backend: down, Emitter: directEmitter{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Run(ctx)
	}()
	downAddr := waitAddr(t, down)
	up := &loopback.Backend{Address: "127.0.0.1:0"}
	s.backends = append(s.backends, up)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = (&tunless.Core{Backend: up, Emitter: &socks5.Client{Address: downAddr}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Run(ctx)
	}()
	s.addr = waitAddr(t, up)
	return s
}

func (s *stack) close() {
	s.cancel()
	for _, b := range s.backends {
		_ = b.Close()
	}
	s.wg.Wait()
}
func waitAddr(t *testing.T, b *loopback.Backend) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if a := b.Addr(); a != nil {
			return a.String()
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("backend did not start")
	return ""
}

func TestTCPConformance(t *testing.T) {
	targetAddr, closeTarget := tcpEcho(t, "tcp4", "127.0.0.1:0")
	defer closeTarget()
	s := startStack(t)
	defer s.close()
	conn := socksConnect(t, s.addr, targetAddr)
	defer conn.Close()
	payload := make([]byte, 2<<20)
	for i := range payload {
		payload[i] = byte(i)
	}
	done := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- err
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if len(got) != len(payload) {
		t.Fatalf("large half-closed transfer: got %d bytes, want %d", len(got), len(payload))
	}
	for i := range got {
		if got[i] != payload[i] {
			t.Fatalf("payload differs at byte %d", i)
		}
	}
}

func TestHTTPConnectReferenceBackend(t *testing.T) {
	targetAddr, closeTarget := tcpEcho(t, "tcp4", "127.0.0.1:0")
	defer closeTarget()
	s := startStack(t)
	defer s.close()
	conn, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "CONNECT "+targetAddr+" HTTP/1.1\r\nHost: "+targetAddr+"\r\n\r\n")
	reader := bufio.NewReader(conn)
	reply, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if reply.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status %s", reply.Status)
	}
	_, _ = conn.Write([]byte("http-connect"))
	got := make([]byte, len("http-connect"))
	if _, err = io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "http-connect" {
		t.Fatalf("echo = %q", got)
	}
}

func TestHTTPForwardReferenceBackend(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RequestURI != "/through-proxy?value=1" {
			t.Errorf("request URI = %q", r.RequestURI)
		}
		_, _ = io.WriteString(w, "forwarded")
	}))
	defer target.Close()
	s := startStack(t)
	defer s.close()
	proxyURL := &url.URL{Scheme: "http", Host: s.addr}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}, Timeout: 5 * time.Second}
	response, err := client.Get(target.URL + "/through-proxy?value=1")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "forwarded" {
		t.Fatalf("response body = %q", body)
	}
}

func TestIPv6Conformance(t *testing.T) {
	targetAddr, closeTarget := tcpEcho(t, "tcp6", "[::1]:0")
	if targetAddr == "" {
		t.Skip("IPv6 loopback unavailable")
	}
	defer closeTarget()
	s := startStack(t)
	defer s.close()
	conn := socksConnect(t, s.addr, targetAddr)
	defer conn.Close()
	_, _ = conn.Write([]byte("ipv6"))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ipv6" {
		t.Fatalf("got %q", buf)
	}
}

func TestUDPConformance(t *testing.T) {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, peer, e := udp.ReadFromUDPAddrPort(buf)
			if e != nil {
				return
			}
			_, _ = udp.WriteToUDPAddrPort(buf[:n], peer)
		}
	}()
	s := startStack(t)
	defer s.close()
	control, relay := socksUDPAssociate(t, s.addr)
	defer control.Close()
	socket, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	payload := []byte("datagram through two SOCKS hops")
	frame := udpFrame(udp.LocalAddr().(*net.UDPAddr).AddrPort(), payload)
	if _, err = socket.WriteToUDPAddrPort(frame, relay); err != nil {
		t.Fatal(err)
	}
	_ = socket.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1024)
	n, _, err := socket.ReadFromUDPAddrPort(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < len(payload) || string(buf[n-len(payload):n]) != string(payload) {
		t.Fatalf("unexpected UDP reply %x", buf[:n])
	}
}

func TestLoopbackUDPRelayUsesConfiguredAddress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := &loopback.Backend{Address: "[::1]:0"}
	if _, err := backend.Start(ctx); err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer backend.Close()
	control, relay := socksUDPAssociate(t, waitAddr(t, backend))
	defer control.Close()
	if want := netip.IPv6Loopback(); relay.Addr() != want {
		t.Fatalf("UDP relay address = %s, want %s", relay.Addr(), want)
	}
}

func TestCancellationMidTransfer(t *testing.T) {
	targetAddr, closeTarget := tcpEcho(t, "tcp4", "127.0.0.1:0")
	defer closeTarget()
	s := startStack(t)
	conn := socksConnect(t, s.addr, targetAddr)
	_, _ = conn.Write(make([]byte, 64<<10))
	s.close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, err := io.Copy(io.Discard, conn)
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("connection did not close after cancellation")
	}
	_ = conn.Close()
}

func TestLoopbackMetadata(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &loopback.Backend{Address: "127.0.0.1:0"}
	flows, err := b.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	c, err := net.Dial("tcp", waitAddr(t, b))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{5, 1, 0})
	readExact(t, c, 2)
	host := "localhost"
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, 443)
	_, _ = c.Write(req)
	readExact(t, c, 3)
	readEncoded(t, c)
	select {
	case flow := <-flows:
		if flow.Hostname != host {
			t.Fatalf("hostname = %q, want %q", flow.Hostname, host)
		}
		if flow.OrigDst.Port() != 443 {
			t.Fatalf("destination = %v", flow.OrigDst)
		}
		if flow.Process.PID != int32(os.Getpid()) || flow.Process.Path == "" {
			t.Fatalf("incomplete process identity: %+v", flow.Process)
		}
		_ = flow.Conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("flow was not emitted")
	}
}

func tcpEcho(t *testing.T, network, address string) (string, func()) {
	t.Helper()
	ln, err := net.Listen(network, address)
	if err != nil {
		return "", func() {}
	}
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func socksConnect(t *testing.T, proxy, target string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte{5, 1, 0})
	readExact(t, c, 2)
	a := netip.MustParseAddrPort(target)
	req := append([]byte{5, 1, 0}, encoded(a)...)
	_, _ = c.Write(req)
	reply := readExact(t, c, 3)
	if reply[1] != 0 {
		t.Fatalf("SOCKS status %d", reply[1])
	}
	readEncoded(t, c)
	return c
}
func socksUDPAssociate(t *testing.T, proxy string) (net.Conn, netip.AddrPort) {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte{5, 1, 0})
	readExact(t, c, 2)
	_, _ = c.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	h := readExact(t, c, 3)
	if h[1] != 0 {
		t.Fatal("UDP associate failed")
	}
	return c, readEncoded(t, c)
}
func readExact(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		t.Fatal(err)
	}
	return b
}
func readEncoded(t *testing.T, r io.Reader) netip.AddrPort {
	t.Helper()
	typ := readExact(t, r, 1)[0]
	n := 4
	if typ == 4 {
		n = 16
	}
	b := readExact(t, r, n+2)
	a, _ := netip.AddrFromSlice(b[:n])
	return netip.AddrPortFrom(a, binary.BigEndian.Uint16(b[n:]))
}
func encoded(a netip.AddrPort) []byte {
	ip := a.Addr().Unmap()
	typ := byte(1)
	if ip.Is6() {
		typ = 4
	}
	b := append([]byte{typ}, ip.AsSlice()...)
	return binary.BigEndian.AppendUint16(b, a.Port())
}
func udpFrame(a netip.AddrPort, p []byte) []byte {
	b := []byte{0, 0, 0}
	b = append(b, encoded(a)...)
	return append(b, p...)
}
