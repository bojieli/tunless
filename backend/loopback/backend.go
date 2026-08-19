// Package loopback implements an explicit SOCKS5 listener used as the
// privilege-free reference backend and conformance target.
package loopback

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bojieli/tunless"
	"golang.org/x/net/netutil"
)

const (
	defaultMaxConnections = 4096
	maxHTTPHeaderBytes    = 32 << 10
)

type Backend struct {
	Address          string
	HandshakeTimeout time.Duration
	MaxConnections   int

	mu       sync.Mutex
	listener net.Listener
	udpIP    net.IP
	flows    chan tunless.Flow
	cancel   context.CancelFunc
	acceptWG sync.WaitGroup
	flowWG   sync.WaitGroup
}

func (b *Backend) Addr() net.Addr {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.listener == nil {
		return nil
	}
	return b.listener.Addr()
}

func (b *Backend) Diagnostics() tunless.BackendDiagnostics {
	b.mu.Lock()
	defer b.mu.Unlock()
	started := b.listener != nil
	listeners := 0
	if started {
		listeners = 1
	}
	return tunless.BackendDiagnostics{Name: "loopback", Started: started, Listeners: listeners}
}

func (b *Backend) Start(ctx context.Context) (<-chan tunless.Flow, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		return nil, errors.New("loopback backend already started")
	}
	addr := b.Address
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	if err := validateListenAddress(addr); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	maxConnections := b.MaxConnections
	if maxConnections == 0 {
		maxConnections = defaultMaxConnections
	}
	if maxConnections < 0 {
		_ = ln.Close()
		return nil, errors.New("loopback backend connection limit cannot be negative")
	}
	ln = netutil.LimitListener(ln, maxConnections)
	ctx, b.cancel = context.WithCancel(ctx)
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = ln.Close()
		return nil, fmt.Errorf("unexpected listener address %T", ln.Addr())
	}
	b.listener, b.udpIP, b.flows = ln, append(net.IP(nil), tcpAddr.IP...), make(chan tunless.Flow)
	b.acceptWG.Add(1)
	go b.accept(ctx, ln)
	return b.flows, nil
}

func validateListenAddress(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return errors.New("loopback backend listen address must be loopback IP:port")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() {
		return errors.New("loopback backend may listen only on a numeric loopback address")
	}
	if _, err = strconv.ParseUint(port, 10, 16); err != nil {
		return errors.New("loopback backend listen port must be between 0 and 65535")
	}
	return nil
}

func (b *Backend) Close() error {
	err := b.closeResources()
	b.acceptWG.Wait()
	b.flowWG.Wait()
	return err
}

func (b *Backend) closeResources() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		b.cancel()
	}
	var err error
	if b.listener != nil {
		err = b.listener.Close()
		b.listener = nil
	}
	return err
}

func (b *Backend) accept(ctx context.Context, ln net.Listener) {
	defer b.acceptWG.Done()
	defer func() {
		b.flowWG.Wait()
		close(b.flows)
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			_ = b.closeResources()
			return
		}
		b.flowWG.Add(1)
		go func() { defer b.flowWG.Done(); b.handle(ctx, conn) }()
	}
}

func (b *Backend) handle(ctx context.Context, conn net.Conn) {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	keep := false
	defer func() {
		if !keep {
			_ = conn.Close()
		}
	}()
	handshakeTimeout := b.HandshakeTimeout
	if handshakeTimeout == 0 {
		handshakeTimeout = 10 * time.Second
	}
	if handshakeTimeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
			return
		}
	}
	reader := bufio.NewReader(conn)
	first, err := reader.Peek(1)
	if err != nil {
		return
	}
	if first[0] != 5 {
		keep = b.handleHTTP(ctx, conn, reader)
		return
	}
	var greeting [2]byte
	if _, err := io.ReadFull(reader, greeting[:]); err != nil {
		return
	}
	methods := make([]byte, greeting[1])
	if _, err := io.ReadFull(reader, methods); err != nil {
		return
	}
	method := byte(0xff)
	for _, offered := range methods {
		if offered == 0 {
			method = 0
			break
		}
		if offered == 2 {
			method = 2
		}
	}
	if _, err := conn.Write([]byte{5, method}); err != nil || method == 0xff {
		return
	}
	if method == 2 && !acceptCredentials(reader, conn) {
		return
	}
	var request [3]byte
	if _, err := io.ReadFull(reader, request[:]); err != nil || request[0] != 5 || request[2] != 0 {
		return
	}
	dst, hostname, err := readAddress(ctx, reader)
	if err != nil {
		return
	}
	process := currentProcess()
	switch request[1] {
	case 1:
		if dst.Port() == 0 {
			_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		if err = conn.SetDeadline(time.Time{}); err != nil {
			return
		}
		if _, err = conn.Write(reply(netip.AddrPortFrom(netip.IPv4Unspecified(), 0))); err != nil {
			return
		}
		flow := tunless.Flow{Proto: tunless.TCP, OrigDst: dst, Hostname: hostname, Process: process, Conn: conn}
		select {
		case b.flows <- flow:
			keep = true
		case <-ctx.Done():
		}
	case 3:
		// Bind the UDP association to the configured TCP listener address. A
		// bridge container can then reach a listener placed on the host bridge
		// gateway instead of receiving an unusable 127.0.0.1 relay address.
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: b.udpIP})
		if err != nil {
			return
		}
		defer udp.Close()
		bound := udp.LocalAddr().(*net.UDPAddr).AddrPort()
		if err = conn.SetDeadline(time.Time{}); err != nil {
			return
		}
		if _, err = conn.Write(reply(bound)); err != nil {
			return
		}
		b.serveUDP(ctx, conn, udp, process)
	default:
		_, _ = conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func acceptCredentials(reader io.Reader, conn net.Conn) bool {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil || header[0] != 1 {
		return false
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, username); err != nil {
		return false
	}
	var size [1]byte
	if _, err := io.ReadFull(reader, size[:]); err != nil {
		return false
	}
	password := make([]byte, int(size[0]))
	if _, err := io.ReadFull(reader, password); err != nil {
		return false
	}
	_, err := conn.Write([]byte{1, 0})
	return err == nil
}

func (b *Backend) handleHTTP(ctx context.Context, conn net.Conn, reader *bufio.Reader) bool {
	limited := &io.LimitedReader{R: reader, N: maxHTTPHeaderBytes + 1}
	requestReader := bufio.NewReader(limited)
	request, err := http.ReadRequest(requestReader)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
		return false
	}
	// ReadRequest may have prefetched body bytes. Drain that reader through its
	// limit and then continue from the original connection reader.
	reader = bufio.NewReader(io.MultiReader(requestReader, reader))
	if request.Method != http.MethodConnect {
		return b.handleHTTPForward(ctx, conn, reader, request)
	}
	host, port := splitHostPort(request.Host, "443")
	dst, hostname, err := resolveHostPort(ctx, host, port)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return false
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return false
	}
	if _, err = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return false
	}
	flow := tunless.Flow{Proto: tunless.TCP, OrigDst: dst, Hostname: hostname, Process: currentProcess(), Conn: &bufferedConn{Conn: conn, reader: reader}}
	select {
	case b.flows <- flow:
		return true
	case <-ctx.Done():
		return false
	}
}

func (b *Backend) handleHTTPForward(ctx context.Context, conn net.Conn, reader *bufio.Reader, request *http.Request) bool {
	host := request.URL.Hostname()
	port := request.URL.Port()
	if host == "" {
		host, port = splitHostPort(request.Host, "80")
	} else if port == "" {
		port = "80"
		if request.URL.Scheme == "https" {
			port = "443"
		}
	}
	dst, hostname, err := resolveHostPort(ctx, host, port)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return false
	}
	path := request.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	var prefix bytes.Buffer
	_, _ = fmt.Fprintf(&prefix, "%s %s HTTP/%d.%d\r\n", request.Method, path, request.ProtoMajor, request.ProtoMinor)
	_, _ = fmt.Fprintf(&prefix, "Host: %s\r\n", request.Host)
	header := request.Header.Clone()
	for _, connection := range header.Values("Connection") {
		for token := range strings.SplitSeq(connection, ",") {
			header.Del(strings.TrimSpace(token))
		}
	}
	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection", "TE", "Trailer", "Upgrade"} {
		header.Del(name)
	}
	header.Set("Connection", "close")
	if request.ContentLength >= 0 {
		header.Set("Content-Length", fmt.Sprint(request.ContentLength))
	}
	if len(request.TransferEncoding) > 0 {
		header.Set("Transfer-Encoding", strings.Join(request.TransferEncoding, ", "))
	}
	_ = header.Write(&prefix)
	prefix.WriteString("\r\n")
	flow := tunless.Flow{
		Proto:    tunless.TCP,
		OrigDst:  dst,
		Hostname: hostname,
		Process:  currentProcess(),
		Conn:     &bufferedConn{Conn: conn, reader: bufio.NewReader(io.MultiReader(bytes.NewReader(prefix.Bytes()), reader))},
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return false
	}
	select {
	case b.flows <- flow:
		return true
	case <-ctx.Done():
		return false
	}
}

func splitHostPort(authority, defaultPort string) (string, string) {
	host, port, err := net.SplitHostPort(authority)
	if err == nil {
		return host, port
	}
	return strings.Trim(authority, "[]"), defaultPort
}

func resolveHostPort(ctx context.Context, host, port string) (netip.AddrPort, string, error) {
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return netip.AddrPort{}, "", errors.New("invalid port")
	}
	parsedPort := uint16(value)
	if addr, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(addr, parsedPort), "", nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, "", fmt.Errorf("resolve %s: %w", host, err)
	}
	return netip.AddrPortFrom(ips[0], parsedPort), host, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (b *Backend) serveUDP(ctx context.Context, control net.Conn, udp *net.UDPConn, process tunless.ProcessInfo) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { var x [1]byte; _, _ = control.Read(x[:]); cancel(); _ = udp.Close() }()
	buf := make([]byte, 65535)
	var port *packetPort
	for {
		n, peer, err := udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		if port != nil && !sameAddrPort(peer, port.peer) {
			continue
		}
		dst, used, err := parseDatagram(ctx, buf[:n])
		if err != nil {
			continue
		}
		if port == nil {
			port = &packetPort{ctx: ctx, udp: udp, peer: peer, in: make(chan tunless.Packet, 32)}
			flow := tunless.Flow{Proto: tunless.UDP, OrigDst: dst, Process: process, Packets: port}
			select {
			case b.flows <- flow:
			case <-ctx.Done():
				return
			}
		}
		packet := tunless.Packet{Dst: dst, Payload: append([]byte(nil), buf[used:n]...)}
		select {
		case port.in <- packet:
		case <-ctx.Done():
			return
		}
	}
}

type packetPort struct {
	ctx  context.Context
	udp  *net.UDPConn
	peer netip.AddrPort
	in   chan tunless.Packet
	once sync.Once
}

func (p *packetPort) ReadPacket(ctx context.Context) (tunless.Packet, error) {
	select {
	case v := <-p.in:
		return v, nil
	case <-ctx.Done():
		return tunless.Packet{}, ctx.Err()
	case <-p.ctx.Done():
		return tunless.Packet{}, p.ctx.Err()
	}
}
func (p *packetPort) WritePacket(ctx context.Context, v tunless.Packet) error {
	if err := v.Validate(); err != nil {
		return err
	}
	address := encodeAddress(v.Dst)
	network := "udp6"
	if p.udp.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap().Is4() {
		network = "udp4"
	}
	if 3+len(address)+len(v.Payload) > maxUDPDatagramSize(network) {
		return errors.New("UDP response exceeds the SOCKS5 relay datagram limit")
	}
	b := make([]byte, 3, 3+len(address)+len(v.Payload))
	b = append(b, address...)
	b = append(b, v.Payload...)
	_, err := p.udp.WriteToUDPAddrPort(b, p.peer)
	return err
}
func (p *packetPort) Close() error {
	var err error
	p.once.Do(func() { err = p.udp.Close() })
	return err
}

func currentProcess() tunless.ProcessInfo {
	path, _ := os.Executable()
	pid := os.Getpid()
	if pid < 0 || int64(pid) > int64(^uint32(0)>>1) {
		return tunless.ProcessInfo{Path: path}
	}
	return tunless.ProcessInfo{PID: int32(pid), Path: path} // #nosec G115 -- range is checked above
}

func reply(a netip.AddrPort) []byte { return append([]byte{5, 0, 0}, encodeAddress(a)...) }

func encodeAddress(a netip.AddrPort) []byte {
	a = netip.AddrPortFrom(a.Addr().Unmap(), a.Port())
	out := []byte{}
	if a.Addr().Is4() {
		out = append(out, 1)
		out = append(out, a.Addr().AsSlice()...)
	} else {
		out = append(out, 4)
		out = append(out, a.Addr().AsSlice()...)
	}
	return binary.BigEndian.AppendUint16(out, a.Port())
}

func readAddress(ctx context.Context, r io.Reader) (netip.AddrPort, string, error) {
	var typ [1]byte
	if _, err := io.ReadFull(r, typ[:]); err != nil {
		return netip.AddrPort{}, "", err
	}
	var n int
	var hostname string
	switch typ[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var s [1]byte
		if _, err := io.ReadFull(r, s[:]); err != nil {
			return netip.AddrPort{}, "", err
		}
		n = int(s[0])
		if n == 0 {
			return netip.AddrPort{}, "", errors.New("empty domain address")
		}
	default:
		return netip.AddrPort{}, "", errors.New("bad address type")
	}
	b := make([]byte, n+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return netip.AddrPort{}, "", err
	}
	var addr netip.Addr
	if typ[0] == 3 {
		hostname = string(b[:n])
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", hostname)
		if err != nil {
			return netip.AddrPort{}, hostname, err
		}
		if len(ips) == 0 {
			return netip.AddrPort{}, hostname, errors.New("domain address resolved without results")
		}
		addr = ips[0]
	} else {
		addr, _ = netip.AddrFromSlice(b[:n])
	}
	port := binary.BigEndian.Uint16(b[n:])
	if !addr.IsValid() {
		return netip.AddrPort{}, hostname, errors.New("invalid destination address")
	}
	return netip.AddrPortFrom(addr, port), hostname, nil
}

func parseDatagram(ctx context.Context, b []byte) (netip.AddrPort, int, error) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return netip.AddrPort{}, 0, errors.New("invalid UDP frame")
	}
	typ := b[3]
	n := 0
	offset := 4
	switch typ {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		if len(b) < 5 {
			return netip.AddrPort{}, 0, io.ErrUnexpectedEOF
		}
		n = int(b[4])
		if n == 0 || len(b) < 5+n+2 {
			return netip.AddrPort{}, 0, errors.New("invalid UDP domain address")
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", string(b[5:5+n]))
		if err != nil {
			return netip.AddrPort{}, 0, err
		}
		if len(ips) == 0 {
			return netip.AddrPort{}, 0, errors.New("UDP domain address resolved without results")
		}
		port := binary.BigEndian.Uint16(b[5+n:])
		if port == 0 {
			return netip.AddrPort{}, 0, errors.New("UDP domain destination has port zero")
		}
		return netip.AddrPortFrom(ips[0], port), 5 + n + 2, nil
	default:
		return netip.AddrPort{}, 0, errors.New("unsupported UDP address")
	}
	if len(b) < offset+n+2 {
		return netip.AddrPort{}, 0, io.ErrUnexpectedEOF
	}
	a, _ := netip.AddrFromSlice(b[offset : offset+n])
	port := binary.BigEndian.Uint16(b[offset+n:])
	if !a.IsValid() || port == 0 {
		return netip.AddrPort{}, 0, errors.New("invalid UDP destination address")
	}
	return netip.AddrPortFrom(a, port), offset + n + 2, nil
}

func maxUDPDatagramSize(network string) int {
	if network == "udp4" {
		return 65507
	}
	return 65527
}

func sameAddrPort(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && a.Addr().Unmap() == b.Addr().Unmap()
}
