package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bojieli/tunless"
	"github.com/bojieli/tunless/internal/dnswire"
)

type Client struct {
	Address string
	// Alternates are further upstream addresses, tried in order when Address
	// does not connect. A named upstream is resolved once before capture
	// starts, and this is what a name's remaining addresses become.
	Alternates       []string
	Username         string
	Password         string
	MetadataUsername bool
	Registry         MetadataRegistry
	Dialer           net.Dialer
	HandshakeTimeout time.Duration
	DNSOverride      netip.AddrPort
	FlowIdleTimeout  time.Duration
	UDPIdleTimeout   time.Duration
	// LocalDomains are name suffixes the DNS override leaves with the
	// application's own resolver, in addition to the reserved and private name
	// spaces internal/dnsname recognises on its own.
	LocalDomains []string
	// ObserveDNS, when set, receives each query relayed to the trusted resolver
	// together with its answer, so that the addresses in that answer can be
	// associated with the name that was asked for.
	ObserveDNS func(query, reply []byte)
}

var ErrUDPIdleTimeout = errors.New("SOCKS5 UDP association idle timeout")

type MetadataRegistry interface {
	Register(uint16, tunless.ProcessInfo) func()
}

type CheckResult struct {
	TCP      bool           `json:"tcp_connect"`
	UDP      bool           `json:"udp_associate"`
	UDPRelay netip.AddrPort `json:"udp_relay"`
}

// Check authenticates to the configured server, opens a TCP CONNECT to target,
// and verifies that the server grants a UDP ASSOCIATE. It does not retain
// either association or send application payload.
func (c *Client) Check(ctx context.Context, target netip.AddrPort) (CheckResult, error) {
	if !target.IsValid() || target.Port() == 0 {
		return CheckResult{}, errors.New("SOCKS5 check target is invalid")
	}
	result := CheckResult{}
	tcp, _, cleanupTCP, err := c.connect(ctx, 1, target, "", c.Username, c.Password, tunless.ProcessInfo{}, nil)
	if err != nil {
		return result, fmt.Errorf("SOCKS5 TCP CONNECT check: %w", err)
	}
	result.TCP = true
	cleanupTCP()
	_ = tcp.Close()

	control, relay, cleanupUDP, err := c.connect(ctx, 3, netip.AddrPortFrom(netip.IPv4Unspecified(), 0), "", c.Username, c.Password, tunless.ProcessInfo{}, nil)
	if err != nil {
		return result, fmt.Errorf("SOCKS5 UDP ASSOCIATE check: %w", err)
	}
	defer control.Close()
	defer cleanupUDP()
	if remote, ok := control.RemoteAddr().(*net.TCPAddr); ok {
		relay = reachableRelayAddress(relay, remote.AddrPort())
	}
	if !relay.IsValid() || relay.Port() == 0 {
		return result, errors.New("SOCKS5 check returned an invalid UDP relay")
	}
	result.UDP = true
	result.UDPRelay = relay
	return result, nil
}

func (c *Client) register(conn net.Conn, process tunless.ProcessInfo) func() {
	if c.Registry == nil {
		return func() {}
	}
	addr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return func() {}
	}
	return c.Registry.Register(addr.AddrPort().Port(), process)
}

func (c *Client) Emit(ctx context.Context, flow tunless.Flow) error {
	if flow.DatapathOwned {
		return errors.New("datapath-owned flow must not be passed to the SOCKS5 emitter")
	}
	if err := flow.Validate(); err != nil {
		return fmt.Errorf("invalid flow: %w", err)
	}
	if c.DNSOverride.IsValid() && (c.DNSOverride.Port() == 0 || c.DNSOverride.Addr().Zone() != "") {
		return errors.New("SOCKS5 DNS override is invalid")
	}
	if c.FlowIdleTimeout < 0 || c.UDPIdleTimeout < 0 {
		return errors.New("SOCKS5 idle timeouts cannot be negative")
	}
	switch flow.Proto {
	case tunless.TCP:
		return c.emitTCP(ctx, flow)
	case tunless.UDP:
		return c.emitUDP(ctx, flow)
	default:
		return errors.New("unsupported flow protocol")
	}
}

func (c *Client) credentials(flow tunless.Flow) (string, string) {
	if !c.MetadataUsername {
		return c.Username, c.Password
	}
	// Paths and signing identifiers are controlled by the captured process.
	// Escape field delimiters so they cannot forge a neighboring identity field
	// when an upstream opts in to parsing this username convention.
	value := fmt.Sprintf("pid=%d;path=%s;signing-id=%s", flow.Process.PID, url.QueryEscape(flow.Process.Path), url.QueryEscape(flow.Process.SigningID))
	if len(value) > 255 {
		value = value[:255]
		// QueryEscape emits percent triplets. Do not leave an ambiguous partial
		// escape at the SOCKS username boundary.
		if escape := strings.LastIndexByte(value, '%'); escape >= len(value)-2 {
			value = value[:escape]
		}
	}
	return value, c.Password
}

func (c *Client) connect(ctx context.Context, command byte, dst netip.AddrPort, hostname, username, password string, process tunless.ProcessInfo, redirectRecords []byte) (net.Conn, netip.AddrPort, func(), error) {
	if command != 1 && command != 3 {
		return nil, netip.AddrPort{}, func() {}, errors.New("unsupported SOCKS5 command")
	}
	if len(username) > 255 || len(password) > 255 {
		return nil, netip.AddrPort{}, func() {}, errors.New("SOCKS5 credentials exceed 255 bytes")
	}
	if !dst.IsValid() || dst.Addr().Zone() != "" || (dst.Port() == 0 && (command != 3 || !dst.Addr().IsUnspecified())) {
		return nil, netip.AddrPort{}, func() {}, errors.New("SOCKS5 destination is invalid")
	}
	// A hostname that cannot be framed is not a reason to fail the flow. The
	// address is right there and always encodable, and a connection that
	// reaches its destination on IP rules alone is better than one that does
	// not happen at all. Only the routing precision is lost, and only for the
	// unusual names this rejects.
	hostname = usableHostname(hostname)
	conn, err := c.dialUpstream(ctx, redirectRecords)
	if err != nil {
		return nil, netip.AddrPort{}, func() {}, fmt.Errorf("dial SOCKS5 upstream: %w", err)
	}
	registryCleanup := c.register(conn, process)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	cleanup := func() {
		stop()
		registryCleanup()
	}
	fail := func(err error) (net.Conn, netip.AddrPort, func(), error) {
		cleanup()
		_ = conn.Close()
		return nil, netip.AddrPort{}, func() {}, err
	}
	handshakeTimeout := c.HandshakeTimeout
	if handshakeTimeout == 0 {
		handshakeTimeout = 10 * time.Second
	}
	if handshakeTimeout > 0 {
		if err = conn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
			return fail(fmt.Errorf("set SOCKS5 handshake deadline: %w", err))
		}
	}
	wantsAuth := username != "" || password != ""
	methods := []byte{0}
	if wantsAuth {
		// Configured credentials are intentional, and metadata usernames are
		// only useful if the server actually receives them. Do not also offer
		// no-auth: a permissive server could select it and silently discard the
		// identity attached to this flow.
		methods = []byte{2}
	}
	if err = writeAll(conn, append([]byte{5, byte(len(methods))}, methods...)); err != nil {
		return fail(err)
	}
	var choice [2]byte
	if _, err = io.ReadFull(conn, choice[:]); err != nil {
		return fail(fmt.Errorf("read SOCKS5 greeting: %w", err))
	}
	if choice[0] != 5 {
		return fail(fmt.Errorf("invalid SOCKS5 greeting version %d", choice[0]))
	}
	if choice[1] == 2 {
		if !wantsAuth {
			return fail(errors.New("SOCKS5 server selected an authentication method that was not offered"))
		}
		auth := []byte{1, byte(len(username))}
		auth = append(auth, username...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, password...)
		if err = writeAll(conn, auth); err != nil {
			return fail(err)
		}
		if _, err = io.ReadFull(conn, choice[:]); err != nil {
			return fail(fmt.Errorf("read SOCKS5 authentication reply: %w", err))
		}
		if choice[0] != 1 || choice[1] != 0 {
			return fail(errors.New("SOCKS5 authentication failed"))
		}
	} else if choice[1] == 0 {
		if wantsAuth {
			return fail(errors.New("SOCKS5 server selected no-auth even though it was not offered"))
		}
	} else {
		return fail(fmt.Errorf("SOCKS5 server selected unsupported auth method %d", choice[1]))
	}
	req := []byte{5, command, 0}
	if hostname != "" {
		req = append(req, 3, byte(len(hostname)))
		req = append(req, hostname...)
		req = binary.BigEndian.AppendUint16(req, dst.Port())
	} else {
		req = append(req, encodeAddr(dst)...)
	}
	if err = writeAll(conn, req); err != nil {
		return fail(err)
	}
	var header [3]byte
	if _, err = io.ReadFull(conn, header[:]); err != nil {
		return fail(err)
	}
	if header[0] != 5 || header[2] != 0 {
		return fail(errors.New("invalid SOCKS5 response header"))
	}
	if header[1] != 0 {
		return fail(fmt.Errorf("SOCKS5 request failed with status %d", header[1]))
	}
	bound, err := readAddr(ctx, conn)
	if err != nil {
		return fail(err)
	}
	if handshakeTimeout > 0 {
		if err = conn.SetDeadline(time.Time{}); err != nil {
			return fail(fmt.Errorf("clear SOCKS5 handshake deadline: %w", err))
		}
	}
	return conn, bound, cleanup, nil
}

// dialUpstream connects to the upstream, walking the addresses a named one
// resolved to until one answers.
//
// Handed a name, Go's dialer does this itself, and staggers the attempts so a
// host with broken IPv6 still reaches an IPv4 address quickly. Pinning the name
// before capture starts is what keeps a lookup out of the datapath, and it
// takes that fallback away, so the attempts happen here instead: in order, each
// bounded by the handshake timeout, so one unreachable address of a multi-homed
// proxy costs a bounded wait rather than the flow.
func (c *Client) dialUpstream(ctx context.Context, redirectRecords []byte) (net.Conn, error) {
	if len(c.Alternates) == 0 {
		return dialContext(ctx, c.Dialer, "tcp", c.Address, redirectRecords)
	}
	timeout := c.HandshakeTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	var failures []error
	for _, address := range append([]string{c.Address}, c.Alternates...) {
		attempt, cancel := ctx, context.CancelFunc(nil)
		if timeout > 0 {
			attempt, cancel = context.WithTimeout(ctx, timeout)
		}
		conn, err := dialContext(attempt, c.Dialer, "tcp", address, redirectRecords)
		if cancel != nil {
			// Cancelling after a successful dial does not disturb the
			// connection; the context covers the dial alone.
			cancel()
		}
		if err == nil {
			return conn, nil
		}
		failures = append(failures, err)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(failures...)
}

func (c *Client) emitTCP(ctx context.Context, flow tunless.Flow) error {
	username, password := c.credentials(flow)
	destination, hostname := c.routedTCPDestination(flow)
	conn, _, cleanup, err := c.connect(ctx, 1, destination, hostname, username, password, flow.Process, flow.RedirectRecords)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer cleanup()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); _ = flow.Conn.Close() })
	defer stop()
	idleTimeout := c.FlowIdleTimeout
	return tunless.RelayContext(ctx, flow.Conn, conn, idleTimeout)
}

func (c *Client) routedTCPDestination(flow tunless.Flow) (netip.AddrPort, string) {
	if c.DNSOverride.IsValid() && flow.OrigDst.Port() == 53 {
		return c.DNSOverride, ""
	}
	return flow.OrigDst, flow.Hostname
}

func (c *Client) emitUDP(ctx context.Context, flow tunless.Flow) error {
	username, password := c.credentials(flow)
	control, relay, cleanup, err := c.connect(ctx, 3, netip.AddrPortFrom(netip.IPv4Unspecified(), 0), "", username, password, flow.Process, flow.RedirectRecords)
	if err != nil {
		return err
	}
	defer control.Close()
	defer cleanup()
	if remote, ok := control.RemoteAddr().(*net.TCPAddr); ok {
		relay = reachableRelayAddress(relay, remote.AddrPort())
	}
	if !relay.IsValid() || relay.Port() == 0 {
		return errors.New("SOCKS5 server returned an invalid UDP relay address")
	}
	udpNetwork := "udp6"
	if relay.Addr().Unmap().Is4() {
		udpNetwork = "udp4"
	}
	udp, err := net.ListenUDP(udpNetwork, nil)
	if err != nil {
		return err
	}
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()
	var closeOnce sync.Once
	closeAll := func() {
		closeOnce.Do(func() {
			cancelWorkers()
			_ = control.Close()
			_ = udp.Close()
			_ = flow.Packets.Close()
		})
	}
	defer closeAll()
	errCh := make(chan error, 3)
	activity := make(chan struct{}, 1)
	touch := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}
	translations := newDNSTransactionMap(4096, 30*time.Second)
	translations.localDomains = c.LocalDomains
	translations.observe = c.ObserveDNS
	// Datagrams neither side could carry. Counted rather than ignored, so a
	// session that quietly loses traffic still says so when it ends.
	var dropped atomic.Uint64
	// Replies to datagrams that bypassed the proxy re-enter the flow the same
	// way relayed ones do, addressed from the destination the sender used.
	directRelay := newDirectDatagramRelay(func(payload []byte, from netip.AddrPort) {
		if err := flow.Packets.WritePacket(workerCtx, tunless.Packet{Payload: payload, Dst: from}); err != nil {
			dropped.Add(1)
		}
	})
	defer directRelay.close()
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		var unexpected [1]byte
		_, err := control.Read(unexpected[:])
		if err == nil {
			err = errors.New("SOCKS5 UDP control connection returned unexpected data")
		}
		errCh <- err
	}()
	go func() {
		defer workers.Done()
		for {
			packet, err := flow.Packets.ReadPacket(workerCtx)
			if err != nil {
				errCh <- err
				return
			}
			if err = packet.Validate(); err != nil {
				dropped.Add(1)
				continue
			}
			payload, destination, direct := translations.prepare(packet.Payload, packet.Dst, c.DNSOverride)
			if direct {
				if !directRelay.send(payload, destination) {
					dropped.Add(1)
				}
				touch()
				continue
			}
			address := encodeAddr(destination)
			if 3+len(address)+len(payload) > maxUDPDatagramSize(udpNetwork) {
				dropped.Add(1)
				continue
			}
			buf := make([]byte, 3, 3+len(address)+len(payload))
			buf = append(buf, address...)
			buf = append(buf, payload...)
			if _, err = udp.WriteToUDPAddrPort(buf, relay); err != nil {
				errCh <- err
				return
			}
			touch()
		}
	}()
	go func() {
		defer workers.Done()
		buf := make([]byte, 65535)
		for {
			n, peer, err := udp.ReadFromUDPAddrPort(buf)
			if err != nil {
				errCh <- err
				return
			}
			if !sameAddrPort(peer, relay) {
				continue
			}
			if n < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
				continue
			}
			dst, used, err := parseAddr(ctx, buf[3:n])
			if err != nil {
				continue
			}
			payload := append([]byte(nil), buf[3+used:n]...)
			payload, dst = translations.restore(payload, dst)
			if err = flow.Packets.WritePacket(workerCtx, tunless.Packet{Payload: payload, Dst: dst}); err != nil {
				if errors.Is(err, tunless.ErrDatagramRejected) {
					dropped.Add(1)
					continue
				}
				errCh <- err
				return
			}
			touch()
		}
	}()

	idleTimeout := c.UDPIdleTimeout
	var timer *time.Timer
	var idle <-chan time.Time
	if idleTimeout > 0 {
		timer = time.NewTimer(idleTimeout)
		idle = timer.C
		defer timer.Stop()
	}
	selecting := true
	for selecting {
		select {
		case err = <-errCh:
			selecting = false
		case <-ctx.Done():
			err = ctx.Err()
			selecting = false
		case <-activity:
			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(idleTimeout)
			}
		case <-idle:
			err = ErrUDPIdleTimeout
			selecting = false
		}
	}
	closeAll()
	workers.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if count := dropped.Load(); count > 0 && err != nil {
		return fmt.Errorf("%w (dropped %d datagram(s) this association could not carry)", err, count)
	}
	return err
}

// ExchangeDNSUDP sends one DNS datagram through a dedicated SOCKS5 UDP
// association. It is used by the optional DNS observer so the observer itself
// never opens a direct resolver socket outside the captured cgroup.
func (c *Client) ExchangeDNSUDP(ctx context.Context, destination netip.AddrPort, query []byte) ([]byte, error) {
	if !destination.IsValid() || destination.Port() == 0 || destination.Addr().Zone() != "" || len(query) > 65535 {
		return nil, errors.New("DNS destination is invalid")
	}
	control, relay, cleanup, err := c.connect(ctx, 3, netip.AddrPortFrom(netip.IPv4Unspecified(), 0), "", c.Username, c.Password, tunless.ProcessInfo{}, nil)
	if err != nil {
		return nil, err
	}
	defer control.Close()
	defer cleanup()
	if remote, ok := control.RemoteAddr().(*net.TCPAddr); ok {
		relay = reachableRelayAddress(relay, remote.AddrPort())
	}
	if !relay.IsValid() || relay.Port() == 0 {
		return nil, errors.New("SOCKS5 server returned an invalid UDP relay address")
	}
	network := "udp6"
	if relay.Addr().Unmap().Is4() {
		network = "udp4"
	}
	udp, err := net.ListenUDP(network, nil)
	if err != nil {
		return nil, err
	}
	defer udp.Close()
	stop := context.AfterFunc(ctx, func() { _ = udp.Close(); _ = control.Close() })
	defer stop()
	address := encodeAddr(destination)
	if 3+len(address)+len(query) > maxUDPDatagramSize(network) {
		return nil, errors.New("DNS UDP query exceeds the SOCKS5 relay datagram limit")
	}
	frame := make([]byte, 3, 3+len(address)+len(query))
	frame = append(frame, address...)
	frame = append(frame, query...)
	if _, err = udp.WriteToUDPAddrPort(frame, relay); err != nil {
		return nil, err
	}
	buffer := make([]byte, 65535)
	for {
		n, peer, readErr := udp.ReadFromUDPAddrPort(buffer)
		if readErr != nil {
			return nil, readErr
		}
		if !sameAddrPort(peer, relay) || n < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
			continue
		}
		source, used, parseErr := parseAddr(ctx, buffer[3:n])
		if parseErr != nil || !sameAddrPort(source, destination) {
			continue
		}
		if !dnswire.AnswersQuery(query, buffer[3+used:n]) {
			continue
		}
		return append([]byte(nil), buffer[3+used:n]...), nil
	}
}

// ExchangeDNSTCP sends one length-prefixed DNS query through SOCKS5 CONNECT.
func (c *Client) ExchangeDNSTCP(ctx context.Context, destination netip.AddrPort, query []byte) ([]byte, error) {
	if !destination.IsValid() || destination.Port() == 0 || destination.Addr().Zone() != "" || len(query) > 65535 {
		return nil, errors.New("DNS query or destination is invalid")
	}
	connection, _, cleanup, err := c.connect(ctx, 1, destination, "", c.Username, c.Password, tunless.ProcessInfo{}, nil)
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	defer cleanup()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	frame := make([]byte, 2, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query))) // #nosec G115 -- length is checked above
	frame = append(frame, query...)
	if err = writeAll(connection, frame); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err = io.ReadFull(connection, size[:]); err != nil {
		return nil, err
	}
	reply := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err = io.ReadFull(connection, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func sameAddrPort(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && a.Addr().Unmap() == b.Addr().Unmap()
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if written < 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func maxUDPDatagramSize(network string) int {
	if network == "udp4" {
		return 65507
	}
	return 65527
}

func reachableRelayAddress(relay, server netip.AddrPort) netip.AddrPort {
	// SOCKS servers commonly return an unspecified or loopback UDP relay
	// address. Loopback is usable only when the server itself was reached
	// through loopback; across Docker Desktop it would point back into the
	// controller container instead of at the host bridge.
	if relay.Addr().IsUnspecified() || (relay.Addr().IsLoopback() && !server.Addr().IsLoopback()) {
		return netip.AddrPortFrom(server.Addr(), relay.Port())
	}
	return relay
}

func encodeAddr(a netip.AddrPort) []byte {
	addr := a.Addr().Unmap()
	var out []byte
	if addr.Is4() {
		out = append(out, 1)
		out = append(out, addr.AsSlice()...)
	} else {
		out = append(out, 4)
		out = append(out, addr.AsSlice()...)
	}
	return binary.BigEndian.AppendUint16(out, a.Port())
}

func readAddr(ctx context.Context, r io.Reader) (netip.AddrPort, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return netip.AddrPort{}, err
	}
	var n int
	switch atyp[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var size [1]byte
		if _, err := io.ReadFull(r, size[:]); err != nil {
			return netip.AddrPort{}, err
		}
		n = int(size[0])
		if n == 0 {
			return netip.AddrPort{}, errors.New("empty SOCKS5 domain address")
		}
	default:
		return netip.AddrPort{}, errors.New("invalid SOCKS5 address type")
	}
	b := make([]byte, n+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return netip.AddrPort{}, err
	}
	if atyp[0] == 3 {
		// BND.ADDR is informational for CONNECT. For UDP ASSOCIATE, an
		// unspecified result is safely replaced with the already-numeric SOCKS
		// peer address. Never invoke the host resolver for a server-supplied name.
		return netip.AddrPortFrom(netip.IPv4Unspecified(), binary.BigEndian.Uint16(b[n:])), nil
	}
	addr, ok := netip.AddrFromSlice(b[:n])
	if !ok {
		return netip.AddrPort{}, errors.New("invalid address")
	}
	return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(b[n:])), nil
}

// usableHostname returns hostname when it can be carried in a SOCKS5 request,
// and "" when the caller should fall back to the numeric address.
//
// SOCKS5 gives the domain field a single length byte, so anything past 255
// bytes cannot be represented at all. The rest of the check is about what a
// downstream proxy will do with the value: a name carrying spaces, control
// bytes, or a NUL either gets rejected or, worse, parsed as something other
// than what was sent.
func usableHostname(hostname string) string {
	if hostname == "" || len(hostname) > 255 {
		return ""
	}
	for i := 0; i < len(hostname); i++ {
		if hostname[i] <= ' ' || hostname[i] == 0x7f {
			return ""
		}
	}
	return hostname
}

func parseAddr(_ context.Context, b []byte) (netip.AddrPort, int, error) {
	if len(b) < 1 {
		return netip.AddrPort{}, 0, io.ErrUnexpectedEOF
	}
	n := 0
	switch b[0] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		if len(b) < 2 {
			return netip.AddrPort{}, 0, io.ErrUnexpectedEOF
		}
		n = int(b[1])
		if n == 0 || len(b) < 2+n+2 {
			return netip.AddrPort{}, 0, errors.New("invalid SOCKS5 UDP domain address")
		}
		return netip.AddrPort{}, 0, errors.New("SOCKS5 UDP domain address requires forbidden local DNS resolution")
	default:
		return netip.AddrPort{}, 0, errors.New("unsupported address")
	}
	if len(b) < 1+n+2 {
		return netip.AddrPort{}, 0, io.ErrUnexpectedEOF
	}
	a, ok := netip.AddrFromSlice(b[1 : 1+n])
	port := binary.BigEndian.Uint16(b[1+n:])
	if !ok || port == 0 {
		return netip.AddrPort{}, 0, errors.New("invalid SOCKS5 UDP source address")
	}
	return netip.AddrPortFrom(a, port), 1 + n + 2, nil
}
