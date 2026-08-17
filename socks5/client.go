package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/bojieli/tunless"
)

type Client struct {
	Address          string
	Username         string
	Password         string
	MetadataUsername bool
	Registry         MetadataRegistry
	Dialer           net.Dialer
	HandshakeTimeout time.Duration
}

type MetadataRegistry interface {
	Register(uint16, tunless.ProcessInfo) func()
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
	value := fmt.Sprintf("pid=%d;path=%s;signing-id=%s", flow.Process.PID, flow.Process.Path, flow.Process.SigningID)
	if len(value) > 255 {
		value = value[:255]
	}
	return value, c.Password
}

func (c *Client) connect(ctx context.Context, command byte, dst netip.AddrPort, hostname, username, password string, process tunless.ProcessInfo, redirectRecords []byte) (net.Conn, netip.AddrPort, func(), error) {
	conn, err := dialContext(ctx, c.Dialer, "tcp", c.Address, redirectRecords)
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
	if _, err = conn.Write(append([]byte{5, byte(len(methods))}, methods...)); err != nil {
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
		if len(username) > 255 || len(password) > 255 {
			return fail(errors.New("SOCKS5 credentials exceed 255 bytes"))
		}
		auth := []byte{1, byte(len(username))}
		auth = append(auth, username...)
		auth = append(auth, byte(len(password)))
		auth = append(auth, password...)
		if _, err = conn.Write(auth); err != nil {
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
		if len(hostname) > 255 {
			return fail(errors.New("SOCKS5 hostname exceeds 255 bytes"))
		}
		req = append(req, 3, byte(len(hostname)))
		req = append(req, hostname...)
		req = binary.BigEndian.AppendUint16(req, dst.Port())
	} else {
		req = append(req, encodeAddr(dst)...)
	}
	if _, err = conn.Write(req); err != nil {
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

func (c *Client) emitTCP(ctx context.Context, flow tunless.Flow) error {
	username, password := c.credentials(flow)
	conn, _, cleanup, err := c.connect(ctx, 1, flow.OrigDst, flow.Hostname, username, password, flow.Process, flow.RedirectRecords)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer cleanup()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); _ = flow.Conn.Close() })
	defer stop()
	return tunless.Relay(flow.Conn, conn)
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
	defer udp.Close()
	stop := context.AfterFunc(ctx, func() { _ = udp.Close(); _ = flow.Packets.Close() })
	defer stop()
	errCh := make(chan error, 3)
	go func() {
		var unexpected [1]byte
		_, err := control.Read(unexpected[:])
		if err == nil {
			err = errors.New("SOCKS5 UDP control connection returned unexpected data")
		}
		errCh <- err
	}()
	go func() {
		for {
			packet, err := flow.Packets.ReadPacket(ctx)
			if err != nil {
				errCh <- err
				return
			}
			buf := []byte{0, 0, 0}
			buf = append(buf, encodeAddr(packet.Dst)...)
			buf = append(buf, packet.Payload...)
			if _, err = udp.WriteToUDPAddrPort(buf, relay); err != nil {
				errCh <- err
				return
			}
		}
	}()
	go func() {
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
			if err = flow.Packets.WritePacket(ctx, tunless.Packet{Payload: payload, Dst: dst}); err != nil {
				errCh <- err
				return
			}
		}
	}()
	err = <-errCh
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func sameAddrPort(a, b netip.AddrPort) bool {
	return a.Port() == b.Port() && a.Addr().Unmap() == b.Addr().Unmap()
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
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", string(b[:n]))
		if err != nil {
			return netip.AddrPort{}, err
		}
		if len(ips) == 0 {
			return netip.AddrPort{}, errors.New("SOCKS5 domain address resolved without results")
		}
		return netip.AddrPortFrom(ips[0], binary.BigEndian.Uint16(b[n:])), nil
	}
	addr, ok := netip.AddrFromSlice(b[:n])
	if !ok {
		return netip.AddrPort{}, errors.New("invalid address")
	}
	return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(b[n:])), nil
}

func parseAddr(ctx context.Context, b []byte) (netip.AddrPort, int, error) {
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
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", string(b[2:2+n]))
		if err != nil {
			return netip.AddrPort{}, 0, err
		}
		if len(ips) == 0 {
			return netip.AddrPort{}, 0, errors.New("SOCKS5 UDP domain address resolved without results")
		}
		return netip.AddrPortFrom(ips[0], binary.BigEndian.Uint16(b[2+n:])), 2 + n + 2, nil
	default:
		return netip.AddrPort{}, 0, errors.New("unsupported address")
	}
	if len(b) < 1+n+2 {
		return netip.AddrPort{}, 0, io.ErrUnexpectedEOF
	}
	a, _ := netip.AddrFromSlice(b[1 : 1+n])
	return netip.AddrPortFrom(a, binary.BigEndian.Uint16(b[1+n:])), 1 + n + 2, nil
}
