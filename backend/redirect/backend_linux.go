//go:build linux

// Package redirect captures flows that netfilter has already redirected to a
// local listener, for hosts where the eBPF backend cannot run.
//
// The socket-layer backend needs cgroup v2, CAP_BPF and a 5.7 kernel. Plenty of
// Linux hosts have none of those and all of them have netfilter: an older
// kernel, a distribution that disables unprivileged BPF, a managed node whose
// operator will grant NET_ADMIN and not CAP_BPF.
//
// The kernel still terminates TCP here, so a redirected connection arrives as
// an ordinary socket and the original destination is recovered from it with
// SO_ORIGINAL_DST. That is the whole reason to prefer this over a TUN device,
// which delivers packets and would need a second TCP/IP stack in userspace to
// turn them back into the byte streams a proxy can forward.
//
// # What this gives up
//
// Fail-open. The eBPF backend attaches an unpinned bpf_link, so if the process
// dies the attachment dies with it and new traffic goes direct. A netfilter
// rule outlives the process that benefits from it: kill this backend and the
// rule keeps sending connections at a port nobody is listening on, so they
// fail rather than bypassing. That is the property the project's main backend
// exists to preserve, and this one cannot.
//
// So it is a fallback, chosen deliberately and not by default, and the rule is
// the operator's to install and remove. Installing it here would mean mutating
// global state that no longer has an owner the moment this process is killed,
// which is exactly the failure mode the TUN critique in BLUEPRINT.md is about.
package redirect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	"github.com/bojieli/tunless"
	"golang.org/x/sys/unix"
)

// soOriginalDst is the getsockopt option netfilter answers with the address a
// connection was headed for before it was rewritten. The name and number are
// the same for IPv4 under SOL_IP and IPv6 under SOL_IPV6.
const soOriginalDst = 80

// Backend accepts connections netfilter has redirected and reports where each
// was originally going.
type Backend struct {
	// Address is the local address the netfilter rule redirects to. It must be
	// loopback: a rule pointing at a routable address would accept traffic
	// from off-host, and this backend has no way to tell that apart from a
	// redirect.
	Address string
	Filter  tunless.Filter

	mu       sync.Mutex
	listener net.Listener
	flows    chan tunless.Flow
	closed   bool
}

// Start listens and reports flows as they are redirected in.
func (b *Backend) Start(ctx context.Context) (<-chan tunless.Flow, error) {
	if b.Address == "" {
		return nil, errors.New("redirect backend needs a listen address")
	}
	// Process filters cannot be honoured here, and one that silently matches
	// nothing is worse than one that is refused: an operator who excluded a
	// process would believe it was excluded.
	if len(b.Filter.IncludeProcesses) > 0 || len(b.Filter.ExcludeProcesses) > 0 {
		return nil, errors.New("the redirect backend cannot attribute processes, so " +
			"--include-process and --exclude-process cannot be honoured; filter on " +
			"destinations, or use the eBPF backend")
	}
	host, _, err := net.SplitHostPort(b.Address)
	if err != nil {
		return nil, fmt.Errorf("redirect listen address: %w", err)
	}
	if ip, err := netip.ParseAddr(host); err != nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("redirect listen address %q must be a literal loopback IP; "+
			"a routable one would accept off-host traffic this backend cannot distinguish "+
			"from a redirect", b.Address)
	}
	ln, err := net.Listen("tcp", b.Address)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = ln.Close()
		return nil, net.ErrClosed
	}
	b.listener = ln
	b.flows = make(chan tunless.Flow)
	flows := b.flows
	b.mu.Unlock()

	go b.accept(ctx, ln, flows)
	return flows, nil
}

func (b *Backend) accept(ctx context.Context, ln net.Listener, flows chan tunless.Flow) {
	defer close(flows)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		dst, err := originalDestination(conn)
		if err != nil {
			// A connection with no redirect record was sent here by something
			// other than the rule. Refusing it is right: forwarding it would
			// make this backend an open proxy on loopback.
			_ = conn.Close()
			continue
		}
		// The capture floor applies here as it does everywhere. A redirect rule
		// wide enough to be useful is wide enough to catch the metadata
		// service, and sending that upstream loses it rather than routing it.
		if tunless.IsReservedDestination(dst.Addr()) {
			_ = conn.Close()
			continue
		}
		// Process is left empty. Recovering it would mean matching the source
		// port against /proc/net/tcp for an inode, then scanning every
		// process's descriptors for that inode, once per connection, racing a
		// process that may already have exited. Start refuses process filters
		// rather than running them against a field this backend never fills.
		flow := tunless.Flow{Proto: tunless.TCP, OrigDst: dst, Conn: conn}
		if !b.Filter.Capture(flow) {
			_ = conn.Close()
			continue
		}
		select {
		case flows <- flow:
		case <-ctx.Done():
			_ = conn.Close()
			return
		}
	}
}

// Close stops accepting. Connections already handed on are the caller's.
func (b *Backend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	if b.listener == nil {
		return nil
	}
	err := b.listener.Close()
	b.listener = nil
	return err
}

// Diagnostics reports what this backend is, so the doctor command can say
// which one is running and what it costs.
func (b *Backend) Diagnostics() tunless.BackendDiagnostics {
	b.mu.Lock()
	defer b.mu.Unlock()
	d := tunless.BackendDiagnostics{Name: "redirect"}
	if b.listener != nil {
		d.Started, d.Listeners = true, 1
	}
	return d
}

// originalDestination recovers where a redirected connection was headed.
//
// netfilter keeps the pre-rewrite address on the conntrack entry and hands it
// back through getsockopt. Without it the destination is lost: the socket's own
// remote address is this listener, which is the point of the redirect.
func originalDestination(conn net.Conn) (netip.AddrPort, error) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, errors.New("not a TCP connection")
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var addr netip.AddrPort
	var opErr error
	if err := raw.Control(func(fd uintptr) {
		addr, opErr = originalDestinationFD(fd)
	}); err != nil {
		return netip.AddrPort{}, err
	}
	return addr, opErr
}

func originalDestinationFD(fd uintptr) (netip.AddrPort, error) {
	// sockaddr_storage is large enough for either family, and the length the
	// kernel writes back says which one it filled in.
	var buf [128]byte
	size := uint32(len(buf))
	// IPv6 first: a dual-stack listener receives v4 connections as
	// v4-mapped, and asking SOL_IP about them succeeds while returning the
	// wrong family. Asking SOL_IPV6 first and falling back is the order that
	// gets both right.
	if _, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd,
		uintptr(unix.SOL_IPV6), soOriginalDst,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0); errno == 0 {
		if ap, ok := decodeSockaddr(buf[:size]); ok {
			return ap, nil
		}
	}
	size = uint32(len(buf))
	if _, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, fd,
		uintptr(unix.SOL_IP), soOriginalDst,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0); errno != 0 {
		return netip.AddrPort{}, fmt.Errorf("SO_ORIGINAL_DST: %w", errno)
	}
	ap, ok := decodeSockaddr(buf[:size])
	if !ok {
		return netip.AddrPort{}, errors.New("SO_ORIGINAL_DST returned an address of no known family")
	}
	return ap, nil
}

// decodeSockaddr reads a sockaddr_in or sockaddr_in6 as the kernel laid it
// out. The port is big-endian in both.
func decodeSockaddr(b []byte) (netip.AddrPort, bool) {
	if len(b) < 4 {
		return netip.AddrPort{}, false
	}
	family := uint16(b[0]) | uint16(b[1])<<8
	port := uint16(b[2])<<8 | uint16(b[3])
	switch family {
	case syscall.AF_INET:
		if len(b) < 8 {
			return netip.AddrPort{}, false
		}
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), port), true
	case syscall.AF_INET6:
		if len(b) < 24 {
			return netip.AddrPort{}, false
		}
		var a [16]byte
		copy(a[:], b[8:24])
		addr := netip.AddrFrom16(a)
		// A v4-mapped address is a v4 destination that arrived on a
		// dual-stack socket, and reporting it as v6 would not match any rule
		// an operator wrote.
		if addr.Is4In6() {
			addr = addr.Unmap()
		}
		return netip.AddrPortFrom(addr, port), true
	}
	return netip.AddrPort{}, false
}
