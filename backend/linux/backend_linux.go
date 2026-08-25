//go:build linux

package linux

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/bojieli/tunless"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

//go:embed bpf/tunless_bpf.o
var program []byte

type Backend struct {
	CgroupPath       string
	NetworkNamespace string
	Address          string
	Filter           tunless.Filter

	mu         sync.Mutex
	cancel     context.CancelFunc
	listeners  []net.Listener
	udp        []*net.UDPConn
	links      []link.Link
	collection *ebpf.Collection
	flows      chan tunless.Flow
	wg         sync.WaitGroup
	sessions   map[udpSessionKey]*packetPort
}

func (b *Backend) Diagnostics() tunless.BackendDiagnostics {
	b.mu.Lock()
	diagnostics := tunless.BackendDiagnostics{
		Name:         "linux",
		Started:      b.collection != nil,
		Listeners:    len(b.listeners),
		UDPSockets:   len(b.udp),
		Links:        len(b.links),
		Associations: len(b.sessions),
	}
	if b.collection == nil {
		b.mu.Unlock()
		return diagnostics
	}
	diagnostics.Maps = make(map[string]tunless.MapDiagnostics, len(b.collection.Maps))
	clones := make(map[string]*ebpf.Map, len(b.collection.Maps))
	for name, m := range b.collection.Maps {
		clone, err := m.Clone()
		if err != nil {
			diagnostics.Maps[name] = tunless.MapDiagnostics{Error: err.Error()}
			continue
		}
		clones[name] = clone
	}
	b.mu.Unlock()
	for name, m := range clones {
		item := tunless.MapDiagnostics{}
		info, err := m.Info()
		if err != nil {
			item.Error = err.Error()
			diagnostics.Maps[name] = item
			_ = m.Close()
			continue
		}
		item.MaxEntries = info.MaxEntries
		item.Memlock, _ = info.Memlock()
		key := make([]byte, info.KeySize)
		value := make([]byte, info.ValueSize)
		iterator := m.Iterate()
		for iterator.Next(&key, &value) {
			item.Entries++
		}
		if err = iterator.Err(); err != nil {
			item.Error = err.Error()
		}
		diagnostics.Maps[name] = item
		_ = m.Close()
	}
	return diagnostics
}

func (b *Backend) Start(ctx context.Context) (<-chan tunless.Flow, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		return nil, errors.New("linux backend already started")
	}
	if b.CgroupPath == "" {
		return nil, errors.New("linux backend requires a cgroup v2 path")
	}
	if err := b.Filter.Validate(); err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil && !errors.Is(err, os.ErrPermission) {
		return nil, fmt.Errorf("memlock: %w", err)
	}
	port, listeners, udp, err := listenSockets(b.Address, b.NetworkNamespace)
	if err != nil {
		return nil, err
	}
	cleanup := func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
		for _, c := range udp {
			_ = c.Close()
		}
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(program))
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("read eBPF object: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("load eBPF programs: %w", err)
	}
	config := make([]byte, 24)
	v4 := netip.MustParseAddr("127.0.0.1").As4()
	copy(config, v4[:])
	v6 := netip.IPv6Loopback().As16()
	copy(config[4:20], v6[:])
	binary.BigEndian.PutUint16(config[20:22], port)
	// An include list is an allowlist, not a per-family one. Both flags go on
	// together so that a family nobody named matches nothing instead of
	// everything: asking to capture 203.0.113.0/24 and getting every IPv6
	// destination along with it is the opposite of narrowing, and it is what
	// the macOS provider already does with the same flags.
	if len(b.Filter.IncludeDestinations) > 0 {
		config[22], config[23] = 1, 1
	}
	if err = collection.Maps["config_map"].Put(uint32(0), config); err != nil {
		collection.Close()
		cleanup()
		return nil, fmt.Errorf("configure eBPF: %w", err)
	}
	if err = loadPrefixes(collection, "include", withMappedForms(b.Filter.IncludeDestinations)); err != nil {
		collection.Close()
		cleanup()
		return nil, err
	}
	// The floor goes in before the operator's exclusions and is not reachable
	// from the configuration: the program consults the exclusion maps before
	// the inclusion maps, so nothing a filter says can put these back.
	if err = loadPrefixes(collection, "exclude", withMappedForms(reservedCapturePrefixes())); err != nil {
		collection.Close()
		cleanup()
		return nil, err
	}
	if err = loadPrefixes(collection, "exclude", withMappedForms(b.Filter.ExcludeDestinations)); err != nil {
		collection.Close()
		cleanup()
		return nil, err
	}
	attachments := []struct {
		name   string
		attach ebpf.AttachType
	}{
		{"connect4", ebpf.AttachCGroupInet4Connect}, {"connect6", ebpf.AttachCGroupInet6Connect}, {"established", ebpf.AttachCGroupSockOps},
		{"udp_sendmsg4", ebpf.AttachCGroupUDP4Sendmsg}, {"udp_sendmsg6", ebpf.AttachCGroupUDP6Sendmsg}, {"udp_recvmsg4", ebpf.AttachCGroupUDP4Recvmsg}, {"udp_recvmsg6", ebpf.AttachCGroupUDP6Recvmsg},
	}
	var links []link.Link
	for _, item := range attachments {
		lnk, e := link.AttachCgroup(link.CgroupOptions{Path: b.CgroupPath, Attach: item.attach, Program: collection.Programs[item.name]})
		if e != nil {
			for _, old := range links {
				_ = old.Close()
			}
			collection.Close()
			cleanup()
			return nil, fmt.Errorf("attach %s: %w", item.name, e)
		}
		links = append(links, lnk)
	}
	ctx, b.cancel = context.WithCancel(ctx)
	b.listeners = listeners
	b.udp = udp
	b.links = links
	b.collection = collection
	b.flows = make(chan tunless.Flow)
	b.sessions = make(map[udpSessionKey]*packetPort)
	for _, ln := range listeners {
		b.wg.Add(1)
		go b.accept(ctx, ln)
	}
	b.wg.Add(1)
	go b.readPackets4(ctx, udp[0])
	b.wg.Add(1)
	go b.readPackets(ctx, udp[1])
	flows := b.flows
	go func() {
		b.wg.Wait()
		close(flows)
	}()
	go func() { <-ctx.Done(); b.closeResources() }()
	return b.flows, nil
}

func loadPrefixes(collection *ebpf.Collection, kind string, prefixes []netip.Prefix) error {
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		// Deliberately not unmapped: a prefix in IPv4-mapped form describes what
		// the IPv6 hooks see, and belongs in the IPv6 map at its 128-bit length.
		addr := prefix.Addr()
		var key []byte
		name := kind + "6"
		if addr.Is4() {
			name = kind + "4"
			key = make([]byte, 8)
			binary.LittleEndian.PutUint32(key, uint32(prefix.Bits()))
			a := addr.As4()
			copy(key[4:], a[:])
		} else {
			key = make([]byte, 20)
			binary.LittleEndian.PutUint32(key, uint32(prefix.Bits()))
			a := addr.As16()
			copy(key[4:], a[:])
		}
		if err := collection.Maps[name].Put(key, uint8(1)); err != nil {
			return fmt.Errorf("load %s prefix %s: %w", kind, prefix, err)
		}
	}
	return nil
}

func listenSockets(address, networkNamespace string) (uint16, []net.Listener, []*net.UDPConn, error) {
	if networkNamespace == "" {
		return listenSocketsCurrentNamespace(address)
	}
	type result struct {
		port      uint16
		listeners []net.Listener
		udp       []*net.UDPConn
		err       error
	}
	completed := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		unlock := true
		defer func() {
			if unlock {
				runtime.UnlockOSThread()
			}
		}()
		current, err := os.Open("/proc/self/ns/net")
		if err != nil {
			completed <- result{err: fmt.Errorf("open current network namespace: %w", err)}
			return
		}
		defer current.Close()
		target, err := os.Open(networkNamespace)
		if err != nil {
			completed <- result{err: fmt.Errorf("open target network namespace: %w", err)}
			return
		}
		defer target.Close()
		if err = unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
			completed <- result{err: fmt.Errorf("enter target network namespace: %w", err)}
			return
		}
		port, listeners, udp, listenErr := listenSocketsCurrentNamespace(address)
		if restoreErr := unix.Setns(int(current.Fd()), unix.CLONE_NEWNET); restoreErr != nil {
			for _, listener := range listeners {
				_ = listener.Close()
			}
			for _, socket := range udp {
				_ = socket.Close()
			}
			// Returning from a goroutine that remains locked terminates this OS
			// thread. Never release a thread whose network namespace could not be
			// restored back into the Go scheduler's shared pool.
			unlock = false
			completed <- result{err: fmt.Errorf("restore host network namespace: %w", restoreErr)}
			return
		}
		completed <- result{port: port, listeners: listeners, udp: udp, err: listenErr}
	}()
	created := <-completed
	return created.port, created.listeners, created.udp, created.err
}

func listenSocketsCurrentNamespace(address string) (uint16, []net.Listener, []*net.UDPConn, error) {
	port, err := parseRedirectListenPort(address)
	if err != nil {
		return 0, nil, nil, err
	}
	v4, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
	if err != nil {
		return 0, nil, nil, err
	}
	actual := v4.Addr().(*net.TCPAddr).AddrPort().Port()
	v6, err := net.Listen("tcp6", net.JoinHostPort("::1", fmt.Sprint(actual)))
	if err != nil {
		_ = v4.Close()
		return 0, nil, nil, err
	}
	// The IPv4 redirect socket is the one thing here that cannot be pinned to a
	// single address. Each captured UDP association is redirected to its own
	// 127.x.y.z relay address, derived from the socket cookie, and that address
	// is how a datagram is correlated back to the flow that sent it. Receiving
	// across all of 127.0.0.0/8 means binding the wildcard; a socket bound to
	// one address only ever sees datagrams addressed to that one.
	//
	// What that opens is a port reachable from the network, so the receive path
	// checks that a datagram was delivered to a loopback address before doing
	// anything with it. Correlation would refuse a foreign one anyway — every
	// key in the relay map is a 127.x address — but an invariant this load
	// bearing is worth stating where it is relied on.
	u4, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: int(actual)})
	if err != nil {
		_ = v4.Close()
		_ = v6.Close()
		return 0, nil, nil, err
	}
	u6, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: int(actual)})
	if err != nil {
		_ = v4.Close()
		_ = v6.Close()
		_ = u4.Close()
		return 0, nil, nil, err
	}
	return actual, []net.Listener{v4, v6}, []*net.UDPConn{u4, u6}, nil
}

func tupleKey(ap netip.AddrPort, proto byte) []byte {
	key := make([]byte, 24)
	addr := ap.Addr().Unmap()
	if addr.Is4() {
		v := addr.As4()
		copy(key, v[:])
		key[18] = 2
	} else {
		v := addr.As16()
		copy(key, v[:])
		key[18] = 10
	}
	binary.BigEndian.PutUint16(key[16:18], ap.Port())
	key[19] = proto
	return key
}

func decodeOriginal(value []byte) (netip.AddrPort, tunless.ProcessInfo, error) {
	dst, pid, cgroupID, err := decodeOriginalRecord(value)
	if err != nil {
		return netip.AddrPort{}, tunless.ProcessInfo{}, err
	}
	path, _ := os.Readlink(filepath.Join("/proc", fmt.Sprint(pid), "exe"))
	return dst, tunless.ProcessInfo{PID: pid, Path: path, CgroupID: cgroupID}, nil
}

func (b *Backend) lookup(ap netip.AddrPort, proto byte) (uint64, []byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.collection == nil {
		return 0, nil, net.ErrClosed
	}
	var cookie uint64
	key := tupleKey(ap, proto)
	if err := b.collection.Maps["tuple_map"].Lookup(key, &cookie); err != nil {
		if proto != 17 || !ap.Addr().Is6() {
			return 0, nil, err
		}
		// At the UDP6 sendmsg hook an unbound socket has its source port but
		// not yet its selected source address. The listener sees ::1 after
		// redirection, so retry the correlation key with an unspecified IP.
		key = tupleKey(netip.AddrPortFrom(netip.IPv6Unspecified(), ap.Port()), proto)
		if err = b.collection.Maps["tuple_map"].Lookup(key, &cookie); err != nil {
			return 0, nil, err
		}
	}
	value := make([]byte, 32)
	if err := b.collection.Maps["original_map"].Lookup(cookie, &value); err != nil {
		return 0, nil, err
	}
	return cookie, value, nil
}

func (b *Backend) accept(ctx context.Context, ln net.Listener) {
	defer b.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			b.closeResources()
			return
		}
		peer := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		cookie, value, err := b.lookup(peer, 6)
		if err != nil {
			_ = conn.Close()
			continue
		}
		dst, process, err := decodeOriginal(value)
		if err != nil {
			_ = conn.Close()
			continue
		}
		b.mu.Lock()
		if b.collection != nil {
			_ = b.collection.Maps["tuple_map"].Delete(tupleKey(peer, 6))
			_ = b.collection.Maps["original_map"].Delete(cookie)
		}
		b.mu.Unlock()
		flow := tunless.Flow{Proto: tunless.TCP, OrigDst: dst, Process: process, Conn: conn}
		select {
		case b.flows <- flow:
		case <-ctx.Done():
			_ = conn.Close()
			return
		}
	}
}

func (b *Backend) readPackets(ctx context.Context, conn *net.UDPConn) {
	defer b.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, peer, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			b.closeResources()
			return
		}
		cookie, value, err := b.lookup(peer, 17)
		if err != nil {
			continue
		}
		dst, process, err := decodeOriginal(value)
		if err != nil {
			continue
		}
		sessionKey := makeUDPSessionKey("udp6", peer, cookie)
		b.mu.Lock()
		port := b.sessions[sessionKey]
		fresh := port == nil
		if fresh {
			port = &packetPort{ctx: ctx, backend: b, conn: conn, peer: peer, cookie: cookie, sessionKey: sessionKey, in: make(chan tunless.Packet, 64)}
			b.sessions[sessionKey] = port
		}
		b.mu.Unlock()
		if fresh {
			flow := tunless.Flow{Proto: tunless.UDP, OrigDst: dst, Process: process, Packets: port}
			select {
			case b.flows <- flow:
			case <-ctx.Done():
				return
			}
		}
		packet := tunless.Packet{Dst: dst, Payload: append([]byte(nil), buf[:n]...)}
		select {
		case port.in <- packet:
		case <-ctx.Done():
			return
		}
	}
}

func (b *Backend) readPackets4(ctx context.Context, conn *net.UDPConn) {
	defer b.wg.Done()
	raw, err := conn.SyscallConn()
	if err != nil {
		b.closeResources()
		return
	}
	var optionErr error
	if err = raw.Control(func(fd uintptr) { optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1) }); err != nil || optionErr != nil {
		b.closeResources()
		return
	}
	buf, oob := make([]byte, 65535), make([]byte, 128)
	for {
		n, oobn, _, peer, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			b.closeResources()
			return
		}
		var relayKey uint32
		var relayIP netip.Addr
		messages, _ := unix.ParseSocketControlMessage(oob[:oobn])
		for _, message := range messages {
			if message.Header.Level == unix.IPPROTO_IP && message.Header.Type == unix.IP_PKTINFO && len(message.Data) >= 12 {
				relayKey = binary.LittleEndian.Uint32(message.Data[8:12])
				relayIP, _ = netip.AddrFromSlice(message.Data[8:12])
			}
		}
		// See the wildcard bind in listenSocketsCurrentNamespace: this socket
		// can be reached from off the machine, and a redirected datagram is
		// always delivered to the 127.x relay address BPF chose for its flow.
		if relayKey == 0 || !relayIP.IsLoopback() {
			continue
		}
		var cookie uint64
		value := make([]byte, 32)
		b.mu.Lock()
		if b.collection == nil {
			b.mu.Unlock()
			return
		}
		err = b.collection.Maps["udp_relay_map"].Lookup(relayKey, &cookie)
		if err == nil {
			err = b.collection.Maps["original_map"].Lookup(cookie, &value)
		}
		b.mu.Unlock()
		if err != nil {
			continue
		}
		dst, process, err := decodeOriginal(value)
		if err != nil {
			continue
		}
		sessionKey := makeUDPSessionKey("udp4", peer, cookie)
		b.mu.Lock()
		port := b.sessions[sessionKey]
		fresh := port == nil
		if fresh {
			port = &packetPort{ctx: ctx, backend: b, conn: conn, peer: peer, cookie: cookie, relay: relayIP, sessionKey: sessionKey, in: make(chan tunless.Packet, 64)}
			b.sessions[sessionKey] = port
		}
		b.mu.Unlock()
		if fresh {
			flow := tunless.Flow{Proto: tunless.UDP, OrigDst: dst, Process: process, Packets: port}
			select {
			case b.flows <- flow:
			case <-ctx.Done():
				return
			}
		}
		packet := tunless.Packet{Dst: dst, Payload: append([]byte(nil), buf[:n]...)}
		select {
		case port.in <- packet:
		case <-ctx.Done():
			return
		}
	}
}

type packetPort struct {
	ctx        context.Context
	backend    *Backend
	conn       *net.UDPConn
	peer       netip.AddrPort
	cookie     uint64
	relay      netip.Addr
	sessionKey udpSessionKey
	in         chan tunless.Packet
	once       sync.Once
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
func (p *packetPort) WritePacket(_ context.Context, v tunless.Packet) error {
	if err := v.Validate(); err != nil {
		return err
	}
	p.backend.mu.Lock()
	collection := p.backend.collection
	if collection == nil {
		p.backend.mu.Unlock()
		return net.ErrClosed
	}
	value := make([]byte, 32)
	if err := collection.Maps["original_map"].Lookup(p.cookie, &value); err != nil {
		p.backend.mu.Unlock()
		return err
	}
	err := validateUDPResponseRecord(value, v.Dst)
	p.backend.mu.Unlock()
	if err != nil {
		return err
	}
	if p.relay.Is4() {
		_, err := ipv4.NewPacketConn(p.conn).WriteTo(v.Payload, &ipv4.ControlMessage{Src: net.IP(p.relay.AsSlice())}, net.UDPAddrFromAddrPort(p.peer))
		return err
	}
	_, err = p.conn.WriteToUDPAddrPort(v.Payload, p.peer)
	return err
}
func (p *packetPort) Close() error {
	p.once.Do(func() {
		p.backend.mu.Lock()
		delete(p.backend.sessions, p.sessionKey)
		collection := p.backend.collection
		if collection != nil {
			value := make([]byte, 32)
			if err := collection.Maps["original_map"].Lookup(p.cookie, &value); err == nil {
				protocol, connected, decodeErr := decodeOriginalProtocol(value)
				if decodeErr == nil && protocol == originalProtocolUDP && !connected {
					// An unconnected socket may select a new destination only after its
					// userspace association has ended. Remove every correlation key before
					// the original record so a concurrent send can at worst be dropped,
					// never attached to the association that is closing.
					if p.relay.Is4() {
						relay := p.relay.As4()
						_ = collection.Maps["udp_relay_map"].Delete(binary.LittleEndian.Uint32(relay[:]))
					} else {
						_ = collection.Maps["tuple_map"].Delete(tupleKey(p.peer, originalProtocolUDP))
						unspecified := netip.AddrPortFrom(netip.IPv6Unspecified(), p.peer.Port())
						_ = collection.Maps["tuple_map"].Delete(tupleKey(unspecified, originalProtocolUDP))
					}
					_ = collection.Maps["original_map"].Delete(p.cookie)
				}
			}
		}
		// Connected UDP sockets cannot recreate their connect-hook state after a
		// transient SOCKS failure, so their marked records remain until LRU
		// reclamation and allow the next datagram to open a fresh association.
		p.backend.mu.Unlock()
	})
	return nil
}

func (b *Backend) Close() error {
	b.closeResources()
	b.wg.Wait()
	return nil
}
func (b *Backend) closeResources() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		b.cancel()
	}
	// Stop new kernel redirection before closing its userspace endpoints. This
	// avoids a teardown window in which fresh connections are sent to dead
	// listeners.
	for _, lnk := range b.links {
		_ = lnk.Close()
	}
	b.links = nil
	for _, ln := range b.listeners {
		_ = ln.Close()
	}
	b.listeners = nil
	for _, c := range b.udp {
		_ = c.Close()
	}
	b.udp = nil
	if b.collection != nil {
		b.collection.Close()
		b.collection = nil
	}
}
