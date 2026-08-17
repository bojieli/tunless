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
	sessions   map[string]*packetPort
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
		return nil, errors.New("Linux backend already started")
	}
	if b.CgroupPath == "" {
		return nil, errors.New("Linux backend requires a cgroup v2 path")
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
	for _, prefix := range b.Filter.IncludeDestinations {
		if prefix.Addr().Unmap().Is4() {
			config[22] = 1
		} else {
			config[23] = 1
		}
	}
	if err = collection.Maps["config_map"].Put(uint32(0), config); err != nil {
		collection.Close()
		cleanup()
		return nil, fmt.Errorf("configure eBPF: %w", err)
	}
	if err = loadPrefixes(collection, "include", b.Filter.IncludeDestinations); err != nil {
		collection.Close()
		cleanup()
		return nil, err
	}
	if err = loadPrefixes(collection, "exclude", b.Filter.ExcludeDestinations); err != nil {
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
	b.sessions = make(map[string]*packetPort)
	for _, ln := range listeners {
		b.wg.Add(1)
		go b.accept(ctx, ln)
	}
	b.wg.Add(1)
	go b.readPackets4(ctx, udp[0])
	b.wg.Add(1)
	go b.readPackets(ctx, udp[1])
	go func() { <-ctx.Done(); b.closeResources() }()
	return b.flows, nil
}

func loadPrefixes(collection *ebpf.Collection, kind string, prefixes []netip.Prefix) error {
	for _, prefix := range prefixes {
		prefix = prefix.Masked()
		addr := prefix.Addr().Unmap()
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	current, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return 0, nil, nil, fmt.Errorf("open current network namespace: %w", err)
	}
	defer current.Close()
	target, err := os.Open(networkNamespace)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("open target network namespace: %w", err)
	}
	defer target.Close()
	if err = unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
		return 0, nil, nil, fmt.Errorf("enter target network namespace: %w", err)
	}
	port, listeners, udp, listenErr := listenSocketsCurrentNamespace(address)
	restoreErr := unix.Setns(int(current.Fd()), unix.CLONE_NEWNET)
	if restoreErr != nil {
		for _, listener := range listeners {
			_ = listener.Close()
		}
		for _, socket := range udp {
			_ = socket.Close()
		}
		return 0, nil, nil, fmt.Errorf("restore host network namespace: %w", restoreErr)
	}
	return port, listeners, udp, listenErr
}

func listenSocketsCurrentNamespace(address string) (uint16, []net.Listener, []*net.UDPConn, error) {
	port := uint16(0)
	if address != "" {
		_, p, err := net.SplitHostPort(address)
		if err != nil {
			return 0, nil, nil, err
		}
		parsed, err := netip.ParseAddrPort(net.JoinHostPort("127.0.0.1", p))
		if err != nil {
			return 0, nil, nil, err
		}
		port = parsed.Port()
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
	var dst netip.Addr
	switch value[18] {
	case 2:
		dst, _ = netip.AddrFromSlice(value[:4])
	case 10:
		dst, _ = netip.AddrFromSlice(value[:16])
	default:
		return netip.AddrPort{}, tunless.ProcessInfo{}, fmt.Errorf("unknown address family %d", value[18])
	}
	pid := int32(binary.LittleEndian.Uint32(value[20:24]))
	path, _ := os.Readlink(filepath.Join("/proc", fmt.Sprint(pid), "exe"))
	return netip.AddrPortFrom(dst, binary.BigEndian.Uint16(value[16:18])), tunless.ProcessInfo{PID: pid, Path: path, CgroupID: binary.LittleEndian.Uint64(value[24:32])}, nil
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
		sessionKey := conn.LocalAddr().Network() + "/" + peer.String()
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
		return
	}
	if err = raw.Control(func(fd uintptr) { err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1) }); err != nil {
		return
	}
	buf, oob := make([]byte, 65535), make([]byte, 128)
	for {
		n, oobn, _, peer, err := conn.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
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
		if relayKey == 0 {
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
		sessionKey := "udp4/" + peer.String()
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
	sessionKey string
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
	addr := v.Dst.Addr().Unmap()
	if addr.Is4() {
		a := addr.As4()
		copy(value, a[:])
		value[18] = 2
	} else {
		a := addr.As16()
		copy(value, a[:])
		value[18] = 10
	}
	binary.BigEndian.PutUint16(value[16:18], v.Dst.Port())
	value[19] = 17
	err := collection.Maps["original_map"].Put(p.cookie, value)
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
		// Keep kernel correlation until the LRU maps reclaim it. A connected UDP
		// socket has already had its destination rewritten by connect(2), so it
		// cannot recreate these entries in sendmsg after a transient SOCKS relay
		// failure. Retaining them lets the next datagram open a fresh association;
		// a newly created socket always refreshes entries for its own cookie.
		p.backend.mu.Unlock()
	})
	return nil
}

func (b *Backend) Close() error {
	b.mu.Lock()
	if b.cancel != nil {
		b.cancel()
	}
	b.mu.Unlock()
	b.closeResources()
	b.wg.Wait()
	return nil
}
func (b *Backend) closeResources() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ln := range b.listeners {
		_ = ln.Close()
	}
	b.listeners = nil
	for _, c := range b.udp {
		_ = c.Close()
	}
	b.udp = nil
	for _, lnk := range b.links {
		_ = lnk.Close()
	}
	b.links = nil
	if b.collection != nil {
		b.collection.Close()
		b.collection = nil
	}
}
