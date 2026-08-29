package socks5

import (
	"net"
	"net/netip"
	"sync"
)

// directDatagramRelay carries datagrams that must not go through the proxy,
// straight out of this process.
//
// Capture declines a flow by handing it back, and the kernel then routes it as
// though tunless were not installed. A datagram inside an already-accepted flow
// has no equivalent: the flow belongs to the emitter, so a destination the
// proxy cannot usefully reach has nowhere to go. That is not hypothetical for
// DNS. A query for a name only the local network can answer has to reach the
// resolver on that network, and a resolver on a private address is exactly what
// a proxy's rules send somewhere else — or to a node on the other side of the
// world, which then cannot reach it at all. Leaving the query unrewritten is
// not enough; it has to leave by a different door.
//
// One socket per destination, reused for as long as the flow lives, so a
// resolver client that keeps asking the same server does not pay for a new
// socket each time.
type directDatagramRelay struct {
	deliver func(payload []byte, from netip.AddrPort)

	mu          sync.Mutex
	connections map[netip.AddrPort]*net.UDPConn
	closed      bool
	workers     sync.WaitGroup
}

// maxDirectDestinations bounds how many peers one flow may reach this way. A
// flow addressing more than this is not a resolver client, and the cap keeps a
// misbehaving sender from turning one captured flow into unbounded sockets.
const maxDirectDestinations = 16

func newDirectDatagramRelay(deliver func(payload []byte, from netip.AddrPort)) *directDatagramRelay {
	return &directDatagramRelay{
		deliver:     deliver,
		connections: make(map[netip.AddrPort]*net.UDPConn),
	}
}

// send writes one datagram straight to destination, reporting whether it left.
func (r *directDatagramRelay) send(payload []byte, destination netip.AddrPort) bool {
	conn := r.connection(destination)
	if conn == nil {
		return false
	}
	_, err := conn.Write(payload)
	return err == nil
}

func (r *directDatagramRelay) connection(destination netip.AddrPort) *net.UDPConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	if existing, ok := r.connections[destination]; ok {
		return existing
	}
	if len(r.connections) >= maxDirectDestinations {
		return nil
	}
	network := "udp4"
	if !destination.Addr().Unmap().Is4() {
		network = "udp6"
	}
	conn, err := net.DialUDP(network, nil, net.UDPAddrFromAddrPort(destination))
	if err != nil {
		return nil
	}
	r.connections[destination] = conn
	r.workers.Add(1)
	go r.read(conn, destination)
	return conn
}

// read hands each reply back to the flow addressed from the destination the
// sender used, so connected-datagram semantics hold and the application cannot
// tell this apart from never having been captured.
func (r *directDatagramRelay) read(conn *net.UDPConn, destination netip.AddrPort) {
	defer r.workers.Done()
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		r.deliver(append([]byte(nil), buf[:n]...), destination)
	}
}

func (r *directDatagramRelay) close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	connections := r.connections
	r.connections = make(map[netip.AddrPort]*net.UDPConn)
	r.mu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
	r.workers.Wait()
}
