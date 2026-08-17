package dnsobserver

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type record struct {
	name    string
	expires time.Time
}
type Observer struct {
	Listen, Upstream string
	mu               sync.Mutex
	records          map[netip.Addr]map[string]time.Time
	udp              *net.UDPConn
	tcp              net.Listener
	close            sync.Once
}

func (o *Observer) Lookup(addr netip.Addr) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	names := o.records[addr.Unmap()]
	now := time.Now()
	result := ""
	for name, expires := range names {
		if now.After(expires) {
			delete(names, name)
			continue
		}
		if result != "" && result != name {
			return ""
		}
		result = name
	}
	return result
}

func (o *Observer) Serve(ctx context.Context) error {
	if o.Listen == "" {
		o.Listen = "127.0.0.1:5353"
	}
	if o.Upstream == "" {
		o.Upstream = "1.1.1.1:53"
	}
	o.mu.Lock()
	o.records = make(map[netip.Addr]map[string]time.Time)
	o.mu.Unlock()
	addr, err := net.ResolveUDPAddr("udp", o.Listen)
	if err != nil {
		return err
	}
	o.udp, err = net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	o.tcp, err = net.Listen("tcp", o.Listen)
	if err != nil {
		o.udp.Close()
		return err
	}
	go func() { <-ctx.Done(); o.Close() }()
	go o.serveUDP(ctx)
	for {
		conn, err := o.tcp.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go o.serveTCP(ctx, conn)
	}
}
func (o *Observer) Close() error {
	var err error
	o.close.Do(func() {
		if o.udp != nil {
			err = o.udp.Close()
		}
		if o.tcp != nil {
			err = errors.Join(err, o.tcp.Close())
		}
	})
	return err
}

func (o *Observer) serveUDP(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, peer, err := o.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		go func() {
			reply, err := o.exchangeUDP(ctx, query)
			if err == nil {
				o.observe(query, reply)
				_, _ = o.udp.WriteToUDPAddrPort(reply, peer)
			}
		}()
	}
}
func (o *Observer) exchangeUDP(ctx context.Context, query []byte) ([]byte, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", o.Upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	return append([]byte(nil), buf[:n]...), err
}
func (o *Observer) serveTCP(ctx context.Context, client net.Conn) {
	defer client.Close()
	var size [2]byte
	if _, err := io.ReadFull(client, size[:]); err != nil {
		return
	}
	query := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(client, query); err != nil {
		return
	}
	d := net.Dialer{}
	upstream, err := d.DialContext(ctx, "tcp", o.Upstream)
	if err != nil {
		return
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = upstream.Write(append(size[:], query...)); err != nil {
		return
	}
	if _, err = io.ReadFull(upstream, size[:]); err != nil {
		return
	}
	reply := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err = io.ReadFull(upstream, reply); err != nil {
		return
	}
	o.observe(query, reply)
	_, _ = client.Write(append(size[:], reply...))
}
func (o *Observer) observe(query, reply []byte) {
	var q, r dnsmessage.Message
	if q.Unpack(query) != nil || r.Unpack(reply) != nil || len(q.Questions) == 0 {
		return
	}
	names := make(map[string]struct{})
	for _, question := range q.Questions {
		names[question.Name.String()] = struct{}{}
	}
	for _, answer := range r.Answers {
		var addr netip.Addr
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			addr = netip.AddrFrom4(body.A)
		case *dnsmessage.AAAAResource:
			addr = netip.AddrFrom16(body.AAAA)
		default:
			continue
		}
		ttl := time.Duration(answer.Header.TTL) * time.Second
		if ttl == 0 {
			ttl = time.Second
		}
		o.mu.Lock()
		if o.records[addr] == nil {
			o.records[addr] = make(map[string]time.Time)
		}
		for name := range names {
			o.records[addr][name] = time.Now().Add(ttl)
		}
		o.mu.Unlock()
	}
}
