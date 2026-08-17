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

type Observer struct {
	Listen, Upstream string
	MaxConcurrent    int
	mu               sync.Mutex
	records          map[netip.Addr]map[string]time.Time
	udp              *net.UDPConn
	tcp              net.Listener
	sem              chan struct{}
	wg               sync.WaitGroup
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
	maxConcurrent := o.MaxConcurrent
	if maxConcurrent == 0 {
		maxConcurrent = 256
	}
	if maxConcurrent < 0 {
		return errors.New("DNS observer concurrency limit cannot be negative")
	}
	o.sem = make(chan struct{}, maxConcurrent)
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
	o.wg.Add(1)
	go func() {
		defer o.wg.Done()
		o.serveUDP(ctx)
	}()
	for {
		conn, err := o.tcp.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !o.acquire() {
			_ = conn.Close()
			continue
		}
		o.wg.Add(1)
		go func() {
			defer o.wg.Done()
			defer o.release()
			o.serveTCP(ctx, conn)
		}()
	}
}

func (o *Observer) acquire() bool {
	select {
	case o.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (o *Observer) release() { <-o.sem }

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
	o.wg.Wait()
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
		if !o.acquire() {
			continue
		}
		o.wg.Add(1)
		go func() {
			defer o.wg.Done()
			defer o.release()
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
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	for {
		_ = client.SetDeadline(time.Now().Add(10 * time.Second))
		var size [2]byte
		if _, err := io.ReadFull(client, size[:]); err != nil {
			return
		}
		query := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, err := io.ReadFull(client, query); err != nil {
			return
		}
		reply, err := o.exchangeTCP(ctx, query)
		if err != nil {
			return
		}
		o.observe(query, reply)
		binary.BigEndian.PutUint16(size[:], uint16(len(reply)))
		if _, err = client.Write(append(size[:], reply...)); err != nil {
			return
		}
	}
}

func (o *Observer) exchangeTCP(ctx context.Context, query []byte) ([]byte, error) {
	d := net.Dialer{}
	upstream, err := d.DialContext(ctx, "tcp", o.Upstream)
	if err != nil {
		return nil, err
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
	frame := make([]byte, 2, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	frame = append(frame, query...)
	if _, err = upstream.Write(frame); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err = io.ReadFull(upstream, size[:]); err != nil {
		return nil, err
	}
	reply := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err = io.ReadFull(upstream, reply); err != nil {
		return nil, err
	}
	return reply, nil
}

func (o *Observer) observe(query, reply []byte) {
	var q, r dnsmessage.Message
	if q.Unpack(query) != nil || r.Unpack(reply) != nil || !matchingResponse(q, r) {
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

func matchingResponse(query, reply dnsmessage.Message) bool {
	if query.Header.Response || !reply.Header.Response || query.Header.ID != reply.Header.ID || len(query.Questions) == 0 || len(query.Questions) != len(reply.Questions) {
		return false
	}
	for index := range query.Questions {
		if query.Questions[index] != reply.Questions[index] {
			return false
		}
	}
	return true
}
