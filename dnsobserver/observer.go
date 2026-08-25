package dnsobserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bojieli/tunless/internal/dnswire"
	"golang.org/x/net/dns/dnsmessage"
)

type Observer struct {
	Listen, Upstream string
	MaxConcurrent    int
	// MaxRecords bounds cached address/name associations. Zero selects the
	// default. The observer is fed by an external DNS server, so this limit is
	// independent of the number of concurrently proxied requests.
	MaxRecords  int
	UDPExchange func(context.Context, []byte) ([]byte, error)
	TCPExchange func(context.Context, []byte) ([]byte, error)
	mu          sync.Mutex
	records     map[netip.Addr]map[string]time.Time
	recordCount int
	stateMu     sync.Mutex
	udp         *net.UDPConn
	tcp         net.Listener
	closed      bool
	serving     bool
	sem         chan struct{}
	wg          sync.WaitGroup
	close       sync.Once
}

const (
	defaultMaxRecords            = 65536
	maxObservedNamesPerMessage   = 256
	maxAssociationsPerDNSMessage = 4096
)

func (o *Observer) Lookup(addr netip.Addr) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	names := o.records[addr.Unmap()]
	now := time.Now()
	result := ""
	for name, expires := range names {
		if now.After(expires) {
			delete(names, name)
			if o.recordCount > 0 {
				o.recordCount--
			}
			continue
		}
		if result != "" && result != name {
			return ""
		}
		result = name
	}
	if len(names) == 0 {
		delete(o.records, addr.Unmap())
	}
	return result
}

func (o *Observer) Serve(ctx context.Context) error {
	o.stateMu.Lock()
	if o.closed {
		o.stateMu.Unlock()
		return net.ErrClosed
	}
	if o.serving || o.udp != nil || o.tcp != nil {
		o.stateMu.Unlock()
		return errors.New("DNS observer already serving")
	}
	o.serving = true
	o.stateMu.Unlock()
	defer func() {
		o.stateMu.Lock()
		o.serving = false
		o.stateMu.Unlock()
	}()
	if o.Listen == "" {
		o.Listen = "127.0.0.1:5353"
	}
	if o.Upstream == "" {
		o.Upstream = "1.1.1.1:53"
	}
	listen, err := ValidateAddress(o.Listen)
	if err != nil {
		return err
	}
	o.Listen = listen
	maxConcurrent := o.MaxConcurrent
	if maxConcurrent == 0 {
		maxConcurrent = 256
	}
	if maxConcurrent < 0 {
		return errors.New("DNS observer concurrency limit cannot be negative")
	}
	if o.MaxRecords < 0 {
		return errors.New("DNS observer record limit cannot be negative")
	}
	o.sem = make(chan struct{}, maxConcurrent)
	o.mu.Lock()
	o.records = make(map[netip.Addr]map[string]time.Time)
	o.recordCount = 0
	o.mu.Unlock()
	// The observer answers on UDP and TCP at the same port, and when the
	// operator asks for an ephemeral one the kernel chooses it for UDP alone.
	// Nothing reserves that number on the TCP side, so a busy host hands out a
	// UDP port whose TCP half is already taken and startup fails with "address
	// already in use" — rarely, and for no reason the operator can act on.
	// Ask again instead. A fixed port is a request, not a suggestion, so it is
	// still attempted exactly once and its error still surfaces.
	requested := o.Listen
	_, requestedPort, splitErr := net.SplitHostPort(requested)
	ephemeral := splitErr == nil && requestedPort == "0"
	attempts := 1
	if ephemeral {
		attempts = 8
	}
	var udp *net.UDPConn
	var tcp net.Listener
	for attempt := 0; attempt < attempts && tcp == nil; attempt++ {
		var addr *net.UDPAddr
		if addr, err = net.ResolveUDPAddr("udp", requested); err != nil {
			return err
		}
		if udp, err = net.ListenUDP("udp", addr); err != nil {
			return err
		}
		candidate := requested
		if ephemeral {
			candidate = udp.LocalAddr().String()
		}
		if tcp, err = net.Listen("tcp", candidate); err != nil {
			_ = udp.Close()
			udp = nil
			if !ephemeral {
				return err
			}
			continue
		}
		o.Listen = candidate
	}
	if tcp == nil {
		return fmt.Errorf("DNS observer found no port free for both UDP and TCP in %d attempts: %w", attempts, err)
	}
	o.stateMu.Lock()
	if o.closed {
		o.stateMu.Unlock()
		_ = udp.Close()
		_ = tcp.Close()
		return net.ErrClosed
	}
	o.udp, o.tcp = udp, tcp
	// Count the TCP accept loop as well as the UDP loop. This keeps the wait
	// group nonzero while the accept loop can add connection handlers, avoiding
	// Add/Wait races during concurrent shutdown.
	o.wg.Add(2)
	o.stateMu.Unlock()
	defer o.Close()
	serveDone := make(chan struct{})
	defer close(serveDone)
	go func() {
		defer o.wg.Done()
		o.serveUDP(ctx)
	}()
	go func() {
		select {
		case <-ctx.Done():
			_ = o.Close()
		case <-serveDone:
		}
	}()
	defer o.wg.Done()
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
		o.stateMu.Lock()
		o.closed = true
		udp, tcp := o.udp, o.tcp
		o.stateMu.Unlock()
		if udp != nil {
			err = udp.Close()
		}
		if tcp != nil {
			err = errors.Join(err, tcp.Close())
		}
	})
	o.wg.Wait()
	return err
}

func (o *Observer) Ready() bool {
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	return !o.closed && o.udp != nil && o.tcp != nil
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
	if len(query) > 65535 {
		return nil, errors.New("DNS UDP query exceeds 65535 bytes")
	}
	if o.UDPExchange != nil {
		exchangeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		reply, err := o.UDPExchange(exchangeCtx, query)
		if len(reply) > 65535 {
			return nil, errors.New("DNS UDP reply exceeds 65535 bytes")
		}
		return reply, err
	}
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
	for {
		n, readErr := conn.Read(buf)
		if readErr != nil {
			return append([]byte(nil), buf[:n]...), readErr
		}
		if !dnswire.AnswersQuery(query, buf[:n]) {
			continue
		}
		return append([]byte(nil), buf[:n]...), nil
	}
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
		if len(reply) > 65535 {
			return
		}
		o.observe(query, reply)
		binary.BigEndian.PutUint16(size[:], uint16(len(reply))) // #nosec G115 -- length is checked immediately above
		if err = writeAll(client, append(size[:], reply...)); err != nil {
			return
		}
	}
}

func (o *Observer) exchangeTCP(ctx context.Context, query []byte) ([]byte, error) {
	if len(query) > 65535 {
		return nil, errors.New("DNS TCP query exceeds 65535 bytes")
	}
	if o.TCPExchange != nil {
		exchangeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		reply, err := o.TCPExchange(exchangeCtx, query)
		if len(reply) > 65535 {
			return nil, errors.New("DNS TCP reply exceeds 65535 bytes")
		}
		return reply, err
	}
	d := net.Dialer{}
	upstream, err := d.DialContext(ctx, "tcp", o.Upstream)
	if err != nil {
		return nil, err
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
	frame := make([]byte, 2, len(query)+2)
	binary.BigEndian.PutUint16(frame, uint16(len(query))) // #nosec G115 -- length is checked above
	frame = append(frame, query...)
	if err = writeAll(upstream, frame); err != nil {
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

func (o *Observer) observe(query, reply []byte) {
	var q, r dnsmessage.Message
	if q.Unpack(query) != nil || r.Unpack(reply) != nil || !matchingResponse(q, r) {
		return
	}
	// Attribute an address only to a queried name that owns the A/AAAA answer,
	// directly or through the response's CNAME chain. Merely appearing in the
	// answer section is not sufficient: unrelated records must not pollute later
	// flow attribution.
	now := time.Now()
	type cnameRecord struct {
		target  string
		expires time.Time
	}
	cname := make(map[string]cnameRecord)
	for _, answer := range r.Answers {
		body, ok := answer.Body.(*dnsmessage.CNAMEResource)
		if !ok || answer.Header.Class != dnsmessage.ClassINET || answer.Header.Type != dnsmessage.TypeCNAME {
			continue
		}
		owner := strings.ToLower(answer.Header.Name.String())
		target := strings.ToLower(body.CNAME.String())
		expires := now.Add(observedTTL(answer.Header.TTL))
		if current, exists := cname[owner]; !exists {
			cname[owner] = cnameRecord{target: target, expires: expires}
		} else if current.target == target {
			if expires.Before(current.expires) {
				current.expires = expires
				cname[owner] = current
			}
		} else {
			// Conflicting aliases are not safe to attribute.
			cname[owner] = cnameRecord{}
		}
	}
	type originRecord struct {
		name    string
		typ     dnsmessage.Type
		expires time.Time
	}
	origins := make(map[string][]originRecord)
	seenQuestions := make(map[string]struct{})
	for _, question := range q.Questions {
		if question.Class != dnsmessage.ClassINET || (question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA) {
			continue
		}
		name := question.Name.String()
		canonicalName := strings.ToLower(name)
		if _, seen := seenQuestions[canonicalName]; seen || len(seenQuestions) >= maxObservedNamesPerMessage {
			continue
		}
		seenQuestions[canonicalName] = struct{}{}
		current := canonicalName
		var chainExpires time.Time
		visited := make(map[string]struct{})
		validChain := false
		for range len(r.Answers) + 1 {
			if _, loop := visited[current]; loop {
				break
			}
			visited[current] = struct{}{}
			next, ok := cname[current]
			if !ok {
				validChain = true
				break
			}
			if next.target == "" {
				break
			}
			if chainExpires.IsZero() || next.expires.Before(chainExpires) {
				chainExpires = next.expires
			}
			current = next.target
		}
		if !validChain {
			continue
		}
		// Only the terminal owner may carry address records. A CNAME owner is
		// not allowed to carry an A/AAAA record alongside the alias.
		origins[current] = append(origins[current], originRecord{name: name, typ: question.Type, expires: chainExpires})
	}
	type observedRecord struct {
		addr    netip.Addr
		name    string
		expires time.Time
	}
	records := make([]observedRecord, 0, min(len(r.Answers), maxAssociationsPerDNSMessage))
	for _, answer := range r.Answers {
		if answer.Header.Class != dnsmessage.ClassINET {
			continue
		}
		var addr netip.Addr
		var answerType dnsmessage.Type
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			addr = netip.AddrFrom4(body.A)
			answerType = dnsmessage.TypeA
		case *dnsmessage.AAAAResource:
			addr = netip.AddrFrom16(body.AAAA)
			answerType = dnsmessage.TypeAAAA
		default:
			continue
		}
		if answer.Header.Type != answerType {
			continue
		}
		originRecords := origins[strings.ToLower(answer.Header.Name.String())]
		if len(originRecords) == 0 {
			continue
		}
		addressExpires := now.Add(observedTTL(answer.Header.TTL))
		for _, origin := range originRecords {
			if origin.typ != answerType {
				continue
			}
			if len(records) >= maxAssociationsPerDNSMessage {
				break
			}
			expires := addressExpires
			if !origin.expires.IsZero() && origin.expires.Before(expires) {
				expires = origin.expires
			}
			records = append(records, observedRecord{addr: addr.Unmap(), name: origin.name, expires: expires})
		}
		if len(records) >= maxAssociationsPerDNSMessage {
			break
		}
	}
	if len(records) == 0 {
		return
	}
	limit := o.MaxRecords
	if limit == 0 {
		limit = defaultMaxRecords
	}
	if limit < 1 {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.records == nil {
		o.records = make(map[netip.Addr]map[string]time.Time)
	}
	type recordKey struct {
		addr netip.Addr
		name string
	}
	countNew := func() int {
		seen := make(map[recordKey]struct{}, len(records))
		count := 0
		for _, record := range records {
			key := recordKey{addr: record.addr, name: record.name}
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			if _, exists := o.records[record.addr][record.name]; !exists {
				count++
			}
		}
		return count
	}
	newRecords := countNew()
	if o.recordCount+newRecords > limit {
		o.pruneExpiredLocked(now)
		newRecords = countNew()
		if excess := o.recordCount + min(newRecords, limit) - limit; excess > 0 {
			o.evictLocked(excess)
		}
	}
	for _, record := range records {
		names := o.records[record.addr]
		if names != nil {
			if _, exists := names[record.name]; exists {
				names[record.name] = record.expires
				continue
			}
		}
		if o.recordCount >= limit {
			continue
		}
		if names == nil {
			names = make(map[string]time.Time)
			o.records[record.addr] = names
		}
		names[record.name] = record.expires
		o.recordCount++
	}
}

// maxObservedTTL bounds how long one answer may keep claiming an address.
//
// The TTL belongs to whoever wrote the record, and a record is free to say a
// century. That is not a claim about freshness, it is a claim on every future
// tenant of the address — cloud and CDN addresses are recycled constantly, and
// an attribution that outlives its answer hands someone else's traffic to the
// old name's routing rules. A day is what common resolvers cap their own
// caches at, and already far longer than the window this cache exists to
// serve: the connection that follows the lookup.
const maxObservedTTL = 24 * time.Hour

func observedTTL(value uint32) time.Duration {
	if value == 0 {
		return time.Second
	}
	if ttl := time.Duration(value) * time.Second; ttl < maxObservedTTL {
		return ttl
	}
	return maxObservedTTL
}

func (o *Observer) pruneExpiredLocked(now time.Time) {
	for addr, names := range o.records {
		for name, expires := range names {
			if !now.Before(expires) {
				delete(names, name)
				if o.recordCount > 0 {
					o.recordCount--
				}
			}
		}
		if len(names) == 0 {
			delete(o.records, addr)
		}
	}
}

func (o *Observer) evictLocked(count int) {
	for addr, names := range o.records {
		for name := range names {
			delete(names, name)
			o.recordCount--
			count--
			if count == 0 {
				break
			}
		}
		if len(names) == 0 {
			delete(o.records, addr)
		}
		if count == 0 {
			return
		}
	}
}

func matchingResponse(query, reply dnsmessage.Message) bool {
	if query.Header.Response || !reply.Header.Response || reply.Header.RCode != dnsmessage.RCodeSuccess || query.Header.ID != reply.Header.ID || len(query.Questions) == 0 || len(query.Questions) != len(reply.Questions) {
		return false
	}
	for index := range query.Questions {
		if query.Questions[index] != reply.Questions[index] {
			return false
		}
	}
	return true
}

// ValidateAddress accepts only an unauthenticated numeric loopback listener.
// Port zero is retained for tests and callers that want an ephemeral port.
func ValidateAddress(value string) (string, error) {
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return "", errors.New("DNS observer listen address must be loopback IP:port")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() {
		return "", errors.New("DNS observer may listen only on a numeric loopback address")
	}
	if _, err = strconv.ParseUint(port, 10, 16); err != nil {
		return "", errors.New("DNS observer listen port must be between 0 and 65535")
	}
	return value, nil
}
