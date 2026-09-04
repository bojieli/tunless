package socks5

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/bojieli/tunless/internal/dnspolicy"
	"github.com/bojieli/tunless/internal/dnswire"
)

// ResolveWithPolicy answers one query the way the capture datapath would.
//
// It exists so the optional DNS observer, which applications are pointed at
// explicitly, does not quietly disagree with the capture path about where a
// name goes. Two resolvers on one host that answer the same name differently is
// a difference nobody can see and everybody has to debug.
//
// trusted carries the query to the trusted resolver over whichever transport
// the caller is serving, so the same function answers for UDP and for TCP.
//
// Split-horizon names are the one case this cannot honour. The capture path
// sends them to the resolver the application already chose, which it knows
// because it saw the datagram addressed to it; a listener has no such thing to
// fall back to, so those names go to the trusted resolver here, and a network
// with private zones on it wants its own resolver in front of this one anyway.
func (c *Client) ResolveWithPolicy(ctx context.Context, query []byte, trusted func(context.Context, []byte) ([]byte, error)) ([]byte, error) {
	policy := c.dnsPolicy()
	decision := policy.Decide(query)
	c.DNSStats.RecordDecision(decision)
	switch decision.Route {
	case dnspolicy.RouteDirect:
		if !policy.DirectResolver.IsValid() {
			return trusted(ctx, query)
		}
		return c.exchangeDirectUDP(ctx, query)
	case dnspolicy.RouteAdjudicate:
		return c.adjudicate(ctx, query, trusted)
	default:
		return trusted(ctx, query)
	}
}

// adjudicate asks both resolvers and applies the policy to what comes back.
//
// The datapath does this with timers and a pending map because it multiplexes
// many exchanges over one association. Here there is exactly one, so the same
// rules are a loop over two channels — and running the identical Adjudicate
// against the identical Exchange is what keeps the two paths from drifting into
// two different policies with one name.
func (c *Client) adjudicate(ctx context.Context, query []byte, trusted func(context.Context, []byte) ([]byte, error)) ([]byte, error) {
	policy := c.dnsPolicy()
	breaker := c.directBreaker()
	ctx, cancel := context.WithTimeout(ctx, dnspolicy.AdjudicationDeadline)
	defer cancel()

	var exchange dnspolicy.Exchange
	directCh := make(chan []byte, 1)
	trustedCh := make(chan []byte, 1)

	askDirect := breaker.allow(time.Now())
	if askDirect {
		go func() {
			reply, err := c.exchangeDirectUDP(ctx, query)
			if err != nil {
				directCh <- nil
				return
			}
			directCh <- reply
		}()
	} else {
		exchange.DirectDone = true
		c.DNSStats.directSkipped.Add(1)
	}
	go func() {
		reply, err := trusted(ctx, query)
		if err != nil {
			trustedCh <- nil
			return
		}
		trustedCh <- reply
	}()

	window := time.NewTimer(dnspolicy.DirectReplyWindow)
	defer window.Stop()
	for {
		verdict, reason := policy.Adjudicate(exchange)
		if verdict != dnspolicy.VerdictWait {
			c.DNSStats.recordVerdict(verdict, reason)
			switch verdict {
			case dnspolicy.VerdictServeDirect:
				return exchange.Direct, nil
			case dnspolicy.VerdictServeTrusted:
				return exchange.Trusted, nil
			case dnspolicy.VerdictRefuse:
				if refusal := dnspolicy.Refusal(query); refusal != nil {
					return refusal, nil
				}
			}
			return nil, errors.New("no resolver answered")
		}
		select {
		case reply := <-directCh:
			exchange.DirectDone = true
			if reply != nil && dnswire.AnswersQuery(query, reply) {
				exchange.Direct = reply
				breaker.succeed()
			} else {
				breaker.fail(time.Now())
			}
		case reply := <-trustedCh:
			exchange.TrustedDone = true
			if reply != nil && dnswire.AnswersQuery(query, reply) {
				exchange.Trusted = reply
			}
		case <-window.C:
			if !exchange.DirectDone {
				breaker.fail(time.Now())
			}
			exchange.DirectWindowClosed = true
		case <-ctx.Done():
			exchange.DeadlineReached = true
		}
	}
}

// ExchangeDirect asks the direct resolver without the proxy. It is what
// diagnostics use to show what that resolver actually says.
func (c *Client) ExchangeDirect(ctx context.Context, query []byte) ([]byte, error) {
	return c.exchangeDirectUDP(ctx, query)
}

// exchangeDirectUDP asks the direct resolver without the proxy.
//
// One socket per exchange rather than a pool. This path is the observer's, not
// the datapath's — the datapath reuses one socket per resolver through
// directDatagramRelay — and a listener that an operator points a handful of
// clients at does not need a connection cache to justify itself.
func (c *Client) exchangeDirectUDP(ctx context.Context, query []byte) ([]byte, error) {
	resolver := c.dnsPolicy().DirectResolver
	if !resolver.IsValid() {
		return nil, errors.New("no direct resolver configured")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(dnspolicy.DirectReplyWindow)
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "udp", resolver.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	// A datagram that is not an answer to this question does not end the
	// exchange. Forging one is cheap for anyone who can guess the port, and
	// letting it consume the read would close the socket in front of the real
	// answer arriving a moment later.
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if dnswire.AnswersQuery(query, buf[:n]) {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}
