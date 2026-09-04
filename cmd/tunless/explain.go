package main

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/bojieli/tunless/internal/dnspolicy"
	"github.com/bojieli/tunless/socks5"
	"golang.org/x/net/dns/dnsmessage"
)

// explainName reports where one name would be resolved and, when both
// resolvers would be asked, what each of them actually says about it.
//
// It exists because the policy has four layers and two of them are files an
// operator downloads with tens of thousands of lines in them. "Why did this
// name go there" is the first question of every investigation, and without a
// way to ask it the answer is reconstructed by reading a list nobody can read.
// Running the real exchange rather than only reporting the decision is
// deliberate: a name is usually being explained because something about the
// answer was surprising, and the routing decision alone cannot show that the
// direct resolver is returning an address outside the credible set.
func explainName(ctx context.Context, out io.Writer, name string, policy *dnspolicy.Policy, client *socks5.Client, trustedResolver netip.AddrPort) error {
	canonical := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if canonical == "" {
		return fmt.Errorf("--explain needs a name")
	}
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		query, err := buildQuery(canonical, qtype)
		if err != nil {
			return err
		}
		decision := policy.Decide(query)
		label := "A"
		if qtype == dnsmessage.TypeAAAA {
			label = "AAAA"
		}
		fmt.Fprintf(out, "%-14s %s %s\n", "name", canonical, label)
		fmt.Fprintf(out, "%-14s %s (%s)\n", "decision", decision.Route, decision.Reason)
		if decision.Suffix != "" {
			fmt.Fprintf(out, "%-14s %s\n", "matched", decision.Suffix)
		} else if policy.Suffixes.Len() > 0 {
			fmt.Fprintf(out, "%-14s no suffix in --direct-domain or --trusted-domain\n", "matched")
		}
		switch decision.Route {
		case dnspolicy.RouteLocal:
			fmt.Fprintf(out, "%-14s the resolver the application chose\n", "resolver")
		case dnspolicy.RouteDirect:
			fmt.Fprintf(out, "%-14s %s\n", "resolver", resolverLabel(policy.DirectResolver, "the resolver the application chose"))
		case dnspolicy.RouteTrusted:
			fmt.Fprintf(out, "%-14s %s through the proxy\n", "resolver", trustedResolver)
		case dnspolicy.RouteAdjudicate:
			explainAdjudication(ctx, out, query, policy, client, trustedResolver)
		}
		fmt.Fprintln(out)
	}
	return nil
}

// explainAdjudication runs both halves and shows the verdict they produce.
func explainAdjudication(ctx context.Context, out io.Writer, query []byte, policy *dnspolicy.Policy, client *socks5.Client, trustedResolver netip.AddrPort) {
	exchangeCtx, cancel := context.WithTimeout(ctx, dnspolicy.AdjudicationDeadline)
	defer cancel()

	type result struct {
		reply   []byte
		elapsed time.Duration
		err     error
	}
	directCh := make(chan result, 1)
	trustedCh := make(chan result, 1)
	go func() {
		started := time.Now()
		reply, err := client.ExchangeDirect(exchangeCtx, query)
		directCh <- result{reply, time.Since(started), err}
	}()
	go func() {
		started := time.Now()
		reply, err := client.ExchangeDNSUDP(exchangeCtx, trustedResolver, query)
		trustedCh <- result{reply, time.Since(started), err}
	}()
	direct, trusted := <-directCh, <-trustedCh

	report := func(label string, where string, r result, judge bool) {
		if r.err != nil {
			fmt.Fprintf(out, "%-14s %s → %v\n", label, where, r.err)
			return
		}
		addresses := dnspolicy.ReplyAddresses(r.reply)
		if len(addresses) == 0 {
			fmt.Fprintf(out, "%-14s %s → %s in %s\n", label, where, dnspolicy.ReplySummary(r.reply), r.elapsed.Round(time.Microsecond))
			return
		}
		rendered := make([]string, 0, len(addresses))
		for _, addr := range addresses {
			if judge && policy.Prefixes.Contains(addr) {
				rendered = append(rendered, addr.String()+" (in set)")
				continue
			}
			rendered = append(rendered, addr.String())
		}
		fmt.Fprintf(out, "%-14s %s → %s in %s\n", label, where, strings.Join(rendered, ", "), r.elapsed.Round(time.Microsecond))
	}
	report("direct", policy.DirectResolver.String(), direct, true)
	report("trusted", trustedResolver.String()+" through the proxy", trusted, false)

	verdict, reason := policy.Adjudicate(dnspolicy.Exchange{
		Direct:      direct.reply,
		Trusted:     trusted.reply,
		DirectDone:  true,
		TrustedDone: true,
	})
	fmt.Fprintf(out, "%-14s %s (%s)\n", "verdict", verdict, reason)
}

func resolverLabel(resolver netip.AddrPort, fallback string) string {
	if !resolver.IsValid() {
		return fallback
	}
	return resolver.String()
}

// buildQuery encodes a recursion-desired query, the same shape a stub resolver
// would send.
func buildQuery(name string, qtype dnsmessage.Type) ([]byte, error) {
	encoded, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, fmt.Errorf("--explain: %w", err)
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  encoded,
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	return builder.Finish()
}
