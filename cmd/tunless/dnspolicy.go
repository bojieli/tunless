package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/bojieli/tunless/internal/dnspolicy"
)

type dnsPolicyOptions struct {
	localDomains      []string
	directDomains     []string
	trustedDomains    []string
	directPrefixes    []string
	directDomainFile  string
	trustedDomainFile string
	directPrefixFile  string
	directResolver    string
	overrideEnabled   bool
}

// configured reports whether the operator asked for anything beyond the
// default of sending every captured query to the trusted resolver.
func (o dnsPolicyOptions) configured() bool {
	return o.directResolver != "" || len(o.directDomains) > 0 || len(o.trustedDomains) > 0 ||
		len(o.directPrefixes) > 0 || o.directDomainFile != "" || o.trustedDomainFile != "" ||
		o.directPrefixFile != ""
}

// buildDNSPolicy assembles the policy from flags and list files.
//
// Every incoherent combination is refused here rather than started and left to
// behave unexpectedly later. That is the whole design of this validation: each
// of these has a runtime appearance identical to the feature working perfectly
// and finding nothing to do, which is the one failure an operator cannot
// distinguish by looking.
func buildDNSPolicy(options dnsPolicyOptions) (*dnspolicy.Policy, error) {
	policy := &dnspolicy.Policy{LocalDomains: options.localDomains}
	if !options.overrideEnabled {
		if options.configured() {
			return nil, errors.New("--disable-dns-override leaves every query with the application's own resolver, so --dns-direct and the DNS name lists have nothing to route; drop one or the other")
		}
		return policy, nil
	}

	suffixes := dnspolicy.NewSuffixSet()
	// The trusted list is loaded first so that a duplicate resolves toward the
	// tunnel; see SuffixSet.Add.
	if err := addSuffixes(suffixes, options.trustedDomains, dnspolicy.RouteTrusted, "--trusted-domain"); err != nil {
		return nil, err
	}
	if options.trustedDomainFile != "" {
		loaded, err := dnspolicy.LoadSuffixFile(options.trustedDomainFile)
		if err != nil {
			return nil, fmt.Errorf("--trusted-domain-file: %w", err)
		}
		if err := addSuffixes(suffixes, loaded, dnspolicy.RouteTrusted, options.trustedDomainFile); err != nil {
			return nil, err
		}
	}
	if err := addSuffixes(suffixes, options.directDomains, dnspolicy.RouteDirect, "--direct-domain"); err != nil {
		return nil, err
	}
	if options.directDomainFile != "" {
		loaded, err := dnspolicy.LoadSuffixFile(options.directDomainFile)
		if err != nil {
			return nil, fmt.Errorf("--direct-domain-file: %w", err)
		}
		if err := addSuffixes(suffixes, loaded, dnspolicy.RouteDirect, options.directDomainFile); err != nil {
			return nil, err
		}
	}
	if suffixes.Len() > 0 {
		policy.Suffixes = suffixes
	}

	var prefixes []netip.Prefix
	for _, entry := range options.directPrefixes {
		prefix, err := dnspolicy.ParsePrefix(entry)
		if err != nil {
			return nil, fmt.Errorf("--dns-direct-prefix: %w", err)
		}
		prefixes = append(prefixes, prefix)
	}
	if options.directPrefixFile != "" {
		loaded, err := dnspolicy.LoadPrefixFile(options.directPrefixFile)
		if err != nil {
			return nil, fmt.Errorf("--dns-direct-prefix-file: %w", err)
		}
		prefixes = append(prefixes, loaded...)
	}
	if len(prefixes) > 0 {
		policy.Prefixes = dnspolicy.NewPrefixSet(prefixes)
	}

	if options.directResolver != "" {
		resolver, err := netip.ParseAddrPort(options.directResolver)
		if err != nil || resolver.Port() == 0 {
			return nil, errors.New("--dns-direct must be a numeric IP:port (IPv6 addresses require brackets)")
		}
		policy.DirectResolver = netip.AddrPortFrom(resolver.Addr().Unmap(), resolver.Port())
		if policy.Prefixes == nil {
			// An empty set makes every direct answer look uncredible, so the
			// direct resolver would be asked on every unlisted name and never
			// believed: the latency of answer-based selection with none of its
			// effect, and nothing anywhere reporting a problem.
			return nil, errors.New("--dns-direct needs --dns-direct-prefix or --dns-direct-prefix-file: without addresses to judge by, no direct answer can ever be believed")
		}
	} else if policy.Prefixes != nil {
		return nil, errors.New("--dns-direct-prefix needs --dns-direct: prefixes judge answers from a direct resolver, and no direct resolver is configured")
	}
	return policy, nil
}

func addSuffixes(set *dnspolicy.SuffixSet, suffixes []string, route dnspolicy.Route, source string) error {
	for _, suffix := range suffixes {
		if err := set.Add(suffix, route); err != nil {
			return fmt.Errorf("%s: %w", source, err)
		}
	}
	return nil
}

// logDNSPolicy states at startup what the policy will do.
//
// A list that loaded as empty, a prefix file that collapsed to nothing, a
// direct resolver nobody is going to ask: all of them run silently, and this is
// where an operator finds out before the questions start.
func logDNSPolicy(logger *slog.Logger, policy *dnspolicy.Policy) {
	if policy == nil {
		return
	}
	if policy.Suffixes == nil && !policy.DirectResolver.IsValid() {
		return
	}
	attrs := []any{"name_suffixes", policy.Suffixes.Len()}
	if policy.DirectResolver.IsValid() {
		attrs = append(attrs,
			"dns_direct", policy.DirectResolver.String(),
			"credible_ranges", policy.Prefixes.Len(),
			"adjudicating", policy.Adjudicates())
	}
	logger.Info("DNS policy configured", attrs...)
}

// dnsDirectStatus renders the direct resolver for the status endpoint, empty
// when none is configured.
func dnsDirectStatus(policy *dnspolicy.Policy) string {
	if policy == nil || !policy.DirectResolver.IsValid() {
		return ""
	}
	return policy.DirectResolver.String()
}
