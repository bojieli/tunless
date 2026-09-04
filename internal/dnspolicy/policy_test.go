package dnspolicy

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func testPolicy(t *testing.T) *Policy {
	t.Helper()
	suffixes := NewSuffixSet()
	mustAdd(t, suffixes, "example.com", RouteDirect)
	mustAdd(t, suffixes, "secret.example.com", RouteTrusted)
	return &Policy{
		Suffixes:       suffixes,
		Prefixes:       NewPrefixSet(prefixes(t, "203.0.113.0/24")),
		DirectResolver: netip.MustParseAddrPort("223.5.5.5:53"),
	}
}

func TestTheDefaultPolicySendsEverythingToTheTrustedResolver(t *testing.T) {
	// The zero value has to be the behaviour the datapath had before any of
	// this existed, or upgrading changes where traffic goes without anyone
	// asking for it.
	policy := &Policy{}
	decision := policy.Decide(query(t, "www.example.com.", dnsmessage.TypeA))
	if decision.Route != RouteTrusted {
		t.Fatalf("Decide = %v, want trusted", decision.Route)
	}
	if policy.Adjudicates() {
		t.Error("the zero policy adjudicates")
	}
}

func TestLocalNamesOutrankEveryList(t *testing.T) {
	// A split-horizon name has no answer anywhere but the resolver the
	// application asked, so no list and no address set can make another
	// resolver right for it. This is a category, not a preference.
	policy := testPolicy(t)
	policy.LocalDomains = []string{"corp.example.com"}
	for _, name := range []string{"printer.local.", "nas.lan.", "wiki.corp.example.com.", "host."} {
		decision := policy.Decide(query(t, name, dnsmessage.TypeA))
		if decision.Route != RouteLocal {
			t.Errorf("Decide(%q) = %v (%s), want local", name, decision.Route, decision.Reason)
		}
	}
}

func TestTheNameListsDecideBeforeTheAddressSet(t *testing.T) {
	policy := testPolicy(t)
	for _, test := range []struct {
		name   string
		route  Route
		reason string
	}{
		{"www.example.com.", RouteDirect, ReasonDirectList},
		{"secret.example.com.", RouteTrusted, ReasonTrustedList},
		{"unlisted.test.invalid.example.", RouteAdjudicate, ReasonAdjudicating},
	} {
		decision := policy.Decide(query(t, test.name, dnsmessage.TypeA))
		if decision.Route != test.route || decision.Reason != test.reason {
			t.Errorf("Decide(%q) = %v/%s, want %v/%s", test.name, decision.Route, decision.Reason, test.route, test.reason)
		}
	}
}

func TestOnlyAddressQuestionsAreAdjudicated(t *testing.T) {
	// Adjudication reads addresses out of the answer and tests them against the
	// set, so a question with no address to test cannot be adjudicated. HTTPS
	// and SVCB matter most: a browser asks for them on every navigation and the
	// record carries the encrypted-client-hello configuration, so serving one
	// from the direct path would be this project inflicting a downgrade rather
	// than preventing one.
	policy := testPolicy(t)
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		if got := policy.Decide(query(t, "unlisted.example.net.", qtype)).Route; got != RouteAdjudicate {
			t.Errorf("Decide(%v) = %v, want adjudicate", qtype, got)
		}
	}
	for _, qtype := range []dnsmessage.Type{
		dnsmessage.TypeHTTPS, dnsmessage.TypeSVCB, dnsmessage.TypeMX,
		dnsmessage.TypeTXT, dnsmessage.TypeSRV, dnsmessage.TypePTR, dnsmessage.TypeNS,
	} {
		decision := policy.Decide(query(t, "unlisted.example.net.", qtype))
		if decision.Route != RouteTrusted || decision.Reason != ReasonNotAddress {
			t.Errorf("Decide(%v) = %v/%s, want trusted/%s", qtype, decision.Route, decision.Reason, ReasonNotAddress)
		}
	}
}

func TestAListedNameIsRoutedWhateverItAsksFor(t *testing.T) {
	// The type gate belongs to adjudication, which needs an address to judge.
	// An operator who listed a name has already decided, so their decision
	// applies to every record type under it.
	policy := testPolicy(t)
	if got := policy.Decide(query(t, "www.example.com.", dnsmessage.TypeHTTPS)).Route; got != RouteDirect {
		t.Errorf("Decide(HTTPS on a listed name) = %v, want direct", got)
	}
}

func TestAnUnreadableQueryGoesToTheTrustedResolver(t *testing.T) {
	// The safe direction: an unreadable query sent to a resolver that cannot
	// answer it fails a lookup, while one left on a poisoned path fails a
	// connection.
	policy := testPolicy(t)
	for _, message := range [][]byte{nil, {}, make([]byte, 11), make([]byte, 12)} {
		decision := policy.Decide(message)
		if decision.Route != RouteTrusted || decision.Reason != ReasonUnreadable {
			t.Errorf("Decide(%d bytes) = %v/%s, want trusted/%s", len(message), decision.Route, decision.Reason, ReasonUnreadable)
		}
	}
}

func TestAMessageWhoseNamesDisagreeIsNotSplit(t *testing.T) {
	// One datagram carries one transaction. A message whose names would take
	// different routes has no route that serves it, so it falls through to the
	// default rather than having one name's answer chosen over another's.
	policy := testPolicy(t)
	decision := policy.Decide(twoQuestions(t, "www.example.com.", "secret.example.com."))
	if decision.Route != RouteAdjudicate && decision.Route != RouteTrusted {
		t.Fatalf("Decide(mixed) = %v, want the default rather than either name's route", decision.Route)
	}
	if decision.Route == RouteDirect {
		t.Fatal("a mixed message took the direct path")
	}
	// A message whose names agree is still routed.
	agreed := policy.Decide(twoQuestions(t, "a.example.com.", "b.example.com."))
	if agreed.Route != RouteDirect {
		t.Fatalf("Decide(agreed) = %v, want direct", agreed.Route)
	}
	// A message mixing a local name with a public one is not local: half of it
	// would be unanswerable by the resolver the whole message must go to.
	mixed := policy.Decide(twoQuestions(t, "printer.local.", "www.example.net."))
	if mixed.Route == RouteLocal {
		t.Fatal("a message mixing local and public names was treated as local")
	}
}

func TestAdjudicationNeedsBothADirectResolverAndASet(t *testing.T) {
	// Either half alone is the latency of answer-based selection with none of
	// its effect, and nothing anywhere reporting a problem.
	suffixes := NewSuffixSet()
	mustAdd(t, suffixes, "example.com", RouteDirect)
	resolverOnly := &Policy{Suffixes: suffixes, DirectResolver: netip.MustParseAddrPort("223.5.5.5:53")}
	if resolverOnly.Adjudicates() {
		t.Error("a policy with no prefix set adjudicates")
	}
	if got := resolverOnly.Decide(query(t, "unlisted.example.net.", dnsmessage.TypeA)); got.Route != RouteTrusted {
		t.Errorf("Decide with no set = %v, want trusted", got.Route)
	}
	setOnly := &Policy{Prefixes: NewPrefixSet(prefixes(t, "203.0.113.0/24"))}
	if setOnly.Adjudicates() {
		t.Error("a policy with no direct resolver adjudicates")
	}
	empty := &Policy{Prefixes: NewPrefixSet(nil), DirectResolver: netip.MustParseAddrPort("223.5.5.5:53")}
	if empty.Adjudicates() {
		t.Error("a policy with an empty set adjudicates")
	}
}

func TestNameListsWorkWithoutADirectResolver(t *testing.T) {
	// This is what makes the lists usable on their own: an operator who wants
	// the deterministic half and not the heuristic half gets it, and those
	// queries go to the resolver the application already chose.
	suffixes := NewSuffixSet()
	mustAdd(t, suffixes, "example.com", RouteDirect)
	policy := &Policy{Suffixes: suffixes}
	if got := policy.Decide(query(t, "www.example.com.", dnsmessage.TypeA)).Route; got != RouteDirect {
		t.Fatalf("Decide = %v, want direct without a configured resolver", got)
	}
	if policy.DirectResolver.IsValid() {
		t.Error("a resolver appeared from nowhere")
	}
}
