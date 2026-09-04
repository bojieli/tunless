// Package dnspolicy decides which resolver answers a captured DNS query, and
// which of two answers to believe when both were asked.
//
// Capture rewrites port-53 flows to a trusted resolver reached through the
// proxy, so that an answer from the network the host happens to be on cannot
// decide where a connection goes. That is the right default and it stays the
// default. It has two costs that this package exists to let an operator buy
// back, deliberately and one at a time.
//
// The first is locality. A resolver on the far side of a tunnel answers a
// geographically aware name from where the tunnel exits, so a service that
// would have handed this host a nearby address hands it a distant one instead.
// The name resolved correctly and the connection is slow.
//
// The second is availability. When every lookup on the host goes through one
// proxy, that proxy going down does not degrade name resolution, it ends it —
// including for the destinations an operator already excluded from capture and
// which would otherwise still be reachable. The routes are fine. Nothing can
// learn an address to use them with.
//
// Two mechanisms answer those, and they decide at different moments:
//
//   - A name list decides from the question, before anything leaves the host.
//     Exact, free, and limited to the names someone thought to list.
//   - An address set decides from the answer, by asking both resolvers and
//     believing the direct one only when it names an address inside a set the
//     operator supplied. Catches every name nobody listed, at the cost of one
//     query on the direct path per unlisted name.
//
// They compose: the lists decide first and the address set catches the rest.
// With neither configured this package returns RouteTrusted for everything,
// which is what the datapath did before it existed.
package dnspolicy

import (
	"net/netip"
	"time"

	"github.com/bojieli/tunless/internal/dnsname"
	"golang.org/x/net/dns/dnsmessage"
)

// Route names the resolver that answers a query.
type Route uint8

const (
	// RouteUnset is the zero value, carried by a suffix trie node that exists
	// only to hold children. It is never returned by Decide.
	RouteUnset Route = iota
	// RouteTrusted sends the query to the trusted resolver through the proxy.
	// This is the default for everything and the behaviour of the datapath
	// before this package existed.
	RouteTrusted
	// RouteDirect sends the query to the direct resolver, or to the resolver
	// the application chose when no direct resolver is configured, and serves
	// whatever comes back without adjudication.
	RouteDirect
	// RouteLocal sends the query to the resolver the application chose,
	// because the name has no answer anywhere else. Split-horizon zones,
	// `.local`, and the private reverse zones. See internal/dnsname.
	RouteLocal
	// RouteAdjudicate asks both resolvers and decides from the answers. See
	// Policy.Adjudicate.
	RouteAdjudicate
)

func (r Route) String() string {
	switch r {
	case RouteTrusted:
		return "trusted"
	case RouteDirect:
		return "direct"
	case RouteLocal:
		return "local"
	case RouteAdjudicate:
		return "adjudicate"
	default:
		return "unset"
	}
}

// Decision is the route for one query and why it was chosen. The reason is not
// decoration: with four layers and two operator-supplied lists, "which layer
// decided this" is the question every misroute investigation starts from, and
// it is what `tunless explain` prints and what the counters are keyed on.
type Decision struct {
	Route Route
	// Reason is a stable kebab-case token, safe to use as a metric label.
	Reason string
	// Suffix is the entry from a name list that matched, when one did.
	Suffix string
}

// Reasons a Decision can carry.
const (
	ReasonUnreadable   = "unreadable-query"
	ReasonLocalName    = "local-name"
	ReasonDirectList   = "direct-list"
	ReasonTrustedList  = "trusted-list"
	ReasonNoDirect     = "no-direct-resolver"
	ReasonNotAddress   = "not-an-address-query"
	ReasonMixedNames   = "mixed-question-routes"
	ReasonAdjudicating = "unlisted"
)

// Policy holds the operator's DNS configuration. The zero value routes
// everything to the trusted resolver.
//
// A Policy is read-only once built and safe for concurrent use.
type Policy struct {
	// LocalDomains are the operator's split-horizon zones, added to the
	// reserved and private name spaces internal/dnsname recognises on its own.
	LocalDomains []string
	// Suffixes carries the --direct-domain and --trusted-domain lists. Longest
	// match wins between them; see SuffixSet.
	Suffixes *SuffixSet
	// Prefixes are the addresses that make a direct answer credible. Empty
	// disables adjudication entirely, whatever else is set.
	Prefixes *PrefixSet
	// DirectResolver is the resolver reached without the proxy. Invalid means
	// a RouteDirect query goes to the resolver the application chose, which is
	// what makes the name lists useful on their own.
	DirectResolver netip.AddrPort
}

// question is one entry of a query's question section.
type question struct {
	name  string
	qtype dnsmessage.Type
}

// maxQuestions bounds the question section of one message. Real queries carry
// exactly one; the limit keeps a crafted header count from turning a single
// datagram into a long parse.
const maxQuestions = 8

// questions parses the question section, returning nothing for a message this
// cannot read. A caller that gets nothing routes to the trusted resolver, which
// is the safe direction: an unreadable query sent to a resolver that cannot
// answer it fails a lookup, while one left on a poisoned path fails a
// connection.
func questions(message []byte) []question {
	var parser dnsmessage.Parser
	if _, err := parser.Start(message); err != nil {
		return nil
	}
	var found []question
	for range maxQuestions {
		q, err := parser.Question()
		if err != nil {
			break
		}
		found = append(found, question{name: q.Name.String(), qtype: q.Type})
	}
	return found
}

// Decide picks the resolver for one raw query.
//
// The layers are checked in an order that is not a preference ranking. Local
// names come first because they are a different category rather than a stronger
// opinion: those names have no answer anywhere but the resolver the application
// asked, so no list and no address set can make another resolver right for
// them. Everything after that is preference, and there longest-suffix match
// decides, not the order the lists were given in.
func (p *Policy) Decide(query []byte) Decision {
	asked := questions(query)
	if len(asked) == 0 {
		return Decision{Route: RouteTrusted, Reason: ReasonUnreadable}
	}
	if p.allLocal(asked) {
		return Decision{Route: RouteLocal, Reason: ReasonLocalName}
	}
	if route, suffix, ok := p.listRoute(asked); ok {
		switch route {
		case RouteDirect:
			return Decision{Route: RouteDirect, Reason: ReasonDirectList, Suffix: suffix}
		case RouteTrusted:
			return Decision{Route: RouteTrusted, Reason: ReasonTrustedList, Suffix: suffix}
		}
	}
	return p.unlistedRoute(asked)
}

// allLocal reports whether every name asked belongs to the local network. A
// query mixing a local name with a public one is not local: half of it would be
// unanswerable by the local resolver, and the local resolver is the only place
// the whole message can go.
func (p *Policy) allLocal(asked []question) bool {
	for _, q := range asked {
		if !dnsname.IsLocal(q.name, p.LocalDomains) {
			return false
		}
	}
	return true
}

// listRoute matches the question names against the operator's name lists.
//
// Every name in the message has to agree. A message whose names would take
// different routes cannot be sent twice — it is one datagram with one
// transaction ID — so there is no route that serves it, and the caller falls
// through to the default rather than picking one name's answer over another's.
func (p *Policy) listRoute(asked []question) (Route, string, bool) {
	if p.Suffixes == nil {
		return RouteUnset, "", false
	}
	route, suffix, ok := p.Suffixes.Match(asked[0].name)
	if !ok {
		return RouteUnset, "", false
	}
	for _, q := range asked[1:] {
		other, _, found := p.Suffixes.Match(q.name)
		if !found || other != route {
			return RouteUnset, "", false
		}
	}
	return route, suffix, true
}

// unlistedRoute decides what happens to a name nobody listed.
func (p *Policy) unlistedRoute(asked []question) Decision {
	if !p.adjudicates() {
		return Decision{Route: RouteTrusted, Reason: ReasonNoDirect}
	}
	// Adjudication reads addresses out of the answer and tests them against the
	// prefix set, so a question with no address to test cannot be adjudicated.
	// Those go to the trusted resolver rather than to a coin flip.
	//
	// HTTPS and SVCB are the ones that matter here, and not because they are
	// unusual: a browser asks for them on every navigation, and the record
	// carries the encrypted-client-hello configuration. Serving one from the
	// direct path hands whoever answered it the ability to strip ECH, which is
	// a downgrade this project would be inflicting rather than preventing.
	for _, q := range asked {
		if q.qtype != dnsmessage.TypeA && q.qtype != dnsmessage.TypeAAAA {
			return Decision{Route: RouteTrusted, Reason: ReasonNotAddress}
		}
	}
	return Decision{Route: RouteAdjudicate, Reason: ReasonAdjudicating}
}

// adjudicates reports whether answer-based selection is configured. Both halves
// are required: a direct resolver to ask, and a prefix set to judge with.
func (p *Policy) adjudicates() bool {
	return p.DirectResolver.IsValid() && p.Prefixes != nil && !p.Prefixes.Empty()
}

// Adjudicates reports whether this policy ever asks two resolvers.
func (p *Policy) Adjudicates() bool { return p.adjudicates() }

// DirectReplyWindow bounds how long an adjudication waits for the direct
// resolver once the trusted one has already answered usably.
//
// Waiting at all is what keeps the outcome from depending on a race. If the
// first answer to arrive won, the same name would resolve differently on a busy
// network than on an idle one, and a policy whose result depends on timing
// cannot be reasoned about or tested. Waiting for both makes the decision a
// function of the two answers.
//
// Bounding the wait is what keeps that from costing a round trip on every
// lookup when the direct resolver is not answering at all. The direct resolver
// is by construction the near one, so a reply that has not arrived within this
// window was not going to improve the answer. A resolver that misses the window
// repeatedly is taken out of the path entirely; see the circuit breaker in the
// arbiter.
const DirectReplyWindow = 800 * time.Millisecond

// AdjudicationDeadline bounds the whole exchange. Past it the query is decided
// on whatever arrived, which is usually nothing, and the application's own
// resolver retries the way it would against any resolver that did not answer.
const AdjudicationDeadline = 4 * time.Second
