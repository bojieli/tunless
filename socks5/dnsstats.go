package socks5

import (
	"sync/atomic"

	"github.com/bojieli/tunless/internal/dnspolicy"
)

// DNSStats counts what the DNS policy decided, keyed by the layer that decided
// it.
//
// The counters are not decoration. Answer-based selection has a failure mode
// that produces no error anywhere: a prefix set that matches nothing looks
// exactly like a network with no interference on it, and both present as every
// answer coming from the trusted resolver. The only way to tell them apart is
// to be able to see that the direct half is being asked and is losing. The same
// goes in the other direction — a set that has grown to cover more than it
// should shows up here as direct answers displacing trusted ones long before it
// shows up as a connection going somewhere unexpected.
//
// Names and destinations are deliberately absent. This is a health surface, and
// a health surface that accumulates the names a host looked up is a log of the
// user's browsing wearing a different hat.
type DNSStats struct {
	local            atomic.Uint64
	directList       atomic.Uint64
	trustedList      atomic.Uint64
	trustedDefault   atomic.Uint64
	notAddress       atomic.Uint64
	unreadable       atomic.Uint64
	adjudicated      atomic.Uint64
	servedDirect     atomic.Uint64
	servedTrusted    atomic.Uint64
	servedNoAnswer   atomic.Uint64
	refused          atomic.Uint64
	droppedNoReply   atomic.Uint64
	directSkipped    atomic.Uint64
	directSendFailed atomic.Uint64
}

// DNSStatsSnapshot is the JSON shape reported by the status endpoint.
type DNSStatsSnapshot struct {
	// Routing decisions, one per captured query.
	LocalName      uint64 `json:"local_name"`
	DirectList     uint64 `json:"direct_list"`
	TrustedList    uint64 `json:"trusted_list"`
	TrustedDefault uint64 `json:"trusted_default"`
	NotAddress     uint64 `json:"not_address_query"`
	Unreadable     uint64 `json:"unreadable_query"`
	Adjudicated    uint64 `json:"adjudicated"`
	// Adjudication outcomes. These sum to Adjudicated once the exchanges they
	// belong to have concluded.
	ServedDirect   uint64 `json:"served_direct"`
	ServedTrusted  uint64 `json:"served_trusted"`
	ServedNoAnswer uint64 `json:"served_direct_no_answer"`
	Refused        uint64 `json:"refused"`
	DroppedNoReply uint64 `json:"dropped_no_reply"`
	// Direct resolver health.
	DirectSkipped     uint64 `json:"direct_skipped"`
	DirectSendFailed  uint64 `json:"direct_send_failed"`
	DirectBreakerOpen bool   `json:"direct_breaker_open"`
}

// RecordDecision counts one routing decision.
func (s *DNSStats) RecordDecision(decision dnspolicy.Decision) {
	if s == nil {
		return
	}
	switch decision.Reason {
	case dnspolicy.ReasonLocalName:
		s.local.Add(1)
	case dnspolicy.ReasonDirectList:
		s.directList.Add(1)
	case dnspolicy.ReasonTrustedList:
		s.trustedList.Add(1)
	case dnspolicy.ReasonNotAddress:
		s.notAddress.Add(1)
	case dnspolicy.ReasonUnreadable:
		s.unreadable.Add(1)
	case dnspolicy.ReasonAdjudicating:
		s.adjudicated.Add(1)
	default:
		s.trustedDefault.Add(1)
	}
}

func (s *DNSStats) recordVerdict(verdict dnspolicy.Verdict, reason string) {
	if s == nil {
		return
	}
	switch verdict {
	case dnspolicy.VerdictServeDirect:
		if reason == dnspolicy.ReasonDirectNoAnswer {
			s.servedNoAnswer.Add(1)
			return
		}
		s.servedDirect.Add(1)
	case dnspolicy.VerdictServeTrusted:
		s.servedTrusted.Add(1)
	case dnspolicy.VerdictRefuse:
		s.refused.Add(1)
	case dnspolicy.VerdictDrop:
		s.droppedNoReply.Add(1)
	}
}

// Snapshot reports the counters. breakerOpen is passed in because the breaker
// belongs to the client that owns the datapath, not to the counters.
func (s *DNSStats) Snapshot(breakerOpen bool) DNSStatsSnapshot {
	if s == nil {
		return DNSStatsSnapshot{}
	}
	return DNSStatsSnapshot{
		LocalName:         s.local.Load(),
		DirectList:        s.directList.Load(),
		TrustedList:       s.trustedList.Load(),
		TrustedDefault:    s.trustedDefault.Load(),
		NotAddress:        s.notAddress.Load(),
		Unreadable:        s.unreadable.Load(),
		Adjudicated:       s.adjudicated.Load(),
		ServedDirect:      s.servedDirect.Load(),
		ServedTrusted:     s.servedTrusted.Load(),
		ServedNoAnswer:    s.servedNoAnswer.Load(),
		Refused:           s.refused.Load(),
		DroppedNoReply:    s.droppedNoReply.Load(),
		DirectSkipped:     s.directSkipped.Load(),
		DirectSendFailed:  s.directSendFailed.Load(),
		DirectBreakerOpen: breakerOpen,
	}
}
