package dnspolicy

import (
	"encoding/binary"
	"strconv"
)

// Verdict is what an adjudication has concluded so far.
type Verdict uint8

const (
	// VerdictWait means neither half has settled the question yet.
	VerdictWait Verdict = iota
	// VerdictServeDirect returns the direct resolver's reply to the
	// application.
	VerdictServeDirect
	// VerdictServeTrusted returns the trusted resolver's reply.
	VerdictServeTrusted
	// VerdictRefuse returns SERVFAIL. It is chosen over serving an answer that
	// could be wrong in the direction that matters.
	VerdictRefuse
	// VerdictDrop returns nothing, leaving the application's own resolver to
	// retry the way it would against any resolver that did not answer.
	VerdictDrop
)

func (v Verdict) String() string {
	switch v {
	case VerdictServeDirect:
		return "serve-direct"
	case VerdictServeTrusted:
		return "serve-trusted"
	case VerdictRefuse:
		return "refuse"
	case VerdictDrop:
		return "drop"
	default:
		return "wait"
	}
}

// Reasons an adjudication can conclude with.
const (
	ReasonDirectInSet    = "direct-in-set"
	ReasonDirectOutOfSet = "direct-out-of-set"
	ReasonDirectNoAnswer = "direct-no-answer"
	ReasonTrustedOnly    = "trusted-only"
	ReasonSuspectAnswer  = "suspect-answer-refused"
	ReasonNoReply        = "no-reply"
)

// Exchange is the state of one adjudication: what each half has produced and
// whether it is still able to produce anything.
type Exchange struct {
	// Direct and Trusted are the replies, nil when that half failed or has not
	// answered yet.
	Direct, Trusted []byte
	// DirectDone and TrustedDone report that the half will produce nothing
	// further, whether because it answered or because it failed.
	DirectDone, TrustedDone bool
	// DirectWindowClosed reports that DirectReplyWindow has elapsed, so the
	// direct half can no longer change the outcome even if it has not formally
	// finished.
	DirectWindowClosed bool
	// DeadlineReached reports that the whole exchange is out of time.
	DeadlineReached bool
}

// Adjudicate decides what to do with the answers so far.
//
// The rule in full, because the reasoning matters more than the branches:
//
// An answer from the direct resolver is believed when it names an address
// inside the operator's set, and that decision is made the moment it arrives.
// Nothing the trusted resolver could say would change it, so nothing waits for
// it, and the names an operator cares about most — the ones near enough for the
// set to cover — resolve at the speed of the near resolver and do not depend on
// the tunnel being up at all.
//
// An answer naming addresses outside the set is not served. It may be a
// perfectly good answer for a service that is genuinely far away, and it may be
// an injected one; from the addresses alone those are the same message. So the
// trusted resolver decides, which is what would have happened without any of
// this.
//
// An answer naming no address at all is a third case, and it is the one worth
// being careful about. Refusing it costs real traffic: every AAAA lookup for a
// v4-only host returns no address, and treating that as suspect would put a
// tunnel round trip in front of half of every dual-stack application's
// lookups, and fail them outright while the tunnel is down. Serving it cannot
// misroute a connection, because there is no address in it to connect to — the
// worst an injected one can do is deny a name, and refusing it denies the same
// name just as thoroughly. So it is served once the trusted resolver has been
// given its chance and could not take it, and not before: while the tunnel is
// up, a forged NXDOMAIN still loses to the real answer.
func (p *Policy) Adjudicate(e Exchange) (Verdict, string) {
	if e.Direct != nil && p.answersInSet(e.Direct) {
		return VerdictServeDirect, ReasonDirectInSet
	}
	// The direct half can still change the outcome until it settles or its
	// window closes, so nothing is concluded from the trusted half alone. That
	// is what keeps the same name from resolving differently on a busy network
	// than on an idle one.
	directSettled := e.DirectDone || e.DirectWindowClosed || e.DeadlineReached
	if !directSettled {
		return VerdictWait, ""
	}
	if replyUsable(e.Trusted) {
		if e.Direct != nil {
			return VerdictServeTrusted, ReasonDirectOutOfSet
		}
		return VerdictServeTrusted, ReasonTrustedOnly
	}
	if !e.TrustedDone && !e.DeadlineReached {
		return VerdictWait, ""
	}
	if e.Direct == nil {
		return VerdictDrop, ReasonNoReply
	}
	if len(answerAddresses(e.Direct)) == 0 {
		return VerdictServeDirect, ReasonDirectNoAnswer
	}
	return VerdictRefuse, ReasonSuspectAnswer
}

// answersInSet reports whether a reply names at least one address the operator
// said the direct resolver answers credibly for.
//
// One address is enough rather than all of them. A content network routinely
// answers with a mixed set, and requiring every address to be inside would
// reject the correct nearby answer for containing one distant member of the
// same rotation.
func (p *Policy) answersInSet(reply []byte) bool {
	if p.Prefixes == nil || !replyUsable(reply) {
		return false
	}
	for _, addr := range answerAddresses(reply) {
		if p.Prefixes.Contains(addr) {
			return true
		}
	}
	return false
}

// dnsHeaderSize is the fixed DNS message header: ID, flags, and four counts.
const dnsHeaderSize = 12

// replyUsable reports whether a message is an answer a client can act on.
//
// NOERROR and NXDOMAIN are answers: one says where the name points, the other
// says it points nowhere, and a resolver client caches and acts on both.
// SERVFAIL and REFUSED are the resolver reporting that it could not answer,
// which is not a result to prefer over asking somewhere else.
func replyUsable(reply []byte) bool {
	if len(reply) < dnsHeaderSize {
		return false
	}
	// Byte 2 carries QR in its high bit; a message not marked as a response is
	// not one, whatever else it says.
	if reply[2]&0x80 == 0 {
		return false
	}
	switch reply[3] & 0x0f {
	case 0, 3: // NOERROR, NXDOMAIN
		return true
	default:
		return false
	}
}

// Refusal builds the SERVFAIL returned to the application when neither
// resolver produced an answer worth believing.
//
// SERVFAIL rather than silence, and rather than the suspect answer. Silence
// makes a decision look like a dead network and costs the client its full
// retry schedule before it finds out. The suspect answer is the thing this
// whole path exists not to serve. SERVFAIL says the resolver could not answer,
// which is exactly true, and every stub resolver already knows what to do with
// it — including not caching it, so a lookup retried after the tunnel returns
// gets the real answer rather than a remembered failure.
//
// The question section is echoed and everything after it dropped. A response
// has to carry the question to be matched to its query; the answer, authority
// and additional sections of the query are not ours to repeat.
func Refusal(query []byte) []byte {
	end, ok := questionSectionEnd(query)
	if !ok {
		return nil
	}
	reply := make([]byte, end)
	copy(reply, query[:end])
	// QR set, opcode and RD preserved from the query, AA and TC cleared.
	reply[2] = (reply[2] & 0x79) | 0x80
	// RA set, Z and AD/CD cleared, RCODE 2 (SERVFAIL).
	reply[3] = 0x80 | 0x02
	binary.BigEndian.PutUint16(reply[6:8], 0)
	binary.BigEndian.PutUint16(reply[8:10], 0)
	binary.BigEndian.PutUint16(reply[10:12], 0)
	return reply
}

// questionSectionEnd returns the offset just past the last question.
//
// The names are walked rather than parsed, and a compression pointer ends the
// walk unsuccessfully. A pointer in a question section is malformed — there is
// nothing earlier in the message for it to point at — and following one is how
// a name walker is turned into a loop.
func questionSectionEnd(query []byte) (int, bool) {
	if len(query) < dnsHeaderSize {
		return 0, false
	}
	count := int(binary.BigEndian.Uint16(query[4:6]))
	if count == 0 || count > maxQuestions {
		return 0, false
	}
	offset := dnsHeaderSize
	for range count {
		for {
			if offset >= len(query) {
				return 0, false
			}
			length := int(query[offset])
			if length&0xc0 != 0 {
				return 0, false
			}
			offset += 1 + length
			if length == 0 {
				break
			}
		}
		// QTYPE and QCLASS.
		offset += 4
		if offset > len(query) {
			return 0, false
		}
	}
	return offset, true
}

// ReplySummary describes a reply that carries no address, for diagnostics.
func ReplySummary(reply []byte) string {
	if len(reply) < dnsHeaderSize {
		return "no reply"
	}
	switch reply[3] & 0x0f {
	case 0:
		return "no address records"
	case 1:
		return "FORMERR"
	case 2:
		return "SERVFAIL"
	case 3:
		return "NXDOMAIN"
	case 4:
		return "NOTIMP"
	case 5:
		return "REFUSED"
	default:
		return "rcode " + strconv.Itoa(int(reply[3]&0x0f))
	}
}
