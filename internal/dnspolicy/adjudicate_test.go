package dnspolicy

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func adjudicator(t *testing.T) *Policy {
	t.Helper()
	return &Policy{
		Prefixes:       NewPrefixSet(prefixes(t, "203.0.113.0/24")),
		DirectResolver: netip.MustParseAddrPort("223.5.5.5:53"),
	}
}

func TestADirectAnswerInsideTheSetIsServedImmediately(t *testing.T) {
	// Nothing the trusted resolver could say would change this, so nothing
	// waits for it. That is where the whole availability property comes from:
	// a name the set covers resolves at the speed of the near resolver and does
	// not depend on the tunnel being up at all.
	policy := adjudicator(t)
	verdict, reason := policy.Adjudicate(Exchange{
		Direct: answer(t, "www.example.com.", "203.0.113.7"),
	})
	if verdict != VerdictServeDirect || reason != ReasonDirectInSet {
		t.Fatalf("Adjudicate = %v/%s, want serve-direct/%s", verdict, reason, ReasonDirectInSet)
	}
}

func TestOneAddressInsideTheSetIsEnough(t *testing.T) {
	// A content network routinely answers with a mixed set, and requiring every
	// address to be inside would reject the correct nearby answer for
	// containing one distant member of the same rotation.
	policy := adjudicator(t)
	verdict, _ := policy.Adjudicate(Exchange{
		Direct: answer(t, "www.example.com.", "198.51.100.1", "203.0.113.7", "192.0.2.1"),
	})
	if verdict != VerdictServeDirect {
		t.Fatalf("Adjudicate = %v, want serve-direct", verdict)
	}
}

func TestAnAnswerOutsideTheSetLosesToTheTrustedResolver(t *testing.T) {
	// It may be a good answer for a service that is genuinely far away, and it
	// may be injected; from the addresses alone those are the same message.
	policy := adjudicator(t)
	verdict, reason := policy.Adjudicate(Exchange{
		Direct:      answer(t, "www.example.com.", "198.51.100.1"),
		DirectDone:  true,
		Trusted:     answer(t, "www.example.com.", "192.0.2.9"),
		TrustedDone: true,
	})
	if verdict != VerdictServeTrusted || reason != ReasonDirectOutOfSet {
		t.Fatalf("Adjudicate = %v/%s, want serve-trusted/%s", verdict, reason, ReasonDirectOutOfSet)
	}
}

func TestTheOutcomeDoesNotDependOnWhichReplyArrivesFirst(t *testing.T) {
	// If the first answer to arrive won, the same name would resolve
	// differently on a busy network than on an idle one, and a policy whose
	// result depends on timing cannot be reasoned about or tested.
	policy := adjudicator(t)
	inSet := answer(t, "www.example.com.", "203.0.113.7")
	trusted := answer(t, "www.example.com.", "192.0.2.9")

	// The trusted half is in, the direct half is still outstanding: nothing is
	// concluded, because the direct half can still change the answer.
	verdict, _ := policy.Adjudicate(Exchange{Trusted: trusted, TrustedDone: true})
	if verdict != VerdictWait {
		t.Fatalf("Adjudicate with only the trusted half = %v, want wait", verdict)
	}
	// Once it arrives and is inside the set, it wins even though it was second.
	verdict, _ = policy.Adjudicate(Exchange{
		Trusted: trusted, TrustedDone: true,
		Direct: inSet, DirectDone: true,
	})
	if verdict != VerdictServeDirect {
		t.Fatalf("Adjudicate = %v, want serve-direct regardless of arrival order", verdict)
	}
}

func TestTheDirectWindowReleasesAnExchangeTheDirectHalfAbandoned(t *testing.T) {
	// Waiting is bounded so that a direct resolver which is not answering does
	// not cost a round trip on every lookup.
	policy := adjudicator(t)
	trusted := answer(t, "www.example.com.", "192.0.2.9")
	verdict, reason := policy.Adjudicate(Exchange{
		Trusted: trusted, TrustedDone: true,
		DirectWindowClosed: true,
	})
	if verdict != VerdictServeTrusted || reason != ReasonTrustedOnly {
		t.Fatalf("Adjudicate = %v/%s, want serve-trusted/%s", verdict, reason, ReasonTrustedOnly)
	}
}

func TestASuspectAnswerIsRefusedRatherThanServedWhenTheTunnelIsDown(t *testing.T) {
	// Serving it is the one thing this path exists not to do. SERVFAIL says the
	// resolver could not answer, which is exactly true, and stub resolvers do
	// not cache it — so a lookup retried after the tunnel returns gets the real
	// answer rather than a remembered lie.
	policy := adjudicator(t)
	verdict, reason := policy.Adjudicate(Exchange{
		Direct: answer(t, "www.example.com.", "198.51.100.1"), DirectDone: true,
		TrustedDone: true,
	})
	if verdict != VerdictRefuse || reason != ReasonSuspectAnswer {
		t.Fatalf("Adjudicate = %v/%s, want refuse/%s", verdict, reason, ReasonSuspectAnswer)
	}
}

func TestAnAnswerWithNoAddressIsServedOnceTheTrustedHalfHasFailed(t *testing.T) {
	// Every AAAA lookup for a v4-only host returns no address. Treating that as
	// suspect would put a tunnel round trip in front of half of every
	// dual-stack application's lookups and fail them outright while the tunnel
	// is down. There is no address in the reply to misroute a connection to, so
	// the worst an injected one can do is deny a name — which refusing does
	// just as thoroughly.
	policy := adjudicator(t)
	for _, empty := range [][]byte{
		answer(t, "www.example.com."),
		answerWithCode(t, "www.example.com.", dnsmessage.RCodeNameError),
	} {
		verdict, reason := policy.Adjudicate(Exchange{
			Direct: empty, DirectDone: true, TrustedDone: true,
		})
		if verdict != VerdictServeDirect || reason != ReasonDirectNoAnswer {
			t.Fatalf("Adjudicate = %v/%s, want serve-direct/%s", verdict, reason, ReasonDirectNoAnswer)
		}
	}
}

func TestAForgedDenialStillLosesWhileTheTunnelIsUp(t *testing.T) {
	// The concession above is bounded to the case where nothing else can
	// answer. A trusted resolver that is working overrules an injected
	// NXDOMAIN, which is the censorship technique this whole path exists for.
	policy := adjudicator(t)
	verdict, _ := policy.Adjudicate(Exchange{
		Direct: answerWithCode(t, "www.example.com.", dnsmessage.RCodeNameError), DirectDone: true,
		Trusted: answer(t, "www.example.com.", "192.0.2.9"), TrustedDone: true,
	})
	if verdict != VerdictServeTrusted {
		t.Fatalf("Adjudicate = %v, want the real answer to beat a forged denial", verdict)
	}
}

func TestAResolverReportingFailureIsNotAnAnswerToPrefer(t *testing.T) {
	// SERVFAIL and REFUSED are the resolver saying it could not answer, which
	// is not a result to serve over asking somewhere else. NXDOMAIN is.
	policy := adjudicator(t)
	for _, code := range []dnsmessage.RCode{dnsmessage.RCodeServerFailure, dnsmessage.RCodeRefused, dnsmessage.RCodeFormatError} {
		verdict, _ := policy.Adjudicate(Exchange{
			Direct: answer(t, "www.example.com.", "198.51.100.1"), DirectDone: true,
			Trusted: answerWithCode(t, "www.example.com.", code), TrustedDone: true,
		})
		if verdict != VerdictRefuse {
			t.Errorf("Adjudicate with trusted %v = %v, want refuse", code, verdict)
		}
	}
	verdict, _ := policy.Adjudicate(Exchange{
		Direct: answer(t, "www.example.com.", "198.51.100.1"), DirectDone: true,
		Trusted: answerWithCode(t, "www.example.com.", dnsmessage.RCodeNameError), TrustedDone: true,
	})
	if verdict != VerdictServeTrusted {
		t.Errorf("Adjudicate with trusted NXDOMAIN = %v, want serve-trusted", verdict)
	}
}

func TestNothingArrivingAtAllIsDroppedRatherThanAnswered(t *testing.T) {
	policy := adjudicator(t)
	verdict, reason := policy.Adjudicate(Exchange{DirectDone: true, TrustedDone: true})
	if verdict != VerdictDrop || reason != ReasonNoReply {
		t.Fatalf("Adjudicate = %v/%s, want drop/%s", verdict, reason, ReasonNoReply)
	}
	deadline, _ := policy.Adjudicate(Exchange{DeadlineReached: true})
	if deadline != VerdictDrop {
		t.Fatalf("Adjudicate at the deadline = %v, want drop", deadline)
	}
}

func TestOnlyTheAnswerSectionIsBelieved(t *testing.T) {
	// Believing an address because of a section the querier did not ask about
	// is how a resolver gets poisoned by a record it never requested.
	policy := adjudicator(t)
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, Response: true})
	name := dnsmessage.MustNewName("www.example.com.")
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := builder.StartAdditionals(); err != nil {
		t.Fatal(err)
	}
	inSet := netip.MustParseAddr("203.0.113.7")
	if err := builder.AResource(
		dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 300},
		dnsmessage.AResource{A: inSet.As4()},
	); err != nil {
		t.Fatal(err)
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if policy.answersInSet(message) {
		t.Fatal("an address in the additional section was believed")
	}
}

func TestRefusalEchoesTheQuestionAndNothingElse(t *testing.T) {
	// A response has to carry the question to be matched to its query. The
	// answer, authority and additional sections of the query are not ours to
	// repeat.
	original := query(t, "www.example.com.", dnsmessage.TypeA)
	refusal := Refusal(original)
	if refusal == nil {
		t.Fatal("Refusal returned nothing for a well-formed query")
	}
	if binary.BigEndian.Uint16(refusal[:2]) != binary.BigEndian.Uint16(original[:2]) {
		t.Error("the refusal carried a different transaction ID")
	}
	if refusal[2]&0x80 == 0 {
		t.Error("the refusal was not marked as a response")
	}
	if got := refusal[3] & 0x0f; got != 2 {
		t.Errorf("rcode = %d, want 2 (SERVFAIL)", got)
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(refusal)
	if err != nil {
		t.Fatalf("the refusal did not parse: %v", err)
	}
	if !header.Response || header.RCode != dnsmessage.RCodeServerFailure {
		t.Errorf("header = %+v, want a SERVFAIL response", header)
	}
	question, err := parser.Question()
	if err != nil {
		t.Fatalf("the refusal carried no question: %v", err)
	}
	if question.Name.String() != "www.example.com." {
		t.Errorf("question = %q, want the name that was asked", question.Name.String())
	}
	if _, err := parser.Question(); err == nil {
		t.Error("the refusal carried more questions than the query")
	}
	if err := parser.SkipAllAnswers(); err != nil {
		t.Fatal(err)
	}
	if _, err := parser.AuthorityHeader(); err == nil {
		t.Error("the refusal carried authority records")
	}
}

func TestRefusalDeclinesToInventAResponseItCannotFrame(t *testing.T) {
	// A query with no readable question section has nothing to echo, and a
	// malformed response would be worse than none.
	for _, message := range [][]byte{nil, make([]byte, 11), make([]byte, 12), {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c}} {
		if got := Refusal(message); got != nil {
			t.Errorf("Refusal(%d bytes) = %x, want nothing", len(message), got)
		}
	}
}
