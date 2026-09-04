package dnspolicy

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// query builds a recursion-desired query, the shape a stub resolver sends.
func query(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  qtype,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

// twoQuestions builds a message asking two names at once, which real stub
// resolvers do not send but which the policy still has to route somewhere.
func twoQuestions(t *testing.T, first, second string) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{first, second} {
		if err := builder.Question(dnsmessage.Question{
			Name:  dnsmessage.MustNewName(name),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}); err != nil {
			t.Fatal(err)
		}
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

// answer builds a reply carrying the given addresses.
func answer(t *testing.T, name string, addresses ...string) []byte {
	t.Helper()
	return answerWithCode(t, name, dnsmessage.RCodeSuccess, addresses...)
}

func answerWithCode(t *testing.T, name string, code dnsmessage.RCode, addresses ...string) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID:                 0x1234,
		Response:           true,
		RecursionAvailable: true,
		RCode:              code,
	})
	encoded := dnsmessage.MustNewName(name)
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: encoded, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := builder.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	for _, value := range addresses {
		addr := netip.MustParseAddr(value)
		header := dnsmessage.ResourceHeader{Name: encoded, Class: dnsmessage.ClassINET, TTL: 300}
		if addr.Is4() {
			if err := builder.AResource(header, dnsmessage.AResource{A: addr.As4()}); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := builder.AAAAResource(header, dnsmessage.AAAAResource{AAAA: addr.As16()}); err != nil {
			t.Fatal(err)
		}
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}
