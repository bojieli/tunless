// Package dnsname classifies the names in a DNS query as answerable only by
// the resolver the application chose, or by any resolver.
//
// Capture rewrites port-53 flows to a trusted resolver so that a poisoned or
// filtered answer from the network the host happens to be on cannot decide
// where a connection goes. That rewrite is correct for every name whose answer
// is the same everywhere, and wrong for every name whose answer exists only on
// the local network: a trusted public resolver has never heard of `nas.lan`,
// and neither has the proxy behind it. Sending those queries away is how a
// working DNS override still breaks the printer.
//
// The split is by name rather than by resolver address, because the resolver
// address says nothing about which half a query falls into. The same LAN
// resolver answers `nas.lan` from its own records and `www.google.com` by
// forwarding upstream, and it is only the second one that needs protecting.
package dnsname

import (
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// localSuffixes are the name spaces whose answers are defined by the local
// network rather than by the public DNS.
//
// The first group is reserved by RFC: `localhost` and `invalid` (RFC 6761),
// `local` (RFC 6762 multicast DNS), `test` (RFC 6761, reserved for testing),
// and `home.arpa` (RFC 8375, the name for a residential network). The second
// group is not reserved by an RFC but is withheld from delegation and used for
// private networks in practice, which makes forwarding them to a public
// resolver a lookup that cannot succeed and can only leak the name.
var localSuffixes = []string{
	"localhost",
	"local",
	"invalid",
	"test",
	"home.arpa",
	"internal",
	"intranet",
	"private",
	"corp",
	"home",
	"lan",
	"localdomain",
}

// localReverseSuffixes are the reverse zones for address ranges that are not
// globally unique. A PTR lookup for 192.168.1.1 has a different right answer on
// every network, so only the local resolver can give it.
var localReverseSuffixes = []string{
	"10.in-addr.arpa",
	"127.in-addr.arpa",
	"168.192.in-addr.arpa",
	"254.169.in-addr.arpa",
	// fc00::/7 unique local addresses.
	"c.f.ip6.arpa",
	"d.f.ip6.arpa",
	// fe80::/10 link-local addresses.
	"8.e.f.ip6.arpa",
	"9.e.f.ip6.arpa",
	"a.e.f.ip6.arpa",
	"b.e.f.ip6.arpa",
	// ::1 loopback.
	"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
}

// Canonical lowercases a name and removes the trailing root label, so that the
// wire form, the presentation form, and any mix of case compare equal.
func Canonical(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// IsLocal reports whether name can only be answered by the resolver the
// application asked, and must therefore not be redirected to a trusted one.
//
// extraSuffixes carries operator-supplied domains, for a network whose internal
// names live under a name that is also a real public zone — a split-horizon
// `corp.example.com` is the usual shape, and no list of reserved names can
// predict it.
func IsLocal(name string, extraSuffixes []string) bool {
	canonical := Canonical(name)
	if canonical == "" {
		return false
	}
	// An unqualified name has no meaning outside the search domains of the
	// resolver that was asked. Sending it to a different resolver asks a
	// question that resolver cannot even parse the intent of.
	if !strings.Contains(canonical, ".") {
		return true
	}
	// 172.16.0.0/12 is the one private range whose reverse zone is not a whole
	// number of labels, so it is matched arithmetically rather than listed.
	if rest, ok := strings.CutSuffix(canonical, ".172.in-addr.arpa"); ok {
		if second, found := lastLabel(rest); found && second >= 16 && second <= 31 {
			return true
		}
	}
	for _, suffix := range localReverseSuffixes {
		if hasDNSSuffix(canonical, suffix) {
			return true
		}
	}
	for _, suffix := range localSuffixes {
		if hasDNSSuffix(canonical, suffix) {
			return true
		}
	}
	for _, suffix := range extraSuffixes {
		if canonical := Canonical(suffix); canonical != "" && hasDNSSuffix(Canonical(name), canonical) {
			return true
		}
	}
	return false
}

// lastLabel parses the final label of name as a decimal number, which is how
// the second octet of a 172.x reverse name is carried.
func lastLabel(name string) (int, bool) {
	label := name
	if index := strings.LastIndex(name, "."); index >= 0 {
		label = name[index+1:]
	}
	if label == "" || len(label) > 3 {
		return 0, false
	}
	value := 0
	for _, character := range label {
		if character < '0' || character > '9' {
			return 0, false
		}
		value = value*10 + int(character-'0')
	}
	return value, true
}

// hasDNSSuffix matches on label boundaries, so that `notlocal.example` does not
// match the `local` suffix while `printer.local` does.
func hasDNSSuffix(name, suffix string) bool {
	if name == suffix {
		return true
	}
	return len(name) > len(suffix) && strings.HasSuffix(name, "."+suffix)
}

// QuestionNames returns the names asked by a DNS message.
//
// A message with no question section, or one this cannot parse, returns no
// names rather than an error: the caller's decision is whether any name in the
// query is local, and a query that cannot be read has none that are known to
// be. Treating it as non-local sends it to the trusted resolver, which is the
// safe direction — an unreadable query redirected to a resolver that cannot
// answer it fails a lookup, while one left on a poisoned path fails a
// connection.
func QuestionNames(message []byte) []string {
	var parser dnsmessage.Parser
	if _, err := parser.Start(message); err != nil {
		return nil
	}
	var names []string
	for range maxQuestions {
		question, err := parser.Question()
		if err != nil {
			break
		}
		names = append(names, question.Name.String())
	}
	return names
}

// maxQuestions bounds the question section of one message. Real queries carry
// exactly one; the limit keeps a crafted header count from turning a single
// datagram into a long parse.
const maxQuestions = 8

// QueryIsLocal reports whether a raw DNS query asks only for names the local
// resolver owns. A query carrying no readable question is not local; see
// QuestionNames.
func QueryIsLocal(message []byte, extraSuffixes []string) bool {
	names := QuestionNames(message)
	if len(names) == 0 {
		return false
	}
	for _, name := range names {
		if !IsLocal(name, extraSuffixes) {
			return false
		}
	}
	return true
}
