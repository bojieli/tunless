package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bojieli/tunless/internal/dnspolicy"
	"golang.org/x/net/dns/dnsmessage"
)

func writeList(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func aQuery(t *testing.T, name string) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  dnsmessage.TypeA,
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

func TestTheDefaultConfigurationRoutesEverythingThroughTheTunnel(t *testing.T) {
	// Nobody who does not ask for any of this may have their traffic move.
	policy, err := buildDNSPolicy(dnsPolicyOptions{overrideEnabled: true})
	if err != nil {
		t.Fatalf("buildDNSPolicy: %v", err)
	}
	if policy.Adjudicates() || policy.Suffixes.Len() != 0 || policy.Prefixes.Len() != 0 {
		t.Fatal("an unconfigured policy is not inert")
	}
	if got := policy.Decide(aQuery(t, "www.example.com.")).Route; got != dnspolicy.RouteTrusted {
		t.Fatalf("Decide = %v, want trusted", got)
	}
}

func TestIncoherentCombinationsAreRefusedAtStartup(t *testing.T) {
	// Each of these has a runtime appearance identical to the feature working
	// perfectly and finding nothing to do, which is the one failure an operator
	// cannot distinguish by looking.
	for _, test := range []struct {
		name    string
		options dnsPolicyOptions
		wants   string
	}{
		{
			name:    "a direct resolver with nothing to judge answers by",
			options: dnsPolicyOptions{overrideEnabled: true, directResolver: "223.5.5.5:53"},
			wants:   "--dns-direct-prefix",
		},
		{
			name:    "prefixes with no resolver to judge",
			options: dnsPolicyOptions{overrideEnabled: true, directPrefixes: []string{"203.0.113.0/24"}},
			wants:   "--dns-direct",
		},
		{
			name: "a policy with nothing to route",
			options: dnsPolicyOptions{
				overrideEnabled: false,
				directResolver:  "223.5.5.5:53",
				directPrefixes:  []string{"203.0.113.0/24"},
			},
			wants: "--disable-dns-override",
		},
		{
			name: "a direct resolver that is not an address",
			options: dnsPolicyOptions{
				overrideEnabled: true,
				directResolver:  "dns.example.com:53",
				directPrefixes:  []string{"203.0.113.0/24"},
			},
			wants: "numeric IP:port",
		},
		{
			name: "a direct resolver with no port",
			options: dnsPolicyOptions{
				overrideEnabled: true,
				directResolver:  "223.5.5.5:0",
				directPrefixes:  []string{"203.0.113.0/24"},
			},
			wants: "numeric IP:port",
		},
		{
			name:    "a malformed prefix",
			options: dnsPolicyOptions{overrideEnabled: true, directResolver: "223.5.5.5:53", directPrefixes: []string{"nonsense"}},
			wants:   "--dns-direct-prefix",
		},
		{
			name:    "a malformed suffix",
			options: dnsPolicyOptions{overrideEnabled: true, directDomains: []string{"a b.com"}},
			wants:   "--direct-domain",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := buildDNSPolicy(test.options)
			if err == nil {
				t.Fatal("the configuration was accepted")
			}
			if !strings.Contains(err.Error(), test.wants) {
				t.Errorf("error %q does not mention %q", err, test.wants)
			}
		})
	}
}

func TestNameListsAreUsableWithoutADirectResolver(t *testing.T) {
	policy, err := buildDNSPolicy(dnsPolicyOptions{
		overrideEnabled: true,
		directDomains:   []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("buildDNSPolicy: %v", err)
	}
	if got := policy.Decide(aQuery(t, "www.example.com.")).Route; got != dnspolicy.RouteDirect {
		t.Fatalf("Decide = %v, want direct", got)
	}
}

func TestListsLoadFromFilesAndCombineWithFlags(t *testing.T) {
	directFile := writeList(t, "direct.txt", "# generated\nfromfile.example\n\nsecond.example\n")
	trustedFile := writeList(t, "trusted.txt", "private.fromfile.example\n")
	prefixFile := writeList(t, "prefixes.txt", "203.0.113.0/24\n2001:db8::/32\n")
	policy, err := buildDNSPolicy(dnsPolicyOptions{
		overrideEnabled:   true,
		directResolver:    "223.5.5.5:53",
		directDomains:     []string{"fromflag.example"},
		trustedDomains:    []string{"private.fromflag.example"},
		directPrefixes:    []string{"198.51.100.0/24"},
		directDomainFile:  directFile,
		trustedDomainFile: trustedFile,
		directPrefixFile:  prefixFile,
	})
	if err != nil {
		t.Fatalf("buildDNSPolicy: %v", err)
	}
	if !policy.Adjudicates() {
		t.Fatal("a fully configured policy does not adjudicate")
	}
	for _, test := range []struct {
		name string
		want dnspolicy.Route
	}{
		{"a.fromfile.example.", dnspolicy.RouteDirect},
		{"a.second.example.", dnspolicy.RouteDirect},
		{"a.fromflag.example.", dnspolicy.RouteDirect},
		// The longer suffix wins whichever source it came from, so a hand
		// written exception carves a name out of a downloaded list.
		{"private.fromfile.example.", dnspolicy.RouteTrusted},
		{"deep.private.fromflag.example.", dnspolicy.RouteTrusted},
		{"unlisted.example.net.", dnspolicy.RouteAdjudicate},
	} {
		if got := policy.Decide(aQuery(t, test.name)).Route; got != test.want {
			t.Errorf("Decide(%q) = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestAMissingListFileStopsStartup(t *testing.T) {
	// An empty list and a path that does not exist behave identically at
	// runtime and mean completely different things.
	absent := filepath.Join(t.TempDir(), "absent")
	for _, options := range []dnsPolicyOptions{
		{overrideEnabled: true, directDomainFile: absent},
		{overrideEnabled: true, trustedDomainFile: absent},
		{overrideEnabled: true, directResolver: "223.5.5.5:53", directPrefixFile: absent},
	} {
		if _, err := buildDNSPolicy(options); err == nil {
			t.Error("a missing list file was treated as an empty one")
		}
	}
}

func TestLocalDomainsSurviveThePolicy(t *testing.T) {
	// The split-horizon escape hatch predates all of this and must keep working
	// alongside it.
	policy, err := buildDNSPolicy(dnsPolicyOptions{
		overrideEnabled: true,
		localDomains:    []string{"corp.example.com"},
		directDomains:   []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("buildDNSPolicy: %v", err)
	}
	if got := policy.Decide(aQuery(t, "wiki.corp.example.com.")).Route; got != dnspolicy.RouteLocal {
		t.Fatalf("Decide = %v, want local even under a direct-listed zone", got)
	}
}
