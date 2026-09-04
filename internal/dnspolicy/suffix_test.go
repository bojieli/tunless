package dnspolicy

import "testing"

func mustAdd(t *testing.T, set *SuffixSet, suffix string, route Route) {
	t.Helper()
	if err := set.Add(suffix, route); err != nil {
		t.Fatalf("Add(%q): %v", suffix, err)
	}
}

func TestTheLongestSuffixDecidesRatherThanTheOrderListsLoaded(t *testing.T) {
	// An operator who sends a zone down the direct path and carves one name out
	// of it back to the tunnel has said something precise. Resolving that by
	// which list loaded first would silently do the opposite of it.
	set := NewSuffixSet()
	mustAdd(t, set, "example.com", RouteDirect)
	mustAdd(t, set, "secret.example.com", RouteTrusted)

	for _, test := range []struct {
		name   string
		want   Route
		suffix string
	}{
		{"www.example.com", RouteDirect, "example.com"},
		{"example.com", RouteDirect, "example.com"},
		{"secret.example.com", RouteTrusted, "secret.example.com"},
		{"deep.secret.example.com", RouteTrusted, "secret.example.com"},
	} {
		route, suffix, ok := set.Match(test.name)
		if !ok || route != test.want || suffix != test.suffix {
			t.Errorf("Match(%q) = %v/%q/%v, want %v/%q", test.name, route, suffix, ok, test.want, test.suffix)
		}
	}
}

func TestSuffixesMatchOnLabelBoundaries(t *testing.T) {
	// Matching on characters rather than labels would put notexample.com on the
	// direct path because it happens to end in example.com.
	set := NewSuffixSet()
	mustAdd(t, set, "example.com", RouteDirect)
	for _, name := range []string{"notexample.com", "example.com.evil.net", "com"} {
		if _, _, ok := set.Match(name); ok {
			t.Errorf("Match(%q) matched a suffix it does not end in on a label boundary", name)
		}
	}
}

func TestADuplicateSuffixResolvesTowardTheTunnel(t *testing.T) {
	// The direct list is the one an operator downloads with thousands of
	// entries in it; the trusted list is the one they write by hand. A
	// collision between them should not be decided by the one nobody read.
	forward := NewSuffixSet()
	mustAdd(t, forward, "example.com", RouteDirect)
	mustAdd(t, forward, "example.com", RouteTrusted)
	if route, _, _ := forward.Match("example.com"); route != RouteTrusted {
		t.Errorf("direct then trusted = %v, want trusted", route)
	}
	reverse := NewSuffixSet()
	mustAdd(t, reverse, "example.com", RouteTrusted)
	mustAdd(t, reverse, "example.com", RouteDirect)
	if route, _, _ := reverse.Match("example.com"); route != RouteTrusted {
		t.Errorf("trusted then direct = %v, want trusted", route)
	}
}

func TestSuffixesAreCaseAndRootLabelInsensitive(t *testing.T) {
	set := NewSuffixSet()
	mustAdd(t, set, "Example.COM.", RouteDirect)
	for _, name := range []string{"WWW.EXAMPLE.COM", "www.example.com.", "www.Example.com"} {
		if route, _, ok := set.Match(name); !ok || route != RouteDirect {
			t.Errorf("Match(%q) = %v/%v, want direct", name, route, ok)
		}
	}
}

func TestMalformedSuffixesAreRefusedAtLoad(t *testing.T) {
	// A list is thousands of lines nobody reads. A line that cannot mean
	// anything has to be reported, not skipped: skipping it produces a policy
	// that is quietly missing an entry the operator believes is there.
	set := NewSuffixSet()
	for _, suffix := range []string{"", "   ", "example..com", ".example.com", "example.com.", "a b.com"} {
		err := set.Add(suffix, RouteDirect)
		if suffix == "example.com." {
			if err != nil {
				t.Errorf("Add(%q) rejected a name with a root label: %v", suffix, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("Add(%q) accepted a malformed suffix", suffix)
		}
	}
}

func TestAnEmptySetMatchesNothing(t *testing.T) {
	var nilSet *SuffixSet
	if _, _, ok := nilSet.Match("example.com"); ok {
		t.Error("a nil set matched")
	}
	if nilSet.Len() != 0 {
		t.Error("a nil set reported entries")
	}
	if _, _, ok := NewSuffixSet().Match("example.com"); ok {
		t.Error("an empty set matched")
	}
}

func TestIntermediateLabelsDoNotMatchOnTheirOwn(t *testing.T) {
	// Adding a.b.c creates trie nodes for c and b.c. Neither is an entry, and
	// treating one as an entry would route a whole public suffix on the
	// strength of a single name below it.
	set := NewSuffixSet()
	mustAdd(t, set, "a.b.c", RouteDirect)
	for _, name := range []string{"c", "b.c", "other.b.c"} {
		if _, _, ok := set.Match(name); ok {
			t.Errorf("Match(%q) matched an interior node", name)
		}
	}
	if _, _, ok := set.Match("x.a.b.c"); !ok {
		t.Error("Match did not cover a name below the entry")
	}
}
