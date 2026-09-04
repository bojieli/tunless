package dnspolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestListFilesSkipCommentsAndBlankLines(t *testing.T) {
	path := write(t, strings.Join([]string{
		"# a generated list",
		"",
		"example.com",
		"   spaced.example.net   ",
		"trailing.example.org # why this one is here",
		"; another comment style",
		"",
	}, "\n"))
	suffixes, err := LoadSuffixFile(path)
	if err != nil {
		t.Fatalf("LoadSuffixFile: %v", err)
	}
	want := []string{"example.com", "spaced.example.net", "trailing.example.org"}
	if len(suffixes) != len(want) {
		t.Fatalf("loaded %v, want %v", suffixes, want)
	}
	for i, entry := range want {
		if suffixes[i] != entry {
			t.Errorf("entry %d = %q, want %q", i, suffixes[i], entry)
		}
	}
}

func TestPrefixFilesAcceptBothFamiliesAndBareAddresses(t *testing.T) {
	path := write(t, "10.0.0.0/8\n2001:db8::/32\n203.0.113.7\n")
	loaded, err := LoadPrefixFile(path)
	if err != nil {
		t.Fatalf("LoadPrefixFile: %v", err)
	}
	if len(loaded) != 3 {
		t.Fatalf("loaded %d prefixes, want 3", len(loaded))
	}
	if got := loaded[2].Bits(); got != 32 {
		t.Errorf("a bare address became /%d, want a host route", got)
	}
}

func TestAMalformedLineReportsWhereItIs(t *testing.T) {
	// These files run to tens of thousands of lines. An error that does not say
	// where costs an afternoon.
	path := write(t, "10.0.0.0/8\n# fine\nnot-a-prefix\n")
	_, err := LoadPrefixFile(path)
	if err == nil {
		t.Fatal("a malformed prefix loaded without complaint")
	}
	if !strings.Contains(err.Error(), ":3:") {
		t.Errorf("error %q does not name line 3", err)
	}
}

func TestAMissingFileIsAnErrorRatherThanAnEmptyList(t *testing.T) {
	// An empty list and a path that does not exist behave identically at
	// runtime and mean completely different things.
	if _, err := LoadSuffixFile(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a missing suffix file loaded as empty")
	}
	if _, err := LoadPrefixFile(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a missing prefix file loaded as empty")
	}
}

func TestARealisticListLoadsIntoAWorkingSet(t *testing.T) {
	var builder strings.Builder
	builder.WriteString("# generated\n")
	for i := range 5000 {
		builder.WriteString("10.")
		builder.WriteByte(byte('0' + i%10))
		builder.WriteString(".0.0/24\n")
	}
	path := write(t, builder.String())
	loaded, err := LoadPrefixFile(path)
	if err != nil {
		t.Fatalf("LoadPrefixFile: %v", err)
	}
	if len(loaded) != 5000 {
		t.Fatalf("loaded %d entries, want 5000", len(loaded))
	}
	set := NewPrefixSet(loaded)
	if set.Empty() {
		t.Fatal("a set built from 5000 entries is empty")
	}
}
