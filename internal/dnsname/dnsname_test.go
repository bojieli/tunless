package dnsname

import "testing"

func TestIsLocalRecognisesReservedAndPrivateNameSpaces(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{"unqualified name", "nas", true},
		{"multicast dns", "printer.local", true},
		{"multicast dns with root label", "printer.local.", true},
		{"residential network", "router.home.arpa", true},
		{"reserved for testing", "host.test", true},
		{"withheld delegation", "files.lan", true},
		{"private use", "wiki.internal", true},
		{"uppercase", "PRINTER.LOCAL", true},
		{"public name", "www.google.com", false},
		{"suffix is not a label boundary", "notlocal.example", false},
		{"label boundary is required", "mylocal.example.com", false},
		{"public zone ending in a local label", "local.example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsLocal(tt.query, nil); got != tt.want {
				t.Fatalf("IsLocal(%q) = %v, want %v", tt.query, got, tt.want)
			}
		})
	}
}

func TestIsLocalCoversPrivateReverseZones(t *testing.T) {
	local := []string{
		"1.1.168.192.in-addr.arpa",
		"5.4.3.10.in-addr.arpa",
		"1.0.0.127.in-addr.arpa",
		"7.6.16.172.in-addr.arpa",
		"7.6.31.172.in-addr.arpa",
		"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa",
	}
	for _, name := range local {
		if !IsLocal(name, nil) {
			t.Errorf("IsLocal(%q) = false, want true", name)
		}
	}
	// 172.15 and 172.32 fall outside 172.16.0.0/12 and are ordinary public
	// space, so their reverse names must still reach the trusted resolver.
	public := []string{
		"7.6.15.172.in-addr.arpa",
		"7.6.32.172.in-addr.arpa",
		"7.6.8.8.in-addr.arpa",
	}
	for _, name := range public {
		if IsLocal(name, nil) {
			t.Errorf("IsLocal(%q) = true, want false", name)
		}
	}
}

func TestIsLocalHonoursOperatorSuffixes(t *testing.T) {
	extra := []string{"corp.example.com", "office.test.net."}
	if !IsLocal("wiki.corp.example.com", extra) {
		t.Fatal("operator suffix did not match")
	}
	if !IsLocal("printer.office.test.net", extra) {
		t.Fatal("operator suffix with a root label did not match")
	}
	if IsLocal("www.example.com", extra) {
		t.Fatal("operator suffix matched a name outside it")
	}
	if IsLocal("notcorp.example.com", extra) {
		t.Fatal("operator suffix matched across a label boundary")
	}
}

func TestQueryIsLocalReadsTheQuestionSection(t *testing.T) {
	// A minimal query for printer.local, built by hand so the test does not
	// depend on the builder it is checking.
	query := func(labels ...string) []byte {
		message := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		for _, label := range labels {
			message = append(message, byte(len(label)))
			message = append(message, label...)
		}
		return append(message, 0x00, 0x00, 0x01, 0x00, 0x01)
	}
	if !QueryIsLocal(query("printer", "local"), nil) {
		t.Fatal("local query was not recognised")
	}
	if QueryIsLocal(query("www", "google", "com"), nil) {
		t.Fatal("public query was treated as local")
	}
	// An unreadable query has no known-local name, and must take the trusted
	// path rather than the network's own resolver.
	if QueryIsLocal([]byte{0x12}, nil) {
		t.Fatal("truncated query was treated as local")
	}
	if QueryIsLocal(nil, nil) {
		t.Fatal("empty query was treated as local")
	}
}

func TestQueryIsLocalRequiresEveryQuestionToBeLocal(t *testing.T) {
	// Two questions in one message, one local and one not. Redirecting the
	// message is the only way to answer the public name, so the message is not
	// local even though half of it is.
	message := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0}
	for _, labels := range [][]string{{"printer", "local"}, {"www", "google", "com"}} {
		for _, label := range labels {
			message = append(message, byte(len(label)))
			message = append(message, label...)
		}
		message = append(message, 0x00, 0x00, 0x01, 0x00, 0x01)
	}
	if QueryIsLocal(message, nil) {
		t.Fatal("mixed query was treated as local")
	}
}
