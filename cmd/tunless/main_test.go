package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWaitForServicePrefersReportedError(t *testing.T) {
	want := errors.New("listener failed")
	serviceErrors := make(chan error, 1)
	serviceErrors <- want
	if got := waitForService(context.Background(), serviceErrors, func() bool { return false }); !errors.Is(got, want) {
		t.Fatalf("waitForService error = %v, want %v", got, want)
	}
	if err := waitForService(context.Background(), make(chan error), func() bool { return true }); err != nil {
		t.Fatalf("ready service returned %v", err)
	}
}

func TestCgroupPathFromProc(t *testing.T) {
	path, err := cgroupPathFromProc([]byte("0::/docker/0123456789abcdef\n"))
	if err != nil {
		t.Fatal(err)
	}
	if path != "/sys/fs/cgroup/docker/0123456789abcdef" {
		t.Fatalf("path = %q", path)
	}
}

func TestCgroupMatchesExactContainer(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, path := range []string{
		"/docker/" + id,
		"/system.slice/docker-" + id + ".scope",
		"/cri-containerd-" + id + ".scope",
		"/crio-" + id + ".scope",
		"/machine.slice/libpod-" + id + ".scope",
	} {
		if !cgroupMatchesContainer(path, id) {
			t.Fatalf("did not match %q", path)
		}
	}
	if cgroupMatchesContainer("/docker/"+id+"-neighbor", id) || cgroupMatchesContainer("/docker/prefix-"+id, id) {
		t.Fatal("accepted a partial container ID match")
	}
}

func TestWatchContainerScopeStopsWhenNamespaceDisappears(t *testing.T) {
	root := t.TempDir()
	cgroup := filepath.Join(root, "cgroup")
	namespace := filepath.Join(root, "netns")
	if err := os.Mkdir(cgroup, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(namespace, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := make(chan struct{})
	go watchContainerScope(ctx, func() { cancel(); close(stopped) }, cgroup, namespace)
	if err := os.Remove(namespace); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("container scope watcher did not stop")
	}
}

func TestCgroupPathFromProcRejectsRootAndLegacy(t *testing.T) {
	for _, value := range []string{"0::/\n", "2:cpu:/docker/id\n", "", "0::/../../user.slice\n"} {
		if _, err := cgroupPathFromProc([]byte(value)); err == nil {
			t.Fatalf("accepted unsafe cgroup data %q", value)
		}
	}
}

func TestPrivateDNSPrefixes(t *testing.T) {
	got := privateDNSPrefixes([]byte("nameserver 127.0.0.11\nnameserver 192.168.65.7\nnameserver 1.1.1.1\nnameserver 192.168.65.7\n"))
	if len(got) != 2 || got[0] != "127.0.0.11/32" || got[1] != "192.168.65.7/32" {
		t.Fatalf("prefixes = %v", got)
	}
}

func TestValidateContainerID(t *testing.T) {
	if err := validateContainerID("0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"short", "0123456789AB", "0123456789../"} {
		if err := validateContainerID(value); err == nil {
			t.Fatalf("accepted unsafe container ID %q", value)
		}
	}
}

func TestParseUpstreamValidatesAndNormalizesAddress(t *testing.T) {
	tests := []struct {
		value   string
		address string
		valid   bool
	}{
		{"127.0.0.1:7890", "127.0.0.1:7890", true},
		{"socks5://user:pass@[::1]:1080", "[::1]:1080", true},
		{"localhost", "", false},
		{"localhost:0", "", false},
		{"socks5://localhost", "", false},
		{"socks5://localhost:1080/path", "", false},
		{"http://localhost:1080", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			client, err := parseUpstream(tt.value)
			if (err == nil) != tt.valid {
				t.Fatalf("error = %v", err)
			}
			if tt.valid && client.Address != tt.address {
				t.Fatalf("address = %q, want %q", client.Address, tt.address)
			}
		})
	}
}

func TestReservedDestinationsKeepTheDatapathDirect(t *testing.T) {
	// The loop this prevents: the upstream dials the resolver to answer a
	// query tunless rewrote, and capturing that dial hands the query back to
	// the upstream that is waiting on it.
	reserved, err := reservedDestinations("192.0.2.10:1080", netip.MustParseAddrPort("1.1.1.1:53"), nil)
	if err != nil {
		t.Fatalf("reservedDestinations: %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.10/32"), netip.MustParsePrefix("1.1.1.1/32")}
	if len(reserved) != len(want) {
		t.Fatalf("reserved = %v, want %v", reserved, want)
	}
	for i, prefix := range want {
		if reserved[i] != prefix {
			t.Fatalf("reserved[%d] = %v, want %v", i, reserved[i], prefix)
		}
	}
}

func TestReservedDestinationsSkipLoopbackAndExplicitIncludes(t *testing.T) {
	// A loopback upstream is already skipped in the capture path itself.
	reserved, err := reservedDestinations("127.0.0.1:7897", netip.MustParseAddrPort("1.1.1.1:53"), nil)
	if err != nil {
		t.Fatalf("reservedDestinations: %v", err)
	}
	if len(reserved) != 1 || reserved[0] != netip.MustParsePrefix("1.1.1.1/32") {
		t.Fatalf("reserved = %v, want only the resolver", reserved)
	}
	// Naming a prefix explicitly is the operator saying they know.
	reserved, err = reservedDestinations("127.0.0.1:7897", netip.MustParseAddrPort("1.1.1.1:53"), []string{"1.1.1.1/32"})
	if err != nil {
		t.Fatalf("reservedDestinations: %v", err)
	}
	if len(reserved) != 0 {
		t.Fatalf("reserved = %v, want none", reserved)
	}
}

func TestReservedDestinationsOmitDisabledOverride(t *testing.T) {
	reserved, err := reservedDestinations("127.0.0.1:7897", netip.AddrPort{}, nil)
	if err != nil {
		t.Fatalf("reservedDestinations: %v", err)
	}
	if len(reserved) != 0 {
		t.Fatalf("reserved = %v, want none when DNS override is off", reserved)
	}
}
