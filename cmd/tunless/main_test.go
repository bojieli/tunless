package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCgroupPathFromProc(t *testing.T) {
	path, err := cgroupPathFromProc([]byte("0::/docker/0123456789abcdef\n"))
	if err != nil {
		t.Fatal(err)
	}
	if path != "/sys/fs/cgroup/docker/0123456789abcdef" {
		t.Fatalf("path = %q", path)
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
