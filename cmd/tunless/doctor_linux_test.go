//go:build linux

package main

import (
	"strings"
	"testing"

	"github.com/bojieli/tunless"
)

// The netfilter fallback used to report "privilege-free backend selected",
// which is what every backend that is not the eBPF one reported. It is the
// opposite of privilege-free: it wants NET_ADMIN and a rule somebody else
// installed, and an operator running doctor to find out whether the host was
// ready was being told yes.
func TestDoctorChecksWhatTheRedirectBackendActuallyNeeds(t *testing.T) {
	checks := doctorRedirect("127.0.0.1:1080", tunless.Filter{})
	seen := map[string]doctorCheck{}
	for _, c := range checks {
		seen[c.Name] = c
	}
	for _, want := range []string{"redirect_listener", "redirect_filters", "so_original_dst", "redirect_rule"} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("doctor did not check %q; it reported %v", want, checks)
		}
	}
	if got := seen["redirect_listener"].Status; got != "pass" {
		t.Fatalf("a loopback listener was reported %q: %s", got, seen["redirect_listener"].Detail)
	}
	if got := seen["so_original_dst"].Status; got != "pass" {
		t.Fatalf("SO_ORIGINAL_DST reported %q on a Linux host: %s", got, seen["so_original_dst"].Detail)
	}
}

// A routable listener is an open proxy, because this backend cannot tell a
// redirected connection from one that arrived on its own. The backend refuses
// to start on one, so doctor has to say so rather than let the operator find
// out at start time.
func TestDoctorRefusesARoutableRedirectListener(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:1080", "192.0.2.1:1080"} {
		var got doctorCheck
		for _, c := range doctorRedirect(addr, tunless.Filter{}) {
			if c.Name == "redirect_listener" {
				got = c
			}
		}
		if got.Status != "fail" {
			t.Fatalf("listener %q reported %q, want fail: %s", addr, got.Status, got.Detail)
		}
		if !strings.Contains(got.Detail, "loopback") {
			t.Fatalf("the failure for %q does not say why: %s", addr, got.Detail)
		}
	}
}

// The backend refuses process filters rather than silently matching nothing.
// Doctor has to reach the same verdict, or it certifies a configuration that
// will not start.
func TestDoctorRefusesProcessFiltersOnRedirect(t *testing.T) {
	var got doctorCheck
	for _, c := range doctorRedirect("127.0.0.1:1080", tunless.Filter{IncludeProcesses: []string{"curl"}}) {
		if c.Name == "redirect_filters" {
			got = c
		}
	}
	if got.Status != "fail" {
		t.Fatalf("a process filter on the redirect backend reported %q, want fail", got.Status)
	}
}

// The platform dispatcher has to route the redirect backend to these checks
// rather than to the privilege-free answer.
func TestDoctorPlatformRoutesRedirect(t *testing.T) {
	checks := doctorPlatform(t.Context(), "redirect", "127.0.0.1:1080", "", "", tunless.Filter{})
	for _, c := range checks {
		if c.Name == "capture_backend" && strings.Contains(c.Detail, "privilege-free") {
			t.Fatal("the redirect backend is still reported as privilege-free")
		}
	}
	if len(checks) < 4 {
		t.Fatalf("doctorPlatform returned %d checks for the redirect backend: %v", len(checks), checks)
	}
}
