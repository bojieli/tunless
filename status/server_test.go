package status

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bojieli/tunless"
)

func TestRejectsNonLoopbackListener(t *testing.T) {
	for _, address := range []string{"", ":6060", "0.0.0.0:6060", "localhost:6060", "192.0.2.1:6060"} {
		if _, err := ValidateAddress(address); err == nil {
			t.Fatalf("accepted status address %q", address)
		}
	}
}

type countingDiagnostics struct{ calls atomic.Int32 }

func (d *countingDiagnostics) Start(context.Context) (<-chan tunless.Flow, error) {
	return make(chan tunless.Flow), nil
}
func (d *countingDiagnostics) Close() error { return nil }
func (d *countingDiagnostics) Diagnostics() tunless.BackendDiagnostics {
	d.calls.Add(1)
	return tunless.BackendDiagnostics{Name: "counting"}
}

func TestCaptureDiagnosticsAreRateLimited(t *testing.T) {
	backend := &countingDiagnostics{}
	server := &Server{Backend: backend, BackendName: "counting"}
	for range 10 {
		if got := server.captureDiagnostics(); got.Name != "counting" {
			t.Fatalf("unexpected diagnostics: %+v", got)
		}
	}
	if calls := backend.calls.Load(); calls != 1 {
		t.Fatalf("diagnostics calls = %d, want 1", calls)
	}
}

func TestStatusEndpoints(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{Address: "127.0.0.1:0", Version: "test", BackendName: "fake", Upstream: "127.0.0.1:7890", DNSUpstream: "1.1.1.1:53", DNSOverride: true, MaxConcurrent: 7, Stats: &tunless.Stats{}}
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()
	deadline := time.Now().Add(time.Second)
	for s.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.Addr() == nil {
		t.Fatal("status server did not start")
	}
	response, err := http.Get("http://" + s.Addr().String() + "/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body map[string]any
	if err = json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["version"] != "test" || body["backend"] != "fake" {
		t.Fatalf("unexpected status: %+v", body)
	}
	if body["dns_upstream"] != "1.1.1.1:53" || body["dns_override"] != true {
		t.Fatalf("unexpected DNS status: %+v", body)
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}
