package tunless

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type closeFirstBackend struct {
	closed chan struct{}
	once   sync.Once
}

func (b *closeFirstBackend) Start(context.Context) (<-chan Flow, error) {
	flows := make(chan Flow, 1)
	client, server := net.Pipe()
	_ = server.Close()
	flows <- Flow{Proto: TCP, OrigDst: netip.MustParseAddrPort("192.0.2.1:443"), Conn: client}
	close(flows)
	return flows, nil
}

func (b *closeFirstBackend) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

type waitForBackendClose struct{ closed <-chan struct{} }

func (e waitForBackendClose) Emit(context.Context, Flow) error {
	<-e.closed
	return nil
}

type flowListBackend struct {
	flows  chan Flow
	closed chan struct{}
}

func (b *flowListBackend) Start(context.Context) (<-chan Flow, error) { return b.flows, nil }
func (b *flowListBackend) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

type blockingEmitter struct {
	started chan struct{}
	release <-chan struct{}
}

func (e blockingEmitter) Emit(context.Context, Flow) error {
	select {
	case e.started <- struct{}{}:
	default:
	}
	<-e.release
	return nil
}

func TestCoreClosesBackendBeforeWaitingForEmitters(t *testing.T) {
	backend := &closeFirstBackend{closed: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- (&Core{Backend: backend, Emitter: waitForBackendClose{closed: backend.closed}}).Run(context.Background())
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Core.Run waited for an emitter before closing its backend")
	}
}

func TestCoreRejectsFlowsBeyondConcurrencyLimit(t *testing.T) {
	firstClient, firstCore := net.Pipe()
	secondClient, secondCore := net.Pipe()
	flows := make(chan Flow, 2)
	flows <- Flow{Proto: TCP, OrigDst: netip.MustParseAddrPort("192.0.2.1:443"), Conn: firstCore}
	flows <- Flow{Proto: TCP, OrigDst: netip.MustParseAddrPort("192.0.2.2:443"), Conn: secondCore}
	close(flows)
	backend := &flowListBackend{flows: flows, closed: make(chan struct{})}
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	stats := &Stats{}
	done := make(chan error, 1)
	go func() {
		done <- (&Core{
			Backend:       backend,
			Emitter:       blockingEmitter{started: started, release: release},
			Stats:         stats,
			MaxConcurrent: 1,
		}).Run(context.Background())
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first flow did not start")
	}
	_ = secondClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := secondClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("overloaded flow was not closed")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = firstClient.Close()
	_ = secondClient.Close()
	snapshot := stats.Snapshot()
	if snapshot.AcceptedFlows != 1 || snapshot.OverloadedFlows != 1 || snapshot.CompletedFlows != 1 {
		t.Fatalf("unexpected stats: %+v", snapshot)
	}
}
