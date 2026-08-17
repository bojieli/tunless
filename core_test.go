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
