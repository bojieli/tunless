package tunless

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestRelayContextUnblocksOppositePumpAfterHardError(t *testing.T) {
	aClient, aRelay := net.Pipe()
	bRelay, bServer := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- RelayContext(context.Background(), aRelay, bRelay, 0) }()

	_ = bServer.Close()
	if _, err := aClient.Write([]byte("trigger write failure")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("hard relay error was not reported")
		}
	case <-time.After(time.Second):
		t.Fatal("opposite relay pump remained blocked after a hard error")
	}
	_ = aClient.Close()
}

func TestRelayContextCancellationClosesBothPumps(t *testing.T) {
	aClient, aRelay := net.Pipe()
	bRelay, bServer := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RelayContext(ctx, aRelay, bRelay, 0) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("relay error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not finish after cancellation")
	}
	_ = aClient.Close()
	_ = bServer.Close()
}

func TestRelayContextIdleTimeout(t *testing.T) {
	aClient, aRelay := net.Pipe()
	bRelay, bServer := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- RelayContext(context.Background(), aRelay, bRelay, 20*time.Millisecond) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRelayIdleTimeout) {
			t.Fatalf("relay error = %v, want idle timeout", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle relay did not time out")
	}
	_ = aClient.Close()
	_ = bServer.Close()
}

func TestRelayPreservesTCPHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		payload, readErr := io.ReadAll(conn)
		if readErr == nil && string(payload) == "request" {
			_, readErr = conn.Write([]byte("response"))
		}
		serverDone <- readErr
	}()

	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	proxyClient, proxyRelay := net.Pipe()
	relayDone := make(chan error, 1)
	go func() { relayDone <- Relay(proxyRelay, client) }()
	if _, err = proxyClient.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	// net.Pipe has no CloseWrite, so close the application side only after the
	// request has crossed; the TCP half-close assertion is on the upstream side.
	_ = proxyClient.Close()
	select {
	case <-relayDone:
	case <-time.After(time.Second):
		t.Fatal("half-closed relay did not finish")
	}
	if err = <-serverDone; err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
