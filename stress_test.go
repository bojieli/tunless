//go:build stress

package tunless_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/bojieli/tunless"
	"github.com/bojieli/tunless/backend/loopback"
)

func TestConnectionStress(t *testing.T) {
	connections := 10_000
	if value := os.Getenv("TUNLESS_STRESS_CONNECTIONS"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 1_000_000 {
			t.Fatalf("invalid TUNLESS_STRESS_CONNECTIONS %q", value)
		}
		connections = parsed
	}
	// Use separate IPv4 and IPv6 ephemeral-port pools so 10,000 logical
	// connections do not benchmark macOS's 16,384-port client range instead.
	target, closeTarget := tcpEcho(t, "tcp6", "[::1]:0")
	defer closeTarget()
	stack := startStressStack(t)

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	jobs := make(chan int)
	errs := make(chan error, 1)
	workers := 32
	if value := os.Getenv("TUNLESS_STRESS_WORKERS"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 256 {
			t.Fatalf("invalid TUNLESS_STRESS_WORKERS %q", value)
		}
		workers = parsed
	}
	if connections < workers {
		workers = connections
	}
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for sequence := range jobs {
				if err := stressExchange(stack.addr, target, sequence); err != nil {
					select {
					case errs <- err:
					default:
					}
					return
				}
			}
		}()
	}
	for sequence := range connections {
		select {
		case jobs <- sequence:
		case err := <-errs:
			close(jobs)
			wg.Wait()
			stack.close()
			t.Fatal(err)
		}
	}
	close(jobs)
	wg.Wait()
	select {
	case err := <-errs:
		stack.close()
		t.Fatal(err)
	default:
	}
	stack.close()

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if retained > 64<<20 {
		t.Fatalf("retained heap grew by %d bytes", retained)
	}
	t.Logf("connections=%d elapsed=%s rate=%.0f/s retained_heap=%d", connections, time.Since(started), float64(connections)/time.Since(started).Seconds(), retained)
}

func startStressStack(t *testing.T) *stack {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	backend := &loopback.Backend{Address: "127.0.0.1:0"}
	s := &stack{cancel: cancel, backends: []*loopback.Backend{backend}}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_ = (&tunless.Core{
			Backend: backend,
			Emitter: directEmitter{},
			Logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		}).Run(ctx)
	}()
	s.addr = waitAddr(t, backend)
	return s
}

func stressExchange(proxy, target string, sequence int) error {
	conn, err := stressDial(proxy)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	var greeting [2]byte
	if _, err = io.ReadFull(conn, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		return fmt.Errorf("SOCKS greeting %x: %w", greeting, err)
	}
	destination := netip.MustParseAddrPort(target)
	request := []byte{5, 1, 0}
	if destination.Addr().Is4() {
		request = append(request, 1)
	} else {
		request = append(request, 4)
	}
	request = append(request, destination.Addr().AsSlice()...)
	request = binary.BigEndian.AppendUint16(request, destination.Port())
	if _, err = conn.Write(request); err != nil {
		return err
	}
	var reply [10]byte
	if _, err = io.ReadFull(conn, reply[:]); err != nil || reply[1] != 0 {
		return fmt.Errorf("SOCKS CONNECT reply %x: %w", reply, err)
	}
	payload := make([]byte, 64)
	binary.BigEndian.PutUint64(payload, uint64(sequence))
	if _, err = conn.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		return err
	}
	if !equalBytes(got, payload) {
		return errors.New("echo payload mismatch")
	}
	return nil
}

func stressDial(address string) (net.Conn, error) {
	var err error
	for attempt := range 100 {
		var conn net.Conn
		conn, err = net.DialTimeout("tcp", address, 5*time.Second)
		if err == nil {
			return conn, nil
		}
		if !errors.Is(err, syscall.EADDRNOTAVAIL) && !errors.Is(err, syscall.EADDRINUSE) {
			return nil, err
		}
		time.Sleep(time.Duration(attempt+1) * time.Millisecond)
	}
	return nil, err
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
