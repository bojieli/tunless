package tunless

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

var ErrRelayIdleTimeout = errors.New("relay idle timeout")

// Relay copies a stream in both directions and preserves TCP half-close.
func Relay(a, b net.Conn) error {
	return RelayContext(context.Background(), a, b, 0)
}

// RelayContext copies a stream in both directions, preserves clean TCP
// half-closes, and tears down both directions after a hard error, cancellation,
// or an optional period with no bytes transferred. Closing both connections on
// a hard error is important: otherwise the opposite copy can remain blocked
// forever and the flow never reaches its completion path.
func RelayContext(ctx context.Context, a, b net.Conn, idleTimeout time.Duration) error {
	type closeWriter interface{ CloseWrite() error }
	type result struct {
		dst net.Conn
		err error
	}
	results := make(chan result, 2)
	activity := make(chan struct{}, 1)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	stopCancellation := context.AfterFunc(ctx, closeBoth)
	defer stopCancellation()

	copyOne := func(dst, src net.Conn) {
		buffer := make([]byte, 32<<10)
		for {
			n, readErr := src.Read(buffer)
			if n > 0 {
				written := 0
				for written < n {
					m, writeErr := dst.Write(buffer[written:n])
					written += m
					if writeErr != nil {
						results <- result{dst: dst, err: writeErr}
						return
					}
					if m == 0 {
						results <- result{dst: dst, err: io.ErrNoProgress}
						return
					}
				}
				select {
				case activity <- struct{}{}:
				default:
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					readErr = nil
				}
				results <- result{dst: dst, err: readErr}
				return
			}
		}
	}
	go copyOne(a, b)
	go copyOne(b, a)

	var timer *time.Timer
	var timeout <-chan time.Time
	if idleTimeout > 0 {
		timer = time.NewTimer(idleTimeout)
		timeout = timer.C
		defer timer.Stop()
	}
	ctxDone := ctx.Done()
	remaining := 2
	var all []error
	for remaining > 0 {
		select {
		case item := <-results:
			remaining--
			if item.err == nil {
				if writer, ok := item.dst.(closeWriter); ok {
					_ = writer.CloseWrite()
				}
				continue
			}
			if !errors.Is(item.err, net.ErrClosed) {
				all = append(all, item.err)
			}
			closeBoth()
		case <-activity:
			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(idleTimeout)
			}
		case <-ctxDone:
			ctxDone = nil
			closeBoth()
		case <-timeout:
			timeout = nil
			all = append(all, ErrRelayIdleTimeout)
			closeBoth()
		}
	}
	if ctx.Err() != nil {
		all = append(all, ctx.Err())
	}
	return errors.Join(all...)
}
