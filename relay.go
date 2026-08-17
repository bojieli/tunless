package tunless

import (
	"errors"
	"io"
	"net"
	"sync"
)

// Relay copies a stream in both directions and preserves TCP half-close.
func Relay(a, b net.Conn) error {
	type closeWriter interface{ CloseWrite() error }
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		if err != nil && !errors.Is(err, net.ErrClosed) {
			errs <- err
		}
	}
	wg.Add(2)
	go copyOne(a, b)
	go copyOne(b, a)
	wg.Wait()
	close(errs)
	return errors.Join(func() []error {
		var all []error
		for err := range errs {
			all = append(all, err)
		}
		return all
	}()...)
}
