package tunless

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
)

var ErrBackendStopped = errors.New("backend flow stream stopped unexpectedly")

type Emitter interface {
	Emit(context.Context, Flow) error
}

type Core struct {
	Backend       Backend
	Emitter       Emitter
	Filter        Filter
	Logger        *slog.Logger
	Resolver      NameResolver
	Stats         *Stats
	MaxConcurrent int
}

type NameResolver interface{ Lookup(netip.Addr) string }

func (c *Core) Run(ctx context.Context) (runErr error) {
	if c.Backend == nil || c.Emitter == nil {
		return errors.New("backend and emitter are required")
	}
	maxConcurrent := c.MaxConcurrent
	if maxConcurrent == 0 {
		maxConcurrent = 4096
	}
	if maxConcurrent < 0 {
		return errors.New("maximum concurrent flows cannot be negative")
	}
	if err := c.Filter.Validate(); err != nil {
		return err
	}
	stats := c.Stats
	if stats == nil {
		stats = &Stats{}
	}
	stats.start()
	slots := make(chan struct{}, maxConcurrent)
	logger := c.Logger
	if logger == nil {
		logger = slog.Default()
	}
	flows, err := c.Backend.Start(ctx)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	defer func() {
		// Closing the backend first releases any flow-owned sockets on which an
		// emitter may still be blocked. Waiting first deadlocks when a backend
		// closes its flow channel because of an internal shutdown.
		closeErr := c.Backend.Close()
		wg.Wait()
		if closeErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close backend: %w", closeErr))
		}
	}()
	if flows == nil {
		return errors.New("backend returned a nil flow stream")
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case flow, ok := <-flows:
			if !ok {
				if ctx.Err() != nil {
					return nil
				}
				return ErrBackendStopped
			}
			if err := flow.Validate(); err != nil {
				stats.invalid.Add(1)
				logger.Error("invalid flow", "error", err)
				closeFlow(flow)
				continue
			}
			if flow.Hostname == "" && c.Resolver != nil {
				flow.Hostname = c.Resolver.Lookup(flow.OrigDst.Addr())
			}
			if !c.Filter.Capture(flow) {
				stats.excluded.Add(1)
				logger.Debug("flow excluded", "proto", flow.Proto, "destination", flow.OrigDst)
				closeFlow(flow)
				continue
			}
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				closeFlow(flow)
				return nil
			default:
				overloaded := stats.overloaded.Add(1)
				// Log the first rejection and powers of two so a local connection
				// flood cannot turn the safety limit into an unbounded log flood.
				if overloaded == 1 || overloaded&(overloaded-1) == 0 {
					logger.Warn("flow rejected at concurrency limit", "proto", flow.Proto, "destination", flow.OrigDst, "limit", maxConcurrent, "total", overloaded)
				}
				closeFlow(flow)
				continue
			}
			stats.accepted.Add(1)
			if flow.Proto == TCP {
				stats.activeTCP.Add(1)
			} else {
				stats.activeUDP.Add(1)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					<-slots
					stats.completed.Add(1)
					if flow.Proto == TCP {
						stats.activeTCP.Add(-1)
					} else {
						stats.activeUDP.Add(-1)
					}
				}()
				defer closeFlow(flow)
				logger.Info("flow started", "proto", flow.Proto, "destination", flow.OrigDst, "hostname", flow.Hostname, "pid", flow.Process.PID)
				if flow.DatapathOwned {
					return
				}
				if err := c.Emitter.Emit(ctx, flow); err != nil && ctx.Err() == nil {
					stats.errors.Add(1)
					logger.Warn("flow ended with error", "proto", flow.Proto, "destination", flow.OrigDst, "error", err)
				}
			}()
		}
	}
}

func closeFlow(f Flow) {
	if f.Conn != nil {
		_ = f.Conn.Close()
	}
	if f.Packets != nil {
		_ = f.Packets.Close()
	}
}
