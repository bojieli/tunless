package tunless

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
)

type Emitter interface {
	Emit(context.Context, Flow) error
}

type Core struct {
	Backend  Backend
	Emitter  Emitter
	Filter   Filter
	Logger   *slog.Logger
	Resolver NameResolver
}

type NameResolver interface{ Lookup(netip.Addr) string }

func (c *Core) Run(ctx context.Context) error {
	if c.Backend == nil || c.Emitter == nil {
		return errors.New("backend and emitter are required")
	}
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
		_ = c.Backend.Close()
		wg.Wait()
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case flow, ok := <-flows:
			if !ok {
				return nil
			}
			if flow.Hostname == "" && c.Resolver != nil {
				flow.Hostname = c.Resolver.Lookup(flow.OrigDst.Addr())
			}
			if err := flow.Validate(); err != nil {
				logger.Error("invalid flow", "error", err)
				closeFlow(flow)
				continue
			}
			if !c.Filter.Capture(flow) {
				logger.Debug("flow excluded", "proto", flow.Proto, "destination", flow.OrigDst)
				closeFlow(flow)
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer closeFlow(flow)
				logger.Info("flow started", "proto", flow.Proto, "destination", flow.OrigDst, "hostname", flow.Hostname, "pid", flow.Process.PID)
				if flow.DatapathOwned {
					return
				}
				if err := c.Emitter.Emit(ctx, flow); err != nil && ctx.Err() == nil {
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
