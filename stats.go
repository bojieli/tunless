package tunless

import (
	"sync"
	"sync/atomic"
	"time"
)

// Stats contains lock-free runtime counters suitable for health endpoints.
// It intentionally contains no destination or process identifiers.
type Stats struct {
	startedOnce sync.Once
	started     time.Time
	accepted    atomic.Uint64
	completed   atomic.Uint64
	errors      atomic.Uint64
	invalid     atomic.Uint64
	excluded    atomic.Uint64
	overloaded  atomic.Uint64
	activeTCP   atomic.Int64
	activeUDP   atomic.Int64
}

type StatsSnapshot struct {
	StartedAt       time.Time `json:"started_at"`
	UptimeSeconds   float64   `json:"uptime_seconds"`
	AcceptedFlows   uint64    `json:"accepted_flows"`
	CompletedFlows  uint64    `json:"completed_flows"`
	EmitterErrors   uint64    `json:"emitter_errors"`
	InvalidFlows    uint64    `json:"invalid_flows"`
	ExcludedFlows   uint64    `json:"excluded_flows"`
	OverloadedFlows uint64    `json:"overloaded_flows"`
	ActiveTCP       int64     `json:"active_tcp"`
	ActiveUDP       int64     `json:"active_udp"`
}

func (s *Stats) start() {
	s.startedOnce.Do(func() { s.started = time.Now().UTC() })
}

func (s *Stats) Snapshot() StatsSnapshot {
	s.start()
	return StatsSnapshot{
		StartedAt:       s.started,
		UptimeSeconds:   time.Since(s.started).Seconds(),
		AcceptedFlows:   s.accepted.Load(),
		CompletedFlows:  s.completed.Load(),
		EmitterErrors:   s.errors.Load(),
		InvalidFlows:    s.invalid.Load(),
		ExcludedFlows:   s.excluded.Load(),
		OverloadedFlows: s.overloaded.Load(),
		ActiveTCP:       s.activeTCP.Load(),
		ActiveUDP:       s.activeUDP.Load(),
	}
}
