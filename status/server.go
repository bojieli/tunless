package status

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/bojieli/tunless"
)

type Server struct {
	Address       string
	Version       string
	BackendName   string
	Upstream      string
	MaxConcurrent int
	Stats         *tunless.Stats
	Backend       tunless.Backend

	mu       sync.Mutex
	listener net.Listener
	http     *http.Server

	captureMu sync.Mutex
	captureAt time.Time
	capture   tunless.BackendDiagnostics
}

type response struct {
	Status        string                     `json:"status"`
	Version       string                     `json:"version"`
	Backend       string                     `json:"backend"`
	Upstream      string                     `json:"upstream"`
	MaxConcurrent int                        `json:"max_concurrent_flows"`
	Flows         tunless.StatsSnapshot      `json:"flows"`
	Capture       tunless.BackendDiagnostics `json:"capture"`
}

func (s *Server) Serve(ctx context.Context) error {
	address, err := ValidateAddress(s.Address)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/v1/status", s.status)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	s.mu.Lock()
	s.listener = listener
	s.http = server
	s.mu.Unlock()
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

func (s *Server) Close() error {
	s.mu.Lock()
	server := s.http
	listener := s.listener
	s.http = nil
	s.listener = nil
	s.mu.Unlock()
	if server != nil {
		return server.Close()
	}
	if listener != nil {
		return listener.Close()
	}
	return nil
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	capture := s.captureDiagnostics()
	var flows tunless.StatsSnapshot
	if s.Stats != nil {
		flows = s.Stats.Snapshot()
	}
	writeJSON(w, response{
		Status:        "ok",
		Version:       s.Version,
		Backend:       s.BackendName,
		Upstream:      s.Upstream,
		MaxConcurrent: s.MaxConcurrent,
		Flows:         flows,
		Capture:       capture,
	})
}

func (s *Server) captureDiagnostics() tunless.BackendDiagnostics {
	s.captureMu.Lock()
	defer s.captureMu.Unlock()
	if !s.captureAt.IsZero() && time.Since(s.captureAt) < time.Second {
		return s.capture
	}
	if provider, ok := s.Backend.(tunless.DiagnosticsProvider); ok {
		s.capture = provider.Diagnostics()
	} else {
		s.capture = tunless.BackendDiagnostics{Name: s.BackendName}
	}
	s.captureAt = time.Now()
	return s.capture
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func ValidateAddress(value string) (string, error) {
	if value == "" {
		return "", errors.New("status listen address is empty")
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return "", errors.New("status listen address must be loopback host:port")
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() {
		return "", errors.New("status API may listen only on a numeric loopback address")
	}
	return value, nil
}
