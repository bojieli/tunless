package status

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/bojieli/tunless"
	"github.com/bojieli/tunless/socks5"
	"golang.org/x/net/netutil"
)

const maxStatusConnections = 128

type Server struct {
	Address     string
	Version     string
	BackendName string
	Upstream    string
	DNSUpstream string
	DNSOverride bool
	// DNSDirect, DNSNameSuffixes and DNSCredibleRanges describe the DNS policy
	// as configured, so that a list which loaded empty or a prefix file that
	// collapsed to nothing is visible without reading the startup log.
	DNSDirect         string
	DNSNameSuffixes   int
	DNSCredibleRanges int
	// DNSCounters reports what the policy actually decided. Nil omits the
	// section, which is what a caller that has no DNS datapath to report should
	// do; a caller that has one reports it even when every counter is zero,
	// because an inert policy is a thing an operator has to be able to see.
	DNSCounters   func() socks5.DNSStatsSnapshot
	MaxConcurrent int
	Stats         *tunless.Stats
	Backend       tunless.Backend

	mu       sync.Mutex
	listener net.Listener
	http     *http.Server
	closed   bool
	serving  bool

	captureMu sync.Mutex
	captureAt time.Time
	capture   tunless.BackendDiagnostics
}

type response struct {
	Status        string                     `json:"status"`
	Version       string                     `json:"version"`
	Backend       string                     `json:"backend"`
	Upstream      string                     `json:"upstream"`
	DNSUpstream   string                     `json:"dns_upstream"`
	DNSOverride   bool                       `json:"dns_override"`
	DNSPolicy     *dnsPolicyResponse         `json:"dns_policy,omitempty"`
	MaxConcurrent int                        `json:"max_concurrent_flows"`
	Flows         tunless.StatsSnapshot      `json:"flows"`
	Capture       tunless.BackendDiagnostics `json:"capture"`
}

func (s *Server) Serve(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if s.serving || s.listener != nil || s.http != nil {
		s.mu.Unlock()
		return errors.New("status API already serving")
	}
	s.serving = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.serving = false
		s.mu.Unlock()
	}()
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
	if s.closed {
		s.mu.Unlock()
		_ = listener.Close()
		return net.ErrClosed
	}
	s.listener = listener
	s.http = server
	s.mu.Unlock()
	defer s.Close()
	serveDone := make(chan struct{})
	defer close(serveDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-serveDone:
		}
	}()
	err = server.Serve(netutil.LimitListener(listener, maxStatusConnections))
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && s.listener != nil
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
	s.closed = true
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

// dnsPolicyResponse is the configured policy and what it has decided.
type dnsPolicyResponse struct {
	Direct         string                  `json:"direct_resolver,omitempty"`
	NameSuffixes   int                     `json:"name_suffixes"`
	CredibleRanges int                     `json:"credible_ranges"`
	Decisions      socks5.DNSStatsSnapshot `json:"decisions"`
}

func (s *Server) dnsPolicy() *dnsPolicyResponse {
	if s.DNSCounters == nil {
		return nil
	}
	return &dnsPolicyResponse{
		Direct:         s.DNSDirect,
		NameSuffixes:   s.DNSNameSuffixes,
		CredibleRanges: s.DNSCredibleRanges,
		Decisions:      s.DNSCounters(),
	}
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
		DNSUpstream:   s.DNSUpstream,
		DNSOverride:   s.DNSOverride,
		DNSPolicy:     s.dnsPolicy(),
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
	if _, err = strconv.ParseUint(port, 10, 16); err != nil {
		return "", errors.New("status API listen port must be between 0 and 65535")
	}
	return value, nil
}
