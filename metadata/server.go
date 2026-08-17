package metadata

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/bojieli/tunless"
)

type entry struct {
	Process tunless.ProcessInfo `json:"process"`
	Expires time.Time           `json:"expires"`
}
type Server struct {
	Path     string
	mu       sync.RWMutex
	entries  map[uint16]entry
	listener net.Listener
	http     *http.Server
}

func (s *Server) Register(port uint16, process tunless.ProcessInfo) func() {
	s.mu.Lock()
	if s.entries == nil {
		s.entries = make(map[uint16]entry)
	}
	s.entries[port] = entry{Process: process, Expires: time.Now().Add(10 * time.Minute)}
	s.mu.Unlock()
	return func() { s.mu.Lock(); delete(s.entries, port); s.mu.Unlock() }
}
func (s *Server) Serve(ctx context.Context) error {
	if s.Path == "" {
		return errors.New("metadata socket path is empty")
	}
	if _, err := os.Lstat(s.Path); err == nil {
		return errors.New("metadata socket already exists")
	}
	listener, err := net.Listen("unix", s.Path)
	if err != nil {
		return err
	}
	s.listener = listener
	_ = os.Chmod(s.Path, 0600)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/flow", s.handle)
	s.http = &http.Server{Handler: mux, ReadHeaderTimeout: time.Second}
	go func() { <-ctx.Done(); _ = s.Close() }()
	err = s.http.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	value, err := strconv.ParseUint(r.URL.Query().Get("source_port"), 10, 16)
	if err != nil {
		http.Error(w, "invalid source_port", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	item, ok := s.entries[uint16(value)]
	s.mu.RUnlock()
	if !ok || time.Now().After(item.Expires) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(item)
}
func (s *Server) Close() error {
	if s.http != nil {
		_ = s.http.Close()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.Path != "" {
		if info, err := os.Lstat(s.Path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return os.Remove(s.Path)
		}
	}
	return nil
}
