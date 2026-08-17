package metadata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	stateMu  sync.Mutex
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
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect metadata socket: %w", err)
	}
	listener, err := net.Listen("unix", s.Path)
	if err != nil {
		return err
	}
	_ = os.Chmod(s.Path, 0600)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/flow", s.handle)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: time.Second,
		WriteTimeout:      2 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	s.stateMu.Lock()
	s.listener = listener
	s.http = server
	s.stateMu.Unlock()
	go func() { <-ctx.Done(); _ = s.Close() }()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	value, err := strconv.ParseUint(r.URL.Query().Get("source_port"), 10, 16)
	if err != nil {
		http.Error(w, "invalid source_port", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	item, ok := s.entries[uint16(value)]
	s.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if time.Now().After(item.Expires) {
		s.mu.Lock()
		if current, exists := s.entries[uint16(value)]; exists && time.Now().After(current.Expires) {
			delete(s.entries, uint16(value))
		}
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(item)
}
func (s *Server) Close() error {
	s.stateMu.Lock()
	server := s.http
	listener := s.listener
	s.http = nil
	s.listener = nil
	s.stateMu.Unlock()
	if server != nil {
		_ = server.Close()
	}
	if listener != nil {
		_ = listener.Close()
	}
	if s.Path != "" {
		if info, err := os.Lstat(s.Path); err == nil && info.Mode()&os.ModeSocket != 0 {
			return os.Remove(s.Path)
		}
	}
	return nil
}
