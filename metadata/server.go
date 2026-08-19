package metadata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/bojieli/tunless"
	"golang.org/x/net/netutil"
)

const maxMetadataConnections = 64

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
	owned    os.FileInfo
	closed   bool
	serving  bool
}

func (s *Server) Ready() bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	return !s.closed && s.listener != nil
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
	s.stateMu.Lock()
	if s.closed {
		s.stateMu.Unlock()
		return net.ErrClosed
	}
	if s.serving || s.listener != nil || s.http != nil {
		s.stateMu.Unlock()
		return errors.New("metadata API already serving")
	}
	s.serving = true
	s.stateMu.Unlock()
	defer func() {
		s.stateMu.Lock()
		s.serving = false
		s.stateMu.Unlock()
	}()
	if s.Path == "" {
		return errors.New("metadata socket path is empty")
	}
	if runtime.GOOS == "windows" {
		return errors.New("metadata Unix socket is unavailable on Windows; use SOCKS metadata usernames")
	}
	parent := filepath.Dir(s.Path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect metadata socket directory: %w", err)
	}
	if !parentInfo.IsDir() {
		return errors.New("metadata socket parent is not a directory")
	}
	if !ownedByEffectiveUser(parentInfo) {
		return errors.New("metadata socket directory must be owned by the service user")
	}
	if parentInfo.Mode().Perm()&0077 != 0 {
		return errors.New("metadata socket directory must not grant group or world access")
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
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return errors.New("metadata listener is not a Unix socket")
	}
	// net.UnixListener otherwise unlinks its address by pathname on Close. A
	// different file could have replaced that path by then, so cleanup below
	// instead compares the socket node created here before removing it.
	unixListener.SetUnlinkOnClose(false)
	socketInfo, err := os.Lstat(s.Path)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 {
		_ = listener.Close()
		_ = removeOwnedSocket(s.Path, socketInfo)
		if err == nil {
			err = errors.New("metadata listener did not create a Unix socket node")
		}
		return fmt.Errorf("inspect created metadata socket: %w", err)
	}
	if err = os.Chmod(s.Path, 0600); err != nil {
		_ = listener.Close()
		_ = removeOwnedSocket(s.Path, socketInfo)
		return fmt.Errorf("secure metadata socket permissions: %w", err)
	}
	pathInfo, err := os.Lstat(s.Path)
	if err != nil || pathInfo.Mode()&os.ModeSocket == 0 || !os.SameFile(socketInfo, pathInfo) || pathInfo.Mode().Perm() != 0600 {
		_ = listener.Close()
		_ = removeOwnedSocket(s.Path, socketInfo)
		if err == nil {
			err = errors.New("metadata socket path or permissions changed during creation")
		}
		return fmt.Errorf("inspect created metadata socket: %w", err)
	}
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
	if s.closed {
		s.stateMu.Unlock()
		_ = listener.Close()
		_ = removeOwnedSocket(s.Path, socketInfo)
		return net.ErrClosed
	}
	s.listener = listener
	s.http = server
	s.owned = socketInfo
	s.stateMu.Unlock()
	// Serve owns the filesystem entry. Ensure an unexpected HTTP-server error
	// cannot leave a stale socket that blocks a safe restart.
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
	err = server.Serve(netutil.LimitListener(listener, maxMetadataConnections))
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
	s.closed = true
	server := s.http
	listener := s.listener
	owned := s.owned
	s.http = nil
	s.listener = nil
	s.owned = nil
	s.stateMu.Unlock()
	if server != nil {
		_ = server.Close()
	}
	if listener != nil {
		_ = listener.Close()
	}
	return removeOwnedSocket(s.Path, owned)
}

func removeOwnedSocket(path string, owned os.FileInfo) error {
	if path == "" || owned == nil {
		return nil
	}
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Mode()&os.ModeSocket == 0 || !os.SameFile(owned, current) {
		return nil
	}
	return os.Remove(path)
}
