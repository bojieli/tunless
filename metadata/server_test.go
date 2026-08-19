package metadata

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bojieli/tunless"
)

func TestRegister(t *testing.T) {
	s := &Server{}
	cleanup := s.Register(1234, tunless.ProcessInfo{PID: 42})
	if s.entries[1234].Process.PID != 42 {
		t.Fatal("entry missing")
	}
	cleanup()
	if _, ok := s.entries[1234]; ok {
		t.Fatal("entry not removed")
	}
}

func TestServeRejectsSharedSocketDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	server := &Server{Path: filepath.Join(directory, "metadata.sock")}
	if err := server.Serve(t.Context()); err == nil {
		t.Fatal("metadata socket was created in a group/world-accessible directory")
	}
}

func TestCloseDoesNotRemoveUnownedSocket(t *testing.T) {
	directory, err := os.MkdirTemp("", "tm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "existing.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &Server{Path: path}
	if err = server.Serve(context.Background()); err == nil {
		t.Fatal("metadata API replaced an existing socket")
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(path); err != nil {
		t.Fatalf("unowned socket was removed: %v", err)
	}
}

func TestCloseDoesNotRemoveReplacementSocket(t *testing.T) {
	directory, err := os.MkdirTemp("", "tm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "metadata.sock")
	server := &Server{Path: path}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background()) }()
	for deadline := time.Now().Add(2 * time.Second); !server.Ready(); {
		select {
		case err = <-serveDone:
			t.Fatalf("metadata socket failed to start: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("metadata socket did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if err = os.Rename(path, path+".owned"); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("replacement socket was removed: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("replacement path mode = %v, want socket", info.Mode())
	}
	select {
	case err = <-serveDone:
		if err != nil {
			t.Fatalf("metadata server stopped with error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("metadata server did not stop")
	}
}

func TestCloseBeforeServePreventsStart(t *testing.T) {
	server := &Server{Path: filepath.Join(t.TempDir(), "metadata.sock")}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Serve(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Serve after Close = %v, want net.ErrClosed", err)
	}
}

func TestHandlerRejectsMutationAndPurgesExpiredEntries(t *testing.T) {
	s := &Server{entries: map[uint16]entry{1234: {Expires: time.Now().Add(-time.Second)}}}
	request := httptest.NewRequest(http.MethodPost, "/v1/flow?source_port=1234", nil)
	response := httptest.NewRecorder()
	s.handle(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/flow?source_port=1234", nil)
	response = httptest.NewRecorder()
	s.handle(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("expired lookup status = %d", response.Code)
	}
	if _, ok := s.entries[1234]; ok {
		t.Fatal("expired metadata entry was not purged")
	}
}
