package metadata

import (
	"github.com/bojieli/tunless"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
