package metadata

import (
	"github.com/bojieli/tunless"
	"testing"
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
