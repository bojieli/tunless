//go:build linux

package main

import (
	"github.com/bojieli/tunless"
	redirectbackend "github.com/bojieli/tunless/backend/redirect"
)

// newRedirectBackend builds the netfilter fallback.
//
// It is never chosen by "auto". The eBPF backend is fail-open by construction
// and this one is not: the rule that feeds it belongs to the operator and
// outlives this process, so killing the agent makes new connections fail
// rather than go direct. That is a deliberate trade and has to be asked for.
func newRedirectBackend(listen string, filter tunless.Filter) tunless.Backend {
	return &redirectbackend.Backend{Address: listen, Filter: filter}
}
