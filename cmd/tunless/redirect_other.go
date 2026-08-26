//go:build !linux

package main

import "github.com/bojieli/tunless"

func newRedirectBackend(string, tunless.Filter) tunless.Backend { return nil }
