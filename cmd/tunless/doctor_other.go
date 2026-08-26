//go:build !linux

package main

import (
	"context"

	"github.com/bojieli/tunless"
)

func doctorPlatform(_ context.Context, backendName, _, _, _ string, _ tunless.Filter) []doctorCheck {
	return []doctorCheck{{Name: "capture_backend", Status: "pass", Detail: backendName + " configuration parsed on this platform"}}
}
