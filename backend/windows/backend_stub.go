//go:build !windows

package windows

import (
	"context"
	"errors"
	"github.com/bojieli/tunless"
)

type Backend struct{ Address string }

func (*Backend) Start(context.Context) (<-chan tunless.Flow, error) {
	return nil, errors.New("Windows WFP backend is only available on Windows")
}
func (*Backend) Close() error { return nil }
