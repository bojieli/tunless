//go:build !linux

package linux

import (
	"context"
	"errors"

	"github.com/bojieli/tunless"
)

type Backend struct {
	CgroupPath, NetworkNamespace, Address string
	Filter                                tunless.Filter
}

func (*Backend) Start(context.Context) (<-chan tunless.Flow, error) {
	return nil, errors.New("linux eBPF backend is only available on Linux")
}
func (*Backend) Close() error { return nil }
