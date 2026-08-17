//go:build !windows

package socks5

import (
	"context"
	"net"
)

func dialContext(ctx context.Context, dialer net.Dialer, network, address string, _ []byte) (net.Conn, error) {
	return dialer.DialContext(ctx, network, address)
}
