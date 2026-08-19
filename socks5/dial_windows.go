//go:build windows

package socks5

import (
	"context"
	"errors"
	"net"
	"syscall"
	"unsafe"

	win "golang.org/x/sys/windows"
)

const sioSetRedirectRecords = uint32(0x980000de)

var wsaIoctl = win.NewLazySystemDLL("ws2_32.dll").NewProc("WSAIoctl")

func dialContext(ctx context.Context, dialer net.Dialer, network, address string, records []byte) (net.Conn, error) {
	if len(records) == 0 {
		return dialer.DialContext(ctx, network, address)
	}
	previousControl := dialer.Control
	dialer.Control = func(controlNetwork, controlAddress string, raw syscall.RawConn) error {
		if previousControl != nil {
			if err := previousControl(controlNetwork, controlAddress, raw); err != nil {
				return err
			}
		}
		var ioctlErr error
		if err := raw.Control(func(fd uintptr) {
			var returned uint32
			result, _, callErr := wsaIoctl.Call(
				fd,
				uintptr(sioSetRedirectRecords),
				uintptr(unsafe.Pointer(&records[0])),
				uintptr(len(records)),
				0,
				0,
				uintptr(unsafe.Pointer(&returned)),
				0,
				0,
			)
			if result != 0 {
				if errors.Is(callErr, syscall.Errno(0)) {
					ioctlErr = errors.New("WFP redirect-record install failed without a Windows error code")
				} else {
					ioctlErr = callErr
				}
			}
		}); err != nil {
			return err
		}
		return ioctlErr
	}
	return dialer.DialContext(ctx, network, address)
}
