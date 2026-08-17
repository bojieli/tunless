//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"github.com/bojieli/tunless"
	win "golang.org/x/sys/windows"
)

const (
	sioQueryRedirectRecords = uint32(0x980000dc)
	sioQueryRedirectContext = uint32(0x980000dd)
	ioctlConfigure          = uint32(0x0012e004)
	ioctlStart              = uint32(0x0012e008)
)

var wsaIoctl = win.NewLazySystemDLL("ws2_32.dll").NewProc("WSAIoctl")

type Backend struct {
	Address   string
	mu        sync.Mutex
	listeners []net.Listener
	device    win.Handle
	cancel    context.CancelFunc
	flows     chan tunless.Flow
	wg        sync.WaitGroup
}
type driverConfig struct {
	PID      uint64
	Port     uint16
	Reserved [6]byte
}

func (b *Backend) Start(ctx context.Context) (<-chan tunless.Flow, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		return nil, errors.New("Windows backend already started")
	}
	address := b.Address
	if address == "" {
		address = "127.0.0.1:15080"
	}
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	parsed, err := netip.ParseAddrPort(net.JoinHostPort("127.0.0.1", portText))
	if err != nil {
		return nil, err
	}
	requestedPort := parsed.Port()
	v4, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(requestedPort)))
	if err != nil {
		return nil, err
	}
	port := v4.Addr().(*net.TCPAddr).AddrPort().Port()
	v6, err := net.Listen("tcp6", net.JoinHostPort("::1", fmt.Sprint(port)))
	if err != nil {
		v4.Close()
		return nil, err
	}
	device, err := win.CreateFile(win.StringToUTF16Ptr(`\\.\Tunless`), win.GENERIC_READ|win.GENERIC_WRITE, 0, nil, win.OPEN_EXISTING, win.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		v4.Close()
		v6.Close()
		return nil, fmt.Errorf("open WFP driver: %w", err)
	}
	config := driverConfig{PID: uint64(os.Getpid()), Port: port}
	var returned uint32
	if err = win.DeviceIoControl(device, ioctlConfigure, (*byte)(unsafe.Pointer(&config)), uint32(unsafe.Sizeof(config)), nil, 0, &returned, nil); err == nil {
		err = win.DeviceIoControl(device, ioctlStart, nil, 0, nil, 0, &returned, nil)
	}
	if err != nil {
		win.CloseHandle(device)
		v4.Close()
		v6.Close()
		return nil, fmt.Errorf("configure WFP driver: %w", err)
	}
	ctx, b.cancel = context.WithCancel(ctx)
	b.listeners = []net.Listener{v4, v6}
	b.device = device
	b.flows = make(chan tunless.Flow)
	for _, ln := range b.listeners {
		b.wg.Add(1)
		go b.accept(ctx, ln)
	}
	return b.flows, nil
}

func (b *Backend) accept(ctx context.Context, ln net.Listener) {
	defer b.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		flow, err := redirectedFlow(conn)
		if err != nil {
			conn.Close()
			continue
		}
		select {
		case b.flows <- flow:
		case <-ctx.Done():
			conn.Close()
			return
		}
	}
}

func redirectedFlow(conn net.Conn) (tunless.Flow, error) {
	tcp := conn.(*net.TCPConn)
	raw, err := tcp.SyscallConn()
	if err != nil {
		return tunless.Flow{}, err
	}
	var context, redirectRecords []byte
	var queryErr error
	err = raw.Control(func(fd uintptr) {
		redirectRecords, queryErr = queryWSAIoctl(fd, sioQueryRedirectRecords, 1024)
		if queryErr == nil {
			context, queryErr = queryWSAIoctl(fd, sioQueryRedirectContext, 128+8+520)
		}
	})
	if err != nil {
		return tunless.Flow{}, err
	}
	if queryErr != nil {
		return tunless.Flow{}, queryErr
	}
	size := len(context)
	if size < 128 {
		return tunless.Flow{}, errors.New("WFP redirect context is truncated")
	}
	family := binary.LittleEndian.Uint16(context[:2])
	var addr netip.Addr
	var port uint16
	switch family {
	case syscall.AF_INET:
		addr, _ = netip.AddrFromSlice(context[4:8])
		port = binary.BigEndian.Uint16(context[2:4])
	case syscall.AF_INET6:
		addr, _ = netip.AddrFromSlice(context[8:24])
		port = binary.BigEndian.Uint16(context[2:4])
	default:
		return tunless.Flow{}, fmt.Errorf("WFP address family %d", family)
	}
	process := tunless.ProcessInfo{}
	if size >= 136 {
		process.PID = int32(binary.LittleEndian.Uint64(context[128:136]))
		words := make([]uint16, 0, 260)
		for offset := 136; offset+1 < size && offset < 656; offset += 2 {
			v := binary.LittleEndian.Uint16(context[offset:])
			if v == 0 {
				break
			}
			words = append(words, v)
		}
		process.SigningID = string(utf16.Decode(words))
	}
	return tunless.Flow{
		Proto:           tunless.TCP,
		OrigDst:         netip.AddrPortFrom(addr, port),
		Process:         process,
		Conn:            conn,
		RedirectRecords: redirectRecords,
	}, nil
}

func queryWSAIoctl(fd uintptr, code uint32, initialSize int) ([]byte, error) {
	buffer := make([]byte, initialSize)
	for attempts := 0; attempts < 2; attempts++ {
		var returned uint32
		result, _, callErr := wsaIoctl.Call(
			fd,
			uintptr(code),
			0,
			0,
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			uintptr(unsafe.Pointer(&returned)),
			0,
			0,
		)
		if result == 0 {
			return append([]byte(nil), buffer[:returned]...), nil
		}
		if returned > uint32(len(buffer)) && returned <= 1<<20 {
			buffer = make([]byte, returned)
			continue
		}
		return nil, callErr
	}
	return nil, errors.New("WFP redirect record exceeds one MiB")
}

func (b *Backend) Close() error {
	b.mu.Lock()
	if b.cancel != nil {
		b.cancel()
	}
	for _, ln := range b.listeners {
		_ = ln.Close()
	}
	b.listeners = nil
	if b.device != 0 {
		_ = win.CloseHandle(b.device)
		b.device = 0
	}
	b.mu.Unlock()
	b.wg.Wait()
	return nil
}
