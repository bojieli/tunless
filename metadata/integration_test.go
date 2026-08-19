package metadata_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/bojieli/tunless"
	"github.com/bojieli/tunless/metadata"
	"github.com/bojieli/tunless/socks5"
)

func TestSOCKSRegistryEndToEnd(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("metadata Unix sockets require POSIX filesystem permissions")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	directory, err := os.MkdirTemp("", "tm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	path := filepath.Join(directory, "metadata.sock")
	registry := &metadata.Server{Path: path}
	serveDone := make(chan error, 1)
	go func() { serveDone <- registry.Serve(ctx) }()
	for deadline := time.Now().Add(2 * time.Second); ; {
		if registry.Ready() {
			info, statErr := os.Stat(path)
			if statErr != nil {
				t.Fatalf("ready metadata socket is unavailable: %v", statErr)
			}
			if got := info.Mode().Perm(); got != 0600 {
				t.Fatalf("metadata socket mode = %04o, want 0600", got)
			}
			break
		}
		select {
		case err = <-serveDone:
			t.Fatalf("metadata socket failed to start: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("metadata socket did not start")
		}
		time.Sleep(time.Millisecond)
	}
	defer registry.Close()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peerPort := make(chan uint16, 1)
	continueHandshake := make(chan struct{})
	go serveSOCKSOnce(ctx, listener, peerPort, continueHandshake)

	app, captured := net.Pipe()
	defer app.Close()
	emitDone := make(chan error, 1)
	client := &socks5.Client{Address: listener.Addr().String(), Registry: registry}
	go func() {
		emitDone <- client.Emit(ctx, tunless.Flow{
			Proto:   tunless.TCP,
			OrigDst: netip.MustParseAddrPort("203.0.113.7:443"),
			Process: tunless.ProcessInfo{PID: 4242, Path: "/usr/bin/browser"},
			Conn:    captured,
		})
	}()
	port := <-peerPort

	transport := &http.Transport{DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", path)
	}}
	httpClient := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()
	url := "http://unix/v1/flow?source_port=" + strconv.Itoa(int(port))
	var response *http.Response
	for deadline := time.Now().Add(2 * time.Second); ; {
		response, err = httpClient.Get(url)
		if err == nil && response.StatusCode == http.StatusOK {
			break
		}
		if response != nil {
			response.Body.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("metadata lookup did not become available: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	var body struct {
		Process tunless.ProcessInfo `json:"process"`
	}
	if err = json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if body.Process.PID != 4242 || body.Process.Path != "/usr/bin/browser" {
		t.Fatalf("metadata process = %+v", body.Process)
	}
	close(continueHandshake)

	cancel()
	_ = app.Close()
	select {
	case <-emitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("SOCKS emitter did not stop")
	}
	for deadline := time.Now().Add(2 * time.Second); ; {
		if _, err = os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("metadata socket was not removed after shutdown: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

func serveSOCKSOnce(ctx context.Context, listener net.Listener, peerPort chan<- uint16, continueHandshake <-chan struct{}) {
	conn, err := listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	peerPort <- conn.RemoteAddr().(*net.TCPAddr).AddrPort().Port()
	select {
	case <-continueHandshake:
	case <-ctx.Done():
		return
	}
	greeting := make([]byte, 3)
	_, _ = io.ReadFull(conn, greeting)
	_, _ = conn.Write([]byte{5, 0})
	request := make([]byte, 10)
	_, _ = io.ReadFull(conn, request)
	_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
	<-ctx.Done()
}
