//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/bojieli/tunless"
	linuxbackend "github.com/bojieli/tunless/backend/linux"
	"golang.org/x/sys/unix"
)

func doctorPlatform(ctx context.Context, backendName, listen, cgroupPath, networkNamespace string, filter tunless.Filter) []doctorCheck {
	if backendName == "redirect" {
		return doctorRedirect(listen, filter)
	}
	if backendName != "linux" {
		return []doctorCheck{{Name: "capture_backend", Status: "pass", Detail: "privilege-free backend selected"}}
	}
	checks := make([]doctorCheck, 0, 5)
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		checks = append(checks, doctorCheck{Name: "kernel", Status: "fail", Detail: err.Error()})
	} else {
		checks = append(checks, doctorCheck{Name: "kernel", Status: "pass", Detail: unix.ByteSliceToString(uname.Release[:])})
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(cgroupPath, &stat); err != nil {
		checks = append(checks, doctorCheck{Name: "cgroup_v2", Status: "fail", Detail: err.Error()})
		return checks
	}
	if stat.Type != unix.CGROUP2_SUPER_MAGIC {
		checks = append(checks, doctorCheck{Name: "cgroup_v2", Status: "fail", Detail: "capture path is not on cgroup v2"})
		return checks
	}
	checks = append(checks, doctorCheck{Name: "cgroup_v2", Status: "pass", Detail: cgroupPath})

	if own, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		if ownPath, pathErr := cgroupPathFromProc(own); pathErr == nil && (ownPath == cgroupPath || strings.HasPrefix(ownPath, strings.TrimSuffix(cgroupPath, "/")+"/")) {
			checks = append(checks, doctorCheck{Name: "loop_avoidance", Status: "fail", Detail: "Tunless itself is inside the captured cgroup"})
		} else {
			checks = append(checks, doctorCheck{Name: "loop_avoidance", Status: "pass", Detail: "Tunless process is outside the captured cgroup"})
		}
	}

	temporary, err := os.MkdirTemp(cgroupPath, ".tunless-doctor-")
	if err != nil {
		checks = append(checks, doctorCheck{Name: "bpf_load_attach", Status: "fail", Detail: fmt.Sprintf("create empty test cgroup: %v", err)})
		return checks
	}
	defer os.Remove(temporary)
	probe := &linuxbackend.Backend{Address: "127.0.0.1:0", CgroupPath: temporary, NetworkNamespace: networkNamespace, Filter: filter}
	probeCtx, cancel := context.WithCancel(ctx)
	_, err = probe.Start(probeCtx)
	cancel()
	closeErr := probe.Close()
	if err != nil {
		checks = append(checks, doctorCheck{Name: "bpf_load_attach", Status: "fail", Detail: err.Error()})
	} else if closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
		checks = append(checks, doctorCheck{Name: "bpf_load_attach", Status: "fail", Detail: closeErr.Error()})
	} else {
		checks = append(checks, doctorCheck{Name: "bpf_load_attach", Status: "pass", Detail: "embedded programs loaded and attached to an empty temporary cgroup"})
	}
	return checks
}

// doctorRedirect checks what the netfilter fallback actually needs, which is
// not what a privilege-free backend needs.
//
// Reporting it as privilege-free was worse than reporting nothing: this backend
// wants NET_ADMIN and a netfilter rule that somebody else installed, and the
// two ways it goes wrong in production are a listener reachable from off-host
// and a rule that is not there. An operator running doctor to find out whether
// the host is ready was being told yes.
func doctorRedirect(listen string, filter tunless.Filter) []doctorCheck {
	checks := make([]doctorCheck, 0, 4)

	// A routable listener is an open proxy, because this backend cannot tell a
	// redirected connection from one that arrived on its own.
	host, _, err := net.SplitHostPort(listen)
	switch {
	case err != nil:
		checks = append(checks, doctorCheck{Name: "redirect_listener", Status: "fail",
			Detail: fmt.Sprintf("listen address %q: %v", listen, err)})
	default:
		ip, parseErr := netip.ParseAddr(host)
		if parseErr != nil || !ip.IsLoopback() {
			checks = append(checks, doctorCheck{Name: "redirect_listener", Status: "fail",
				Detail: fmt.Sprintf("listen address %q must be a literal loopback IP; a routable "+
					"one accepts off-host traffic this backend cannot distinguish from a redirect", listen)})
		} else {
			checks = append(checks, doctorCheck{Name: "redirect_listener", Status: "pass", Detail: listen})
		}
	}

	// Process filters cannot be honoured, and a filter that silently matches
	// nothing is the failure this refusal exists to prevent.
	if len(filter.IncludeProcesses) > 0 || len(filter.ExcludeProcesses) > 0 {
		checks = append(checks, doctorCheck{Name: "redirect_filters", Status: "fail",
			Detail: "this backend cannot attribute processes, so --include-process and " +
				"--exclude-process are refused; filter on destinations, or use the eBPF backend"})
	} else {
		checks = append(checks, doctorCheck{Name: "redirect_filters", Status: "pass",
			Detail: "no process filters requested"})
	}

	// SO_ORIGINAL_DST is the whole mechanism. If the kernel does not answer it
	// there is nothing to fall back to.
	checks = append(checks, doctorOriginalDst())

	// The rule belongs to the operator rather than to this process, which is
	// also why fail-open is lost: it outlives us. Not finding one is a warning
	// rather than a failure, because it may be installed after this runs.
	checks = append(checks, doctorRedirectRule(listen))
	return checks
}

// doctorOriginalDst asks the kernel for SO_ORIGINAL_DST on a socket that was
// never redirected. ENOENT means the option is understood and this connection
// simply has no original destination, which is the answer that proves support.
func doctorOriginalDst() doctorCheck {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return doctorCheck{Name: "so_original_dst", Status: "fail", Detail: err.Error()}
	}
	defer func() { _ = ln.Close() }()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return doctorCheck{Name: "so_original_dst", Status: "fail", Detail: err.Error()}
	}
	defer func() { _ = conn.Close() }()
	accepted, err := ln.Accept()
	if err != nil {
		return doctorCheck{Name: "so_original_dst", Status: "fail", Detail: err.Error()}
	}
	defer func() { _ = accepted.Close() }()
	tcpConn, ok := accepted.(*net.TCPConn)
	if !ok {
		return doctorCheck{Name: "so_original_dst", Status: "fail", Detail: "accepted connection is not TCP"}
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return doctorCheck{Name: "so_original_dst", Status: "fail", Detail: err.Error()}
	}
	var optErr error
	if ctlErr := raw.Control(func(fd uintptr) {
		_, optErr = unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, soOriginalDstOption)
	}); ctlErr != nil {
		return doctorCheck{Name: "so_original_dst", Status: "fail", Detail: ctlErr.Error()}
	}
	if optErr != nil && !errors.Is(optErr, unix.ENOENT) && !errors.Is(optErr, unix.ENOPROTOOPT) {
		// Any other error still means the option was understood.
		return doctorCheck{Name: "so_original_dst", Status: "pass",
			Detail: fmt.Sprintf("kernel understands the option (%v on an unredirected socket)", optErr)}
	}
	if errors.Is(optErr, unix.ENOPROTOOPT) {
		return doctorCheck{Name: "so_original_dst", Status: "fail",
			Detail: "kernel does not support SO_ORIGINAL_DST, which is how this backend " +
				"learns where a connection was going"}
	}
	return doctorCheck{Name: "so_original_dst", Status: "pass",
		Detail: "kernel answers the option on an unredirected socket"}
}

// soOriginalDstOption mirrors the constant the backend uses. It is repeated
// rather than exported because it is a kernel number, not an API.
const soOriginalDstOption = 80

// doctorRedirectRule looks for a netfilter rule pointing at this listener.
func doctorRedirectRule(listen string) doctorCheck {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return doctorCheck{Name: "redirect_rule", Status: "warn", Detail: "listen address unparsed"}
	}
	for _, probe := range [][]string{
		{"nft", "list", "ruleset"},
		{"iptables-save", "-t", "nat"},
	} {
		path, lookErr := exec.LookPath(probe[0])
		if lookErr != nil {
			continue
		}
		out, runErr := exec.Command(path, probe[1:]...).CombinedOutput()
		if runErr != nil {
			continue
		}
		if strings.Contains(string(out), port) {
			return doctorCheck{Name: "redirect_rule", Status: "pass",
				Detail: fmt.Sprintf("%s mentions port %s", probe[0], port)}
		}
		return doctorCheck{Name: "redirect_rule", Status: "warn",
			Detail: fmt.Sprintf("%s lists no rule mentioning port %s; nothing will be "+
				"redirected here until one is installed, and this backend cannot install it", probe[0], port)}
	}
	return doctorCheck{Name: "redirect_rule", Status: "warn",
		Detail: "neither nft nor iptables-save is available, so the rule could not be checked"}
}
