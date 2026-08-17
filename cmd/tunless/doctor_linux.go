//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/bojieli/tunless"
	linuxbackend "github.com/bojieli/tunless/backend/linux"
	"golang.org/x/sys/unix"
)

func doctorPlatform(ctx context.Context, backendName, cgroupPath, networkNamespace string, filter tunless.Filter) []doctorCheck {
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
