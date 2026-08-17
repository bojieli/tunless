package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"time"

	"github.com/bojieli/tunless"
	"github.com/bojieli/tunless/socks5"
)

type doctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type doctorReport struct {
	Version   string        `json:"version"`
	OS        string        `json:"os"`
	Arch      string        `json:"arch"`
	CheckedAt time.Time     `json:"checked_at"`
	OK        bool          `json:"ok"`
	Checks    []doctorCheck `json:"checks"`
}

func runDoctor(ctx context.Context, backendName, cgroupPath, networkNamespace string, filter tunless.Filter, client *socks5.Client, target netip.AddrPort) error {
	report := doctorReport{
		Version:   version,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		CheckedAt: time.Now().UTC(),
		OK:        true,
	}
	report.Checks = append(report.Checks, doctorPlatform(ctx, backendName, cgroupPath, networkNamespace, filter)...)
	result, err := client.Check(ctx, target)
	if err != nil {
		report.Checks = append(report.Checks, doctorCheck{Name: "socks5_upstream", Status: "fail", Detail: err.Error()})
		report.OK = false
	} else {
		report.Checks = append(report.Checks, doctorCheck{
			Name:   "socks5_upstream",
			Status: "pass",
			Detail: fmt.Sprintf("TCP CONNECT and UDP ASSOCIATE passed; relay=%s", result.UDPRelay),
		})
	}
	for _, check := range report.Checks {
		if check.Status == "fail" {
			report.OK = false
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(report); err != nil {
		return err
	}
	if !report.OK {
		return errors.New("preflight checks failed")
	}
	return nil
}
