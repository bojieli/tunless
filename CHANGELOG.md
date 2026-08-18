# Changelog

This project follows semantic versioning after its first public release. Dates
use ISO 8601. The repository has not made a public release yet.

## Unreleased

### Added

- Default-on, numeric trusted-DNS override for the portable/Linux emitter and
  macOS provider, a cross-platform disable switch, SOCKS-routed DNS observation,
  and bounded transaction-ID translation for unambiguous UDP response restore.
- Bounded TCP/UDP inactivity, hard-error and pending-callback cancellation,
  joined UDP worker teardown, short-write-safe SOCKS control messages, macOS
  active-flow cancellation, SOCKS half-close draining, and TCP plus UDP
  completion telemetry.
- An optional macOS user LaunchAgent that persists bounded, private flow
  telemetry under `~/.tunless`, with size-based rotation.
- Linux cgroup eBPF capture for TCP and connected/unconnected UDP over IPv4 and
  IPv6, including namespace-local Docker, Podman, and one-container
  Kubernetes/containerd application capture.
- SOCKS5 TCP/UDP relay, optional real-answer DNS observation, metadata
  transports, bounded runtime statistics, a loopback-only status API, and an
  active `--check` diagnostic.
- macOS Network Extension and Windows WFP source paths with explicit runtime
  qualification gates.
- Kernel 5.10 and current-kernel integration harnesses, fuzz targets, stress and
  WAN benchmarks, deterministic BPF verification, SBOMs, packages, OCI output,
  and a non-publishing release-candidate workflow.
- Reproducible static `scratch` controller images plus amd64/arm64 DEB, RPM,
  archive, and OCI install/runtime smoke tests.
- Deterministic SPDX SBOMs for both raw binaries and each OCI architecture,
  plus synchronized third-party license notices carried by every archive and
  native package.

### Security

- Exact cgroup/container identity validation, privilege separation, fail-open
  BPF lifecycle, bounded flow concurrency, full-history secret scanning,
  public-release gates for CodeQL, dependency review, and provenance
  attestations.
