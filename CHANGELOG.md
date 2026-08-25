# Changelog

This project follows semantic versioning after its first public release. Dates
use ISO 8601. The repository has not made a public release yet.

## Unreleased

### Added

- A capture floor the configuration cannot reach past: loopback, the
  unspecified address, link-local, multicast, broadcast, the SOCKS5 upstream,
  and the trusted resolver's own endpoint are reserved from capture on macOS
  and Linux. Reserving the resolver ends the DNS recursion that a proxy running
  its own TUN and DNS hijack produced, without depending on the operator naming
  the upstream's process.
- Private, carrier-grade NAT, and `198.18.0.0/15` fake-IP ranges excluded by
  default on macOS, with `--include-destination` overriding per prefix and
  `--no-default-exclusions` dropping the set.
- macOS process selection that matches the executable path and its basename as
  well as the signing identifier, so a rule can name one program even when the
  toolchain gave it a default identifier shared with unrelated binaries;
  telemetry carries the executable behind each flow.
- A macOS flow ceiling (`--max-flows`, default 4096) matching the portable
  core, so one application cannot push the extension into the CPU budget macOS
  terminates it for. Rejected flows go direct.
- macOS health probing over both DNS transports, gated on what preflight
  observed, so an upstream that stops relaying UDP no longer looks healthy to a
  TCP-only probe.
- A macOS soak harness (`scripts/tunless-macos-soak.sh`) that asserts
  resolution and capture state across sleeps, wakes, and network changes, plus
  release gates for a 48-hour soak and for surviving an app deletion while
  capture runs.
- A macOS capture health watchdog that re-proves name resolution through the
  live upstream every 30 seconds. After three consecutive failures the provider
  stops claiming flows, so they go direct as though tunless were not installed,
  and it resumes on the first probe that succeeds again. A probation window
  covers a start that is never confirmed. Sleep suspends the watchdog and a
  wake discards the failures that led into it, so a sleeping laptop cannot pause
  capture and wake up unprotected. `status` reports what capture is doing in a
  `capture` field, and every transition is written to the unified log under
  subsystem `com.bojieli.tunless`. `--no-health-watchdog` opts out.

- Idempotent macOS `stop` and `cleanup` recovery commands, a bounded cleanup
  script bundled in the app, stale-manager removal, Network Extension
  deactivation, and a documented manual disable path for fail-safe recovery.
- A focused macOS Clash Verge companion preset with automatic loop exclusions,
  SOCKS5 preflight, strict launcher commands, and non-destructive status output.
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
- Bounded DNS attribution state with CNAME-chain validation, failure-safe
  private metadata-socket permissions, strict release-version validation, and
  workflow input isolation for release-candidate builds. Process-controlled
  metadata username fields are delimiter-escaped before SOCKS authentication;
  valid SemVer build metadata is mapped safely into OCI tag syntax. DNS TCP
  framing now completes short writes rather than silently truncating messages.
- Unauthenticated reference-proxy, DNS-observer, and status listeners are
  restricted to numeric loopback addresses and ports; auxiliary service
  failures now produce a fatal process result instead of a clean exit. Private
  metadata sockets also require private parent directories, never remove a
  pre-existing socket they did not create, and requested auxiliary services
  must become ready before capture starts. Status and metadata HTTP connection
  counts are bounded against local slow-connection exhaustion.
- Hosted checks do not persist checkout credentials into code under test, use
  explicit runner images, and gate public-only dependency review consistently.
- Linux UDP associations include the kernel socket cookie so endpoint reuse
  cannot inherit an older userspace session; malformed kernel-map records and
  invalid or oversized datagrams fail closed. An active unconnected association
  rejects a different destination rather than overwriting in-flight source
  attribution, while connected associations retain marked recovery state and
  unconnected state is released on association turnover. DNS attribution now
  matches the requested A/AAAA type and uses the shortest validated
  CNAME/address TTL. DEB/RPM config is root-owned mode `0600`, and pre-install
  scripts reject an existing `/etc/tunless.env` symlink before package
  extraction.
