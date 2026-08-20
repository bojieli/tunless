# Contributing

Tunless welcomes focused bug fixes, tests, portability work, documentation, and
performance improvements. Start with a discussion for changes that alter the
capture architecture, supported platform floor, proxy protocol, or security
boundary.

## Development setup

Source builds require Go 1.25 or newer. Install Go 1.26.6 or a compatible
newer Go release: the module toolchain directive and container build pin Go
1.26.6 so released binaries do not silently inherit known standard-library
vulnerabilities from an older local compiler. Linux BPF regeneration also
requires clang 14, llvm 14, and libbpf headers; macOS work requires the Xcode
toolchain. The committed eBPF object is built from
`backend/linux/bpf/tunless.bpf.c`. The ordinary portable checks are:

```console
go test -race ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
bash -n scripts/*.sh
cd macos && swift test
```

Windows driver work needs a Windows 11 VM with Visual Studio and the WDK, and
is test-signed only: build against a WDK-generated certificate with
`bcdedit /set testsigning on` in a snapshot-capable VM, never on a machine you
depend on. The project holds no EV certificate and no Partner Center account,
so no contribution can be production-signed and no signed `tunless.sys` is
published. Contributions are still welcome on that basis — see the
[Windows notes](docs/WINDOWS.md) for why the driver cannot be signed any other
way and what production signing would cost.

Run `./scripts/verify-bpf.sh` before changing the embedded BPF program. On a
native cgroup-v2 Linux host, run `scripts/integration-linux.sh` (set
`TUNLESS_BINARY` and `SINGBOX_BINARY` as needed); container changes should also
run `scripts/integration-containers.sh`. Performance work runs
`./scripts/benchmark-wan.sh` on the Linux capture host with `TUNLESS_PID`,
`TUNLESS_PROXY_PID`, `TUNLESS_CGROUP`, and `TUNLESS_UPSTREAM` set as needed.
Platform-specific claims need a real runtime result on that platform.

Every push and pull request runs the race suite, vet, Linux/Windows builds,
Swift tests, Docker build, shell parsing, and `govulncheck`. Scheduled checks
add privileged kernel integration, fuzzing, CodeQL, full-history secret
scanning, and public-only OpenSSF Scorecard analysis.

## Changes

Keep commits reviewable and describe intent, not just mechanics. Add regression
tests for bug fixes. Avoid adding a second packet stack, environment-variable
proxying, fake DNS answers, route hijacking, or silent fail-closed behavior: all
conflict with the design goals in `BLUEPRINT.md`.

Never commit private keys, notarization credentials, certificates, proxy
credentials, generated Xcode data, or release output. Logs and issue reports
must redact credentials and addresses the reporter considers sensitive.

Every contribution is licensed under the repository's MIT license. By opening a
pull request, you represent that you have the right to submit the work under
that license. Contributors must follow `CODE_OF_CONDUCT.md`.

## Review expectations

Pull requests need passing CI and maintainer review. Changes to privileged code,
release workflows, dependencies, or trust boundaries receive security-focused
review. Runtime support is not claimed until its documented gate passes; source
completion and cross-compilation alone do not qualify a platform.
