# Contributing

Tunless welcomes focused bug fixes, tests, portability work, documentation, and
performance improvements. Start with a discussion for changes that alter the
capture architecture, supported platform floor, proxy protocol, or security
boundary.

## Development setup

Install Go 1.26.6 or a compatible newer Go release. Linux BPF regeneration also
requires clang 14, llvm 14, and libbpf headers; macOS work requires the Xcode
toolchain. The ordinary portable checks are:

```console
go test -race ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@latest ./...
bash -n scripts/*.sh
cd macos && swift test
```

Run `./scripts/verify-bpf.sh` before changing the embedded BPF program. On a
native cgroup-v2 Linux host, run `scripts/integration-linux.sh`; container
changes should also run `scripts/integration-containers.sh`. Platform-specific
claims need a real runtime result on that platform.

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
