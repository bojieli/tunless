# Release checklist

The pre-public-release review record: checked and unchecked gates a maintainer
must resolve before tagging.

*Audience: maintainers preparing a public release.*

This checklist is a review record, not an assertion that every platform is
qualified. Link each completed item to a run, commit, or measurement.

## Source and project

- [x] Scope, license, changelog, compatibility matrix, threat model, support,
      governance, conduct, contribution guide, and release notes reviewed
- [x] Repository history contains no secrets or oversized unintended artifacts
- [x] Discussions, issue templates, dependency alerts, and automated security
      fixes configured while the repository remains private
- [ ] Branch protection and required hosted CI/security checks enabled during
      the public visibility transition and before a tag is created
- [ ] Private vulnerability reporting enabled after the repository becomes public
      and before a public tag or release is created
- [x] Dependencies and licenses reviewed; govulncheck and the full-history
      secret scan have acceptable results
- [ ] Public-only CodeQL, dependency review, and Scorecard have acceptable results
- [ ] Exact candidate commit has passing hosted CI, security, fuzz, and
      current-kernel workflows

## Correctness and resilience

- [x] Race, vet, static analysis, fuzz smoke, 10,000-connection stress, soak, and
      malformed-input suites pass
- [x] Linux exact embedded BPF object is reproducible and verifier/runtime-tested
      on x86-64 current kernel and ARM64 kernel 5.10
- [x] TCP/UDP WAN, upstream restart, overload, controller crash, stale PID,
      container stop/recreate, and fail-open recovery pass
- [x] Docker native Linux and Docker Desktop macOS tests cover unmodified,
      no-proxy-environment applications
- [ ] Linux unconnected UDP sockets that alternate destinations fail safely or
      preserve per-datagram attribution in a current-kernel live test
- [x] Rootful Podman and selected CRI/Kubernetes behavior are tested or marked
      experimental; rootless limitation is documented

## Artifacts

- [x] Two clean builds of release binaries/archives/packages are byte-identical
- [x] DEB/RPM install, service hardening, upgrade, uninstall, archives, and OCI
      amd64/arm64 smoke tests pass
- [x] SBOMs, checksums, package manifests, licenses, and versions reviewed;
      synchronized notices cover every embedded third-party Go module
- [ ] GitHub provenance attestations generated and reviewed after public
      visibility enables that service and before a tag is created
- [ ] Candidate was produced by the manual non-publishing workflow and reviewed
      without changing repository visibility, creating a tag, or publishing

## Explicit external platform gates

- [ ] macOS Developer ID entitlements, activation, notarization, staple, and
      clean-machine runtime qualification complete
- [ ] Windows WDK driver build/signing, Driver Verifier, Windows host/container
      runtime, coexistence, and rollback qualification complete

## Evidence snapshot

The checked items above were revalidated on 2026-08-17. Exact host versions,
test counts, WAN results, resource measurements, BPF object hash, OCI digest,
and deliberately unqualified platforms are recorded in
[Measurements and release gates](MEASUREMENTS.md). The remaining unchecked
items are release blockers, not waived requirements. In particular, Windows
Docker behavior is source-complete but remains part of the Windows runtime gate.
The current GitHub plan returns `403` for branch protection on this private
repository. GitHub documents the relevant plan boundaries for
[protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
and [security features](https://docs.github.com/en/code-security/getting-started/github-security-features),
including CodeQL, dependency review, and artifact attestations. Those unchecked
items are ordered visibility-transition gates: make the repository public,
enable them, obtain passing results, and only then consider a tag. The
unpublished private candidate does not satisfy those public gates.

The 2026-08-19 hosted run for base commit `24c6cde` passed embedded-BPF
verification, WAN/recovery, and Docker lifecycle stages, but hit its 30-minute
job limit during the subsequent Podman stage; the workflow now allows 60
minutes and must pass on the exact reviewed candidate. The same commit's CI
jobs were never assigned hosted runners and the run was ultimately marked
failed without executing a step. Local substitution is useful diagnostic
evidence, but it does not satisfy the exact-commit hosted gate.

## Approval

- [ ] Maintainer explicitly approves the exact commit and candidate checksums
- [ ] Only after approval, signed tag and public release are created manually

See also: [Releasing](RELEASING.md) and
[Measurements and release gates](MEASUREMENTS.md).
