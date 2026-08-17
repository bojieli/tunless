# Public-release review checklist

This checklist is a review record, not an assertion that every platform is
qualified. Link each completed item to a run, commit, or measurement.

## Source and project

- [x] Scope, license, changelog, compatibility matrix, threat model, support,
      governance, conduct, contribution guide, and release notes reviewed
- [x] Repository history contains no secrets or oversized unintended artifacts
- [ ] Branch protection and required hosted CI/security checks configured;
      Discussions, issue templates, dependency alerts, and automated security
      fixes are already enabled
- [ ] Private vulnerability reporting enabled after the repository becomes public
      and before a public tag or release is created
- [ ] Dependencies and licenses reviewed; CodeQL, govulncheck, dependency review,
      secret scan, and public-only Scorecard have acceptable results

## Correctness and resilience

- [x] Race, vet, static analysis, fuzz smoke, 10,000-connection stress, soak, and
      malformed-input suites pass
- [x] Linux exact embedded BPF object is reproducible and verifier/runtime-tested
      on x86-64 current kernel and ARM64 kernel 5.10
- [x] TCP/UDP WAN, upstream restart, overload, controller crash, stale PID,
      container stop/recreate, and fail-open recovery pass
- [x] Docker native Linux and Docker Desktop macOS tests cover unmodified,
      no-proxy-environment applications
- [x] Rootful Podman and selected CRI/Kubernetes behavior are tested or marked
      experimental; rootless limitation is documented

## Artifacts

- [ ] Two clean builds of release binaries/archives/packages are byte-identical
- [ ] DEB/RPM install, service hardening, upgrade, uninstall, archives, and OCI
      amd64/arm64 smoke tests pass
- [ ] SBOMs, checksums, package manifests, licenses, versions, and provenance
      attestations reviewed
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

## Approval

- [ ] Maintainer explicitly approves the exact commit and candidate checksums
- [ ] Only after approval, signed tag and public release are created manually
