# Public-release review checklist

This checklist is a review record, not an assertion that every platform is
qualified. Link each completed item to a run, commit, or measurement.

## Source and project

- [ ] Scope, license, changelog, compatibility matrix, threat model, support,
      governance, conduct, contribution guide, and release notes reviewed
- [ ] Repository history contains no secrets or oversized unintended artifacts
- [ ] Branch protection, required CI/security checks, private vulnerability
      reporting, Discussions, and issue templates configured
- [ ] Dependencies and licenses reviewed; CodeQL, govulncheck, dependency review,
      secret scan, and public-only Scorecard have acceptable results

## Correctness and resilience

- [ ] Race, vet, static analysis, fuzz smoke, 10,000-connection stress, soak, and
      malformed-input suites pass
- [ ] Linux exact embedded BPF object is reproducible and verifier/runtime-tested
      on x86-64 current kernel and ARM64 kernel 5.10
- [ ] TCP/UDP WAN, upstream restart, overload, controller crash, stale PID,
      container stop/recreate, and fail-open recovery pass
- [ ] Docker native Linux and Docker Desktop macOS tests cover unmodified,
      no-proxy-environment applications; Windows Docker Desktop test is recorded
- [ ] Rootful Podman and selected CRI/Kubernetes behavior are tested or marked
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

## Approval

- [ ] Maintainer explicitly approves the exact commit and candidate checksums
- [ ] Only after approval, signed tag and public release are created manually
