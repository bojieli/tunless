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
- [ ] `./scripts/github-harden.sh` run immediately after the repository becomes
      public, reporting every setting verified
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
- [x] Linux unconnected UDP sockets that alternate destinations fail safely or
      preserve per-datagram attribution in a current-kernel live test
- [x] Rootful Podman and selected CRI/Kubernetes behavior are tested or marked
      experimental; rootless limitation is documented
- [ ] macOS capture soaked for at least 48 hours across sleeps, wakes, and a
      network change with `scripts/tunless-macos-soak.sh`, and its summary
      reports no unresolved interval and no unexplained not-capturing interval.
      Every serious defect found so far surfaced over hours rather than
      minutes — a watchdog that mistook a sleeping laptop for a failing
      upstream left a host resolving unprotected for nine hours — and no
      shorter test can see that class of bug
- [x] macOS host still resolves after `Tunless.app` is deleted while capture is
      running, without running `stop` or `cleanup` first. Deleting the app is
      what an ordinary uninstall looks like, and the fail-open claim is only
      demonstrated if the host survives it. Demonstrated on build 13; note that
      capture keeps running after the deletion, so the documented recovery is
      System Settings or reinstalling the app
- [ ] Linux WAN throughput and footprint re-measured on the tagged tree; the
      published figures predate the current one

## Release scope

- [ ] Release notes state the per-platform maturity from
      [RELEASING.md](RELEASING.md#what-the-first-release-covers): Linux
      generally available, macOS beta, Windows source only
- [ ] No Windows binary or driver is attached to the release, and the Windows
      documentation still says it is not a shippable artifact

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

- [ ] `scripts/macos-qualify.sh` run against the exact notarized candidate on a
      machine with no prior tunless installation, reporting zero failures
- [ ] macOS Developer ID entitlements, activation, notarization, staple, and
      clean-machine runtime qualification complete. Signing and notarization
      are automated in `.github/workflows/macos-release.yml`, which uploads the
      verified bundle as an artifact without publishing a release; see
      [macOS notes](MACOS.md).
- [ ] Windows WDK driver build/signing, Driver Verifier, Windows host/container
      runtime, coexistence, and rollback qualification complete. Production
      driver signing is deferred by decision for this phase: the project holds
      no EV certificate or Partner Center account, so the signing portion
      cannot pass and Windows is recorded as unsupported rather than the gate
      being weakened. See [Windows notes](WINDOWS.md).

## Evidence snapshot

The checked items above were revalidated through 2026-08-19. Exact host
versions, test counts, WAN results, resource measurements, BPF object hash,
OCI digest,
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

The initial 2026-08-19 hosted run for base commit `24c6cde` passed embedded-BPF
verification, WAN/recovery, and Docker lifecycle stages before its old
30-minute job limit stopped it during Podman. A subsequent exact-head failure
isolated a concurrent rootful-Podman metadata-query hang. Commit `5fadb80`
bounded those queries and serialized them with a private lock; exact run
[`32239472690`](https://github.com/bojieli/tunless/actions/runs/32239472690)
then passed BPF verification, WAN/recovery, Docker, Podman, containerd/CRI, and
teardown. Exact commit `d0ed79c` subsequently passed hosted
CI [`32240014731`](https://github.com/bojieli/tunless/actions/runs/32240014731),
Security
[`32240014758`](https://github.com/bojieli/tunless/actions/runs/32240014758),
and the full privileged workflow
[`32240014706`](https://github.com/bojieli/tunless/actions/runs/32240014706).
The exact-candidate aggregate gate remains open because hosted fuzz and the
manual candidate review have not run.

The clean local two-build pipeline for source commit `5fadb80` produced
byte-identical binaries, archives, packages, OCI output, SBOMs, and notices;
all package and OCI smoke tests passed. Its exact hashes are recorded in the
measurements document. This refreshes local artifact evidence but does not
satisfy the unchecked manual hosted workflow, provenance, or maintainer-review
gates.

## Approval

- [ ] Maintainer explicitly approves the exact commit and candidate checksums
- [ ] Only after approval, signed tag and public release are created manually

See also: [Releasing](RELEASING.md) and
[Measurements and release gates](MEASUREMENTS.md).
