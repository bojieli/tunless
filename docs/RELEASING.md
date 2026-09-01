# Releasing

How a release candidate is prepared, reviewed by a maintainer, published only
after explicit approval, and rolled back if defective.

*Audience: maintainers.*

No public release is created by the current automation. The
`release-candidate.yml` workflow is manual and only builds a review artifact.
It has no tag trigger, package-registry credentials, GitHub Release operation,
or repository-visibility step.

## What the first release covers

The three platforms are not at the same maturity, and a release that implies
they are would be the most damaging thing this project could publish. Each one
ships at the level its evidence supports, stated on the release itself and not
only in a document a reader may not reach:

| Platform | Ships as | Because |
| --- | --- | --- |
| Linux | Generally available | eBPF capture for TCP and UDP over both families, host and container namespaces, a reproducible embedded BPF object verified on the 5.10 floor and a current kernel, and dated throughput and footprint evidence |
| macOS | Beta | Notarized builds pass the recorded live suites; upstream degradation remains fail-closed and network changes invalidate stale transports, but exact-candidate clean-machine qualification is open and HTTP/3 name recovery is not demonstrated |
| Windows | Source only, not a shippable artifact | The WFP backend is implemented, but WDK build, Driver Verifier, runtime, UDP, fuzzing, and Microsoft attestation gates are all unmet, and loading a driver on Windows 10 or later needs a signature this project does not obtain |

Release notes must carry that table, no Windows binary may be attached to a
release, and the Windows source must keep saying what it is. A user who
installs a driver believing it was qualified is the failure this scoping
exists to prevent.

## Going public

Branch protection, rulesets, and private vulnerability reporting are all
refused on a private repository on GitHub Free. That makes the flip to public a
window rather than an event: for as long as it stays open, `main` is public and
unprotected, and someone who finds a vulnerability in code they can now read
has no private way to report it.

Close it with one command rather than a memory:

```console
gh repo edit bojieli/tunless --visibility public --accept-visibility-change-consequences
./scripts/github-harden.sh
```

`github-harden.sh` applies branch protection with the CI checks named exactly
as the workflow reports them, enforces linear history and conversation
resolution, refuses force pushes and deletions, enables private vulnerability
reporting and Dependabot alerts, and then reads every one of them back. It
refuses to do anything while the repository is still private, and is safe to
re-run.

CodeQL, dependency review, and Scorecard only produce results on a public
repository, so their first real output arrives after this point. Re-run the
security workflows and read what they find **before** creating a tag — that
ordering is the whole reason the release is not tagged at the same moment
visibility changes.

## Prepare a candidate

1. Ensure `main` is clean, CI/security/kernel workflows pass, and the version's
   scope is final. Update `CHANGELOG.md`, `docs/RELEASE_NOTES.md`, and the
   measurements.
2. Run `./scripts/release-check.sh VERSION`. This creates Linux amd64/arm64 raw
   binaries, normalized archives, DEB/RPM packages, an amd64/arm64 OCI archive,
   deterministic SPDX JSON SBOMs for each binary and OCI platform, synchronized
   third-party notices, and SHA-256 checksums under ignored `dist/`. The command
   recreates that generated output directory so stale files cannot enter a
   candidate. Syft may retain `NOASSERTION` for licenses it cannot infer
   from a static binary; `THIRD_PARTY_NOTICES.md` contains the reviewed license
   texts and is verified against each binary's embedded module metadata. The
   command rejects a dirty tree; `TUNLESS_ALLOW_DIRTY_RELEASE=1` exists only for local
   pipeline development and is never set by the candidate workflow.
3. Run the same candidate through the manual **Release candidate** workflow.
   Download the artifact, verify its checksums, and compare the reproducibility
   report. On GitHub Free, provenance attestations are unavailable while this
   repository is private; the attestation step is intentionally gated until
   public visibility and must pass before a tag is created.
4. Install/upgrade/uninstall DEB and RPM packages in clean amd64 and arm64
   systems; verify systemd units and run both archive and `scratch` OCI
   architecture smoke tests. Run Linux kernel 5.10 plus current-kernel integration,
   container lifecycle tests, macOS tests, Windows qualification when in scope,
   fuzz smoke tests, stress/soak, and real-WAN benchmarks.
5. Review `docs/RELEASE_CHECKLIST.md`. Record every deferred platform as
   unsupported rather than weakening a gate.

## Maintainer review boundary

Stop after candidate creation. A human maintainer reviews source, changelog,
SBOMs, checksums, attestations, package contents, measurements, known
limitations, and release notes. Candidate artifacts are not releases and must
not be distributed as supported binaries.

## Publishing (intentionally manual and not yet authorized)

Only after explicit maintainer approval: create a signed annotated tag from the
reviewed commit, rerun the immutable source revision, verify its outputs, create
the GitHub Release, upload the reviewed assets, and publish the OCI image by
digest. Never build a release from a dirty tree or move an existing tag. This
section documents the later procedure; it is not permission to execute it.

## Rollback

Do not replace published assets or retag. Mark a defective release as withdrawn,
publish a security advisory when appropriate, fix forward with a new version,
and preserve checksums/provenance so consumers can identify affected files.

See also: [Release checklist](RELEASE_CHECKLIST.md) and the
[project README](../README.md).
