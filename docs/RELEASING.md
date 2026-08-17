# Release process

No public release is created by the current automation. The
`release-candidate.yml` workflow is manual and only builds a review artifact.
It has no tag trigger, package-registry credentials, GitHub Release operation,
or repository-visibility step.

## Prepare a candidate

1. Ensure `main` is clean, CI/security/kernel workflows pass, and the version's
   scope is final. Update `CHANGELOG.md` and the measurements.
2. Run `./scripts/release-check.sh VERSION`. This creates Linux amd64/arm64 raw
   binaries, normalized archives, DEB/RPM packages, an amd64/arm64 OCI archive,
   SPDX JSON SBOMs, synchronized third-party notices, and SHA-256 checksums under
   ignored `dist/`. Syft may retain `NOASSERTION` for licenses it cannot infer
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
