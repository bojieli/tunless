# Security policy

Tunless changes process-wide network behavior and includes privileged Linux and
Windows components. Please do not open a public issue for a suspected security
vulnerability.

While the repository is private, authorized reviewers should report a suspected
vulnerability directly to the repository owner rather than opening an issue.
[GitHub only makes private vulnerability reporting available to public
repositories](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/repository-security-advisories).
Enabling GitHub's **Security → Report a vulnerability** form is a mandatory
visibility-transition gate and must happen before any public tag or release is
created.

Include the affected platform and version, a minimal reproducer, expected and
observed behavior, and whether the issue can escape the configured cgroup,
container, process, or destination scope. Do not include credentials or other
unrelated secrets in a report.

Only the latest commit on `main` receives security fixes until the project
publishes versioned releases. Runtime claims for unsigned or unvalidated
platform components remain explicitly listed in `docs/MEASUREMENTS.md`.

## OpenSSF Scorecard findings

Scorecard runs on every push and uploads its checks as code-scanning alerts.
Some of them are acted on and some are accepted; both are recorded here so a
reader does not have to guess which is which.

**Acted on.** Branch protection, required status checks, linear history, and
review-before-merge are enforced on `main` as of the repository becoming
public, by `scripts/github-harden.sh`. Container base images are pinned by
digest.

**Accepted, with reasons:**

- **Binary-Artifacts — `backend/linux/bpf/tunless_bpf.o`.** The compiled BPF
  object is committed deliberately: it is embedded in the binary so that
  installing tunless does not require a toolchain, and so the object a user
  runs is the object that was tested. A committed binary is a real
  supply-chain concern, and the answer is reproducibility rather than trust —
  `scripts/build-bpf.sh` rebuilds it and `scripts/verify-bpf.sh` checks the
  result byte-for-byte against the committed object. Anyone can confirm the
  object matches its source without taking anyone's word for it.
- **Pinned-Dependencies — `packaging/oci/Dockerfile:2`.** `FROM release` names
  a build stage supplied by the build context, not an image from a registry.
  There is nothing to pin. The Dockerfiles that do reference registry images
  pin them by digest.
- **Code-Review and Branch-Protection history.** Commits made before the
  repository was public were pushed directly to `main` by the sole maintainer.
  That history cannot be rewritten to satisfy the check, and doing so would be
  worse than the finding. The protection applies from the transition forward.
- **Maintained.** Scorecard scores this 0 because the repository was created
  within the last ninety days. It is a measure of elapsed time, not of the
  code, and the only thing that resolves it is time passing.
- **SAST.** Scored 7 of 10: "SAST tool detected but not run on all commits."
  CodeQL runs on every pull request and every push to `main`. The commits it
  did not analyse are the pre-public ones that went straight to `main`, which
  is the same history described under Code-Review above and equally not
  rewritable.
- **CII-Best-Practices.** No badge has been applied for. It is a process
  artifact rather than a property of the code.
