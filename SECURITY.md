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
