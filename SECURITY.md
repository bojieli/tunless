# Security policy

Tunless changes process-wide network behavior and includes privileged Linux and
Windows components. Please do not open a public issue for a suspected security
vulnerability.

Use GitHub's **Security → Report a vulnerability** form for this repository.
Include the affected platform and version, a minimal reproducer, expected and
observed behavior, and whether the issue can escape the configured cgroup,
container, process, or destination scope.

Only the latest commit on `main` receives security fixes until the project
publishes versioned releases. Runtime claims for unsigned or unvalidated
platform components remain explicitly listed in `docs/MEASUREMENTS.md`.
