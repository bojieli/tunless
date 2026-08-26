# Documentation

Everything below links from the [README](../README.md); the design rationale
lives in [BLUEPRINT.md](../BLUEPRINT.md), the design of record.

## Start here

- [Questions people ask](FAQ.md) — whether it costs you your routing rules,
  proxying only some applications, whether to keep your proxy's TUN on, what
  happens when it crashes, and why DNS broke that one time.

## Using tunless

- [Containers and virtual machines](CONTAINERS.md) — Docker, Podman,
  containerd/CRI-O, Docker Desktop, and the boundaries of container capture.
- [macOS](MACOS.md) — Network Extension build, signing, the Clash Verge
  preset, and recovery.
- [Windows](WINDOWS.md) — WFP driver design, build, and release gates
  (source-complete, not release-qualified).
- [Operations](OPERATIONS.md) — preflight checks, health API, DNS override and
  observation, process metadata, capacity, and recovery.
- [Flow attribution](FLOW_ATTRIBUTION.md) — what the agent can say about the
  process behind a flow, what it deliberately refuses to guess, and the wire
  shape a consumer reads.
- [The netfilter fallback](REDIRECT_BACKEND.md) — capturing on a host whose
  kernel cannot run the eBPF backend, what you give up by doing so, and why it
  is netfilter rather than a tunnel device.

## Evaluating the project

- [Measurements and release gates](MEASUREMENTS.md) — dated performance and
  gate evidence, including what has not been demonstrated.
- [Threat model](THREAT_MODEL.md) — assets, trust boundaries, risks, and
  explicit non-goals.

## For maintainers

- [Releasing](RELEASING.md) — the candidate-build and manual-publish
  procedure.
- [Release checklist](RELEASE_CHECKLIST.md) — the pre-public-release review
  record and its gates.
