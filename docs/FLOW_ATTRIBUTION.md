# Flow attribution

Capturing at the socket layer knows more about a flow than a proxy protocol can
carry. SOCKS5 expresses a destination and nothing else; the kernel handed over
the calling process, and on a host running containers that process sits in a
cgroup that names the pod or container it belongs to.

This document describes what `tunless` makes available about a flow, and the
terms on which a consumer may rely on it.

## What is available

| Field | Source | Present when |
|---|---|---|
| `PID` | the capture hook | always |
| `Path` | `/proc/PID/exe` | the process still exists at lookup |
| `SigningID` | code signature | macOS |
| `CgroupID` | the capture hook | Linux |
| `Workload.Kind` | cgroup path | Linux, one of `kubernetes`, `container`, `systemd`, `unknown` |
| `Workload.PodUID` | cgroup path | the process is in a Kubernetes pod |
| `Workload.ContainerID` | cgroup path | the process is in a container |
| `Workload.Unit` | cgroup path | the process is in a systemd unit |
| `Workload.Cgroup` | `/proc/PID/cgroup` | Linux |

## What is deliberately absent

**A pod's namespace and name.** The cgroup path carries the pod's UID and the
container's ID, and nothing else. Namespace and name live in the API server.
Reporting the UID and calling it a UID is accurate; deriving a name for it
would be a guess that reads like a fact, and a consumer cannot tell the two
apart after the fact.

**Anything about the flow's contents.** Attribution says what produced a flow,
never what is in it.

## The terms

**It is optional.** Every field may be empty, and a consumer that ignores all
of them behaves exactly as it did before they existed. `tunless` emits plain
SOCKS5 to any listener; attribution is carried alongside, over the local
metadata endpoint, for consumers that ask.

**It is advisory.** A process that exits between capture and lookup leaves the
process fields empty. A host with no container runtime leaves the workload
fields empty. Neither is an error and neither invalidates the flow.

**The raw cgroup path is retained.** A consumer that disagrees with the parse
in `workload.FromCgroupPath` can redo it from `Workload.Cgroup`, so no parsing
decision made here is final.

## Why a consumer would want it

A transport downstream of `tunless` has to decide what kind of flow it is
carrying: whether to spend parity on it, whether to give it a lane of its own,
whether to protect it from something else. Without attribution those decisions
are made by inference from byte counts and elapsed time, which has two
problems. Volume does not separate a large request from a small transfer -- they
are the same size by construction. And inference needs a second or so of
evidence, by which time a request that completes in 200ms has finished.

Attribution replaces the inference with a fact that was available before the
first byte moved. What the consumer does with it remains the consumer's policy;
`tunless` states what produced the flow and stops there.
