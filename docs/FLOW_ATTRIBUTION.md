# Flow attribution

Capturing at the socket layer tells us more about a flow than a proxy protocol
can carry. SOCKS5 gives you a destination and nothing else. The kernel already
handed us the calling process, and on a host running containers that process
sits in a cgroup that names the pod or container it belongs to.

This document lists what `tunless` makes available about a flow, and what you
can rely on.

## What's available

| Field | Source | Present when |
|---|---|---|
| `PID` | the capture hook | always |
| `Path` | `/proc/PID/exe` | the process still exists at lookup |
| `SigningID` | code signature | macOS |
| `CgroupID` | the capture hook | Linux |
| `Workload.Kind` | cgroup path | Linux; one of `kubernetes`, `container`, `systemd`, `unknown` |
| `Workload.PodUID` | cgroup path | the process is in a Kubernetes pod |
| `Workload.ContainerID` | cgroup path | the process is in a container |
| `Workload.Unit` | cgroup path | the process is in a systemd unit |
| `Workload.Cgroup` | `/proc/PID/cgroup` | Linux |

## What we deliberately don't provide

**A pod's namespace and name.** The cgroup path carries the pod's UID and the
container's ID. Namespace and name live in the API server. We report the UID
and call it a UID. Deriving a name for it would be a guess, and once it's in
the output you can't tell a guess from a fact.

**Anything about a flow's contents.** Attribution says what produced a flow. It
never says what's in it.

## What you can rely on

**It's optional.** Every field can be empty, and a consumer that ignores all of
them works exactly as it did before they existed. `tunless` still emits plain
SOCKS5 to any listener. Attribution rides alongside, over the local metadata
endpoint, for consumers that ask.

**It's advisory.** A process that exits between capture and lookup leaves the
process fields empty. A host with no container runtime leaves the workload
fields empty. Neither is an error, and neither makes the flow less valid.

**The raw cgroup path is kept.** If you disagree with how
`workload.FromCgroupPath` parses something, redo it yourself from
`Workload.Cgroup`. None of our parsing decisions are final.

## The wire shape

Consumers decode these bytes by hand, so the JSON is the contract rather than
the Go type. `GET /v1/flow?source_port=N` over the Unix socket returns:

```json
{
  "process": {
    "PID": 991,
    "Path": "/app/voice-gateway",
    "SigningID": "",
    "CgroupID": 77,
    "Workload": {
      "kind": "kubernetes",
      "pod_uid": "1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809",
      "container_id": "9f8e7d6c5b4a39281706152433425160",
      "cgroup": "/kubepods.slice/..."
    }
  },
  "expires": "2026-08-26T11:27:03+08:00"
}
```

A flow the agent doesn't know returns 404, which is ordinary rather than an
error: a connection it never captured, or one it has already forgotten.

`TestWireShapeForConsumers` pins this from the producing side. Renaming a field
or moving one under a different object would otherwise break a consumer
silently, since the lookup keeps returning 200 and the consumer keeps reading
zeroes.

## Why you'd want this

A transport downstream of `tunless` has to decide what kind of flow it's
carrying: whether to spend parity on it, whether to give it its own lane,
whether to protect it from something else. Without attribution, those decisions
come from byte counts and elapsed time, and that has two problems.

Volume doesn't separate a large request from a small transfer. They're the same
size.

Inference needs a second or so of evidence. A request that finishes in 200ms is
already done by then.

Attribution replaces the guess with something that was available before the
first byte moved. What you do with it is your policy. `tunless` reports what
produced the flow and stops there.
