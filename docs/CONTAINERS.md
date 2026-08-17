# Containers and virtual machines

Tunless does not require a dev container to understand proxy settings. Its
Linux container mode preserves the host socket-layer architecture:

1. the controller opens the target container's network namespace only long
   enough to create TCP4/TCP6 and UDP4/UDP6 redirect sockets;
2. it restores its original namespace before starting the SOCKS relay;
3. eBPF links attach to the exact container cgroup, so ordinary application
   `connect()` and UDP operations reach loopback in that container namespace;
   and
4. outbound SOCKS connections originate outside the captured cgroup and remain
   able to reach the configured upstream.

There is no TUN device, policy route, NAT rule, proxy environment variable, or
privileged process inside the application container. Listener ports are chosen
dynamically per namespace. Process exit closes unpinned BPF links, retaining
fail-open behavior.

## Platform matrix

| Host / engine | Application containers | Capture path |
| --- | --- | --- |
| Native Linux | Linux | Host Tunless, namespace-local sockets, container cgroup eBPF |
| Native Linux, rootful Podman | Linux | Same host namespace/cgroup path; Podman `libpod` scope identity is verified |
| Kubernetes node, containerd | Linux | Per-container `crictl` helper validated on a disposable kind/Kubernetes node |
| Kubernetes node, CRI-O | Linux | Source-complete per-container helper; runtime qualification pending |
| macOS Docker Desktop | Linux | Privileged Tunless controller in LinuxKit; temporary local SOCKS bridge when needed |
| Windows Docker Desktop | Linux | Privileged Tunless controller in the Desktop Linux VM; temporary local SOCKS bridge when needed |
| Windows Docker engine | Windows | Global host WFP backend for host and container TCP; Windows UDP stays direct |

The first three rows use the same Linux backend. The Desktop controller joins
the VM's host PID and cgroup namespaces, bind-mounts cgroup v2, creates listeners
in the application container's network namespace, then relays from its own
uncaptured namespace. `--privileged`, `--pid host`, and `--cgroupns host` apply
only to that controller. They are never added to the application container.

## One container

Build or install Tunless on a native Linux host, start the container normally,
and run:

```console
TUNLESS_UPSTREAM=127.0.0.1:7890 \
  TUNLESS_BINARY=/usr/local/bin/tunless \
  ./scripts/tunless-docker.sh CONTAINER_NAME_OR_ID
```

The helper obtains the live init PID from Docker, derives the exact cgroup-v2
path from `/proc/PID/cgroup`, and supplies `/proc/PID/ns/net` to
`--network-namespace`. It refreshes the PID after image/bridge preparation and
passes the expected full container ID; Tunless refuses attachment if PID reuse
changed the cgroup. The helper remains in the foreground and terminates Tunless
when the container stops. `SIGHUP`, `SIGINT`, and `SIGTERM` perform the same
cleanup. Pass ordinary Tunless flags after the container name.

Rootful Podman on native Linux uses the same implementation:

```console
TUNLESS_UPSTREAM=127.0.0.1:7890 \
  TUNLESS_BINARY=/usr/local/bin/tunless \
  ./scripts/tunless-podman.sh CONTAINER_NAME_OR_ID
```

Use `tunless-podman-watch.sh` for lifecycle discovery. Rootless Docker and
Podman cannot attach host cgroup BPF or enter another process's network
namespace; the launchers detect rootless mode and stop with an actionable
error. A rootful host controller is required. The application container itself
remains unprivileged.

On macOS Docker Desktop, omit `TUNLESS_BINARY`; the helper builds
`packaging/docker/Dockerfile` and launches the Linux controller. On Windows
Docker Desktop use PowerShell:

```powershell
$env:TUNLESS_UPSTREAM = '127.0.0.1:7890'
.\scripts\tunless-docker.ps1 CONTAINER_NAME_OR_ID
```

The helper requires Docker API access. Native Linux runs Tunless with `sudo`
because loading cgroup BPF and entering a network namespace require host
privileges. Docker Desktop puts those privileges in the controller. The target
container receives no capability and never mounts the host cgroup tree.

Docker's private resolver is part of the container dataplane, not an external
destination. Tunless reads the target's `/etc/resolv.conf` and automatically
keeps only loopback, private, and link-local nameserver addresses direct. A
public resolver remains captured. This was exercised with Docker Desktop's
`192.168.65.7` resolver and native Docker's `127.0.0.11` resolver.

SOCKS5 UDP association usually returns a separate UDP relay port. Rewriting
only `127.0.0.1` to `host.docker.internal` handles TCP but can leave that relay
unreachable. When the configured upstream is host-loopback, the macOS and
PowerShell launchers therefore run a temporary loopback Tunless bridge on the
host. The controller uses the bridge, which forwards TCP and UDP to the original
authenticated or unauthenticated upstream. Set `TUNLESS_DOCKER_BRIDGE=never`
only when the supplied upstream is already fully reachable from the Desktop VM.
An installed bridge binary can be selected with
`TUNLESS_DOCKER_BRIDGE_BINARY`.

Start one helper for each cgroup. Containers sharing a network namespace may
still have separate cgroups, so attaching each independently is safe; each
instance has its own BPF maps and dynamically chosen listener port. When a
container is recreated, its PID, namespace, and cgroup change. The one-shot
helper exits, while watch mode attaches the replacement automatically.

## All containers and Dev Containers

Run one host supervisor to discover running containers and follow lifecycle
changes:

```console
TUNLESS_UPSTREAM=127.0.0.1:7890 ./scripts/tunless-docker-watch.sh
```

The PowerShell equivalent is:

```powershell
$env:TUNLESS_UPSTREAM = '127.0.0.1:7890'
.\scripts\tunless-docker-watch.ps1
```

By default the watcher attaches to every running application container and
automatically excludes its own controllers. To cover only VS Code Dev
Containers and compatible tooling, select the label those containers carry:

```console
TUNLESS_DOCKER_LABEL=devcontainer.local_folder \
  ./scripts/tunless-docker-watch.sh
```

This is host-side configuration. Nothing is added to `devcontainer.json`, the
image, the container environment, or the application command. Run the normal
host Tunless backend at the same time; both use `TUNLESS_UPSTREAM` and the same
destination flags while retaining the correct platform capture mechanism.

DEB/RPM installations include the helpers under `/usr/libexec/tunless` and an
opt-in `tunless-container-watch.service`. Its default label gate is
`com.bojieli.tunless`; `examples/compose.yaml` demonstrates it. Review
`/etc/tunless.env`, label selected containers, then enable the watcher. The
ordinary `tunless.service` can run simultaneously for host applications:

```console
sudo systemctl enable --now tunless tunless-container-watch
```

Set `TUNLESS_CONTAINER_ENGINE=podman` in the environment file for rootful
Podman. Neither unit is enabled automatically by package installation.

## Kubernetes and CRI runtimes

On a containerd or CRI-O node, a root operator can attach one running workload
container by its CRI ID:

```console
sudo TUNLESS_UPSTREAM=127.0.0.1:7890 \
  TUNLESS_BINARY=/usr/local/bin/tunless \
  ./scripts/tunless-cri.sh "$(sudo crictl ps --name my-app --quiet)"
```

The helper asks the configured CRI endpoint for the full ID, running state, and
host PID, then Tunless independently verifies that PID's cgroup component is an
exact `cri-containerd-…scope` or `crio-…scope` match. It polls identity and PID
and detaches when the container stops or is replaced. This is intentionally a
node-side privileged operation; mounting the runtime socket into an ordinary
workload would grant a host-control capability and is not recommended.

The one-container path passed on a disposable kind v0.30.0 Kubernetes v1.34.0
node backed by containerd: TCP and UDP from an unmodified pod used Tunless, all
seven links and map diagnostics were present, and pod deletion detached the
helper. `scripts/integration-cri-kind.sh` reproduces that test and deletes only
the uniquely named cluster it creates. CRI-O remains untested.

Automatic cluster-wide policy/controller behavior remains experimental rather
than being hidden in a privileged DaemonSet. Operators should first validate
the one-container helper against their runtime's cgroup driver. Full VMs still
require an in-guest installation as described below.

## Windows containers

Windows containers use the host Windows kernel and WFP layers. When Docker is
in Windows-container mode, `tunless-docker.ps1` starts the elevated global WFP
backend instead of a Linux controller. Its ALE connect-redirect filters have no
compartment restriction, set `localRedirectTargetPID`, query redirect context
and opaque redirect records on accepted sockets, and set those records on every
outbound SOCKS socket before connect. One service configuration is therefore
intended to cover ordinary host processes and Windows-container TCP.

This path is source-complete but not release-qualified: the available machines
did not include Windows plus WDK, so the driver has not been built, loaded under
Driver Verifier, or exercised in a Windows container. UDP is deliberately
direct on Windows. The PowerShell launchers were parser-checked and the Go
service cross-built, which is not a substitute for that runtime gate.

## Host-network containers

`--network=host` containers do not need namespace-local listeners. They can be
captured by placing their cgroup beneath the cgroup used by the normal host
Tunless service. With Docker's cgroup-v2 `cgroupfs` driver, the tested form was
`--cgroup-parent=/tunless-containers`; other cgroup drivers use different parent
syntax.

Once Docker enables controllers and creates descendants, the cgroup parent is
an internal node and cannot also hold ordinary host processes. Put host
processes in a separate child instead of writing them directly to that parent.

## Boundaries

Attaching host-loopback mode to a bridge container without
`--network-namespace` redirects traffic to the container's private `127.0.0.1`,
where no relay is listening. The measured result is `ECONNREFUSED`; this is why
the namespace-local listener is required.

Full VMs are different. Guest socket calls occur in the guest kernel and are
not visible to a host cgroup hook, WFP service, or Network Extension. TAP,
bridge, and kernel-NAT traffic is packet forwarding, so install Tunless inside
the guest when socket-layer behavior is required. A host QEMU/SLIRP process can
be captured only for connections it creates itself. If guest installation is
impossible, whole-VM transparency is inherently a packet-layer problem and TUN
or TPROXY is the appropriate mechanism.
