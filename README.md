<p align="center">
  <img src="assets/tunless-icon.png" alt="Tunless icon" width="160">
</p>

# tunless

[![CI](https://github.com/bojieli/tunless/actions/workflows/ci.yml/badge.svg)](https://github.com/bojieli/tunless/actions/workflows/ci.yml)

**TUN-less transparent proxying. No fake IP, no route hijack, no second TCP stack.**

`tunless` captures local TCP and UDP flows at the socket layer and hands them to
an ordinary SOCKS5 listener. Applications keep using normal sockets; your
existing mihomo or sing-box instance keeps its nodes, subscriptions, and routing
rules.

| Platform | Capture mechanism | Implementation status |
| --- | --- | --- |
| Linux | eBPF cgroup connect/sendmsg/recvmsg and sockops | Host and Docker namespace TCP plus connected/unconnected UDP4/UDP6; trusted DNS override is implemented in the shared SOCKS emitter |
| macOS | `NETransparentProxyProvider` system extension | Notarized universal build passes live trusted-DNS redirection, SOCKS TCP/UDP, HTTP/1.x, HTTP/2, TLS, and concurrency tests |
| Windows | WFP ALE connect-redirect callout | TCP and TCP DNS override source are implemented; WDK, signing, fuzzing, runtime, and UDP DNS gates are unmet |

The portable core includes SOCKS5 TCP/UDP emission, HTTP CONNECT and SOCKS5
reference inbounds, destination/process capture filters, a real-answer DNS
observer, and two opt-in process-metadata transports. See
[measurements and release gates](docs/MEASUREMENTS.md) for results that were
actually demonstrated rather than assumed.

The repository is preparing an unpublished candidate; no public release has
been made. Reviewable packages, SBOMs, checksums, and OCI output are built only
by the manual non-publishing workflow described in
[the release process](docs/RELEASING.md).

## Linux quick start

Requirements: cgroup v2, kernel 5.7 or newer, and privileges to load and attach
BPF programs. The intended 5.10 floor and a current 6.8 kernel have both passed
the verifier and live runtime suite; the exact hosts are recorded in
[the measurements](docs/MEASUREMENTS.md).

```console
make
sudo make install
sudo systemctl enable --now tunless
```

The installed unit reads `/etc/tunless.env` if present and defaults to:

```ini
TUNLESS_UPSTREAM=127.0.0.1:7890
TUNLESS_CGROUP=/sys/fs/cgroup/user.slice
TUNLESS_DNS_UPSTREAM=1.1.1.1:53
```

Run mihomo/sing-box as a system service outside `user.slice`. The `tunless`
unit itself runs in `system.slice`; this cgroup separation is loop avoidance,
not an exception list. Do not run both the downstream proxy and `tunless`
interactively inside the cgroup being captured.

For an isolated scope or development test:

```console
sudo ./tunless --upstream 127.0.0.1:7890 \
  --backend linux --cgroup /sys/fs/cgroup/my-apps
```

Destination filters are evaluated in the BPF hook, so excluded flows stay
direct instead of being accepted and then dropped:

```console
sudo ./tunless --upstream 127.0.0.1:7890 \
  --cgroup /sys/fs/cgroup/my-apps \
  --include-destination 0.0.0.0/0 \
  --include-destination ::/0 \
  --exclude-destination 192.168.0.0/16 \
  --exclude-destination fc00::/7
```

On Linux the cgroup is the process filter. Process glob flags are rejected
because a userspace decision after `connect()` would be too late to let a flow
continue direct.

Captured TCP and UDP queries whose original destination port is 53 are sent to
the numeric `--dns-upstream` through SOCKS5 by default. UDP query IDs are
translated per outstanding request and restored with the original resolver
source on reply, so reused IDs and out-of-order responses are unambiguous. Use
`--disable-dns-override` or `TUNLESS_DISABLE_DNS_OVERRIDE=true` to retain each
application's original resolver. `--flow-idle-timeout` and
`--udp-idle-timeout` bound abandoned flows; zero disables the corresponding
timeout.

### Containers and virtual machines

Normal bridge-network containers use namespace-local mode. Tunless opens the
container's network namespace only while creating redirect sockets, restores
its original namespace for the SOCKS relay, and attaches eBPF to the exact
container cgroup. Applications inside the container need no environment
variables, capabilities, proxy configuration, route changes, or TUN device:

```console
make
TUNLESS_UPSTREAM=127.0.0.1:7890 \
  TUNLESS_DNS_UPSTREAM=1.1.1.1:53 \
  TUNLESS_BINARY="$PWD/tunless" \
  ./scripts/tunless-docker.sh my-dev-container
```

The same command works on native Linux and macOS Docker Desktop. On Windows
Docker Desktop use `scripts\tunless-docker.ps1`. Desktop launchers build a
privileged controller inside the Linux VM; the application container remains
unmodified. When the configured SOCKS server is host-loopback, the launcher
also creates a short-lived host bridge so TCP and the separate SOCKS5 UDP relay
are both reachable across the Desktop boundary.

For automatic Dev Container coverage, run the watcher once on the host:

```console
TUNLESS_DOCKER_LABEL=devcontainer.local_folder \
  ./scripts/tunless-docker-watch.sh
```

Omit the label to attach to every running application container. PowerShell has
the equivalent `tunless-docker-watch.ps1`. Controller containers are excluded,
and recreated containers are discovered automatically. Both one-shot and watch
modes detach when the target stops; forced process death leaves new traffic
direct.

On native Linux, rootful Podman uses `tunless-podman.sh` and
`tunless-podman-watch.sh`. A node operator can attach a containerd or CRI-O
workload with `tunless-cri.sh`. Rootless engines cannot provide the host cgroup
and network-namespace authority this socket-layer design needs; the helpers
reject that configuration instead of silently falling back to proxy variables.
Rootful Docker and Podman lifecycle tests pass on RTX-PRO, and the containerd
helper passes inside a disposable kind/Kubernetes node; CRI-O remains an
explicitly untested runtime.

Windows containers share the Windows kernel rather than the Docker Desktop
Linux VM. The host WFP backend therefore covers host applications and Windows
container TCP with one global configuration. That source path includes WFP
redirect-record propagation, but remains release-blocked because no Windows/WDK
runtime was available; UDP remains direct on Windows.

A Docker container with `--network=host` can alternatively be captured when its
cgroup is beneath the normal Linux Tunless cgroup. A full VM is different:
guest socket calls are invisible to host cgroup/WFP/Network Extension hooks, so
run Tunless inside the guest. If guest installation is impossible, whole-VM
transparency requires a packet-layer mechanism such as TUN or TPROXY.

For host-network containers, attach Tunless to a parent and let Docker create
descendants beneath it. Once Docker enables controllers on that parent, Linux
will not allow ordinary processes directly in the parent; use a separate child
for host test processes. Cgroup-parent syntax varies by Docker cgroup driver.

Processes that migrate to another systemd scope are captured only if the new
scope remains under the attached ancestor. For example, attaching to
`user.slice` covers its descendant user scopes, while attaching to one narrow
manually-created leaf does not follow a Snap application that moves itself to a
sibling scope.

The namespace implementation and operational boundaries are detailed in
[the container notes](docs/CONTAINERS.md).

## Migrate from mihomo TUN

Keep `mixed-port` and your rules. Delete the TUN block, DNS hijack, fake-IP pool,
and fake-IP filters. Current mihomo calls its real-answer mode `redir-host`.

```diff
 mixed-port: 7890
-tun:
-  enable: true
-  stack: mixed
-  auto-route: true
-  auto-redirect: true
-  auto-detect-interface: true
-  dns-hijack: ["any:53", "tcp://any:53"]
 dns:
   enable: true
-  enhanced-mode: fake-ip
-  fake-ip-range: 198.18.0.1/16
-  fake-ip-filter: [...]
+  enhanced-mode: redir-host
```

Then start the service with `TUNLESS_UPSTREAM=127.0.0.1:7890`. The current
mihomo TUN and DNS fields are documented in its
[TUN](https://wiki.metacubex.one/config/inbound/tun/) and
[DNS](https://wiki.metacubex.one/en/config/dns/) references.

## Migrate from sing-box TUN

Remove the `tun` inbound and any `hijack-dns` rules used solely by it. Keep or
add a loopback `mixed` inbound for `tunless`:

```diff
 "inbounds": [
   {
-    "type": "tun",
-    "tag": "tun-in",
-    "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"],
-    "auto_route": true,
-    "auto_redirect": true,
-    "strict_route": true,
-    "stack": "mixed"
+    "type": "mixed",
+    "tag": "tunless-in",
+    "listen": "127.0.0.1",
+    "listen_port": 7890,
+    "set_system_proxy": false
   }
 ]
```

Point `TUNLESS_UPSTREAM` at `127.0.0.1:7890`. The current schema is in the
official sing-box [TUN](https://sing-box.sagernet.org/configuration/inbound/tun/)
and [mixed inbound](https://sing-box.sagernet.org/configuration/inbound/mixed/)
documentation.

Downstream `PROCESS-NAME` rules see `tunless`, not the original application.
Move capture-time process selection into the cgroup on Linux or signing-ID
filters on macOS. Destination, domain, node, and subscription rules remain
downstream.

## macOS

The containing app is a bare launcher. Build it with:

```console
brew install xcodegen
xcodegen generate --spec macos/project.yml
xcodebuild -project macos/Tunless.xcodeproj -scheme Tunless \
  -configuration Release -derivedDataPath build build
```

After signing with the Network Extension and System Extension entitlements,
place `Tunless.app` in `/Applications`. When Clash Verge is the existing proxy
client, keep its mixed/SOCKS listener and rules, disable its TUN mode, and use
the focused companion preset:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless \
  check --preset clash-verge --upstream 127.0.0.1:7897
/Applications/Tunless.app/Contents/MacOS/Tunless \
  start --preset clash-verge --upstream 127.0.0.1:7897
/Applications/Tunless.app/Contents/MacOS/Tunless status
/Applications/Tunless.app/Contents/MacOS/Tunless stop
/Applications/Tunless.app/Contents/MacOS/Tunless cleanup
```

The preset adds only the known Clash Verge process exclusions and defaults to
port 7897; an explicit `--upstream` always wins. It does not import or replace
Clash rules, nodes, subscriptions, or UI. `check` verifies SOCKS5 negotiation
before capture is enabled, and preset-based `start` performs the same preflight
automatically. The launcher also accepts the same repeated process/destination
filter names as the Go CLI. macOS process patterns match signing identifiers.
Re-running `start` updates a running provider, while `telemetry` prints and
drains its bounded JSON flow buffer. `status` is non-destructive and reports
the active state, credential-free upstream, DNS upstream, and recognized
preset. `stop` disables capture but retains its configuration; `cleanup` stops
capture, removes every Tunless transparent-proxy configuration, and requests
Network Extension deactivation. A bounded recovery script is bundled at
`Tunless.app/Contents/Resources/tunless-cleanup`. If Tunless cannot respond at
all, the Network Extension can always be disabled manually under **System
Settings > General > Login Items & Extensions > Network Extensions**. First
activation requires normal macOS user approval. Legacy `--stop`, `--cleanup`,
and `--telemetry` spellings remain supported.
Detailed signing, Clash loop exclusions, and runtime validation are in
[the macOS notes](docs/MACOS.md).

## Windows

The WFP driver and Go redirect service are under `windows/driver` and
`backend/windows`. TCP is filtered at ALE connect-redirect; UDP is deliberately
left direct until a Windows UDP datapath passes its own gate. The userspace
service applies the same trusted-resolver rewrite to captured TCP port 53,
unless `--disable-dns-override` is set. It queries the accepted socket's redirect context and records, then sets
those records on the outbound socket before `connect()`, as required for
cooperation with other WFP redirectors. Do not deploy this driver from an
unvalidated build. See [the Windows notes](docs/WINDOWS.md).

## Optional real-answer DNS observation

The observer forwards UDP and TCP DNS without changing answers, records A/AAAA
TTL mappings, and supplies a hostname only when exactly one unexpired name maps
to the address. Ambiguous CDN addresses remain IP-only.

```console
tunless --upstream 127.0.0.1:7890 \
  --dns-listen 127.0.0.1:5353 --dns-upstream 1.1.1.1:53
```

Point selected clients at that listener yourself. It is opt-in and never edits
system DNS. Both UDP and TCP observer exchanges use the configured SOCKS5
upstream rather than opening a direct resolver socket.

## Diagnostics and health

Before starting privileged Linux capture, validate the exact embedded BPF
program, cgroup topology, loop avoidance, and both SOCKS5 commands:

```console
sudo tunless --upstream 127.0.0.1:7890 \
  --backend linux --cgroup /sys/fs/cgroup/my-apps --check
```

`--check` prints JSON and does not leave capture attached. For monitoring, add
`--status-listen 127.0.0.1:6060`; `GET /healthz` is a liveness response and
`GET /v1/status` reports bounded flow counters, backend resources, BPF map
occupancy, and the credential-free upstream address. The API accepts only a
numeric loopback listener. `--max-flows` defaults to 4096; excess flows are
failed immediately and counted instead of allowing unbounded goroutine growth.
See [operations](docs/OPERATIONS.md).

## Optional process metadata

`--metadata-socket /run/tunless/metadata.sock` exposes:

```text
GET /v1/flow?source_port=54321
```

over a mode-`0600` Unix socket. Entries exist only for the lifetime of the
SOCKS control connection. `--metadata-username` instead encodes
`pid=...;path=...;signing-id=...` as the SOCKS5 username and requires the
upstream to accept username/password negotiation.

## Development

Source builds require Go 1.25 or newer. The module toolchain directive and
container build pin Go 1.26.6 so released binaries do not silently inherit
known standard-library vulnerabilities from an older local compiler.

```console
go test -race ./...
go vet ./...
cd macos && swift test
sudo TUNLESS_BINARY=./tunless SINGBOX_BINARY=sing-box \
  ./scripts/integration-linux.sh
./scripts/benchmark-wan.sh
```

The committed eBPF object is built from
[`backend/linux/bpf/tunless.bpf.c`](backend/linux/bpf/tunless.bpf.c). Run the
benchmark on the Linux capture host and set `TUNLESS_PID`,
`TUNLESS_PROXY_PID`, `TUNLESS_CGROUP`, and `TUNLESS_UPSTREAM` as needed.
Every push and pull request runs the race suite, vet, Linux/Windows builds,
Swift tests, Docker build, shell parsing, and `govulncheck`. Scheduled checks
add privileged kernel integration, fuzzing, CodeQL, full-history secret
scanning, and public-only OpenSSF Scorecard analysis. Security reports
should follow [`SECURITY.md`](SECURITY.md).

This project is local socket capture, not an IP-forwarding proxy. Container
support attaches inside the container's cgroup and network namespace; Tunless
does not intercept transit bridge packets merely because they cross the host.
It also does not capture other machines, raw ICMP, ESP, GRE, or arbitrary IP
protocols. It is not a VPN, rule engine, proxy protocol collection, GUI, or
mobile backend.

MIT licensed. [`BLUEPRINT.md`](BLUEPRINT.md) remains the design of record.
Contribution, support, governance, threat-model, and release-review policies
are linked from [`CONTRIBUTING.md`](CONTRIBUTING.md).
