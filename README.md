<p align="center">
  <img src="assets/tunless-icon.png" alt="Tunless icon" width="160">
</p>

<h1 align="center">tunless</h1>

<p align="center">
  <strong>TUN-less transparent proxying. No fake IP, no route hijack, no second TCP stack.</strong>
</p>

<p align="center">
  <a href="https://github.com/bojieli/tunless/actions/workflows/ci.yml"><img src="https://github.com/bojieli/tunless/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
</p>

`tunless` captures local TCP and UDP flows at the socket layer and hands them to
an ordinary SOCKS5 listener. Applications keep using normal sockets; your
existing mihomo or sing-box instance keeps its nodes, subscriptions, and routing
rules.

## Why tunless?

If you want unmodified applications to use a proxy today, you get two options —
and both have structural problems.

**TUN mode** captures packets, not sockets. To connect that packet stream back
to application-level routing rules it has to fake things: it forges DNS answers
from a fake-IP pool (which leaks into DoH-aware apps, caches, WebRTC, and logs,
and needs `fake-ip-filter` exception lists to stop breaking things), it sniffs
SNI to recover hostnames (a bridge that ECH is removing), and it rewrites the
global routing table with `auto-route` — a routing table entry has no owner, so
a crash leaves your networking broken. It also runs a second userspace TCP/IP
stack alongside the kernel's.

**Explicit HTTP/SOCKS proxy settings** require every application to cooperate.
Most applications ignore them. That is the entire reason TUN mode exists.

`tunless` takes a third path: capture at the **socket layer**, where the
operating system still knows the real destination and the real process.
That gives you transparency without the trade-offs:

- **No fabricated DNS answers** — names resolve normally, to real addresses.
- **No route table mutation** — there is nothing to roll back after a crash.
- **No second TCP/IP stack** — flows stay on the kernel's own sockets.
- **Fail-open by construction** — capture state is owned by the kernel
  (unpinned `bpf_link`, dynamic WFP session, system-extension lifecycle), so if
  `tunless` dies, new traffic simply goes direct. This is tested with SIGKILL,
  not asserted.
- **Keep your proxy stack** — `tunless` only replaces the inbound. Nodes,
  subscriptions, and rules stay in mihomo/sing-box where they belong.

The full design rationale is in [BLUEPRINT.md](BLUEPRINT.md).

## How it works

| Platform | Capture mechanism | Implementation status |
| --- | --- | --- |
| Linux | eBPF cgroup connect/sendmsg/recvmsg and sockops | Host and Docker namespace TCP plus connected/unconnected UDP4/UDP6; trusted DNS override is implemented in the shared SOCKS emitter |
| macOS | `NETransparentProxyProvider` system extension | Notarized universal build passes live trusted-DNS redirection, SOCKS TCP/UDP, HTTP/1.x, HTTP/2, TLS, and concurrency tests |
| Windows | WFP ALE connect-redirect callout | TCP and TCP DNS override source are implemented; WDK, signing, fuzzing, runtime, and UDP DNS gates are unmet |

The portable core includes SOCKS5 TCP/UDP emission, HTTP CONNECT and SOCKS5
reference inbounds, destination/process capture filters, a real-answer DNS
observer, and two opt-in process-metadata transports.

Measured overhead is within **0.4% of direct throughput** (inside WAN
run-to-run spread), at roughly 2.8% of one core and ~9 MB RSS. Every number is
recorded with its host and date in
[measurements and release gates](docs/MEASUREMENTS.md) — demonstrated, not
assumed.

## Quick start (Linux)

Requirements: cgroup v2, kernel 5.7 or newer, and privileges to load and attach
BPF programs. The intended 5.10 floor and a current 6.8 kernel have both passed
the verifier and live runtime suite.

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
not an exception list.

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

Captured queries whose original destination port is 53 are sent to the numeric
`--dns-upstream` through SOCKS5 by default, with query IDs translated per
outstanding request. Use `--disable-dns-override` to retain each application's
original resolver.

### Containers and virtual machines

Containers need **no** TUN device, policy route, NAT rule, proxy environment
variable, or privileged process inside them. One command captures an existing
container:

```console
TUNLESS_UPSTREAM=127.0.0.1:7890 ./scripts/tunless-docker.sh my-dev-container
```

The same helper works on native Linux and macOS Docker Desktop; a PowerShell
equivalent covers Windows Docker Desktop. Watch-mode variants attach to Dev
Containers automatically, and rootful Podman, containerd, and CRI-O have their
own helpers. See [the container notes](docs/CONTAINERS.md).

### macOS and Windows

On macOS, `tunless` is a notarized Network Extension with a small launcher app
and presets for coexisting with Clash Verge. On Windows, the WFP backend is
implemented but not yet release-qualified — treat it as source, not a shippable
driver. Details: [macOS notes](docs/MACOS.md) · [Windows notes](docs/WINDOWS.md).

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

Then start the service with `TUNLESS_UPSTREAM=127.0.0.1:7890`. References:
mihomo [TUN](https://wiki.metacubex.one/config/inbound/tun/) and
[DNS](https://wiki.metacubex.one/en/config/dns/).

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

Point `TUNLESS_UPSTREAM` at `127.0.0.1:7890`. References: sing-box
[TUN](https://sing-box.sagernet.org/configuration/inbound/tun/) and
[mixed inbound](https://sing-box.sagernet.org/configuration/inbound/mixed/).

Downstream `PROCESS-NAME` rules see `tunless`, not the original application.
Move capture-time process selection into the cgroup on Linux or signing-ID
filters on macOS. Destination, domain, node, and subscription rules remain
downstream.

## Project status

The repository is preparing an unpublished candidate; **no public release has
been made**. Reviewable packages, SBOMs, checksums, and OCI output are built
only by the manual non-publishing workflow described in
[the release process](docs/RELEASING.md), and the evidence for each release
gate — including the gates not yet demonstrated — is recorded in
[docs/MEASUREMENTS.md](docs/MEASUREMENTS.md).

## Documentation

| Document | Contents |
| --- | --- |
| [BLUEPRINT.md](BLUEPRINT.md) | Design of record: the thesis, the faults in TUN mode, rejected alternatives |
| [docs/CONTAINERS.md](docs/CONTAINERS.md) | Docker, Podman, containerd/CRI-O, Docker Desktop, VMs |
| [docs/MACOS.md](docs/MACOS.md) | Network Extension build, signing, Clash Verge preset, recovery |
| [docs/WINDOWS.md](docs/WINDOWS.md) | WFP driver design, build, and release gates |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Preflight checks, health API, capacity, DNS override, metadata, recovery |
| [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md) | Dated performance and gate evidence, including what is not demonstrated |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Assets, trust boundaries, risks, and explicit non-goals |
| [docs/RELEASING.md](docs/RELEASING.md) · [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md) | Release procedure and review gates (maintainers) |

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
development setup (`go test -race ./...`, `go vet`, `swift test`, privileged
integration suites) and review expectations. Security reports should follow
[SECURITY.md](SECURITY.md).

`tunless` is local socket capture, not an IP-forwarding proxy: it does not
intercept transit traffic from other machines, raw ICMP, ESP, GRE, or arbitrary
IP protocols, and it is not a VPN, rule engine, proxy protocol collection, GUI,
or mobile backend.

MIT licensed.
