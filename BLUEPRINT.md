# tunless — blueprint

Status: design of record. All stages now have implementation artifacts; release
gates are recorded in `docs/MEASUREMENTS.md`. Every claim in §3 that remains
marked **unverified** is still an assumption, not a completed measurement.

---

## 1. Framing

### 1.1 What this is

`tunless` captures outbound network flows at the **socket layer** and hands them
to an ordinary SOCKS5 proxy. It is a replacement for the TUN mode of Clash /
mihomo / sing-box / tun2proxy, and nothing else.

The application is unaware. It calls `connect()` to `api.example.com:443` and
gets a working connection. It does not read a proxy environment variable, does
not need to speak SOCKS, and does not need to be recompiled or restarted. That
is the same property TUN mode provides, and it is the only reason TUN mode
exists.

The difference is what happens underneath.

### 1.2 The two structural faults in TUN mode

**Fault one: it captures at L3 and makes policy at L7.**

A TUN device hands you IP packets. A rule engine wants to decide based on domain
names. Those are irreconcilable, so the ecosystem bridges them with **fake-IP**:
hijack port 53, hand the application a fabricated address from `198.18.0.0/16`,
remember the mapping, recover the domain at connect time.

The bridge is made of forged DNS, and it leaks:

- Any application that resolves its own names bypasses it entirely — DoH in
  Firefox and Chrome, hardcoded resolvers, anything in a container. Domain rules
  silently never match. There is no error; the rule just doesn't fire.
- Fake addresses escape the process. They get cached by applications, embedded
  in WebRTC candidates, written to logs, handed to subprocesses. When the tunnel
  stops, those applications are dialing a black hole.
- The mapping is created at resolve time and consumed at connect time, with an
  LRU in between whose eviction policy is unrelated to the TTL the application
  was given.
- Split-horizon DNS, `.local` names, corporate internal zones and IP-based ACLs
  all break, which is why `fake-ip-filter` exists. An exception list is the
  tell: the mechanism is wrong and is being patched per case.

The newer answer is **sniffing** — peek at the first bytes, read the SNI or Host
header, ignore the fake address. That is a tacit admission that fake-IP was the
wrong bridge, and it costs a buffered peek on every connection, works only for
TLS and plaintext HTTP, and **Encrypted Client Hello removes it**.

So there are two bridges. DoH is eroding one and ECH is scheduled to remove the
other. Neither is a foundation to build on.

**Fault two: it mutates global OS state with no crash-safe rollback.**

`auto-route` rewrites the routing table — typically the `0.0.0.0/1` +
`128.0.0.0/1` split so it outranks the real default without deleting it — and on
Windows also touches DNS settings and interface metrics. On clean exit it undoes
all of it.

Clean exit is the only path that works. SIGKILL, a panic, an OOM kill, a hard
power-off, or a sleep/wake that reshuffles interfaces mid-teardown, and the
machine is left with a default route pointing at a device that no longer
forwards. Total loss of connectivity, and the remedy requires knowing to inspect
the routing table.

This is not a bug that can be fixed. There is no kernel primitive in use whose
destruction the OS guarantees. A routing table entry has no owner.

**And a third, smaller: loop avoidance is an exception list.**

Once you own the default route, your own traffic to the proxy server hits your
own TUN. Every remedy is "please don't recurse" rather than a structural
separation: pin a host route to the server (breaks when the address changes, when
it's a hostname, when there are several, when the gateway changes), `fwmark` +
policy routing (Linux only), or bind to the physical interface (races network
changes, ambiguous with several interfaces up).

### 1.3 The thesis

**Intercept at the socket layer instead. All three desktop platforms have a
native primitive for it.**

| Platform | Primitive |
| --- | --- |
| Linux | eBPF `cgroup/connect4` + `connect6`, with `sockops` and a socket-cookie map |
| macOS | `NETransparentProxyProvider` system extension |
| Windows | WFP callout at `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4` / `_V6` |

They share nothing in implementation and everything in what they yield:

- **The real destination**, as the application supplied it. No fabrication.
- **Native process identity** — a code-signing identifier on macOS, an app ID and
  PID on Windows, pid and cgroup on Linux. Not a per-connection socket-owner
  lookup that races short-lived processes.
- **Often the real hostname** on macOS, when the application resolved through the
  system stack.
- **No routing table to mutate**, therefore no crash-leaves-machine-offline mode.
- **Kernel-owned teardown.** An unpinned `bpf_link` detaches when its fd closes.
  A WFP session opened with `FWPM_SESSION_FLAG_DYNAMIC` deletes every filter it
  created when the handle closes. A dead system extension stops diverting flows.
  In all three cases the kernel reverts the change when the process dies.
- **Structural loop avoidance.** The proxy's own egress is not subject to the
  hook — a different cgroup, a PID check, a flow the extension is never handed.
  Not a list to maintain.
- **No second TCP/IP stack.** No gVisor or lwIP in the datapath, no per-packet
  CPU cost, no fixed MTU guess, no broken PMTU discovery, and no reshaping of
  the application's write pattern before anything downstream observes it.
- **Honest diagnostics.** ICMP is not synthesized. `ping` and `traceroute`
  continue to report reality.

### 1.4 What this is not

This section is load-bearing. The project fails if it grows past it.

- **Not a rule engine.** No routing rules, no policy groups, no subscription
  parsing, no GEOIP database. That is mihomo's and sing-box's job and they are
  good at it.
- **Not a proxy protocol.** No VMess, no Trojan, no Hysteria, no TUIC. `tunless`
  speaks SOCKS5 upstream and stops.
- **Not a transport.** It does not touch the wire between you and a server.
- **Not a VPN.** No tunnel, no virtual interface, no encryption of its own.
- **Not a GUI.**
- **Not a LAN gateway.** Socket-layer capture is local-process-only by
  construction. If you need the machine to proxy *other devices'* traffic, you
  need TUN or TPROXY and this project cannot help you. **Decide this early — it
  is the one capability difference that is not recoverable later.**
- **Not iOS or Android.** Neither exposes a flow-level API to third-party apps;
  both force `NEPacketTunnelProvider` / `VpnService`, which is a TUN. Out of
  scope permanently.

### 1.5 Why now

Fake-IP and SNI sniffing are both in decline for reasons outside anyone's
control — DoH adoption and ECH standardization respectively. The socket-layer
primitives, meanwhile, have all matured: `NETransparentProxyProvider` since
macOS 11, `bpf_link` since kernel 5.7, WFP connect-redirect for far longer. The
crossing point has already happened.

---

## 2. What it replaces, concretely

The adoption story is that a user changes one config block and keeps everything
else — rules, subscriptions, proxy nodes, GUI.

**Before** (mihomo):

```yaml
tun:
  enable: true
  stack: gvisor
  auto-route: true
  auto-detect-interface: true
  dns-hijack: ["any:53"]
mixed-port: 7890
dns:
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter: [...]
```

**After**:

```yaml
mixed-port: 7890
dns:
  enhanced-mode: normal      # real answers, no hijack, no pool
```

```console
$ tunless --upstream 127.0.0.1:7890
```

Everything that existed to manage TUN's failure modes disappears from the
config: the stack choice, the MTU, `auto-route`, `auto-detect-interface`, the
fake-IP pool and its filter list, the DNS hijack.

**The direction of the datapath matters and is easy to get backwards.**
`tunless` is a SOCKS5 **client**. It captures a flow, dials the downstream
proxy's existing SOCKS5 listener, issues `CONNECT`, and pipes bytes. The
downstream client applies its rules and dials its outbound. `tunless` never
listens for proxied traffic and never terminates TLS.

---

## 3. Design

### 3.1 The one abstraction

Everything platform-specific lives behind a single interface. Everything above
it is portable Go.

```go
type Proto uint8 // TCP, UDP

type ProcessInfo struct {
    PID       int32
    Path      string // executable path, best effort
    SigningID string // macOS code-signing identifier; Windows app ID; empty on Linux
    CgroupID  uint64 // Linux only
}

type Flow struct {
    Proto    Proto
    OrigDst  netip.AddrPort // always populated, always real
    Hostname string         // may be empty — see §3.4
    Process  ProcessInfo
    Conn     net.Conn       // TCP: a bidirectional stream
    Packets  PacketPort     // UDP: datagram in/out with per-packet dst
}

type Backend interface {
    Start(context.Context) (<-chan Flow, error)
    Close() error
}
```

The SOCKS5 emitter, the capture filter, the DNS observer, metrics, and the CLI
are written once against this and never learn which OS they are on. The
divergence is confined to three `Backend` implementations.

**This abstraction is the most important decision in the project.** Get it right
and the per-platform work is a shim. Get it wrong and every platform leaks into
the core.

### 3.2 Where policy lives

`tunless` carries a **capture filter** and nothing more: which processes and
which destinations to capture, expressed as include/exclude lists. Everything
captured goes upstream; everything else goes direct, untouched.

Rich routing stays downstream, keyed on destination and hostname, where it
already works.

This split exists for one reason: **it requires no cooperation from any existing
client.** SOCKS5 has no field for process identity, so a downstream `PROCESS-NAME`
rule against a `tunless` inbound would resolve to `tunless` itself, not the real
application. Rather than patch every client, process policy lives here, where the
identity is native and free.

Two ways to convey identity downstream are deferred, not rejected:

- Stuff `pid=/path=/signing-id=` into the SOCKS5 **username** field. Works with
  unmodified clients that accept user/pass auth, but they will not parse it into
  rules.
- A local metadata API on a unix socket, keyed by source port, returning the
  process for a flow. Clean, but requires an upstream patch to mihomo/sing-box.

Both are stage 5. Neither is on the critical path.

### 3.3 Platform backends

#### 3.3.1 Linux — eBPF cgroup connect hook

Three cooperating programs, which is the shape that actually works:

1. **`cgroup/connect4` and `connect6`** — fires inside `connect()`. Rewrite the
   destination to the local listener; store the original destination in a map
   keyed by the socket cookie (`bpf_get_socket_cookie`).
2. **`sockops`** — fires on established connection. Record
   `(src_ip, src_port) → cookie`, which is the bridge the listener needs, because
   the accepted socket's own cookie is not the client's.
3. **Listener side** — `getpeername()` on the accepted connection yields
   `(src_ip, src_port)`; look up the cookie, then the original destination.

An alternative is a `cgroup/getsockopt` hook servicing `SO_ORIGINAL_DST`, which
keeps the userspace side conventional at the cost of a third kernel program.
Pick one in stage 1 and measure; do not carry both.

- **Loop avoidance**: attach to a cgroup that does not contain `tunless`. Run
  under its own systemd slice. The proxy's egress is structurally outside the
  hook — nothing to configure, nothing to keep correct across network changes.
- **Teardown**: create the attachment as an unpinned `bpf_link`. The kernel
  detaches it when the last fd closes, including on SIGKILL.
- **UDP**: `connect4/6` covers connected UDP. Unconnected UDP needs
  `cgroup/sendmsg4/6` and `recvmsg4/6`, which have materially different
  semantics. Treat UDP as its own gate, not a footnote to TCP.
- **Requires**: cgroup v2, `CAP_BPF` + `CAP_NET_ADMIN`, kernel ≥ 5.7 for
  `bpf_link`. Target 5.10 as the floor.
- **Loader**: `cilium/ebpf`.
- **Does not cover** forwarded traffic. For a router box the answer is TPROXY,
  which is a legitimate fourth backend if anyone wants it, and is out of scope
  for v1.

#### 3.3.2 macOS — `NETransparentProxyProvider` system extension

A system extension (Swift) plus the Go core.

The critical constraint: **`NEAppProxyFlow` is not a file descriptor.** It is a
read/write API (`readData`/`write`, `readDatagrams`/`writeDatagrams`). You cannot
hand it to another process. Therefore **the extension itself must move the
bytes**, which means the extension speaks SOCKS5 outbound — roughly 500 lines of
Swift — and the Go core is a control plane over XPC providing configuration and
receiving telemetry.

This is a real asymmetry with the other two backends and the abstraction in §3.1
must survive it. Most likely the macOS `Backend` is a thin XPC shim whose `Flow`
channel carries metadata while the extension handles the datapath, and the core's
generic SOCKS5 emitter is bypassed on this platform. **Resolve this in stage 2
before writing the Swift**; if the abstraction cannot absorb it cleanly, change
the abstraction, not the platform.

What the flow yields:

- `flow.metaData.sourceAppSigningIdentifier` and `sourceAppAuditToken` — process
  identity as a signing identity, handed over by the kernel. Not a path to be
  trusted, not a PID to be raced.
- `flow.remoteEndpoint` — the real destination.
- `flow.remoteHostname` — the name, **when the application connected by name
  through the system stack** (URLSession, Network.framework, ordinary
  `getaddrinfo`). An application that resolves independently and connects to a
  literal yields only the address. **Unverified: what fraction of real
  applications actually yield a hostname. Stage 2 must measure this before any
  design depends on it.**

- **Interest declaration**: `NENetworkRule`s in
  `NETransparentProxyNetworkSettings.includedNetworkRules`, matched on
  destination, port and protocol. Process filtering happens in `handleNewFlow`,
  not in the rules.
- **Teardown**: extension exits, the system stops diverting, flows go direct.
  Fail-open without doing anything.
- **Known gaps**: some system daemons and other network extensions are not
  diverted; localhost is not included by default; the UDP flow path has
  historically been rougher than TCP. **Stage 2 must enumerate what is missed,
  not assume it is nothing.**
- **Entitlements**: `com.apple.developer.networking.networkextension` containing
  `app-proxy-provider-systemextension`, plus
  `com.apple.developer.system-extension.install` on the containing app. Paid
  Apple Developer Program ($99/yr). Developer ID signing and notarization; the
  Mac App Store does not distribute system extensions. The containing app must
  live in `/Applications` unless `systemextensionsctl developer on`.

#### 3.3.3 Windows — WFP connect-redirect callout

A kernel-mode callout driver (C) plus a userspace Go service.

- Classify at `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4` / `_V6`. Acquire writable
  layer data, rewrite remote address and port to the local listener, attach a
  redirect handle and a redirect context.
- Userspace recovers the **original** destination with
  `WSAIoctl(SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS)` and the context with
  `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`.
- Process identity comes from the layer's app-ID and process-ID fields. Native.
- **Loop avoidance**: skip redirect when the connecting PID is ours.
- **Teardown**: open the engine with `FWPM_SESSION_FLAG_DYNAMIC`. Every filter
  added in that session is deleted automatically when the session handle closes,
  including on process death. The driver stays loaded; redirection simply stops.
  Fail-open.
- **Cost**: EV code-signing certificate (~$300–600/yr, key on hardware or cloud
  HSM), Microsoft Partner Center enrollment gated on holding that certificate,
  then attestation signing (free once enrolled, and sufficient — full WHQL is
  only needed for Windows Update distribution). Attestation-signed drivers load
  on Windows 10 1607+ with Secure Boot.
- **Risk**: a driver defect is a bugcheck, not a crash. This is the only
  component in the project with an irreversible blast radius, and the only one
  with a hard monetary floor. **Deliberately last.**

### 3.4 Names, without lying

**Do not hijack DNS. Do not fabricate addresses. Ever. This is the project's
reason to exist.**

Hostname recovery, in order of preference:

1. **macOS**: use `flow.remoteHostname` when present. This is the truth, handed
   over by the OS, and it is immune to both DoH and ECH.
2. **Optional DNS observer** (stage 5, opt-in): a resolver that returns **real**
   answers and records `(client, name, address, timestamp)` on the side. Policy
   consults the side table at connect time. Nothing fabricated ever leaves the
   process, so nothing leaks into application caches, and if `tunless` dies the
   machine's DNS was never poisoned.

   The honest cost: this mapping is many-to-one. A CDN address serving fifty
   domains is ambiguous, where fake-IP is unambiguous by construction. **That
   ambiguity is the actual reason fake-IP won, and pretending otherwise would
   repeat the mistake in a new form.** For ambiguous cases, pass the address
   downstream and let the downstream client sniff if it chooses.
3. **Otherwise**: pass the real address. An unknown name is reported as unknown.

`tunless` never sniffs. If a downstream client wants SNI, it can peek at its own
inbound; that is its decision and its ECH problem.

### 3.5 Fail-open is an invariant, not a feature

Stated as a testable property, because it is the single biggest user-visible
improvement over TUN and it is easy to lose by accident:

> If the `tunless` process dies by any means, including `SIGKILL`, the machine's
> network connectivity must be unchanged from before `tunless` started, with no
> manual remediation.

Every backend must pass a conformance test that starts a bulk transfer, sends
`SIGKILL`, and asserts that a fresh connection succeeds immediately. This test
exists from stage 0 and no backend ships without it.

### 3.6 What is not captured

Stated plainly so nobody discovers it as a surprise:

- Anything that is not TCP or UDP — ESP, GRE, SCTP, raw ICMP from applications.
  These go direct, unmodified. TUN drops them; `tunless` is at worst equal here
  and is honest about it.
- Traffic from other machines. See §1.4.
- On macOS, whatever the system declines to divert — to be enumerated in stage 2.

---

## 4. Implementation plan

Each stage has a gate that can fail. A gate that has not been demonstrated is
recorded as not met, not as pending.

### Stage 0 — skeleton and conformance harness

**Implementation status (2026-08-17): complete; gate met.**

- Go module, repo layout, the `Backend` interface from §3.1.
- The generic core: SOCKS5 client emitter, capture filter, CLI, structured logs.
- A **`loopback` reference backend** — an ordinary explicit SOCKS5/HTTP listener
  that fabricates `Flow` values from its own inbound. It captures nothing and
  needs no privileges, and it exists so the core can be developed and tested on
  any machine with no kernel work at all.
- The **conformance suite**, which every backend must pass:
  original destination preserved exactly; process identity present and correct;
  TCP half-close in both directions; a large upload and a large download;
  cancellation mid-transfer; IPv6; UDP; and the §3.5 SIGKILL test.

**Gate**: the `loopback` backend passes conformance end to end with mihomo
downstream.

### Stage 1 — Linux backend

**Implementation status (2026-08-17): complete on kernel 5.10 ARM64 and kernel
6.8 x86-64, including the live TCP/UDP/browser/fail-open and Docker namespace
gates.**

First because it is free, needs no signing, has the best teardown semantics, and
is where the abstraction gets its first real test.

- The three eBPF programs from §3.3.1, loaded with `cilium/ebpf`.
- cgroup-based scope and loop avoidance under a systemd slice.
- TCP first. UDP is a separate gate.

**Gate**: conformance passes for TCP and UDP on kernel 5.10 and current stable;
a real browser and a CLI tool both work through mihomo unchanged; `SIGKILL`
under load leaves connectivity intact.

### Stage 2 — macOS backend

**Implementation status (2026-08-17): source and unsigned build complete;
provisioned activation and measurement gate unmet.**

The platform where the design is most clearly better than TUN, and the one that
will decide whether the §3.1 abstraction is right.

- Resolve the datapath asymmetry in §3.3.2 **before** writing the Swift.
- System extension, XPC control channel, SOCKS5 client in the extension.
- Entitlement request, Developer ID signing, notarization pipeline.

**Gate**: conformance passes. **Plus two measurements that are not assumptions**:
(a) the fraction of a realistic application set for which `remoteHostname` is
populated; (b) an enumerated list of what the system declines to divert. Both go
into the README as known limits, whatever the numbers say.

### Stage 3 — drop-in ergonomics

**Implementation status (2026-08-17): service, flags, filters, migrations, and
host-side Docker/Dev Container lifecycle launchers complete; independent
first-time-user gate not measured.**

The stage that decides whether anyone adopts it.

- `tunless --upstream 127.0.0.1:7890` and nothing else required.
- Capture filter config: process and destination include/exclude.
- Documentation written as a **migration**, not a tutorial: "delete your `tun:`
  block, set `enhanced-mode: normal`, run this." Side-by-side config diffs for
  mihomo and sing-box.
- The README's first line is the pitch, not the description:
  *TUN-less transparent proxying. No fake IP, no route hijack, no second TCP
  stack.*

**Gate**: a user who has never seen the project converts a working mihomo TUN
setup in under five minutes using only the README.

### Stage 4 — Windows backend

**Implementation status (2026-08-17): TCP source complete; Windows/WDK build,
UDP, signing, fuzzing, and runtime gate unmet.**

Only once stages 1–3 have demonstrated that anyone wants this. It is the only
stage with a hard monetary floor and the only one that can bugcheck a machine.

- WFP callout driver, dynamic session, userspace recovery of original
  destination, and query/set propagation of opaque redirect records.
- EV certificate, Partner Center enrollment, attestation signing.

**Gate**: conformance passes; the driver survives a fuzzing pass at the redirect
layer without a bugcheck; an attestation-signed build loads on a clean Windows
11 with Secure Boot enabled.

### Stage 5 — optional and deferred

**Implementation status (2026-08-17): DNS observer and both metadata transports
complete. TPROXY remains conditional on a router-deployment request.**

- DNS observer (§3.4), opt-in, off by default.
- Process identity conveyed downstream: SOCKS5 username encoding, then a unix
  socket metadata API, then upstream patches to mihomo and sing-box.
- TPROXY backend for router deployments, if asked for.

---

## 5. Risks and unknowns

Ranked by how much they could invalidate the design.

1. **macOS hostname availability may be far lower than hoped.** The entire "no
   fake-IP" claim is strongest on macOS precisely because the OS supplies names.
   If most real applications resolve independently and connect to literals, macOS
   degrades to the same many-to-one ambiguity as Linux. *Resolved by: the stage 2
   measurement, before any Swift is written that depends on it.*
2. **The §3.1 abstraction may not survive the macOS datapath asymmetry.** If the
   extension must own the bytes, the `Backend` interface is doing two different
   things on different platforms. *Resolved by: designing stage 2 against the
   interface on paper first, and changing the interface if it does not fit.*
3. **UDP semantics differ most across the three backends** and are the likeliest
   place for the abstraction to leak. *Resolved by: UDP as an independent gate
   per backend, never folded into the TCP gate.*
4. **eBPF portability across kernel versions and distributions.** CO-RE helps;
   the connect-hook and `bpf_link` floors do not move. *Resolved by: an explicit
   5.10 floor, tested on two kernels in CI.*
5. **The Windows driver is the only irreversible cost.** *Resolved by:
   deliberately sequencing it last, after adoption is demonstrated.*
6. **Nobody adopts it because TUN mode is good enough for them.** The failure
   modes this fixes are intermittent, and users blame their proxy provider. This
   is a real possibility and stage 3's gate is the honest test of it.

---

## 6. Decisions not yet made

- **License.** MIT.
- **Module path.** `github.com/bojieli/tunless`.
- **Config format.** Flags and environment variables for v1.
- **macOS containing app.** Bare activation/configuration launcher.
- **Relationship to `queqiao`.** None, deliberately. `queqiao` is a transport;
  this is a capture layer. If they are ever used together it is because a user
  pointed `tunless --upstream` at a SOCKS5 port that happens to be queqiao's,
  which requires no coupling in either codebase and no mention in either README.

---

## Appendix A — platform requirements and costs

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Mechanism | eBPF cgroup/connect | `NETransparentProxyProvider` | WFP ALE connect-redirect |
| Language | C + Go | Swift + Go | C + Go |
| Privilege | `CAP_BPF`, `CAP_NET_ADMIN` | user approval of system extension | kernel driver, admin install |
| Membership | none | Apple Developer Program, $99/yr | Microsoft Partner Center |
| Signing | none | Developer ID + notarization | EV certificate, ~$300–600/yr |
| Review | none | none (Developer ID path) | attestation signing |
| Distribution | direct | direct download, not Mac App Store | direct |
| Hostname available | no | often (unverified, §5.1) | no |
| Fail-open mechanism | unpinned `bpf_link` | extension exit | dynamic WFP session |

## Appendix B — why not the alternatives

- **Explicit proxy (`HTTP_PROXY`, system proxy settings)**: requires application
  cooperation. Most applications ignore it. This is the reason TUN mode exists
  and the reason this project must not regress to it.
- **TUN**: §1.2.
- **`LD_PRELOAD` / DLL injection of `connect()`**: highest fidelity when it
  works — you see the hostname and the process trivially — but breaks on static
  binaries, hardened and protected processes, and is indistinguishable from
  malware to any EDR. Not viable for something people install.
- **Per-app VPN / MDM**: requires management infrastructure nobody running a
  personal machine has.
