# Release notes

*Audience:* the body of the GitHub Release, and anyone deciding whether to
install this.

## 0.2.3 — 2026-08-29

A correction to 0.2.2, which shipped one of its three fixes inert.

### Platform maturity

Unchanged. Linux is generally available, macOS is beta, and Windows is source
only — no Windows binary or driver is attached to this release.

### What this release fixes

0.2.2 made an application's own query to the trusted resolver capturable instead
of declining it. On macOS the flow was claimed and then every datagram on it was
sent direct anyway, so the behaviour was the same as before: on a host with the
upstream's TUN underneath, `dig @1.1.1.1` kept returning a fake address from the
datapath the query was supposed to bypass. The datagram path asked whether a
destination was reserved without saying it was a datagram, and that question
defaults to the answer for a stream, which still reserves the resolver.

The second half is subtler and would have been worse on its own. A query already
addressed to the trusted resolver is rewritten to itself, and the response map
skipped any datagram whose route did not change — so no identifier of capture's
own was assigned, and the loop guard recognises the upstream's forwarded copy by
exactly that identifier. Claiming those flows without one would have reopened the
loop the old address reservation existed to close. It did not happen in 0.2.2
only because the first defect kept the flows from being relayed at all.

Both are fixed together, because fixing either alone is worse than fixing
neither.

### Known limitations

Unchanged from 0.2.2: name recovery applies to streams and not to QUIC, DNS over
HTTPS and over TLS remain out of reach, and the 48-hour soak has not been
completed on either platform.

### Upgrading

No configuration change is required. If you are on 0.2.2 and pointed anything at
the same resolver as `--dns-upstream`, this is the release where that starts
being protected.

## 0.2.2 — 2026-08-29

A patch release for three gaps in 0.2.1, found by going back over it on a live
host and trying to disprove it rather than confirm it.

### Platform maturity

Unchanged. Linux is generally available, macOS is beta, and Windows is source
only — no Windows binary or driver is attached to this release.

### What this release fixes

**An application's own query to the trusted resolver was declined.**
`--dns-upstream` names a resolver, and 0.2.1 reserved that resolver by address,
so capture declined every port-53 flow aimed at it. On the affected host every
resolver was being overridden correctly except the one `tunless` relays to, which
came back with an address no part of the datapath had answered for. Since the
default `--dns-upstream` is `1.1.1.1` — also one of the most commonly configured
resolvers there is — the people most likely to be protected were the ones getting
nothing.

The reservation exists for a real loop: capture relays a query to the trusted
resolver, the upstream dials that resolver itself, and capturing that dial hands
the query back to the upstream waiting on it, after which every lookup on the
host recurses until it times out. But the two flows are distinguishable without
the address. Capture already rewrites the transaction ID of every query it
relays, to an ID drawn at random the application never chose, and the upstream
forwards that query verbatim — so the datagram that would close the loop carries
an ID capture is still holding open, and an application's own query does not.
Streams stay reserved, because a connection announces nothing at connect time.

**A local name asked over TCP was redirected to a resolver that cannot answer
it.** 0.2.1 exempted port 53 from destination rules on both transports, so a
DNS-over-TCP query to your own network's resolver went to a trusted public one
instead. The name-based split cannot help there: a stream has to be routed before
any bytes arrive. Those are left alone now, exactly as they would be if nothing
were installed, and your local resolver answers them. Public resolvers are still
captured on both transports, having no local names to lose.

**Associations expired before the connections they exist for.** An association is
written when the answer arrives and read when the connection opens, and a browser
resolves once and then opens connections over the seconds that follow. Honouring
a one-second TTL literally meant the first connection was recognised by name and
the rest were not. Names published with a TTL that short are real. The floor is
thirty seconds now; what the bound protects against is an address being
reassigned and inheriting the old name's routing, which does not happen that
fast, and if it did the flow still reaches a real address that still works.

### Known limitations

Everything in 0.2.1's list still stands, plus one that is now measured rather
than assumed:

- **Name recovery applies to streams.** A datagram flow — QUIC and HTTP/3 — is
  emitted on its address even when the name is known, so those lose domain rules
  while still reaching the right server. This is a measurement, not an unfinished
  feature: a SOCKS5 UDP relay reports the source of every reply, and an upstream
  asked to send to a name reports the address it resolved that name to. mihomo
  returns `8.8.4.4` for a datagram addressed to `dns.google`. A QUIC client uses a
  connected socket, so replies from an address it never wrote to are dropped by
  the kernel before the application sees them. Rewriting UDP destinations to
  names would trade rule-by-name for breaking QUIC outright.
- **DNS over HTTPS and over TLS remain out of reach**, and fail more mildly than
  what this fixes: an encrypted answer cannot be substituted, so the browser
  reaches the right address and loses only the domain rules.
- **macOS remains beta.** The 48-hour soak has not been completed on either
  platform.

### Upgrading

No configuration change is required. If you had pointed anything at the same
resolver as `--dns-upstream` and wondered why it was not being protected, it is
now.

## 0.2.1 — 2026-08-29

A patch release for one defect with two halves: on a network that answers DNS
falsely, a browser could not reach a site that `curl` reached from the same
machine, through the same proxy, a second apart.

### Platform maturity

Unchanged from 0.2.0. Linux is generally available, macOS is beta, and Windows
is source only — no Windows binary or driver is attached to this release.

### The defect this release exists for

`tunless` exists so that the name an application asked for is what reaches your
proxy, and both halves of this defect were ways that stopped being true.

**The DNS override could not see the query.** Capture applied the operator's
destination rules before it considered the port, and the defaults exclude
`192.168.0.0/16` so that nobody accidentally puts a proxy in front of their own
LAN. A home router is the resolver and lives in that range, so every port-53
flow to it was declined and left on the network's own path. Nothing reported an
error. The answers came back substituted, and every name on the host resolved to
whatever had been substituted — on the host where this was found,
`www.google.com` resolved to an address belonging to Facebook.

A resolver's address is not a destination an application chose to reach. It is a
resolver the network handed out, and replacing it is what the override is for.
While a DNS override is configured, destination rules no longer apply to port
53. Process rules and the reserved set still do: handing the upstream's own
query back to the upstream is a loop that takes DNS down host-wide.

**macOS had no name to hand over.** The system attaches `remoteHostname` only
for a name it resolved on the application's behalf. `curl` gets one. Anything
shipping its own DNS client — every Chromium browser, Firefox — does not, so
those flows arrived carrying a bare address, the proxy lost every rule written
about names, and the address it was handed was the substituted one. `curl` never
noticed, because its address had already been discarded. That asymmetry is why
this reads as "my browser is broken" rather than as a DNS problem.

The provider now records which name each address was answered for, from the
answers it is already relaying, and hands the name over instead. Only answers
that came through the trusted resolver are recorded: learning one from the
network's own path would let whoever supplied that answer choose the name a
later flow is proxied under, which is the same substitution re-entering one
layer up.

This is not fake IP under another name, and the difference is the failure mode.
Every address here is real, so an association that is missing, expired, or
claimed by two names costs you rule-by-name and nothing else — the flow still
goes out on an address that works. A fake IP that outlives its mapping connects
and then transfers nothing.

### Names only your own network can answer

Capturing all of DNS is only safe if those names keep reaching the resolver that
has them, so they are not redirected: `.local`, `.home.arpa`, `.internal`,
`.lan`, `.test`, `.localhost`, unqualified single-label names, and the reverse
zones for private, CGNAT and link-local space. They are also sent directly
rather than through the proxy, because a private address relayed to a node on
the other side of the world is as unanswerable as a public resolver that never
heard of the name.

`--local-domain` adds split-horizon zones that no built-in list could predict,
`corp.example.com` being the usual shape. It is repeatable, and
`TUNLESS_LOCAL_DOMAIN` sets it in the environment file.

### Known limitations

- **DNS over HTTPS and over TLS are still out of reach.** There is no port-53
  flow to see, so the name never passes through `tunless`. This failure is
  milder than the one above rather than worse: an encrypted answer cannot be
  substituted in the first place, so the browser reaches the right address and
  loses only the domain rules. Turning a browser's secure DNS off restores them.
- **The name-based split reads the query, so it applies to DNS over UDP.** A
  query over TCP has to be routed before any bytes arrive and goes to the
  trusted resolver like anything else. Stub resolvers use UDP first and fall
  back to TCP only for answers too large to fit.
- **macOS remains beta, and the reason is unchanged.** The 48-hour soak has not
  been completed on either platform.

### Upgrading

No configuration change is required, and none of the defaults that were there
before have moved. If your internal names live under a public zone, name it with
`--local-domain`.

## 0.2.0 — 2026-08-27

The first release that is not a preview. What changed is not the feature list —
it is that a defect class this project was built to avoid was found on a live
machine, understood, and closed, and the platform it affected now has evidence
behind it rather than only tests.

`tunless` catches connections at the socket layer and hands them to a SOCKS5
proxy you already run, so unmodified applications go through your proxy without
a TUN device, a fake-IP pool, or a rewritten routing table. The kernel still
knows the hostname and the calling process at that layer, so nothing has to be
reconstructed or faked, and if `tunless` stops, connections go out the normal
way.

### Platform maturity

| Platform | Ships as | Because |
| --- | --- | --- |
| Linux | Generally available | eBPF capture for TCP and UDP over both address families, on the host and inside container namespaces, from a reproducible embedded BPF object, with dated throughput, footprint, filter, and recovery evidence, plus a netfilter fallback for kernels the eBPF backend cannot run on |
| macOS | Beta | The resolver-lifetime defect below was found and fixed on a live host, but the fix itself has not been qualified on one: a locally signed system extension cannot activate while SIP is on, so installing it requires the notarized build path. Clean-machine qualification of the exact candidate is open |
| Windows | Source only, not a shippable artifact | The WFP backend is implemented, but WDK build, Driver Verifier, runtime, UDP, fuzzing, and Microsoft attestation gates are all unmet, and loading a driver on Windows 10 or later needs a signature this project does not hold |

**No Windows binary or driver is attached to this release.** The Windows source
is a design to read and build on, not a download.

### The defect this release exists for

On macOS, a captured UDP flow used to be closed whenever the transport under it
failed — a watchdog pause, a SOCKS5 handshake that timed out against a busy
mixed port, an upstream that dropped its UDP association, or two minutes of an
idle one.

macOS treats a datagram flow the provider closed as final. It does not
re-capture the socket above it and does not hand it back to the kernel, so
every later send on that socket fails locally. `mDNSResponder` holds one
resolver socket per delegated client and never replaces it. One closed flow
therefore ended name resolution **for one application**, for as long as the
daemon ran, while every other program on the host resolved normally — which
reads like a problem with the site, not with DNS.

Measured on a live host: a single watchdog pause at 16:47 produced 6,307
`sending ... failed: [22: Invalid argument]` messages over the following five
hours, with one application's lookups timing out at thirty seconds throughout.

The association is now the disposable half. It is retired and rebuilt
underneath a flow that stays open; while it cannot carry them, datagrams go out
directly, exactly as they would if tunless were not installed; and the
application's socket is never touched.

### Also in this release

- **Flow attribution**: what produced a flow, not just where it was going.
- **Kubernetes capture scope**: pick a node's pod hierarchy without capturing
  the agent's own traffic, with the remaining gap reported rather than worked
  around.
- **A netfilter fallback backend** for hosts the eBPF backend cannot run on —
  an older kernel, a distribution that disables unprivileged BPF, or an
  operator who will grant `NET_ADMIN` and not `CAP_BPF`. It gives up fail-open
  and cannot attribute processes, and says so rather than silently matching
  nothing. `auto` never selects it.
- **DNS probes that read what the upstream actually sent.** Both probes decoded
  a relayed answer at a fixed ten-byte offset, which is the SOCKS5 UDP header
  length only for an IPv4 source; an upstream answering from an IPv6 address
  had a good answer scored as no answer, which told operators UDP relaying was
  broken and dropped the watchdog to TCP-only probing for the session.
- **A UDP association that survives a duplicate answer.** A resolver answering
  the same query twice produced a datagram the flow correctly refused, and the
  association used to end over it, discarding every other query in flight on
  that socket.
- **DNS stays watched with `--disable-dns-override`.** That flag preserves each
  application's resolver; it never stopped capture relaying the query, but it
  did switch off the preflight proof, the post-start verification, and the
  runtime watchdog.
- **`doctor` checks what the selected backend actually needs** instead of
  reporting every non-eBPF backend as privilege-free.

The complete list is in [CHANGELOG.md](../CHANGELOG.md).

### Upgrading from 0.1.0

Linux: replace the binary and restart the unit. Nothing in the datapath's
configuration changed.

macOS: the extension must actually be replaced, which is worth checking rather
than assuming. `CFBundleVersion` was 14 for two different binaries in 0.1.0,
and macOS keys system-extension replacement on that number, so an install could
leave the earlier code running while the launcher reported the newer version.
This release is build 15, the number now lives in `macos/project.yml` where the
build reads it, and the release checklist gates on it. After installing, read
the running build back:

```console
systemextensionsctl list | grep tunless
```

### Known limitations

- **The macOS fix has not been qualified on a live host.** It is covered by
  unit tests that stand a real SOCKS5 upstream up and kill it, and the defect it
  closes was diagnosed on a live machine — but a locally signed system extension
  cannot activate while SIP is enabled, so running the fixed build requires the
  notarized path. Until that has run, treat macOS as beta in the strict sense.
- **The 48-hour soak has still not been completed.** The harnesses exist on
  both platforms. Every serious defect this project has found surfaced over
  hours rather than minutes, including this release's.
- **Rootful Podman is unreliable.** Podman commands against an attached
  container hang in roughly two runs in five on podman 5.8.4 with netavark.
  Docker and containerd via kind do not show it. Cause unknown. Use Docker.
- **The 5.10 kernel floor is unverified on this code.** Current kernels are
  tested continuously; the oldest supported one was last exercised before the
  0.1.0 datapath changes.

## 0.1.0 — 2026-08-25 — preview

First release, and a **preview**: install it to try it, not to depend on it.
The code is exercised against a live kernel on every pull request and every
claim below is backed by a dated measurement, but the evidence is narrow in one
specific way — nobody has run it for hours. Read
[what a preview means here](../README.md#where-the-project-actually-is) and the
**Gates not demonstrated** table in [MEASUREMENTS.md](MEASUREMENTS.md) before
deciding this belongs on a machine you care about.

 `tunless` catches connections at the socket layer and hands them
to a SOCKS5 proxy you already run, so unmodified applications go through your
proxy without a TUN device, a fake-IP pool, or a rewritten routing table. The
kernel still knows the hostname and the calling process at that layer, so
nothing has to be reconstructed or faked, and if `tunless` stops, connections go
out the normal way.

### Platform maturity

The three platforms are not at the same maturity, and this release says so on
its face rather than only in a document you might not reach.

| Platform | Ships as | Because |
| --- | --- | --- |
| Linux | Preview, and the platform this release is for | eBPF capture for TCP and UDP over both address families, on the host and inside container namespaces, from a reproducible embedded BPF object, with dated throughput, footprint, filter, and recovery evidence |
| macOS | Beta | Notarized builds pass the recorded live suites and capture stands aside on its own when the upstream stops resolving, but exact-candidate clean-machine qualification is open and `remoteHostname` and HTTP/3 coverage are not demonstrated |
| Windows | Source only, not a shippable artifact | The WFP backend is implemented, but WDK build, Driver Verifier, runtime, UDP, fuzzing, and Microsoft attestation gates are all unmet, and loading a driver on Windows 10 or later needs a signature this project does not hold |

**No Windows binary or driver is attached to this release.** The Windows source
is a design to read and build on, not a download.

### Install

Linux, with cgroup v2 and kernel 5.7 or newer:

```console
make
sudo make install
sudo systemctl enable --now tunless
```

The unit reads `/etc/tunless.env`, installed root-owned mode `0600` because an
upstream URL may carry SOCKS credentials. Run your proxy outside the captured
cgroup — the packaged unit captures `user.slice` and lives in `system.slice`
for exactly that reason. Packages, archives, an OCI image, SBOMs, and checksums
are attached; verify them before installing.

Containers need nothing inside them: one command attaches an existing
container, described in [CONTAINERS.md](CONTAINERS.md).

macOS ships as a beta Network Extension; see [MACOS.md](MACOS.md), including
what happens if the upstream stops resolving.

### What is in it

- **Linux eBPF capture** for TCP and connected/unconnected UDP over IPv4 and
  IPv6, on the host and inside container network namespaces, with destination
  and process filters evaluated in the hook so excluded flows stay direct
  instead of being accepted and dropped.
- **A capture floor the configuration cannot reach past.** Loopback, the
  unspecified address, link-local — which is where a cloud instance asks about
  itself — multicast, broadcast, the SOCKS5 upstream, and the trusted
  resolver's own endpoint are never captured, whatever the filters say, on both
  Linux and macOS. A proxy cannot carry any of them, so capturing them loses
  the traffic rather than routing it.
- **A default-on trusted DNS override** with per-request randomized transaction
  IDs, replies matched to the query that asked, and observed name-to-address
  mappings that expire within a day whatever TTL an answer claimed.
- **macOS capture that is accountable for the network it takes over**: it
  refuses to start when the upstream cannot relay DNS, re-proves resolution
  through the live datapath, stands aside so flows go direct when that stops
  being true, and resumes when it recovers.
- **A SOCKS5 TCP/UDP relay**, HTTP CONNECT and SOCKS5 reference inbounds, an
  optional real-answer DNS observer, and two optional ways to pass process
  identity downstream.
- **Reproducible artifacts**: byte-identical rebuilds, a static `scratch` OCI
  image, deterministic SPDX SBOMs for binaries and each OCI architecture, and
  synchronized third-party notices.

The complete list, including every security fix, is in
[CHANGELOG.md](../CHANGELOG.md).

### Known limitations

- **Nobody has soaked this.** The 48-hour soak harnesses exist on both
  platforms; neither has been run. Every serious defect this project has found
  surfaced over hours rather than minutes, so this is the gap most likely to
  still be hiding one.
- **Rootful Podman is unreliable.** Podman commands against an attached
  container — `rm --force`, `exec` — hang in roughly two runs in five on podman
  5.8.4 with netavark. Docker and containerd via kind do not show it and podman
  3.4.4 on CNI did not either. Cause unknown. Use Docker.
- **The 5.10 kernel floor is unverified on this code.** Current kernels are
  tested continuously; the oldest supported one was last exercised before this
  release's datapath changes.

These are boundaries, not bugs waiting on a patch:

- **`PROCESS-NAME` rules downstream stop matching.** SOCKS5 has nowhere to put
  process identity, so every captured flow reaches the proxy looking like it
  came from `tunless`. Application selection moves to capture time: a cgroup on
  Linux, `--include-process` on macOS. Domain, destination, GEOIP, node, and
  subscription rules are unaffected, and a real destination address gives them
  more to work with than a fake one did.
- **Linux unconnected UDP associations are single-destination on purpose.** A
  second destination on the same socket fails with a permission error while the
  association is active, rather than risking a reply with the wrong apparent
  source. Use a connected socket or separate sockets when destinations overlap.
- **Simultaneous unconnected UDP6 sockets sharing one source endpoint via
  `SO_REUSEPORT` are ambiguous** at the redirect listener and are not
  supported.
- **Rootless Podman is not supported**; rootful Podman, containerd, and CRI-O
  have helpers. See [CONTAINERS.md](CONTAINERS.md).
- **`tunless` is not a VPN, a rule engine, a proxy-protocol collection, a GUI,
  or a mobile backend.** It captures sockets on the machine it runs on. Traffic
  forwarded from other machines, and raw ICMP, ESP, and GRE, belong to the
  proxy downstream or somewhere else entirely.

### Evidence, and what is not demonstrated

Every performance and compatibility claim above is backed by a dated entry in
[MEASUREMENTS.md](MEASUREMENTS.md) naming the host it ran on, and that file also
carries a **Gates not demonstrated** table listing what has not been shown.
Read it before deciding this is safe for a machine you care about. Capture costs
about a quarter of a percent of throughput on the recorded host; the numbers,
the machine, and the date are all there.

### Security

Report vulnerabilities privately through the path in
[SECURITY.md](../SECURITY.md). The threat model, including explicit non-goals,
is in [THREAT_MODEL.md](THREAT_MODEL.md).

### Verifying what you downloaded

Check `SHA256SUMS` against the files, review the SPDX SBOM for the artifact you
are installing, and verify the build provenance attestation with
`gh attestation verify`. The OCI image is published by digest.
