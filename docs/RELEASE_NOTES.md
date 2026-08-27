# Release notes

*Audience:* the body of the GitHub Release, and anyone deciding whether to
install this.

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
