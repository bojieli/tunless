# Release notes

*Audience:* the body of the GitHub Release, and anyone deciding whether to
install this.

> **Draft for 0.1.0. Nothing has been published.** The gates that must be met
> before this text becomes a release are in
> [RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md), and the evidence behind every
> claim below is in [MEASUREMENTS.md](MEASUREMENTS.md). Delete this block at tag
> time; the checklist says when.

## 0.1.0 — UNRELEASED

First release. `tunless` catches connections at the socket layer and hands them
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
| Linux | Generally available | eBPF capture for TCP and UDP over both address families, on the host and inside container namespaces, from a reproducible embedded BPF object, with dated throughput, footprint, filter, and recovery evidence |
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
