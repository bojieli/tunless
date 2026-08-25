# Measurements and release gates

*Audience:* prospective adopters evaluating the evidence behind this project's
claims, and release reviewers checking gate status before a tag.

This file is the project's evidence log. Every performance and compatibility
claim in the [README](../README.md) is backed here by a dated entry naming the
host it ran on. Results distinguish implementation from release qualification:
an untested gate is not called complete, and anything that has not been
demonstrated is listed explicitly in
[Gates not demonstrated](#gates-not-demonstrated).

Measured 2026-08-17.

Exit addresses in this log are described rather than printed. Which address a
flow left by is the evidence — a captured process exiting by the proxy's node
instead of the host's own is what proves capture worked — and that evidence
survives naming the addresses by role. Printing them would publish the test
infrastructure's addresses for no gain in reproducibility, since nobody
reproducing these runs would be using the same hosts.

## Headline results

- WAN throughput: the transparent eBPF path (captured process → tunless →
  proxy) finished within ~0.4% of direct throughput — median 25.83 MB/s
  versus 25.93 MB/s across five 100 MiB downloads, 0.4% longer by total
  time — well inside the run-to-run WAN spread. Raw runs and method:
  [WAN download results](#wan-download-results). Re-taken on the current tree
  at a higher rate and a steadier link: 112.82 MB/s captured against 113.13
  direct, 0.27% below, in
  [Linux WAN throughput and footprint on the current tree](#linux-wan-throughput-and-footprint-on-the-current-tree-2026-08-25).
- Footprint: during those transfers `tunless` used about 2.8% of one core
  (0.57 CPU seconds over 20.48 s aggregate wall time), process RSS moved from
  8,996 KiB to 9,012 KiB (~9 MB), and the three preallocated 65,536-entry LRU
  BPF maps report 17.5 MiB of kernel memlock. Details:
  [WAN download results](#wan-download-results).

## Hosts

- Local: Apple Silicon Mac, macOS 26.3 (25D125), Xcode 26.2, Swift 6.2.3,
  Go 1.26.6. Docker Desktop reported server 27.3.1, LinuxKit 6.10.14,
  ARM64, and cgroup v2.
- Local VM: Lima/QEMU ARM64, Debian 11, kernel
  `5.10.0-46-cloud-arm64` (`5.10.262-1`). The VM used 4 vCPUs and 4 GiB RAM.
- Remote: RTX-PRO, Ubuntu 22.04.5, x86-64 kernel 6.8.0-111-generic,
  cgroup v2, bpftool 7.4.0, clang 14. Its native Docker engine was 28.5.2
  with the cgroupfs driver.
- Downstream: mihomo v1.19.30 in direct mode on RTX-PRO. A second test used a
  reverse SSH port to the Mac's existing local SOCKS listener. Native Docker
  namespace tests used sing-box 1.13.18 as a loopback direct-mode SOCKS server.
- WAN object: OVH VIN 100 MiB static test file over IPv4 and HTTP/1.1. Five
  runs per mode, with mode order rotated each run.

## Functional gates demonstrated

- Portable Go: race-enabled TCP/UDP, IPv4/IPv6, 2 MiB bidirectional/half-close,
  cancellation, destination, process metadata, SOCKS5 and HTTP CONNECT tests.
- Reference backend: its SOCKS5 and HTTP CONNECT inbounds both completed through
  a real mihomo v1.19.30 downstream on RTX-PRO; the HTTPS checks returned that
  host's own WAN exit address and HTTP 200 respectively.
- SOCKS metadata: authenticated username negotiation and Unix-socket
  source-port registration/lookup/lifecycle integration. Go and Swift clients
  also reject a server-selected authentication method they did not offer.
- Linux TCP: `curl` and headless Chromium loaded through mihomo with no proxy
  configuration in either application. The final browser check used an unpacked
  Google Chrome build and asserted that the flow count increased; Ubuntu's Snap
  Chromium moved to a sibling cgroup and was correctly treated as out of scope
  for the deliberately narrow test cgroup.
- Linux UDP: connected and unconnected UDP4 and UDP6 round-tripped. UDP6 used a
  temporary `2001:db8::1/128` loopback echo target that was removed afterward.
  The final relay allocator was verifier-loaded and runtime-tested after adding
  fail-open handling for its 24-bit relay-address collision case.
- BPF filters: `0.0.0.0/0` exclusion emitted no flow; a `1.1.1.0/24` inclusion
  captured DNS while unrelated HTTPS stayed direct.
- DNS observer: returned real `example.com` answers and attributed a later
  IP-only flow to `example.com.`; ambiguous mappings are unit-tested as unknown.
- Fail-open: during a 1 GiB transfer, `SIGKILL` caused the in-flight TLS stream
  to end (curl 56). A fresh connection succeeded direct in 263 ms, and bpftool
  reported zero links without manual network repair.
- systemd topology: a transient service ran in
  `/system.slice/tunless-integration.service`, captured the test cgroup, and
  left zero links after `systemctl stop`.
- Kernel floor: the seven programs were compiled and verifier-loaded natively
  in the ARM64 5.10 VM. The release binary, using the shipped embedded BPF
  object, then passed HTTPS, headless Chromium, UDP4, connected/unconnected
  UDP6, include/exclude policy, DNS attribution, graceful teardown, and
  SIGKILL fail-open. The final binary additionally passed a live HTTPS capture
  with redirect sockets created through `--network-namespace` on that exact
  5.10 kernel. This is independent of the x86-64 6.8 run.
- Native Linux Docker namespace mode: a stock Python container with no proxy
  environment completed hostname-based HTTPS, connected/unconnected UDP4, TCP6,
  and connected/unconnected UDP6. IPv6 used an isolated dual-stack Docker
  network and a second echo container. Docker's `127.0.0.11` name service stayed
  direct while the resolved connection was captured. All seven Tunless links
  were visible on the target cgroup. After `SIGKILL`, only Docker's device hook
  remained and fresh TCP/UDP succeeded direct. Stopping the target also stopped
  the controller automatically.
- macOS Docker Desktop namespace mode: a stock Python bridge container with an
  empty proxy environment and unchanged routes completed hostname-based HTTPS
  plus connected/unconnected UDP4 through the automatically created host SOCKS
  bridge. Docker Desktop's `192.168.65.7` resolver stayed direct. Stopping the
  controller immediately restored direct TCP/UDP; stopping the target removed
  the controller in the next 250 ms poll. Label-scoped watch mode attached only
  the Dev Container-labelled target and followed its lifecycle.
- Container boundary negative control: the earlier host-loopback implementation
  still produced `ECONNREFUSED` for a bridge container because its private
  loopback had no listener. Namespace-local sockets are the implemented fix,
  not an environment-variable or route workaround.
- macOS build 9 upgrade smoke: on 2026-08-18 the 25-test Swift suite, Go suite,
  and unsigned Debug containing-app/system-extension build passed. The
  universal Release bundle was signed with direct Developer ID profiles,
  notarized, stapled, accepted by Gatekeeper, and installed over build 8. The
  build 9 (`1.0.8`) extension was the single `activated enabled` entry, status
  reported `connected` through the Clash Verge preset at `127.0.0.1:7897`, and
  SOCKS5 preflight plus live HTTPS passed. Provider telemetry confirmed live
  DNS rewriting to `1.1.1.1:53`.
- macOS build 8 full validation: on 2026-08-17, build 8 (`1.0.7`) was signed with
  matching direct Developer ID profiles, notarized, stapled, accepted by
  Gatekeeper, installed, activated, and enabled. Captured UDP and TCP queries
  addressed to the configured `223.6.6.6` system resolver were rewritten to
  `1.1.1.1:53` through Clash; Google, YouTube, Google Video, GitHub, and
  Cloudflare returned public answers. Repeated DNS checks passed 20/20 UDP and
  10/10 TCP, and Cloudflare DNS-over-HTTPS agreed. HTTP/1.0 close-delimited
  responses passed 5/5 after the provider began propagating remote EOF as soon
  as Clash closed. HTTP/1.1, HTTP/2, redirects, streaming, a POST upload, raw
  TLS 1.3, SSH over TCP/443, Cloudflare and Google STUN, and 32 concurrent HTTPS
  requests passed. A loopback packet capture measured 0.865 ms from Clash FIN
  to Tunless FIN in the fixed path. A 2 MiB Cloudflare speed probe was slow in
  both Tunless and explicit-SOCKS controls, identifying the selected Clash path
  rather than Tunless as the bottleneck. Both paths reported the same public
  egress IP. Private destination exclusions kept the LAN gateway reachable over
  ICMP and HTTP with zero captured gateway records. Clash remained at the same
  PIDs and its original HTTP/HTTPS proxy settings were restored and rechecked.
- macOS negative boundary: when a client calls `shutdown(SHUT_WR)`, macOS marks
  its `NEAppProxyTCPFlow` disconnected. Packet capture showed Clash returning
  the response after FIN, but the provider's later write failed with
  `NEAppProxyFlowErrorDomain` code 1. The SOCKS transport's delayed response-
  after-FIN unit test passes, isolating this behavior to the Network Extension
  flow API. Client-FIN-delimited protocols therefore require a packet-layer
  backend. The installed Apple curl has HTTP/2 but no HTTP/3 feature, so QUIC
  HTTP/3 was not claimed; non-DNS UDP was covered independently with STUN.
- Windows userspace: Go cross-compiles to a PE32+ amd64 executable. The accepted
  WFP socket now carries queried redirect records into the flow, and the SOCKS
  dialer sets them before outbound connect. Both PowerShell Docker launchers
  pass the PowerShell parser; this is source validation, not Windows runtime
  evidence.
- Cross-platform DNS/lifecycle source gate on 2026-08-18: all Go packages and
  the race suite passed; vet and Linux/Windows amd64 cross-builds passed; the
  macOS Swift suite increased to 25 passing tests; and an unsigned build of the
  containing app plus embedded extension succeeded. This covers disable-policy
  routing, TCP/UDP inactivity, hard-error and pending-callback cancellation,
  joined UDP teardown, short TCP writes, bounded UDP DNS-ID translation, and
  Clash Verge preset argument validation. Live local SOCKS5 preflight also
  passed against the active Clash listener, while a refused port returned a
  nonzero result without enabling capture.
  The build-9 app was not installed over
  the active notarized build, and Windows UDP remains runtime-gated.

## Follow-up hardening validation

On 2026-08-19, the pre-publication working tree passed the Go race suite, vet,
Staticcheck v0.7.0 for Linux/macOS/Windows build tags, Gosec v2.22.9,
Govulncheck v1.1.4 with no vulnerabilities found, dependency-license and
third-party-notice checks, all 25 Swift tests, ShellCheck, actionlint, and
Linux/Windows amd64/arm64 cross-builds. A local non-publishing
`0.1.0-rc.1` release check produced two byte-identical sets of binaries,
archives, DEB/RPM packages, the multi-platform OCI archive, and per-platform
SPDX documents. Package install/upgrade/uninstall, systemd, archive, and both
OCI architecture smoke tests passed. This deliberately dirty-tree pipeline
development run is not the required manual hosted candidate and created no tag
or release. Five current-tree fuzz targets completed five-second runs without
a crash (approximately 38,000 to 797,000 inputs per target), and the
race-enabled 10,000-connection stress rerun completed in 1.672 s (5,980
connections/s) with 381,120 bytes retained after forced garbage collection.

The final same-day pass added kernel-cookie UDP session identity, strict
kernel-map/datagram validation, private metadata-socket ownership and cleanup,
exact DNS record-type/CNAME-TTL attribution, and secret-safe package config.
The race suite and tagged static/security scans remained clean; five fresh
five-second fuzz runs completed approximately 86,000 to 1,480,000 inputs each.
A new two-build `0.1.0-rc.1` development pipeline was byte-reproducible, and
its DEB and RPM tests proved that a dangling `/etc/tunless.env` symlink is
rejected before extraction and that root ownership plus mode `0600` survive
upgrade. Systemd, archive, SBOM, and amd64/arm64 OCI checks also passed.

A Docker Desktop Linux-kernel probe tested whether unconnected UDP6 could carry
the socket cookie through an IPv4-mapped loopback relay address. The kernel
rejected that `sendmsg6` rewrite with error 524, while connected UDP6 remained
functional, so the experimental change was reverted. The embedded BPF object
remains the canonical hash recorded below. Userspace now separates every
successfully correlated UDP socket by cookie, but simultaneous unconnected
UDP6 `SO_REUSEPORT` sockets sharing the exact source endpoint remain an
explicitly documented ambiguity; no incompatible alias design was shipped.

A separate Docker Desktop probe sent 40 DNS queries from one unconnected UDP4
socket, alternating between `1.1.1.1:53` and `8.8.8.8:53` without waiting for
replies. All 40 replies arrived, but 20 carried the wrong apparent source: each
affected `1.1.1.1` reply was attributed to `8.8.8.8`. The kernel
`original_map` retains only the latest destination per socket cookie, so a
later send can overwrite attribution for an earlier in-flight datagram. This
was treated as a release blocker rather than a documented correctness caveat.

The replacement BPF/userspace ABI marks connected UDP records and makes an
unconnected record's destination immutable for the life of its userspace
association. A conflicting send returns a permission error; unconnected state
is removed when the association ends so the same socket can later select a new
destination, while marked connected state remains available for relay
recovery. Response sources must match the preserved original destination.
On LinuxKit 6.10.14 ARM64, the exact 40-query Docker Desktop reproducer then
reported 20 accepted sends, 20 rejected conflicting sends, and zero wrong
sources in each of three container lifecycle probes. The same run proved
post-idle destination turnover, connected UDP, TCP/UDP WAN routing,
immutable-ID attachment, and same-name container recreation (`attachments=3`,
`tcp_flows=6`, `udp_flows=39`).

A clean local non-publishing candidate pipeline for source commit `5fadb80`
then rebuilt `0.1.0-rc.1` twice with `SOURCE_DATE_EPOCH=1787132889`.
Binaries, archives, DEB/RPM packages, the multi-platform OCI archive,
per-platform SPDX SBOMs, and third-party notices were byte-identical. Package
symlink rejection, root-owned mode-`0600` config preservation, systemd unit
verification, archive contents, and amd64/arm64 OCI runtime tests passed. The
final manifest is SHA-256
`04ddaba1dedc349b836b6492219756f4e8e789a31b4b046263ead7bccefe6558`;
the OCI archive is
`970f71f8bb96c86351271f048ceceb9e98eac3f1dbd18d547aa1a99a7ba8cb71`
and its index digest is
`63af8dc50364969d4f77febc938a14ddd54b58ece523466fb355692e5f04a37a`.
The Linux amd64 and arm64 binaries are SHA-256
`cda407a79a94cd011e1c87d3beaca780b5deee392e2cba2d29d1e5ff7e8d1ff1`
and
`5f57e206a8ff689312a5886b5fb95690979d529ff510a56d09f6db5f5ff2a847`,
respectively.
These ignored local artifacts are validation evidence, not a manual hosted
candidate or a published release.

The original hosted current-kernel run for base commit `24c6cde` passed the
embedded-BPF rebuild/verifier, WAN/recovery, and Docker lifecycle stages before
GitHub stopped it at its then-configured 30-minute limit during Podman. A later
exact-head run exposed a separate rootful-Podman startup hang: two concurrent
controllers could block in engine metadata queries before logging `starting
tunless`. Commit `5fadb80` bounds those queries to ten seconds by default,
serializes concurrent rootful-Podman queries with a private lock, and retains
unbounded waits only for the long-lived controller and lifecycle operations.
Its regression test proves a fake 30-second query is terminated in one second
with an actionable error.

Hosted privileged run
[`32239472690`](https://github.com/bojieli/tunless/actions/runs/32239472690)
on exact commit `5fadb80` then passed the embedded-BPF rebuild/verifier,
WAN/recovery, native Docker, rootful Podman, containerd/kind CRI, and BPF-link
teardown stages. After the macOS deadline test was made deterministic without
changing production code, exact commit `d0ed79c` passed hosted
CI [`32240014731`](https://github.com/bojieli/tunless/actions/runs/32240014731),
Security
[`32240014758`](https://github.com/bojieli/tunless/actions/runs/32240014758),
and the full privileged current-kernel workflow
[`32240014706`](https://github.com/bojieli/tunless/actions/runs/32240014706).
The CI run includes the Go race/stress/vet/static-analysis, license/notices,
cross-build, shell, Docker build, Govulncheck, Windows source, PowerShell
parser, and 25-test macOS Swift jobs. These runs do not close the separately
required hosted fuzz, manual non-publishing candidate, public-only security,
provenance, or maintainer-approval gates.

After the initial measurements, the build toolchain was pinned to Go 1.26.6
and the direct dependencies were updated to cilium/ebpf 0.22.0, x/net 0.58.0,
and x/sys 0.47.0. `govulncheck ./...` initially found one reachable x/net DNS
parser vulnerability plus eleven reachable standard-library findings from the
older local compiler. The same scan reports `No vulnerabilities found` with
the pinned toolchain and updated modules. `staticcheck`, `actionlint`, the Go
race suite, vet, Linux/Windows cross-builds, seven Swift tests, and the unsigned
Release app/system-extension build all pass.

The new `scripts/integration-linux.sh` was then run as root on RTX-PRO with the
updated x86-64 binary. A captured, unmodified curl completed real WAN TLS and
reported that host's own WAN exit address. The harness kept one connected UDP
socket open,
killed and restarted sing-box, and recovered that same socket on its second
retry. Five UDP flow events were observed across the run, and teardown left
zero Tunless BPF links. This specifically validates preservation of the kernel
socket correlation needed to create a new SOCKS UDP association after an
upstream failure.

On macOS Docker Desktop, the updated controller image and host bridge captured
an unmodified `python:3.11-slim` container. WAN TLS reported the Mac proxy's
node exit address rather than the container's own; a UDP DNS query returned 45
bytes with its original
transaction ID `0x7200`; three flow events were observed. The second run used
an active TCP readiness probe for the temporary bridge and reduced the Docker
build context from 99.09 MB of Xcode artifacts to 7.56 kB compressed.

Finally, a fresh Debian 11 Lima/QEMU ARM64 guest revalidated the dependency
update on kernel `5.10.0-46-cloud-arm64` (`5.10.262-1`). The shipped BPF object
loaded through cilium/ebpf 0.22.0; captured WAN TLS and UDP DNS completed with
three flow events; and a new connection in the same cgroup succeeded after
Tunless stopped. The disposable guest was deleted after the run while Lima's
download cache was retained.

## Prerelease resilience and container matrix

The release-hardening run added five native Go fuzz targets covering SOCKS5
client/inbound address parsing, DNS observations, the metadata API, and CLI
configuration. Each target completed a 10-second local smoke run without a
crash; the final run executed approximately 40,000 to 774,000 inputs per target.
A race-enabled 10,000-connection TCP relay run completed in 1.639 s (6,101
connections/s) and retained 382,696 bytes after a forced GC. The final
post-hardening rerun completed in 2.113 s (4,732 connections/s) and retained
397,744 bytes. A separate
60-second soak completed 26 iterations of 1,000 connections (26,000 total),
with observed iteration rates around 5,000–5,900 connections/s and retained
heap around 300 KiB. These are local loopback resilience measurements, not WAN
throughput claims.

The final multi-container lifecycle harness forces the WAN probe to IPv4 so a
host without usable IPv6 does not turn DNS address ordering into a false
capture failure. On Docker Desktop for macOS, two initial unmodified Python
containers and one recreated instance all returned the Mac proxy's node exit
address; the watcher recorded three attachments, six TCP flows, and
four UDP flows. On RTX-PRO, rootful Docker recorded three attachments, six TCP
flows, and six UDP flows. Rootful Podman 3.4.4 on the same host recorded three
attachments, six TCP flows, and six UDP flows. All application containers
had proxy variables explicitly empty, and the recreated instance was captured
without restarting the watcher.

The CRI helper was exercised inside a disposable kind v0.30.0 Kubernetes
v1.34.0 node using its containerd runtime. An unmodified Python pod returned
the RTX-PRO WAN exit address, completed UDP DNS through the SOCKS
association, exposed seven attached BPF links plus map diagnostics, and caused
the helper to detach after Kubernetes deleted the pod. The kind cluster was
then deleted. This qualifies the one-container containerd helper and its
lifecycle; it does not qualify CRI-O or a cluster-wide policy controller.

The new `--check` path was run against sing-box on both current-kernel RTX-PRO
and the kernel-floor guest. It verifier-loaded and attached the exact embedded
object to an empty temporary cgroup, checked cgroup-v2 and loop avoidance, and
successfully negotiated SOCKS5 TCP CONNECT plus UDP ASSOCIATE. The loopback
status API was also exercised during live capture: it reported all seven BPF
links, bounded flow counters, map capacity/occupancy and memlock, then became
unreachable on teardown. BPF map diagnostics clone descriptors before
iteration and are cached for one second, so monitoring cannot hold the
datapath's backend lock while walking large maps.

The canonical Ubuntu 22.04 clang 14.0.0 rebuild is byte-identical to the
embedded BPF ELF at SHA-256
`8216fb35a58c35e53a7450034035c1cd39469a41fb2f28a1be8fb7927d46b44e`.
Ubuntu 24.04 clang 14.0.6 emits different debug/BTF metadata because its UAPI
headers and compiler build differ; after those metadata sections are removed,
the program/map object is byte-identical at SHA-256
`a58b0098e442d17f5ba5a9b7c4e136aa3128ee13e09f475c8c4b8acafdd2f480`.
Hosted CI enforces that normalized comparison and verifier-loads the rebuilt
object; the current-kernel and 5.10 runtime suites load the exact embedded ELF.

The OCI controller was reduced to a static `scratch` image. With BuildKit
inline provenance disabled (the public candidate workflow produces a separate
attestation), two independent amd64/arm64 OCI archives were byte-identical at
SHA-256 `62a86d62c89f1f331127948d31ab0d1398ddc7526d0768a7ac6452f34f9b0b5d`.
This digest is evidence from the development input used for the check, not a
published candidate checksum.

The release check generates separate amd64 and arm64 OCI SPDX documents rather
than letting the scanner silently select its host architecture. Syft's random
document namespace and wall-clock creation time are replaced with a stable
release namespace and `SOURCE_DATE_EPOCH`; package, file, relationship, and
checksum evidence is not modified. Both binary SBOMs and both per-platform OCI
SBOMs must now match across the two isolated candidate builds.

`scripts/benchmark-wan.sh` is the reproducible download harness. `curl` timing
includes DNS/TCP/TLS as applicable. Transparent `time_connect` ends at the
local redirect listener, so TTFB—not connect time—is the comparable latency
metric.

## WAN download results

| Mode | Median TTFB | Median total | Median throughput |
| --- | ---: | ---: | ---: |
| Direct | 375.1 ms | 4.043 s | 25.93 MB/s |
| Explicit SOCKS5 → mihomo | 354.4 ms | 3.350 s | 31.30 MB/s |
| eBPF transparent → tunless → mihomo | 351.6 ms | 4.060 s | 25.83 MB/s |

The transparent median was 0.4% slower than direct by throughput and 0.4%
longer by total time—well inside the run-to-run WAN spread. Explicit SOCKS
appearing faster is also network variation, not a claim that proxying improves
the link.

Raw total seconds / bytes-per-second:

| Run | Direct | Explicit SOCKS | Transparent |
| --- | --- | --- | --- |
| 1 | 4.1398 / 25,329,146 | 3.3497 / 31,303,542 | 3.3167 / 31,615,096 |
| 2 | 3.2860 / 31,910,145 | 3.8869 / 26,977,401 | 5.0949 / 20,580,874 |
| 3 | 3.3126 / 31,654,016 | 3.2325 / 32,438,937 | 4.0603 / 25,825,067 |
| 4 | 4.0435 / 25,932,500 | 4.0152 / 26,115,097 | 4.5747 / 22,921,352 |
| 5 | 4.2378 / 24,743,258 | 3.1872 / 32,900,062 | 3.4348 / 30,528,380 |

Across the five transparent 100 MiB transfers, `tunless` consumed 57 clock
ticks at 100 Hz (0.57 CPU seconds, about 2.8% of one core during their 20.48 s
aggregate wall time). Process RSS moved from 8,996 KiB to 9,012 KiB. The three
preallocated 65,536-entry LRU BPF maps report 17.5 MiB of kernel memlock in
total; LPM filter entries are additional and configuration-dependent.

After the final binary was rebuilt, a second three-run regression transferred
another 900 MiB with rotated ordering:

| Mode | Median TTFB | Median total | Median throughput |
| --- | ---: | ---: | ---: |
| Direct | 378.7 ms | 4.643 s | 22.58 MB/s |
| Explicit SOCKS5 → mihomo | 328.8 ms | 4.200 s | 24.97 MB/s |
| eBPF transparent → tunless → mihomo | 354.0 ms | 4.409 s | 23.78 MB/s |

The WAN variation again exceeds the difference between modes, so this is a
regression check rather than evidence that either proxy path is faster. During
the three transparent transfers, Tunless used 34 ticks at 100 Hz (0.34 CPU
seconds, about 2.3% of one core over their 14.75 seconds aggregate) and RSS
moved from 10,040 KiB to 10,052 KiB.

The final post-hardening binary transferred another 900 MiB over the real WAN
with the same three-mode rotation:

| Mode | Median TTFB | Median total | Median throughput |
| --- | ---: | ---: | ---: |
| Direct | 374.5 ms | 3.341 s | 31.39 MB/s |
| Explicit SOCKS5 → sing-box | 377.3 ms | 4.114 s | 25.49 MB/s |
| eBPF transparent → Tunless → sing-box | 328.1 ms | 4.164 s | 25.18 MB/s |

The three transparent transfers took 12.04 seconds in aggregate. Tunless used
35 clock ticks at 100 Hz (0.35 CPU seconds, about 2.9% of one core) and RSS
moved from 10,860 KiB to 11,156 KiB. As in the earlier samples, the result is a
regression/resource check over a variable WAN, not a ranking claim.

## Docker namespace throughput

A stock `python:3.11-slim` bridge container on RTX-PRO downloaded the same
100 MiB WAN object six times direct and six times through namespace-local
Tunless, in two alternating three-run blocks. The container had no proxy
environment and its route table was unchanged.

| Mode | Median TTFB | Median total | Median throughput |
| --- | ---: | ---: | ---: |
| Container direct | 362.3 ms | 5.068 s | 20.70 MB/s |
| Container namespace → Tunless → sing-box | 351.5 ms | 5.122 s | 20.52 MB/s |

The transparent median was 1.1% longer by total time and 0.9% lower by
throughput, again smaller than WAN run-to-run variation. Raw totals / bytes per
second were:

| Run | Container direct | Container transparent |
| --- | --- | --- |
| 1 | 3.2949 / 31,824,534 | 4.8813 / 21,481,533 |
| 2 | 5.2023 / 20,156,042 | 6.2605 / 16,749,060 |
| 3 | 4.0887 / 25,646,004 | 4.8467 / 21,634,902 |
| 4 | 5.7908 / 18,107,722 | 5.3625 / 19,553,928 |
| 5 | 5.1702 / 20,281,336 | 5.6112 / 18,687,308 |
| 6 | 4.9665 / 21,112,985 | 3.2236 / 32,527,814 |

Across 30.19 seconds of transparent transfer time, the two fresh controller
processes used 75 clock ticks at 100 Hz (0.75 CPU seconds, about 2.5% of one
core). Their RSS grew by 460 KiB and 448 KiB respectively after warm-up.

## WAN upload and cross-site path

A single 20 MiB Cloudflare upload sanity run produced:

| Mode | Total | Throughput |
| --- | ---: | ---: |
| Direct | 0.518 s | 40.52 MB/s |
| Explicit SOCKS5 | 0.313 s | 66.93 MB/s |
| Transparent | 0.481 s | 43.56 MB/s |

One sample is a functional/throughput sanity check, not a statistically useful
ranking.

For the real two-host path, RTX-PRO's local port `17897` was reverse-forwarded
to the Mac's SOCKS port `7897`; an unmodified captured process exited as the
Mac proxy's node exit address instead of RTX-PRO's own. The full 100 MiB
object completed in 41.50 s at 2.53 MB/s with 4.35 s TTFB. This validates the
RTX-PRO → Mac → proxy WAN topology, not the macOS Network Extension capture
path.

## Coexistence with an upstream TUN device

Measured 2026-08-25 on the local Apple Silicon Mac against Clash Verge
(mihomo, `mixed-port: 7897`) with its own TUN interface up: `auto-route: true`,
`enhanced-mode: fake-ip`, `fake-ip-range: 198.18.0.1/16`, and `utun1024`
holding the `0.0.0.0/1`-style split of the default route. Tunless build 11 ran
`start --preset clash-verge --upstream 127.0.0.1:7897` with no other flags.

Capture happens at the socket layer, before the routing table, so a captured
flow never reaches the route that points at the TUN. Interface byte counters
on `utun1024` measure that directly. The same 20 MB object was pinned to one
address with `curl --resolve` and fetched twice: once captured, once with that
address excluded so it fell through to the routing table.

| Path for the 20 MB object | Bytes across `utun1024` | Throughput |
| --- | ---: | ---: |
| Captured by tunless | 3,798 | 15.07 MB/s |
| Excluded, falls through to the TUN | 42,077,835 | 13.57 MB/s |

The 3,798 bytes are unrelated background traffic; the 42 MB is the payload
counted on both the inbound and re-emitted sides of the TUN's userspace stack.
Turning the upstream's TUN off therefore cannot speed up captured traffic: the
TUN is already not in its path.

Throughput either way sits inside the run-to-run spread of this WAN node.
Three interleaved runs of the same object gave 15.17, 19.96, and 19.48 MB/s
captured against 17.34, 24.13, and 19.97 MB/s through the TUN — a spread
within each path wider than the gap between their medians, so these
measurements support "no measurable difference", not a ranking.

## macOS capture on build 13

Measured 2026-08-25 on the local Apple Silicon Mac against Clash Verge
(`mixed-port: 7897`) with its TUN interface up, using the notarized build 13
that carries the reserved-destination floor, the health watchdog, the flow
ceiling, and executable-path process selection. The same 20 MB object was
pinned to one address with `curl --resolve` and fetched three times each way,
alternating configuration between batches.

| Path | Runs (B/s) | Median |
| --- | --- | ---: |
| Captured by tunless | 12,871,760 / 17,967,224 / 12,854,470 | 12.87 MB/s |
| Not captured | 11,005,640 / 17,487,760 / 13,112,114 | 13.11 MB/s |

Time to first byte was 0.47–0.54 s either way. The spread within each path is
wider than the gap between medians, so this supports "no measurable difference
on this path", not a ranking — the same conclusion the coexistence measurement
reached, now on the build that added per-flow reserved checks and a ceiling.

Executable-path resolution was exercised on the same build: 69 of 70 captured
flows resolved their audit token to an executable, and the one that did not was
a short-lived `curl` that exited before the lookup, which is the documented
best-effort fallback to the signing identifier.

**Deleting the app while capture runs.** `Tunless.app` was removed from
`/Applications` with capture live and no `stop` or `cleanup` first. The host
kept working — `www.debian.org` and `news.ycombinator.com` resolved to real
addresses, `github.com` returned 200 in 0.51 s, and the LAN gateway stayed
reachable at 4.6 ms. Capture did not stop: 867 flows were buffered during the
window and drained after reinstalling, and `systemextensionsctl` still reported
the extension `activated enabled`. Reachability survives an app deletion;
capture outlives it, and with the launcher gone the only ways to stop it are
System Settings or reinstalling the app.

**Provenance of the headline Linux numbers.** The WAN throughput and footprint
figures above were measured 2026-08-17 on a tree older than the current one.
The Linux datapath is unchanged since — the reserved-destination work adds
startup exclusions rather than touching the capture path — but the numbers have
not been re-taken on the current tree and should be before a Linux tag.

## Linux datapath on the current tree

Measured 2026-08-25 on Docker Desktop for macOS (server 27.3.1, kernel
6.10.14-linuxkit, ARM64, cgroup v2), running
`scripts/integration-docker-desktop.sh` against the current tree with sing-box
in direct mode as the SOCKS upstream.

The suite passed end to end: three controller attachments across two containers
and one recreated instance, six TCP flows, thirty-nine UDP flows, real WAN TLS
returning the host's own exit address, DNS over the SOCKS association with the
reply presented as coming from the resolver the application addressed, and
correct rejection of a second, ambiguous destination on an unconnected UDP
socket — twenty accepted and twenty rejected across forty alternating sends.

The run also exercised the startup reservation added for the loop this project
found on macOS: the controller logged `reserving datapath destinations from
capture` for the configured resolver, confirming the Linux side applies it.

This closes the datapath half of re-measuring Linux on the current tree. The
throughput and footprint half is still open: those figures need the documented
Linux host under a real WAN proxy, not a LinuxKit VM behind Docker Desktop, and
should be re-taken on the tagged tree.

## Linux capture on a third kernel, 2026-08-25

Run on a remote Debian 10 host, kernel `6.1.0-32-amd64`, x86-64, one vCPU,
cgroup v2, against the current tree. The recorded kernels were 5.10 and 6.8, so
6.1 is a new data point between them. Capture was scoped to a purpose-made
cgroup rather than the host's own slices, because the machine runs production
services whose egress must not move.

- `--check` reported `kernel` pass, `cgroup_v2` pass, and **`bpf_load_attach`
  pass**: the embedded programs loaded and attached on 6.1. It also reported
  `loop_avoidance` fail for the default scope, correctly, since tunless would
  have been inside the cgroup it was capturing.
- An unmodified `curl` inside the measured cgroup completed real WAN TLS
  through a direct-mode SOCKS5 downstream on the same host, and tunless
  recorded the flow. Six flows were captured across the run.

**Throughput over the WAN** could not resolve capture overhead on this link.
Five interleaved pairs gave 4.84, 0.53, 6.20, 5.52, and 5.89 MB/s captured
against 3.49, 4.60, 4.71, 0.92, and 1.70 MB/s direct. The spread inside each
side is an order of magnitude wider than any difference between them, so the
only honest reading is that this link cannot measure the question.

**Throughput at a rate the WAN cannot reach**, server and client on the host
with a non-loopback destination so the program still claims the flow, five
interleaved pairs of 200 MB:

| | Runs (MB/s) | Median |
| --- | --- | ---: |
| Captured | 199.2 / 108.9 / 160.2 / 107.3 / 107.8 | 108.9 |
| Direct | 120.9 / 112.6 / 117.7 / 113.2 / 182.2 | 117.7 |

The medians differ by about 7%, but the origin server here is Python's
`http.server` on a single vCPU and is itself the noisy component, so this
bounds the overhead rather than measuring it. It does establish that capture
sustains roughly 110 MB/s on one vCPU.

**Footprint** is the firmer result: relaying 1 GB captured cost 82 CPU ticks —
0.82 CPU-seconds per GB — with resident memory between 6.5 and 6.8 MB
throughout, consistent with the ~9 MB recorded on other hosts.

This does not replace the headline WAN figures, which were taken on a different
host under a real proxy and still need re-taking on the tagged tree. It does
show the datapath works on a third kernel with the current tree, and it is the
first footprint measurement taken under this tree.

## Linux WAN throughput and footprint on the current tree, 2026-08-25

Re-taken on RTX-PRO, Ubuntu 22.04.5, kernel `6.8.0-111-generic`, x86-64, 32
vCPUs, cgroup v2, with the current tree. This is the re-measurement the earlier
figures needed: those were taken 2026-08-17 on an older tree, and the headline
claim should not rest on a build that no longer exists.

Method as before, with two changes forced by the environment. The target is
`cachefly.cachefly.net/100mb.test`, because `speed.cloudflare.com` answers 403
from this host. The address is pinned with `curl --resolve` so no DNS leaves the
captured cgroup: the downstream is a direct-mode TCP-only SOCKS5 server, and a
captured UDP lookup through it would fail and be counted as capture overhead.
Capture is scoped to a purpose-made cgroup, and captured and direct runs are
interleaved so link drift cannot masquerade as overhead.

| Run | Captured (MB/s) | Direct (MB/s) |
| ---: | ---: | ---: |
| 1 | 112.77 | 112.71 |
| 2 | 112.92 | 113.32 |
| 3 | 112.82 | 112.89 |
| 4 | 112.82 | 113.13 |
| 5 | 112.53 | 113.22 |
| **Median** | **112.82** | **113.13** |

Captured throughput is **0.27% below direct**, and total time 0.30% longer
(0.9294 s against 0.9266 s median). Every one of the ten runs landed between
112.5 and 113.3 MB/s, so unlike the earlier WAN figures this link is stable
enough for the difference to mean something.

**Footprint**, measured separately over ten captured 100 MB downloads with the
process selected by executable name — matching the command line also matches
the `sudo` wrapper, whose CPU is nil and would understate the cost to nothing:

- 135 CPU ticks for 1,000 MB relayed, or **1.35 CPU-seconds per GB**
- Resident memory 9,936 KiB rising to 10,732 KiB, about **10 MB**, in line with
  the ~9 MB recorded previously

Together with the datapath evidence on kernel 6.1, this closes re-measuring
Linux on the current tree. The figures should still be confirmed on the tagged
commit, but they no longer rest on a tree that has since changed.

## Linux privileged WAN, UDP recovery, and container matrix, 2026-08-25

Run on the hosted `ubuntu-24.04` runner, x86-64, cgroup v2, against commit
`6ead291`, with sing-box 1.13.18 in direct mode as the SOCKS upstream. This is
the first full pass of the privileged suite since the resolver reservation
landed on 2026-08-24; the intervening failures were the suite's own probe
addressing the reserved resolver, not a capture defect.

```
wan_exit=<the host's own IPv4 exit>  udp_recovered_after_attempt=2  udp_flows=5  doctor=pass  status=pass
engine=docker    attachments=3 tcp_flows=6 udp_flows=6 recreated=yes
engine=podman    attachments=3 tcp_flows=6 udp_flows=7 recreated=yes
runtime=containerd-via-kind wan_exit=<same host exit> tcp_udp=pass lifecycle_detach=pass
```

Connected UDP recovered on the second attempt after the SOCKS relay was killed
and restarted underneath it, which is the fail-open-and-resume behavior the
README claims. Teardown left zero Tunless BPF links. The same suite passed on
`main` after merge and on two further runs.

Subject to the rule that dated evidence must name the tagged commit — this
names `6ead291`, not a candidate.

## Linux dual-stack destination filters, 2026-08-25

Run by `scripts/integration-linux-dualstack.sh` on the hosted `ubuntu-24.04`
runner, x86-64, cgroup v2, against commit `6ead291` with sing-box 1.13.18 in
direct mode as the SOCKS upstream. This is the first time the filters have been
exercised against an attached cgroup program rather than in userspace unit
tests, and it closes the gate that said so.

One `AF_INET6` socket with `IPV6_V6ONLY` cleared, reaching a routable IPv4
address on the host as `::ffff:10.1.0.18`, in three configurations:

```
dualstack host=10.1.0.18 port=28343 unfiltered_flows=1 mapped_spellings=0 excluded=0 include_elsewhere=0
```

- **Unfiltered**: the flow was captured, and the controller named the
  destination `10.1.0.18:28343`. No mapped spelling appeared anywhere in the
  log. That is the decode fix demonstrated on a real kernel rather than argued
  from unit tests.
- **`--exclude-destination 10.1.0.18/32`**: not captured. An IPv4 exclusion
  prefix covers the mapped form a dual-stack socket presents.
- **`--include-destination 203.0.113.0/24`**: not captured. Naming one
  unrelated IPv4 prefix restricts both families, rather than leaving the v6
  family wide open as an unset `has_include6` used to.

The echo completed in all three phases and in a baseline probe taken before any
capture existed, so "not captured" here means the flow went direct rather than
broke. The result does not depend on how the kernel dispatches a mapped
destination between the v4 and v6 hooks: whichever pair sees it, the assertions
are the same.

Subject to the rule that dated evidence must name the tagged commit — this
names `6ead291`, not a candidate, and should be re-taken on the tag.

## Gates not demonstrated

| Gate | Status / reason |
| --- | --- |
| Linux kernel floor on the current tree | The 5.10 evidence is the Lima ARM64 guest from 2026-08-17/19. Every datapath change since — the upstream and resolver reservation, the capture floor, the both-family filter change, the DNS override work, and the dual-stack decode fix — is unexercised on the oldest kernel this project supports, and its hosted job is gated behind `workflow_dispatch` with `run_kernel_5_10: true`, skipped in every recent run. 6.1 and 6.8 were re-taken on 2026-08-25; the floor was not. |
| Linux long-run soak | `scripts/tunless-linux-soak.sh` exists; no run has been recorded. `stress.sh` soaks the portable core under connection load, which is duration without the eBPF datapath and cannot see a capture that quietly stops claiming flows. |
| Rootful Podman teardown under CI | On 2026-08-25 the Podman lifecycle step timed out at the harness's 120-second guard during container teardown, with the controllers still attached to the container network namespaces, and passed on an immediate re-run with no change. Cause unestablished. `engine_command` now prints container, process, and BPF link state on a timeout so the next occurrence is diagnosable. Three clean runs have followed it, which is not the same as an explanation. |
| macOS exact release candidate | Builds 8 and 9 provide notarization, staple, Gatekeeper, activation, upgrade, and live-runtime evidence, but the current working tree is newer and has not completed exact-candidate clean-machine qualification. |
| macOS `remoteHostname` fraction | Activation and representative declined-flow behavior are verified, but a statistically useful fraction still requires a defined realistic app corpus; no number is invented. |
| macOS HTTP/3 | The installed curl lacks HTTP/3 support. HTTP/1.x, HTTP/2, TLS, DNS UDP/TCP, and non-DNS UDP passed, but no QUIC HTTP client was exercised. |
| Windows WDK build/runtime/UDP | Deferred to contributors: the maintainer has no Windows host. UDP is intentionally left direct. The open work is enumerated in [Windows notes](WINDOWS.md#deferred-to-contributors). |
| Windows verifier/fuzz/attestation/Secure Boot | Deferred to contributors. Requires a Windows test machine, and for signing an EV certificate and Partner Center identity the project does not hold. |
| Independent five-minute migration | Documentation exists, but no independent first-time user was available. |

These unmet items are release blockers for their respective platform, not
silent TODOs.

See also: [README](../README.md) for the claims this ledger backs, and
[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) for the release-time gate review.
