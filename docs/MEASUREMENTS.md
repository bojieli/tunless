# Measurements and release gates

Measured 2026-08-17. These results distinguish implementation from release
qualification; an untested gate is not called complete.

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

## Follow-up hardening validation

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
reported `155.103.252.95`. The harness kept one connected UDP socket open,
killed and restarted sing-box, and recovered that same socket on its second
retry. Five UDP flow events were observed across the run, and teardown left
zero Tunless BPF links. This specifically validates preservation of the kernel
socket correlation needed to create a new SOCKS UDP association after an
upstream failure.

On macOS Docker Desktop, the updated controller image and host bridge captured
an unmodified `python:3.11-slim` container. WAN TLS reported the Mac proxy exit
`23.135.236.244`; a UDP DNS query returned 45 bytes with its original
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
containers and one recreated instance all returned the Mac proxy exit
`23.135.236.244`; the watcher recorded three attachments, six TCP flows, and
four UDP flows. On RTX-PRO, rootful Docker recorded three attachments, six TCP
flows, and six UDP flows. Rootful Podman 3.4.4 on the same host recorded three
attachments, six TCP flows, and six UDP flows. All application containers
had proxy variables explicitly empty, and the recreated instance was captured
without restarting the watcher.

The CRI helper was exercised inside a disposable kind v0.30.0 Kubernetes
v1.34.0 node using its containerd runtime. An unmodified Python pod returned
the RTX-PRO WAN exit `155.103.252.95`, completed UDP DNS through the SOCKS
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
`a915ec5fb1c6b5a0b9549c98bd8689b6dd8bfaa1cdffcea89f3675af74c9cd80`.
Ubuntu 24.04 clang 14.0.6 emits different debug/BTF metadata because its UAPI
headers and compiler build differ; after those metadata sections are removed,
the program/map object is byte-identical at SHA-256
`61cd30e8b026cf2f90742ae54f2533f480d987ad3ef198e9cae554664086ad99`.
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
to the Mac's SOCKS port `7897`; an unmodified captured process exited as
`23.135.236.244` instead of RTX-PRO's direct `155.103.252.95`. The full 100 MiB
object completed in 41.50 s at 2.53 MB/s with 4.35 s TTFB. This validates the
RTX-PRO → Mac → proxy WAN topology, not the macOS Network Extension capture
path.

## Functional gates demonstrated

- Portable Go: race-enabled TCP/UDP, IPv4/IPv6, 2 MiB bidirectional/half-close,
  cancellation, destination, process metadata, SOCKS5 and HTTP CONNECT tests.
- Reference backend: its SOCKS5 and HTTP CONNECT inbounds both completed through
  a real mihomo v1.19.30 downstream on RTX-PRO; the HTTPS checks returned the
  server's `155.103.252.95` exit address and HTTP 200 respectively.
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
- macOS: the 12-test Swift suite and universal Release containing-app/system-
  extension build pass. On 2026-08-17, build 8 (`1.0.7`) was signed with
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

## Gates not demonstrated

| Gate | Status / reason |
| --- | --- |
| macOS `remoteHostname` fraction | Activation and representative declined-flow behavior are verified, but a statistically useful fraction still requires a defined realistic app corpus; no number is invented. |
| macOS HTTP/3 | The installed curl lacks HTTP/3 support. HTTP/1.x, HTTP/2, TLS, DNS UDP/TCP, and non-DNS UDP passed, but no QUIC HTTP client was exercised. |
| Windows WDK build/runtime/UDP | No Windows+WDK host was available. UDP is intentionally left direct. |
| Windows verifier/fuzz/attestation/Secure Boot | Requires a Windows test machine, EV/Partner Center identity, and Microsoft attestation. |
| Independent five-minute migration | Documentation exists, but no independent first-time user was available. |

These unmet items are release blockers for their respective platform, not
silent TODOs.
