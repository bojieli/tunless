# Changelog

This project follows semantic versioning after its first public release. Dates
use ISO 8601.

## Unreleased

### Changed

- macOS now honors an application's explicit per-socket interface binding as a
  generic capture opt-out. `NEAppProxyFlow.isBound`, rather than a source-IP or
  interface-name heuristic, distinguishes intentional scope from the interface
  ordinary routing selected. This lets the outer sockets of independently
  developed local proxy transports stay direct without naming their process or
  server in Tunless. `--capture-bound-flows` restores strict capture for
  operators who prefer enforcement over that composability contract.

### Added

- macOS telemetry now records `interfaceName` and `isBound`; an intentionally
  declined bound flow is recorded as `route: "direct"` with
  `event: "bypass:bound-interface"`.

## 0.3.0 — 2026-09-01

### Fixed

- macOS health degradation no longer opens a proxy bypass. The provider used to
  return `false` for new eligible TCP and UDP flows after three failed DNS
  probes, which `NETransparentProxyProvider` defines as permission to connect
  directly. Existing UDP association failures also fell back to direct sends.
  Eligible traffic now remains captured: TCP retries use SOCKS or fail closed,
  and UDP drops individual datagrams until its disposable association rebuilds.
  Reserved endpoints, resolver-loop prevention, split-horizon local DNS, and
  explicit capture exclusions remain intentionally direct.
- Wi-Fi-to-Personal-Hotspot changes now invalidate transport state even when
  macOS reports both networks as `en0`. Path identity includes gateways, cost,
  endpoints, and protocol capabilities; each change advances a shared epoch,
  recycles TCP streams, and rebuilds UDP associations and direct local relays.
  Results and callbacks belonging to older path/provider generations are
  ignored, with a settling grace period and an immediate recovery probe.
- Live configuration changes now invalidate the health and transport generation.
  Long-lived UDP application flows read the latest configuration on every
  datagram and rebuild against a changed upstream without closing the socket.
- DNS loop-prevention registrations are reference-counted across UDP flows, and
  failed sends release only their own transaction. A saturated guard drops the
  query instead of risking recursive delivery back into the upstream.
- The macOS TCP flow ceiling now claims and refuses excess eligible streams
  instead of returning them to the kernel for a direct connection. UDP flows are
  excluded from that TCP ceiling because macOS cannot safely re-capture an
  application-owned datagram socket after the provider closes or declines it.

### Added

- macOS telemetry records whether traffic was `proxied`, intentionally `direct`,
  or `dropped` while remaining captured, so an original destination sent through
  SOCKS is no longer indistinguishable from a bypass.

## 0.2.3 — 2026-08-29

### Fixed

- The fix 0.2.2 shipped for an application's own query to the trusted resolver
  was inert on macOS. The flow was claimed — telemetry said so, which is what made
  it read as working — and then every datagram on it was sent direct anyway,
  because the datagram path asked whether the destination was reserved without
  saying it was a datagram, and the parameter defaults to the answer for a
  stream. On a host with the upstream's TUN underneath, `dig @1.1.1.1` kept
  returning a fake address from the datapath the query was supposed to bypass.
- A query already addressed to the trusted resolver is given an identifier of
  capture's own even though its route does not change. Without one the loop guard
  has nothing to recognise, so claiming those flows would have reopened exactly
  the loop the old address reservation existed to close: the upstream's forwarded
  copy would carry the application's identifier, look like an ordinary lookup, and
  be relayed again. It did not happen in 0.2.2 only because the first defect kept
  those flows from being relayed at all.

## 0.2.2 — 2026-08-29

### Fixed

- An application's own query to the trusted resolver is captured instead of
  declined. The resolver `--dns-upstream` names was reserved by address, which
  declined two different flows for the price of one. The flow that has to be
  declined is the upstream's own: capture relays a query to that resolver, the
  upstream dials it, and capturing that dial hands the query back to the upstream
  waiting on it — every lookup on the host then recurses until it times out. The
  flow that should not have been declined is an application configured to use the
  same resolver, and since `1.1.1.1` is both the default and one of the most
  commonly configured resolvers there is, the people most likely to be protected
  were the ones getting nothing: on a live host, `dig @1.1.1.1` came back with an
  address no part of the datapath had answered for. Capture rewrites the
  transaction ID of every query it relays and the upstream forwards that query
  verbatim, so the datagram that would close the loop carries an ID capture is
  still holding open while an application's own query does not. Streams stay
  reserved, because nothing identifies one at connect time.
- DNS over TCP to a resolver on this network is left alone rather than
  redirected. The route has to be chosen before any bytes arrive, so claiming it
  meant committing to the trusted resolver for whatever the connection turned out
  to ask, which broke exactly the names a local resolver exists for — 0.2.1
  redirected `nas.lan` over TCP to a resolver that has never heard of it. Public
  resolvers are still captured on both transports, having no local names to lose.
- An observed association is held for at least thirty seconds even when the
  answer's TTL is shorter. It is written when the answer arrives and read when the
  connection opens, and those are different moments: a browser resolves once and
  then opens connections over the following seconds. Names published with a
  one-second TTL are real — `news.ycombinator.com` is one — and honouring that
  literally meant the first connection was recognised by name and the rest were
  not.

### Documented

- Name recovery applies to streams, and a datagram flow is emitted on its address
  even when the name is known. This is measured rather than unfinished: a SOCKS5
  UDP relay reports the source of every reply, and an upstream asked to send to a
  name reports the address it resolved that name to — mihomo returned `8.8.4.4`
  for a datagram addressed to `dns.google`. A QUIC client uses a connected socket,
  so replies from an address it never wrote to are dropped by the kernel before
  the application sees them. Emitting the address keeps QUIC working and costs
  rule-by-name on that transport.

## 0.2.1 — 2026-08-29

### Fixed

- Capture claims port-53 flows whatever the destination rules say, while a DNS
  override is configured. The override could not see the resolver a home network
  hands out: routers live inside `192.168.0.0/16`, that range is excluded by
  default so nobody accidentally proxies their own LAN, and the exclusion was
  applied before the port was ever considered. Nothing errored. Queries went out
  on the network's own path, came back with whatever that path chose to answer,
  and every name on the host resolved to it. Link-local is no longer reserved
  against port 53 either, because a router advertising itself as the resolver
  over IPv6 does so at a link-local address. Process rules and the rest of the
  reserved set still apply, so the loop protection around the upstream and the
  trusted resolver is unchanged.
- macOS recovers the hostname for a flow that arrives without one. The system
  attaches `remoteHostname` only for names it resolved itself, so an application
  with its own DNS client — every Chromium browser, Firefox, anything shipping a
  resolver — produced flows carrying a bare address, and the proxy lost every
  rule written about names. Where the address came from a resolver that answered
  falsely, relaying it faithfully relayed the lie: the browser connected to
  somebody else's server while `curl`, whose name reached the proxy intact,
  worked from the same machine. The provider now records which name each address
  was answered for, from answers that came through the trusted resolver, and
  hands the name over instead. Associations expire on the TTL that carried them
  and are dropped when two names claim one address. Unlike a fake IP, a missing
  or ambiguous association costs only rule-by-name: the address is real and the
  flow still reaches it.
- Linux builds the same address-to-name map from captured DNS rather than only
  from `--dns-listen`, so name recovery no longer requires applications to be
  pointed at the observer — which the applications that need it never are.
- `Observer.Lookup` no longer returns a trailing root label. A rule engine that
  does not normalise `www.google.com.` misses every `DOMAIN` rule written for
  it.

### Added

- `--local-domain`, repeatable, names split-horizon zones that the DNS override
  must leave with the application's own resolver. Reserved and private name
  spaces — `.local`, `.home.arpa`, `.internal`, `.lan`, `.test`, `.localhost`,
  unqualified names, and the reverse zones for private, CGNAT and link-local
  space — are recognised without being named, and now go to the application's
  own resolver directly rather than through the proxy. A private resolver
  reached through a remote node is as unanswerable as a public resolver that
  never heard of the name. `TUNLESS_LOCAL_DOMAIN` sets it in the environment.

## 0.2.0 — 2026-08-27

### Fixed

- macOS: both DNS probes read a relayed answer at a fixed ten-byte offset,
  which is the SOCKS5 UDP header length only when the upstream reports an IPv4
  source. An upstream answering from an IPv6 address, or naming the resolver
  rather than addressing it, had a perfectly good answer read at the wrong
  offset and reported as no answer at all. At preflight that tells an operator
  UDP relaying does not work and switches the watchdog to TCP-only probing for
  the whole session; on the watchdog it fails a healthy upstream until capture
  stands aside. The header is parsed now.
- A datagram the flow declines no longer ends the UDP association. A resolver
  answering the same query twice produces one: the first answer consumes the
  DNS transaction, so the second arrives still naming the trusted resolver as
  its source, the backend rejects it against its record of where the
  application actually wrote, and every other query in flight on that socket
  used to go with it. Duplicate answers are most common exactly when the
  network is already retransmitting. Datagrams neither side can carry are
  counted and reported when the association ends.

- macOS: `--disable-dns-override` switched off every check that watches DNS —
  the preflight proof, the post-start verification, and the runtime watchdog —
  on the premise that capture does not touch port 53 without an override. It
  does: the flag preserves each application's resolver and keeps relaying the
  query, so the upstream could still take resolution down host-wide with
  nothing watching. Verification now runs whenever `--skip-verify` was not
  passed, and the watchdog probes the resolver capture is actually carrying,
  learned from the flows, over the transport those flows used.

- macOS: the extension and app build numbers are bumped to 15, in
  `macos/project.yml`, which is where they actually come from — the checked-in
  `Info.plist` files are xcodegen output, so editing them looks like a bump and
  is silently reverted by the next generate. Build 14 was published twice with
  different extension code, and macOS keys system-extension replacement on that
  number, so an install could leave the earlier binary running while `status`
  reported the newer version. The release checklist now gates on it.

- macOS: a captured UDP flow is no longer closed by the provider, ever. It used
  to end whenever the transport under it did — a watchdog pause, a SOCKS5
  handshake that timed out against a busy mixed port, an upstream that dropped
  its UDP association, or two minutes of an idle one — and macOS treats a
  datagram flow the provider closed as final: it neither re-captures the
  socket above it nor hands it back to the kernel, so every later send on that
  socket fails locally. `mDNSResponder` holds one resolver socket per
  delegated client and never replaces it, so one closed flow ended name
  resolution for one application, for as long as the daemon ran, while the
  rest of the host resolved normally and made it look like a problem with the
  site. The upstream association is now the disposable half: it is retired and
  rebuilt underneath a flow that stays open, datagrams go out directly while it
  cannot carry them, and the application's socket is never touched. The
  ten-second guard around opening a flow follows the same rule: it closes
  streams, so the application retries directly, and leaves datagram flows
  alone. Observed on
  a live host as `sending ... failed: [22: Invalid argument]` repeating for
  hours after a single pause, with one application's lookups timing out at
  thirty seconds and everything else unaffected.
- macOS: a reply that arrives from the resolver the DNS override rewrites to,
  answering no query it rewrote, is withheld rather than handed up carrying a
  transaction identifier the application never chose. Replies from any other
  peer are untouched, so an unconnected socket talking to many peers is
  unaffected.

- `doctor` reported "privilege-free backend selected" for `--backend redirect`,
  which is the answer every backend that is not the eBPF one received. That
  backend is the opposite of privilege-free: it wants `NET_ADMIN` and a
  netfilter rule somebody else installed. It now checks what the backend
  actually needs, which is a loopback listener, no process filters, a kernel
  that answers `SO_ORIGINAL_DST`, and a rule pointing at the listener. The rule
  is reported as a warning rather than a failure, because it may legitimately
  be installed after the check runs.

### Added

- `--backend redirect` captures flows that netfilter has already redirected to
  a local listener, for hosts where the eBPF backend cannot run: an older
  kernel, a distribution that disables unprivileged BPF, or an operator who
  will grant `NET_ADMIN` and not `CAP_BPF`. The kernel still terminates TCP, so
  a connection arrives as an ordinary socket and `SO_ORIGINAL_DST` says where
  it was going, which is why this rather than a TUN device that would need a
  second TCP/IP stack in userspace. It gives up fail-open, since the rule
  outlives the process, and it cannot attribute processes, so process filters
  are refused rather than silently matching nothing. `auto` never selects it.
  See [docs/REDIRECT_BACKEND.md](docs/REDIRECT_BACKEND.md), which also records
  why there is no third, TUN-based backend: the host it would serve, one that
  can create a tunnel device but cannot filter, has not been produced, and a
  virtual interface is a permanent non-goal for this project.
- `--cgroup kubernetes` picks a node's pod hierarchy for capture and refuses
  the setups that would capture the agent's own traffic. A DaemonSet is itself
  a pod, so attaching at the pod root loops. Loop avoidance stays cgroup
  separation rather than an exception list, and the remaining gap, that an
  agent can't capture other pods in its own QoS class this way, is reported
  rather than worked around. See [docs/CONTAINERS.md](docs/CONTAINERS.md).
- The metadata endpoint's JSON shape is pinned by a test, since consumers live
  in other repositories and decode it by hand. Renaming a field would otherwise
  break one silently: the lookup keeps returning 200 and the consumer keeps
  reading zeroes. See [docs/FLOW_ATTRIBUTION.md](docs/FLOW_ATTRIBUTION.md).
- Per-flow workload attribution on Linux. The cgroup a captured process belongs
  to resolves to a Kubernetes pod UID, a container ID, or a systemd unit, and
  travels alongside the existing process fields. We parse both cgroup drivers,
  since both are deployed and reading one as the other gives you a pod UID that
  looks plausible and matches nothing. We deliberately don't derive the pod's
  namespace and name: those live in the API server, and inventing them would
  produce a guess you can't distinguish from a fact. See
  [docs/FLOW_ATTRIBUTION.md](docs/FLOW_ATTRIBUTION.md) for what's available and
  what you can rely on.

## 0.1.0 — 2026-08-25

Preview release. See
[docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md) for what that means.

### Added

- A capture floor the configuration cannot reach past: loopback, the
  unspecified address, link-local, multicast, broadcast, the SOCKS5 upstream,
  and the trusted resolver's own endpoint are reserved from capture on macOS
  and Linux. Reserving the resolver ends the DNS recursion that a proxy running
  its own TUN and DNS hijack produced, without depending on the operator naming
  the upstream's process.
- Private, carrier-grade NAT, and `198.18.0.0/15` fake-IP ranges excluded by
  default on macOS, with `--include-destination` overriding per prefix and
  `--no-default-exclusions` dropping the set.
- macOS process selection that matches the executable path and its basename as
  well as the signing identifier, so a rule can name one program even when the
  toolchain gave it a default identifier shared with unrelated binaries;
  telemetry carries the executable behind each flow.
- A macOS flow ceiling (`--max-flows`, default 4096) matching the portable
  core, so one application cannot push the extension into the CPU budget macOS
  terminates it for. Rejected flows go direct.
- macOS health probing over both DNS transports, gated on what preflight
  observed, so an upstream that stops relaying UDP no longer looks healthy to a
  TCP-only probe.
- A Linux soak harness (`scripts/tunless-linux-soak.sh`) that ticks on its own
  schedule, resolves a name from inside the captured cgroup, and asserts that
  capture is claiming flows while it does. It records every unprotected
  interval, every controller restart systemd performed quietly, and every
  silent hole where the host stopped ticking at all, and summarises them at the
  end. Linux is the platform this project calls generally available and the
  only thing watching it over time was a connection stress test against the
  portable core; a 48-hour run is now a release gate, as it already was on
  macOS.
- A live dual-stack destination-filter suite
  (`scripts/integration-linux-dualstack.sh`, wired into the privileged Linux
  workflow) that drives one AF_INET6 socket at an IPv4 destination through an
  attached cgroup program and asserts what the filters actually did: the flow
  is captured and reported unmapped, an IPv4 exclusion prefix covers the mapped
  form, and an include list naming only an unrelated prefix declines to capture
  it. Those three behaviors were fixed with userspace unit tests, which cannot
  say which map the kernel consults.
- A macOS soak harness (`scripts/tunless-macos-soak.sh`) that asserts
  resolution and capture state across sleeps, wakes, and network changes, plus
  release gates for a 48-hour soak and for surviving an app deletion while
  capture runs.
- A macOS capture health watchdog that re-proves name resolution through the
  live upstream every 30 seconds. After three consecutive failures the provider
  stops claiming flows, so they go direct as though tunless were not installed,
  and it resumes on the first probe that succeeds again. A probation window
  covers a start that is never confirmed. Sleep suspends the watchdog and a
  wake discards the failures that led into it, so a sleeping laptop cannot pause
  capture and wake up unprotected. `status` reports what capture is doing in a
  `capture` field, and every transition is written to the unified log under
  subsystem `com.bojieli.tunless`. `--no-health-watchdog` opts out.

- Idempotent macOS `stop` and `cleanup` recovery commands, a bounded cleanup
  script bundled in the app, stale-manager removal, Network Extension
  deactivation, and a documented manual disable path for fail-safe recovery.
- A focused macOS Clash Verge companion preset with automatic loop exclusions,
  SOCKS5 preflight, strict launcher commands, and non-destructive status output.
- Default-on, numeric trusted-DNS override for the portable/Linux emitter and
  macOS provider, a cross-platform disable switch, SOCKS-routed DNS observation,
  and bounded transaction-ID translation for unambiguous UDP response restore.
- Bounded TCP/UDP inactivity, hard-error and pending-callback cancellation,
  joined UDP worker teardown, short-write-safe SOCKS control messages, macOS
  active-flow cancellation, SOCKS half-close draining, and TCP plus UDP
  completion telemetry.
- An optional macOS user LaunchAgent that persists bounded, private flow
  telemetry under `~/.tunless`, with size-based rotation.
- Linux cgroup eBPF capture for TCP and connected/unconnected UDP over IPv4 and
  IPv6, including namespace-local Docker, Podman, and one-container
  Kubernetes/containerd application capture.
- SOCKS5 TCP/UDP relay, optional real-answer DNS observation, metadata
  transports, bounded runtime statistics, a loopback-only status API, and an
  active `--check` diagnostic.
- macOS Network Extension and Windows WFP source paths with explicit runtime
  qualification gates.
- Kernel 5.10 and current-kernel integration harnesses, fuzz targets, stress and
  WAN benchmarks, deterministic BPF verification, SBOMs, packages, OCI output,
  and a non-publishing release-candidate workflow.
- Reproducible static `scratch` controller images plus amd64/arm64 DEB, RPM,
  archive, and OCI install/runtime smoke tests.
- Deterministic SPDX SBOMs for both raw binaries and each OCI architecture,
  plus synchronized third-party license notices carried by every archive and
  native package.

### Fixed

- macOS watchdog pauses no longer error-close UDP flows that the operating
  system may keep using. A closed flow left `mDNSResponder` sending through a
  stale resolver socket, where every send failed locally with `EINVAL`; `dig`
  still worked because it opened a fresh socket while `getaddrinfo`, curl, and
  applications could hang indefinitely. Existing datagram flows now stay open
  and route directly while capture stands aside, port-53 flows are exempt from
  the generic UDP idle expiry, and provider shutdown ends UDP flows cleanly.
- The DNS observer no longer fails to start when the kernel hands it an
  ephemeral UDP port whose TCP half is already taken. It answers on both
  transports at one port number, and asking the kernel for an ephemeral UDP
  port reserves nothing on the TCP side, so `--dns-listen 127.0.0.1:0` failed
  with `bind: address already in use` on a busy host — rarely, unpredictably,
  and for no reason an operator could act on. The coordinated bind is retried
  up to eight times. A fixed port is still attempted exactly once, so a pinned
  observer reports the conflict rather than moving somewhere nobody asked for.
- A `--upstream` given as a hostname is resolved once at startup and pinned to
  the addresses it returned, instead of being resolved again on every flow. The
  per-flow lookup was a loop: tunless normally shares the captured cgroup, so
  dialing the upstream needed a name lookup, and capturing that lookup needed
  the dial. Resolution recursed until the flow ceiling rejected it, which
  presents as a machine whose DNS stopped working. Every pinned address is
  tried in turn, so a proxy named `localhost` still reaches whichever of ::1
  and 127.0.0.1 it listens on, and all of them are reserved from capture.

### Security

- Linux destination filters mean the same thing whatever socket a program
  used. An IPv4 prefix now also covers the IPv4-mapped form that a dual-stack
  socket presents, so `--exclude-destination 10.0.0.0/8` is no longer silently
  inapplicable to runtimes that open one socket for both families, and a prefix
  written in mapped form is loaded into the IPv6 map at its own length instead
  of being unmapped into an IPv4 map that cannot hold it.
- Linux userspace reads a dual-stack record as the destination it actually
  reaches. The IPv6 hooks record `AF_INET6` because the socket was, not because
  the destination is, so a program that opens one socket for both families
  arrived as `::ffff:10.0.0.1`. An IPv4 prefix does not contain a mapped
  address, so the userspace half of `--exclude-destination 10.0.0.0/8` still
  did not apply to those flows after the BPF maps learned to cover them; the
  DNS observer could not attribute a hostname it had recorded against the
  unmapped answer; a UDP reply was checked against the mapped form and
  rejected, which an application sees as a datagram that never arrives; and the
  log line named an address nobody had configured. Records are unmapped once,
  at the decode boundary, so everything downstream agrees on one spelling.
- A Linux include list is an allowlist across both address families, matching
  macOS. Naming only IPv4 prefixes used to leave `has_include6` unset, which
  captured every IPv6 destination — the opposite of narrowing.
- The Linux capture floor now actually covers what the macOS one does. Only
  loopback was refused outright; link-local, multicast, broadcast, and the
  unspecified address were left to the operator, so
  `--include-destination 0.0.0.0/0` — the example in this project's own README
  — sent mDNS, router discovery, and a cloud instance's queries to
  169.254.169.254 into the upstream, which cannot answer any of them.
- Observed address-to-name mappings expire after at most a day, whatever TTL
  the answer carried. A record may claim a century, which is a claim on every
  future tenant of a recycled address rather than a statement about freshness.
- The Linux IPv4 redirect socket drops datagrams that were not delivered to a
  loopback address. It binds the wildcard because each captured UDP association
  is redirected to its own 127.x relay address and a socket bound to one
  address would see only one of them, which leaves a port reachable from the
  network; correlation refused a foreign datagram already, and now the receive
  path says so where it is relied on.
- Both DNS forwarding paths now check that a datagram answers the query before
  treating it as the answer: the transaction ID has to match and the response
  bit has to be set. Previously the first datagram to reach the socket was
  returned, so a forged one — cheap for anyone who can guess an ephemeral port
  — consumed the exchange and the real answer arrived to a closed socket. The
  observer's own recording already held replies to this standard; the
  forwarding path did not.
- The private DNS transaction ID that replaces an application's own while a
  port-53 query is routed to the trusted resolver is now drawn at random on
  both macOS and the portable emitter. It was counted out from zero, which
  handed every rewritten query an ID an off-path attacker could predict —
  exactly the guesswork RFC 5452 randomization exists to prevent, removed by
  the rewrite rather than by the application.
- Exact cgroup/container identity validation, privilege separation, fail-open
  BPF lifecycle, bounded flow concurrency, full-history secret scanning,
  public-release gates for CodeQL, dependency review, and provenance
  attestations.
- Bounded DNS attribution state with CNAME-chain validation, failure-safe
  private metadata-socket permissions, strict release-version validation, and
  workflow input isolation for release-candidate builds. Process-controlled
  metadata username fields are delimiter-escaped before SOCKS authentication;
  valid SemVer build metadata is mapped safely into OCI tag syntax. DNS TCP
  framing now completes short writes rather than silently truncating messages.
- Unauthenticated reference-proxy, DNS-observer, and status listeners are
  restricted to numeric loopback addresses and ports; auxiliary service
  failures now produce a fatal process result instead of a clean exit. Private
  metadata sockets also require private parent directories, never remove a
  pre-existing socket they did not create, and requested auxiliary services
  must become ready before capture starts. Status and metadata HTTP connection
  counts are bounded against local slow-connection exhaustion.
- Hosted checks do not persist checkout credentials into code under test, use
  explicit runner images, and gate public-only dependency review consistently.
- Linux UDP associations include the kernel socket cookie so endpoint reuse
  cannot inherit an older userspace session; malformed kernel-map records and
  invalid or oversized datagrams fail closed. An active unconnected association
  rejects a different destination rather than overwriting in-flight source
  attribution, while connected associations retain marked recovery state and
  unconnected state is released on association turnover. DNS attribution now
  matches the requested A/AAAA type and uses the shortest validated
  CNAME/address TTL. DEB/RPM config is root-owned mode `0600`, and pre-install
  scripts reject an existing `/etc/tunless.env` symlink before package
  extraction.
