# Operations

How to validate, monitor, and safely run tunless in production, including the
opt-in DNS, metadata, and status surfaces.

*Audience: operators running tunless in production.*

## Preflight

Run the active diagnostic with the same backend, cgroup, namespace, filters,
upstream, and credentials intended for the service:

```console
sudo tunless --backend linux --cgroup /sys/fs/cgroup/my-apps \
  --upstream socks5://user:pass@127.0.0.1:7890 --check
```

The JSON report checks kernel/cgroup access, verifies Tunless is outside the
capture cgroup, loads and attaches the exact embedded BPF programs to an empty
temporary child, and performs real SOCKS5 TCP CONNECT plus UDP ASSOCIATE
commands. It removes the temporary cgroup and attachments before returning.
Use `--check-target IP:PORT` when `1.1.1.1:443` is not suitable. A failure exits
nonzero.

On macOS/Windows or with `--backend loopback`, the report validates the
privilege-free backend selection and upstream protocol. Platform extension
activation remains a separate qualification step.

The explicit SOCKS5/HTTP reference backend is unauthenticated and therefore
accepts only a numeric loopback `--listen` address. It is a local conformance
and bridge component, not a LAN proxy.

## Health and status

Enable the opt-in local API with `--status-listen 127.0.0.1:6060`. Only numeric
IPv4/IPv6 loopback addresses are accepted; wildcard, hostname, LAN, and Unix
socket listeners are rejected.

```console
curl --fail http://127.0.0.1:6060/healthz
curl --fail http://127.0.0.1:6060/v1/status
```

`GET /healthz` is a liveness response. `GET /v1/status` reports bounded flow
counters, backend resources, BPF map occupancy, and the credential-free
upstream address. In detail, the status body contains version/backend, the
upstream address without credentials,
trusted DNS address and whether override is enabled,
configured concurrency limit, accepted/completed/error/overload and active
TCP/UDP counters, open redirect listeners/sockets/BPF links, UDP associations,
and Linux map entry/capacity/memlock data. It intentionally omits destination,
process, and credential data. Protect host loopback access from untrusted local
users when these aggregate values are sensitive.
Map descriptors are cloned before occupancy is counted, so the potentially
long iteration does not hold the backend lock used by live flow correlation.
Capture diagnostics are cached for one second; polling faster only refreshes
the lock-free flow counters.

## Destination filters

`--exclude-destination` and `--include-destination` take CIDR prefixes and are
evaluated in the capture path itself, so an excluded flow stays direct rather
than being accepted and dropped. Exclusions are evaluated first. An include
list is an allowlist across both address families: with any `--include-destination`
present, a destination is captured only if it matches one of them, so naming
only IPv4 prefixes leaves IPv6 direct. A prefix applies however the program
reached the destination — a runtime that opens a single dual-stack socket for
both families sees the same filtering as one that opens an IPv4 socket.

## Destinations that are never captured

Loopback, the unspecified address, link-local (`169.254.0.0/16`, `fe80::/10`),
multicast, and broadcast are excluded by the capture program itself on Linux
and by the provider on macOS. SOCKS5 cannot carry any of them: an upstream
somewhere else cannot answer a router-discovery message, an mDNS query, or a
cloud instance's request to `169.254.169.254` about itself. Capturing them
removes reachability instead of adding a route, so no filter can put them back
— `--include-destination 0.0.0.0/0` included. The upstream and the trusted
resolver are reserved alongside them, for the loop described below.

How much of the resolver is reserved differs by platform, and it is worth
knowing which one you are on. macOS reserves the endpoint: the resolver's
address at the port capture rewrites to, so a connection to that same address
on another port is still captured. Linux reserves the address, at every port,
because its exclusions are prefixes and carry no port. Loop prevention only
needs port 53, so the Linux rule is the broader of the two: if the resolver's
address also serves something you meant to proxy — DNS-over-HTTPS on the same
IP is the usual case — that traffic goes direct on Linux. Choosing a resolver
address you do not otherwise talk to keeps the two rules equivalent.

## DNS override

Captured TCP and UDP queries whose original destination port is 53 are sent to
the numeric `--dns-upstream` through SOCKS5 by default. UDP query IDs are
translated per outstanding request and restored with the original resolver
source on reply, so reused IDs and out-of-order responses are unambiguous. The
translated ID is drawn at random, keeping the off-path spoofing resistance the
application's own random ID was there to provide. Use
`--disable-dns-override` or `TUNLESS_DISABLE_DNS_OVERRIDE=true` to retain each
application's original resolver. An `--upstream` written as a hostname is
resolved once at startup, and the numeric addresses it returned are what every
flow dials, in order, until one answers; the startup log records the name and
the addresses. Resolving per flow would put a lookup inside the path that
carries lookups. A record that changes later is picked up by restarting. `--flow-idle-timeout` and
`--udp-idle-timeout` bound abandoned flows; zero disables the corresponding
timeout.

## DNS observation (opt-in)

The observer forwards UDP and TCP DNS without changing answers, records A/AAAA
TTL mappings, and supplies a hostname only when exactly one unexpired name maps
to the address. A recorded mapping expires with the answer's TTL, bounded to a
day: an address outlives the name that pointed at it, and an attribution that
outlives its answer routes the address's next tenant under the old name's
rules. Ambiguous CDN addresses remain IP-only.

```console
tunless --upstream 127.0.0.1:7890 \
  --dns-listen 127.0.0.1:5353 --dns-upstream 1.1.1.1:53
```

Point selected clients at that listener yourself. It is opt-in and never edits
system DNS. Because it is unauthenticated, the observer accepts only a numeric
loopback listen address. Both UDP and TCP observer exchanges use the configured
SOCKS5 upstream rather than opening a direct resolver socket.

## Process metadata (opt-in)

`--metadata-socket /run/tunless/metadata.sock` exposes:

```text
GET /v1/flow?source_port=54321
```

over a mode-`0600` Unix socket. Entries exist only for the lifetime of the
SOCKS control connection. The socket's parent directory must already exist,
must be owned by the service user, and must grant no group or world access
(mode `0700`); `/run/tunless` is the recommended system location.
`--metadata-username` instead encodes
`pid=...;path=...;signing-id=...` as the SOCKS5 username and requires the
upstream to accept username/password negotiation. The path and signing-ID
values use URL query escaping so process-controlled `;` or `=` characters
cannot forge adjacent fields; consumers must decode each value separately.

## Capacity and alerts

`--max-flows` defaults to 4096. New flows above the limit are failed
immediately and counted: the flow is closed, `overloaded_flows` increases, and
no queue grows without bound. Choose a value below
the host file-descriptor and upstream capacity, then alert on:

- nonzero or increasing `overloaded_flows`;
- sustained `emitter_errors` or active-flow counts that never return;
- BPF map entries approaching `max_entries`;
- fewer than seven Linux BPF links while capture is meant to be running; and
- a stopped health endpoint or unexpected process restart.

TCP inactivity defaults to five minutes and UDP association inactivity to two
minutes. Any transferred byte or datagram refreshes the relevant deadline.
`--flow-idle-timeout=0` and `--udp-idle-timeout=0` disable them for protocols
that intentionally remain silent indefinitely; doing so also removes the
automatic completion bound for a peer that never closes.

The macOS provider exempts UDP port-53 flows from that two-minute association
limit. `mDNSResponder` owns and reuses those sockets; expiring the Network
Extension flow underneath one can leave later system lookups failing locally
instead of opening a replacement flow. DNS transaction attribution remains
separately bounded to 30 seconds and 4,096 outstanding entries.

The three large Linux LRU maps reserve kernel memory at load time. Consult the
measured memlock footprint in `MEASUREMENTS.md` before dense multi-container
deployment; each namespace controller owns independent maps.

## Failure and recovery

Graceful stop and process death close unpinned BPF links. New application flows
then continue directly without route or DNS repair; in-flight proxied streams
can fail and applications must reconnect. After an incident, confirm no stale
links with `bpftool link show`, run `--check`, then restart the controller.

For a container, stop/recreate changes its PID, cgroup, and namespace. The watch
helper discovers the replacement; one-shot helpers exit. Exact container-ID
validation prevents a recycled PID from being attached. An upstream restart
can break an existing association, but the next datagram recreates SOCKS5 UDP
state while retaining kernel socket correlation.

## Soaking a live capture

Short checks answer whether capture works. They cannot answer whether it keeps
working, and on this project that is where the serious defects have been: a
watchdog that mistook a sleeping laptop for a failing upstream left a macOS
host resolving names unprotected for nine hours, and nothing shorter than hours
could have seen it.

`scripts/tunless-linux-soak.sh` watches a running deployment on its own
schedule. Each tick resolves a name from inside the captured cgroup — not
beside it, because a lookup made outside the scope keeps working precisely when
capture has stopped carrying anything — and reads whether capture is still
claiming flows. Point `--status` at the controller's status API for the
stronger of the two readings: without it the soak can only see that BPF links
are attached, not that they are being used.

```console
sudo ./scripts/tunless-linux-soak.sh --status 127.0.0.1:6060 --interval 60
```

Ctrl-C prints the summary, and `--summary FILE` prints it for an earlier run.
It names three things a graph would hide: intervals where the host resolved
names while capture was gone, controller restarts that systemd performed
without comment, and wall-clock holes where no tick was written at all.

## Logs and privacy

JSON logs go to stderr. Debug flow logs may contain destinations, process paths,
or inferred domain names and should be treated as network metadata. Status
counters do not contain those fields. Never place SOCKS credentials in shared
logs, issue reports, shell history, or service files readable by other users.

## Upgrade and uninstall

Verify candidate checksums and SBOMs, run `--check` with the new binary, then
restart the service. A package upgrade must preserve `/etc/tunless.env`; the
file is installed as root-owned mode `0600` because it may contain SOCKS
credentials. Keep those permissions when managing it outside the package.
Uninstall stops/disables both the host and optional container-watcher units
through package scripts and removes the binary/units while leaving the
operator-owned config for deliberate cleanup.
Never replace a running privileged binary with an unreviewed source build.

The optional `tunless-container-watch.service` attaches only containers with
the configured `TUNLESS_CONTAINER_LABEL` (default `com.bojieli.tunless`). It is
packaged but never enabled automatically. Run it alongside `tunless.service`
when both host applications and labelled dev containers need the same upstream.

See also: [README](../README.md), [macOS notes](MACOS.md),
[container notes](CONTAINERS.md).
