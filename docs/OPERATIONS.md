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

Port 53 is the one exception, and only while a DNS override is configured.
Destination rules — the default private, CGNAT and `198.18.0.0/15` exclusions,
and any `--exclude-destination` or `--include-destination` — do not apply to a
port-53 flow, because a resolver's address is not a destination the application
chose to reach. It is a resolver the network handed out, which is precisely what
the override replaces, and judging the flow by that address is how a home
router's resolver inside `192.168.0.0/16` escapes the override entirely. macOS
additionally stops reserving link-local for port 53, since a router advertising
itself as the resolver over IPv6 does so at a link-local address. Process rules,
the upstream, loopback, and the unroutable set are all still reserved against it.

**The trusted resolver is reserved by transport rather than by address.** A
datagram sent to it is captured; a stream is not. Reserving the address outright
was the earlier rule, and it declined two different flows for the price of one.
The flow it needed to decline is the upstream's: capture rewrites a query to the
trusted resolver and relays it to the upstream, the upstream dials that resolver
itself, and capturing *that* dial hands the query back to the upstream waiting on
it — every lookup on the host then recurses until it times out, which reads as a
dead network rather than as a proxy loop. The flow it should not have declined is
an application's own query to the same resolver, and since `1.1.1.1` is both this
project's default `--dns-upstream` and one of the most commonly configured
resolvers there is, the people most likely to be protected were the ones getting
nothing.

The two are distinguishable. Capture rewrites the transaction ID of every query
it relays, to an ID drawn at random that the application never chose, and the
upstream forwards that query verbatim — so the datagram that would close the loop
carries an ID capture is still holding open, and an application's own query does
not. A stream carries nothing to recognise at connect time, so DNS over TCP to
the trusted resolver stays reserved. A transaction-ID collision costs one
datagram the override and the resolver client retries.

**DNS over TCP to a resolver on this network is left alone.** The route has to be
chosen before any bytes arrive, so capturing it means committing to the trusted
resolver for whatever the connection turns out to ask — which breaks exactly the
names a local resolver exists for. Datagrams carry their question in the first
packet, so the name-based split below decides them properly. Stub resolvers use
TCP only for answers too large to fit in a datagram.

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

## Answer-based and name-based resolver selection

Everything above sends every captured query to `--dns-upstream` through the
proxy, and that stays the default: with none of the flags in this section set,
nothing is asked of any other resolver.

Two costs come with routing every lookup through one tunnel. A geographically
aware name resolves from where the tunnel exits, so a service that would have
handed this host a nearby address hands it a distant one. And an upstream outage
does not degrade name resolution, it ends it — including for the destinations
`--exclude-destination` already keeps direct, which stay reachable but
unresolvable. The routes are fine. Nothing can learn an address to use them
with.

Two mechanisms buy those back, and they decide at different moments.

**A name list decides from the question**, before anything leaves the host:

```console
tunless --upstream 127.0.0.1:7890   --direct-domain-file /etc/tunless/direct-domains.txt   --trusted-domain internal.example.com
```

`--direct-domain` and `--direct-domain-file` name what the direct resolver
answers. `--trusted-domain` and `--trusted-domain-file` name what it must never
be asked. Both are repeatable, both take one suffix per line in a file, and both
work without `--dns-direct`: with no direct resolver configured, a
`--direct-domain` name goes to the resolver the application already chose, which
is the deterministic half of this feature without the heuristic half.

**An address set decides from the answer**, for every name nobody listed:

```console
tunless --upstream 127.0.0.1:7890   --dns-direct 223.5.5.5:53   --dns-direct-prefix-file /etc/tunless/near-networks.txt
```

Both resolvers are asked. The direct one is believed only when it returns an
address inside the prefix set.

The two compose, and the lists decide first. Where they overlap, the **longest
matching suffix wins** — `--trusted-domain secret.example.com` carves that name
out of a `--direct-domain example.com` — because that is what dnsmasq, mosdns
and systemd-resolved all do, and because the alternative silently does the
opposite of what an operator wrote. An exact duplicate across the two lists
resolves toward the tunnel.

### The rule, in order

1. The reserved and private name spaces, and `--local-domain`, go to the
   resolver the application chose. This is not a preference: those names have no
   answer anywhere else.
2. The longest matching `--direct-domain` or `--trusted-domain` suffix decides.
3. Otherwise, if `--dns-direct` is configured, both resolvers are asked:
   - The direct answer is served the moment it arrives, if it names at least one
     address inside the prefix set. Nothing waits for the tunnel, so a name the
     set covers resolves at the speed of the near resolver whether or not the
     upstream is up at all.
   - An answer naming addresses outside the set is not served. A good answer for
     a distant service and an injected one are the same message, so the trusted
     resolver decides — which is what would have happened without any of this.
   - An answer naming no address is served once the trusted resolver has had its
     chance and could not take it. There is nothing in it to misroute a
     connection to, and refusing it denies the name just as thoroughly. While
     the tunnel is up a forged NXDOMAIN still loses to the real answer.
   - If nothing believable arrives, the query fails with SERVFAIL rather than
     being answered with something unverified. Stub resolvers do not cache
     SERVFAIL, so a lookup retried after the tunnel returns gets the real answer.
4. Otherwise the trusted resolver, as before.

### What this does not do

**Adjudication reads addresses, so it applies to A and AAAA only.** HTTPS,
SVCB, MX, TXT, SRV and PTR go to the trusted resolver. SVCB matters most: a
browser asks for it on every navigation and the record carries the
encrypted-client-hello configuration, so serving one from the direct path would
inflict the downgrade this project exists to prevent. A name on a list is
routed whatever it asks for — the operator has already decided.

**Adjudication applies to DNS over UDP.** A query over TCP has to be routed
before any bytes arrive, the same limit `--local-domain` already documents.

**Only answers from the trusted resolver are learned from** for hostname
recovery, adjudicated exchanges included. See [DNS observation](#dns-observation).

**Every unlisted name is asked of the direct resolver.** That is inherent to
judging answers — you have to ask before you can judge — so a name you do not
want on that path belongs on `--trusted-domain`.

### The lists

Both kinds are one entry per line, with `#` or `;` starting a comment. They are
read once at startup; a changed list is picked up by restarting, the same
contract `--upstream` has for hostnames. Where the lists come from is yours:
`tunless` does not fetch, cache, or ship them, because a tool that refreshes a
subscription is the rule engine this project is not. A `sed` line to convert
whatever format your source publishes belongs in the timer that downloads it.

An incoherent combination is refused at startup rather than started:
`--dns-direct` without prefixes, prefixes without `--dns-direct`, either with
`--disable-dns-override`, or a list file that does not exist. Each of those has
a runtime appearance identical to the feature working perfectly and finding
nothing to do, which is the one failure an operator cannot tell apart by
looking.

### Seeing what it decided

```console
tunless --upstream 127.0.0.1:7890 --dns-direct 223.5.5.5:53   --dns-direct-prefix-file /etc/tunless/near-networks.txt   --explain www.example.com
```

`--explain` reports the route and the reason, and when both resolvers would be
asked it runs the real exchanges and prints what each returned, which addresses
fell inside the set, and the verdict. Nothing is captured while it runs.

`--status-listen` reports the same policy under `dns_policy`, with a count per
layer: how many queries each list decided, how many were adjudicated, and how
each adjudication came out. `served_direct` staying at zero on a network you
expect interference on means the set is misconfigured, not that the network is
clean — that is the failure this section exists to make visible.

## DNS observation

Capture feeds the same address-to-name map from the queries it relays, so a flow
that arrives without a hostname — which is every flow from an application with
its own DNS client, meaning every Chromium browser and Firefox — is emitted
under the name its own lookup asked for rather than under a bare address. That
runs whenever the DNS override does, and needs no listener. `--dns-listen`
additionally exposes the observer as a resolver applications can be pointed at.

Only answers that came back through the trusted resolver are recorded. An
association learned from an answer that arrived on the network's own path would
let whoever supplied that answer choose the name a later flow is proxied under,
which is the poisoning the override exists to route around, re-entering one
layer up.

Name recovery applies to streams. A datagram flow is emitted on its address even
when the name is known, and that is deliberate rather than unfinished: a SOCKS5
UDP relay reports the source of each reply, and an upstream asked to send to a
name reports the address it resolved that name to. mihomo was measured doing
exactly this — a datagram addressed to `dns.google` came back sourced from
`8.8.4.4`. An application using a connected UDP socket, which is every QUIC
client, would then have its replies arrive from an address it never wrote to and
dropped by the kernel. Emitting the address keeps QUIC working and costs
rule-by-name on that transport.

The observer forwards UDP and TCP DNS without changing answers, records A/AAAA
TTL mappings, and supplies a hostname only when exactly one unexpired name maps
to the address. A recorded mapping is held for at least thirty seconds even when
the answer's TTL is shorter, because an association is written when the answer
arrives and read when the connection opens: a browser resolves once and then
opens connections over the seconds that follow. Names published with a one-second
TTL are real, and honouring that literally meant the first connection was
recognised and the rest were not. A recorded mapping expires with the answer's TTL, bounded to a
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
