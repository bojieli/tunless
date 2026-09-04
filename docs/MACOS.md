# macOS

On macOS, tunless runs as an `NETransparentProxyProvider` system extension that captures TCP and UDP flows and emits them to a local SOCKS5 upstream, with a small launcher app for activation and configuration. Recorded development builds have been notarized and exercised live; the exact release candidate still requires the clean-machine qualification tracked in the release checklist.

*Audience: developers building or running the macOS system extension, and operators deploying it alongside a Clash Verge (mihomo) upstream.*

## Overview

The macOS datapath lives inside `NETransparentProxyProvider` because
`NEAppProxyFlow` is not a file descriptor that can be handed to the Go process.
The extension therefore owns SOCKS5 TCP CONNECT, UDP ASSOCIATE, and byte or
datagram relaying. The containing app is only an activation/configuration
launcher.

The provider records protocol, original destination, rewritten SOCKS
destination (when different), `remoteHostname` when supplied by the OS, and
source signing identifier. It returns `false` for excluded flows, letting the
OS handle them directly. Provider-owned egress is not handed back to the
provider, which is structural loop avoidance. Re-running the launcher sends new
configuration to an active provider.

## Requirements

- macOS 15 or newer for the APIs used by this implementation;
- membership in the Apple Developer Program;
- provisioning for `com.bojieli.tunless.Tunless` and
  `com.bojieli.tunless.TunlessProxy`;
- the `system-extension.install` and
  `app-proxy-provider-systemextension` entitlements already declared in the
  project;
- the sandboxed provider's `com.apple.security.network.client` entitlement, so
  it can open the TCP and UDP connections to the local SOCKS5 listener;
- Developer ID signing and notarization for distribution.

## Build

Signed release builds are produced by CI; see
[Signing and notarization](#signing-and-notarization). Build without signing
for code/test validation:

```console
cd macos
swift test
cd ..
xcodegen generate --spec macos/project.yml
xcodebuild -project macos/Tunless.xcodeproj -scheme Tunless \
  -configuration Debug -derivedDataPath /tmp/tunless-derived \
  CODE_SIGNING_ALLOWED=NO build
```

## Signing and notarization

Release signing and notarization run on GitHub Actions
(`.github/workflows/macos-release.yml`), triggered by a `v*` tag push or
manually via `workflow_dispatch`. The job builds a universal Release archive,
signs it, notarizes it, staples the ticket, and uploads the verified bundle as
a build artifact. It never publishes a release.

The workflow needs these repository secrets:

| Secret | Contents |
| --- | --- |
| `APPLE_DEVELOPER_ID_P12` | base64 PKCS#12 with the Developer ID Application certificate and key |
| `APPLE_DEVELOPER_ID_P12_PASSWORD` | password for that PKCS#12 |
| `APPLE_PROVISIONING_PROFILE_APP` | base64 `.provisionprofile` for `com.bojieli.tunless.Tunless` |
| `APPLE_PROVISIONING_PROFILE_EXT` | base64 `.provisionprofile` for `com.bojieli.tunless.TunlessProxy` |
| `APPLE_API_KEY_P8` | App Store Connect API private key, PEM text |
| `APPLE_API_KEY_ID` | key id for that private key |
| `APPLE_API_ISSUER_ID` | issuer id for that private key |
| `APPLE_TEAM_ID` | Apple Developer team identifier |

The certificate is imported into an ephemeral keychain created under
`RUNNER_TEMP` with a random password, and the keychain, decoded key material,
and installed profiles are deleted in an `always()` cleanup step.

Signing is done by `scripts/macos-sign.sh` rather than
`xcodebuild -exportArchive`, so the archive step runs with
`CODE_SIGNING_ALLOWED=NO`. The reason is that `xcodebuild` under
`CODE_SIGN_STYLE=Manual` refuses a profile marked `IsXcodeManaged`, and the
team's only valid Developer ID Direct profiles carry that flag; automatic
signing is not an option because it needs an interactive Apple ID session.
`codesign` applies no such restriction. The script embeds each profile as
`Contents/embedded.provisionprofile`, merges the
`com.apple.application-identifier` and `com.apple.developer.team-identifier`
values read from the profile into a copy of the project's entitlements, and
signs the system extension before the app so the outer seal covers the inner
one. It refuses to sign when a profile does not authorize the bundle
identifier it was passed for.

Entitlements are merged with `PlistBuddy`, which treats `:` as its keypath
separator. `plutil -extract` and `plutil -insert` cannot be used here: they
treat `.` as a separator, so a dotted entitlement key such as
`com.apple.developer.system-extension.install` is read as a nested path.

The workflow then asserts a Developer ID authority, the hardened runtime flag,
and the required entitlements on both bundles; submits the zipped app to the
notary service with `notarytool submit --wait`, dumping the notary log on
failure; staples with a bounded retry because ticket propagation can lag
acceptance; and finishes with `stapler validate`, `codesign --verify --deep
--strict`, and `spctl --assess`.

To sign a local build the same way, archive unsigned and invoke the script
directly:

```console
xcodegen generate --spec macos/project.yml
xcodebuild archive -project macos/Tunless.xcodeproj -scheme Tunless \
  -configuration Release -destination 'generic/platform=macOS' \
  -archivePath /tmp/Tunless.xcarchive \
  ARCHS="x86_64 arm64" ONLY_ACTIVE_ARCH=NO CODE_SIGNING_ALLOWED=NO
cp -R /tmp/Tunless.xcarchive/Products/Applications/Tunless.app /tmp/Tunless.app
scripts/macos-sign.sh --app /tmp/Tunless.app \
  --identity 'Developer ID Application: NAME (TEAM)' \
  --app-profile APP.provisionprofile \
  --ext-profile EXT.provisionprofile
```

### Notarizing by hand

Prefer the workflow. When notarizing manually, verify the exact bundle that
will be installed. `store-credentials` prompts for the app-specific password
and stores it in the login Keychain; never put that password in the command
line or repository:

```console
xcrun notarytool store-credentials tunless-notary \
  --apple-id APPLE_ID --team-id TEAM_ID
ditto -c -k --keepParent Tunless.app Tunless.zip
xcrun notarytool submit Tunless.zip \
  --keychain-profile tunless-notary --wait
xcrun stapler staple Tunless.app
xcrun stapler validate Tunless.app
codesign --verify --deep --strict --verbose=2 Tunless.app
spctl --assess --type execute --verbose=4 Tunless.app
```

If the accelerated upload times out before transferring any bytes, submit the
same archive again with `--no-s3-acceleration`. Do not install until that
complete upload reports `Accepted` and the staple, signature, and Gatekeeper
checks all pass.

`stapler` fetches the ticket from `api.apple-cloudkit.com`. If the upstream
proxy answers DNS in fake-IP mode, that name resolves into the fake range
(`198.18.0.0/15`) instead of its real address, and stapling fails with a
CloudKit timeout and `Error 68` even though notarization was accepted. Tunless
capture is not a workaround: its DNS override only applies to flows it
captures, so the failure appears exactly when capture is stopped, which is the
normal state while preparing an install. Exempt the host in the upstream's
fake-IP filter so it always resolves to a real address. For Clash, that is a
`fake-ip-filter` entry under `dns`:

```yaml
dns:
  fake-ip-filter:
  - api.apple-cloudkit.com
  - +.apple-dns.net
```

In Clash Verge this belongs in the active profile's merge layer, or in
**Settings > DNS** with DNS overwrite enabled; the two paths are exclusive, and
editing the DNS settings file has no effect while that toggle is off. Confirm
with `dig +short api.apple-cloudkit.com`, which must return a public address
rather than a `198.18.` one.

## Running

For a provisioned team, build Release normally, put `Tunless.app` in
`/Applications`, and invoke its executable with `start --upstream`. First
activation opens the standard macOS approval path. `stop` disables every
manager owned by the Tunless provider bundle; the launcher does not edit
unrelated transparent-proxy managers.

The launcher verbs are `check`, `start`, `status`, `stop`, `cleanup`, and
`--telemetry`. The older flag spellings `--check`, `--status`, `--stop`,
`--cleanup`, and `--telemetry` are still accepted as synonyms of the verbs,
which is what the bundled recovery script relies on.

With Clash Verge as the upstream, a working start is two commands:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless \
  check --preset clash-verge --upstream 127.0.0.1:7897
/Applications/Tunless.app/Contents/MacOS/Tunless \
  start --preset clash-verge --upstream 127.0.0.1:7897
```

The preset is shorthand for two process exclusions and a default upstream of
`127.0.0.1:7897`; the equivalent fully manual command is:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless start \
  --upstream 127.0.0.1:7897 \
  --dns-upstream 1.1.1.1:53 \
  --exclude-process verge-mihomo \
  --exclude-process 'io.github.clash-verge-rev.*'
```

Adjust the port to the active Clash mixed/SOCKS listener. If Xray is also
running independently, exclude its signing identifier as well. Apply this
configuration before disabling any existing proxy path, then verify DNS and
HTTPS and inspect `--telemetry`. DNS entries should show UDP or TCP destination
port 53, and public answers must not be from Clash's `198.18.0.0/15` fake-IP
range. Matching `--include-process` and `--include-destination` flags narrow
capture to an explicit allowlist when exclusions are not the right shape.

### What capture never claims

Earlier releases asked for eight `--exclude-destination` flags here. That was
the wrong place for it: every one of them is a flag someone has to remember,
and forgetting one is discovered only after capture has already taken the host
off the network — the moment at which it is hardest to fix. Two layers replace
that address list. A separate per-socket contract comes first.

**An application's explicit interface scope is honored by default.** macOS
hands an `NEAppProxyFlow` two related facts: `interface` says which interface
the flow uses, while `isBound` says whether the application explicitly chose
it. Tunless declines an otherwise eligible flow only when `isBound` is true.
For a transparent proxy, declining means the original socket continues
directly to its destination, still scoped to the interface the application
selected. A local proxy transport can therefore bind its outer sockets to
`en0` and stay outside capture without a process name, a destination address,
or any Tunless-specific protocol. The decision is per socket; other unbound
sockets from the same process remain eligible.

The distinction is essential. An ordinary unbound browser socket can receive
the same en0 source address and `NWInterface` after routing, so treating either
fact as intent would make most traffic direct whenever Wi-Fi is the default
route. The public opt-out signal is `isBound`, produced by a real interface
constraint such as `IP_BOUND_IF`, `IPV6_BOUND_IF`, or Network.framework's
required-interface facility. Merely looking up an interface's current IP and
binding that address is not guaranteed to produce the interface-bound signal.
Telemetry records `interfaceName`, `isBound`, and
`event: "bypass:bound-interface"` so this contract is observable rather than
assumed.

This is intentionally an escape hatch: any selected application can bind its
socket and go direct. An operator using Tunless as a strict capture boundary
can disable the contract with `--capture-bound-flows` (or
`TUNLESS_CAPTURE_BOUND_FLOWS=true`); those flows are then sent to SOCKS like
other eligible traffic and their requested interface is not preserved across
the application-level proxy hop.

**Reserved by the provider, whatever the configuration says.** Loopback, the
unspecified address, link-local, multicast, and broadcast are the paths a host
needs in order to stay reachable at all; the SOCKS upstream and the resolver
the upstream was asked to query are tunless's own datapath. The provider
refuses to capture any of them, so a forgotten flag, a stale saved
configuration, or an over-broad `--include-destination` cannot reach them.

One edge is worth knowing. The upstream is matched as it was written, so an
`--upstream` given as a hostname is recognized only when a flow names the same
host; a flow addressed to the IP that name resolves to is not recognized as the
upstream and is captured like anything else. Nothing on the machine has to
notice — the provider's own connection to the upstream is never captured — but
an application pointed at the proxy by address, while tunless was pointed at it
by name, sends its proxy traffic back through the proxy. Writing `--upstream`
as an address on both sides avoids it.

**Excluded by default, overridable per prefix.** RFC 1918 and RFC 4193 private
ranges, RFC 6598 carrier-grade NAT, and the `198.18.0.0/15` fake-IP range are
excluded unless asked for. These are not reachability-critical the way the
reserved set is — fronting a private network through a proxy is a legitimate
configuration — but capturing them is wrong far more often than it is right.
Naming one with `--include-destination` removes it from the default set;
`--no-default-exclusions` drops the whole set.

**Port 53 is judged by neither.** A resolver's address is not a destination the
application chose to reach — it is a resolver the network handed out, and
replacing it with a trusted one is the whole point of the DNS override. Judging a
port-53 flow by that address therefore asks the wrong question and answers it in
the direction that fails silently: a home network hands out the router as the
resolver, the router is inside `192.168.0.0/16`, that range is excluded so nobody
accidentally proxies their own LAN, and the override is left structurally unable
to see the one flow it was configured for. Nothing reports an error. Queries go
out on the network's own path, come back with whatever that path chose to answer,
and every name on the host resolves to it.

So while `--dns-upstream` is set, a port-53 flow is captured whatever the
destination rules say, and link-local is not reserved against it either — a
router advertising itself as the resolver over IPv6 does so at a link-local
address. Process rules and the bound-interface contract still apply, as does
the rest of the reserved set.
Loopback stays reserved, so a stub resolver at `127.0.0.1:53` is left alone; the
upstream is reserved by host rather than by host and port, and it is usually on
loopback too.

The trusted resolver itself is reserved by transport rather than by address: a
datagram to it is captured, a stream is not. Reserving the address outright
declined two different flows for the price of one. The flow that has to be
declined is the upstream's own — capture relays a query to the resolver, the
upstream dials that resolver itself, and capturing that dial hands the query back
to the upstream waiting on it, so every lookup recurses until it times out. The
flow that should not have been declined is an application's query to the same
resolver, and `1.1.1.1` is both the default `--dns-upstream` and one of the most
commonly configured resolvers there is. Capture rewrites the transaction ID of
every query it relays, and the upstream forwards that query verbatim, so the
datagram that would close the loop carries an ID capture is holding open while an
application's does not. A stream carries nothing to recognise at connect time and
stays reserved.

DNS over TCP to a resolver on this network — private space, CGNAT, loopback or
link-local — is left alone for the same reason in reverse: the route has to be
chosen before any bytes arrive, so claiming it means committing to the trusted
resolver for whatever the connection turns out to ask, and that breaks exactly
the names a local resolver exists for.

### Names an application never told the kernel

macOS attaches `remoteHostname` to a flow only for a name it resolved on the
application's behalf. An application with its own DNS client — every Chromium
browser, Firefox, anything that ships a resolver — never gives the kernel a name,
so its flows arrive as bare addresses and the proxy loses every rule written
about names. On a network that answers DNS falsely the address is whatever the
network said, so relaying it faithfully relays the lie.

Capture is already relaying those queries, so the provider records which name
each address was answered for and gives a nameless flow its name back before
emitting it. Associations are learned only from answers that came through the
trusted resolver, expire on the TTL that carried them — held for at least thirty
seconds, because an association is written when the answer arrives and read when
the connection opens, and a browser resolves once and then opens connections over
the seconds that follow — and are dropped when two names claim one address, which
is the ordinary shape of shared hosting.

This applies to streams. A datagram flow is emitted on its address even when the
name is known, which is a measured decision rather than an unfinished one: a
SOCKS5 UDP relay reports the source of each reply, and an upstream asked to send
to a name reports the address it resolved that name to. mihomo was measured doing
exactly that — a datagram addressed to `dns.google` came back sourced from
`8.8.4.4`. A QUIC client uses a connected socket, so replies from an address it
never wrote to are dropped by the kernel before the application sees them.
Emitting the address keeps QUIC working and costs rule-by-name on that
transport.

The difference from the fake-IP scheme this replaces is worth stating, because
the mechanism looks similar and the failure modes are opposite. Every address
here is real. A mapping that has expired, is ambiguous, or was never seen costs
rule-by-name and nothing else, because the flow still goes out on an address that
works. A fake IP that outlives its mapping connects and then transfers nothing.

`--telemetry` shows the result directly: a flow with a `hostname` was handed over
by name, and one whose `hostname` is null was handed over by address.

### Names only your own network can answer

A query for a name the local network owns is not sent to the trusted resolver.
It goes to the resolver the application chose, and goes there directly rather
than through the proxy — a private resolver reached through a remote node is as
unanswerable as a public resolver that never heard of the name.

Reserved and private name spaces are recognised without being told: `.local`,
`.home.arpa`, `.internal`, `.lan`, `.test`, `.localhost`, unqualified
single-label names, and the reverse zones for private, CGNAT and link-local
space. Split-horizon zones cannot be predicted, so name those:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless start \
  --preset clash-verge --upstream 127.0.0.1:7897 \
  --local-domain corp.example.com
```

`TUNLESS_LOCAL_DOMAIN` sets the same thing in the environment file. The split
reads the query, so it applies to DNS over UDP; a query over TCP is routed before
any bytes arrive and goes to the trusted resolver like anything else.

### Names a nearer resolver answers better

Everything above sends every other captured query to `--dns-upstream` through
the proxy, and that stays the default. Two flags change it, and both are off
unless set.

`--dns-direct` names a resolver reached without the proxy, and
`--dns-direct-prefix` the addresses that make its answers credible:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless start \
  --preset clash-verge --upstream 127.0.0.1:7897 \
  --dns-direct 223.5.5.5:53 \
  --dns-direct-prefix-file ~/.config/tunless/near-networks.txt
```

Both resolvers are asked. The direct one is believed only when it returns an
address inside the set, and that decision is made the moment its answer arrives
— so a name the set covers resolves at the speed of the near resolver and does
not depend on the upstream being up. An answer naming addresses outside the set
is never served; the trusted resolver decides, and when it cannot the query
fails with SERVFAIL rather than being answered with something unverified.

`--direct-domain` and `--trusted-domain` decide the same thing from the name
instead, before any query leaves the host, and take the longest match where they
overlap. `--trusted-domain` matters as soon as `--dns-direct` is on: from then
on every unlisted name is asked of the direct resolver, so a name you want kept
off that path has to be listed.

Each flag has a `-file` form and a `TUNLESS_`-prefixed environment variable, and
the launcher reads the list files itself rather than handing a path to the
system extension — a sandboxed extension running outside your session may not be
able to open it, and a parse error belongs where you can see it. An incoherent
combination is refused before capture starts.

Only answers from the trusted resolver are ever learned from for
[hostname recovery](#names-an-application-never-told-the-kernel), adjudicated
exchanges included. Adjudication reads addresses, so it covers A and AAAA;
HTTPS and SVCB go to the trusted resolver because they carry the
encrypted-client-hello configuration. The full rule is in
[resolver selection](OPERATIONS.md#answer-based-and-name-based-resolver-selection).

### Deploying without losing the network

Enabling capture moves every matching flow onto the SOCKS5 upstream at once,
and the DNS override redirects every captured port-53 flow to the configured
resolver through that same upstream. If the upstream cannot carry DNS, name
resolution stops host-wide the moment capture starts, and the host cannot
resolve the addresses needed to diagnose it. Three guards make that outcome
recoverable, and all three are on by default.

**Before capture.** `check` and `start` both prove the upstream can actually
relay DNS, not merely that it speaks SOCKS5. A correct greeting says nothing
about whether the upstream will relay a query to the resolver, so the probe
opens SOCKS5 CONNECT to the configured resolver, sends a real query, and
requires a well-formed response. `start` refuses to enable capture when that
fails. Any response code counts, including `NXDOMAIN` and `SERVFAIL`, because
the probe is testing reachability rather than whether a name exists.

UDP is probed separately through UDP ASSOCIATE and reported without blocking
the start, because upstreams commonly relay DNS over TCP while refusing UDP.
That combination is usable but degraded: captured UDP queries fail and
applications have to retry over TCP. `check` reports it in the `dns` object:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless \
  check --preset clash-verge --upstream 127.0.0.1:7897
```

```json
{
  "ok": true,
  "detail": "SOCKS5 negotiation passed; DNS relays over TCP and UDP",
  "dns": { "tcpRelayWorks": true, "udpRelayWorks": true }
}
```

**After capture.** Preflight tests the upstream directly, which does not prove
the assembled datapath resolves: the provider also has to be in the path with
its rules loaded. So `start` resolves a name through the live datapath after
capture is enabled, and if that fails it disables capture automatically and
exits non-zero, leaving the host on its previous working path. A rolled-back
start reports what happened rather than claiming success:

```console
Tunless: capture started but DNS did not resolve through it; rolling capture
back so the host keeps working.
Tunless: capture is off and the previous network path is restored. Run check to
test the upstream before starting again.
```

Use `--skip-verify` (or `TUNLESS_SKIP_VERIFY=true`) to suppress the post-start
check and its rollback. Prefer leaving it on: it is what converts a broken
deployment into a failed command instead of an unreachable host.

**For as long as capture runs.** Both checks above prove DNS worked at one
instant. Nothing in them covers the upstream that stops resolving an hour
later, when the proxy is restarted, a node is switched, a TUN device comes up
beneath it, or the laptop moves to another network. So the provider keeps
proving it: every 30 seconds it sends a real query along the same path a
captured port-53 flow takes. After three consecutive failures it marks the
datapath degraded and retires transports that cannot recover in place.

Capture deliberately remains installed. Returning `false` from a transparent
proxy flow handler does not report an error; macOS sends that flow directly to
its ultimate destination. Treating an upstream outage as permission to decline
flows therefore converts a visible proxy failure into a silent proxy bypass.
Eligible TCP retries remain claimed and either reconnect through SOCKS or fail
closed. Eligible UDP datagrams remain claimed and are dropped until their
association can be rebuilt. Only explicit process/destination exclusions,
application-bound interfaces, reserved endpoints, the DNS loop-prevention copy,
and split-horizon local DNS use the direct route.

The same mechanism closes the gap left by a launcher that never reports back.
Capture is armed on a probation window when it starts, and a provider that is
not told resolution works — because the launcher was killed, suspended, or
disconnected between enabling capture and verifying it — reports degraded when
that window expires. It still fails closed. A probe that succeeds on its own
counts as proof, so a start that genuinely works never depends on the launcher
surviving.

Link state gates the evidence: a host with no usable network fails every probe,
but that says nothing about the upstream. `--no-health-watchdog` (or
`TUNLESS_NO_HEALTH_WATCHDOG=true`) disables periodic probing and degradation
reports; it does not change routing or make upstream failures direct.

When a probe succeeds again, the degraded state clears. Running `start` is the
operator asking for capture, and temporary upstream trouble does not withdraw
that request or silently expose traffic to the current network.

Flows already admitted need separate treatment. TCP streams cannot change
their route in place, so the provider closes them and lets applications retry
through the still-installed capture path. Datagram flows are never closed by
the provider at all.

That rule is absolute, and it is the one this platform got wrong for longest.
A UDP socket outlives the flow underneath it, and macOS neither re-captures
such a socket nor releases it back to the kernel: once the provider has closed
its flow, every later send on that socket fails locally — `EPIPE` on an
ordinary connected socket, `EINVAL` on the resolver sockets `mDNSResponder`
holds. `mDNSResponder` keeps one of those per delegated client and does not
replace it, so a single closed flow ends name resolution for whichever
application owned that socket, while every other application on the host keeps
resolving normally and hides the failure. Recovery took a `killall
mDNSResponder`; nothing tunless did could undo it.

That rule is enforced rather than described: `DatagramFlowCloseGuardTests`
reads this provider and fails if a flow close appears anywhere it could reach a
datagram flow.

So the association is what fails, never the flow. Upstream degradation, a proxy
restart, a node switch, a SOCKS handshake that times out on a busy mixed port,
an idle association past its two-minute limit — each of those tears down the
upstream half and leaves the flow untouched. Proxy-eligible datagrams are
dropped rather than sent direct while the upstream is unavailable, and the
association is rebuilt underneath the same flow when the upstream answers
again. Port-53 flows additionally carry no idle limit at all, since a resolver
socket is idle between lookups by design.

Network changes are a separate invalidation signal, not something that waits
for three failed probes. The path identity includes gateways, local endpoints,
cost and capabilities as well as interface names, so Wi-Fi to Personal Hotspot
is detected even when macOS calls both paths `en0`. The provider advances a
shared network epoch, closes old TCP streams, and makes UDP associations and
intentional direct-relay sockets rebuild lazily on the new path. Probe results
from the old epoch are ignored, failures are cleared, and the new path gets a
15-second settling interval followed by an immediate recovery probe.

Sleep is excluded from the evidence. A machine going to sleep tears its network
down and fails every probe, so the provider invalidates its transport epoch on
`NEProvider.sleep()` and ignores probe results for twenty seconds after
`wake()`, discarding the failures that led into sleep. Existing TCP streams are
recycled and a recovery probe runs after the grace period.

Because a degraded session stays connected and keeps capturing, `status` alone
cannot describe datapath health. The `capture` field names both facts:

```console
{ "status": "connected", "capture": "capturing (degraded: name resolution failed 3 times in a row through the upstream)" }
{ "status": "connected", "capture": "capturing" }
```

Each transition is also written to the unified log under subsystem
`com.bojieli.tunless`, and appears in `--telemetry` as a `capture` record:

```console
/usr/bin/log show --last 1h --predicate 'subsystem == "com.bojieli.tunless"'
capture degraded: name resolution failed 3 times in a row through the upstream.
Proxy-eligible flows remain captured and retry; reserved/local traffic keeps its direct route
upstream recovered: capture remained active; rebuilding disposable datagram transports
network path changed (generation 1); rebuilding upstream transports
```

Log first and to somewhere that survives, because the first version of this
recorded the reason into the telemetry buffer and then cancelled the provider,
which threw that buffer away — destroying the one message that explained why
the host had lost capture.

If the upstream genuinely cannot relay DNS and capture is still wanted, start
with `--disable-dns-override` so each application keeps its own resolver.
Capture still relays those port-53 flows — the flag changes where they are
addressed, not whether they are proxied — so the upstream can still take
resolution down host-wide. The watchdog therefore keeps watching: with no
configured resolver to prove, it probes the resolver capture is actually
carrying, learned from the flows themselves, over whichever transport those
flows used. Until capture has carried a port-53 flow there is nothing to prove
and nothing is probed.

**When the upstream runs a TUN device.** Clash Verge and similar upstreams can
run their own TUN interface with `auto-route` and `dns-hijack`, which puts a
second transparent capture layer beneath tunless. Both layers then claim port
53: the upstream hijacks it while tunless redirects it to the configured
resolver.

The failure this used to produce is worth naming, because it looks like a dead
network rather than a proxy problem. Capture rewrites an application's port-53
flow to the trusted resolver and relays it to the upstream. The upstream dials
that resolver to answer it. If that dial is captured too, the query is handed
straight back to the upstream that is waiting on it, and every lookup on the
host recurses until it times out. Nothing errors, and the recursion consumes
flows while it runs. Excluding the upstream's process — what `--preset
clash-verge` does — prevented it, but only for an operator who knew which
process to name; an unrecognized build, a differently packaged mihomo, or
sing-box in place of Clash left the loop wide open.

TCP connections to the resolver remain reserved because a stream exposes no DNS
transaction identifier at connect time. UDP is more precise: an application's
own query to the trusted resolver is captured, while the copy forwarded by the
upstream carries the private transaction ID Tunless assigned and is sent direct
by the loop guard. The upstream can therefore reach the resolver without
leaving an application's identical query unprotected. Process exclusions remain
worth setting: they also keep the upstream's non-DNS traffic — its subscription
fetches and its own DoH or DoT resolvers on ports 443 and 853 — from being
routed back through it.

Fake-IP answers make that failure quiet rather than loud. A fake address from
the upstream's range is meaningful only to the resolver that minted it, so a
cached one that outlives its mapping still gets a successful `CONNECT` reply
and then transfers nothing:

```console
by domain     cp.cloudflare.com:80   120 bytes in 0.23s
by fake IP    198.18.57.30:80          0 bytes in 0.21s
```

Nothing reports an error; connections simply return no data, which reads as a
stalled network rather than a DNS problem. The fake-IP range is excluded by
default for this reason, and loopback and link-local are reserved outright, so
what remains is procedural: change one layer at a time, and run `check` between
changes rather than after both.

### Should the upstream keep its TUN device?

The two layers do not fight over a packet. Capture happens at the socket layer,
before the routing table, so a flow tunless captures never reaches the route
that points at the TUN; a flow it does not capture falls through and the TUN
takes it. Measured on `utun1024`'s own byte counters, a captured 20 MB transfer
put 3,798 bytes across the upstream's TUN and an excluded one put 42 MB:
[coexistence with an upstream TUN device](MEASUREMENTS.md#coexistence-with-an-upstream-tun-device).

**Turning the TUN off will not make anything faster.** It is already not in the
path of captured traffic, and the same measurement found throughput either way
inside this WAN node's run-to-run spread. Performance is not the reason to
choose.

The reasons to turn it off are what tunless exists for, and they are all
consequences of fake IP and the route table:

- **Fake-IP answers disappear.** With the TUN hijacking port 53, anything that
  reaches its resolver gets an address from `198.18.0.0/15` — meaningful only
  to the resolver that minted it, and quietly fatal once cached past its
  mapping. Turning the upstream TUN off removes that second port-53 interception
  layer and its fake-answer path.
- **The route table stops being rewritten.** `auto-route` replaces the default
  route with a split that has no owner, which is the failure tunless is built
  to avoid: nothing rolls it back if the proxy dies.
- **Rules keep the domain.** Tunless hands the upstream a hostname, so
  domain rules match exactly. The TUN path carrying a real address has only the
  address, so its rules degrade to IP matching or SNI sniffing.
- **One capture layer to reason about.** `check` and `--telemetry` then
  describe the whole picture rather than half of it.

The reason to keep it is leak containment after capture itself disappears. If
the extension process stops, is uninstalled, or the operator stops its session,
macOS has no provider left to claim new flows and they use the ordinary route.
An upstream outage while the provider is alive is different and now fails
closed. With the upstream's TUN up, even traffic created after capture has gone
is still proxied.
Anything the interface-binding contract, reserved set, and default exclusions
leave direct — explicitly scoped sockets, loopback, link-local, multicast, the
LAN, private and CGNAT ranges — is direct on purpose, but a host that must never
send an unproxied packet wants either `--capture-bound-flows` or the TUN
underneath as a backstop, and should accept fake IP as the price of the latter.

Whichever way, change one layer at a time and run `check` between changes.
When a flow stops working after the TUN comes down, it was a flow capture had
been declining all along and the TUN had been covering; the reasons are
enumerated in
[I turned the TUN off and some things stopped working](FAQ.md#i-turned-the-tun-off-and-some-things-stopped-working).

### Capturing only some applications

`--include-process` turns capture into an allowlist: name the applications that
should use the proxy and nothing else is claimed. Patterns match a signing
identifier, the executable path, or its basename, so a program the toolchain
left with a generic identifier can still be named precisely.

```console
Tunless start --preset clash-verge --upstream 127.0.0.1:7897 \
  --include-process /usr/bin/curl
```

Demonstrated on build 14: with that include list, ambient traffic from other
processes produced no captured flows over twenty seconds, while `curl` resolved
`www.debian.org` to a real address through the override rather than the fake-IP
answer the upstream's TUN hands to everything else.

Changing the selection on a running capture is applied by the provider, not
assumed: `start` sends the new configuration and restarts the session if the
provider does not confirm it. Before build 14 the reply was discarded, so
narrowing capture on a running session reported success while leaving the old
rules in force.

Downstream `PROCESS-NAME` rules cannot see through this — every captured flow
reaches the proxy as `tunless` — but domain, rule-set, GEOIP, node, and
subscription rules match exactly, because the hostname is what tunless sends.

### Bounding what one application can consume

`--max-flows` (default 4096, or `TUNLESS_MAX_FLOWS`) caps concurrent TCP relay
work. Past the ceiling a stream is still claimed and is refused with an
application-visible error. A transparent provider that returned `false` here
would tell macOS to send the stream direct, so overload must fail closed. The
ceiling exists because macOS reports and can terminate an extension that spends
too much CPU, and an application opening streams faster than the upstream
retires them would otherwise turn itself into a capture outage for everything
else on the host. `status` reports the live flow count and running refusal total.

UDP application flows are not counted against that TCP ceiling. They cannot be
closed or declined safely: the former permanently ends the application-owned
socket on macOS, and the latter is a direct route. Their disposable SOCKS
associations remain bounded internally and are rebuilt without ending the flow.

### Qualifying a candidate

`scripts/macos-qualify.sh --app Tunless.app` runs the exact-candidate checks in
one pass: signature, Gatekeeper, staple, install, DNS preflight over both
transports, activation, the live datapath, telemetry, and that the host still
resolves after `stop`. Every check prints what it observed and the exit status
is the gate, so a qualification cannot be half-remembered.

```console
scripts/macos-qualify.sh --app Tunless.app --preset clash-verge
PASS  Gatekeeper accepts the candidate                notarized Developer ID
PASS  resolution returns a real address               194.177.211.216
PASS  host still resolves after stop                  198.18.0.14
14 passed, 0 failed
```

Run it on a machine that has never had tunless installed. What it cannot cover
— `remoteHostname` fractions, HTTP/3, the soak, and first-approval behaviour —
it prints rather than omits.

### Soaking a deployment

Every serious defect this project has found surfaced over hours rather than
minutes, on triggers that only a real machine produces: a sleep, a wake, a node
switch, a network change. A watchdog that mistook a sleeping laptop for a
failing upstream left a host resolving names unprotected for nine hours, and it
was noticed by accident rather than by a test. Unit tests cannot see that class
of bug and neither can a five-minute smoke test.

`scripts/tunless-macos-soak.sh` watches the assembled system on the machine's
own schedule, asserting on every tick that a name resolves and that capture is
claiming flows while it does:

```console
scripts/tunless-macos-soak.sh --interval 60
```

Leave it running across sleeps and network changes; Ctrl-C prints the summary,
and `--summary ~/.tunless/soak.jsonl` reprints it later. It reports unresolved
intervals, not-capturing intervals, and silent holes — stretches with no tick at
all, which is what a sleeping or wedged host looks like from the outside and is
itself a finding.

```console
soak 08-25 10:12 -> 08-27 09:41 (47.5 hours, 2849 ticks)
  resolved:  2849/2849 ticks (100.00%)
  capturing: 2849/2849 ticks (100.00%)
  no UNRESOLVED intervals
  no not-capturing intervals
```

A degraded watchdog state still begins with `capturing`, because eligible flows
remain claimed. A not-capturing interval now means the session was stopped,
restarting, or unavailable and should always have an explanation; an unresolved
interval should never be ignored.

### Telemetry and flow lifecycle

Every accepted TCP and UDP flow emits a terminal completion record.
`--telemetry` prints and drains a JSON buffer capped at 4,096 flow records, so
an unattended extension cannot grow the buffer without bound. The optional
`route` field distinguishes `proxied`, intentional `direct`, and `dropped`
datagrams; `routedDestination` alone cannot make that distinction when the
SOCKS destination equals the application's destination.

Provider stop closes active TCP flows, leaves application-owned UDP flows for
Network Extension to release, cancels their tasks, and waits for teardown.
SOCKS setup is bounded to 10 seconds, inactive TCP streams to five minutes, UDP
associations (not their flows) to two minutes, and a TCP peer has 30 seconds to
finish after an application half-close. Re-running the launcher invalidates the
transport epoch and recycles TCP streams. Long-lived UDP flows read the latest
configuration on every datagram and rebuild their association when it changes.

### Persistent telemetry log

The optional user LaunchAgent in
`packaging/launchd/com.bojieli.tunless.telemetry.plist` drains non-empty
telemetry batches every 10 seconds into `~/.tunless/flow.log`. The collector
keeps the active log and five 10 MiB backups, and forces the directory and log
permissions to `0700` and `0600` because flow records contain destinations,
hostnames, and source application signing identifiers.

Install it for the current user after installing `Tunless.app`:

```console
install -d -m 0700 ~/.tunless/bin ~/Library/LaunchAgents
install -m 0700 scripts/tunless-macos-telemetry-log.sh \
  ~/.tunless/bin/tunless-macos-telemetry-log.sh
sed "s|/Users/YOU|$HOME|g" \
  packaging/launchd/com.bojieli.tunless.telemetry.plist \
  > ~/Library/LaunchAgents/com.bojieli.tunless.telemetry.plist
launchctl bootstrap "gui/$(id -u)" \
  ~/Library/LaunchAgents/com.bojieli.tunless.telemetry.plist
```

Follow the JSON log with `tail -f ~/.tunless/flow.log`. Stop collecting with:

```console
launchctl bootout "gui/$(id -u)/com.bojieli.tunless.telemetry"
```

The collector does not change Tunless routing. Each successful poll consumes
the provider's in-memory telemetry snapshot after it has been persisted.

## Recovery

Tunless capture is never intended to be irreversible. If the SOCKS5 upstream
stops, the provider gets stuck, or networking fails while Tunless is enabled,
disable capture immediately with:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless stop
```

`stop` needs no name resolution: it talks only to the local Network Extension
preferences, so it still works when DNS is down. Do not try to fix resolution
first; disable capture, then diagnose with the host back on its previous path.

**Deleting the app does not stop capture.** Removing `Tunless.app` while
capture is running leaves the host working — reachability survives, because
nothing about the deletion breaks the flows the provider is already relaying —
but the provider keeps capturing, and the binary that could stop it is gone.
Demonstrated on build 13: 867 flows were captured during the window with no app
on disk, and `systemextensionsctl` still reported the extension as `activated
enabled`. Recovery is then System Settings > General > Login Items & Extensions
> Network Extensions, or reinstalling the app and running `cleanup`. Prefer
running `cleanup` *before* deleting the app, which is what it is for.

`stop` stops all running Tunless proxy sessions and persists them as disabled.
For a stronger reset, `cleanup` also removes every transparent-proxy
configuration owned by Tunless, including stale duplicates left by an
interrupted update, and asks macOS to deactivate the Tunless Network Extension:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless cleanup
```

Capture is stopped before the deactivation request, so connectivity does not
wait for approval or a restart if macOS requires either to remove the
extension.

The app bundle includes a bounded recovery script. It runs the legacy-safe stop
command first, times out a wedged launcher, and performs the full cleanup when
paired with the launcher bundled beside it:

```console
/Applications/Tunless.app/Contents/Resources/tunless-cleanup
```

You can always disable the Tunless Network Extension without using Tunless.
Open **System Settings > General > Login Items & Extensions > Network
Extensions**, find Tunless, and turn it off. This is the final recovery path if
the launcher and cleanup script cannot respond. Disabling or removing Tunless
does not change Clash Verge rules, nodes, subscriptions, or system proxy
settings.

After recovery, `status` should report `enabled: false` or `not-configured`:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless status
```

### `dig` resolves but applications do not

If `dig api.anthropic.com` returns an address while curl remains above its
progress meter without printing `Host ... was resolved` or `Trying ...`, the
authoritative record and the configured DNS server are not the missing pieces.
curl is blocked in the macOS `getaddrinfo` path through `mDNSResponder`; `dig`
opened a separate socket and did not test that state.

Builds up to and including 1.0.8/14 could leave `mDNSResponder` reusing a UDP
socket after its transparent-proxy flow was closed by a watchdog pause, an
upstream failure, or idle expiry. Because that daemon holds one resolver socket
per delegated client, the damage is per-application: one program's lookups hang
for thirty seconds and then fail while every other program on the host resolves
normally, which reads like a problem with the site rather than with DNS. The
unified log identifies the state with repeated messages like `sending ...
failed: [22: Invalid argument]`:

```console
/usr/bin/log show --last 10m --style compact \
  --predicate 'process == "mDNSResponder"' | grep 'Invalid argument'
```

Restart the resolver to discard its stale socket. launchd recreates the daemon
immediately, and the command does not edit the configured DNS servers:

```console
sudo killall mDNSResponder
curl --connect-timeout 10 -v https://api.anthropic.com/
```

Verify that the PID changed with `pgrep -x mDNSResponder` if necessary. Builds
from 1.0.8/15 never close a datagram flow: the upstream association is what is
retired and rebuilt, so a pause, an upstream failure, or an idle interval
cannot reach the application's socket. Upgrade after recovery, and confirm with
`systemextensionsctl list` that the build actually changed — otherwise another
pause reproduces the stale resolver state.

## DNS override

`--dns-upstream` defaults to `1.1.1.1:53`. Tunless redirects captured UDP and
TCP port 53 queries to that numeric resolver through the SOCKS5 upstream; it
does not send them to the resolver named in macOS network settings. A numeric
address is required so selecting the trusted resolver cannot itself depend on
system DNS. UDP replies are presented to the application as coming from the
resolver it originally addressed, preserving connected-datagram semantics.
Tunless assigns a private transaction ID to each outstanding UDP query, then
restores the application's original ID and resolver endpoint on reply. This
prevents concurrent reused IDs and out-of-order responses from being matched by
FIFO order. That private ID is drawn at random rather than counted out, so a
rewritten query is no easier to answer falsely than the one the application
wrote (RFC 5452). Entries expire after 30 seconds and are capped at 4,096. Set
`TUNLESS_DNS_UPSTREAM` to choose another trusted resolver. Use
`--disable-dns-override` or `TUNLESS_DISABLE_DNS_OVERRIDE=true` to preserve the
original DNS destination while continuing to proxy the flow. Post-start
verification runs either way, since it resolves through the assembled path
rather than through a configured resolver; only `--skip-verify` opts out.

The 30-second expiry above applies to transaction-ID attribution, not to the
macOS resolver flow. Port-53 UDP flows remain open for the lifetime chosen by
`mDNSResponder`, and a reply that matches no outstanding rewritten query is
dropped unless the application actually addressed the server it came from,
rather than being handed up under an address that application never wrote to.

The resolver's own address and port are reserved from capture while the
override is on, so the upstream can reach it to answer the queries tunless
rewrote. One consequence is worth stating plainly: an application that itself
addresses `1.1.1.1:53` is left direct rather than proxied, because from the
provider's side that flow is indistinguishable from the upstream answering a
rewritten query. Choosing a resolver address that local applications do not
query directly avoids the overlap; `--disable-dns-override` removes the
reservation along with the rewrite.

## Limitations

On application EOF, Tunless now half-closes the SOCKS connection and continues
reading the peer until EOF or the 30-second drain bound. The Network Extension
flow API still does not reliably preserve a client TCP half-close. A test
application that calls `shutdown(SHUT_WR)` causes its `NEAppProxyTCPFlow` to
become disconnected; a later provider `write` fails with
`NEAppProxyFlowErrorDomain` code 1 even though the SOCKS peer can still return
data. Tunless recognizes that disconnect as an application EOF and attempts the
correct SOCKS lifecycle, but it cannot make the disconnected Apple flow accept
the response. Normal full-duplex TCP, HTTP/1.x, HTTP/2, TLS, and remote-first
EOF are supported. Protocols that require a client FIN as an application-level
message delimiter need a packet-layer implementation rather than an app-proxy
flow.

Older extension builds may remain listed as `terminated waiting to uninstall on
reboot` after an in-place update. The newest build must be the single
`activated enabled` entry; a reboot is not required just to use that build.

## Appendix: Validation history

These dated logs record what was actually run and observed on real hardware.
They are kept verbatim in substance; they describe specific builds, not
standing guarantees.

**CI signing and notarization, 2026-08-20.** The
`macOS signed release` workflow ran on `macos-15` against commit `9e7ac70`
(run 32327477603). It archived a universal Release bundle unsigned, signed the
system extension and app with `scripts/macos-sign.sh` using the direct
Developer ID profiles, and asserted the Developer ID authority, hardened
runtime, and required entitlements. Notary submission
`9791c240-a607-40b5-806d-e549d68f0e59` returned `Accepted`, the ticket
stapled, and `spctl` reported `accepted / source=Notarized Developer ID`. The
uploaded artifact `Tunless-1.0.8-10.zip`
(`19c9aaac2cc8dc4b614bef3e89e63a8d3e4ed844576b86b5d5194a55198bd2eb`) was
downloaded and re-verified off the runner: the checksum matched, `stapler
validate` accepted the embedded ticket, Gatekeeper accepted it as a notarized
Developer ID bundle, both Mach-O binaries were `x86_64 arm64`, and the app and
extension entitlements were identical to installed build 10. This exercised
signing and notarization only; clean-machine runtime qualification is still
tracked in the release checklist.

**Build 9 (`1.0.8`), 2026-08-18.** Its 25-test Swift suite, Go suite, and
unsigned containing-app/system-extension Debug build passed. The universal
Release app and nested extension were signed with direct Developer ID profiles,
notarized, stapled, accepted by Gatekeeper, and installed over build 8. The
build 9 extension became the single `activated enabled` entry and the launcher
reported `connected` with the Clash Verge preset at `127.0.0.1:7897`. SOCKS5
preflight and a live HTTPS request passed, while live telemetry showed captured
DNS requests rewritten from the configured system resolver to `1.1.1.1:53`.

**Build 8 (`1.0.7`), validated on macOS 26.3 on 2026-08-17.** The universal
Release app and nested system extension was signed with direct Developer ID
provisioning profiles, notarized, stapled, accepted by Gatekeeper, installed,
activated, and enabled. The 12-test Swift integration suite passed. Live UDP
and TCP queries addressed to the configured `223.6.6.6` system resolver were
rewritten to `1.1.1.1:53` through Clash and returned public Google/YouTube
answers; repeated checks passed 20/20 UDP and 10/10 TCP. HTTP/1.0 remote EOF,
HTTP/1.1, HTTP/2, redirects, streaming, upload, raw TLS, SSH, two public STUN
servers, and 32 concurrent HTTPS connections passed. The Tunless path and an
explicit Clash SOCKS path reported the same public egress IP. The LAN gateway
remained directly reachable over ICMP and HTTP and produced no Tunless flow
record. Clash was not stopped or reconfigured during validation, and its
original macOS HTTP/HTTPS proxy settings were restored and rechecked.

See also: [../README.md](../README.md) for the cross-platform overview, and
[OPERATIONS.md](OPERATIONS.md) for preflight checks, health API, and recovery
procedures shared across platforms.
