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
that list.

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
captured port-53 flow takes, and after three consecutive failures it stops
claiming flows, which puts the host back on the path it had before capture.

The same mechanism closes the gap left by a launcher that never reports back.
Capture is armed on a probation window when it starts, and a provider that is
not told resolution works — because the launcher was killed, suspended, or
disconnected between enabling capture and verifying it — stands aside when that
window expires rather than holding the host indefinitely on an unverified
claim. A probe that succeeds on its own counts as proof, so a start that
genuinely works never depends on the launcher surviving.

Link state gates the decision: a host with no usable network fails every probe,
and standing aside there would change nothing capture caused.
`--no-health-watchdog` (or `TUNLESS_NO_HEALTH_WATCHDOG=true`) turns the watchdog
off for a host that would rather keep capture through an outage than have it
stand aside underneath a running workload.

Standing aside is a pause, not a verdict. Declining a flow hands it back to the
kernel, which routes it as though tunless were not installed, so the host
recovers exactly as it would if the provider had died — while the provider
stays alive to keep probing. When a probe succeeds again, capture resumes on
its own. Running `start` is the operator asking for capture, and a few minutes
of upstream trouble does not withdraw that request; staying aside afterwards
would leave the host resolving names through whatever the network hands it,
which is the exposure the DNS override exists to remove.

Flows already admitted need separate treatment. TCP streams cannot change
their route in place, so the provider closes them and lets applications retry
directly. UDP sockets can outlive a Network Extension transition — notably the
resolver sockets owned by `mDNSResponder`. The provider therefore leaves their
flows open and sends new datagrams directly while paused, then returns them to
SOCKS when the probe succeeds. Error-closing those flows made macOS retain a
resolver socket whose later sends failed with `EINVAL`, defeating the recovery
the watchdog was meant to provide.

Sleep is excluded from the evidence. A machine going to sleep tears its network
down and fails every probe, so the provider suspends the watchdog on
`NEProvider.sleep()` and ignores probe results for twenty seconds after
`wake()`, discarding the failures that led into the sleep. Without that, a
laptop pauses capture at the moment nothing is using the network, and the pause
outlives the sleep: the host wakes with its DNS unprotected and nothing on
screen to say so.

Because a paused session stays connected, `status` alone would report
`connected` either way. The `capture` field is the signal that matters:

```console
{ "status": "connected", "capture": "paused: name resolution failed 3 times in a row through the upstream" }
{ "status": "connected", "capture": "capturing" }
```

Each transition is also written to the unified log under subsystem
`com.bojieli.tunless`, and appears in `--telemetry` as a `capture` record:

```console
/usr/bin/log show --last 1h --predicate 'subsystem == "com.bojieli.tunless"'
capture paused: name resolution failed 3 times in a row through the upstream.
Flows now go direct; capture resumes automatically when the upstream resolves again
```

Log first and to somewhere that survives, because the first version of this
recorded the reason into the telemetry buffer and then cancelled the provider,
which threw that buffer away — destroying the one message that explained why
the host had lost capture.

If the upstream genuinely cannot relay DNS and capture is still wanted, start
with `--disable-dns-override` so each application keeps its own resolver and
capture no longer touches port 53.

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

The resolver address is now reserved from capture outright, so the upstream can
always reach the resolver it was asked to query, whichever proxy it is and
whether or not its process was named. Process exclusions remain worth setting:
they also keep the upstream's non-DNS traffic — its subscription fetches and
its own DoH or DoT resolvers on ports 443 and 853 — from being routed back
through it.

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
  mapping. Reserving the trusted resolver from capture means an application
  that queries it directly falls through to the TUN and gets a fake answer;
  with no TUN, it gets the real one.
- **The route table stops being rewritten.** `auto-route` replaces the default
  route with a split that has no owner, which is the failure tunless is built
  to avoid: nothing rolls it back if the proxy dies.
- **Rules keep the domain.** Tunless hands the upstream a hostname, so
  domain rules match exactly. The TUN path carrying a real address has only the
  address, so its rules degrade to IP matching or SNI sniffing.
- **One capture layer to reason about.** `check` and `--telemetry` then
  describe the whole picture rather than half of it.

The reason to keep it is leak containment. Tunless is fail-open by
construction: if the extension stops, is uninstalled, or releases capture, new
flows go direct. With the upstream's TUN up, those flows are still proxied.
Anything the reserved set and the default exclusions leave direct — loopback,
link-local, multicast, the LAN, private and CGNAT ranges — is direct on
purpose, but a host that must never send an unproxied packet wants the TUN
underneath as a backstop, and should accept fake IP as the price.

Whichever way, change one layer at a time and run `check` between changes.

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

`--max-flows` (default 4096, or `TUNLESS_MAX_FLOWS`) caps the flows the
provider holds at once. Past the ceiling a flow is declined rather than queued,
which sends it direct — the same outcome as any other declined flow, so the
application degrades instead of failing. The ceiling exists because macOS
reports and can terminate an extension that spends too much CPU, and an
application opening flows faster than the upstream retires them would otherwise
turn itself into a capture outage for everything else on the host. `status`
reports the live count and the running rejection total, so a rising rejection
count identifies which of the two is happening.

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
  capturing: 2841/2849 ticks (99.72%)
  no UNRESOLVED intervals
  not-capturing intervals: 1
     08-26 03:14:02 -> 03:22:11  (8.1 min)  paused: name resolution failed 3 times...
```

A not-capturing interval is not automatically a failure — capture standing
aside during a genuine upstream outage is the watchdog working — but every one
of them should have an explanation, and an unresolved interval never should.

### Telemetry and flow lifecycle

Every accepted TCP and UDP flow emits a terminal completion record.
`--telemetry` prints and drains a JSON buffer capped at 4,096 flow records, so
an unattended extension cannot grow the buffer without bound.

Provider stop closes all active Apple flows, cancels their tasks, and waits for
teardown. SOCKS setup is bounded to 10 seconds, inactive TCP and UDP flows to
five and two minutes, and a TCP peer has 30 seconds to finish after an
application half-close. Re-running the launcher updates only new flows; each
accepted flow retains the configuration snapshot under which it started.

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

Affected older Tunless builds could leave `mDNSResponder` reusing a UDP socket
after its transparent-proxy flow was error-closed by a watchdog pause or idle
expiry. The unified log identifies that state with repeated messages like
`sending ... failed: [22: Invalid argument]`:

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

Verify that the PID changed with `pgrep -x mDNSResponder` if necessary. Current
builds keep admitted UDP flows alive and direct while capture is paused, end
them cleanly on provider shutdown, and exempt port-53 flows from the ordinary
two-minute UDP idle limit. Upgrade after recovery; otherwise another pause can
reproduce the stale resolver state.

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
original DNS destination while continuing to proxy the flow.

The 30-second expiry above applies to transaction-ID attribution, not to the
macOS resolver flow. Port-53 UDP flows remain open for the lifetime chosen by
`mDNSResponder`; applying the generic two-minute UDP association idle timeout
under that socket can make the next system lookup fail locally instead of
opening a replacement flow.

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
