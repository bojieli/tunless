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

When Clash Verge is the upstream, exclude its outbound processes so their
connections are not handed back to Clash through Tunless:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless \
  check --preset clash-verge --upstream 127.0.0.1:7897
/Applications/Tunless.app/Contents/MacOS/Tunless \
  start --preset clash-verge --upstream 127.0.0.1:7897 \
  --dns-upstream 1.1.1.1:53 \
  --exclude-destination 10.0.0.0/8 \
  --exclude-destination 172.16.0.0/12 \
  --exclude-destination 192.168.0.0/16 \
  --exclude-destination 127.0.0.0/8 \
  --exclude-destination ::1/128 \
  --exclude-destination 169.254.0.0/16 \
  --exclude-destination fc00::/7 \
  --exclude-destination fe80::/10
```

The preset is shorthand only for the two known process exclusions below and a
default upstream of `127.0.0.1:7897`. It performs a SOCKS5 negotiation before
enabling capture. The equivalent fully manual command is:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless start \
  --upstream 127.0.0.1:7897 \
  --dns-upstream 1.1.1.1:53 \
  --exclude-process verge-mihomo \
  --exclude-process 'io.github.clash-verge-rev.*' \
  --exclude-destination 10.0.0.0/8 \
  --exclude-destination 172.16.0.0/12 \
  --exclude-destination 192.168.0.0/16 \
  --exclude-destination 127.0.0.0/8 \
  --exclude-destination ::1/128 \
  --exclude-destination 169.254.0.0/16 \
  --exclude-destination fc00::/7 \
  --exclude-destination fe80::/10
```

Adjust the port to the active Clash mixed/SOCKS listener. If Xray is also
running independently, exclude its signing identifier as well. Apply this
configuration before disabling any existing proxy path, then verify DNS and
HTTPS and inspect `--telemetry`. DNS entries should show UDP or TCP destination
port 53, and public answers must not be from Clash's `198.18.0.0/15` fake-IP
range. Add the local, link-local, multicast, or other destination prefixes that
must remain directly reachable on the host's network. Matching
`--include-process` and `--include-destination` flags narrow capture to an
explicit allowlist when exclusions are not the right shape.

### Deploying without losing the network

Enabling capture moves every matching flow onto the SOCKS5 upstream at once,
and the DNS override redirects every captured port-53 flow to the configured
resolver through that same upstream. If the upstream cannot carry DNS, name
resolution stops host-wide the moment capture starts, and the host cannot
resolve the addresses needed to diagnose it. Two guards make that outcome
recoverable, and both are on by default.

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

If the upstream genuinely cannot relay DNS and capture is still wanted, start
with `--disable-dns-override` so each application keeps its own resolver and
capture no longer touches port 53.

**When the upstream runs a TUN device.** Clash Verge and similar upstreams can
run their own TUN interface with `auto-route` and `dns-hijack`, which puts a
second transparent capture layer beneath tunless. Turning both on at once is
the configuration most likely to stall, because both layers claim port 53: the
upstream hijacks it while tunless redirects it to the configured resolver.

Fake-IP answers make that failure quiet rather than loud. A fake address from
the upstream's range is meaningful only to the resolver that minted it, so a
cached one that outlives its mapping still gets a successful `CONNECT` reply
and then transfers nothing:

```console
by domain     cp.cloudflare.com:80   120 bytes in 0.23s
by fake IP    198.18.57.30:80          0 bytes in 0.21s
```

Nothing reports an error; connections simply return no data, which reads as a
stalled network rather than a DNS problem. Keep the upstream's fake-IP range
out of capture, exclude the loopback and link-local ranges as shown above,
change one layer at a time, and run `check` between changes rather than after
both.

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
FIFO order. Entries expire after 30 seconds and are capped at 4,096. Set
`TUNLESS_DNS_UPSTREAM` to choose another trusted resolver. Use
`--disable-dns-override` or `TUNLESS_DISABLE_DNS_OVERRIDE=true` to preserve the
original DNS destination while continuing to proxy the flow.

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
