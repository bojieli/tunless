# macOS system extension

The macOS datapath lives inside `NETransparentProxyProvider` because
`NEAppProxyFlow` is not a file descriptor that can be handed to the Go process.
The extension therefore owns SOCKS5 TCP CONNECT, UDP ASSOCIATE, and byte or
datagram relaying. The containing app is only an activation/configuration
launcher.

Requirements:

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

Build without signing for code/test validation:

```console
cd macos
swift test
cd ..
xcodegen generate --spec macos/project.yml
xcodebuild -project macos/Tunless.xcodeproj -scheme Tunless \
  -configuration Debug -derivedDataPath /tmp/tunless-derived \
  CODE_SIGNING_ALLOWED=NO build
```

For a provisioned team, build Release normally, put `Tunless.app` in
`/Applications`, and invoke its executable with `start --upstream`. First
activation opens the standard macOS approval path. `stop` disables every
manager owned by the Tunless provider bundle; the launcher does not edit
unrelated transparent-proxy managers.

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
  --exclude-destination fc00::/7 \
  --exclude-destination fe80::/10
```

## Emergency disable and cleanup

Tunless capture is never intended to be irreversible. If the SOCKS5 upstream
stops, the provider gets stuck, or networking fails while Tunless is enabled,
disable capture immediately with:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless stop
```

`stop` stops all running Tunless proxy sessions and persists them as disabled.
For a stronger reset, `cleanup` also removes every transparent-proxy
configuration owned by Tunless, including stale duplicates left by an
interrupted update, and asks macOS to deactivate the Tunless Network Extension:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless cleanup
```

Capture is stopped before the deactivation request, so connectivity does not
wait for approval or a restart if macOS requires either to remove the extension.
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

Adjust the port to the active Clash mixed/SOCKS listener. If Xray is also
running independently, exclude its signing identifier as well. Apply this
configuration before disabling any existing proxy path, then verify DNS and
HTTPS and inspect `--telemetry`. DNS entries should show UDP or TCP destination
port 53, and public answers must not be from Clash's `198.18.0.0/15` fake-IP
range. Add the local, link-local, multicast, or other destination prefixes that
must remain directly reachable on the host's network.

The provider records protocol, original destination, rewritten SOCKS
destination (when different), `remoteHostname` when supplied by the OS, and
source signing identifier. It returns `false` for excluded flows,
letting the OS handle them directly. Provider-owned egress is not handed back to
the provider, which is structural loop avoidance. Re-running the launcher sends
new configuration to an active provider; `--telemetry` prints and drains a JSON
buffer capped at 4,096 flow records, so an unattended extension cannot grow the
buffer without bound.

Every accepted TCP and UDP flow emits a terminal completion record. Provider
stop closes all active Apple flows, cancels their tasks, and waits for teardown.
SOCKS setup is bounded to 10 seconds, inactive TCP and UDP flows to five and two
minutes, and a TCP peer has 30 seconds to finish after an application half-close.
Re-running the launcher updates only new flows; each accepted flow retains the
configuration snapshot under which it started.

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

On application EOF, Tunless now half-closes the SOCKS connection and continues
reading the peer until EOF or the 30-second drain bound. The Network Extension
flow API still does not reliably preserve a client TCP half-close. A
test application that calls `shutdown(SHUT_WR)` causes its
`NEAppProxyTCPFlow` to become disconnected; a later provider `write` fails with
`NEAppProxyFlowErrorDomain` code 1 even though the SOCKS peer can still return
data. Tunless recognizes that disconnect as an application EOF and attempts the
correct SOCKS lifecycle, but it cannot make the disconnected Apple flow accept
the response. Normal full-duplex TCP, HTTP/1.x, HTTP/2, TLS, and remote-first EOF are
supported. Protocols that require a client FIN as an application-level message
delimiter need a packet-layer implementation rather than an app-proxy flow.

Current source is build 9 (`1.0.8`). On 2026-08-18 its 25-test Swift suite and
unsigned containing-app/system-extension Debug build passed. It has not yet
replaced the installed notarized build or been represented as a new live
network validation.

Validated on macOS 26.3 on 2026-08-17: build 8 (`1.0.7`) of the universal
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

Older extension builds may remain listed as `terminated waiting to uninstall on
reboot` after an in-place update. The newest build must be the single
`activated enabled` entry; a reboot is not required just to use that build.
