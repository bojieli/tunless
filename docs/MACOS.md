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
`/Applications`, and invoke its executable with `--upstream`. First activation
opens the standard macOS approval path. `--stop` disables only the manager whose
localized description is exactly `tunless`; the launcher never edits the first
unrelated transparent-proxy manager it finds.

When Clash Verge is the upstream, exclude its outbound processes so their
connections are not handed back to Clash through Tunless:

```console
/Applications/Tunless.app/Contents/MacOS/Tunless \
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

`--dns-upstream` defaults to `1.1.1.1:53`. Tunless redirects captured UDP and
TCP port 53 queries to that numeric resolver through the SOCKS5 upstream; it
does not send them to the resolver named in macOS network settings. A numeric
address is required so selecting the trusted resolver cannot itself depend on
system DNS. UDP replies are presented to the application as coming from the
resolver it originally addressed, preserving connected-datagram semantics.
Set `TUNLESS_DNS_UPSTREAM` to choose another trusted resolver.

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

The Network Extension flow API does not preserve a client TCP half-close. A
test application that calls `shutdown(SHUT_WR)` causes its
`NEAppProxyTCPFlow` to become disconnected; a later provider `write` fails with
`NEAppProxyFlowErrorDomain` code 1 even though the SOCKS peer can still return
data. Normal full-duplex TCP, HTTP/1.x, HTTP/2, TLS, and remote-first EOF are
supported. Protocols that require a client FIN as an application-level message
delimiter need a packet-layer implementation rather than an app-proxy flow.

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
