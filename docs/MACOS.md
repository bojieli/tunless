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

The provider records protocol, real destination, `remoteHostname` when supplied
by the OS, and source signing identifier. It returns `false` for excluded flows,
letting the OS handle them directly. Provider-owned egress is not handed back to
the provider, which is structural loop avoidance. Re-running the launcher sends
new configuration to an active provider; `--telemetry` prints and drains a JSON
buffer capped at 4,096 flow records, so an unattended extension cannot grow the
buffer without bound.

Current gate: the unsigned Release build and Swift integration tests pass. The
installed `Developer ID Application: Li Bojie (5BR9M56H9W)` identity
timestamp-signs both nested bundles with hardened runtime and their real
entitlements, and strict deep signature verification passes. Gatekeeper reports
that manual artifact as `Unnotarized Developer ID`.

The normal Xcode Release build with `-allowProvisioningUpdates` reaches Apple's
developer service, which reports that an updated Program License Agreement must
be accepted and cannot create matching macOS profiles for either bundle ID.
Installing the manually signed test copy in `/Applications` did not bypass that
check: AMFI terminated it with error -413, `No matching profile found`, before
an activation request could succeed. No Tunless system extension or network
configuration was left installed, and the test app was removed afterward.

Activation, notarization, hostname-population measurement, and the declined-flow
inventory therefore remain unverified. Accepting a legal account agreement is
an account-holder action; weakening SIP, AMFI, or entitlement enforcement is
not an acceptable substitute for this release gate.
