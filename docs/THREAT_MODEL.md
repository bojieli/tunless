# Threat model

## Assets and goals

Tunless should deliver selected local socket flows to the configured SOCKS5
upstream without changing application configuration, fabricating DNS answers,
or routing unrelated traffic. It should not leak upstream credentials through
logs/status, capture outside the configured process/cgroup/destination scope, or
leave traffic blocked after the controller exits.

## Trust boundaries

The administrator, operating-system kernel, installed Tunless binary and BPF or
platform extension, and configured SOCKS5 server are trusted. The SOCKS server
can observe and modify proxied cleartext traffic and destinations. Root or
kernel compromise, a malicious administrator, and a malicious upstream are
outside the protection boundary.

Applications and application containers are untrusted. Their socket arguments,
DNS messages, connection rates, protocol behavior, process metadata, and
lifecycle timing may be adversarial. Container images do not receive Tunless
credentials or privileges. Docker/Podman/CRI control access is privileged and
must be limited to trusted operators; control of an engine socket is effectively
host-root access.

## Principal risks and controls

| Risk | Control | Residual risk |
| --- | --- | --- |
| Capturing Tunless's own upstream connection | Relay runs outside the captured cgroup; Windows uses redirect records; container controller remains outside the target cgroup | Incorrect administrator cgroup layout can create loops |
| PID reuse attaches to another container | PID is refreshed and its cgroup must contain the exact validated engine ID | A compromised engine/kernel can forge inspection state |
| Controller crash blocks traffic | BPF links and redirect sockets are unpinned; process exit detaches them and new flows continue direct | In-flight proxied flows fail and must reconnect |
| Resource exhaustion | Fixed BPF map capacities, maximum concurrent flow admission, bounded DNS/telemetry state, HTTP timeouts, and stress tests | The OS/upstream can still be exhausted below Tunless |
| Status or metadata exposure | Status is numeric loopback-only; metadata socket is mode 0600; upstream credentials are omitted | Local privileged users can observe process/network state |
| Malformed network input | Strict SOCKS/DNS/address parsing, length bounds, race tests, and fuzz targets | Kernel and platform-specific parsers remain trusted dependencies |
| DNS pollution or response misassociation | Captured port-53 traffic uses a numeric trusted resolver through SOCKS; UDP IDs and source endpoints are translated and restored with bounded expiry | Encrypted DNS and Windows UDP remain outside the override; disabling override intentionally retains the original resolver |
| Supply-chain compromise | Pinned toolchains/actions, dependency review, CodeQL, secret scanning, SBOMs, checksums, and provenance for candidate artifacts | Maintainer/account or upstream dependency compromise remains possible |

## Explicit non-goals

Tunless is not an anonymity system, content filter, sandbox, firewall, VPN, TLS
inspector, or packet-forwarding gateway. It does not protect traffic the
configured filters exclude, traffic using unsupported protocols, raw packets,
or guest-VM sockets when Tunless is installed only on the host. Windows UDP is
currently direct. Unsigned/unactivated macOS source and an unqualified Windows
driver are not release-supported security boundaries.

## Reporting and review

Report vulnerabilities privately through GitHub Security Advisories. Changes to
privilege, capture scope, parsing, release provenance, or fail-open behavior
require threat-model review and a regression test on the affected platform.
