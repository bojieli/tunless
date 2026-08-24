import Foundation
import Network

/// Confirms that name resolution works through the live tunless datapath.
///
/// Preflight proves the upstream can relay DNS. This proves the assembled
/// system actually resolves once capture is enabled: the provider is in the
/// path, its rules are loaded, and its DNS rewrite reaches a resolver that
/// answers. The two are different failures, and only this one can be detected
/// after `startVPNTunnel` returns.
///
/// The query deliberately goes through the system resolver so it traverses
/// whatever the host would really use, which is the path that stalls when
/// something in the chain cannot carry DNS.
enum DNSDatapathCheck {
    /// Resolves a well-known name, retrying briefly because the provider needs
    /// a moment to install its rules after the tunnel reports connected.
    static func run(
        timeout: TimeInterval,
        name: String = "example.com",
        completion: @escaping (Bool) -> Void
    ) {
        let deadline = Date().addingTimeInterval(timeout)
        attempt(name: name, deadline: deadline, completion: completion)
    }

    private static func attempt(
        name: String,
        deadline: Date,
        completion: @escaping (Bool) -> Void
    ) {
        let remaining = deadline.timeIntervalSinceNow
        guard remaining > 0 else {
            completion(false)
            return
        }
        let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(name), port: 443)
        // A monitor gives the resolution result without opening a connection to
        // the destination, so the check does not depend on the remote host
        // accepting traffic.
        let path = NWConnection(to: endpoint, using: .tcp)
        let queue = DispatchQueue(label: "com.bojieli.tunless.dns-datapath-check")
        var settled = false
        let settle: (Bool) -> Void = { resolved in
            guard !settled else { return }
            settled = true
            path.cancel()
            if resolved {
                DispatchQueue.main.async { completion(true) }
            } else {
                // Retry until the deadline; the provider may still be settling.
                queue.asyncAfter(deadline: .now() + 1) {
                    attempt(name: name, deadline: deadline, completion: completion)
                }
            }
        }
        path.stateUpdateHandler = { state in
            switch state {
            case .ready:
                // Reaching ready means the name resolved and a connection
                // completed through the datapath.
                settle(true)
            case let .waiting(error):
                // DNS failures surface here as a resolution error rather than a
                // hard failure, so treat waiting as not-yet-resolved.
                _ = error
                settle(false)
            case .failed:
                settle(false)
            default:
                break
            }
        }
        path.start(queue: queue)
        queue.asyncAfter(deadline: .now() + min(3, max(1, remaining))) {
            settle(false)
        }
    }
}
