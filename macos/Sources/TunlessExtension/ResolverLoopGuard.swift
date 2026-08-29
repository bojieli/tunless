import Foundation

/// Breaks the one loop that stops capture from claiming an application's own
/// query to the trusted resolver.
///
/// The trusted resolver used to be reserved by address: capture declined every
/// port-53 flow addressed to it, whatever asked. That is a real protection —
/// capture rewrites port-53 flows to that resolver and relays them to the
/// upstream, the upstream then dials the resolver itself, and if that dial were
/// captured too the query would be handed back to the upstream waiting on it.
/// Nothing errors. Every lookup on the host recurses until it times out, which
/// reads as a dead network rather than as a proxy loop.
///
/// The cost of doing it by address is that an application configured to use that
/// same resolver — and `1.1.1.1` is both this project's default and one of the
/// most commonly configured resolvers there is — was declined for the same
/// reason, so the DNS override never saw the queries of anyone who had already
/// chosen a good resolver. They went out on the network's own path and came back
/// with whatever that path decided to answer.
///
/// The two flows are distinguishable without reserving the address. Capture
/// rewrites the transaction ID of every query it relays, to an ID drawn at
/// random that the application never chose. The upstream forwards that query
/// verbatim, so the dial that would close the loop is carrying an ID capture
/// itself is holding open, while an application's own query to the same resolver
/// is not. Registering the IDs in flight is therefore enough to tell "this is my
/// own query coming back" from "this is somebody's lookup".
///
/// A false positive costs one query the override: an application whose own
/// transaction ID happens to collide with one in flight, while querying the
/// resolver capture relays to, has that datagram sent direct. That is the
/// behaviour every such query had before this existed, it lasts one datagram,
/// and the resolver client retries.
final class ResolverLoopGuard: @unchecked Sendable {
    private let lock = NSLock()
    private var inFlight: [UInt16: Date] = [:]
    private let lifetime: TimeInterval
    private let maxEntries: Int
    private let now: @Sendable () -> Date

    /// An entry outlives its exchange only when a reply never came. The lifetime
    /// is what bounds that, and it is deliberately longer than the response map's
    /// own timeout so that the guard is never the first thing to forget.
    init(
        lifetime: TimeInterval = 60,
        maxEntries: Int = 8192,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.lifetime = lifetime
        self.maxEntries = maxEntries
        self.now = now
    }

    func register(_ identifier: UInt16) {
        let moment = now()
        lock.lock()
        defer { lock.unlock() }
        prune(moment)
        // A full table stops registering rather than evicting. Dropping an entry
        // to make room would let the query it belonged to close the loop, and a
        // guard that forgets under load forgets exactly when a loop is running.
        guard inFlight.count < maxEntries || inFlight[identifier] != nil else { return }
        inFlight[identifier] = moment.addingTimeInterval(lifetime)
    }

    func release(_ identifier: UInt16) {
        lock.lock()
        inFlight.removeValue(forKey: identifier)
        lock.unlock()
    }

    /// Whether this identifier belongs to a query capture is currently relaying,
    /// which makes the datagram carrying it the upstream's own forwarded copy.
    func isRelaying(_ identifier: UInt16) -> Bool {
        let moment = now()
        lock.lock()
        defer { lock.unlock() }
        guard let expires = inFlight[identifier] else { return false }
        if moment >= expires {
            inFlight.removeValue(forKey: identifier)
            return false
        }
        return true
    }

    /// Whether the first bytes of `payload` carry an identifier being relayed.
    func isRelayedQuery(_ payload: Data) -> Bool {
        guard payload.count >= 12 else { return false }
        let bytes = [UInt8](payload.prefix(2))
        return isRelaying(UInt16(bytes[0]) << 8 | UInt16(bytes[1]))
    }

    func count() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return inFlight.count
    }

    private func prune(_ moment: Date) {
        guard inFlight.count >= maxEntries / 2 else { return }
        inFlight = inFlight.filter { moment < $0.value }
    }
}
