import Foundation

/// Runs the exchanges that answer-based selection needs.
///
/// Every other DNS path in the provider forwards: a datagram arrives, it is
/// rewritten, it leaves, and the reply is rewritten back. Adjudication cannot be
/// expressed that way. It has one question, two answers, and a decision that
/// belongs to neither of them, so the query has to be held while both resolvers
/// are asked and a single reply synthesised for the application afterwards. That
/// is the whole reason this actor exists, and it is deliberately the only place
/// in the datapath that holds a query.
///
/// It is bounded in every direction that matters. An adjudication occupies one
/// transaction ID, which is the same ceiling forwarding already has; it is
/// abandoned at a deadline whether or not anyone answered; and a direct resolver
/// that stops answering is taken out of the path entirely rather than being
/// waited on once per lookup for as long as it stays down.
///
/// The Go side carries the same actor as `socks5.dnsArbiter`, and the two are
/// meant to reach the same verdict from the same pair of answers.
actor DNSArbiter {
    /// One query held while both resolvers are asked.
    private final class Adjudication {
        let originalID: UInt16
        /// The resolver address the application wrote to, which the concluded
        /// reply has to appear to come from. A datagram arriving from anywhere
        /// else is discarded by the kernel on a connected socket, which is every
        /// resolver client worth naming.
        let original: SOCKSAddress
        let query: Data
        var exchange = DNSExchange()
        var settled = false
        var timers: [Task<Void, Never>] = []

        init(originalID: UInt16, original: SOCKSAddress, query: Data) {
            self.originalID = originalID
            self.original = original
            self.query = query
        }
    }

    private let policy: DNSPolicy
    /// Puts one query on the direct path, reporting whether it left.
    ///
    /// A closure rather than the relay itself, because what this actor needs is
    /// "ask the direct resolver" and nothing else about how. It also means the
    /// direct half can be driven deterministically in a test instead of through
    /// a socket whose failure timing decides the result.
    private let askDirect: @Sendable (Data) async -> Bool
    /// Hands the concluded reply to the application, addressed from the resolver
    /// it believed it was asking.
    private let deliver: @Sendable (Data, SOCKSAddress) async -> Void
    /// Frees the transaction ID and its loop-guard registration once an
    /// adjudication can no longer receive anything.
    private let release: @Sendable (UInt16) async -> Void
    private let breaker: DirectResolverBreaker
    private let counters: DNSPolicyCounters
    /// Injectable so a test can drive the window and the deadline by hand
    /// rather than by outwaiting them, which is both slow and a race.
    private let directReplyWindow: TimeInterval
    private let adjudicationDeadline: TimeInterval

    private var pending: [UInt16: Adjudication] = [:]
    private var cancelled = false

    init(
        policy: DNSPolicy,
        askDirect: @escaping @Sendable (Data) async -> Bool,
        breaker: DirectResolverBreaker,
        counters: DNSPolicyCounters,
        deliver: @escaping @Sendable (Data, SOCKSAddress) async -> Void,
        release: @escaping @Sendable (UInt16) async -> Void,
        directReplyWindow: TimeInterval = DNSPolicy.directReplyWindow,
        adjudicationDeadline: TimeInterval = DNSPolicy.adjudicationDeadline
    ) {
        self.policy = policy
        self.askDirect = askDirect
        self.breaker = breaker
        self.counters = counters
        self.deliver = deliver
        self.release = release
        self.directReplyWindow = directReplyWindow
        self.adjudicationDeadline = adjudicationDeadline
    }

    /// Holds a query and asks both resolvers.
    ///
    /// The query handed here has already had its transaction ID rewritten, and
    /// the same rewritten query goes to both resolvers. One identifier for both
    /// halves keeps the two replies matchable by the socket they arrived on
    /// rather than by anything a third party could arrange to collide with, and
    /// it keeps the unpredictable identifier the rewrite exists to preserve in
    /// front of both.
    ///
    /// Reports whether the trusted half should be sent by the caller. It always
    /// should, unless the provider is shutting down: the direct half is this
    /// actor's business, the trusted half travels on the flow's own SOCKS
    /// association and stays the caller's.
    func begin(
        identifier: UInt16, originalID: UInt16, original: SOCKSAddress, query: Data
    ) -> Bool {
        guard !cancelled else { return false }
        // Defensive: `decide` only returns `.adjudicate` when a direct resolver
        // is configured. Without one there is nothing to adjudicate against, and
        // the exchange degrades to the plain trusted query it would have been.
        guard policy.directResolver != nil else { return true }
        let entry = Adjudication(originalID: originalID, original: original, query: query)
        pending[identifier] = entry

        // A direct resolver that has stopped answering is not asked. Without
        // this a resolver that is merely unreachable costs every single lookup
        // the whole direct window before the trusted answer is served, which
        // turns one misconfiguration into a host-wide latency floor that looks
        // like the proxy being slow.
        let window = directReplyWindow
        let deadline = adjudicationDeadline
        if breaker.allow() {
            entry.timers.append(
                Task { [weak self] in
                    try? await Task.sleep(
                        nanoseconds: UInt64(window * 1_000_000_000))
                    guard !Task.isCancelled else { return }
                    await self?.expire(identifier, deadline: false)
                })
            let ask = self.askDirect
            let counters = self.counters
            Task { [weak self] in
                if await ask(query) { return }
                counters.directSendFailed()
                await self?.completeDirect(identifier, reply: nil)
            }
        } else {
            entry.exchange.directDone = true
            counters.directSkipped()
        }
        entry.timers.append(
            Task { [weak self] in
                try? await Task.sleep(
                    nanoseconds: UInt64(deadline * 1_000_000_000))
                guard !Task.isCancelled else { return }
                await self?.expire(identifier, deadline: true)
            })
        return true
    }

    /// Whether an outstanding identifier belongs to this actor, so the reply
    /// path can hand it here instead of delivering it to the application.
    func isAdjudicating(_ identifier: UInt16) -> Bool { pending[identifier] != nil }

    /// Offers a datagram that arrived from the direct resolver, reporting
    /// whether it belonged to an adjudication. A datagram this declines is the
    /// answer to a query the name lists routed here, and the caller delivers it
    /// the ordinary way.
    @discardableResult
    func deliverDirect(_ payload: Data, from source: SOCKSAddress) async -> Bool {
        guard payload.count >= 2, let directResolver = policy.directResolver,
            source == directResolver, let identifier = Self.identifier(in: payload)
        else { return false }
        return await completeDirect(identifier, reply: payload)
    }

    /// Offers a datagram that came back through the proxy, reporting whether it
    /// belonged to an adjudication.
    @discardableResult
    func deliverTrusted(_ payload: Data, identifier: UInt16) async -> Bool {
        guard let entry = pending[identifier] else { return false }
        guard !entry.settled else { return true }
        guard DNSPolicy.isReply(payload, to: entry.query) else {
            // Claimed but not believed. The identifier is one this process
            // minted, so nothing else on the host is entitled to it, and
            // dropping a mismatched datagram here keeps a forged one from
            // consuming the exchange the real answer belongs to.
            return true
        }
        entry.exchange.trusted = payload
        entry.exchange.trustedDone = true
        await evaluate(identifier, entry)
        return true
    }

    /// Records the direct half's result, whether an answer or a failure.
    @discardableResult
    private func completeDirect(_ identifier: UInt16, reply: Data?) async -> Bool {
        guard let entry = pending[identifier] else { return false }
        guard !entry.settled, !entry.exchange.directDone else { return true }
        if let reply {
            guard DNSPolicy.isReply(reply, to: entry.query) else { return true }
            entry.exchange.direct = reply
            breaker.succeed()
        } else {
            breaker.fail()
        }
        entry.exchange.directDone = true
        await evaluate(identifier, entry)
        return true
    }

    /// Marks a window or the deadline as reached.
    private func expire(_ identifier: UInt16, deadline: Bool) async {
        guard let entry = pending[identifier], !entry.settled else { return }
        if deadline {
            entry.exchange.deadlineReached = true
        } else {
            entry.exchange.directWindowClosed = true
            if !entry.exchange.directDone {
                // A direct resolver that missed its window on this query is one
                // step closer to being taken out of the path. Counted here
                // rather than at the deadline so a resolver that is slow rather
                // than dead is still measured as failing.
                breaker.fail()
            }
        }
        await evaluate(identifier, entry)
    }

    /// Asks the policy whether the exchange has settled, and concludes it when
    /// it has.
    private func evaluate(_ identifier: UInt16, _ entry: Adjudication) async {
        let (verdict, reason) = policy.adjudicate(entry.exchange)
        guard verdict != .wait else { return }
        entry.settled = true
        pending.removeValue(forKey: identifier)
        for timer in entry.timers { timer.cancel() }
        counters.record(verdict: verdict, reason: reason)

        var reply: Data?
        switch verdict {
        case .serveDirect: reply = entry.exchange.direct
        case .serveTrusted: reply = entry.exchange.trusted
        case .refuse: reply = DNSPolicy.refusal(for: entry.query)
        default: reply = nil
        }
        await release(identifier)
        guard var final = reply, final.count >= 2 else { return }
        // The application is owed its own transaction ID back. It never saw the
        // one this process minted, and a reply carrying an identifier the client
        // did not choose is a reply the client discards.
        final[final.startIndex] = UInt8(entry.originalID >> 8)
        final[final.startIndex + 1] = UInt8(entry.originalID & 0xff)
        await deliver(final, entry.original)
    }

    /// Abandons everything outstanding. Nothing is delivered, which is what a
    /// flow going away means: the socket that asked is gone.
    func cancel() async {
        cancelled = true
        let outstanding = pending
        pending.removeAll()
        for (identifier, entry) in outstanding {
            for timer in entry.timers { timer.cancel() }
            await release(identifier)
        }
    }

    func outstandingCount() -> Int { pending.count }

    private static func identifier(in message: Data) -> UInt16? {
        guard message.count >= 2 else { return nil }
        let start = message.startIndex
        return UInt16(message[start]) << 8 | UInt16(message[start + 1])
    }
}

/// Takes a direct resolver that has stopped answering out of the adjudication
/// path, and puts it back when it starts answering again.
///
/// Without it, an unreachable direct resolver is not a degraded feature but a
/// host-wide slowdown: every unlisted name waits the full direct window before
/// the trusted answer it was always going to get is served. With it the cost is
/// paid a handful of times and then stops, and a resolver that comes back is
/// found by the next probe rather than by a restart.
///
/// It is shared across flows on purpose. Reachability is a property of the
/// resolver and the network, not of the socket that happened to ask, and a
/// per-flow breaker would relearn the same outage once per application.
final class DirectResolverBreaker: @unchecked Sendable {
    /// More than one, because a single lookup can lose a race with a network
    /// change. Not many more, because every one of them costs a lookup the full
    /// direct window.
    let failuresBeforeOpen: Int
    /// Long enough that a resolver which is genuinely down is not probed once
    /// per lookup, short enough that one which came back is used again before
    /// anybody thinks to restart anything.
    let cooldownSeconds: TimeInterval
    private let clock: @Sendable () -> Date
    private let lock = NSLock()
    private var consecutive = 0
    private var openUntil: Date?

    init(
        failuresBeforeOpen: Int = 5,
        cooldownSeconds: TimeInterval = 30,
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.failuresBeforeOpen = failuresBeforeOpen
        self.cooldownSeconds = cooldownSeconds
        self.clock = clock
    }

    /// Whether the direct resolver should be asked. One query is let through
    /// once the cooldown has elapsed, so recovery is observed rather than
    /// assumed.
    func allow() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let until = openUntil else { return true }
        if clock() > until {
            openUntil = nil
            return true
        }
        return false
    }

    func fail() {
        lock.lock()
        defer { lock.unlock() }
        consecutive += 1
        if consecutive >= failuresBeforeOpen {
            openUntil = clock().addingTimeInterval(cooldownSeconds)
            consecutive = 0
        }
    }

    func succeed() {
        lock.lock()
        defer { lock.unlock() }
        consecutive = 0
        openUntil = nil
    }

    /// Whether the direct resolver is currently out of the path.
    var isOpen: Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let until = openUntil else { return false }
        return clock() <= until
    }
}

/// Counts what the DNS policy decided, keyed by the layer that decided it.
///
/// The counters are not decoration. Answer-based selection has a failure mode
/// that produces no error anywhere: a prefix set that matches nothing looks
/// exactly like a network with no interference on it, and both present as every
/// answer coming from the trusted resolver. The only way to tell them apart is
/// to be able to see that the direct half is being asked and is losing.
///
/// Names and destinations are deliberately absent. This is a health surface, and
/// a health surface that accumulates the names a host looked up is a log of the
/// user's browsing wearing a different hat.
final class DNSPolicyCounters: @unchecked Sendable {
    struct Snapshot: Sendable, Codable, Equatable {
        var localName = 0
        var directList = 0
        var trustedList = 0
        var trustedDefault = 0
        var notAddressQuery = 0
        var unreadableQuery = 0
        var adjudicated = 0
        var servedDirect = 0
        var servedTrusted = 0
        var servedDirectNoAnswer = 0
        var refused = 0
        var droppedNoReply = 0
        var directSkipped = 0
        var directSendFailed = 0
        var directBreakerOpen = false
    }

    private let lock = NSLock()
    private var snapshot = Snapshot()

    func record(decision: DNSDecision) {
        lock.lock()
        defer { lock.unlock() }
        switch decision.reason {
        case .localName: snapshot.localName += 1
        case .directList: snapshot.directList += 1
        case .trustedList: snapshot.trustedList += 1
        case .notAddressQuery: snapshot.notAddressQuery += 1
        case .unreadableQuery: snapshot.unreadableQuery += 1
        case .unlisted: snapshot.adjudicated += 1
        case .noDirectResolver: snapshot.trustedDefault += 1
        }
    }

    func record(verdict: DNSVerdict, reason: DNSVerdictReason?) {
        lock.lock()
        defer { lock.unlock() }
        switch verdict {
        case .serveDirect:
            if reason == .directNoAnswer {
                snapshot.servedDirectNoAnswer += 1
            } else {
                snapshot.servedDirect += 1
            }
        case .serveTrusted: snapshot.servedTrusted += 1
        case .refuse: snapshot.refused += 1
        case .drop: snapshot.droppedNoReply += 1
        case .wait: break
        }
    }

    func directSkipped() {
        lock.lock()
        defer { lock.unlock() }
        snapshot.directSkipped += 1
    }

    func directSendFailed() {
        lock.lock()
        defer { lock.unlock() }
        snapshot.directSendFailed += 1
    }

    func current(breakerOpen: Bool) -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        var copy = snapshot
        copy.directBreakerOpen = breakerOpen
        return copy
    }
}

/// Offers each datagram the direct relay receives to the arbiter before the
/// application sees it.
///
/// The relay carries two different things on one socket: the answer to a query
/// a name list routed direct, which belongs to the application, and the direct
/// half of an adjudication, which belongs to the arbiter. Only the arbiter can
/// tell them apart, because only it knows which identifiers it is holding.
///
/// What the arbiter declines is restored on the way past, because a query the
/// policy sent to a configured direct resolver was rewritten to get there: it
/// carries an identifier the application never chose and comes back from an
/// address the application never wrote to, and a connected resolver socket
/// discards both.
actor ArbitratedDatagramSink: DatagramSink {
    private let downstream: any DatagramSink
    private let dnsResponses: DNSResponseMap
    private var arbiter: DNSArbiter?

    init(downstream: any DatagramSink, dnsResponses: DNSResponseMap) {
        self.downstream = downstream
        self.dnsResponses = dnsResponses
    }

    /// Attached after construction because the arbiter sends on the relay this
    /// sink belongs to, so one of the two references has to be resolved later.
    func attach(_ arbiter: DNSArbiter) { self.arbiter = arbiter }

    func write(_ payload: Data, from source: SOCKSAddress) async {
        if let arbiter, await arbiter.deliverDirect(payload, from: source) { return }
        let restored = await dnsResponses.restore(response: payload, receivedFrom: source)
        await downstream.write(restored.payload, from: restored.source)
    }
}
