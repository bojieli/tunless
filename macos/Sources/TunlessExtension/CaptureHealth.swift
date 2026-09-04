import Foundation
import Network

/// The part of an `NWPath` that identifies the network carrying the
/// provider's sockets.
///
/// `NWPathMonitor` is allowed to report the same interface name for two very
/// different networks. In particular, macOS commonly keeps Wi-Fi and an
/// iPhone hotspot on `en0`; the gateway, cost, endpoint, and path capabilities
/// still change. Keeping a value type here makes that distinction explicit and
/// gives the watchdog something deterministic to compare instead of treating
/// `path.status == .satisfied` as a complete description of the network.
struct NetworkPathIdentity: Equatable, Sendable {
    let status: String
    let interfaces: [String]
    let expensive: Bool
    let constrained: Bool
    let supportsIPv4: Bool
    let supportsIPv6: Bool
    let supportsDNS: Bool
    let gateways: [String]
    let localEndpoint: String?
    let remoteEndpoint: String?

    init(
        status: String,
        interfaces: [String] = [],
        expensive: Bool = false,
        constrained: Bool = false,
        supportsIPv4: Bool = true,
        supportsIPv6: Bool = false,
        supportsDNS: Bool = true,
        gateways: [String] = [],
        localEndpoint: String? = nil,
        remoteEndpoint: String? = nil
    ) {
        self.status = status
        self.interfaces = interfaces.sorted()
        self.expensive = expensive
        self.constrained = constrained
        self.supportsIPv4 = supportsIPv4
        self.supportsIPv6 = supportsIPv6
        self.supportsDNS = supportsDNS
        self.gateways = gateways.sorted()
        self.localEndpoint = localEndpoint
        self.remoteEndpoint = remoteEndpoint
    }

    init(path: NWPath) {
        self.init(
            status: String(describing: path.status),
            interfaces: path.availableInterfaces.map {
                "\($0.name):\($0.index):\(String(describing: $0.type))"
            },
            expensive: path.isExpensive,
            constrained: path.isConstrained,
            supportsIPv4: path.supportsIPv4,
            supportsIPv6: path.supportsIPv6,
            supportsDNS: path.supportsDNS,
            gateways: path.gateways.map(\.debugDescription),
            localEndpoint: path.localEndpoint?.debugDescription,
            remoteEndpoint: path.remoteEndpoint?.debugDescription)
    }
}

/// Tracks meaningful path changes while ignoring duplicate monitor callbacks.
///
/// The first callback establishes the baseline. Every later identity change is
/// a new generation, even when the active interface has the same name.
struct NetworkPathGeneration: Equatable, Sendable {
    private(set) var generation: UInt64 = 0
    private(set) var identity: NetworkPathIdentity?

    /// Returns true when `identity` starts a new network generation.
    @discardableResult
    mutating func update(_ identity: NetworkPathIdentity) -> Bool {
        guard let previous = self.identity else {
            self.identity = identity
            return false
        }
        guard previous != identity else { return false }
        self.identity = identity
        generation &+= 1
        return true
    }
}

/// A small thread-safe epoch shared by all disposable network transports.
///
/// It deliberately is not an actor: `NWPathMonitor` callbacks, association
/// actors, and probe tasks all need to read the value without introducing an
/// await point in the middle of a transport validity check.
final class NetworkEpoch: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64 = 0

    var current: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    @discardableResult
    func advance() -> UInt64 {
        lock.lock()
        value &+= 1
        let next = value
        lock.unlock()
        return next
    }
}

/// Decides when the upstream datapath is degraded and when it is healthy
/// again.
///
/// Name resolution is the first host-wide signal that a local SOCKS upstream
/// has stopped carrying traffic. Three failures mark the session degraded and
/// retire streams that cannot recover in place; one success clears that state.
/// The provider deliberately keeps claiming proxy-eligible traffic throughout
/// the pause. Handing those flows back to the kernel would convert an upstream
/// outage into an unreported proxy bypass, which is worse than a visible,
/// fail-closed retry. Reserved and local traffic still follows its intentional
/// direct routes.
///
/// Sleep is excluded from the evidence entirely. A machine going to sleep tears
/// its network down, every probe fails, and pausing is both pointless — nothing
/// is using the network — and harmful, because the pause outlives the sleep.
///
/// It is a plain state machine so every one of those decisions can be tested
/// without a network: the provider supplies the clock, the probe, and the path
/// state.
struct CaptureHealth: Equatable {
    /// What the provider should do after an observation.
    enum Decision: Equatable {
        /// Nothing changes.
        case unchanged
        /// Mark the upstream degraded, for the stated reason.
        case pause(String)
        /// Clear the degraded state; the upstream is carrying DNS again.
        case resume
        /// Roll capture back, for the stated reason.
        ///
        /// Degradation keeps proxy-eligible flows captured and failing closed,
        /// which is right while the upstream is coming back and wrong once it
        /// is not coming back. Rolling capture back is the same response the
        /// launcher already makes to a failed post-start verification, moved
        /// to the one state that could otherwise hold a host offline
        /// indefinitely.
        case rollBack(String)
    }

    /// How long capture may run before anything confirms it resolves names.
    ///
    /// The launcher confirms once it has resolved a name through the live
    /// datapath. Without this, a launcher that is killed, suspended, or
    /// disconnected between enabling capture and verifying it leaves capture on
    /// with nothing having checked it — the exact state the post-start rollback
    /// exists to prevent, reached by a path the rollback cannot see.
    let probationSeconds: TimeInterval
    /// How long capture may stay degraded before it is rolled back.
    ///
    /// `probationSeconds` bounds capture that never worked. Nothing bounded
    /// capture that worked and then stopped: once paused, every later failure
    /// was absorbed and the session waited for a recovery that a circular
    /// dependency can make impossible, because capture is itself what prevents
    /// the upstream from resolving the name its datapath needs. Fail-closed is
    /// the right transient and the wrong steady state, so it gets a deadline.
    ///
    /// Generous relative to a real outage — observed recoveries land around
    /// twenty seconds — because rolling back is the more disruptive answer and
    /// should lose every race against an upstream that is genuinely returning.
    /// Zero disables the deadline for operators who would rather have the host
    /// offline than have capture stand aside.
    let degradedSeconds: TimeInterval
    /// Consecutive failed probes tolerated before capture is marked degraded.
    ///
    /// More than one, because a single query can lose a race with a node switch
    /// or a route change. Not many more, because every probe interval spent
    /// failing is an interval the host spends unable to resolve.
    let failuresBeforePause: Int
    /// How long after a wake to ignore probe results.
    ///
    /// Interfaces, routes, and the upstream's own connections come back over
    /// several seconds, and probes taken during that window measure the wake,
    /// not the upstream.
    let wakeGraceSeconds: TimeInterval
    /// How long after a path/network change to ignore probe results.
    ///
    /// A route can be reported as satisfied before the local proxy has rebuilt
    /// its own outbound sockets. Probing in that window measures the teardown
    /// rather than the new path and would otherwise trip the failure budget.
    let networkChangeGraceSeconds: TimeInterval

    private(set) var confirmed = false
    private(set) var consecutiveFailures = 0
    private(set) var paused = false
    private(set) var pauseReason: String?
    /// Monotonically increasing token captured by asynchronous probes.
    private(set) var networkGeneration: UInt64 = 0
    private var armedAt: Date?
    /// When the current degraded state began, and so what `degradedSeconds` is
    /// measured from. Cleared everywhere `paused` is.
    private var pausedAt: Date?
    private var asleep = false
    private var ignoreProbesUntil: Date?

    init(
        probationSeconds: TimeInterval = 45,
        failuresBeforePause: Int = 3,
        wakeGraceSeconds: TimeInterval = 20,
        networkChangeGraceSeconds: TimeInterval = 15,
        degradedSeconds: TimeInterval = 300
    ) {
        self.probationSeconds = probationSeconds
        self.degradedSeconds = degradedSeconds
        self.failuresBeforePause = failuresBeforePause
        self.wakeGraceSeconds = wakeGraceSeconds
        self.networkChangeGraceSeconds = networkChangeGraceSeconds
    }

    /// Historical name for the state-machine pause. The provider uses this for
    /// diagnostics, not admission: proxy-eligible flows remain fail-closed.
    var shouldDeclineFlows: Bool { paused }

    /// Capture has just been enabled and its probation window starts now.
    mutating func arm(at now: Date) {
        armedAt = now
        confirmed = false
        consecutiveFailures = 0
        paused = false
        pauseReason = nil
        pausedAt = nil
        // Do not reset this token. A probe from a previous provider session
        // can finish after a rapid stop/start; keeping the counter monotonic
        // guarantees that result cannot be mistaken for the new session's
        // first generation.
        networkGeneration &+= 1
        asleep = false
        ignoreProbesUntil = nil
    }

    /// The launcher resolved a name through the live datapath.
    mutating func confirm() {
        confirmed = true
        consecutiveFailures = 0
    }

    /// The system is about to sleep. Probes taken from here until the wake are
    /// measuring a machine with no network, so they say nothing about capture.
    mutating func systemWillSleep() {
        asleep = true
        consecutiveFailures = 0
        networkGeneration &+= 1
    }

    /// The system woke. Give the network time to come back before believing any
    /// probe again, and forget the failures that led into the sleep.
    mutating func systemDidWake(at now: Date) {
        asleep = false
        consecutiveFailures = 0
        networkGeneration &+= 1
        ignoreProbesUntil = now.addingTimeInterval(wakeGraceSeconds)
        // A machine that slept while degraded has not spent that time waiting
        // for the upstream; nothing was using the network. Restart the clock so
        // a long sleep cannot roll capture back the moment the host wakes.
        if paused { pausedAt = now }
    }

    /// The path carrying the upstream changed.
    ///
    /// A successful probe on the old path must never be allowed to affect the
    /// new path, so this advances the probe token as well as clearing all
    /// evidence collected before the transition. Capture remains claimed (the
    /// provider fails closed for proxy-eligible traffic), and a previously
    /// paused health state is cleared so new flows can immediately attempt the
    /// rebuilt upstream without inheriting stale failure evidence.
    mutating func networkDidChange(at now: Date) -> Decision {
        networkGeneration &+= 1
        consecutiveFailures = 0
        confirmed = false
        armedAt = now
        ignoreProbesUntil = now.addingTimeInterval(networkChangeGraceSeconds)
        paused = false
        pauseReason = nil
        pausedAt = nil
        // This is not a successful health observation. The old failure no
        // longer applies, but the new path still has to prove itself after the
        // grace interval, so do not emit a misleading "resumed" decision.
        return .unchanged
    }

    /// True when a probe result should not be acted on at all.
    func ignoringProbes(at now: Date) -> Bool {
        if asleep { return true }
        if let until = ignoreProbesUntil, now < until { return true }
        return false
    }

    /// A health probe finished. `pathSatisfied` is the host's own link state:
    /// when the host has no usable network, a failed probe says nothing about
    /// capture, and pausing would only add a recovery step to an outage capture
    /// did not cause.
    mutating func observe(
        succeeded: Bool,
        detail: String = "no answer",
        pathSatisfied: Bool,
        at now: Date,
        generation: UInt64? = nil
    ) -> Decision {
        // An async probe can finish after NWPathMonitor has delivered a new
        // path. Its result belongs to the old sockets and must be discarded.
        if let generation, generation != networkGeneration { return .unchanged }
        guard !ignoringProbes(at: now) else { return .unchanged }
        guard pathSatisfied else { return .unchanged }
        if succeeded {
            confirmed = true
            consecutiveFailures = 0
            guard paused else { return .unchanged }
            // The upstream carries DNS again, so the degraded state is gone.
            // One success is enough: this same loop is still watching and can
            // mark another sustained failure on later probes.
            paused = false
            pauseReason = nil
            pausedAt = nil
            return .resume
        }
        guard !paused else {
            // Still failing, and the degraded state has outlived its deadline.
            // Capture is no longer protecting anything it could not protect by
            // standing aside, so stop holding the host's traffic hostage.
            guard degradedTooLong(at: now) else { return .unchanged }
            return rollBack(
                "capture stayed degraded for \(Int(degradedSeconds))s without resolving a name: \(detail)")
        }
        consecutiveFailures += 1
        if !confirmed {
            // Still unconfirmed: probation, not the failure budget, bounds
            // this. A failing probe here is expected while the provider
            // settles, and the probation window is what ends it.
            guard expired(at: now) else { return .unchanged }
            return pause("capture never resolved a name within its probation window", at: now)
        }
        guard consecutiveFailures >= failuresBeforePause else { return .unchanged }
        return pause(
            "name resolution failed \(consecutiveFailures) times in a row through the upstream: \(detail)",
            at: now)
    }

    /// Called on a timer with no probe result, to end an unbounded state on its
    /// own.
    ///
    /// Two states need that. A launcher that dies before confirming leaves
    /// nothing else to end probation. And an upstream that stops answering
    /// probes altogether stops driving `observe`, so the degraded deadline
    /// needs a clock that does not depend on the thing that is broken.
    mutating func probationDecision(at now: Date) -> Decision {
        guard !ignoringProbes(at: now) else { return .unchanged }
        if degradedTooLong(at: now) {
            return rollBack(
                "capture stayed degraded for \(Int(degradedSeconds))s without resolving a name")
        }
        guard !paused, !confirmed, expired(at: now) else { return .unchanged }
        return pause(
            "capture was never confirmed to resolve names within its probation window", at: now)
    }

    /// Ends the degraded state by giving capture up rather than by recovering.
    private mutating func rollBack(_ reason: String) -> Decision {
        paused = true
        pauseReason = reason
        return .rollBack(reason)
    }

    private mutating func pause(_ reason: String, at now: Date) -> Decision {
        paused = true
        pauseReason = reason
        pausedAt = now
        return .pause(reason)
    }

    /// True once capture has been degraded for longer than the deadline allows.
    ///
    /// A zero or negative deadline disables the rollback entirely, which is the
    /// pre-deadline behaviour and remains available to operators who prefer an
    /// offline host to a bypassed one.
    private func degradedTooLong(at now: Date) -> Bool {
        guard paused, degradedSeconds > 0, let pausedAt else { return false }
        return now.timeIntervalSince(pausedAt) >= degradedSeconds
    }

    private func expired(at now: Date) -> Bool {
        guard let armedAt else { return false }
        return now.timeIntervalSince(armedAt) >= probationSeconds
    }
}

/// Why capture cancelled itself.
///
/// Carried out through `cancelProxyWithError` so the reason reaches the system
/// log and `status`, rather than a bare cancellation that looks like an
/// ordinary stop.
enum CaptureRollbackError: LocalizedError, Equatable {
    case degradedTooLong(String)

    var errorDescription: String? {
        switch self {
        case let .degradedTooLong(reason): return reason
        }
    }
}
