import Foundation

/// Decides when capture has stopped being safe to keep on, and when it is safe
/// again.
///
/// Capture is the only thing standing between the host and its previous,
/// working network path, and the failure that matters is not a crash: a crash
/// is already fail-open, because the flows go direct once nothing is capturing
/// them. The dangerous state is a provider that is alive, holding every flow on
/// the host, and relaying them into an upstream that has stopped being able to
/// answer. Name resolution is where that shows up first and worst, and a host
/// that cannot resolve cannot be told how to fix itself.
///
/// Handing the network back is therefore a pause, not a verdict. An operator
/// who ran `start` asked for capture, and a minute of upstream trouble does not
/// withdraw that request — it only means capture must stand aside until the
/// upstream can carry traffic again. Staying paused after the upstream recovers
/// is its own harm: the host spends that time resolving names through whatever
/// the network hands it, which is the exposure the DNS override exists to
/// remove. So this pauses when the evidence says capture is hurting, and
/// resumes on the first probe that says it is not.
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
        /// Stop claiming flows and let them go direct, for the stated reason.
        case pause(String)
        /// Claim flows again; the upstream is carrying DNS.
        case resume
    }

    /// How long capture may run before anything confirms it resolves names.
    ///
    /// The launcher confirms once it has resolved a name through the live
    /// datapath. Without this, a launcher that is killed, suspended, or
    /// disconnected between enabling capture and verifying it leaves capture on
    /// with nothing having checked it — the exact state the post-start rollback
    /// exists to prevent, reached by a path the rollback cannot see.
    let probationSeconds: TimeInterval
    /// Consecutive failed probes tolerated before capture stands aside.
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

    private(set) var confirmed = false
    private(set) var consecutiveFailures = 0
    private(set) var paused = false
    private(set) var pauseReason: String?
    private var armedAt: Date?
    private var asleep = false
    private var ignoreProbesUntil: Date?

    init(
        probationSeconds: TimeInterval = 45,
        failuresBeforePause: Int = 3,
        wakeGraceSeconds: TimeInterval = 20
    ) {
        self.probationSeconds = probationSeconds
        self.failuresBeforePause = failuresBeforePause
        self.wakeGraceSeconds = wakeGraceSeconds
    }

    /// True while the provider should hand flows straight back to the host.
    var shouldDeclineFlows: Bool { paused }

    /// Capture has just been enabled and its probation window starts now.
    mutating func arm(at now: Date) {
        armedAt = now
        confirmed = false
        consecutiveFailures = 0
        paused = false
        pauseReason = nil
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
    }

    /// The system woke. Give the network time to come back before believing any
    /// probe again, and forget the failures that led into the sleep.
    mutating func systemDidWake(at now: Date) {
        asleep = false
        consecutiveFailures = 0
        ignoreProbesUntil = now.addingTimeInterval(wakeGraceSeconds)
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
        at now: Date
    ) -> Decision {
        guard !ignoringProbes(at: now) else { return .unchanged }
        guard pathSatisfied else { return .unchanged }
        if succeeded {
            confirmed = true
            consecutiveFailures = 0
            guard paused else { return .unchanged }
            // The upstream carries DNS again, so the reason for standing aside
            // is gone. One success is enough: capture resuming cannot strand
            // the host the way capture starting can, because this same loop is
            // still watching and can stand aside again on the next probe.
            paused = false
            pauseReason = nil
            return .resume
        }
        guard !paused else { return .unchanged }
        consecutiveFailures += 1
        if !confirmed {
            // Still unconfirmed: probation, not the failure budget, bounds
            // this. A failing probe here is expected while the provider
            // settles, and the probation window is what ends it.
            guard expired(at: now) else { return .unchanged }
            return pause("capture never resolved a name within its probation window")
        }
        guard consecutiveFailures >= failuresBeforePause else { return .unchanged }
        return pause(
            "name resolution failed \(consecutiveFailures) times in a row through the upstream: \(detail)")
    }

    /// Called on a timer with no probe result, to end probation on its own. A
    /// launcher that dies before confirming leaves nothing else to notice.
    mutating func probationDecision(at now: Date) -> Decision {
        guard !ignoringProbes(at: now), !paused, !confirmed, expired(at: now) else { return .unchanged }
        return pause("capture was never confirmed to resolve names within its probation window")
    }

    private mutating func pause(_ reason: String) -> Decision {
        paused = true
        pauseReason = reason
        return .pause(reason)
    }

    private func expired(at now: Date) -> Bool {
        guard let armedAt else { return false }
        return now.timeIntervalSince(armedAt) >= probationSeconds
    }
}
