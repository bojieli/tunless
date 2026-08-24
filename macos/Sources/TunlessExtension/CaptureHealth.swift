import Foundation

/// Decides when capture has stopped being safe to keep on.
///
/// Capture is the only thing standing between the host and its previous,
/// working network path, and the failure that matters is not a crash: a crash
/// is already fail-open, because the flows go direct once nothing is capturing
/// them. The dangerous state is a provider that is alive, holding every flow
/// on the host, and relaying them into an upstream that has stopped being able
/// to answer. Name resolution is where that shows up first and worst, and a
/// host that cannot resolve cannot be told how to fix itself.
///
/// The existing checks around `start` prove DNS worked at one instant. This
/// keeps proving it, and gives up capture when it stops being true. It is a
/// plain state machine so the decision can be tested without a network: the
/// provider supplies the clock, the probe, and the path state.
struct CaptureHealth: Equatable {
    /// What the provider should do after an observation.
    enum Decision: Equatable {
        /// Keep capturing.
        case keep
        /// Give capture back to the host, for the stated reason.
        case release(String)
    }

    /// How long capture may run before the first successful confirmation.
    ///
    /// The launcher confirms once it has resolved a name through the live
    /// datapath. Without this, a launcher that is killed, suspended, or
    /// disconnected between enabling capture and verifying it leaves capture
    /// on with nothing having checked it — the exact state the post-start
    /// rollback exists to prevent, reached by a path the rollback cannot see.
    let probationSeconds: TimeInterval
    /// Consecutive failed probes tolerated after confirmation.
    ///
    /// More than one, because a single query can lose a race with a node
    /// switch or a wake-from-sleep, and re-enabling capture is manual. Not
    /// many more, because every probe interval spent failing is an interval
    /// the host spends unable to resolve.
    let failuresBeforeRelease: Int

    private(set) var confirmed = false
    private(set) var consecutiveFailures = 0
    private var armedAt: Date?

    init(probationSeconds: TimeInterval = 45, failuresBeforeRelease: Int = 3) {
        self.probationSeconds = probationSeconds
        self.failuresBeforeRelease = failuresBeforeRelease
    }

    /// Capture has just been enabled and its probation window starts now.
    mutating func arm(at now: Date) {
        armedAt = now
        confirmed = false
        consecutiveFailures = 0
    }

    /// The launcher resolved a name through the live datapath.
    mutating func confirm() {
        confirmed = true
        consecutiveFailures = 0
    }

    /// A health probe finished. `pathSatisfied` is the host's own link state:
    /// when the host has no usable network at all, a failed probe says nothing
    /// about capture, and releasing it would only add a manual restart to an
    /// outage capture did not cause.
    mutating func observe(succeeded: Bool, pathSatisfied: Bool, at now: Date) -> Decision {
        guard pathSatisfied else { return .keep }
        if succeeded {
            confirmed = true
            consecutiveFailures = 0
            return .keep
        }
        consecutiveFailures += 1
        if !confirmed {
            // Still unconfirmed: probation, not the failure budget, is what
            // bounds this. A failing probe here is expected while the provider
            // settles, and `expired` is what ends it.
            return expired(at: now)
                ? .release("capture never resolved a name and its probation expired")
                : .keep
        }
        guard consecutiveFailures >= failuresBeforeRelease else { return .keep }
        return .release(
            "name resolution failed \(consecutiveFailures) times in a row through the upstream")
    }

    /// Called on a timer with no probe result, to end probation on its own.
    /// A launcher that dies before confirming leaves nothing else to notice.
    func probationDecision(at now: Date) -> Decision {
        guard !confirmed, expired(at: now) else { return .keep }
        return .release("capture was never confirmed to resolve names within its probation window")
    }

    private func expired(at now: Date) -> Bool {
        guard let armedAt else { return false }
        return now.timeIntervalSince(armedAt) >= probationSeconds
    }
}
