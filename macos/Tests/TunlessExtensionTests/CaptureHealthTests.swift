import XCTest
@testable import TunlessExtension

final class CaptureHealthTests: XCTestCase {
    private let start = Date(timeIntervalSince1970: 1_700_000_000)

    private func armed(
        probation: TimeInterval = 45,
        failures: Int = 3,
        confirmed: Bool = true
    ) -> CaptureHealth {
        var health = CaptureHealth(probationSeconds: probation, failuresBeforePause: failures)
        health.arm(at: start)
        if confirmed { health.confirm() }
        return health
    }

    private func failUntilPaused(_ health: inout CaptureHealth, at now: Date) -> String? {
        for _ in 0..<health.failuresBeforePause {
            if case let .pause(reason) = health.observe(succeeded: false, pathSatisfied: true, at: now) {
                return reason
            }
        }
        return nil
    }

    // MARK: - Standing aside

    func testCaptureStandsAsideAfterConsecutiveFailures() {
        var health = armed()
        XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: true, at: start), .unchanged)
        XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: true, at: start), .unchanged)
        guard case let .pause(reason) = health.observe(succeeded: false, pathSatisfied: true, at: start) else {
            return XCTFail("sustained resolution failure must hand the network back")
        }
        XCTAssertTrue(reason.contains("3 times"))
        XCTAssertTrue(health.shouldDeclineFlows)
    }

    func testUnconfirmedCaptureIsPausedWhenProbationExpires() {
        var health = armed(confirmed: false)
        XCTAssertEqual(health.probationDecision(at: start.addingTimeInterval(30)), .unchanged)
        guard case let .pause(reason) = health.probationDecision(at: start.addingTimeInterval(45)) else {
            return XCTFail("probation must end on its own when nothing confirms it")
        }
        XCTAssertTrue(reason.contains("probation"))
    }

    func testConfirmationEndsProbation() {
        var health = armed()
        XCTAssertEqual(health.probationDecision(at: start.addingTimeInterval(600)), .unchanged)
    }

    func testASuccessfulProbeConfirmsWithoutTheLauncher() {
        var health = armed(confirmed: false)
        XCTAssertEqual(health.observe(succeeded: true, pathSatisfied: true, at: start.addingTimeInterval(30)), .unchanged)
        XCTAssertEqual(health.probationDecision(at: start.addingTimeInterval(600)), .unchanged)
    }

    // MARK: - Standing back up

    /// The operator asked for capture by running `start`. A minute of upstream
    /// trouble does not withdraw that request, and staying aside afterwards
    /// leaves the host resolving names through whatever the network hands it —
    /// the exposure the DNS override exists to remove.
    func testCaptureResumesOnTheFirstProbeThatSucceedsAgain() {
        var health = armed()
        XCTAssertNotNil(failUntilPaused(&health, at: start))
        XCTAssertTrue(health.shouldDeclineFlows)

        XCTAssertEqual(health.observe(succeeded: true, pathSatisfied: true, at: start.addingTimeInterval(60)), .resume)
        XCTAssertFalse(health.shouldDeclineFlows)
        XCTAssertNil(health.pauseReason)
    }

    func testAPausedCaptureDoesNotPauseAgainOrResumeTwice() {
        var health = armed()
        XCTAssertNotNil(failUntilPaused(&health, at: start))
        for _ in 0..<5 {
            XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: true, at: start), .unchanged)
        }
        XCTAssertEqual(health.observe(succeeded: true, pathSatisfied: true, at: start), .resume)
        XCTAssertEqual(health.observe(succeeded: true, pathSatisfied: true, at: start), .unchanged)
    }

    // MARK: - Sleep

    /// The outage this exists to prevent: a Mac going to sleep tears its
    /// network down, every probe fails, capture stands aside at the moment
    /// nothing is using the network — and the pause outlives the sleep, so the
    /// host wakes with its DNS unprotected and nothing on screen to say so.
    func testSleepDoesNotPauseCapture() {
        var health = armed()
        health.systemWillSleep()
        for i in 0..<10 {
            XCTAssertEqual(
                health.observe(succeeded: false, pathSatisfied: true, at: start.addingTimeInterval(Double(i) * 30)),
                .unchanged)
        }
        XCTAssertFalse(health.shouldDeclineFlows)
        XCTAssertEqual(health.consecutiveFailures, 0)
    }

    func testProbesAreIgnoredForAGracePeriodAfterWake() {
        var health = CaptureHealth(probationSeconds: 45, failuresBeforePause: 3, wakeGraceSeconds: 20)
        health.arm(at: start)
        health.confirm()
        health.systemWillSleep()
        let wake = start.addingTimeInterval(30_000)
        health.systemDidWake(at: wake)

        XCTAssertTrue(health.ignoringProbes(at: wake.addingTimeInterval(5)))
        XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: true, at: wake.addingTimeInterval(5)), .unchanged)
        XCTAssertEqual(health.consecutiveFailures, 0)

        XCTAssertFalse(health.ignoringProbes(at: wake.addingTimeInterval(25)))
        XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: true, at: wake.addingTimeInterval(25)), .unchanged)
        XCTAssertEqual(health.consecutiveFailures, 1)
    }

    func testFailuresLeadingIntoSleepAreForgottenOnWake() {
        var health = armed(failures: 3)
        _ = health.observe(succeeded: false, pathSatisfied: true, at: start)
        _ = health.observe(succeeded: false, pathSatisfied: true, at: start)
        XCTAssertEqual(health.consecutiveFailures, 2)
        health.systemWillSleep()
        let wake = start.addingTimeInterval(30_000)
        health.systemDidWake(at: wake)
        // Without this, two pre-sleep failures plus one post-wake failure would
        // pause capture on a host whose upstream never actually failed.
        XCTAssertEqual(
            health.observe(succeeded: false, pathSatisfied: true, at: wake.addingTimeInterval(25)),
            .unchanged)
        XCTAssertFalse(health.shouldDeclineFlows)
    }

    func testProbationDecisionIsAlsoSuspendedAcrossSleep() {
        var health = armed(confirmed: false)
        health.systemWillSleep()
        XCTAssertEqual(health.probationDecision(at: start.addingTimeInterval(600)), .unchanged)
    }

    // MARK: - Link state

    func testAnOfflineHostDoesNotLoseCapture() {
        var health = armed(failures: 2)
        for _ in 0..<10 {
            XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: false, at: start), .unchanged)
        }
        XCTAssertEqual(health.consecutiveFailures, 0)
        XCTAssertFalse(health.shouldDeclineFlows)
    }

    func testASuccessfulProbeForgivesEarlierFailures() {
        var health = armed()
        _ = health.observe(succeeded: false, pathSatisfied: true, at: start)
        _ = health.observe(succeeded: false, pathSatisfied: true, at: start)
        XCTAssertEqual(health.observe(succeeded: true, pathSatisfied: true, at: start), .unchanged)
        XCTAssertEqual(health.consecutiveFailures, 0)
        XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: true, at: start), .unchanged)
    }

    // MARK: - Control protocol

    func testControlMessageIsDistinguishableFromConfigurationAndTelemetry() {
        XCTAssertEqual(ControlMessage.decode(ControlMessage.confirmHealthy.encoded), .confirmHealthy)
        XCTAssertEqual(ControlMessage.decode(ControlMessage.queryHealth.encoded), .queryHealth)
        XCTAssertNil(ControlMessage.decode(Data()))
        XCTAssertNil(ControlMessage.decode(Data("{}".utf8)))
        XCTAssertNil(ControlMessage.decode(Data([0xfe])))
    }

    func testHealthReportSaysWhyCaptureIsNotClaimingFlows() {
        let paused = CaptureHealthReport(
            capturing: false, pauseReason: "upstream stopped resolving", confirmed: true, consecutiveFailures: 3)
        XCTAssertEqual(paused.summary, "paused: upstream stopped resolving")
        XCTAssertEqual(
            CaptureHealthReport(capturing: true, pauseReason: nil, confirmed: true, consecutiveFailures: 0).summary,
            "capturing")
        XCTAssertEqual(
            CaptureHealthReport(capturing: true, pauseReason: nil, confirmed: false, consecutiveFailures: 0).summary,
            "capturing (unconfirmed)")
    }

    // MARK: - What counts as a failure

    /// The blind spot this closes, hit live: an upstream that relays DNS over
    /// TCP while refusing UDP ASSOCIATE looks perfectly healthy to a TCP-only
    /// probe, and is not — nearly every resolver client uses UDP, so captured
    /// lookups get nothing back while the watchdog reports capturing.
    func testUDPLossCountsAsAFailureWhenTheUpstreamOfferedUDP() {
        let lostUDP = DNSProbeOutcome(tcp: true, udp: false)
        XCTAssertFalse(lostUDP.healthy)
        XCTAssertTrue(lostUDP.detail.contains("UDP"))

        var health = armed()
        for _ in 0..<2 {
            XCTAssertEqual(
                health.observe(succeeded: lostUDP.healthy, detail: lostUDP.detail, pathSatisfied: true, at: start),
                .unchanged)
        }
        guard case let .pause(reason) = health.observe(
            succeeded: lostUDP.healthy, detail: lostUDP.detail, pathSatisfied: true, at: start) else {
            return XCTFail("losing the transport applications resolve over must stand capture aside")
        }
        XCTAssertTrue(reason.contains("UDP"), "the reason must name the transport that broke: \(reason)")
    }

    /// An upstream that never offered UDP is a degraded state the operator was
    /// warned about at start. Treating it as a failure would stand capture
    /// aside forever on a host where DNS works over TCP.
    func testAnUpstreamThatNeverOfferedUDPStaysHealthy() {
        XCTAssertTrue(DNSProbeOutcome(tcp: true, udp: nil).healthy)
        XCTAssertEqual(DNSProbeOutcome(tcp: true, udp: nil).detail, "answered")
    }

    func testLosingTCPIsAFailureWhicheverWayUDPWent() {
        XCTAssertFalse(DNSProbeOutcome(tcp: false, udp: true).healthy)
        XCTAssertFalse(DNSProbeOutcome(tcp: false, udp: nil).healthy)
        XCTAssertEqual(DNSProbeOutcome(tcp: false, udp: true).detail, "no answer over TCP")
    }

    func testBothTransportsAnsweringIsHealthy() {
        XCTAssertTrue(DNSProbeOutcome(tcp: true, udp: true).healthy)
    }

}

/// What the watchdog probes when the operator turned the DNS override off.
///
/// The flag preserves each application's resolver; it does not stop capture
/// relaying the query. So the upstream can still take resolution down
/// host-wide, and a watchdog that treats "no override" as "nothing of ours can
/// fail" is not watching the failure it exists for.
final class HealthProbeTargetTests: XCTestCase {
    private let upstream = ProviderConfiguration(upstreamHost: "127.0.0.1", upstreamPort: 7897)
    private let carried = DNSHealthProbe.CarriedResolver(
        address: SOCKSAddress(host: "223.6.6.6", port: 53), overUDP: true)

    func testConfiguredOverrideIsProbedAsBefore() {
        var configuration = upstream
        configuration.dnsHost = "1.1.1.1"
        configuration.dnsPort = 53
        configuration.expectUDPRelay = true
        let target = DNSHealthProbe.target(configuration: configuration, carried: carried)
        XCTAssertEqual(target?.resolver, SOCKSAddress(host: "1.1.1.1", port: 53))
        XCTAssertEqual(target?.probeUDP, true)
    }

    func testAnOverrideThatNeverRelayedUDPIsNotProbedOverUDP() {
        var configuration = upstream
        configuration.dnsHost = "1.1.1.1"
        configuration.dnsPort = 53
        configuration.expectUDPRelay = false
        XCTAssertEqual(
            DNSHealthProbe.target(configuration: configuration, carried: carried)?.probeUDP,
            false)
    }

    func testWithoutAnOverrideTheResolverCaptureCarriesIsProbed() {
        let target = DNSHealthProbe.target(configuration: upstream, carried: carried)
        XCTAssertEqual(target?.resolver, SOCKSAddress(host: "223.6.6.6", port: 53))
        XCTAssertEqual(
            target?.probeUDP, true,
            "a host resolving over UDP through capture is exactly what a broken UDP relay breaks")
    }

    func testATCPOnlyResolverIsNotProbedOverUDP() {
        let overTCP = DNSHealthProbe.CarriedResolver(
            address: SOCKSAddress(host: "223.6.6.6", port: 53), overUDP: false)
        XCTAssertEqual(
            DNSHealthProbe.target(configuration: upstream, carried: overTCP)?.probeUDP,
            false)
    }

    func testNothingIsProbedUntilCaptureHasCarriedAResolver() {
        XCTAssertNil(
            DNSHealthProbe.target(configuration: upstream, carried: nil),
            "capture that has carried no port-53 flow is claiming nothing that could be false")
    }
}
