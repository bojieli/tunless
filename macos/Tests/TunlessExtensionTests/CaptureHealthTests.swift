import XCTest
@testable import TunlessExtension

final class CaptureHealthTests: XCTestCase {
    private let start = Date(timeIntervalSince1970: 1_700_000_000)

    func testUnconfirmedCaptureIsReleasedWhenProbationExpires() {
        var health = CaptureHealth(probationSeconds: 45, failuresBeforeRelease: 3)
        health.arm(at: start)
        XCTAssertEqual(health.probationDecision(at: start.addingTimeInterval(30)), .keep)
        guard case let .release(reason) = health.probationDecision(at: start.addingTimeInterval(45)) else {
            return XCTFail("probation must end on its own when nothing confirms it")
        }
        XCTAssertTrue(reason.contains("probation"))
    }

    func testConfirmationEndsProbation() {
        var health = CaptureHealth(probationSeconds: 45, failuresBeforeRelease: 3)
        health.arm(at: start)
        health.confirm()
        XCTAssertEqual(health.probationDecision(at: start.addingTimeInterval(600)), .keep)
    }

    func testConfirmedCaptureIsReleasedAfterConsecutiveFailures() {
        var health = CaptureHealth(probationSeconds: 45, failuresBeforeRelease: 3)
        health.arm(at: start)
        health.confirm()
        XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: true, at: start), .keep)
        XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: true, at: start), .keep)
        guard case let .release(reason) = health.observe(succeeded: false, pathSatisfied: true, at: start) else {
            return XCTFail("sustained resolution failure must give the network back")
        }
        XCTAssertTrue(reason.contains("3 times"))
    }

    func testASuccessfulProbeForgivesEarlierFailures() {
        var health = CaptureHealth(probationSeconds: 45, failuresBeforeRelease: 3)
        health.arm(at: start)
        health.confirm()
        _ = health.observe(succeeded: false, pathSatisfied: true, at: start)
        _ = health.observe(succeeded: false, pathSatisfied: true, at: start)
        XCTAssertEqual(health.observe(succeeded: true, pathSatisfied: true, at: start), .keep)
        XCTAssertEqual(health.consecutiveFailures, 0)
        XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: true, at: start), .keep)
    }

    /// An offline host fails every probe. Releasing capture there would add a
    /// manual restart to an outage capture did not cause, so link state gates
    /// the decision.
    func testAnOfflineHostDoesNotLoseCapture() {
        var health = CaptureHealth(probationSeconds: 45, failuresBeforeRelease: 2)
        health.arm(at: start)
        health.confirm()
        for _ in 0..<10 {
            XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: false, at: start), .keep)
        }
        XCTAssertEqual(health.consecutiveFailures, 0)
    }

    /// A probe that succeeds before the launcher reports in is itself proof,
    /// so a launcher killed mid-verification does not cost the host capture.
    func testASuccessfulProbeConfirmsWithoutTheLauncher() {
        var health = CaptureHealth(probationSeconds: 45, failuresBeforeRelease: 3)
        health.arm(at: start)
        XCTAssertEqual(health.observe(succeeded: true, pathSatisfied: true, at: start.addingTimeInterval(30)), .keep)
        XCTAssertEqual(health.probationDecision(at: start.addingTimeInterval(600)), .keep)
    }

    func testProbesDuringProbationAreBoundedByProbationRatherThanTheFailureBudget() {
        var health = CaptureHealth(probationSeconds: 45, failuresBeforeRelease: 2)
        health.arm(at: start)
        XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: true, at: start.addingTimeInterval(10)), .keep)
        XCTAssertEqual(health.observe(succeeded: false, pathSatisfied: true, at: start.addingTimeInterval(20)), .keep)
        guard case .release = health.observe(succeeded: false, pathSatisfied: true, at: start.addingTimeInterval(50)) else {
            return XCTFail("an unconfirmed capture must not outlive its probation window")
        }
    }

    func testControlMessageIsDistinguishableFromConfigurationAndTelemetry() {
        XCTAssertEqual(ControlMessage.decode(ControlMessage.confirmHealthy.encoded), .confirmHealthy)
        XCTAssertNil(ControlMessage.decode(Data()))
        XCTAssertNil(ControlMessage.decode(Data("{}".utf8)))
        XCTAssertNil(ControlMessage.decode(Data([0xfe])))
    }
}
