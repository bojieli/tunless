import XCTest

@testable import TunlessExtension

/// Whether an application's own query to the trusted resolver can be captured
/// without the upstream's forwarded copy closing a loop.
///
/// Reserving the resolver by address was the old answer, and it declined both
/// flows for the price of one: `1.1.1.1` is this project's default upstream and
/// one of the most commonly configured resolvers there is, so the people most
/// likely to be protected were the ones who got nothing.
final class ResolverLoopGuardTests: XCTestCase {
    private var clock = Date(timeIntervalSince1970: 1_000_000)

    private func guarded(lifetime: TimeInterval = 60, maxEntries: Int = 8192) -> ResolverLoopGuard {
        ResolverLoopGuard(lifetime: lifetime, maxEntries: maxEntries, now: { [self] in clock })
    }

    func testAQueryInFlightIsRecognisedAndAnUnrelatedOneIsNot() {
        let guardian = guarded()
        guardian.register(0x1234)
        XCTAssertTrue(guardian.isRelaying(0x1234))
        XCTAssertFalse(guardian.isRelaying(0x1235))
        // The payload form reads the identifier from the wire.
        var payload = Data([0x12, 0x34])
        payload.append(Data(repeating: 0, count: 10))
        XCTAssertTrue(guardian.isRelayedQuery(payload))
        XCTAssertFalse(guardian.isRelayedQuery(Data([0x12, 0x34])))  // too short to judge
    }

    func testAnAnsweredExchangeIsNoLongerInFlight() {
        let guardian = guarded()
        guardian.register(0x1234)
        guardian.release(0x1234)
        XCTAssertFalse(guardian.isRelaying(0x1234))
        XCTAssertEqual(guardian.count(), 0)
    }

    func testAnEntryOutlivesItsExchangeOnlyUntilTheLifetime() {
        let guardian = guarded(lifetime: 60)
        guardian.register(0x1234)
        clock = clock.addingTimeInterval(59)
        XCTAssertTrue(guardian.isRelaying(0x1234))
        clock = clock.addingTimeInterval(2)
        XCTAssertFalse(guardian.isRelaying(0x1234))
    }

    func testAFullTableStopsRegisteringRatherThanEvicting() {
        // Dropping an entry to make room would let the query it belonged to
        // close the loop, and a guard that forgets under load forgets exactly
        // when a loop is running.
        let guardian = guarded(maxEntries: 2)
        guardian.register(1)
        guardian.register(2)
        guardian.register(3)
        XCTAssertLessThanOrEqual(guardian.count(), 2)
        XCTAssertTrue(guardian.isRelaying(1))
        XCTAssertTrue(guardian.isRelaying(2))
        XCTAssertFalse(guardian.isRelaying(3))
    }
}

/// The capture rules that decide which port-53 flows the override may see.
final class ResolverCaptureRulesTests: XCTestCase {
    private let installed = ProviderConfiguration(
        upstreamHost: "127.0.0.1",
        upstreamPort: 7897,
        dnsHost: "1.1.1.1",
        dnsPort: 53,
        excludeDestinations: ["192.168.0.0/16"])

    func testAnApplicationsDatagramToTheTrustedResolverIsCaptured() {
        XCTAssertTrue(
            installed.captures(
                host: "1.1.1.1", port: 53, signingIdentifier: "com.apple.curl", isDatagram: true))
    }

    func testAStreamToTheTrustedResolverStaysReserved() {
        // Nothing identifies it at connect time, so the loop guard cannot police
        // it and the address reservation is still the only protection there is.
        XCTAssertFalse(
            installed.captures(
                host: "1.1.1.1", port: 53, signingIdentifier: "com.apple.curl", isDatagram: false))
    }

    func testTheUpstreamIsReservedOnEveryTransport() {
        for isDatagram in [true, false] {
            XCTAssertFalse(
                installed.captures(
                    host: "127.0.0.1", port: 53, signingIdentifier: "com.apple.curl",
                    isDatagram: isDatagram))
        }
    }

    func testAnotherPortOnTheResolversAddressIsNotTheResolver() {
        XCTAssertTrue(
            installed.captures(
                host: "1.1.1.1", port: 443, signingIdentifier: "com.apple.curl", isDatagram: true))
    }

    func testDNSOverTCPToANetworkResolverIsLeftAlone() {
        // The route has to be chosen before the name is visible, so capturing it
        // means committing to the trusted resolver for whatever it turns out to
        // ask — which breaks exactly the names the local resolver exists for.
        for host in ["192.168.3.1", "10.0.0.1", "100.64.0.1", "169.254.1.1", "fe80::1"] {
            XCTAssertFalse(
                installed.captures(
                    host: host, port: 53, signingIdentifier: "com.apple.curl", isDatagram: false),
                "DNS over TCP to \(host) should be left alone")
            XCTAssertTrue(
                installed.captures(
                    host: host, port: 53, signingIdentifier: "com.apple.curl", isDatagram: true),
                "DNS over UDP to \(host) should be captured")
        }
        // A public resolver has no local names to lose.
        XCTAssertTrue(
            installed.captures(
                host: "8.8.8.8", port: 53, signingIdentifier: "com.apple.curl", isDatagram: false))
    }
}
