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

    func testCollidingIdentifiersAreReferenceCountedAcrossFlows() {
        let guardian = guarded()
        XCTAssertTrue(guardian.register(0x1234))
        XCTAssertTrue(guardian.register(0x1234))
        XCTAssertEqual(guardian.count(), 2)

        guardian.release(0x1234)
        XCTAssertTrue(
            guardian.isRelaying(0x1234),
            "one flow completing must not release a colliding flow's guard")
        XCTAssertEqual(guardian.count(), 1)
        guardian.release(0x1234)
        XCTAssertFalse(guardian.isRelaying(0x1234))
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
        XCTAssertFalse(guardian.register(3))
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

/// The datagram path has to ask the reservation question the way it means it.
///
/// Both of these were live defects that unit tests passed straight through: the
/// flow was claimed, telemetry said so, and the answers still came from whatever
/// the network wanted to say.
final class ResolverDatagramPathTests: XCTestCase {
    private let installed = ProviderConfiguration(
        upstreamHost: "127.0.0.1", upstreamPort: 7897, dnsHost: "1.1.1.1", dnsPort: 53)

    func testTheDatagramPathDoesNotReserveTheTrustedResolver() {
        // routesDirect is the datagram path by construction. Asking without
        // isDatagram gets the answer for a stream, which sends every datagram on
        // an already-claimed flow straight back out.
        XCTAssertFalse(
            DatagramFlowContinuity.routesDirect(
                capturePaused: false,
                destination: SOCKSAddress(host: "1.1.1.1", port: 53),
                configuration: installed))
        // The upstream is still reserved on the datagram path.
        XCTAssertTrue(
            DatagramFlowContinuity.routesDirect(
                capturePaused: false,
                destination: SOCKSAddress(host: "127.0.0.1", port: 7897),
                configuration: installed))
        // Upstream degradation never changes an otherwise proxied destination
        // into a direct one.
        XCTAssertFalse(
            DatagramFlowContinuity.routesDirect(
                capturePaused: true,
                destination: SOCKSAddress(host: "203.0.113.1", port: 443),
                configuration: installed))
    }

    func testAQueryToTheResolverItselfStillGetsAnIdentifierToRecogniseItBy() async {
        // Rewritten to itself, nothing distinguishes this datagram from the one
        // the upstream forwards — so the guard has nothing to recognise unless an
        // identifier is assigned anyway.
        let guardian = ResolverLoopGuard()
        let map = DNSResponseMap(maxEntries: 16, ttlSeconds: 30, loopGuard: guardian)
        let resolver = SOCKSAddress(host: "1.1.1.1", port: 53)
        var query = Data([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        query.append(contentsOf: DNSWire.question("www.google.com"))

        let unpoliced = await map.prepare(query: query, original: resolver, routed: resolver)
        XCTAssertEqual(unpoliced, query, "an unpoliced identical route should be left alone")
        XCTAssertFalse(guardian.isRelayedQuery(unpoliced))

        let policed = await map.prepare(
            query: query, original: resolver, routed: resolver, policed: true)
        XCTAssertNotEqual(policed.prefix(2), query.prefix(2), "no identifier was assigned")
        XCTAssertTrue(
            guardian.isRelayedQuery(policed),
            "the upstream's forwarded copy would not be recognised")

        // The reply still maps back to the application's own identifier.
        let restored = await map.restore(response: policed, receivedFrom: resolver)
        XCTAssertTrue(restored.matched)
        XCTAssertEqual(restored.payload.prefix(2), query.prefix(2))
        XCTAssertEqual(restored.source, resolver)
        XCTAssertFalse(guardian.isRelayedQuery(policed), "a finished exchange stayed in flight")
    }
}
