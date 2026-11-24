import XCTest
@testable import TunlessExtension

/// The provider reserves a small set of destinations that capture must never
/// claim. These are the paths whose loss is what turns a misconfiguration into
/// an unreachable host, so they are checked here against configurations that
/// deliberately try to capture everything.
final class ReservedDestinationTests: XCTestCase {
    private let captureEverything = ProviderConfiguration(
        upstreamHost: "127.0.0.1",
        upstreamPort: 7897,
        dnsHost: "1.1.1.1",
        dnsPort: 53,
        includeDestinations: ["0.0.0.0/0", "::/0"])

    func testAnIncludeEverythingConfigurationStillLeavesTheHostReachable() {
        for host in ["127.0.0.1", "127.0.0.53", "::1", "169.254.1.1", "fe80::1", "224.0.0.251", "255.255.255.255", "0.0.0.0"] {
            XCTAssertFalse(
                captureEverything.captures(host: host, port: 443, signingIdentifier: "com.example.app"),
                "\(host) must never be captured")
        }
        XCTAssertTrue(captureEverything.captures(host: "93.184.216.34", port: 443, signingIdentifier: "com.example.app"))
    }

    func testTrafficAimedAtTheUpstreamIsNeverHandedBackToIt() {
        let remote = ProviderConfiguration(upstreamHost: "192.0.2.10", upstreamPort: 1080)
        XCTAssertFalse(remote.captures(host: "192.0.2.10", port: 1080, signingIdentifier: "com.example.app"))
        XCTAssertFalse(remote.captures(host: "192.0.2.10", port: 443, signingIdentifier: "com.example.app"))
        XCTAssertTrue(remote.captures(host: "192.0.2.11", port: 443, signingIdentifier: "com.example.app"))
    }

    /// The loop this exists to prevent: the provider rewrites a captured
    /// port-53 flow to the trusted resolver and relays it to the upstream. The
    /// upstream then dials that resolver itself. Capturing *that* flow hands
    /// the query back to the upstream that is waiting on it, and every lookup
    /// on the host recurses instead of resolving.
    func testTheUpstreamCanReachTheResolverItWasAskedToQuery() {
        XCTAssertFalse(captureEverything.captures(host: "1.1.1.1", port: 53, signingIdentifier: "verge-mihomo"))
        // Only the resolver endpoint is reserved; the same host on another
        // port is ordinary traffic and stays captured.
        XCTAssertTrue(captureEverything.captures(host: "1.1.1.1", port: 443, signingIdentifier: "com.example.app"))
        // With the override off, nothing rewrites port 53 and there is no
        // resolver of ours for the upstream to be answering.
        let noOverride = ProviderConfiguration(
            upstreamHost: "127.0.0.1", upstreamPort: 7897, includeDestinations: ["0.0.0.0/0"])
        XCTAssertTrue(noOverride.captures(host: "1.1.1.1", port: 53, signingIdentifier: "com.example.app"))
    }

    func testReservationDoesNotDependOnTheOperatorNamingTheUpstreamProcess() {
        // The same protection as `--exclude-process verge-mihomo`, without
        // requiring the operator to know which process to name.
        let noProcessExclusions = ProviderConfiguration(
            upstreamHost: "127.0.0.1", upstreamPort: 7897, dnsHost: "9.9.9.9", dnsPort: 53)
        XCTAssertFalse(noProcessExclusions.captures(host: "9.9.9.9", port: 53, signingIdentifier: "sing-box"))
        XCTAssertFalse(noProcessExclusions.captures(host: "127.0.0.1", port: 7897, signingIdentifier: "anything"))
    }

    func testIPv6ResolverAndUpstreamMatchAcrossSpelling() {
        let ipv6 = ProviderConfiguration(
            upstreamHost: "2001:db8::1", upstreamPort: 1080, dnsHost: "2606:4700:4700::1111", dnsPort: 53)
        XCTAssertFalse(ipv6.captures(host: "2001:0db8:0000::1", port: 1080, signingIdentifier: "com.example.app"))
        XCTAssertFalse(ipv6.captures(host: "2606:4700:4700:0::1111", port: 53, signingIdentifier: "com.example.app"))
    }
}

/// The provider had no equivalent of the portable core's flow ceiling, so one
/// application opening flows faster than the upstream retires them could push
/// the extension into the CPU budget macOS terminates it for — turning a noisy
/// process into a capture outage for the whole host.
final class FlowCeilingTests: XCTestCase {
    func testCeilingDefaultsToThePortableCoreValue() {
        XCTAssertEqual(ProviderConfiguration(upstreamHost: "127.0.0.1", upstreamPort: 7897).flowCeiling, 4096)
        XCTAssertEqual(
            ProviderConfiguration(upstreamHost: "127.0.0.1", upstreamPort: 7897, maxConcurrentFlows: 64).flowCeiling,
            64)
    }

    func testAnUnusableCeilingIsRejectedRatherThanSilentlyIgnored() {
        XCTAssertThrowsError(
            try ProviderConfiguration(upstreamHost: "127.0.0.1", upstreamPort: 7897, maxConcurrentFlows: 0).validated())
        XCTAssertNoThrow(
            try ProviderConfiguration(upstreamHost: "127.0.0.1", upstreamPort: 7897, maxConcurrentFlows: 1).validated())
    }

    func testHealthReportSurfacesRejectionsSoAFloodIsVisible() {
        let report = CaptureHealthReport(
            capturing: true, pauseReason: nil, confirmed: true, consecutiveFailures: 0,
            activeFlows: 4096, rejectedFlows: 128)
        XCTAssertEqual(report.summary, "capturing, 4096 active, 128 refused at the ceiling")
        let quiet = CaptureHealthReport(
            capturing: true, pauseReason: nil, confirmed: true, consecutiveFailures: 0,
            activeFlows: 7, rejectedFlows: 0)
        XCTAssertEqual(quiet.summary, "capturing, 7 active")
    }
}

/// A signing identifier is not an identity. Binaries built without a bundle —
/// every Homebrew tool, most Go and Rust programs — report the linker default,
/// so the local xray on the dogfood host arrives as `a.out` alongside any
/// number of unrelated programs.
final class ProcessIdentityTests: XCTestCase {
    func testAnExecutablePathSelectsOneProgramWhereTheIdentifierCannot() {
        let config = ProviderConfiguration(
            upstreamHost: "127.0.0.1", upstreamPort: 7897,
            excludeProcesses: ["/opt/homebrew/*/xray"])
        XCTAssertFalse(config.captures(
            host: "203.0.113.1", port: 443, signingIdentifier: "a.out",
            executablePath: "/opt/homebrew/Cellar/xray/25.6.8/libexec/xray"))
        // A different program sharing the same toolchain default is untouched.
        XCTAssertTrue(config.captures(
            host: "203.0.113.1", port: 443, signingIdentifier: "a.out",
            executablePath: "/opt/homebrew/bin/some-other-tool"))
    }

    func testTheBasenameAlsoMatches() {
        let config = ProviderConfiguration(
            upstreamHost: "127.0.0.1", upstreamPort: 7897, excludeProcesses: ["xray"])
        XCTAssertFalse(config.captures(
            host: "203.0.113.1", port: 443, signingIdentifier: "a.out",
            executablePath: "/opt/homebrew/Cellar/xray/25.6.8/libexec/xray"))
    }

    func testSigningIdentifierMatchingStillWorksAndSurvivesAnUnknownExecutable() {
        let config = ProviderConfiguration(
            upstreamHost: "127.0.0.1", upstreamPort: 7897, excludeProcesses: ["verge-mihomo"])
        XCTAssertFalse(config.captures(
            host: "203.0.113.1", port: 443, signingIdentifier: "verge-mihomo", executablePath: nil))
        XCTAssertFalse(config.captures(
            host: "203.0.113.1", port: 443, signingIdentifier: "verge-mihomo",
            executablePath: "/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo"))
    }

    func testIncludePatternsAcceptEitherIdentity() {
        let config = ProviderConfiguration(
            upstreamHost: "127.0.0.1", upstreamPort: 7897,
            includeProcesses: ["/usr/bin/curl"])
        XCTAssertTrue(config.captures(
            host: "203.0.113.1", port: 443, signingIdentifier: "com.apple.curl",
            executablePath: "/usr/bin/curl"))
        XCTAssertFalse(config.captures(
            host: "203.0.113.1", port: 443, signingIdentifier: "com.apple.dig",
            executablePath: "/usr/bin/dig"))
    }
}

/// A reserved destination reached from inside an already-accepted UDP flow used
/// to be dropped. Dropping leaves the sender waiting for an answer that never
/// comes, with nothing anywhere reporting why — so it is delivered directly
/// instead, which is what declining the flow would have produced.
final class DirectDatagramRelayTests: XCTestCase {
    func testAReservedDestinationInsideAnAcceptedFlowIsStillReserved() {
        let config = ProviderConfiguration(
            upstreamHost: "127.0.0.1", upstreamPort: 7897, dnsHost: "1.1.1.1", dnsPort: 53)
        // Admitted on an ordinary destination...
        XCTAssertTrue(config.captures(host: "8.8.8.8", port: 53, signingIdentifier: "com.example.resolver"))
        // ...then addressing the trusted resolver, which must not be relayed
        // back into the upstream that is waiting on it.
        XCTAssertTrue(config.reservedDestination(host: "1.1.1.1", port: 53))
        XCTAssertFalse(config.reservedDestination(host: "8.8.8.8", port: 53))
    }

    func testCancellingTheRelayRefusesFurtherSends() async {
        let relay = DirectDatagramRelay(sink: RecordingSink())
        // Cancelling releases everything and refuses further sends, so a torn
        // down flow cannot leave sockets behind.
        await relay.cancelAll()
        let sent = await relay.send(
            Data([1]), to: SOCKSAddress(host: "127.0.0.1", port: 30_000))
        XCTAssertFalse(sent)
        let count = await relay.activeDestinationCount
        XCTAssertEqual(count, 0)
    }

    func testAPathChangePurgesTheWholeDestinationPoolBeforeApplyingItsCap() async throws {
        let epoch = NetworkEpoch()
        let relay = DirectDatagramRelay(
            sink: RecordingSink(), networkEpoch: epoch, sendTimeoutSeconds: 1)

        // Every destination is a loopback socket this test binds on an
        // ephemeral port. Fixed, unused ports used to stand in for peers, but
        // each send to one draws an ICMP port-unreachable onto a connected UDP
        // socket that Network.framework never reports: the connection stays
        // ready and keeps the error pending. Every NWConnection and NWListener
        // in the process is serviced by one shared framework queue, and
        // depending on the macOS release those refused sockets either make it
        // spin or measurably slow it. Neither has anything to do with the pool
        // rules checked here, and a real peer also lets the test confirm that
        // each datagram arrived.
        let firstPath = try (0..<16).map { _ in try LoopbackUDPSink() }
        let secondPath = try LoopbackUDPSink()
        defer {
            firstPath.forEach { $0.close() }
            secondPath.close()
        }

        // Fill the pool on the first path.
        for (offset, sink) in firstPath.enumerated() {
            let sent = await relay.send(
                Data([UInt8(offset)]),
                to: SOCKSAddress(host: "127.0.0.1", port: sink.port))
            XCTAssertTrue(sent, "failed to prepare destination \(offset)")
        }
        let fullCount = await relay.activeDestinationCount
        XCTAssertEqual(fullCount, 16)
        for (offset, sink) in firstPath.enumerated() {
            XCTAssertEqual(sink.receive(timeout: 5), Data([UInt8(offset)]),
                           "destination \(offset) did not get its datagram")
        }

        _ = epoch.advance()
        let sentOnNewPath = await relay.send(
            Data([0xff]), to: SOCKSAddress(host: "127.0.0.1", port: secondPath.port))
        XCTAssertTrue(sentOnNewPath)
        let rebuiltCount = await relay.activeDestinationCount
        XCTAssertEqual(
            rebuiltCount, 1,
            "stale Wi-Fi sockets must not consume the hotspot destination cap")
        XCTAssertEqual(secondPath.receive(timeout: 5), Data([0xff]))
        await relay.cancelAll()
    }
}

/// A UDP socket bound to an ephemeral loopback port that accepts whatever is
/// sent to it, so a test can address a real peer without picking a fixed port
/// and without provoking ICMP port-unreachable replies.
private final class LoopbackUDPSink {
    struct SocketError: Error {
        let call: String
        let code: Int32
    }

    private var descriptor: Int32
    let port: UInt16

    init() throws {
        let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw SocketError(call: "socket", code: errno) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = in_addr_t(INADDR_LOOPBACK).bigEndian
        address.sin_port = 0
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, length) == 0 && getsockname(fd, $0, &length) == 0
            }
        }
        guard bound else {
            let code = errno
            Darwin.close(fd)
            throw SocketError(call: "bind", code: code)
        }
        descriptor = fd
        port = UInt16(bigEndian: address.sin_port)
    }

    deinit { close() }

    /// The next datagram, or nil if none arrives within `timeout` seconds.
    func receive(timeout: TimeInterval) -> Data? {
        guard descriptor >= 0 else { return nil }
        var poller = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        guard poll(&poller, 1, Int32(timeout * 1000)) == 1 else { return nil }
        var buffer = [UInt8](repeating: 0, count: 2048)
        let count = recv(descriptor, &buffer, buffer.count, 0)
        return count >= 0 ? Data(buffer.prefix(count)) : nil
    }

    func close() {
        guard descriptor >= 0 else { return }
        Darwin.close(descriptor)
        descriptor = -1
    }
}

/// Regression coverage for a live macOS failure: the watchdog error-closed an
/// admitted DNS UDP flow, mDNSResponder kept using its socket, and every later
/// getaddrinfo call waited while the socket's sends failed locally with EINVAL.
final class DatagramFlowContinuityTests: XCTestCase {
    private let config = ProviderConfiguration(
        upstreamHost: "127.0.0.1", upstreamPort: 7897, dnsHost: "1.1.1.1", dnsPort: 53)

    func testDatagramFlowsSurviveAWatchdogPause() {
        XCTAssertTrue(DatagramFlowContinuity.survivesCapturePause)
    }

    func testADegradedFlowDoesNotTurnAnUpstreamFailureIntoADirectRoute() {
        XCTAssertFalse(DatagramFlowContinuity.routesDirect(
            capturePaused: true,
            destination: SOCKSAddress(host: "223.6.6.6", port: 53),
            configuration: config))
        XCTAssertFalse(DatagramFlowContinuity.routesDirect(
            capturePaused: true,
            destination: SOCKSAddress(host: "203.0.113.10", port: 443),
            configuration: config))
    }

    func testAHealthyFlowStillUsesSOCKSUnlessItsDestinationIsReserved() {
        XCTAssertFalse(DatagramFlowContinuity.routesDirect(
            capturePaused: false,
            destination: SOCKSAddress(host: "223.6.6.6", port: 53),
            configuration: config))
        // A datagram to the trusted resolver is relayed now rather than sent
        // direct. Reserving it here was how an application that had configured
        // the same resolver got no override at all, and the loop that
        // reservation existed for is caught by the identifier capture assigns
        // instead — see ResolverLoopGuard.
        XCTAssertFalse(DatagramFlowContinuity.routesDirect(
            capturePaused: false,
            destination: SOCKSAddress(host: "1.1.1.1", port: 53),
            configuration: config))
        // The upstream itself is still reserved on every transport.
        XCTAssertTrue(DatagramFlowContinuity.routesDirect(
            capturePaused: false,
            destination: SOCKSAddress(host: config.upstreamHost, port: config.upstreamPort),
            configuration: config))
    }

    func testLongLivedResolverFlowsDoNotExpireUnderMDNSResponder() {
        XCTAssertEqual(DatagramFlowContinuity.idleTimeoutSeconds(
            for: SOCKSAddress(host: "223.6.6.6", port: 53)), 0)
        XCTAssertEqual(DatagramFlowContinuity.idleTimeoutSeconds(
            for: SOCKSAddress(host: "203.0.113.10", port: 443)), 120)
    }

    func testAnUpstreamFailureDropsAProxyEligibleDatagramInsteadOfSendingItDirect() {
        XCTAssertEqual(
            DatagramFlowContinuity.route(
                capturePaused: true,
                destination: SOCKSAddress(host: "8.8.8.8", port: 53),
                configuration: config,
                upstreamAvailable: false),
            .dropped(reason: "upstream-unavailable"))
    }

    func testOnlyStructuralDestinationsUseTheDirectRoute() {
        XCTAssertEqual(
            DatagramFlowContinuity.route(
                capturePaused: true,
                destination: SOCKSAddress(host: config.upstreamHost, port: config.upstreamPort),
                configuration: config,
                upstreamAvailable: false),
            .direct(reason: "reserved-destination"))
        XCTAssertEqual(
            DatagramFlowContinuity.route(
                capturePaused: false,
                destination: SOCKSAddress(host: "8.8.8.8", port: 53),
                configuration: config,
                upstreamAvailable: true),
            .proxied)
    }

    func testAnUnconnectedFlowReevaluatesEveryDatagramsDestinationScope() {
        let scoped = ProviderConfiguration(
            upstreamHost: "127.0.0.1", upstreamPort: 7897,
            includeDestinations: ["198.51.100.0/24"])
        XCTAssertNil(DatagramFlowContinuity.directReasonForOwnedFlow(
            destination: SOCKSAddress(host: "198.51.100.10", port: 443),
            configuration: scoped,
            signingIdentifier: "com.example.browser"))
        XCTAssertEqual(
            DatagramFlowContinuity.directReasonForOwnedFlow(
                destination: SOCKSAddress(host: "203.0.113.10", port: 443),
                configuration: scoped,
                signingIdentifier: "com.example.browser"),
            "capture-scope-exclusion")
    }

    func testALiveProcessRuleNarrowingAppliesToAnAlreadyOwnedDatagramFlow() {
        let destination = SOCKSAddress(host: "198.51.100.10", port: 443)
        let broad = ProviderConfiguration(upstreamHost: "127.0.0.1", upstreamPort: 7897)
        XCTAssertNil(DatagramFlowContinuity.directReasonForOwnedFlow(
            destination: destination,
            configuration: broad,
            signingIdentifier: "com.example.browser"))

        let narrowed = ProviderConfiguration(
            upstreamHost: "127.0.0.1", upstreamPort: 7897,
            includeProcesses: ["com.example.mail"])
        XCTAssertEqual(
            DatagramFlowContinuity.directReasonForOwnedFlow(
                destination: destination,
                configuration: narrowed,
                signingIdentifier: "com.example.browser"),
            "capture-scope-exclusion")
    }
}

/// A hostname that cannot be carried in a SOCKS5 request is not a reason to
/// fail the connection — the address is always encodable, and reaching the
/// destination on IP rules beats not reaching it at all.
final class UsableHostnameTests: XCTestCase {
    func testOrdinaryNamesAreKept() {
        XCTAssertEqual(SOCKSAddress.usableHostname("github.com"), "github.com")
        XCTAssertEqual(SOCKSAddress.usableHostname("xn--80ak6aa92e.com"), "xn--80ak6aa92e.com")
        XCTAssertEqual(SOCKSAddress.usableHostname(String(repeating: "a", count: 255)),
                       String(repeating: "a", count: 255))
    }

    func testNamesThatCannotBeFramedFallBack() {
        // The domain field carries a single length byte.
        XCTAssertNil(SOCKSAddress.usableHostname(String(repeating: "a", count: 256)))
        // Multi-byte characters count as bytes, not characters.
        XCTAssertNil(SOCKSAddress.usableHostname(String(repeating: "é", count: 200)))
        XCTAssertNil(SOCKSAddress.usableHostname(nil))
        XCTAssertNil(SOCKSAddress.usableHostname(""))
    }

    func testNamesADownstreamProxyWouldMisreadFallBack() {
        XCTAssertNil(SOCKSAddress.usableHostname("exa mple.com"))
        XCTAssertNil(SOCKSAddress.usableHostname("example.com\u{0}extra"))
        XCTAssertNil(SOCKSAddress.usableHostname("example.com\n"))
        XCTAssertNil(SOCKSAddress.usableHostname("example.com\u{7f}"))
    }

    func testAnEncodableNameStillEncodes() throws {
        let encoded = try SOCKSAddress(host: "github.com", port: 443).encoded()
        XCTAssertEqual(encoded.first, 3)
        XCTAssertEqual(Int(encoded[1]), "github.com".utf8.count)
    }
}
