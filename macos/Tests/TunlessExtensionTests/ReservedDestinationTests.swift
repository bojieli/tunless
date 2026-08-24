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
