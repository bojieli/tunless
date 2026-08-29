import XCTest

@testable import TunlessExtension

/// Whether the DNS override can see the queries it exists for.
///
/// The failure these guard against is silent. A home network hands out the
/// router as the resolver, the router is inside `192.168.0.0/16`, that range is
/// excluded from capture by default so nobody accidentally proxies their own
/// LAN, and the override is then structurally unable to reach the one flow it
/// was configured for. Nothing errors: queries go out on the network's own
/// path, come back with whatever that path chose to answer, and every name on
/// the host resolves to it.
final class DNSCaptureRulesTests: XCTestCase {
    /// The shape a macOS install actually has: a Clash Verge upstream on
    /// loopback, a trusted resolver, and the default private-range exclusions.
    private let installed = ProviderConfiguration(
        upstreamHost: "127.0.0.1",
        upstreamPort: 7897,
        dnsHost: "1.1.1.1",
        dnsPort: 53,
        excludeProcesses: ["verge-mihomo"],
        excludeDestinations: [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
            "100.64.0.0/10", "198.18.0.0/15",
        ])

    func testAResolverInsideAnExcludedRangeIsStillCapturedForDNS() {
        // Datagrams, because that is the transport the override acts on: a
        // query carries its question in the first packet, so a name only the
        // local network can answer is recognised before the route is chosen.
        // The stream case is covered in ResolverCaptureRulesTests.
        for resolver in ["192.168.3.1", "10.0.0.1", "100.64.0.1", "198.18.0.1"] {
            XCTAssertTrue(
                installed.captures(
                    host: resolver, port: 53, signingIdentifier: "com.apple.curl",
                    isDatagram: true),
                "\(resolver):53 must be captured so the override can rewrite it")
        }
    }

    func testTheExemptionDoesNotLeakToOtherPorts() {
        // Excluding private space is about not putting a proxy in front of the
        // LAN, and that reason is untouched by anything here.
        for port: UInt16 in [80, 443, 22, 5353] {
            XCTAssertFalse(
                installed.captures(host: "192.168.3.1", port: port, signingIdentifier: "com.apple.curl"),
                "192.168.3.1:\(port) must stay excluded")
        }
    }

    func testWithoutATrustedResolverTheOperatorsExclusionIsTheOnlyInstruction() {
        // Nothing to rewrite the query to means nothing to gain by claiming it.
        let noOverride = ProviderConfiguration(
            upstreamHost: "127.0.0.1",
            upstreamPort: 7897,
            excludeDestinations: ["192.168.0.0/16"])
        XCTAssertFalse(
            noOverride.captures(host: "192.168.3.1", port: 53, signingIdentifier: "com.apple.curl"))
    }

    func testAnAddressAllowlistDoesNotNarrowDNS() {
        let allowlist = ProviderConfiguration(
            upstreamHost: "127.0.0.1",
            upstreamPort: 7897,
            dnsHost: "1.1.1.1",
            dnsPort: 53,
            includeDestinations: ["203.0.113.0/24"])
        XCTAssertTrue(
            allowlist.captures(
                host: "192.168.3.1", port: 53, signingIdentifier: "com.apple.curl",
                isDatagram: true))
        XCTAssertFalse(
            allowlist.captures(host: "192.168.3.1", port: 443, signingIdentifier: "com.apple.curl"))
    }

    func testARouterAdvertisedLinkLocalResolverIsCaptured() {
        // Link-local is reserved because it carries DHCP, mDNS and router
        // discovery — none of which is on port 53. A router advertising itself
        // as the resolver over IPv6 does so at a link-local address, which makes
        // it exactly the resolver the override exists to replace.
        XCTAssertTrue(
            installed.captures(
                host: "fe80::1", port: 53, signingIdentifier: "com.apple.curl", isDatagram: true))
        XCTAssertTrue(
            installed.captures(
                host: "169.254.1.1", port: 53, signingIdentifier: "com.apple.curl",
                isDatagram: true))
        XCTAssertFalse(installed.captures(host: "fe80::1", port: 443, signingIdentifier: "com.apple.curl"))
    }

    func testTheDatapathIsStillReservedOnPortFiftyThree() {
        // Handing the upstream's own query back to the upstream is the loop
        // that takes DNS down host-wide, so the exemption must not reach it.
        // The trusted resolver is reachable on datagrams now, policed by the
        // loop guard rather than by address; see ResolverCaptureRulesTests. The
        // upstream and the unroutable set stay reserved on every transport.
        XCTAssertFalse(
            installed.captures(
                host: "1.1.1.1", port: 53, signingIdentifier: "com.apple.curl", isDatagram: false))
        for isDatagram in [true, false] {
            XCTAssertFalse(
                installed.captures(
                    host: "127.0.0.1", port: 53, signingIdentifier: "com.apple.curl",
                    isDatagram: isDatagram))
            for unroutable in ["0.0.0.0", "224.0.0.251", "255.255.255.255", "::1", "ff02::1"] {
                XCTAssertFalse(
                    installed.captures(
                        host: unroutable, port: 53, signingIdentifier: "com.apple.curl",
                        isDatagram: isDatagram),
                    "\(unroutable):53 must never be captured")
            }
        }
    }

    func testAnExcludedProcessKeepsItsOwnDNS() {
        // Naming the upstream process is the other half of the loop protection,
        // and a port-53 flow from the upstream is exactly the flow it is for.
        XCTAssertFalse(
            installed.captures(
                host: "192.168.3.1", port: 53, signingIdentifier: "verge-mihomo",
                executablePath: "/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo",
                isDatagram: true))
        XCTAssertTrue(
            installed.captures(
                host: "192.168.3.1", port: 53, signingIdentifier: "com.apple.curl",
                isDatagram: true))
    }
}
