import XCTest
@testable import TunlessExtension

final class ConfigRoundTripTests: XCTestCase {
    /// The launcher encodes its configuration and the provider decodes it as
    /// ProviderConfiguration. A key that does not survive that hop silently
    /// leaves the provider on its previous rules.
    func testIncludeProcessesSurvivesTheWireFormat() throws {
        let json = """
        {"upstreamHost":"127.0.0.1","upstreamPort":7897,"dnsHost":"1.1.1.1","dnsPort":53,
         "includeProcesses":["/usr/bin/curl"],
         "excludeProcesses":["verge-mihomo","io.github.clash-verge-rev.*"],
         "expectUDPRelay":true}
        """
        let decoded = try JSONDecoder().decode(ProviderConfiguration.self, from: Data(json.utf8))
        XCTAssertEqual(decoded.includeProcesses, ["/usr/bin/curl"])
        let validated = try decoded.validated()
        XCTAssertEqual(validated.includeProcesses, ["/usr/bin/curl"])
        XCTAssertFalse(validated.captures(
            host: "203.0.113.9", port: 443, signingIdentifier: "a.out",
            executablePath: "/Users/x/.queqiao/bin/queqiaod"),
            "an unlisted process must not be captured when an include list is set")
        XCTAssertTrue(validated.captures(
            host: "203.0.113.9", port: 443, signingIdentifier: "com.apple.curl",
            executablePath: "/usr/bin/curl"))
    }
}
