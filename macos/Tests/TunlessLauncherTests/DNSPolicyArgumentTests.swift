import XCTest

@testable import TunlessLauncher

final class DNSPolicyArgumentTests: XCTestCase {
    private func start(_ options: [String], environment: [String: String] = [:]) throws
        -> LauncherArguments
    {
        try LauncherArguments(
            arguments: ["Tunless", "start", "--upstream", "127.0.0.1:7890"] + options,
            environment: environment)
    }

    func testNothingIsConfiguredByDefault() throws {
        // Nobody who does not ask for any of this may have their traffic move.
        let parsed = try start([])
        XCTAssertNil(parsed.configuration?.directDNSHost)
        XCTAssertNil(parsed.configuration?.directPrefixes)
        XCTAssertNil(parsed.configuration?.directDomains)
        XCTAssertNil(parsed.configuration?.trustedDomains)
    }

    func testTheFlagsBuildAPolicy() throws {
        let parsed = try start([
            "--dns-direct", "223.5.5.5:53",
            "--dns-direct-prefix", "203.0.113.0/24",
            "--direct-domain", "example.com",
            "--trusted-domain", "secret.example.com",
        ])
        XCTAssertEqual(parsed.configuration?.directDNSHost, "223.5.5.5")
        XCTAssertEqual(parsed.configuration?.directDNSPort, 53)
        XCTAssertEqual(parsed.configuration?.directPrefixes, ["203.0.113.0/24"])
        XCTAssertEqual(parsed.configuration?.directDomains, ["example.com"])
        XCTAssertEqual(parsed.configuration?.trustedDomains, ["secret.example.com"])
    }

    func testTheEqualsFormWorksToo() throws {
        let parsed = try start([
            "--dns-direct=223.5.5.5:53", "--dns-direct-prefix=203.0.113.0/24",
        ])
        XCTAssertEqual(parsed.configuration?.directDNSHost, "223.5.5.5")
    }

    func testTheEnvironmentConfiguresTheSameThings() throws {
        let parsed = try start([], environment: [
            "TUNLESS_DNS_DIRECT": "223.5.5.5:53",
            "TUNLESS_DNS_DIRECT_PREFIX": "203.0.113.0/24",
            "TUNLESS_DIRECT_DOMAIN": "example.com",
        ])
        XCTAssertEqual(parsed.configuration?.directDNSHost, "223.5.5.5")
        XCTAssertEqual(parsed.configuration?.directPrefixes, ["203.0.113.0/24"])
        XCTAssertEqual(parsed.configuration?.directDomains, ["example.com"])
    }

    func testAnIPv6DirectResolverIsAccepted() throws {
        let parsed = try start([
            "--dns-direct", "[2001:db8::1]:53", "--dns-direct-prefix", "2001:db8::/32",
        ])
        XCTAssertEqual(parsed.configuration?.directDNSHost, "2001:db8::1")
        XCTAssertEqual(parsed.configuration?.directDNSPort, 53)
    }

    func testIncoherentCombinationsAreRefused() {
        // Each of these has a runtime appearance identical to the feature
        // working perfectly and finding nothing to do.
        XCTAssertThrowsError(try start(["--dns-direct", "223.5.5.5:53"])) { error in
            XCTAssertEqual(
                error as? LauncherArgumentError, .directResolverWithoutPrefixes)
        }
        XCTAssertThrowsError(try start(["--dns-direct-prefix", "203.0.113.0/24"])) { error in
            XCTAssertEqual(
                error as? LauncherArgumentError, .prefixesWithoutDirectResolver)
        }
        XCTAssertThrowsError(
            try start([
                "--disable-dns-override", "--dns-direct", "223.5.5.5:53",
                "--dns-direct-prefix", "203.0.113.0/24",
            ])
        ) { error in
            XCTAssertEqual(
                error as? LauncherArgumentError, .directResolverWithoutOverride)
        }
        XCTAssertThrowsError(
            try start(["--dns-direct", "dns.example.com:53", "--dns-direct-prefix", "203.0.113.0/24"])
        )
        XCTAssertThrowsError(
            try start(["--dns-direct", "223.5.5.5:53", "--dns-direct-prefix", "nonsense"])
        ) { error in
            XCTAssertEqual(error as? LauncherArgumentError, .invalidDirectPrefix("nonsense"))
        }
    }

    func testListFilesAreReadByTheLauncher() throws {
        // The launcher reads them rather than handing a path to a sandboxed
        // system extension, so the parse errors land where the operator is.
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let domains = directory.appendingPathComponent("direct.txt")
        try "# generated\n\nfromfile.example\nsecond.example # why\n".write(
            to: domains, atomically: true, encoding: .utf8)
        let prefixes = directory.appendingPathComponent("prefixes.txt")
        try "203.0.113.0/24\n; comment\n2001:db8::/32\n".write(
            to: prefixes, atomically: true, encoding: .utf8)

        let parsed = try start([
            "--dns-direct", "223.5.5.5:53",
            "--direct-domain-file", domains.path,
            "--dns-direct-prefix-file", prefixes.path,
        ])
        XCTAssertEqual(
            parsed.configuration?.directDomains, ["fromfile.example", "second.example"])
        XCTAssertEqual(
            parsed.configuration?.directPrefixes, ["203.0.113.0/24", "2001:db8::/32"])
    }

    func testAMissingListFileStopsStartup() {
        // An empty list and a path that does not exist behave identically at
        // runtime and mean completely different things.
        XCTAssertThrowsError(
            try start(["--direct-domain-file", "/nonexistent/tunless-test-list.txt"])
        ) { error in
            XCTAssertEqual(
                error as? LauncherArgumentError,
                .unreadableList("--direct-domain-file", "/nonexistent/tunless-test-list.txt"))
        }
    }

    func testAMalformedSuffixStopsStartup() {
        // A list is thousands of lines nobody reads. A line that cannot mean
        // anything has to be reported, not skipped.
        XCTAssertThrowsError(try start(["--direct-domain", "a b.com"])) { error in
            XCTAssertEqual(error as? LauncherArgumentError, .invalidDomainSuffix("a b.com"))
        }
        XCTAssertThrowsError(try start(["--trusted-domain", "example..com"]))
        XCTAssertThrowsError(try start(["--direct-domain", ""]))
    }

    func testSuffixValidationAcceptsWhatGeneratedListsCarry() {
        XCTAssertTrue(LauncherArguments.validDomainSuffix("example.com"))
        XCTAssertTrue(LauncherArguments.validDomainSuffix("example.com."))
        XCTAssertTrue(LauncherArguments.validDomainSuffix("  Example.COM  "))
        XCTAssertFalse(LauncherArguments.validDomainSuffix(""))
        XCTAssertFalse(LauncherArguments.validDomainSuffix("a b.com"))
        XCTAssertFalse(LauncherArguments.validDomainSuffix(".example.com"))
        XCTAssertFalse(LauncherArguments.validDomainSuffix("example..com"))
    }

    func testPrefixValidationAcceptsBareAddressesAndRejectsNonsense() {
        XCTAssertTrue(LauncherArguments.validDirectPrefix("203.0.113.7"))
        XCTAssertTrue(LauncherArguments.validDirectPrefix("10.0.0.0/8"))
        XCTAssertTrue(LauncherArguments.validDirectPrefix("2001:db8::/32"))
        XCTAssertFalse(LauncherArguments.validDirectPrefix("10.0.0.0/33"))
        XCTAssertFalse(LauncherArguments.validDirectPrefix("2001:db8::/129"))
        XCTAssertFalse(LauncherArguments.validDirectPrefix("nonsense"))
        XCTAssertFalse(LauncherArguments.validDirectPrefix(""))
    }
}
