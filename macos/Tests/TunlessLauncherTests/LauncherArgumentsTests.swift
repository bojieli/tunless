import XCTest
@testable import TunlessLauncher

final class LauncherArgumentsTests: XCTestCase {
    func testClashVergePresetUsesCompanionDefaults() throws {
        let parsed = try LauncherArguments(
            arguments: ["Tunless", "start", "--preset", "clash-verge"],
            environment: [:])

        XCTAssertEqual(parsed.action, .start)
        XCTAssertEqual(parsed.preset, .clashVerge)
        XCTAssertEqual(parsed.configuration?.upstreamAddress, "127.0.0.1:7897")
        XCTAssertEqual(
            parsed.configuration?.excludeProcesses,
            ["verge-mihomo", "io.github.clash-verge-rev.*"])
    }

    func testExplicitUpstreamAndExclusionsExtendPreset() throws {
        let parsed = try LauncherArguments(
            arguments: [
                "Tunless", "check", "--preset=clash-verge",
                "--upstream", "127.0.0.1:9000",
                "--exclude-process", "com.example.helper",
                "--exclude-process", "verge-mihomo",
            ],
            environment: [:])

        XCTAssertEqual(parsed.action, .check)
        XCTAssertEqual(parsed.configuration?.upstreamAddress, "127.0.0.1:9000")
        XCTAssertEqual(
            parsed.configuration?.excludeProcesses,
            ["verge-mihomo", "io.github.clash-verge-rev.*", "com.example.helper"])
    }

    func testLegacyActionsRemainSupported() throws {
        XCTAssertEqual(
            try LauncherArguments(arguments: ["Tunless", "--stop"], environment: [:]).action,
            .stop)
        XCTAssertEqual(
            try LauncherArguments(arguments: ["Tunless", "--telemetry"], environment: [:]).action,
            .telemetry)
        XCTAssertEqual(
            try LauncherArguments(arguments: ["Tunless", "--cleanup"], environment: [:]).action,
            .cleanup)
    }

    func testCleanupDoesNotConstructCaptureConfiguration() throws {
        let parsed = try LauncherArguments(
            arguments: ["Tunless", "cleanup"],
            environment: ["TUNLESS_UPSTREAM": "not-a-valid-upstream"])

        XCTAssertEqual(parsed.action, .cleanup)
        XCTAssertNil(parsed.configuration)
    }

    func testUnknownPresetIsActionable() {
        XCTAssertThrowsError(
            try LauncherArguments(
                arguments: ["Tunless", "start", "--preset", "unknown"],
                environment: [:])) { error in
            XCTAssertEqual(error as? LauncherArgumentError, .unknownPreset("unknown"))
            XCTAssertTrue(error.localizedDescription.contains("clash-verge"))
        }
    }

    func testUnknownOptionsAreRejected() {
        XCTAssertThrowsError(
            try LauncherArguments(arguments: ["Tunless", "--mystery"], environment: [:])) { error in
            XCTAssertEqual(error as? LauncherArgumentError, .unknownOption("--mystery"))
        }
    }

    func testEnvironmentConfigurationStillWorks() throws {
        let parsed = try LauncherArguments(
            arguments: ["Tunless", "start", "--preset", "clash-verge"],
            environment: [
                "TUNLESS_UPSTREAM": "127.0.0.1:8080",
                "TUNLESS_DISABLE_DNS_OVERRIDE": "true",
                "TUNLESS_EXCLUDE_PROCESS": "com.example.one,com.example.two",
            ])

        XCTAssertEqual(parsed.configuration?.upstreamAddress, "127.0.0.1:8080")
        XCTAssertNil(parsed.configuration?.dnsHost)
        XCTAssertEqual(
            parsed.configuration?.excludeProcesses,
            [
                "verge-mihomo", "io.github.clash-verge-rev.*",
                "com.example.one", "com.example.two",
            ])
    }
}

extension LauncherArgumentsTests {
    func testSkipVerifyDefaultsToOff() throws {
        let arguments = try LauncherArguments(
            arguments: ["Tunless", "start"], environment: [:])
        XCTAssertFalse(arguments.skipVerify)
    }

    func testSkipVerifyFlagIsParsed() throws {
        let arguments = try LauncherArguments(
            arguments: ["Tunless", "start", "--skip-verify"], environment: [:])
        XCTAssertTrue(arguments.skipVerify)
    }

    func testSkipVerifyAcceptsAssignmentForm() throws {
        let arguments = try LauncherArguments(
            arguments: ["Tunless", "start", "--skip-verify=false"], environment: [:])
        XCTAssertFalse(arguments.skipVerify)
    }

    func testSkipVerifyReadsEnvironment() throws {
        let arguments = try LauncherArguments(
            arguments: ["Tunless", "start"],
            environment: ["TUNLESS_SKIP_VERIFY": "yes"])
        XCTAssertTrue(arguments.skipVerify)
    }

    func testSkipVerifyRejectsNonBooleanEnvironment() {
        XCTAssertThrowsError(try LauncherArguments(
            arguments: ["Tunless", "start"],
            environment: ["TUNLESS_SKIP_VERIFY": "maybe"]))
    }

    func testSkipVerifyIsAvailableToNonStartActions() throws {
        // Parsed before the start/check early return, so it never crashes on
        // commands that carry no configuration.
        let arguments = try LauncherArguments(
            arguments: ["Tunless", "status", "--skip-verify"], environment: [:])
        XCTAssertTrue(arguments.skipVerify)
        XCTAssertNil(arguments.configuration)
    }

    /// Safety that has to be typed is safety that gets forgotten, and the
    /// destinations below are the ones whose capture takes the LAN, the local
    /// resolver, or the upstream's own fake-IP answers off the host.
    func testSafeDestinationExclusionsApplyWithoutBeingAskedFor() throws {
        let parsed = try LauncherArguments(
            arguments: ["Tunless", "start", "--upstream", "127.0.0.1:7897"],
            environment: [:])

        XCTAssertTrue(parsed.usesDefaultExclusions)
        let excluded = parsed.configuration?.excludeDestinations ?? []
        for prefix in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7", "198.18.0.0/15"] {
            XCTAssertTrue(excluded.contains(prefix), "\(prefix) should be excluded by default")
        }
    }

    func testAnExplicitIncludeWinsOverTheDefaultExclusion() throws {
        let parsed = try LauncherArguments(
            arguments: [
                "Tunless", "start", "--upstream", "127.0.0.1:7897",
                "--include-destination", "10.0.0.0/8",
            ],
            environment: [:])

        XCTAssertEqual(parsed.configuration?.includeDestinations, ["10.0.0.0/8"])
        XCTAssertFalse(parsed.configuration?.excludeDestinations?.contains("10.0.0.0/8") ?? false)
        XCTAssertTrue(parsed.configuration?.excludeDestinations?.contains("192.168.0.0/16") ?? false)
    }

    func testDefaultExclusionsCanBeTurnedOff() throws {
        let parsed = try LauncherArguments(
            arguments: ["Tunless", "start", "--upstream", "127.0.0.1:7897", "--no-default-exclusions"],
            environment: [:])

        XCTAssertFalse(parsed.usesDefaultExclusions)
        XCTAssertNil(parsed.configuration?.excludeDestinations)

        let fromEnvironment = try LauncherArguments(
            arguments: ["Tunless", "start", "--upstream", "127.0.0.1:7897"],
            environment: ["TUNLESS_NO_DEFAULT_EXCLUSIONS": "true"])
        XCTAssertFalse(fromEnvironment.usesDefaultExclusions)
    }

    func testHealthWatchdogIsOnUnlessExplicitlyDisabled() throws {
        XCTAssertNil(
            try LauncherArguments(
                arguments: ["Tunless", "start", "--upstream", "127.0.0.1:7897"],
                environment: [:]).configuration?.disableHealthWatchdog)
        XCTAssertEqual(
            try LauncherArguments(
                arguments: ["Tunless", "start", "--upstream", "127.0.0.1:7897", "--no-health-watchdog"],
                environment: [:]).configuration?.disableHealthWatchdog,
            true)
        XCTAssertEqual(
            try LauncherArguments(
                arguments: ["Tunless", "start", "--upstream", "127.0.0.1:7897"],
                environment: ["TUNLESS_NO_HEALTH_WATCHDOG": "yes"]).configuration?.disableHealthWatchdog,
            true)
    }

}
