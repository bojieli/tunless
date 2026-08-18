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
