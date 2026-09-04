import Foundation
import XCTest

@testable import TunlessExtension

final class DNSPolicyConfigurationTests: XCTestCase {
    private func configuration(
        directHost: String? = nil,
        directPort: UInt16? = nil,
        directPrefixes: [String]? = nil,
        directDomains: [String]? = nil,
        trustedDomains: [String]? = nil,
        dnsHost: String? = "1.1.1.1",
        dnsPort: UInt16? = 53
    ) -> ProviderConfiguration {
        ProviderConfiguration(
            upstreamHost: "127.0.0.1", upstreamPort: 1080,
            dnsHost: dnsHost, dnsPort: dnsPort,
            directDNSHost: directHost, directDNSPort: directPort,
            directDomains: directDomains, trustedDomains: trustedDomains,
            directPrefixes: directPrefixes)
    }

    func testTheDefaultConfigurationRoutesEverythingThroughTheTunnel() throws {
        // Nobody who does not ask for any of this may have their traffic move.
        let validated = try configuration().validated()
        let policy = validated.dnsPolicy
        XCTAssertFalse(policy.adjudicates)
        XCTAssertNil(policy.directResolver)
        XCTAssertEqual(policy.decide(dnsQuery(name: "www.example.com")).route, .trusted)
    }

    func testADirectResolverWithNothingToJudgeByIsRefused() {
        // Without addresses to judge by, the direct resolver would be asked on
        // every unlisted name and never believed: the latency of answer-based
        // selection with none of its effect, and nothing reporting a problem.
        XCTAssertThrowsError(
            try configuration(directHost: "223.5.5.5", directPort: 53).validated()
        ) { error in
            XCTAssertEqual(error as? ConfigurationError, .directResolverWithoutPrefixes)
        }
    }

    func testPrefixesWithNoResolverToJudgeAreRefused() {
        XCTAssertThrowsError(
            try configuration(directPrefixes: ["203.0.113.0/24"]).validated()
        ) { error in
            XCTAssertEqual(error as? ConfigurationError, .prefixesWithoutDirectResolver)
        }
    }

    func testAPolicyWithNothingToRouteIsRefused() {
        XCTAssertThrowsError(
            try configuration(
                directHost: "223.5.5.5", directPort: 53,
                directPrefixes: ["203.0.113.0/24"],
                dnsHost: nil, dnsPort: nil
            ).validated()
        ) { error in
            XCTAssertEqual(error as? ConfigurationError, .directResolverWithoutOverride)
        }
    }

    func testAMalformedDirectResolverIsRefused() {
        for (host, port) in [("dns.example.com", UInt16(53)), ("223.5.5.5", UInt16(0))] {
            XCTAssertThrowsError(
                try configuration(
                    directHost: host, directPort: port,
                    directPrefixes: ["203.0.113.0/24"]
                ).validated()
            ) { error in
                XCTAssertEqual(error as? ConfigurationError, .invalidDirectResolver)
            }
        }
        XCTAssertThrowsError(try configuration(directHost: "223.5.5.5").validated())
    }

    func testAMalformedPrefixIsRefused() {
        XCTAssertThrowsError(
            try configuration(
                directHost: "223.5.5.5", directPort: 53,
                directPrefixes: ["nonsense"]
            ).validated()
        )
    }

    func testAFullyConfiguredPolicyRoutesEachLayer() throws {
        let validated = try configuration(
            directHost: "223.5.5.5", directPort: 53,
            directPrefixes: ["203.0.113.0/24"],
            directDomains: ["example.com"],
            trustedDomains: ["secret.example.com"]
        ).validated()
        let policy = validated.dnsPolicy
        XCTAssertTrue(policy.adjudicates)
        XCTAssertEqual(policy.decide(dnsQuery(name: "www.example.com")).route, .direct)
        // The longer suffix wins, so a hand-written exception carves a name out
        // of a downloaded list.
        XCTAssertEqual(policy.decide(dnsQuery(name: "secret.example.com")).route, .trusted)
        XCTAssertEqual(policy.decide(dnsQuery(name: "unlisted.example.net")).route, .adjudicate)
        XCTAssertEqual(policy.directResolver, SOCKSAddress(host: "223.5.5.5", port: 53))
    }

    func testNameListsAreUsableWithoutADirectResolver() throws {
        let validated = try configuration(directDomains: ["example.com"]).validated()
        let policy = validated.dnsPolicy
        XCTAssertFalse(policy.adjudicates)
        XCTAssertEqual(policy.decide(dnsQuery(name: "www.example.com")).route, .direct)
    }

    func testAConfigurationSurvivesTheControlProtocol() throws {
        // It crosses to the extension as JSON, and a field that does not round
        // trip is a policy the provider silently does not have.
        let original = try configuration(
            directHost: "223.5.5.5", directPort: 53,
            directPrefixes: ["203.0.113.0/24"],
            directDomains: ["example.com"],
            trustedDomains: ["secret.example.com"]
        ).validated()
        let encoded = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(ProviderConfiguration.self, from: encoded)
        XCTAssertEqual(decoded, original)
        XCTAssertTrue(decoded.dnsPolicy.adjudicates)
    }
}
