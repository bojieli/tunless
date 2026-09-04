import Foundation
import Network
import XCTest

@testable import TunlessExtension

/// Builds a query the way a stub resolver would.
func dnsQuery(id: UInt16 = 0x1234, name: String, type: UInt16 = DNSMessage.typeA) -> Data {
    var message = Data([UInt8(id >> 8), UInt8(id & 0xff), 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
    for label in name.split(separator: ".") {
        message.append(UInt8(label.utf8.count))
        message.append(contentsOf: Array(label.utf8))
    }
    message.append(0)
    message.append(contentsOf: [UInt8(type >> 8), UInt8(type & 0xff), 0x00, 0x01])
    return message
}

/// Builds a reply to `query` carrying the given addresses.
func dnsReply(to query: Data, addresses: [String] = [], rcode: UInt8 = 0) -> Data {
    var message = query
    message[message.startIndex + 2] = 0x81
    message[message.startIndex + 3] = 0x80 | rcode
    let count = UInt16(addresses.count)
    message[message.startIndex + 6] = UInt8(count >> 8)
    message[message.startIndex + 7] = UInt8(count & 0xff)
    for address in addresses {
        // A compression pointer back to the question's name.
        message.append(contentsOf: [0xc0, 0x0c])
        if let v4 = IPv4Address(address) {
            message.append(contentsOf: [0x00, 0x01, 0x00, 0x01, 0, 0, 0x01, 0x2c, 0x00, 0x04])
            message.append(v4.rawValue)
        } else if let v6 = IPv6Address(address) {
            message.append(contentsOf: [0x00, 0x1c, 0x00, 0x01, 0, 0, 0x01, 0x2c, 0x00, 0x10])
            message.append(v6.rawValue)
        }
    }
    return message
}

final class DNSSuffixSetTests: XCTestCase {
    func testTheLongestSuffixDecidesRatherThanTheOrderListsLoaded() {
        // An operator who sends a zone down the direct path and carves one name
        // out of it back to the tunnel has said something precise.
        let set = DNSSuffixSet(direct: ["example.com"], trusted: ["secret.example.com"])
        XCTAssertEqual(set.match("www.example.com")?.route, .direct)
        XCTAssertEqual(set.match("example.com")?.route, .direct)
        XCTAssertEqual(set.match("secret.example.com")?.route, .trusted)
        XCTAssertEqual(set.match("deep.secret.example.com")?.route, .trusted)
        XCTAssertEqual(set.match("secret.example.com")?.suffix, "secret.example.com")
    }

    func testSuffixesMatchOnLabelBoundaries() {
        let set = DNSSuffixSet(direct: ["example.com"], trusted: [])
        XCTAssertNil(set.match("notexample.com"))
        XCTAssertNil(set.match("example.com.evil.net"))
        XCTAssertNil(set.match("com"))
    }

    func testADuplicateSuffixResolvesTowardTheTunnel() {
        // The direct list is the one an operator downloads with thousands of
        // entries in it; the trusted list is the one they write by hand.
        let set = DNSSuffixSet(direct: ["example.com"], trusted: ["example.com"])
        XCTAssertEqual(set.match("example.com")?.route, .trusted)
    }

    func testMatchingIgnoresCaseAndTheRootLabel() {
        let set = DNSSuffixSet(direct: ["Example.COM."], trusted: [])
        XCTAssertEqual(set.match("WWW.EXAMPLE.COM")?.route, .direct)
        XCTAssertEqual(set.match("www.example.com.")?.route, .direct)
    }

    func testInteriorLabelsAreNotEntries() {
        // Adding a.b.c creates nodes for c and b.c. Treating one as an entry
        // would route a whole public suffix on the strength of one name below it.
        let set = DNSSuffixSet(direct: ["a.b.c"], trusted: [])
        XCTAssertNil(set.match("c"))
        XCTAssertNil(set.match("b.c"))
        XCTAssertNotNil(set.match("x.a.b.c"))
    }
}

final class DNSPrefixSetTests: XCTestCase {
    func testTheSetCoversTheAddressesItWasGiven() {
        let set = DNSPrefixSet(prefixes: ["10.0.0.0/8", "203.0.113.0/24", "2001:db8::/32"])
        for address in ["10.0.0.1", "10.255.255.255", "203.0.113.7", "2001:db8::1"] {
            XCTAssertTrue(set.contains(Self.raw(address)), "\(address) should be inside")
        }
        for address in ["11.0.0.1", "203.0.114.1", "203.0.112.255", "2001:db9::1"] {
            XCTAssertFalse(set.contains(Self.raw(address)), "\(address) should be outside")
        }
    }

    func testBoundariesAreIncluded() {
        // An off-by-one at a range edge misroutes exactly one network out of
        // thousands, which is the defect least likely to be noticed.
        let set = DNSPrefixSet(prefixes: ["192.0.2.0/24"])
        XCTAssertTrue(set.contains(Self.raw("192.0.2.0")))
        XCTAssertTrue(set.contains(Self.raw("192.0.2.255")))
        XCTAssertFalse(set.contains(Self.raw("192.0.1.255")))
        XCTAssertFalse(set.contains(Self.raw("192.0.3.0")))
    }

    func testAdjacentPrefixesCollapseAndGapsSurvive() {
        let merged = DNSPrefixSet(prefixes: ["10.0.0.0/24", "10.0.1.0/24"])
        XCTAssertEqual(merged.count, 1)
        let gapped = DNSPrefixSet(prefixes: ["10.0.0.0/24", "10.9.0.0/24", "10.5.0.0/24"])
        XCTAssertEqual(gapped.count, 3)
        XCTAssertTrue(gapped.contains(Self.raw("10.5.0.1")))
        XCTAssertFalse(gapped.contains(Self.raw("10.4.255.255")))
        XCTAssertFalse(gapped.contains(Self.raw("10.6.0.0")))
    }

    func testMappedAddressesAreJudgedAsTheAddressTheyCarry() {
        let set = DNSPrefixSet(prefixes: ["203.0.113.0/24"])
        XCTAssertTrue(set.contains(Self.raw("::ffff:203.0.113.7")))
        XCTAssertFalse(set.contains(Self.raw("2001:db8::1")))
    }

    func testTheTopOfTheAddressSpaceDoesNotOverflow() {
        // The last address of a family has no successor, and the merge asks for
        // one when it tests adjacency.
        let set = DNSPrefixSet(prefixes: ["0.0.0.0/0", "255.255.255.255/32"])
        XCTAssertTrue(set.contains(Self.raw("255.255.255.255")))
    }

    func testInvalidEntriesAreRejected() {
        for entry in ["", "nonsense", "10.0.0.0/33", "2001:db8::/129", "10.0.0.0/-1"] {
            XCTAssertFalse(DNSPrefixSet.isValidPrefix(entry), "\(entry) should be rejected")
        }
        XCTAssertTrue(DNSPrefixSet.isValidPrefix("203.0.113.7"))
        XCTAssertTrue(DNSPrefixSet.isValidPrefix("10.0.0.0/8"))
    }

    func testAnEmptySetContainsNothing() {
        XCTAssertTrue(DNSPrefixSet().isEmpty)
        XCTAssertFalse(DNSPrefixSet().contains(Self.raw("10.0.0.1")))
    }

    private static func raw(_ address: String) -> Data {
        IPv4Address(address)?.rawValue ?? IPv6Address(address)!.rawValue
    }
}

final class DNSPolicyDecisionTests: XCTestCase {
    private func policy() -> DNSPolicy {
        var policy = DNSPolicy()
        policy.suffixes = DNSSuffixSet(direct: ["example.com"], trusted: ["secret.example.com"])
        policy.prefixes = DNSPrefixSet(prefixes: ["203.0.113.0/24"])
        policy.directResolver = SOCKSAddress(host: "223.5.5.5", port: 53)
        return policy
    }

    func testTheDefaultPolicySendsEverythingToTheTrustedResolver() {
        // The zero value has to be the behaviour the datapath had before any of
        // this existed, or upgrading moves traffic without anyone asking.
        let decision = DNSPolicy().decide(dnsQuery(name: "www.example.com"))
        XCTAssertEqual(decision.route, .trusted)
        XCTAssertFalse(DNSPolicy().adjudicates)
    }

    func testLocalNamesOutrankEveryList() {
        var configured = policy()
        configured.localDomains = ["corp.example.com"]
        for name in ["printer.local", "nas.lan", "wiki.corp.example.com"] {
            XCTAssertEqual(configured.decide(dnsQuery(name: name)).route, .local, name)
        }
    }

    func testTheNameListsDecideBeforeTheAddressSet() {
        let configured = policy()
        XCTAssertEqual(configured.decide(dnsQuery(name: "www.example.com")).route, .direct)
        XCTAssertEqual(configured.decide(dnsQuery(name: "secret.example.com")).route, .trusted)
        XCTAssertEqual(configured.decide(dnsQuery(name: "unlisted.example.net")).route, .adjudicate)
    }

    func testOnlyAddressQuestionsAreAdjudicated() {
        // HTTPS and SVCB carry the encrypted-client-hello configuration, and a
        // browser asks for them on every navigation. Serving one from the direct
        // path would be this project inflicting a downgrade rather than
        // preventing one.
        let configured = policy()
        XCTAssertEqual(configured.decide(dnsQuery(name: "a.example.net", type: 28)).route, .adjudicate)
        for type: UInt16 in [65, 64, 15, 16, 33, 12, 2] {
            let decision = configured.decide(dnsQuery(name: "a.example.net", type: type))
            XCTAssertEqual(decision.route, .trusted, "type \(type)")
            XCTAssertEqual(decision.reason, .notAddressQuery, "type \(type)")
        }
    }

    func testAnUnreadableQueryGoesToTheTrustedResolver() {
        let configured = policy()
        for message in [Data(), Data(repeating: 0, count: 11), Data(repeating: 0, count: 12)] {
            let decision = configured.decide(message)
            XCTAssertEqual(decision.route, .trusted)
            XCTAssertEqual(decision.reason, .unreadableQuery)
        }
    }

    func testNameListsWorkWithoutADirectResolver() {
        // The deterministic half without the heuristic half: these go to the
        // resolver the application already chose.
        var lists = DNSPolicy()
        lists.suffixes = DNSSuffixSet(direct: ["example.com"], trusted: [])
        XCTAssertEqual(lists.decide(dnsQuery(name: "www.example.com")).route, .direct)
        XCTAssertNil(lists.directResolver)
        XCTAssertFalse(lists.adjudicates)
    }

    func testAdjudicationNeedsBothADirectResolverAndASet() {
        var resolverOnly = DNSPolicy()
        resolverOnly.directResolver = SOCKSAddress(host: "223.5.5.5", port: 53)
        XCTAssertFalse(resolverOnly.adjudicates)
        var setOnly = DNSPolicy()
        setOnly.prefixes = DNSPrefixSet(prefixes: ["203.0.113.0/24"])
        XCTAssertFalse(setOnly.adjudicates)
    }
}

final class DNSAdjudicationTests: XCTestCase {
    private func policy() -> DNSPolicy {
        var policy = DNSPolicy()
        policy.prefixes = DNSPrefixSet(prefixes: ["203.0.113.0/24"])
        policy.directResolver = SOCKSAddress(host: "223.5.5.5", port: 53)
        return policy
    }

    func testADirectAnswerInsideTheSetIsServedImmediately() {
        // Nothing the trusted resolver could say would change this, so nothing
        // waits for it. That is where the availability property comes from.
        let query = dnsQuery(name: "www.example.net")
        var exchange = DNSExchange()
        exchange.direct = dnsReply(to: query, addresses: ["203.0.113.7"])
        let (verdict, reason) = policy().adjudicate(exchange)
        XCTAssertEqual(verdict, .serveDirect)
        XCTAssertEqual(reason, .directInSet)
    }

    func testOneAddressInsideTheSetIsEnough() {
        // A content network routinely answers with a mixed set.
        let query = dnsQuery(name: "www.example.net")
        var exchange = DNSExchange()
        exchange.direct = dnsReply(to: query, addresses: ["198.51.100.1", "203.0.113.7"])
        XCTAssertEqual(policy().adjudicate(exchange).verdict, .serveDirect)
    }

    func testTheOutcomeDoesNotDependOnWhichReplyArrivesFirst() {
        // A policy whose result depends on timing cannot be reasoned about.
        let query = dnsQuery(name: "www.example.net")
        var exchange = DNSExchange()
        exchange.trusted = dnsReply(to: query, addresses: ["192.0.2.9"])
        exchange.trustedDone = true
        XCTAssertEqual(policy().adjudicate(exchange).verdict, .wait)

        exchange.direct = dnsReply(to: query, addresses: ["203.0.113.7"])
        exchange.directDone = true
        XCTAssertEqual(policy().adjudicate(exchange).verdict, .serveDirect)
    }

    func testAnAnswerOutsideTheSetLosesToTheTrustedResolver() {
        let query = dnsQuery(name: "www.example.net")
        var exchange = DNSExchange()
        exchange.direct = dnsReply(to: query, addresses: ["198.51.100.1"])
        exchange.directDone = true
        exchange.trusted = dnsReply(to: query, addresses: ["192.0.2.9"])
        exchange.trustedDone = true
        let (verdict, reason) = policy().adjudicate(exchange)
        XCTAssertEqual(verdict, .serveTrusted)
        XCTAssertEqual(reason, .directOutOfSet)
    }

    func testASuspectAnswerIsRefusedRatherThanServed() {
        let query = dnsQuery(name: "www.example.net")
        var exchange = DNSExchange()
        exchange.direct = dnsReply(to: query, addresses: ["198.51.100.1"])
        exchange.directDone = true
        exchange.trustedDone = true
        let (verdict, reason) = policy().adjudicate(exchange)
        XCTAssertEqual(verdict, .refuse)
        XCTAssertEqual(reason, .suspectAnswerRefused)
    }

    func testAnAnswerWithNoAddressIsServedOnceTheTrustedHalfHasFailed() {
        // Every AAAA lookup for a v4-only host returns no address. Treating that
        // as suspect would put a tunnel round trip in front of half of every
        // dual-stack application's lookups and fail them while the tunnel is
        // down. There is no address in it to misroute a connection to.
        let query = dnsQuery(name: "www.example.net")
        for reply in [dnsReply(to: query), dnsReply(to: query, rcode: 3)] {
            var exchange = DNSExchange()
            exchange.direct = reply
            exchange.directDone = true
            exchange.trustedDone = true
            let (verdict, reason) = policy().adjudicate(exchange)
            XCTAssertEqual(verdict, .serveDirect)
            XCTAssertEqual(reason, .directNoAnswer)
        }
    }

    func testAForgedDenialStillLosesWhileTheTunnelIsUp() {
        // The concession above is bounded to the case where nothing else can
        // answer. This is the censorship technique the whole path exists for.
        let query = dnsQuery(name: "www.example.net")
        var exchange = DNSExchange()
        exchange.direct = dnsReply(to: query, rcode: 3)
        exchange.directDone = true
        exchange.trusted = dnsReply(to: query, addresses: ["192.0.2.9"])
        exchange.trustedDone = true
        XCTAssertEqual(policy().adjudicate(exchange).verdict, .serveTrusted)
    }

    func testAResolverReportingFailureIsNotAnAnswerToPrefer() {
        let query = dnsQuery(name: "www.example.net")
        for rcode: UInt8 in [2, 5, 1] {
            var exchange = DNSExchange()
            exchange.direct = dnsReply(to: query, addresses: ["198.51.100.1"])
            exchange.directDone = true
            exchange.trusted = dnsReply(to: query, rcode: rcode)
            exchange.trustedDone = true
            XCTAssertEqual(policy().adjudicate(exchange).verdict, .refuse, "rcode \(rcode)")
        }
    }

    func testNothingArrivingIsDroppedRatherThanAnswered() {
        var exchange = DNSExchange()
        exchange.directDone = true
        exchange.trustedDone = true
        let (verdict, reason) = policy().adjudicate(exchange)
        XCTAssertEqual(verdict, .drop)
        XCTAssertEqual(reason, .noReply)
    }

    func testRefusalEchoesTheQuestionAndNothingElse() {
        let query = dnsQuery(id: 0xabcd, name: "www.example.net")
        guard let refusal = DNSPolicy.refusal(for: query) else {
            return XCTFail("refusal returned nothing for a well-formed query")
        }
        XCTAssertEqual(refusal[refusal.startIndex], 0xab)
        XCTAssertEqual(refusal[refusal.startIndex + 1], 0xcd)
        XCTAssertEqual(refusal[refusal.startIndex + 2] & 0x80, 0x80)
        XCTAssertEqual(refusal[refusal.startIndex + 3] & 0x0f, 2)
        let parsed = DNSMessage.parse(refusal)
        XCTAssertEqual(parsed?.questions.count, 1)
        XCTAssertEqual(parsed?.questions.first?.name, "www.example.net")
        XCTAssertEqual(parsed?.answers.count, 0)
    }

    func testRefusalDeclinesAMessageItCannotFrame() {
        XCTAssertNil(DNSPolicy.refusal(for: Data()))
        XCTAssertNil(DNSPolicy.refusal(for: Data(repeating: 0, count: 12)))
        // A compression pointer in a question section is malformed, and
        // following one is how a name walker becomes a loop.
        XCTAssertNil(DNSPolicy.refusal(for: Data([0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c])))
    }

    func testOnlyTheAnswerSectionIsBelieved() {
        // Believing an address because of a section the querier did not ask
        // about is how a resolver gets poisoned by a record it never requested.
        let query = dnsQuery(name: "www.example.net")
        var message = query
        message[message.startIndex + 2] = 0x81
        message[message.startIndex + 3] = 0x80
        // One additional record, no answers.
        message[message.startIndex + 10] = 0x00
        message[message.startIndex + 11] = 0x01
        message.append(contentsOf: [0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0, 0, 0x01, 0x2c, 0x00, 0x04])
        message.append(IPv4Address("203.0.113.7")!.rawValue)
        XCTAssertFalse(policy().answersInSet(message))
    }
}

/// A clock the test moves by hand, so a cooldown can elapse without waiting.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Date()

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func advance(by seconds: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        value = value.addingTimeInterval(seconds)
    }
}

final class DirectResolverBreakerTests: XCTestCase {
    func testAResolverThatStopsAnsweringIsTakenOutOfThePath() {
        // Without this, an unreachable direct resolver is a host-wide slowdown:
        // every unlisted name waits the full window for an answer never coming.
        let clock = TestClock()
        let breaker = DirectResolverBreaker(
            failuresBeforeOpen: 3, cooldownSeconds: 30, clock: { clock.now })
        breaker.fail()
        breaker.fail()
        XCTAssertTrue(breaker.allow())
        breaker.fail()
        XCTAssertFalse(breaker.allow())
        XCTAssertTrue(breaker.isOpen)

        // It closes again on its own, so a resolver that comes back is found
        // without a restart.
        clock.advance(by: 31)
        XCTAssertTrue(breaker.allow())
        XCTAssertFalse(breaker.isOpen)
    }

    func testOneSuccessClearsTheAccumulatedFailures() {
        let breaker = DirectResolverBreaker(failuresBeforeOpen: 3)
        breaker.fail()
        breaker.fail()
        breaker.succeed()
        breaker.fail()
        breaker.fail()
        XCTAssertTrue(breaker.allow())
    }
}
