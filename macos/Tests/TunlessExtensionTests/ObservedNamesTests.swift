import XCTest

@testable import TunlessExtension

/// The address-to-name map that gives a flow back the hostname its application
/// never told the kernel about.
///
/// Every test here is really about one property: an association is recorded
/// only when the answer proves it, and a flow whose address has no unambiguous
/// name keeps its address. That is what separates this from the fake-IP scheme
/// it replaces — a wrong or missing entry costs rule-by-name, never
/// reachability.
final class ObservedNamesTests: XCTestCase {
    private var clock = Date(timeIntervalSince1970: 1_000_000)

    private func names(maxRecords: Int = 65536) -> ObservedNames {
        ObservedNames(maxRecords: maxRecords, now: { [self] in clock })
    }

    func testAnAnsweredQueryNamesTheAddressItReturned() {
        let observed = names()
        observed.observe(
            query: DNSWire.query(["www.google.com"]),
            reply: DNSWire.reply(
                questions: ["www.google.com"],
                answers: [DNSWire.aRecord("www.google.com", [142, 251, 151, 119])]))
        XCTAssertEqual(observed.lookup(host: "142.251.151.119"), "www.google.com")
        XCTAssertNil(observed.lookup(host: "203.0.113.1"))
    }

    func testAnIPv6AnswerIsFoundByEitherSpellingOfItsAddress() {
        let observed = names()
        let address: [UInt8] = [
            0x24, 0x04, 0x68, 0x00, 0x40, 0x08, 0x0c, 0x05,
            0, 0, 0, 0, 0, 0, 0, 0x66,
        ]
        observed.observe(
            query: DNSWire.query(["www.google.com"], type: 28),
            reply: DNSWire.reply(
                questions: ["www.google.com"], type: 28,
                answers: [DNSWire.aaaaRecord("www.google.com", address)]))
        XCTAssertEqual(observed.lookup(host: "2404:6800:4008:c05::66"), "www.google.com")
        XCTAssertEqual(observed.lookup(host: "2404:6800:4008:C05:0:0:0:66"), "www.google.com")
    }

    func testAnIPv4MappedFlowFindsAnIPv4Answer() {
        let observed = names()
        observed.observe(
            query: DNSWire.query(["www.google.com"]),
            reply: DNSWire.reply(
                questions: ["www.google.com"],
                answers: [DNSWire.aRecord("www.google.com", [142, 251, 151, 119])]))
        XCTAssertEqual(observed.lookup(host: "::ffff:142.251.151.119"), "www.google.com")
    }

    func testACNAMEChainAttributesTheAddressToTheNameThatWasAsked() {
        let observed = names()
        observed.observe(
            query: DNSWire.query(["www.example.com"]),
            reply: DNSWire.reply(
                questions: ["www.example.com"],
                answers: [
                    DNSWire.cnameRecord("www.example.com", "edge.cdn.net"),
                    DNSWire.aRecord("edge.cdn.net", [203, 0, 113, 5]),
                ]))
        // The name the application asked for is the one the proxy's rules are
        // written about, not the CDN's internal name.
        XCTAssertEqual(observed.lookup(host: "203.0.113.5"), "www.example.com")
    }

    func testRecordsForNamesNobodyAskedAboutAreIgnored() {
        let observed = names()
        observed.observe(
            query: DNSWire.query(["www.google.com"]),
            reply: DNSWire.reply(
                questions: ["www.google.com"],
                answers: [
                    DNSWire.aRecord("www.google.com", [142, 251, 151, 119]),
                    // Not reachable from the question, directly or by alias.
                    DNSWire.aRecord("unrelated.example", [203, 0, 113, 9]),
                ]))
        XCTAssertEqual(observed.lookup(host: "142.251.151.119"), "www.google.com")
        XCTAssertNil(observed.lookup(host: "203.0.113.9"))
    }

    func testAnAddressClaimedByTwoNamesIsTreatedAsUnknown() {
        let observed = names()
        for name in ["first.example.com", "second.example.com"] {
            observed.observe(
                query: DNSWire.query([name]),
                reply: DNSWire.reply(
                    questions: [name], answers: [DNSWire.aRecord(name, [203, 0, 113, 7])]))
        }
        // Shared hosting and CDNs make this ordinary, and the address alone
        // cannot say which name this flow is for. Guessing would route somebody
        // under somebody else's rules.
        XCTAssertNil(observed.lookup(host: "203.0.113.7"))
    }

    func testAnAssociationExpiresWithTheTTLThatCarriedIt() {
        let observed = names()
        observed.observe(
            query: DNSWire.query(["www.google.com"]),
            reply: DNSWire.reply(
                questions: ["www.google.com"],
                answers: [DNSWire.aRecord("www.google.com", [142, 251, 151, 119], ttl: 60)]))
        clock = clock.addingTimeInterval(59)
        XCTAssertEqual(observed.lookup(host: "142.251.151.119"), "www.google.com")
        clock = clock.addingTimeInterval(2)
        // Expiring costs the name, not the route: the flow still goes out on a
        // real address that still works.
        XCTAssertNil(observed.lookup(host: "142.251.151.119"))
        XCTAssertEqual(observed.count(), 0)
    }

    func testAReplyThatDoesNotAnswerTheQueryTeachesNothing() {
        let observed = names()
        let query = DNSWire.query(id: 0x1234, ["www.google.com"])
        // Right question, wrong transaction: a forged datagram racing the real
        // answer must not be able to name an address.
        observed.observe(
            query: query,
            reply: DNSWire.reply(
                id: 0x9999, questions: ["www.google.com"],
                answers: [DNSWire.aRecord("www.google.com", [31, 13, 92, 37])]))
        // Right transaction, different question.
        observed.observe(
            query: query,
            reply: DNSWire.reply(
                id: 0x1234, questions: ["www.example.com"],
                answers: [DNSWire.aRecord("www.example.com", [31, 13, 92, 38])]))
        // A failure response.
        observed.observe(
            query: query,
            reply: DNSWire.reply(
                id: 0x1234, rcode: 2, questions: ["www.google.com"],
                answers: [DNSWire.aRecord("www.google.com", [31, 13, 92, 39])]))
        XCTAssertEqual(observed.count(), 0)
        XCTAssertNil(observed.lookup(host: "31.13.92.37"))
        XCTAssertNil(observed.lookup(host: "31.13.92.38"))
        XCTAssertNil(observed.lookup(host: "31.13.92.39"))
    }

    func testTheTableIsBounded() {
        let observed = names(maxRecords: 2)
        for index in 0 ..< 8 {
            let name = "host\(index).example.com"
            observed.observe(
                query: DNSWire.query([name]),
                reply: DNSWire.reply(
                    questions: [name],
                    answers: [DNSWire.aRecord(name, [203, 0, 113, UInt8(index)])]))
        }
        XCTAssertLessThanOrEqual(observed.count(), 2)
    }

    func testMalformedMessagesAreIgnoredRatherThanTrusted() {
        let observed = names()
        observed.observe(query: Data([0x12]), reply: Data([0x12]))
        observed.observe(query: Data(), reply: Data())
        observed.observe(
            query: DNSWire.query(["www.google.com"]), reply: Data([0xff, 0xff, 0xff]))
        XCTAssertEqual(observed.count(), 0)
        XCTAssertNil(observed.lookup(host: "not-an-address"))
    }
}
