import XCTest
@testable import TunlessLauncher

final class DNSProbeMessageTests: XCTestCase {
    func testQueryCarriesTransactionIDAndOneQuestion() {
        let query = DNSProbeMessage.query(name: "example.com", transactionID: 0xbeef)
        XCTAssertEqual(query[0], 0xbe)
        XCTAssertEqual(query[1], 0xef)
        XCTAssertEqual(UInt16(query[4]) << 8 | UInt16(query[5]), 1, "one question")
        XCTAssertEqual(UInt16(query[6]) << 8 | UInt16(query[7]), 0, "no answers")
    }

    func testQueryEncodesLabelsAndTerminatesWithRoot() {
        let query = DNSProbeMessage.query(name: "example.com", transactionID: 1)
        let question = query.dropFirst(12)
        // 7 'example' 3 'com' 0, then QTYPE and QCLASS.
        let expected: [UInt8] = [7, 101, 120, 97, 109, 112, 108, 101,
                                 3, 99, 111, 109, 0, 0, 1, 0, 1]
        XCTAssertEqual([UInt8](question), expected)
    }

    func testResponseWithMatchingTransactionIDIsAccepted() {
        var response = Data([0x12, 0x34, 0x81, 0x80])
        response.append(Data(repeating: 0, count: 8))
        XCTAssertTrue(DNSProbeMessage.isResponse(response, transactionID: 0x1234))
    }

    func testResponseWithMismatchedTransactionIDIsRejected() {
        var response = Data([0x99, 0x99, 0x81, 0x80])
        response.append(Data(repeating: 0, count: 8))
        XCTAssertFalse(DNSProbeMessage.isResponse(response, transactionID: 0x1234))
    }

    func testQueryIsNotMistakenForAResponse() {
        // QR bit clear: this is a question, not an answer.
        let query = DNSProbeMessage.query(transactionID: 0x1234)
        XCTAssertFalse(DNSProbeMessage.isResponse(query, transactionID: 0x1234))
    }

    func testServerFailureStillCountsAsAnAnswer() {
        // The probe proves reachability, not that a name exists, so SERVFAIL
        // and NXDOMAIN must both count as a working DNS path.
        for rcode: UInt8 in [2, 3] {
            var response = Data([0x12, 0x34, 0x81, 0x80 | rcode])
            response.append(Data(repeating: 0, count: 8))
            XCTAssertTrue(
                DNSProbeMessage.isResponse(response, transactionID: 0x1234),
                "rcode \(rcode) should still prove the resolver answered")
        }
    }

    func testTruncatedMessageIsRejected() {
        XCTAssertFalse(DNSProbeMessage.isResponse(Data([0x12, 0x34]), transactionID: 0x1234))
        XCTAssertFalse(DNSProbeMessage.isResponse(Data(), transactionID: 0x1234))
    }

    func testTCPFramingRoundTrips() {
        let query = DNSProbeMessage.query(transactionID: 0x1234)
        let framed = DNSProbeMessage.tcpFramed(query)
        XCTAssertEqual(framed.count, query.count + 2)
        XCTAssertEqual(DNSProbeMessage.tcpPayloadLength(framed), query.count)
        XCTAssertTrue(DNSProbeMessage.isResponse(
            Data([0x12, 0x34, 0x80, 0x00]) + Data(repeating: 0, count: 8),
            transactionID: 0x1234))
    }

    func testTCPPayloadLengthNeedsTwoBytes() {
        XCTAssertNil(DNSProbeMessage.tcpPayloadLength(Data([0x01])))
        XCTAssertEqual(DNSProbeMessage.tcpPayloadLength(Data([0x00, 0x2a])), 42)
    }
}
