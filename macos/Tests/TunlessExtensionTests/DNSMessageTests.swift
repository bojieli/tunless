import XCTest

@testable import TunlessExtension

/// Helpers shared by the DNS parsing and name-observation tests.
enum DNSWire {
    static func name(_ value: String) -> [UInt8] {
        var bytes: [UInt8] = []
        for label in value.split(separator: ".") {
            bytes.append(UInt8(label.utf8.count))
            bytes.append(contentsOf: Array(label.utf8))
        }
        bytes.append(0)
        return bytes
    }

    static func header(
        id: UInt16, response: Bool, rcode: UInt8 = 0, questions: Int, answers: Int
    ) -> [UInt8] {
        [
            UInt8(id >> 8), UInt8(id & 0xff),
            response ? 0x81 : 0x01, response ? (0x80 | rcode) : 0x00,
            UInt8(questions >> 8), UInt8(questions & 0xff),
            UInt8(answers >> 8), UInt8(answers & 0xff),
            0, 0, 0, 0,
        ]
    }

    static func question(_ value: String, type: UInt16 = 1) -> [UInt8] {
        name(value) + [UInt8(type >> 8), UInt8(type & 0xff), 0, 1]
    }

    static func query(id: UInt16 = 0x1234, _ names: [String], type: UInt16 = 1) -> Data {
        var bytes = header(id: id, response: false, questions: names.count, answers: 0)
        for value in names { bytes += question(value, type: type) }
        return Data(bytes)
    }

    static func record(
        _ owner: String, type: UInt16, ttl: UInt32, payload: [UInt8]
    ) -> [UInt8] {
        var bytes: [UInt8] = name(owner)
        bytes.append(UInt8(type >> 8))
        bytes.append(UInt8(type & 0xff))
        bytes.append(contentsOf: [0, 1] as [UInt8])
        bytes.append(UInt8((ttl >> 24) & 0xff))
        bytes.append(UInt8((ttl >> 16) & 0xff))
        bytes.append(UInt8((ttl >> 8) & 0xff))
        bytes.append(UInt8(ttl & 0xff))
        bytes.append(UInt8(payload.count >> 8))
        bytes.append(UInt8(payload.count & 0xff))
        bytes.append(contentsOf: payload)
        return bytes
    }

    static func aRecord(_ owner: String, _ address: [UInt8], ttl: UInt32 = 300) -> [UInt8] {
        record(owner, type: 1, ttl: ttl, payload: address)
    }

    static func aaaaRecord(_ owner: String, _ address: [UInt8], ttl: UInt32 = 300) -> [UInt8] {
        record(owner, type: 28, ttl: ttl, payload: address)
    }

    static func cnameRecord(_ owner: String, _ target: String, ttl: UInt32 = 300) -> [UInt8] {
        record(owner, type: 5, ttl: ttl, payload: name(target))
    }

    static func reply(
        id: UInt16 = 0x1234, rcode: UInt8 = 0, questions: [String], type: UInt16 = 1,
        answers: [[UInt8]]
    ) -> Data {
        var bytes = header(
            id: id, response: true, rcode: rcode, questions: questions.count,
            answers: answers.count)
        for value in questions { bytes += question(value, type: type) }
        for answer in answers { bytes += answer }
        return Data(bytes)
    }
}

final class DNSMessageTests: XCTestCase {
    func testParsesQuestionsAndAddressRecords() {
        let message = DNSMessage.parse(
            DNSWire.reply(
                questions: ["www.google.com"],
                answers: [DNSWire.aRecord("www.google.com", [142, 251, 151, 119], ttl: 300)]))
        guard let message else { return XCTFail("well-formed reply did not parse") }
        XCTAssertTrue(message.isResponse)
        XCTAssertEqual(message.responseCode, 0)
        XCTAssertEqual(message.questions.map(\.name), ["www.google.com"])
        XCTAssertEqual(message.answers.count, 1)
        XCTAssertEqual(message.answers[0].address, Data([142, 251, 151, 119]))
        XCTAssertEqual(message.answers[0].ttl, 300)
    }

    func testNamesAreComparedWithoutRegardToCase() {
        let message = DNSMessage.parse(DNSWire.query(["WWW.Google.COM"]))
        XCTAssertEqual(message?.questions.first?.name, "www.google.com")
    }

    func testCompressionPointersAreFollowed() {
        // The answer names its owner with a pointer back to the question, which
        // is what a real resolver sends.
        var bytes = DNSWire.header(id: 0x1234, response: true, questions: 1, answers: 1)
        bytes += DNSWire.question("www.google.com")
        bytes += [0xc0, 0x0c]  // pointer to offset 12, the question's name
        bytes += [0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 142, 251, 151, 119]
        let message = DNSMessage.parse(Data(bytes))
        XCTAssertEqual(message?.answers.first?.name, "www.google.com")
        XCTAssertEqual(message?.answers.first?.address, Data([142, 251, 151, 119]))
    }

    func testAForwardPointerIsRefusedRatherThanFollowed() {
        // Only a backward pointer can terminate. A forward one is either a bug
        // or an attempt to make the parser walk somewhere it has not validated.
        var bytes = DNSWire.header(id: 0x1234, response: true, questions: 1, answers: 0)
        bytes += [0xc0, 0x20]
        bytes += Array(repeating: 0, count: 32)
        XCTAssertNil(DNSMessage.parse(Data(bytes)))
    }

    func testATruncatedMessageDoesNotParse() {
        XCTAssertNil(DNSMessage.parse(Data([0x12, 0x34])))
        XCTAssertNil(DNSMessage.parse(Data()))
    }

    func testARecordLengthReachingPastTheMessageEndsTheParse() {
        var bytes = DNSWire.header(id: 0x1234, response: true, questions: 0, answers: 1)
        bytes += DNSWire.name("www.google.com")
        bytes += [0, 1, 0, 1, 0, 0, 1, 44, 0xff, 0xff]  // claims 65535 bytes
        bytes += [142, 251, 151, 119]
        let message = DNSMessage.parse(Data(bytes))
        XCTAssertEqual(message?.answers.count, 0)
    }

    func testAnswersMatchesOnlyTheExchangeThatProducedIt() {
        let query = DNSMessage.parse(DNSWire.query(id: 0x1234, ["www.google.com"]))!
        let good = DNSMessage.parse(
            DNSWire.reply(id: 0x1234, questions: ["www.google.com"], answers: []))!
        XCTAssertTrue(good.answers(query))

        let otherTransaction = DNSMessage.parse(
            DNSWire.reply(id: 0x9999, questions: ["www.google.com"], answers: []))!
        XCTAssertFalse(otherTransaction.answers(query))

        let otherQuestion = DNSMessage.parse(
            DNSWire.reply(id: 0x1234, questions: ["www.example.com"], answers: []))!
        XCTAssertFalse(otherQuestion.answers(query))

        // A failure carries no association worth remembering.
        let servfail = DNSMessage.parse(
            DNSWire.reply(id: 0x1234, rcode: 2, questions: ["www.google.com"], answers: []))!
        XCTAssertFalse(servfail.answers(query))

        // An echoed query is not an answer.
        XCTAssertFalse(query.answers(query))
    }
}

final class LocalNamesTests: XCTestCase {
    func testReservedAndPrivateNameSpacesStayWithTheApplicationsResolver() {
        for name in [
            "nas", "printer.local", "printer.local.", "router.home.arpa", "host.test",
            "files.lan", "wiki.internal", "PRINTER.LOCAL",
        ] {
            XCTAssertTrue(LocalNames.isLocal(name), "\(name) should be local")
        }
        for name in ["www.google.com", "notlocal.example", "local.example.com", "mylocal.example.com"]
        {
            XCTAssertFalse(LocalNames.isLocal(name), "\(name) should not be local")
        }
    }

    func testPrivateReverseZonesAreLocalAndPublicOnesAreNot() {
        for name in [
            "1.1.168.192.in-addr.arpa", "5.4.3.10.in-addr.arpa", "1.0.0.127.in-addr.arpa",
            "7.6.16.172.in-addr.arpa", "7.6.31.172.in-addr.arpa",
        ] {
            XCTAssertTrue(LocalNames.isLocal(name), "\(name) should be local")
        }
        // 172.15 and 172.32 fall outside 172.16.0.0/12.
        for name in ["7.6.15.172.in-addr.arpa", "7.6.32.172.in-addr.arpa", "7.6.8.8.in-addr.arpa"] {
            XCTAssertFalse(LocalNames.isLocal(name), "\(name) should not be local")
        }
    }

    func testOperatorSuppliedSuffixesJoinTheLocalHalf() {
        let extra = ["corp.example.com", "office.test.net."]
        XCTAssertTrue(LocalNames.isLocal("wiki.corp.example.com", extraSuffixes: extra))
        XCTAssertTrue(LocalNames.isLocal("printer.office.test.net", extraSuffixes: extra))
        XCTAssertFalse(LocalNames.isLocal("www.example.com", extraSuffixes: extra))
        XCTAssertFalse(LocalNames.isLocal("notcorp.example.com", extraSuffixes: extra))
    }

    func testAQueryIsLocalOnlyWhenEveryNameInItIs() {
        XCTAssertTrue(LocalNames.queryIsLocal(DNSWire.query(["printer.local"])))
        XCTAssertFalse(LocalNames.queryIsLocal(DNSWire.query(["www.google.com"])))
        XCTAssertFalse(LocalNames.queryIsLocal(DNSWire.query(["printer.local", "www.google.com"])))
        // An unreadable query takes the trusted path: a redirected query that
        // cannot be answered fails a lookup, while one left on a poisoned path
        // fails a connection.
        XCTAssertFalse(LocalNames.queryIsLocal(Data([0x12])))
        XCTAssertFalse(LocalNames.queryIsLocal(Data()))
    }
}
