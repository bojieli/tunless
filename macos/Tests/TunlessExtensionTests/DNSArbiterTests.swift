import Foundation
import Network
import XCTest

@testable import TunlessExtension

final class DNSArbiterTests: XCTestCase {
    private let directResolver = SOCKSAddress(host: "127.0.0.1", port: 15353)
    private let applicationResolver = SOCKSAddress(host: "192.168.1.1", port: 53)

    private func policy() -> DNSPolicy {
        var policy = DNSPolicy()
        policy.prefixes = DNSPrefixSet(prefixes: ["203.0.113.0/24"])
        policy.directResolver = directResolver
        return policy
    }

    /// An arbiter whose direct half is driven by the test rather than by a
    /// socket: the send always reports success and no reply ever arrives on its
    /// own, so every direct answer is one the test hands over deliberately.
    private func makeArbiter(sink: RecordingSink, released: ReleasedIdentifiers) -> DNSArbiter {
        DNSArbiter(
            policy: policy(),
            askDirect: { _ in true },
            breaker: DirectResolverBreaker(),
            counters: DNSPolicyCounters(),
            deliver: { payload, source in await sink.write(payload, from: source) },
            release: { identifier in await released.add(identifier) },
            // Long enough that no timer can settle an exchange these tests
            // expect to still be waiting.
            directReplyWindow: 3600,
            adjudicationDeadline: 3600)
    }

    func testTheApplicationGetsItsOwnTransactionIDAndResolverBack() async throws {
        // The application never saw the identifier this process minted, and it
        // wrote to its own resolver rather than to either of ours. A reply
        // carrying the wrong one of either is a reply the client discards.
        let sink = RecordingSink()
        let released = ReleasedIdentifiers()
        let arbiter = makeArbiter(sink: sink, released: released)
        let rewritten = dnsQuery(id: 0x9999, name: "www.example.net")

        let accepted = await arbiter.begin(
            identifier: 0x9999, originalID: 0x1234,
            original: applicationResolver, query: rewritten)
        XCTAssertTrue(accepted)

        let answered = await arbiter.deliverDirect(
            dnsReply(to: rewritten, addresses: ["203.0.113.7"]), from: directResolver)
        XCTAssertTrue(answered)

        let delivered = try await sink.firstWrite(timeout: 2)
        let payload = delivered.payload
        XCTAssertEqual(payload[payload.startIndex], 0x12)
        XCTAssertEqual(payload[payload.startIndex + 1], 0x34)
        XCTAssertEqual(delivered.source, applicationResolver)
        let identifiers = await released.all()
        XCTAssertEqual(identifiers, [0x9999])
    }

    func testTheTrustedHalfIsHeldUntilTheDirectHalfSettles() async throws {
        let sink = RecordingSink()
        let arbiter = makeArbiter(sink: sink, released: ReleasedIdentifiers())
        let rewritten = dnsQuery(id: 0x4444, name: "www.example.net")
        _ = await arbiter.begin(
            identifier: 0x4444, originalID: 0x1111,
            original: applicationResolver, query: rewritten)

        let claimed = await arbiter.deliverTrusted(
            dnsReply(to: rewritten, addresses: ["192.0.2.9"]), identifier: 0x4444)
        XCTAssertTrue(claimed)
        let pending = await arbiter.outstandingCount()
        XCTAssertEqual(pending, 1, "the trusted half settled the exchange on its own")

        _ = await arbiter.deliverDirect(
            dnsReply(to: rewritten, addresses: ["198.51.100.1"]), from: directResolver)
        let delivered = try await sink.firstWrite(timeout: 2)
        let addresses = DNSPolicy.addresses(in: delivered.payload)
        XCTAssertEqual(addresses.count, 1)
        XCTAssertEqual(addresses.first, IPv4Address("192.0.2.9")!.rawValue)
    }

    func testADatagramFromSomewhereElseIsNotTakenAsTheDirectHalf() async {
        let sink = RecordingSink()
        let arbiter = makeArbiter(sink: sink, released: ReleasedIdentifiers())
        let rewritten = dnsQuery(id: 0x7777, name: "www.example.net")
        _ = await arbiter.begin(
            identifier: 0x7777, originalID: 0x4444,
            original: applicationResolver, query: rewritten)

        let claimed = await arbiter.deliverDirect(
            dnsReply(to: rewritten, addresses: ["203.0.113.7"]),
            from: SOCKSAddress(host: "198.51.100.53", port: 53))
        XCTAssertFalse(claimed)
        let pending = await arbiter.outstandingCount()
        XCTAssertEqual(pending, 1)
    }

    func testAnUnknownIdentifierIsDeclinedSoOrdinaryRepliesStillFlow() async {
        // The same relay carries answers to queries the name lists routed
        // direct. The arbiter has to hand those back rather than swallow them.
        let sink = RecordingSink()
        let arbiter = makeArbiter(sink: sink, released: ReleasedIdentifiers())
        let stray = dnsReply(to: dnsQuery(id: 0x0001, name: "www.example.net"), addresses: ["203.0.113.7"])
        let claimedDirect = await arbiter.deliverDirect(stray, from: directResolver)
        XCTAssertFalse(claimedDirect)
        let claimedTrusted = await arbiter.deliverTrusted(stray, identifier: 0x0001)
        XCTAssertFalse(claimedTrusted)
    }

    func testADatagramThatDoesNotAnswerTheQuestionDoesNotConsumeTheExchange() async throws {
        // Forging one is cheap for anyone who can guess the identifier. Letting
        // it settle would discard the real answer arriving behind it.
        let sink = RecordingSink()
        let arbiter = makeArbiter(sink: sink, released: ReleasedIdentifiers())
        let rewritten = dnsQuery(id: 0x6666, name: "www.example.net")
        _ = await arbiter.begin(
            identifier: 0x6666, originalID: 0x3333,
            original: applicationResolver, query: rewritten)

        var forged = dnsReply(to: rewritten, addresses: ["203.0.113.7"])
        forged[forged.startIndex + 2] &= ~0x80
        _ = await arbiter.deliverDirect(forged, from: directResolver)
        let stillPending = await arbiter.outstandingCount()
        XCTAssertEqual(stillPending, 1)

        _ = await arbiter.deliverDirect(
            dnsReply(to: rewritten, addresses: ["203.0.113.7"]), from: directResolver)
        let delivered = try await sink.firstWrite(timeout: 2)
        XCTAssertEqual(delivered.payload[delivered.payload.startIndex + 1], 0x33)
    }

    func testCancellingAbandonsEverythingOutstanding() async {
        let sink = RecordingSink()
        let released = ReleasedIdentifiers()
        let arbiter = makeArbiter(sink: sink, released: released)
        let rewritten = dnsQuery(id: 0x8888, name: "www.example.net")
        _ = await arbiter.begin(
            identifier: 0x8888, originalID: 0x5555,
            original: applicationResolver, query: rewritten)

        await arbiter.cancel()
        let identifiers = await released.all()
        XCTAssertEqual(identifiers, [0x8888])
        let accepted = await arbiter.begin(
            identifier: 0x9999, originalID: 0x6666,
            original: applicationResolver, query: rewritten)
        XCTAssertFalse(accepted, "a cancelled arbiter accepted a new query")
        // Nothing is delivered: the socket that asked has gone away.
        XCTAssertTrue(sink.all().isEmpty)
    }
}

/// Collects the transaction identifiers an arbiter released.
actor ReleasedIdentifiers {
    private var identifiers: [UInt16] = []
    func add(_ identifier: UInt16) { identifiers.append(identifier) }
    func all() -> [UInt16] { identifiers }
}
