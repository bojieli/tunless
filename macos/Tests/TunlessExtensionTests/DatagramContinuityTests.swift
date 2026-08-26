import Network
import XCTest
@testable import TunlessExtension

/// The rules that keep an application's UDP socket alive when the upstream
/// does not.
///
/// These are regression tests for a failure that took a working host off the
/// network for hours at a time and left nothing on screen to explain it. A
/// capture pause, a proxy restart, or ten seconds of a busy mixed port used to
/// end the datagram flow underneath `mDNSResponder`'s resolver socket. macOS
/// does not re-capture such a socket and does not release it: every later send
/// fails locally, so name resolution ended for whichever client that socket
/// belonged to — one application broken, the rest of the host fine — until the
/// resolver daemon was restarted by hand.
///
/// So the association below is disposable and the flow above it is not.
final class DatagramContinuityTests: XCTestCase {
    // MARK: - The association

    func testAssociationOpensAndRelays() async throws {
        let upstream = try FakeSOCKS5Upstream()
        defer { upstream.stop() }
        let sink = RecordingSink()
        let association = UDPAssociation(
            configuration: upstream.configuration,
            sink: sink,
            dnsResponses: DNSResponseMap(),
            idleTimeoutSeconds: 0)
        defer { Task { await association.shutDown() } }

        let opened = await association.establish()
        XCTAssertTrue(opened, "the association must open against an upstream that answers")
        await association.remember(destination: SOCKSAddress(host: "1.1.1.1", port: 53))
        let relayed = await association.send(Self.frame(to: "1.1.1.1", payload: Data([0xab, 0xcd])))
        XCTAssertTrue(relayed)
        let echoed = try await sink.firstWrite(timeout: 5)
        XCTAssertEqual(echoed.payload, Data([0xab, 0xcd]))
        XCTAssertEqual(echoed.source, SOCKSAddress(host: "1.1.1.1", port: 53))
    }

    /// The regression: an upstream that dies is rebuilt underneath the flow.
    ///
    /// Nothing here closes anything belonging to the application. The old
    /// shape had no way to express that — the association and the flow were the
    /// same object, so losing one lost the other.
    func testAssociationIsRebuiltAfterTheUpstreamDies() async throws {
        let upstream = try FakeSOCKS5Upstream()
        let sink = RecordingSink()
        let association = UDPAssociation(
            configuration: upstream.configuration,
            sink: sink,
            dnsResponses: DNSResponseMap(),
            idleTimeoutSeconds: 0)
        defer { Task { await association.shutDown() } }
        let opened = await association.establish()
        XCTAssertTrue(opened)

        upstream.stop()
        // The send either fails outright or the control connection drops; both
        // land in the same place, which is what the next assertion checks.
        _ = await association.send(Self.frame(to: "1.1.1.1", payload: Data([1, 2])))
        try await Self.eventually(timeout: 5) {
            let ready = await association.isReady
            return ready == false
        }

        let revived = try FakeSOCKS5Upstream(port: upstream.port)
        defer { revived.stop() }
        // A failed association waits out its backoff before dialling again, so
        // an upstream that is down is not dialled once per query.
        var reopened = false
        try await Self.eventually(timeout: 12) {
            reopened = await association.establish()
            return reopened
        }
        XCTAssertTrue(reopened, "a returning upstream must be picked up again by the same flow")
    }

    func testShutDownLeavesNothingOpen() async throws {
        let upstream = try FakeSOCKS5Upstream()
        defer { upstream.stop() }
        let association = UDPAssociation(
            configuration: upstream.configuration,
            sink: RecordingSink(),
            dnsResponses: DNSResponseMap(),
            idleTimeoutSeconds: 0)
        let opened = await association.establish()
        XCTAssertTrue(opened)
        await association.shutDown()
        let ready = await association.isReady
        XCTAssertFalse(ready)
        let reopened = await association.establish()
        XCTAssertFalse(reopened, "a shut-down association must not dial the upstream again")
    }

    // MARK: - Replies nobody asked for

    /// A reply from the override resolver that answers nothing it rewrote is
    /// withheld; a reply from anywhere else is not.
    ///
    /// The second half matters as much as the first: an unconnected socket may
    /// address more peers than any bookkeeping should try to remember, so the
    /// rule is about one address, not about a set that can fill up.
    func testOnlyUnaskedRepliesFromTheOverrideResolverAreWithheld() async throws {
        let upstream = try FakeSOCKS5Upstream()
        defer { upstream.stop() }
        var configuration = upstream.configuration
        configuration.dnsHost = "1.1.1.1"
        configuration.dnsPort = 53
        let sink = RecordingSink()
        let association = UDPAssociation(
            configuration: configuration,
            sink: sink,
            dnsResponses: DNSResponseMap(),
            idleTimeoutSeconds: 0)
        defer { Task { await association.shutDown() } }
        let opened = await association.establish()
        XCTAssertTrue(opened)

        // Echoed back as though it came from the override resolver, matching
        // no rewritten query: the application never chose this identifier.
        let unasked = await association.send(
            Self.frame(to: "1.1.1.1", payload: Data([0x77, 0x88, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0])))
        XCTAssertTrue(unasked)
        let withheld = try? await sink.firstWrite(timeout: 2)
        XCTAssertNil(withheld, "a reply the flow cannot have asked for is not the application's business")

        // Any other peer is ordinary UDP traffic and is delivered untouched.
        let ordinary = await association.send(
            Self.frame(to: "203.0.113.7", payload: Data([9, 9, 9, 9])))
        XCTAssertTrue(ordinary)
        let delivered = try await sink.firstWrite(timeout: 5)
        XCTAssertEqual(delivered.source, SOCKSAddress(host: "203.0.113.7", port: 53))
        XCTAssertEqual(delivered.payload, Data([9, 9, 9, 9]))
    }

    // MARK: - Helpers

    private static func frame(to host: String, payload: Data) -> Data {
        var frame = Data([0, 0, 0])
        frame.append(try! SOCKSAddress(host: host, port: 53).encoded())
        frame.append(payload)
        return frame
    }

    private static func eventually(
        timeout: TimeInterval,
        _ condition: () async -> Bool
    ) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await condition() { return }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        XCTFail("condition never became true within \(timeout)s")
    }
}

/// Collects what the association hands up, in place of a flow.
final class RecordingSink: DatagramSink, @unchecked Sendable {
    struct Write {
        let payload: Data
        let source: SOCKSAddress
    }

    private let box = LockedBox<[Write]>([])

    func write(_ payload: Data, from source: SOCKSAddress) async {
        var current = box.take() ?? []
        current.append(Write(payload: payload, source: source))
        box.set(current)
    }

    func all() -> [Write] {
        let current = box.take() ?? []
        box.set(current)
        return current
    }

    struct NoWrite: Error {}

    func firstWrite(timeout: TimeInterval) async throws -> Write {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let first = all().first { return first }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        throw NoWrite()
    }
}

/// A SOCKS5 upstream that grants UDP ASSOCIATE and echoes what it is handed.
///
/// Real enough for the association to negotiate against, and killable, which
/// is the part these tests are about.
final class FakeSOCKS5Upstream: @unchecked Sendable {
    private(set) var port: UInt16 = 0
    private let listener: NWListener
    private let relay: NWListener
    private let queue = DispatchQueue(label: "tunless.tests.fake-upstream")
    private var connections: [NWConnection] = []
    private let lock = NSLock()

    var configuration: ProviderConfiguration {
        ProviderConfiguration(upstreamHost: "127.0.0.1", upstreamPort: port)
    }

    init(port requested: UInt16? = nil) throws {
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        let udpParameters = NWParameters.udp
        udpParameters.allowLocalEndpointReuse = true
        relay = try NWListener(using: udpParameters)
        listener = try requested.flatMap { NWEndpoint.Port(rawValue: $0) }.map {
            try NWListener(using: parameters, on: $0)
        } ?? NWListener(using: parameters)

        let ready = DispatchSemaphore(value: 0)
        relay.stateUpdateHandler = { state in
            if case .ready = state { ready.signal() }
        }
        let work = queue
        relay.newConnectionHandler = { [weak self] connection in
            self?.retain(connection)
            connection.start(queue: work)
            self?.echo(on: connection)
        }
        relay.start(queue: queue)
        guard ready.wait(timeout: .now() + 5) == .success, let bound = relay.port?.rawValue else {
            throw NoPort()
        }
        let relayPort = bound

        let listening = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            if case .ready = state { listening.signal() }
        }
        listener.newConnectionHandler = { [weak self] connection in
            self?.retain(connection)
            connection.start(queue: work)
            self?.negotiate(on: connection, relayPort: relayPort)
        }
        listener.start(queue: queue)
        guard listening.wait(timeout: .now() + 5) == .success, let listening = listener.port?.rawValue else {
            throw NoPort()
        }
        port = listening
    }

    struct NoPort: Error {}

    func stop() {
        lock.lock()
        let open = connections
        connections.removeAll()
        lock.unlock()
        for connection in open { connection.forceCancel() }
        listener.cancel()
        relay.cancel()
    }

    private func retain(_ connection: NWConnection) {
        lock.lock()
        connections.append(connection)
        lock.unlock()
    }

    /// Greeting, then one UDP ASSOCIATE reply pointing at the echo socket.
    private func negotiate(on connection: NWConnection, relayPort: UInt16) {
        connection.receive(minimumIncompleteLength: 3, maximumLength: 3) { _, _, _, error in
            guard error == nil else { return }
            connection.send(content: Data([5, 0]), completion: .contentProcessed { _ in
                connection.receive(minimumIncompleteLength: 10, maximumLength: 512) { _, _, _, error in
                    guard error == nil else { return }
                    var reply = Data([5, 0, 0, 1, 127, 0, 0, 1])
                    reply.append(UInt8(relayPort >> 8))
                    reply.append(UInt8(relayPort & 0xff))
                    connection.send(content: reply, completion: .contentProcessed { _ in })
                }
            })
        }
    }

    /// Sends every datagram straight back, header intact, which is what the
    /// association's receive loop expects to parse.
    private func echo(on connection: NWConnection) {
        connection.receiveMessage { [weak self] data, _, _, error in
            guard let self, let data, error == nil else { return }
            connection.send(content: data, completion: .contentProcessed { _ in })
            self.echo(on: connection)
        }
    }
}
