import Foundation
import Network

/// What one round of health probing observed.
struct DNSProbeOutcome: Equatable {
    /// A query relayed over SOCKS5 CONNECT came back.
    let tcp: Bool
    /// A query relayed over SOCKS5 UDP ASSOCIATE came back, or nil when UDP
    /// was not probed because this upstream never offered it.
    let udp: Bool?

    /// Whether the upstream can still carry the DNS capture depends on.
    ///
    /// UDP counts only when the upstream was known to relay it at preflight.
    /// An upstream that never offered UDP is a documented degraded state the
    /// operator was warned about at start; one that offered it and stopped is
    /// a datapath that has broken underneath applications which have no reason
    /// to retry over TCP.
    var healthy: Bool { tcp && (udp ?? true) }

    var detail: String {
        switch (tcp, udp) {
        case (false, _): return "no answer over TCP"
        case (true, false?): return "no answer over UDP, which this upstream relayed at preflight"
        default: return "answered"
        }
    }
}

/// Sends DNS queries along the exact paths a captured port-53 flow takes.
///
/// The check that matters is not "is the upstream listening" — that stays true
/// while DNS is dead — but "does a query put through this upstream to this
/// resolver come back". So the probe reuses `SOCKSConnection` and the
/// configured resolver rather than testing anything of its own: if this
/// succeeds, a captured port-53 flow would have succeeded too, and if it fails,
/// resolution on the host is failing in the same way.
///
/// Both transports are probed, because they fail independently. An upstream
/// that relays DNS over TCP while refusing UDP ASSOCIATE looks perfectly
/// healthy to a TCP-only probe, and is not: applications that resolve over UDP
/// — which is nearly all of them — get nothing back, and nothing in the system
/// says why. Probing only the transport that happens to work is how a watchdog
/// misses the failure it exists to catch.
enum DNSHealthProbe {
    /// A resolver capture is carrying, learned from the flows themselves.
    ///
    /// It exists for the case where the operator turned the DNS override off.
    /// Capture still relays every port-53 flow to the upstream then — the flag
    /// preserves each application's choice of resolver, it does not stop
    /// proxying the query — so the upstream can still take DNS down host-wide,
    /// and there is no configured resolver to prove that against. The flows say
    /// which resolver to ask, and which transport the host asks it over.
    struct CarriedResolver: Equatable, Sendable {
        let address: SOCKSAddress
        let overUDP: Bool
    }

    /// Which resolver a probe round should ask, and whether to ask over UDP.
    ///
    /// Nil means there is nothing to prove: no override is configured and
    /// capture has not carried a port-53 flow yet, so capture is making no
    /// claim about resolution that could be false.
    static func target(
        configuration: ProviderConfiguration,
        carried: CarriedResolver?
    ) -> (resolver: SOCKSAddress, probeUDP: Bool)? {
        if let dnsHost = configuration.dnsHost, let dnsPort = configuration.dnsPort {
            return (SOCKSAddress(host: dnsHost, port: dnsPort), configuration.expectUDPRelay == true)
        }
        guard let carried else { return nil }
        // Preflight never tested UDP relaying in this configuration, because it
        // had no resolver to test against. What the flows show is better
        // evidence than that absence: if this host resolves over UDP through
        // capture, a UDP relay that stops answering is the failure the watchdog
        // exists to catch.
        return (carried.address, carried.overUDP)
    }

    static func run(
        configuration: ProviderConfiguration,
        carried: CarriedResolver? = nil,
        timeoutSeconds: TimeInterval = 6
    ) async -> DNSProbeOutcome {
        guard let target = target(configuration: configuration, carried: carried) else {
            return DNSProbeOutcome(tcp: true, udp: nil)
        }
        let tcp = await probeTCP(
            configuration: configuration, resolver: target.resolver, timeoutSeconds: timeoutSeconds)
        guard target.probeUDP else {
            return DNSProbeOutcome(tcp: tcp, udp: nil)
        }
        let udp = await probeUDP(
            configuration: configuration, resolver: target.resolver, timeoutSeconds: timeoutSeconds)
        return DNSProbeOutcome(tcp: tcp, udp: udp)
    }

    /// DNS over TCP, through SOCKS5 CONNECT — the path a captured TCP port-53
    /// flow takes.
    private static func probeTCP(
        configuration: ProviderConfiguration,
        resolver: SOCKSAddress,
        timeoutSeconds: TimeInterval
    ) async -> Bool {
        let transactionID = UInt16.random(in: 1...UInt16.max)
        let connection = SOCKSConnection(configuration: configuration)
        return await withTimeout(timeoutSeconds, onTimeout: { await connection.cancel() }) {
            defer { Task { await connection.cancel() } }
            do {
                _ = try await connection.open(
                    configuration: configuration,
                    command: 1,
                    destination: resolver,
                    timeoutSeconds: timeoutSeconds)
                try await connection.send(
                    DNSProbeMessage.tcpFramed(DNSProbeMessage.query(transactionID: transactionID)))
                let prefix = try await connection.receive(2)
                guard let length = DNSProbeMessage.tcpPayloadLength(prefix), length > 0 else { return false }
                let body = try await connection.receive(min(length, 4096))
                return DNSProbeMessage.isResponse(body, transactionID: transactionID)
            } catch {
                return false
            }
        }
    }

    /// DNS over UDP, through SOCKS5 UDP ASSOCIATE — the path a captured UDP
    /// port-53 flow takes, and the one nearly every resolver client uses.
    private static func probeUDP(
        configuration: ProviderConfiguration,
        resolver: SOCKSAddress,
        timeoutSeconds: TimeInterval
    ) async -> Bool {
        let transactionID = UInt16.random(in: 1...UInt16.max)
        let control = SOCKSConnection(configuration: configuration)
        // The probe task publishes its datagram connection here and the
        // timeout task cancels it. Both run concurrently, so the handoff is
        // locked: an unsynchronised box races the assignment against the read.
        let datagrams = LockedBox<NWConnection>()
        return await withTimeout(timeoutSeconds, onTimeout: {
            await control.cancel()
            datagrams.take()?.cancel()
        }) {
            defer {
                Task { await control.cancel() }
                datagrams.take()?.cancel()
            }
            do {
                var relay = try await control.open(
                    configuration: configuration,
                    command: 3,
                    destination: SOCKSAddress(host: "0.0.0.0", port: 0),
                    timeoutSeconds: timeoutSeconds)
                // An unspecified or loopback relay address is only meaningful
                // relative to the upstream itself, matching how a captured UDP
                // flow resolves it.
                if Self.unspecified(relay.host) || (Self.loopback(relay.host) && !Self.loopback(configuration.upstreamHost)) {
                    relay = SOCKSAddress(host: configuration.upstreamHost, port: relay.port)
                }
                guard relay.port > 0, let port = NWEndpoint.Port(rawValue: relay.port) else { return false }
                let connection = NWConnection(host: NWEndpoint.Host(relay.host), port: port, using: .udp)
                datagrams.set(connection)
                var packet = Data([0, 0, 0])
                packet.append(try resolver.encoded())
                packet.append(DNSProbeMessage.query(transactionID: transactionID))
                return try await withCheckedThrowingContinuation { continuation in
                    let gate = AsyncResultGate<Bool>()
                    guard gate.install(continuation) else { return }
                    connection.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            connection.send(content: packet, completion: .contentProcessed { _ in })
                            connection.receiveMessage { data, _, _, _ in
                                guard let data, data.count > 10 else {
                                    gate.resume(with: .success(false))
                                    return
                                }
                                gate.resume(with: .success(DNSProbeMessage.isResponse(
                                    data.dropFirst(10), transactionID: transactionID)))
                            }
                        case .failed, .cancelled:
                            gate.resume(with: .success(false))
                        default:
                            break
                        }
                    }
                    connection.start(queue: .global(qos: .utility))
                }
            } catch {
                return false
            }
        }
    }

    /// Runs `body`, returning false if it has not finished within the timeout.
    private static func withTimeout(
        _ seconds: TimeInterval,
        onTimeout: @escaping @Sendable () async -> Void,
        _ body: @escaping @Sendable () async -> Bool
    ) async -> Bool {
        await withTaskGroup(of: Bool.self) { group -> Bool in
            group.addTask { await body() }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(max(1, seconds) * 1_000_000_000))
                await onTimeout()
                return false
            }
            defer { group.cancelAll() }
            return await group.next() ?? false
        }
    }

    private static func unspecified(_ host: String) -> Bool { host == "0.0.0.0" || host == "::" }

    private static func loopback(_ host: String) -> Bool {
        if let address = IPv4Address(host) { return address.rawValue.first == 127 }
        if let address = IPv6Address(host) { return address.rawValue == IPv6Address("::1")!.rawValue }
        return false
    }
}

/// Hands a value between the probe's concurrent tasks under a lock.
///
/// The probe task creates a connection and the timeout task has to be able to
/// cancel it, which is a write and a read from two tasks with no ordering
/// between them. `take` clears as it reads so whichever task gets there first
/// owns the cancellation and the other does nothing.
final class LockedBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value?

    init(_ value: Value? = nil) { stored = value }

    func set(_ value: Value) {
        lock.lock()
        defer { lock.unlock() }
        stored = value
    }

    func take() -> Value? {
        lock.lock()
        defer { lock.unlock() }
        let value = stored
        stored = nil
        return value
    }
}
