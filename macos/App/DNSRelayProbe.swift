import Foundation
import Network

/// What the DNS stage of preflight observed.
struct DNSRelayReport: Codable, Equatable {
    /// DNS over TCP through SOCKS5 CONNECT reached the resolver and it answered.
    let tcpRelayWorks: Bool
    /// DNS over UDP through SOCKS5 UDP ASSOCIATE reached the resolver.
    let udpRelayWorks: Bool
    /// Why UDP was unavailable, when it was not.
    let udpDetail: String?

    var summary: String {
        if tcpRelayWorks && udpRelayWorks { return "DNS relays over TCP and UDP" }
        if tcpRelayWorks {
            let reason = udpDetail.map { ": \($0)" } ?? ""
            return "DNS relays over TCP; UDP unavailable\(reason). Captured UDP"
                + " queries will fail, so applications must be able to retry"
                + " over TCP"
        }
        return "DNS does not relay"
    }
}

/// Proves the upstream can carry DNS before capture is enabled.
///
/// This exists because the transparent proxy rewrites every captured port-53
/// flow to the configured resolver and relays it through the SOCKS5 upstream.
/// If that relay does not work, enabling capture removes name resolution from
/// the whole host at once, which is exactly the failure this probe prevents.
final class DNSRelayProbe {
    private let configuration: LauncherConfiguration
    private let dnsHost: String
    private let dnsPort: UInt16
    private let queue = DispatchQueue(label: "com.bojieli.tunless.dns-relay-probe")

    private var connection: NWConnection?
    private var udpConnection: NWConnection?
    private var completion: ((Result<DNSRelayReport, Error>) -> Void)?
    private var completed = false
    private var timeout: TimeInterval = 6
    private let transactionID: UInt16 = UInt16.random(in: 1...UInt16.max)

    init(configuration: LauncherConfiguration, dnsHost: String, dnsPort: UInt16) {
        self.configuration = configuration
        self.dnsHost = dnsHost
        self.dnsPort = dnsPort
    }

    func run(timeout: TimeInterval, completion: @escaping (Result<DNSRelayReport, Error>) -> Void) {
        self.completion = completion
        self.timeout = timeout
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            guard let self, !self.completed else { return }
            self.finish(.failure(PreflightError.dnsRelay(
                "no answer from \(self.dnsHost):\(self.dnsPort) within \(Int(timeout)) seconds")))
        }
        startTCPProbe()
    }

    // MARK: - DNS over TCP, via SOCKS5 CONNECT

    private func startTCPProbe() {
        let connection = NWConnection(
            host: NWEndpoint.Host(configuration.upstreamHost),
            port: NWEndpoint.Port(rawValue: configuration.upstreamPort)!,
            using: .tcp)
        self.connection = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready: self.greet(connection) { self.connectToResolver(connection) }
            case let .failed(error):
                self.finish(.failure(PreflightError.dnsRelay(error.localizedDescription)))
            default: break
            }
        }
        connection.start(queue: queue)
    }

    private func greet(_ connection: NWConnection, then next: @escaping () -> Void) {
        let hasCredentials = configuration.username != nil || configuration.password != nil
        send(connection, Data([5, 1, hasCredentials ? 2 : 0])) { [weak self] ok in
            guard let self, ok else { return }
            self.receiveExactly(connection, 2) { reply in
                guard let reply, reply.count == 2, reply[0] == 5 else {
                    self.finish(.failure(PreflightError.dnsRelay("invalid SOCKS5 greeting")))
                    return
                }
                if reply[1] == 0, !hasCredentials { next(); return }
                guard reply[1] == 2, hasCredentials else {
                    self.finish(.failure(PreflightError.dnsRelay("authentication rejected")))
                    return
                }
                let username = Data((self.configuration.username ?? "").utf8)
                let password = Data((self.configuration.password ?? "").utf8)
                var request = Data([1, UInt8(username.count)])
                request.append(username)
                request.append(UInt8(password.count))
                request.append(password)
                self.send(connection, request) { sent in
                    guard sent else { return }
                    self.receiveExactly(connection, 2) { auth in
                        guard let auth, auth.count == 2, auth[0] == 1, auth[1] == 0 else {
                            self.finish(.failure(PreflightError.dnsRelay("authentication rejected")))
                            return
                        }
                        next()
                    }
                }
            }
        }
    }

    private func connectToResolver(_ connection: NWConnection) {
        guard let target = Self.encodedAddress(host: dnsHost, port: dnsPort) else {
            finish(.failure(PreflightError.dnsRelay("invalid resolver address")))
            return
        }
        send(connection, Data([5, 1, 0]) + target) { [weak self] ok in
            guard let self, ok else { return }
            self.receiveReply(connection) { code in
                guard code == 0 else {
                    self.finish(.failure(PreflightError.dnsRelay(
                        "CONNECT to \(self.dnsHost):\(self.dnsPort) was rejected"
                            + " (SOCKS5 reply \(code.map(String.init) ?? "none"))")))
                    return
                }
                self.sendQueryOverTCP(connection)
            }
        }
    }

    private func sendQueryOverTCP(_ connection: NWConnection) {
        let query = DNSProbeMessage.query(transactionID: transactionID)
        send(connection, DNSProbeMessage.tcpFramed(query)) { [weak self] ok in
            guard let self, ok else { return }
            self.receiveExactly(connection, 2) { prefix in
                guard let prefix, let length = DNSProbeMessage.tcpPayloadLength(prefix), length > 0 else {
                    self.finish(.failure(PreflightError.dnsRelay(
                        "resolver \(self.dnsHost):\(self.dnsPort) did not answer over TCP")))
                    return
                }
                self.receiveExactly(connection, min(length, 4096)) { body in
                    guard let body,
                          DNSProbeMessage.isResponse(body, transactionID: self.transactionID) else {
                        self.finish(.failure(PreflightError.dnsRelay(
                            "resolver \(self.dnsHost):\(self.dnsPort) returned no valid"
                                + " DNS response over TCP")))
                        return
                    }
                    // TCP works. UDP is a bonus, so a failure there is reported
                    // rather than fatal.
                    self.startUDPProbe()
                }
            }
        }
    }

    // MARK: - DNS over UDP, via SOCKS5 UDP ASSOCIATE

    private func startUDPProbe() {
        let control = NWConnection(
            host: NWEndpoint.Host(configuration.upstreamHost),
            port: NWEndpoint.Port(rawValue: configuration.upstreamPort)!,
            using: .tcp)
        udpConnection = control
        control.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.greet(control) { self.associate(control) }
            case let .failed(error):
                self.succeedTCPOnly("control connection failed: \(error.localizedDescription)")
            default: break
            }
        }
        control.start(queue: queue)
    }

    private func associate(_ control: NWConnection) {
        guard let target = Self.encodedAddress(host: "0.0.0.0", port: 0) else {
            succeedTCPOnly("could not encode UDP ASSOCIATE request")
            return
        }
        send(control, Data([5, 3, 0]) + target) { [weak self] ok in
            guard let self, ok else { return }
            self.receiveReplyAddress(control) { relay in
                guard let relay else {
                    self.succeedTCPOnly("upstream refused UDP ASSOCIATE")
                    return
                }
                self.relayQuery(to: relay, control: control)
            }
        }
    }

    private func relayQuery(to relay: (host: String, port: UInt16), control: NWConnection) {
        // An unspecified or loopback bind address is only meaningful relative to
        // the upstream itself, matching how the provider resolves it.
        var host = relay.host
        if host == "0.0.0.0" || host == "::" { host = configuration.upstreamHost }
        guard relay.port > 0, let port = NWEndpoint.Port(rawValue: relay.port) else {
            succeedTCPOnly("upstream returned an unusable UDP relay port")
            return
        }
        let datagrams = NWConnection(host: NWEndpoint.Host(host), port: port, using: .udp)
        guard let target = Self.encodedAddress(host: dnsHost, port: dnsPort) else {
            succeedTCPOnly("invalid resolver address for UDP")
            return
        }
        var packet = Data([0, 0, 0])
        packet.append(target)
        packet.append(DNSProbeMessage.query(transactionID: transactionID))
        datagrams.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                datagrams.send(content: packet, completion: .contentProcessed { _ in })
                datagrams.receiveMessage { data, _, _, _ in
                    defer {
                        datagrams.cancel()
                        control.cancel()
                    }
                    guard let data,
                          let payload = DNSProbeMessage.relayedPayload(data),
                          DNSProbeMessage.isResponse(payload, transactionID: self.transactionID)
                    else {
                        self.succeedTCPOnly("no DNS answer came back through the UDP relay")
                        return
                    }
                    self.finish(.success(DNSRelayReport(
                        tcpRelayWorks: true, udpRelayWorks: true, udpDetail: nil)))
                }
            case let .failed(error):
                datagrams.cancel()
                self.succeedTCPOnly("UDP relay failed: \(error.localizedDescription)")
            default: break
            }
        }
        datagrams.start(queue: queue)
    }

    /// TCP relaying works but UDP does not. That is a degraded but usable
    /// state, so report it instead of blocking the deployment.
    private func succeedTCPOnly(_ detail: String) {
        finish(.success(DNSRelayReport(
            tcpRelayWorks: true, udpRelayWorks: false, udpDetail: detail)))
    }

    // MARK: - Wire helpers

    private static func encodedAddress(host: String, port: UInt16) -> Data? {
        var output = Data()
        if let address = IPv4Address(host) {
            output.append(1)
            output.append(contentsOf: address.rawValue)
        } else if let address = IPv6Address(host) {
            output.append(4)
            output.append(contentsOf: address.rawValue)
        } else {
            let bytes = Data(host.utf8)
            guard !bytes.isEmpty, bytes.count <= 255 else { return nil }
            output.append(3)
            output.append(UInt8(bytes.count))
            output.append(bytes)
        }
        output.append(UInt8(port >> 8))
        output.append(UInt8(port & 0xff))
        return output
    }

    private func send(_ connection: NWConnection, _ data: Data, then next: @escaping (Bool) -> Void) {
        connection.send(content: data, completion: .contentProcessed { [weak self] error in
            guard let self else { return }
            if let error {
                self.finish(.failure(PreflightError.dnsRelay(error.localizedDescription)))
                next(false)
            } else {
                next(true)
            }
        })
    }

    private func receiveExactly(
        _ connection: NWConnection,
        _ count: Int,
        buffer: Data = Data(),
        then next: @escaping (Data?) -> Void
    ) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: count - buffer.count) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if error != nil { next(nil); return }
            var accumulated = buffer
            if let data { accumulated.append(data) }
            if accumulated.count >= count {
                next(accumulated)
            } else if isComplete || data?.isEmpty != false {
                next(nil)
            } else {
                self.receiveExactly(connection, count, buffer: accumulated, then: next)
            }
        }
    }

    /// Reads a SOCKS5 reply and yields only its status byte.
    private func receiveReply(_ connection: NWConnection, then next: @escaping (UInt8?) -> Void) {
        receiveReplyAddress(connection) { relay in
            next(relay == nil ? 1 : 0)
        }
    }

    /// Reads a full SOCKS5 reply, returning the bound address on success.
    private func receiveReplyAddress(
        _ connection: NWConnection,
        then next: @escaping ((host: String, port: UInt16)?) -> Void
    ) {
        receiveExactly(connection, 4) { [weak self] header in
            guard let self, let header, header.count == 4, header[0] == 5, header[1] == 0 else {
                next(nil)
                return
            }
            let addressLength: Int
            switch header[3] {
            case 1: addressLength = 4
            case 4: addressLength = 16
            case 3: addressLength = -1
            default: next(nil); return
            }
            if addressLength == -1 {
                self.receiveExactly(connection, 1) { lengthByte in
                    guard let lengthByte, let length = lengthByte.first else { next(nil); return }
                    self.receiveExactly(connection, Int(length) + 2) { rest in
                        guard let rest, rest.count == Int(length) + 2 else { next(nil); return }
                        let name = String(decoding: rest.prefix(Int(length)), as: UTF8.self)
                        let port = UInt16(rest[rest.index(rest.startIndex, offsetBy: Int(length))]) << 8
                            | UInt16(rest[rest.index(rest.startIndex, offsetBy: Int(length) + 1)])
                        next((name, port))
                    }
                }
                return
            }
            self.receiveExactly(connection, addressLength + 2) { rest in
                guard let rest, rest.count == addressLength + 2 else { next(nil); return }
                let addressBytes = [UInt8](rest.prefix(addressLength))
                let portBytes = [UInt8](rest.suffix(2))
                let port = UInt16(portBytes[0]) << 8 | UInt16(portBytes[1])
                let host: String
                if addressLength == 4 {
                    host = addressBytes.map(String.init).joined(separator: ".")
                } else {
                    host = IPv6Address(Data(addressBytes))?.debugDescription ?? "::"
                }
                next((host, port))
            }
        }
    }

    private func finish(_ result: Result<DNSRelayReport, Error>) {
        guard !completed else { return }
        completed = true
        connection?.cancel()
        udpConnection?.cancel()
        let callback = completion
        completion = nil
        DispatchQueue.main.async { callback?(result) }
    }
}
