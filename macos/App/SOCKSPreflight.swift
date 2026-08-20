import Foundation
import Network

final class SOCKSPreflight {
    private let configuration: LauncherConfiguration
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "com.bojieli.tunless.socks-preflight")
    private var completed = false
    private var completion: ((Result<Void, Error>) -> Void)?
    private var dnsProbe: DNSRelayProbe?
    private var dnsTimeout: TimeInterval = 6

    /// What the DNS stage observed, once it has run.
    private(set) var dnsReport: DNSRelayReport?

    init(configuration: LauncherConfiguration) {
        self.configuration = configuration
        connection = NWConnection(
            host: NWEndpoint.Host(configuration.upstreamHost),
            port: NWEndpoint.Port(rawValue: configuration.upstreamPort)!,
            using: .tcp)
    }

    func run(
        timeout: TimeInterval = 5,
        dnsTimeout: TimeInterval = 6,
        completion: @escaping (Result<Void, Error>) -> Void
    ) {
        self.completion = completion
        self.dnsTimeout = dnsTimeout
        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready: self.negotiate()
            case let .failed(error): self.finish(.failure(PreflightError.connection(error.localizedDescription)))
            case let .waiting(error): self.finish(.failure(PreflightError.connection(error.localizedDescription)))
            case .cancelled:
                if !self.completed { self.finish(.failure(PreflightError.closed)) }
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in
            // Do not fire while the DNS stage is legitimately still running.
            guard let self, !self.completed, self.dnsProbe == nil else { return }
            self.finish(.failure(PreflightError.timeout))
        }
    }

    private func negotiate() {
        let hasCredentials = configuration.username != nil || configuration.password != nil
        send(Data([5, 1, hasCredentials ? 2 : 0])) { [weak self] result in
            guard let self else { return }
            switch result {
            case let .failure(error): self.finish(.failure(error))
            case .success:
                self.receiveExactly(2) { reply in
                    switch reply {
                    case let .failure(error): self.finish(.failure(error))
                    case let .success(data): self.handleMethod(data, hasCredentials: hasCredentials)
                    }
                }
            }
        }
    }

    private func handleMethod(_ reply: Data, hasCredentials: Bool) {
        guard reply.count == 2, reply[0] == 5 else {
            finish(.failure(PreflightError.invalidReply))
            return
        }
        if reply[1] == 0, !hasCredentials {
            checkDNSRelay()
            return
        }
        guard reply[1] == 2, hasCredentials else {
            finish(.failure(PreflightError.authentication))
            return
        }
        let username = Data((configuration.username ?? "").utf8)
        let password = Data((configuration.password ?? "").utf8)
        var request = Data([1, UInt8(username.count)])
        request.append(username)
        request.append(UInt8(password.count))
        request.append(password)
        send(request) { [weak self] result in
            guard let self else { return }
            switch result {
            case let .failure(error): self.finish(.failure(error))
            case .success:
                self.receiveExactly(2) { reply in
                    switch reply {
                    case let .failure(error): self.finish(.failure(error))
                    case let .success(data):
                        if data.count == 2, data[0] == 1, data[1] == 0 {
                            self.checkDNSRelay()
                        } else {
                            self.finish(.failure(PreflightError.authentication))
                        }
                    }
                }
            }
        }
    }

    /// Verifies that the upstream can actually carry the DNS traffic that
    /// capture will redirect into it.
    ///
    /// A SOCKS5 greeting only proves the listener speaks the protocol. Once
    /// capture is enabled, every captured port-53 flow is rewritten to the
    /// configured resolver and relayed through this same upstream, so an
    /// upstream that greets correctly but cannot relay DNS takes name
    /// resolution down host-wide the moment capture starts. Prove the DNS
    /// path works *before* enabling capture, not after.
    ///
    /// DNS over TCP is sufficient evidence on its own: it uses SOCKS5
    /// CONNECT, the same mechanism captured TCP port-53 flows use. UDP
    /// ASSOCIATE is attempted second and reported separately, because many
    /// upstreams refuse it while still relaying TCP correctly.
    private func checkDNSRelay() {
        guard let dnsHost = configuration.dnsHost, let dnsPort = configuration.dnsPort else {
            // DNS override is disabled, so capture does not redirect port 53
            // and there is no additional resolver path to prove.
            finish(.success(()))
            return
        }
        let probe = DNSRelayProbe(
            configuration: configuration,
            dnsHost: dnsHost,
            dnsPort: dnsPort)
        dnsProbe = probe
        probe.run(timeout: dnsTimeout) { [weak self] result in
            guard let self else { return }
            self.dnsProbe = nil
            switch result {
            case let .success(report):
                self.dnsReport = report
                self.finish(.success(()))
            case let .failure(error):
                self.finish(.failure(error))
            }
        }
    }
    private func send(_ data: Data, completion: @escaping (Result<Void, Error>) -> Void) {
        connection.send(content: data, completion: .contentProcessed { error in
            if let error { completion(.failure(PreflightError.connection(error.localizedDescription))) }
            else { completion(.success(())) }
        })
    }

    private func receiveExactly(
        _ count: Int,
        buffer: Data = Data(),
        completion: @escaping (Result<Data, Error>) -> Void
    ) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: count - buffer.count) {
            [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let error {
                completion(.failure(PreflightError.connection(error.localizedDescription)))
                return
            }
            var accumulated = buffer
            if let data { accumulated.append(data) }
            if accumulated.count == count {
                completion(.success(accumulated))
            } else if isComplete || data?.isEmpty != false {
                completion(.failure(PreflightError.closed))
            } else {
                self.receiveExactly(count, buffer: accumulated, completion: completion)
            }
        }
    }

    private func finish(_ result: Result<Void, Error>) {
        guard !completed else { return }
        completed = true
        connection.stateUpdateHandler = nil
        connection.cancel()
        let callback = completion
        completion = nil
        DispatchQueue.main.async { callback?(result) }
    }
}

enum PreflightError: LocalizedError {
    case connection(String)
    case authentication
    case invalidReply
    case closed
    case timeout
    case dnsRelay(String)

    var errorDescription: String? {
        switch self {
        case let .connection(detail): return "cannot connect to SOCKS5 upstream: \(detail)"
        case .authentication: return "SOCKS5 upstream rejected the configured authentication method"
        case .invalidReply: return "upstream did not return a valid SOCKS5 greeting"
        case .closed: return "SOCKS5 upstream closed the connection during negotiation"
        case .timeout: return "SOCKS5 upstream did not respond within 5 seconds"
        case let .dnsRelay(detail):
            return "upstream cannot relay DNS: " + detail
                + ". Capture redirects every port-53 flow into this upstream,"
                + " so starting now would break name resolution host-wide."
                + " Fix the upstream, or start with --disable-dns-override to"
                + " keep each application's own resolver"
        }
    }
}
