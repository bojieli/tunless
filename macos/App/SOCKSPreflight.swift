import Foundation
import Network

final class SOCKSPreflight {
    private let configuration: LauncherConfiguration
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "com.bojieli.tunless.socks-preflight")
    private var completed = false
    private var completion: ((Result<Void, Error>) -> Void)?

    init(configuration: LauncherConfiguration) {
        self.configuration = configuration
        connection = NWConnection(
            host: NWEndpoint.Host(configuration.upstreamHost),
            port: NWEndpoint.Port(rawValue: configuration.upstreamPort)!,
            using: .tcp)
    }

    func run(timeout: TimeInterval = 5, completion: @escaping (Result<Void, Error>) -> Void) {
        self.completion = completion
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
            guard let self, !self.completed else { return }
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
            finish(.success(()))
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
                            self.finish(.success(()))
                        } else {
                            self.finish(.failure(PreflightError.authentication))
                        }
                    }
                }
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

    var errorDescription: String? {
        switch self {
        case let .connection(detail): return "cannot connect to SOCKS5 upstream: \(detail)"
        case .authentication: return "SOCKS5 upstream rejected the configured authentication method"
        case .invalidReply: return "upstream did not return a valid SOCKS5 greeting"
        case .closed: return "SOCKS5 upstream closed the connection during negotiation"
        case .timeout: return "SOCKS5 upstream did not respond within 5 seconds"
        }
    }
}
