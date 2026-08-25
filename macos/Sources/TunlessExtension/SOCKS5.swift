import Foundation
import Network

enum SOCKSError: Error {
    case invalidAddress
    case invalidReply
    case rejected(UInt8)
    case authentication
    case closed
    case timeout(String)
}

final class AsyncResultGate<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Error>?
    private var pendingResult: Result<Value, Error>?
    private var completed = false

    @discardableResult
    func install(_ continuation: CheckedContinuation<Value, Error>) -> Bool {
        lock.lock()
        if let pendingResult {
            completed = true
            self.pendingResult = nil
            lock.unlock()
            continuation.resume(with: pendingResult)
            return false
        }
        guard !completed else {
            lock.unlock()
            return false
        }
        self.continuation = continuation
        lock.unlock()
        return true
    }

    func resume(with result: Result<Value, Error>) {
        lock.lock()
        guard !completed else {
            lock.unlock()
            return
        }
        if let continuation {
            completed = true
            self.continuation = nil
            lock.unlock()
            continuation.resume(with: result)
            return
        }
        guard pendingResult == nil else {
            lock.unlock()
            return
        }
        pendingResult = result
        lock.unlock()
    }
}

struct SOCKSAddress: Equatable, Sendable {
    let host: String
    let port: UInt16

    /// The hostname if a SOCKS5 request can carry it, or nil if the caller
    /// should use the numeric address instead.
    ///
    /// The domain field has a single length byte, so anything past 255 bytes
    /// cannot be represented. The rest is about what a downstream proxy does
    /// with the value: a name carrying spaces, control bytes, or a NUL is
    /// either rejected or parsed as something other than what was sent.
    static func usableHostname(_ hostname: String?) -> String? {
        guard let hostname, !hostname.isEmpty else { return nil }
        let bytes = Data(hostname.utf8)
        guard bytes.count <= 255 else { return nil }
        guard !bytes.contains(where: { $0 <= 0x20 || $0 == 0x7f }) else { return nil }
        return hostname
    }

    func encoded() throws -> Data {
        var output = Data()
        if let address = IPv4Address(host) {
            output.append(1)
            output.append(contentsOf: address.rawValue)
        } else if let address = IPv6Address(host) {
            output.append(4)
            output.append(contentsOf: address.rawValue)
        } else {
            let bytes = Data(host.utf8)
            guard !bytes.isEmpty, bytes.count <= 255 else { throw SOCKSError.invalidAddress }
            output.append(3)
            output.append(UInt8(bytes.count))
            output.append(bytes)
        }
        output.append(UInt8(port >> 8))
        output.append(UInt8(port & 0xff))
        return output
    }

    static func decode(_ data: Data, offset: inout Int) throws -> SOCKSAddress {
        guard offset < data.count else { throw SOCKSError.invalidReply }
        let type = data[offset]
        offset += 1
        let host: String
        switch type {
        case 1:
            guard offset + 4 <= data.count, let address = IPv4Address(data[offset ..< offset + 4]) else {
                throw SOCKSError.invalidReply
            }
            host = address.debugDescription
            offset += 4
        case 4:
            guard offset + 16 <= data.count, let address = IPv6Address(data[offset ..< offset + 16]) else {
                throw SOCKSError.invalidReply
            }
            host = address.debugDescription
            offset += 16
        case 3:
            guard offset < data.count else { throw SOCKSError.invalidReply }
            let size = Int(data[offset])
            offset += 1
            guard size > 0, offset + size <= data.count else { throw SOCKSError.invalidReply }
            host = String(decoding: data[offset ..< offset + size], as: UTF8.self)
            offset += size
        default:
            throw SOCKSError.invalidReply
        }
        guard offset + 2 <= data.count else { throw SOCKSError.invalidReply }
        let port = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        offset += 2
        return SOCKSAddress(host: host, port: port)
    }
}

actor SOCKSConnection {
    private let connection: NWConnection
    private var buffered = Data()

    init(configuration: ProviderConfiguration) {
        connection = NWConnection(
            host: NWEndpoint.Host(configuration.upstreamHost),
            port: NWEndpoint.Port(rawValue: configuration.upstreamPort)!,
            using: .tcp)
    }

    func open(
        configuration: ProviderConfiguration,
        command: UInt8,
        destination: SOCKSAddress,
        timeoutSeconds: TimeInterval = 10
    ) async throws -> SOCKSAddress {
        connection.start(queue: .global(qos: .userInitiated))
        return try await withTaskCancellationHandler(operation: {
            try await withThrowingTaskGroup(of: SOCKSAddress.self) { group in
                group.addTask {
                    try await self.negotiate(configuration: configuration, command: command, destination: destination)
                }
                if timeoutSeconds > 0 {
                    group.addTask {
                        try await Task.sleep(nanoseconds: Self.nanoseconds(timeoutSeconds))
                        await self.cancel()
                        throw SOCKSError.timeout("SOCKS5 handshake")
                    }
                }
                defer { group.cancelAll() }
                guard let result = try await group.next() else { throw SOCKSError.closed }
                return result
            }
        }, onCancel: {
            self.connection.cancel()
        })
    }

    private func negotiate(
        configuration: ProviderConfiguration,
        command: UInt8,
        destination: SOCKSAddress
    ) async throws -> SOCKSAddress {
        try await ready()
        let hasCredentials = configuration.username != nil || configuration.password != nil
        try await send(Data([5, 1, hasCredentials ? 2 : 0]))
        let method = try await receive(2)
        guard method[0] == 5 else { throw SOCKSError.invalidReply }
        if method[1] == 2 {
            guard hasCredentials else { throw SOCKSError.authentication }
            let user = Data((configuration.username ?? "").utf8)
            let password = Data((configuration.password ?? "").utf8)
            guard user.count <= 255, password.count <= 255 else { throw SOCKSError.authentication }
            var authentication = Data([1, UInt8(user.count)])
            authentication.append(user)
            authentication.append(UInt8(password.count))
            authentication.append(password)
            try await send(authentication)
            let reply = try await receive(2)
            guard reply[0] == 1, reply[1] == 0 else { throw SOCKSError.authentication }
        } else if method[1] == 0 {
            guard !hasCredentials else { throw SOCKSError.authentication }
        } else {
            throw SOCKSError.authentication
        }

        var request = Data([5, command, 0])
        request.append(try destination.encoded())
        try await send(request)
        let header = try await receive(4)
        guard header[0] == 5 else { throw SOCKSError.invalidReply }
        guard header[1] == 0 else { throw SOCKSError.rejected(header[1]) }
        let addressLength: Int
        switch header[3] {
        case 1: addressLength = 4
        case 4: addressLength = 16
        case 3: addressLength = 1 + Int(try await receive(1)[0])
        default: throw SOCKSError.invalidReply
        }
        var addressData = Data([header[3]])
        if header[3] == 3 { addressData.append(UInt8(addressLength - 1)) }
        addressData.append(try await receive(addressLength + (header[3] == 3 ? -1 : 0) + 2))
        var offset = 0
        return try SOCKSAddress.decode(addressData, offset: &offset)
    }

    func send(_ data: Data) async throws {
        try Task.checkCancellation()
        let gate = AsyncResultGate<Void>()
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                guard gate.install(continuation) else { return }
                connection.send(content: data, completion: .contentProcessed { error in
                    if let error { gate.resume(with: .failure(error)) }
                    else { gate.resume(with: .success(())) }
                })
            }
        }, onCancel: {
            self.connection.cancel()
            gate.resume(with: .failure(CancellationError()))
        })
    }

    func finishSending() async throws {
        try Task.checkCancellation()
        let gate = AsyncResultGate<Void>()
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                guard gate.install(continuation) else { return }
                connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { error in
                    if let error { gate.resume(with: .failure(error)) }
                    else { gate.resume(with: .success(())) }
                })
            }
        }, onCancel: {
            self.connection.cancel()
            gate.resume(with: .failure(CancellationError()))
        })
    }

    func receive(_ count: Int) async throws -> Data {
        while buffered.count < count {
            buffered.append(try await receiveFromNetwork())
        }
        let value = buffered.prefix(count)
        buffered.removeFirst(count)
        return Data(value)
    }

    func receiveSome() async throws -> Data {
        try Task.checkCancellation()
        if !buffered.isEmpty {
            let value = buffered
            buffered.removeAll(keepingCapacity: true)
            return value
        }
        return try await receiveFromNetwork()
    }

    func cancel() {
        connection.cancel()
    }

    private func receiveFromNetwork() async throws -> Data {
        try Task.checkCancellation()
        let gate = AsyncResultGate<Data>()
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                guard gate.install(continuation) else { return }
                connection.receive(minimumIncompleteLength: 1, maximumLength: 65535) { data, _, _, error in
                    if let error { gate.resume(with: .failure(error)) }
                    else if let data, !data.isEmpty { gate.resume(with: .success(data)) }
                    else { gate.resume(with: .failure(SOCKSError.closed)) }
                }
            }
        }, onCancel: {
            self.connection.cancel()
            gate.resume(with: .failure(CancellationError()))
        })
    }

    private func ready() async throws {
        try Task.checkCancellation()
        let gate = AsyncResultGate<Void>()
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                guard gate.install(continuation) else { return }
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        gate.resume(with: .success(()))
                    case .failed(let error):
                        gate.resume(with: .failure(error))
                    case .cancelled:
                        gate.resume(with: .failure(SOCKSError.closed))
                    default:
                        break
                    }
                }
            }
        }, onCancel: {
            self.connection.cancel()
            gate.resume(with: .failure(CancellationError()))
        })
        connection.stateUpdateHandler = nil
    }

    private nonisolated static func nanoseconds(_ seconds: TimeInterval) -> UInt64 {
        UInt64(min(max(seconds, 0), Double(UInt64.max) / 1_000_000_000) * 1_000_000_000)
    }
}
