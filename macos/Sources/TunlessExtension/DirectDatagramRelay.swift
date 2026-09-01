import Foundation
import Network
import NetworkExtension

/// Carries datagrams that are intentionally outside SOCKS, straight out of the
/// extension.
///
/// Capture declines a flow by handing it back, and the kernel then routes it as
/// though tunless were not installed. A datagram inside an already-accepted
/// flow has no equivalent: the flow belongs to the provider, so a reserved,
/// loop-prevention, or split-horizon destination must be emitted here. An
/// upstream failure never reaches this actor; proxy-eligible datagrams remain
/// captured and are retried instead of being turned into direct traffic.
///
/// The extension's own traffic is not captured, so a plain connection from here
/// reaches the destination directly, and the reply goes back into the flow
/// addressed from the destination the sender used. From the application's side
/// that is indistinguishable from never having been captured, which is exactly
/// the promise capture makes when it declines something.
///
/// One connection per destination, reused for as long as the flow lives, so a
/// resolver client that keeps asking the same server does not pay for a new
/// socket each time.
actor DirectDatagramRelay {
    private struct LiveConnection {
        let connection: NWConnection
        let epoch: UInt64
    }

    private let sink: any DatagramSink
    private let networkEpoch: NetworkEpoch
    private let sendTimeoutSeconds: TimeInterval
    private var connections: [String: LiveConnection] = [:]
    private var cancelled = false

    /// Most destinations one flow may reach directly.
    ///
    /// A flow that addresses more destinations than this through here is not a
    /// resolver client; the cap keeps a misbehaving sender from turning one
    /// captured flow into an unbounded number of sockets.
    private let maxDestinations = 16

    init(
        sink: any DatagramSink,
        networkEpoch: NetworkEpoch = NetworkEpoch(),
        sendTimeoutSeconds: TimeInterval = 10
    ) {
        self.sink = sink
        self.networkEpoch = networkEpoch
        self.sendTimeoutSeconds = sendTimeoutSeconds
    }

    @discardableResult
    func send(_ payload: Data, to destination: SOCKSAddress) async -> Bool {
        await send(payload, to: destination, retryAfterNetworkChange: true)
    }

    private func send(
        _ payload: Data,
        to destination: SOCKSAddress,
        retryAfterNetworkChange: Bool
    ) async -> Bool {
        guard !cancelled, !Task.isCancelled,
              let live = connection(for: destination) else { return false }
        let connection = live.connection
        do {
            try await Self.send(
                payload, on: connection, timeoutSeconds: sendTimeoutSeconds)
        } catch {
            discard(connection, for: destination)
            return false
        }
        guard !cancelled, !Task.isCancelled else {
            discard(connection, for: destination)
            return false
        }
        guard networkEpoch.current == live.epoch else {
            discard(connection, for: destination)
            if retryAfterNetworkChange {
                return await send(
                    payload, to: destination, retryAfterNetworkChange: false)
            }
            return false
        }
        receive(on: connection, from: destination, epoch: live.epoch)
        return true
    }

    func cancelAll() {
        cancelled = true
        for live in connections.values { live.connection.cancel() }
        connections.removeAll()
    }

    private func connection(for destination: SOCKSAddress) -> LiveConnection? {
        let key = "\(destination.host):\(destination.port)"
        let currentEpoch = networkEpoch.current
        retireConnections(olderThan: currentEpoch)
        if let existing = connections[key] { return existing }
        guard connections.count < maxDestinations,
              let port = Network.NWEndpoint.Port(rawValue: destination.port) else { return nil }
        let connection = NWConnection(
            host: NWEndpoint.Host(destination.host), port: port, using: .udp)
        let live = LiveConnection(connection: connection, epoch: currentEpoch)
        connections[key] = live
        connection.start(queue: .global(qos: .utility))
        return live
    }

    /// Retires every socket pinned to a previous path before applying the
    /// per-flow destination cap.
    ///
    /// Checking only the requested destination leaves up to sixteen sockets
    /// from Wi-Fi occupying the pool after a switch to a hotspot. The first
    /// direct/local datagram on the new path then cannot allocate a socket even
    /// though none of the retained sockets is usable.
    private func retireConnections(olderThan currentEpoch: UInt64) {
        let stale = connections.compactMap { key, live in
            live.epoch == currentEpoch ? nil : (key, live.connection)
        }
        for (key, connection) in stale {
            connections.removeValue(forKey: key)
            connection.cancel()
        }
    }

    /// Observable for regression tests and diagnostics; the production cap is
    /// intentionally enforced inside `connection(for:)`.
    var activeDestinationCount: Int { connections.count }

    private func discard(_ connection: NWConnection, for destination: SOCKSAddress) {
        let key = "\(destination.host):\(destination.port)"
        if connections[key]?.connection === connection {
            connections.removeValue(forKey: key)
        }
        connection.cancel()
    }

    private nonisolated static func send(
        _ payload: Data,
        on connection: NWConnection,
        timeoutSeconds: TimeInterval
    ) async throws {
        try Task.checkCancellation()
        let gate = AsyncResultGate<Void>()
        let timeoutTask: Task<Void, Never>? = timeoutSeconds > 0 ? Task {
            do {
                try await Task.sleep(nanoseconds: nanoseconds(timeoutSeconds))
            } catch {
                return
            }
            guard !Task.isCancelled else { return }
            // Only the result that completes the gate may cancel the socket.
            // Otherwise a timer racing a successful send could destroy the
            // receive path after the caller has begun waiting for its reply.
            if gate.resume(with: .failure(SOCKSError.timeout("direct UDP send"))) {
                connection.cancel()
            }
        } : nil
        defer { timeoutTask?.cancel() }
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation {
                (continuation: CheckedContinuation<Void, Error>) in
                guard gate.install(continuation) else { return }
                connection.send(content: payload, completion: .contentProcessed { error in
                    if let error { gate.resume(with: .failure(error)) }
                    else { gate.resume(with: .success(())) }
                })
            }
        }, onCancel: {
            connection.cancel()
            gate.resume(with: .failure(CancellationError()))
        })
    }

    private nonisolated static func nanoseconds(_ seconds: TimeInterval) -> UInt64 {
        UInt64(min(max(seconds, 0), Double(UInt64.max) / 1_000_000_000) * 1_000_000_000)
    }

    /// Waits for one reply and hands it to the flow's writer, addressed from
    /// the destination the sender used so connected-datagram semantics hold.
    private nonisolated func receive(
        on connection: NWConnection,
        from destination: SOCKSAddress,
        epoch: UInt64
    ) {
        connection.receiveMessage { [weak self] data, _, _, _ in
            guard let self, let data, !data.isEmpty else { return }
            Task { await self.forward(data, from: destination, epoch: epoch) }
        }
    }

    private func forward(_ payload: Data, from destination: SOCKSAddress, epoch: UInt64) async {
        guard !cancelled, networkEpoch.current == epoch else { return }
        await sink.write(payload, from: destination)
    }
}
