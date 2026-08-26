import Foundation
import Network
import NetworkExtension

/// Carries datagrams that capture cannot relay, straight out of the extension.
///
/// Capture declines a flow by handing it back, and the kernel then routes it as
/// though tunless were not installed. A datagram inside an already-accepted
/// flow has no equivalent: the flow belongs to the provider, so a destination
/// the provider must not relay — or cannot relay, because the upstream is not
/// answering — has nowhere to go. Dropping it is the easy answer and the wrong
/// one; ending the flow instead is worse still, because the application's
/// socket does not survive that. So send it the way the kernel would have.
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
    private let sink: any DatagramSink
    private var connections: [String: NWConnection] = [:]
    private var cancelled = false

    /// Most destinations one flow may reach directly.
    ///
    /// A flow that addresses more destinations than this through here is not a
    /// resolver client; the cap keeps a misbehaving sender from turning one
    /// captured flow into an unbounded number of sockets.
    private let maxDestinations = 16

    init(sink: any DatagramSink) {
        self.sink = sink
    }

    func send(_ payload: Data, to destination: SOCKSAddress) async {
        guard !cancelled, let connection = connection(for: destination) else { return }
        connection.send(content: payload, completion: .contentProcessed { _ in })
        receive(on: connection, from: destination)
    }

    func cancelAll() {
        cancelled = true
        for connection in connections.values { connection.cancel() }
        connections.removeAll()
    }

    private func connection(for destination: SOCKSAddress) -> NWConnection? {
        let key = "\(destination.host):\(destination.port)"
        if let existing = connections[key] { return existing }
        guard connections.count < maxDestinations,
              let port = Network.NWEndpoint.Port(rawValue: destination.port) else { return nil }
        let connection = NWConnection(
            host: NWEndpoint.Host(destination.host), port: port, using: .udp)
        connections[key] = connection
        connection.start(queue: .global(qos: .utility))
        return connection
    }

    /// Waits for one reply and hands it to the flow's writer, addressed from
    /// the destination the sender used so connected-datagram semantics hold.
    private nonisolated func receive(on connection: NWConnection, from destination: SOCKSAddress) {
        connection.receiveMessage { [weak self] data, _, _, _ in
            guard let self, let data, !data.isEmpty else { return }
            Task { await self.forward(data, from: destination) }
        }
    }

    private func forward(_ payload: Data, from destination: SOCKSAddress) async {
        guard !cancelled else { return }
        await sink.write(payload, from: destination)
    }
}
