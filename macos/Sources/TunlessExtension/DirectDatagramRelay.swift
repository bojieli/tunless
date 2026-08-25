import Foundation
import Network
import NetworkExtension

/// Carries datagrams that capture declined, straight out of the extension.
///
/// Capture declines a flow by handing it back, and the kernel then routes it as
/// though tunless were not installed. A datagram inside an already-accepted
/// flow has no equivalent: the flow belongs to the provider, so a destination
/// the provider must not relay has nowhere to go. Dropping it is the easy
/// answer and the wrong one — the sender waits for an answer that will never
/// come, and nothing anywhere reports why.
///
/// So send it the way the kernel would have. The extension's own traffic is not
/// captured, so a plain connection from here reaches the destination directly,
/// and the reply goes back into the flow addressed from the destination the
/// sender used. From the application's side that is indistinguishable from
/// never having been captured, which is exactly the promise capture makes when
/// it declines something.
///
/// One connection per destination, reused for as long as the flow lives, so a
/// resolver client that keeps asking the same server does not pay for a new
/// socket each time.
actor DirectDatagramRelay {
    private var connections: [String: NWConnection] = [:]
    private var cancelled = false

    /// Most destinations one flow may reach directly.
    ///
    /// A flow that addresses more reserved destinations than this is not a
    /// resolver client; the cap keeps a misbehaving sender from turning one
    /// captured flow into an unbounded number of sockets.
    private let maxDestinations = 16

    func send(
        _ payload: Data,
        to destination: SOCKSAddress,
        from flow: NEAppProxyUDPFlow,
        deadline: InactivityDeadline
    ) async {
        guard !cancelled, let connection = connection(for: destination) else { return }
        connection.send(content: payload, completion: .contentProcessed { _ in })
        receive(on: connection, from: destination, into: flow, deadline: deadline)
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

    /// Waits for one reply and writes it back into the flow, addressed from the
    /// destination the sender used so connected-datagram semantics hold.
    private nonisolated func receive(
        on connection: NWConnection,
        from destination: SOCKSAddress,
        into flow: NEAppProxyUDPFlow,
        deadline: InactivityDeadline
    ) {
        connection.receiveMessage { data, _, _, _ in
            guard let data, !data.isEmpty,
                  let port = Network.NWEndpoint.Port(rawValue: destination.port) else { return }
            let endpoint = Network.NWEndpoint.hostPort(
                host: Network.NWEndpoint.Host(destination.host), port: port)
            // The reply is addressed from the destination the sender used, so a
            // connected socket accepts it as an answer to what it asked.
            flow.writeDatagrams([(data, endpoint)]) { _ in }
            Task { await deadline.touch() }
        }
    }
}
