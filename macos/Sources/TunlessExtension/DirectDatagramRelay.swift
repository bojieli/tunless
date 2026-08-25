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
    /// Serialises writes into the flow.
    ///
    /// `NEAppProxyUDPFlow.writeDatagrams` must not be called again until its
    /// completion handler runs, and the flow already has a writer: the pump
    /// relaying the upstream's replies. Replies from here would interleave with
    /// it, so every write goes through one channel that keeps at most one
    /// outstanding.
    private var writing = false
    private var pending: [(Data, Network.NWEndpoint)] = []
    /// How many replies may wait for the flow to accept them.
    ///
    /// The queue exists because only one write may be outstanding, so a sender
    /// faster than the flow drains would otherwise grow it without limit and
    /// turn one busy socket into unbounded memory inside the extension. Past
    /// this point the oldest reply is dropped: these are datagrams, the sender
    /// already has to tolerate loss, and dropping the stale one keeps the
    /// answers that are still worth having.
    private let maxPending = 64
    private var droppedReplies = 0

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
        pending.removeAll()
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
        connection.receiveMessage { [weak self] data, _, _, _ in
            guard let self, let data, !data.isEmpty,
                  let port = Network.NWEndpoint.Port(rawValue: destination.port) else { return }
            // The reply is addressed from the destination the sender used, so a
            // connected socket accepts it as an answer to what it asked.
            let endpoint = Network.NWEndpoint.hostPort(
                host: Network.NWEndpoint.Host(destination.host), port: port)
            Task {
                await self.enqueue((data, endpoint), into: flow)
                await deadline.touch()
            }
        }
    }

    /// Queues one datagram and starts the writer if it is idle.
    private func enqueue(_ datagram: (Data, Network.NWEndpoint), into flow: NEAppProxyUDPFlow) {
        guard !cancelled else { return }
        pending.append(datagram)
        if pending.count > maxPending {
            pending.removeFirst(pending.count - maxPending)
            droppedReplies += 1
        }
        guard !writing else { return }
        writing = true
        drain(into: flow)
    }

    private func drain(into flow: NEAppProxyUDPFlow) {
        guard !pending.isEmpty, !cancelled else {
            writing = false
            return
        }
        let batch = pending
        pending.removeAll(keepingCapacity: true)
        flow.writeDatagrams(batch) { [weak self] _ in
            Task { await self?.drain(into: flow) }
        }
    }
}
