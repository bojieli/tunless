import Foundation
import Network
import NetworkExtension

public final class TransparentProxyProvider: NETransparentProxyProvider, NEAppProxyUDPFlowHandling {
    private enum PumpResult {
        case applicationEOF(String)
        case networkEOF
        case failed(String)
        case idleTimeout
        case halfCloseTimeout
        case cancelled
    }

    private enum UDPPumpResult {
        case applicationEOF(String)
        case networkEOF(String)
        case controlEOF
        case failed(String)
        case idleTimeout
        case cancelled
    }

    private final class ActiveFlow {
        let flow: NEAppProxyFlow
        let task: Task<Void, Never>

        init(flow: NEAppProxyFlow, task: Task<Void, Never>) {
            self.flow = flow
            self.task = task
        }
    }

    private var configuration = ProviderConfiguration(upstreamHost: "127.0.0.1", upstreamPort: 7890)
    private var telemetry: [FlowTelemetry] = []
    private var activeFlows: [UUID: ActiveFlow] = [:]
    private var stopping = false
    private let lock = NSLock()
    private var health = CaptureHealth()
    private var healthTimer: DispatchSourceTimer?
    private var pathMonitor: NWPathMonitor?
    private var pathIsSatisfied = true
    private let healthQueue = DispatchQueue(label: "com.bojieli.tunless.capture-health")
    /// How often the provider re-proves that the upstream still resolves.
    private static let healthIntervalSeconds = 30

    public override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        guard
            let dictionary = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
            let raw = dictionary["configuration"] as? Data,
            let parsed = try? JSONDecoder().decode(ProviderConfiguration.self, from: raw),
            let validated = try? parsed.validated()
        else {
            completionHandler(ConfigurationError.invalidUpstream)
            return
        }
        lock.lock()
        configuration = validated
        stopping = false
        lock.unlock()

        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let anyPort = NWEndpoint.Port(rawValue: 0)!
        // A transparent-proxy rule cannot combine an any-port endpoint with a
        // wildcard address. Non-zero hosts masked to /1 cover both IP families.
        settings.includedNetworkRules = [
            NENetworkRule(destinationNetworkEndpoint: .hostPort(host: "0.0.0.1", port: anyPort), prefix: 1, protocol: .any),
            NENetworkRule(destinationNetworkEndpoint: .hostPort(host: "128.0.0.1", port: anyPort), prefix: 1, protocol: .any),
            NENetworkRule(destinationNetworkEndpoint: .hostPort(host: "::2", port: anyPort), prefix: 1, protocol: .any),
            NENetworkRule(destinationNetworkEndpoint: .hostPort(host: "8000::1", port: anyPort), prefix: 1, protocol: .any),
        ]
        setTunnelNetworkSettings(settings) { [weak self] error in
            if error == nil { self?.startHealthWatchdog() }
            completionHandler(error)
        }
    }

    /// Starts the watchdog that keeps capture accountable for the network it
    /// took over.
    ///
    /// A provider that dies is harmless: the flows it was holding go direct
    /// again. A provider that stays up while its upstream stops resolving is
    /// not, because every name lookup on the host now fails through it, and a
    /// host that cannot resolve cannot fetch, install, or read its way to the
    /// fix. So capture is treated as a claim that has to keep being true: it
    /// is armed on a probation window the launcher must confirm, then re-proved
    /// on a timer, and handed back automatically when the proof stops holding.
    private func startHealthWatchdog() {
        guard configurationSnapshot().disableHealthWatchdog != true else { return }
        lock.lock()
        health.arm(at: Date())
        lock.unlock()

        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            self.lock.lock()
            self.pathIsSatisfied = path.status == .satisfied
            self.lock.unlock()
        }
        monitor.start(queue: healthQueue)
        pathMonitor = monitor

        let timer = DispatchSource.makeTimerSource(queue: healthQueue)
        timer.schedule(
            deadline: .now() + .seconds(Self.healthIntervalSeconds),
            repeating: .seconds(Self.healthIntervalSeconds))
        timer.setEventHandler { [weak self] in self?.runHealthCheck() }
        timer.resume()
        healthTimer = timer
    }

    /// Records a probe result under the lock. Kept out of the async caller so
    /// the lock is never held across a suspension point.
    private func observeHealth(succeeded: Bool, pathSatisfied: Bool) -> CaptureHealth.Decision {
        lock.lock()
        defer { lock.unlock() }
        return health.observe(succeeded: succeeded, pathSatisfied: pathSatisfied, at: Date())
    }

    private func stopHealthWatchdog() {
        healthTimer?.cancel()
        healthTimer = nil
        pathMonitor?.cancel()
        pathMonitor = nil
    }

    private func runHealthCheck() {
        lock.lock()
        let selected = configuration
        let satisfied = pathIsSatisfied
        let probation = health.probationDecision(at: Date())
        let stoppingNow = stopping
        lock.unlock()
        guard !stoppingNow else { return }
        if case let .release(reason) = probation {
            release(reason)
            return
        }
        Task { [weak self] in
            guard let self else { return }
            let succeeded = await DNSHealthProbe.run(configuration: selected)
            if case let .release(reason) = self.observeHealth(
                succeeded: succeeded, pathSatisfied: satisfied) {
                self.release(reason)
            }
        }
    }

    /// Gives the network back. Stopping the tunnel is what un-captures the
    /// host, so this is the recovery, not merely the report of a problem.
    private func release(_ reason: String) {
        lock.lock()
        guard !stopping else {
            lock.unlock()
            return
        }
        stopping = true
        lock.unlock()
        appendTelemetry(FlowTelemetry(
            protocolName: "capture",
            destination: configurationSnapshot().upstreamHost,
            routedDestination: nil,
            hostname: nil,
            signingIdentifier: "tunless",
            timestamp: Date(),
            event: "released: \(reason)"))
        NSLog("tunless: releasing capture: %@", reason)
        cancelProxyWithError(CaptureReleased(reason: reason))
    }

    public override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stopHealthWatchdog()
        lock.lock()
        stopping = true
        let records = Array(activeFlows.values)
        lock.unlock()
        for record in records {
            record.flow.closeReadWithError(SOCKSError.closed)
            record.flow.closeWriteWithError(SOCKSError.closed)
            record.task.cancel()
        }
        Task {
            for record in records { await record.task.value }
            completionHandler()
        }
    }

    public override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard
            let tcp = flow as? NEAppProxyTCPFlow,
            let originalDestination = Self.address(tcp.remoteFlowEndpoint)
        else { return false }
        let selected = configurationSnapshot()
        guard selected.captures(
            host: originalDestination.host,
            port: originalDestination.port,
            signingIdentifier: flow.metaData.sourceAppSigningIdentifier)
        else { return false }
        let routeHost = (tcp.remoteHostname?.isEmpty == false ? tcp.remoteHostname : nil) ?? originalDestination.host
        let requestedDestination = SOCKSAddress(host: routeHost, port: originalDestination.port)
        let routedDestination = selected.routedDestination(for: requestedDestination)
        guard launch(flow: flow, operation: { [weak self] in
            await self?.handleTCP(
                tcp,
                originalDestination: originalDestination,
                routedDestination: routedDestination,
                configuration: selected)
        }) else { return false }
        record(flow: flow, destination: originalDestination, routedDestination: routedDestination)
        return true
    }

    public func handleNewUDPFlow(
        _ flow: NEAppProxyUDPFlow,
        initialRemoteFlowEndpoint remoteEndpoint: Network.NWEndpoint
    ) -> Bool {
        guard let destination = Self.address(remoteEndpoint) else { return false }
        let selected = configurationSnapshot()
        guard selected.captures(
            host: destination.host,
            port: destination.port,
            signingIdentifier: flow.metaData.sourceAppSigningIdentifier)
        else { return false }
        return launch(flow: flow, operation: { [weak self] in
            await self?.handleUDP(flow, initialDestination: destination, configuration: selected)
        })
    }

    public override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        if messageData.isEmpty {
            lock.lock()
            let snapshot = telemetry
            telemetry.removeAll(keepingCapacity: true)
            lock.unlock()
            completionHandler?(try? JSONEncoder().encode(snapshot))
            return
        }
        if let control = ControlMessage.decode(messageData) {
            switch control {
            case .confirmHealthy:
                lock.lock()
                health.confirm()
                lock.unlock()
                completionHandler?(Data([1]))
            }
            return
        }
        guard
            let updated = try? JSONDecoder().decode(ProviderConfiguration.self, from: messageData),
            let validated = try? updated.validated()
        else {
            completionHandler?(nil)
            return
        }
        lock.lock()
        configuration = validated
        lock.unlock()
        completionHandler?(Data([1]))
    }

    private func launch(flow: NEAppProxyFlow, operation: @escaping @Sendable () async -> Void) -> Bool {
        lock.lock()
        guard !stopping else {
            lock.unlock()
            return false
        }
        let identifier = UUID()
        let task = Task { [weak self] in
            await operation()
            self?.finishFlow(identifier)
        }
        activeFlows[identifier] = ActiveFlow(flow: flow, task: task)
        lock.unlock()
        return true
    }

    private func finishFlow(_ identifier: UUID) {
        lock.lock()
        activeFlows.removeValue(forKey: identifier)
        lock.unlock()
    }

    private func handleTCP(
        _ flow: NEAppProxyTCPFlow,
        originalDestination: SOCKSAddress,
        routedDestination: SOCKSAddress,
        configuration: ProviderConfiguration
    ) async {
        var socks: SOCKSConnection?
        var event: String
        do {
            try Task.checkCancellation()
            try await open(flow)
            try Task.checkCancellation()
            let connection = SOCKSConnection(configuration: configuration)
            socks = connection
            _ = try await connection.open(
                configuration: configuration,
                command: 1,
                destination: routedDestination,
                timeoutSeconds: 10)
            let deadline = InactivityDeadline(timeoutSeconds: 300)
            event = await withTaskGroup(of: PumpResult.self) { group -> String in
                group.addTask { await Self.appToNetwork(flow, socks: connection, deadline: deadline) }
                group.addTask { await Self.networkToApp(socks: connection, flow: flow, deadline: deadline) }
                group.addTask { await deadline.waitForExpiry() ? .idleTimeout : .cancelled }
                var applicationEnded = false
                while let result = await group.next() {
                    switch result {
                    case .applicationEOF(let detail):
                        guard !applicationEnded else { continue }
                        applicationEnded = true
                        do {
                            try await connection.finishSending()
                            await deadline.touch()
                            group.addTask {
                                do {
                                    try await Task.sleep(nanoseconds: 30_000_000_000)
                                    return .halfCloseTimeout
                                } catch {
                                    return .cancelled
                                }
                            }
                        } catch {
                            flow.closeReadWithError(error)
                            flow.closeWriteWithError(error)
                            await connection.cancel()
                            group.cancelAll()
                            return "half-close-error:\(detail):\(error)"
                        }
                    case .networkEOF:
                        flow.closeWriteWithError(nil)
                        flow.closeReadWithError(nil)
                        await connection.cancel()
                        group.cancelAll()
                        return applicationEnded ? "application-half-close-then-network-eof" : "network-eof-first"
                    case .failed(let detail):
                        flow.closeWriteWithError(SOCKSError.closed)
                        flow.closeReadWithError(SOCKSError.closed)
                        await connection.cancel()
                        group.cancelAll()
                        return "failed:\(detail)"
                    case .idleTimeout:
                        let error = SOCKSError.timeout("TCP flow idle")
                        flow.closeWriteWithError(error)
                        flow.closeReadWithError(error)
                        await connection.cancel()
                        group.cancelAll()
                        return "idle-timeout"
                    case .halfCloseTimeout:
                        let error = SOCKSError.timeout("TCP half-close drain")
                        flow.closeWriteWithError(error)
                        flow.closeReadWithError(error)
                        await connection.cancel()
                        group.cancelAll()
                        return "half-close-timeout"
                    case .cancelled:
                        flow.closeWriteWithError(SOCKSError.closed)
                        flow.closeReadWithError(SOCKSError.closed)
                        await connection.cancel()
                        group.cancelAll()
                        return "cancelled"
                    }
                }
                return "no-pump-result"
            }
        } catch is CancellationError {
            event = "cancelled-during-setup"
            flow.closeReadWithError(SOCKSError.closed)
            flow.closeWriteWithError(SOCKSError.closed)
        } catch {
            event = "setup-error:\(error)"
            flow.closeReadWithError(error)
            flow.closeWriteWithError(error)
        }
        if let socks { await socks.cancel() }
        recordCompletion(
            flow: flow,
            protocolName: "tcp-completion",
            destination: originalDestination,
            routedDestination: routedDestination,
            event: event)
    }

    private func handleUDP(
        _ flow: NEAppProxyUDPFlow,
        initialDestination: SOCKSAddress,
        configuration: ProviderConfiguration
    ) async {
        var control: SOCKSConnection?
        var event: String
        let routedForTelemetry = configuration.routedDestination(for: initialDestination)
        do {
            try Task.checkCancellation()
            try await open(flow)
            let controlConnection = SOCKSConnection(configuration: configuration)
            control = controlConnection
            var relay = try await controlConnection.open(
                configuration: configuration,
                command: 3,
                destination: SOCKSAddress(host: "0.0.0.0", port: 0),
                timeoutSeconds: 10)
            if Self.unspecified(relay.host) || (Self.loopback(relay.host) && !Self.loopback(configuration.upstreamHost)) {
                relay = SOCKSAddress(host: configuration.upstreamHost, port: relay.port)
            }
            guard relay.port > 0, IPv4Address(relay.host) != nil || IPv6Address(relay.host) != nil else {
                throw SOCKSError.invalidAddress
            }
            let datagrams = NWConnection(
                host: NWEndpoint.Host(relay.host),
                port: NWEndpoint.Port(rawValue: relay.port)!,
                using: .udp)
            let dnsResponses = DNSResponseMap(maxEntries: 4096, ttlSeconds: 30)
            let deadline = InactivityDeadline(timeoutSeconds: 120)
            datagrams.start(queue: .global(qos: .userInitiated))
            event = await withTaskGroup(of: UDPPumpResult.self) { group -> String in
                group.addTask {
                    await self.appToUDP(
                        flow,
                        connection: datagrams,
                        configuration: configuration,
                        dnsResponses: dnsResponses,
                        deadline: deadline)
                }
                group.addTask {
                    await self.udpToApp(
                        datagrams,
                        flow: flow,
                        dnsResponses: dnsResponses,
                        deadline: deadline)
                }
                group.addTask {
                    do {
                        _ = try await controlConnection.receiveSome()
                        return .failed("unexpected-control-data")
                    } catch SOCKSError.closed {
                        return Task.isCancelled ? .cancelled : .controlEOF
                    } catch {
                        return Task.isCancelled ? .cancelled : .failed("control:\(error)")
                    }
                }
                group.addTask { await deadline.waitForExpiry() ? .idleTimeout : .cancelled }
                guard let result = await group.next() else { return "no-pump-result" }
                datagrams.cancel()
                await controlConnection.cancel()
                group.cancelAll()
                switch result {
                case .applicationEOF(let detail):
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                    return "application-eof:\(detail)"
                case .networkEOF(let detail):
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                    return "network-eof:\(detail)"
                case .controlEOF:
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                    return "control-eof"
                case .failed(let detail):
                    flow.closeReadWithError(SOCKSError.closed)
                    flow.closeWriteWithError(SOCKSError.closed)
                    return "failed:\(detail)"
                case .idleTimeout:
                    let error = SOCKSError.timeout("UDP flow idle")
                    flow.closeReadWithError(error)
                    flow.closeWriteWithError(error)
                    return "idle-timeout"
                case .cancelled:
                    flow.closeReadWithError(SOCKSError.closed)
                    flow.closeWriteWithError(SOCKSError.closed)
                    return "cancelled"
                }
            }
        } catch is CancellationError {
            event = "cancelled-during-setup"
            flow.closeReadWithError(SOCKSError.closed)
            flow.closeWriteWithError(SOCKSError.closed)
        } catch {
            event = "setup-error:\(error)"
            flow.closeReadWithError(error)
            flow.closeWriteWithError(error)
        }
        if let control { await control.cancel() }
        recordCompletion(
            flow: flow,
            protocolName: "udp-completion",
            destination: initialDestination,
            routedDestination: routedForTelemetry,
            event: event)
    }

    private func record(flow: NEAppProxyFlow, destination: SOCKSAddress, routedDestination: SOCKSAddress) {
        let routed = routedDestination == destination ? nil : "\(routedDestination.host):\(routedDestination.port)"
        appendTelemetry(FlowTelemetry(
            protocolName: flow is NEAppProxyTCPFlow ? "tcp" : "udp",
            destination: "\(destination.host):\(destination.port)",
            routedDestination: routed,
            hostname: flow.remoteHostname,
            signingIdentifier: flow.metaData.sourceAppSigningIdentifier,
            timestamp: Date(),
            event: nil))
    }

    private func recordCompletion(
        flow: NEAppProxyFlow,
        protocolName: String,
        destination: SOCKSAddress,
        routedDestination: SOCKSAddress,
        event: String
    ) {
        let routed = routedDestination == destination ? nil : "\(routedDestination.host):\(routedDestination.port)"
        appendTelemetry(FlowTelemetry(
            protocolName: protocolName,
            destination: "\(destination.host):\(destination.port)",
            routedDestination: routed,
            hostname: flow.remoteHostname,
            signingIdentifier: flow.metaData.sourceAppSigningIdentifier,
            timestamp: Date(),
            event: event))
    }

    private func appendTelemetry(_ item: FlowTelemetry) {
        lock.lock()
        if telemetry.count >= 4096 { telemetry.removeFirst(1024) }
        telemetry.append(item)
        lock.unlock()
    }

    private func configurationSnapshot() -> ProviderConfiguration {
        lock.lock()
        defer { lock.unlock() }
        return configuration
    }

    private static func address(_ endpoint: Network.NWEndpoint) -> SOCKSAddress? {
        if case let .hostPort(host, port) = endpoint {
            return SOCKSAddress(host: host.debugDescription, port: port.rawValue)
        }
        return nil
    }

    private static func unspecified(_ host: String) -> Bool { host == "0.0.0.0" || host == "::" }

    private static func loopback(_ host: String) -> Bool {
        if host.lowercased() == "localhost" { return true }
        if let address = IPv4Address(host) { return address.rawValue.first == 127 }
        if let address = IPv6Address(host) { return address.rawValue == IPv6Address("::1")!.rawValue }
        return false
    }

    private func open(_ flow: NEAppProxyFlow) async throws {
        try Task.checkCancellation()
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                let gate = AsyncResultGate<Void>()
                try await withTaskCancellationHandler(operation: {
                    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                        guard gate.install(continuation) else { return }
                        flow.open(withLocalFlowEndpoint: nil) { error in
                            if let error { gate.resume(with: .failure(error)) }
                            else { gate.resume(with: .success(())) }
                        }
                    }
                }, onCancel: {
                    gate.resume(with: .failure(CancellationError()))
                })
            }
            group.addTask {
                try await Task.sleep(nanoseconds: 10_000_000_000)
                let error = SOCKSError.timeout("application flow open")
                flow.closeReadWithError(error)
                flow.closeWriteWithError(error)
                throw error
            }
            defer { group.cancelAll() }
            _ = try await group.next()
        }
    }

    private func readDatagrams(_ flow: NEAppProxyUDPFlow) async throws -> [(Data, Network.NWEndpoint)] {
        try Task.checkCancellation()
        let gate = AsyncResultGate<[(Data, Network.NWEndpoint)]>()
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                guard gate.install(continuation) else { return }
                flow.readDatagrams { packets, error in
                    if let error { gate.resume(with: .failure(error)) }
                    else { gate.resume(with: .success(packets ?? [])) }
                }
            }
        }, onCancel: {
            gate.resume(with: .failure(CancellationError()))
        })
    }

    private static func appToNetwork(
        _ flow: NEAppProxyTCPFlow,
        socks: SOCKSConnection,
        deadline: InactivityDeadline
    ) async -> PumpResult {
        while !Task.isCancelled {
            let data: Data
            do {
                data = try await readData(flow)
            } catch {
                let flowError = error as NSError
                if flowError.domain == "NEAppProxyFlowErrorDomain", flowError.code == 1 {
                    return .applicationEOF("flow-disconnected")
                }
                return Task.isCancelled ? .cancelled : .failed("application-read:\(error)")
            }
            if data.isEmpty { return .applicationEOF("empty-read") }
            do {
                try await socks.send(data)
                await deadline.touch()
            } catch {
                return Task.isCancelled ? .cancelled : .failed("upstream-send:\(error)")
            }
        }
        return .cancelled
    }

    private static func networkToApp(
        socks: SOCKSConnection,
        flow: NEAppProxyTCPFlow,
        deadline: InactivityDeadline
    ) async -> PumpResult {
        while !Task.isCancelled {
            do {
                let data = try await socks.receiveSome()
                try await write(data, to: flow)
                await deadline.touch()
            } catch SOCKSError.closed {
                return Task.isCancelled ? .cancelled : .networkEOF
            } catch {
                return Task.isCancelled ? .cancelled : .failed("network-pump:\(error)")
            }
        }
        return .cancelled
    }

    private func appToUDP(
        _ flow: NEAppProxyUDPFlow,
        connection: NWConnection,
        configuration: ProviderConfiguration,
        dnsResponses: DNSResponseMap,
        deadline: InactivityDeadline
    ) async -> UDPPumpResult {
        while !Task.isCancelled {
            do {
                let packets = try await readDatagrams(flow)
                if packets.isEmpty { return .applicationEOF("empty-read") }
                for (originalPayload, endpoint) in packets {
                    guard let originalAddress = Self.address(endpoint) else { continue }
                    // An unconnected socket admitted on one destination can
                    // later address a reserved one. Relaying that datagram
                    // would hand the upstream's own resolver traffic back to
                    // it, so drop it instead and let the sender retry; the
                    // admission check cannot see it, because it happens after
                    // the flow was already accepted.
                    if configuration.reservedDestination(
                        host: originalAddress.host, port: originalAddress.port) {
                        recordCompletion(
                            flow: flow,
                            protocolName: "udp-datagram",
                            destination: originalAddress,
                            routedDestination: originalAddress,
                            event: "reserved-destination-dropped")
                        continue
                    }
                    let routedAddress = originalPayload.count >= 12
                        ? configuration.routedDestination(for: originalAddress)
                        : originalAddress
                    let payload = await dnsResponses.prepare(
                        query: originalPayload,
                        original: originalAddress,
                        routed: routedAddress)
                    record(flow: flow, destination: originalAddress, routedDestination: routedAddress)
                    var frame = Data([0, 0, 0])
                    frame.append(try routedAddress.encoded())
                    frame.append(payload)
                    try await sendDatagram(frame, on: connection)
                    await deadline.touch()
                }
            } catch {
                return Task.isCancelled ? .cancelled : .failed("application-pump:\(error)")
            }
        }
        return .cancelled
    }

    private func sendDatagram(_ data: Data, on connection: NWConnection) async throws {
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
            gate.resume(with: .failure(CancellationError()))
        })
    }

    private func udpToApp(
        _ connection: NWConnection,
        flow: NEAppProxyUDPFlow,
        dnsResponses: DNSResponseMap,
        deadline: InactivityDeadline
    ) async -> UDPPumpResult {
        while !Task.isCancelled {
            do {
                let frame = try await receiveDatagram(connection)
                guard frame.count > 3, frame[0] == 0, frame[1] == 0, frame[2] == 0 else { continue }
                var offset = 3
                let source = try SOCKSAddress.decode(frame, offset: &offset)
                let payload = Data(frame[offset...])
                let restored = await dnsResponses.restore(response: payload, receivedFrom: source)
                guard let port = NWEndpoint.Port(rawValue: restored.source.port) else { throw SOCKSError.invalidAddress }
                let endpoint = NWEndpoint.hostPort(host: NWEndpoint.Host(restored.source.host), port: port)
                try await writeDatagrams([(restored.payload, endpoint)], to: flow)
                await deadline.touch()
            } catch SOCKSError.closed {
                return Task.isCancelled ? .cancelled : .networkEOF("closed")
            } catch {
                return Task.isCancelled ? .cancelled : .failed("network-pump:\(error)")
            }
        }
        return .cancelled
    }

    private static func readData(_ flow: NEAppProxyTCPFlow) async throws -> Data {
        try Task.checkCancellation()
        let gate = AsyncResultGate<Data>()
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                guard gate.install(continuation) else { return }
                flow.readData { data, error in
                    if let error { gate.resume(with: .failure(error)) }
                    else { gate.resume(with: .success(data ?? Data())) }
                }
            }
        }, onCancel: {
            gate.resume(with: .failure(CancellationError()))
        })
    }

    private static func write(_ data: Data, to flow: NEAppProxyTCPFlow) async throws {
        try Task.checkCancellation()
        let gate = AsyncResultGate<Void>()
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                guard gate.install(continuation) else { return }
                flow.write(data) { error in
                    if let error { gate.resume(with: .failure(error)) }
                    else { gate.resume(with: .success(())) }
                }
            }
        }, onCancel: {
            gate.resume(with: .failure(CancellationError()))
        })
    }

    private func receiveDatagram(_ connection: NWConnection) async throws -> Data {
        try Task.checkCancellation()
        let gate = AsyncResultGate<Data>()
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                guard gate.install(continuation) else { return }
                connection.receiveMessage { data, _, _, error in
                    if let error { gate.resume(with: .failure(error)) }
                    else if let data { gate.resume(with: .success(data)) }
                    else { gate.resume(with: .failure(SOCKSError.closed)) }
                }
            }
        }, onCancel: {
            gate.resume(with: .failure(CancellationError()))
        })
    }

    private func writeDatagrams(
        _ datagrams: [(Data, Network.NWEndpoint)],
        to flow: NEAppProxyUDPFlow
    ) async throws {
        try Task.checkCancellation()
        let gate = AsyncResultGate<Void>()
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                guard gate.install(continuation) else { return }
                flow.writeDatagrams(datagrams) { error in
                    if let error { gate.resume(with: .failure(error)) }
                    else { gate.resume(with: .success(())) }
                }
            }
        }, onCancel: {
            gate.resume(with: .failure(CancellationError()))
        })
    }
}

actor InactivityDeadline {
    private let timeoutSeconds: TimeInterval
    private var lastActivity = Date()

    init(timeoutSeconds: TimeInterval) {
        self.timeoutSeconds = timeoutSeconds
    }

    func touch() {
        lastActivity = Date()
    }

    func waitForExpiry() async -> Bool {
        guard timeoutSeconds > 0 else {
            do {
                try await Task.sleep(nanoseconds: UInt64.max)
            } catch {}
            return false
        }
        while !Task.isCancelled {
            let remaining = timeoutSeconds - Date().timeIntervalSince(lastActivity)
            if remaining <= 0 { return true }
            do {
                let nanoseconds = UInt64(min(remaining, Double(UInt64.max) / 1_000_000_000) * 1_000_000_000)
                try await Task.sleep(nanoseconds: nanoseconds)
            } catch {
                return false
            }
        }
        return false
    }
}

actor DNSResponseMap {
    struct RestoredResponse {
        let payload: Data
        let source: SOCKSAddress
    }

    private struct Entry {
        let originalID: UInt16
        let original: SOCKSAddress
        let routed: SOCKSAddress
        let expires: Date
    }

    private var entries: [UInt16: Entry] = [:]
    private var nextID: UInt16 = 0
    private var nextPrune = Date.distantPast
    private let maxEntries: Int
    private let ttlSeconds: TimeInterval

    init(maxEntries: Int = 4096, ttlSeconds: TimeInterval = 30) {
        self.maxEntries = maxEntries
        self.ttlSeconds = ttlSeconds
    }

    func prepare(query: Data, original: SOCKSAddress, routed: SOCKSAddress) -> Data {
        guard maxEntries > 0, routed != original, query.count >= 12 else { return query }
        let now = Date()
        prune(now: now)
        if entries.count >= maxEntries {
            prune(now: now, force: true)
            if entries.count >= maxEntries {
                // Evict a small oldest batch so a saturated map does not scan
                // every outstanding DNS request for every new datagram.
                evictOldest(count: max(1, maxEntries / 16))
            }
        }
        guard let translatedID = allocateID() else { return query }
        let originalID = Self.identifier(in: query)!
        entries[translatedID] = Entry(
            originalID: originalID,
            original: original,
            routed: routed,
            expires: now.addingTimeInterval(ttlSeconds))
        return Self.replacingIdentifier(in: query, with: translatedID)
    }

    func restore(response: Data, receivedFrom source: SOCKSAddress) -> RestoredResponse {
        guard response.count >= 12, let translatedID = Self.identifier(in: response) else {
            return RestoredResponse(payload: response, source: source)
        }
        let now = Date()
        guard let entry = entries[translatedID], now < entry.expires, entry.routed == source else {
            if let entry = entries[translatedID], now >= entry.expires {
                entries.removeValue(forKey: translatedID)
            }
            return RestoredResponse(payload: response, source: source)
        }
        entries.removeValue(forKey: translatedID)
        return RestoredResponse(
            payload: Self.replacingIdentifier(in: response, with: entry.originalID),
            source: entry.original)
    }

    func outstandingCount() -> Int { entries.count }

    private func allocateID() -> UInt16? {
        for _ in 0 ... UInt16.max {
            let candidate = nextID
            nextID &+= 1
            if entries[candidate] == nil { return candidate }
        }
        return nil
    }

    private func prune(now: Date, force: Bool = false) {
        guard force || now >= nextPrune else { return }
        entries = entries.filter { now < $0.value.expires }
        nextPrune = now.addingTimeInterval(1)
    }

    private func evictOldest(count: Int) {
        for entry in entries.sorted(by: { $0.value.expires < $1.value.expires }).prefix(count) {
            entries.removeValue(forKey: entry.key)
        }
    }

    private static func identifier(in message: Data) -> UInt16? {
        guard message.count >= 2 else { return nil }
        return UInt16(message[message.startIndex]) << 8 |
            UInt16(message[message.index(after: message.startIndex)])
    }

    private static func replacingIdentifier(in message: Data, with identifier: UInt16) -> Data {
        var copy = message
        copy[copy.startIndex] = UInt8(identifier >> 8)
        copy[copy.index(after: copy.startIndex)] = UInt8(identifier & 0xff)
        return copy
    }
}

/// Reported when the provider hands the network back on its own.
struct CaptureReleased: LocalizedError {
    let reason: String
    var errorDescription: String? {
        "tunless disabled capture to keep the host reachable: " + reason
    }
}
