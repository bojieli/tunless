import Foundation
import Network
import NetworkExtension
import os

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
        let survivesCapturePause: Bool

        init(flow: NEAppProxyFlow, task: Task<Void, Never>, survivesCapturePause: Bool) {
            self.flow = flow
            self.task = task
            self.survivesCapturePause = survivesCapturePause
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
    private var rejectedFlows: UInt64 = 0
    private let healthQueue = DispatchQueue(label: "com.bojieli.tunless.capture-health")
    /// How often the provider re-proves that the upstream still resolves.
    private static let healthIntervalSeconds = 30
    private static let log = Logger(subsystem: "com.bojieli.tunless", category: "capture")

    /// The executable behind a flow, resolved from its audit token.
    ///
    /// `sourceAppSigningIdentifier` is what the flow metadata hands over, and
    /// for unbundled binaries it is a toolchain default shared by unrelated
    /// programs. The audit token carries the process itself, so ask the kernel
    /// what that process is running. Best effort by construction: a process
    /// that exited between opening the flow and this lookup resolves to
    /// nothing, and selection falls back to the signing identifier.
    static func executablePath(auditToken: Data?) -> String? {
        guard let auditToken, auditToken.count == MemoryLayout<audit_token_t>.size else { return nil }
        let pid = auditToken.withUnsafeBytes { raw -> pid_t in
            // audit_token_t is eight words and the process id is the sixth,
            // which is what audit_token_to_pid reads.
            let words = raw.bindMemory(to: UInt32.self)
            return pid_t(bitPattern: words[5])
        }
        guard pid > 0 else { return nil }
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(cString: buffer)
    }

    /// True while capture is standing aside and flows should go direct.
    private func decliningFlows() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return health.shouldDeclineFlows
    }

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
    /// fix. So capture is treated as a claim that has to keep being true: it is
    /// armed on a probation window, re-proved on a timer, and stood down
    /// automatically when the proof stops holding — then stood back up when it
    /// holds again.
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
    private func observeHealth(outcome: DNSProbeOutcome, pathSatisfied: Bool) -> CaptureHealth.Decision {
        lock.lock()
        defer { lock.unlock() }
        return health.observe(
            succeeded: outcome.healthy,
            detail: outcome.detail,
            pathSatisfied: pathSatisfied,
            at: Date())
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
        apply(probation)
        Task { [weak self] in
            guard let self else { return }
            let outcome = await DNSHealthProbe.run(configuration: selected)
            self.apply(self.observeHealth(outcome: outcome, pathSatisfied: satisfied))
        }
    }

    /// The system is about to sleep.
    ///
    /// Sleep takes the network down, so every probe from here until the wake
    /// would fail for a reason that has nothing to do with the upstream.
    /// Believing them pauses capture at the exact moment nothing is using it,
    /// and the pause then outlives the sleep — which is how a laptop wakes with
    /// its DNS unprotected and nothing on screen to say so.
    public override func sleep(completionHandler: @escaping () -> Void) {
        lock.lock()
        health.systemWillSleep()
        lock.unlock()
        completionHandler()
    }

    /// The system woke. Interfaces, routes, and the upstream's own connections
    /// come back over several seconds, so probe results are ignored for a grace
    /// period rather than counted against the upstream.
    public override func wake() {
        lock.lock()
        health.systemDidWake(at: Date())
        lock.unlock()
    }

    private func apply(_ decision: CaptureHealth.Decision) {
        switch decision {
        case .unchanged: break
        case let .pause(reason): standDown(reason)
        case .resume: standUp()
        }
    }

    /// Stops claiming new flows and tears down streams in flight.
    ///
    /// This is a pause, not a shutdown. Declining a flow hands it back to the
    /// kernel, which routes it as though tunless were not installed, so the
    /// host recovers exactly as it would if the provider had died — while the
    /// provider stays alive to keep probing and to say why. Cancelling the
    /// tunnel instead would end the session that does the probing, leaving
    /// nothing able to notice the upstream coming back and nothing holding the
    /// explanation.
    private func standDown(_ reason: String) {
        lock.lock()
        guard !stopping else {
            lock.unlock()
            return
        }
        let records = Array(activeFlows.values)
        lock.unlock()
        // Streams already relaying through an upstream that cannot carry them
        // are not going to recover; closing them lets applications retry, and
        // the retry goes direct. Keep datagram flows alive, though. macOS owns
        // long-lived UDP resolver sockets and continues using them after a
        // transparent-proxy flow is error-closed. The subsequent send then
        // fails locally with EINVAL, so getaddrinfo hangs even though a fresh
        // `dig` socket works. Their pump observes the paused health state and
        // carries new datagrams directly until the upstream recovers.
        for record in records where !record.survivesCapturePause {
            record.flow.closeReadWithError(SOCKSError.closed)
            record.flow.closeWriteWithError(SOCKSError.closed)
            record.task.cancel()
        }
        note("capture paused: \(reason). Flows now go direct; capture resumes"
            + " automatically when the upstream resolves again")
    }

    private func standUp() {
        note("capture resumed: the upstream is resolving names again")
    }

    /// Records something that must outlive the provider.
    ///
    /// The first version of this wrote only to the telemetry buffer and then
    /// cancelled the provider, which threw that buffer away — so the one
    /// message explaining why the host lost capture was destroyed by the act of
    /// losing it. Log first, and to a place that survives.
    private func note(_ message: String) {
        Self.log.notice("\(message, privacy: .public)")
        appendTelemetry(FlowTelemetry(
            protocolName: "capture",
            destination: configurationSnapshot().upstreamHost,
            routedDestination: nil,
            hostname: nil,
            signingIdentifier: "tunless",
            executablePath: nil,
            timestamp: Date(),
            event: message))
    }

    /// Health as the launcher reports it, so a paused capture is visible in
    /// `status` instead of looking like a healthy connected session.
    private func healthSnapshot() -> Data? {
        lock.lock()
        let snapshot = CaptureHealthReport(
            capturing: !health.shouldDeclineFlows,
            pauseReason: health.pauseReason,
            confirmed: health.confirmed,
            consecutiveFailures: health.consecutiveFailures,
            activeFlows: activeFlows.count,
            rejectedFlows: rejectedFlows)
        lock.unlock()
        return try? JSONEncoder().encode(snapshot)
    }

    public override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        stopHealthWatchdog()
        lock.lock()
        stopping = true
        let records = Array(activeFlows.values)
        lock.unlock()
        for record in records {
            // UDP sockets, especially mDNSResponder's resolver sockets, can
            // outlive this provider session. End their flow cleanly so macOS
            // replaces it instead of retaining an error-poisoned socket.
            let error: Error? = record.survivesCapturePause ? nil : SOCKSError.closed
            record.flow.closeReadWithError(error)
            record.flow.closeWriteWithError(error)
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
        guard !decliningFlows() else { return false }
        let selected = configurationSnapshot()
        let executablePath = Self.executablePath(auditToken: flow.metaData.sourceAppAuditToken)
        guard selected.captures(
            host: originalDestination.host,
            port: originalDestination.port,
            signingIdentifier: flow.metaData.sourceAppSigningIdentifier,
            executablePath: executablePath)
        else { return false }
        // Prefer the name the application asked for, but fall back to the
        // address when that name cannot be carried. A hostname longer than the
        // SOCKS5 length byte, or one carrying control characters, is not a
        // reason to fail the connection: the address is always encodable, and
        // reaching the destination on IP rules beats not reaching it.
        let routeHost = SOCKSAddress.usableHostname(tcp.remoteHostname) ?? originalDestination.host
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
        guard !decliningFlows() else { return false }
        let selected = configurationSnapshot()
        guard selected.captures(
            host: destination.host,
            port: destination.port,
            signingIdentifier: flow.metaData.sourceAppSigningIdentifier,
            executablePath: Self.executablePath(auditToken: flow.metaData.sourceAppAuditToken))
        else { return false }
        return launch(
            flow: flow,
            survivesCapturePause: DatagramFlowContinuity.survivesCapturePause,
            operation: { [weak self] in
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
            case .queryHealth:
                completionHandler?(healthSnapshot())
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

    private func launch(
        flow: NEAppProxyFlow,
        survivesCapturePause: Bool = false,
        operation: @escaping @Sendable () async -> Void
    ) -> Bool {
        lock.lock()
        guard !stopping else {
            lock.unlock()
            return false
        }
        let ceiling = configuration.flowCeiling
        if activeFlows.count >= ceiling {
            let total = rejectedFlows &+ 1
            rejectedFlows = total
            lock.unlock()
            // Log the first rejection and powers of two, so a local connection
            // flood cannot turn the safety limit into an unbounded log flood.
            if total == 1 || total & (total - 1) == 0 {
                Self.log.notice(
                    "flow rejected at the concurrency ceiling \(ceiling, privacy: .public); rejected \(total, privacy: .public) so far. Rejected flows go direct")
            }
            return false
        }
        let identifier = UUID()
        let task = Task { [weak self] in
            await operation()
            self?.finishFlow(identifier)
        }
        activeFlows[identifier] = ActiveFlow(
            flow: flow, task: task, survivesCapturePause: survivesCapturePause)
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
            // mDNSResponder keeps its UDP resolver sockets for much longer
            // than an individual lookup. Expiring the provider flow underneath
            // one leaves macOS reusing a socket whose proxy flow no longer
            // exists; its later sends fail with EINVAL instead of opening a new
            // flow. Ordinary UDP retains the bounded two-minute association.
            let deadline = InactivityDeadline(
                timeoutSeconds: DatagramFlowContinuity.idleTimeoutSeconds(
                    for: initialDestination))
            let direct = DirectDatagramRelay()
            defer { Task { await direct.cancelAll() } }
            datagrams.start(queue: .global(qos: .userInitiated))
            event = await withTaskGroup(of: UDPPumpResult.self) { group -> String in
                group.addTask {
                    await self.appToUDP(
                        flow,
                        connection: datagrams,
                        configuration: configuration,
                        dnsResponses: dnsResponses,
                        deadline: deadline,
                        direct: direct)
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
                    flow.closeReadWithError(nil)
                    flow.closeWriteWithError(nil)
                    return "cancelled"
                }
            }
        } catch is CancellationError {
            event = "cancelled-during-setup"
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
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
            executablePath: Self.executablePath(auditToken: flow.metaData.sourceAppAuditToken),
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
            executablePath: Self.executablePath(auditToken: flow.metaData.sourceAppAuditToken),
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
        deadline: InactivityDeadline,
        direct: DirectDatagramRelay
    ) async -> UDPPumpResult {
        while !Task.isCancelled {
            do {
                let packets = try await readDatagrams(flow)
                if packets.isEmpty { return .applicationEOF("empty-read") }
                for (originalPayload, endpoint) in packets {
                    guard let originalAddress = Self.address(endpoint) else { continue }
                    // A flow that predates a watchdog pause cannot be handed
                    // back to the kernel without closing the application's
                    // socket. Keep it alive and reproduce the direct path here.
                    // The same route handles an unconnected socket that was
                    // admitted on one destination and later addresses a
                    // reserved one. Sending out of the extension is not itself
                    // captured, and the reply is written back as though the
                    // flow had never been claimed.
                    if DatagramFlowContinuity.routesDirect(
                        capturePaused: decliningFlows(),
                        destination: originalAddress,
                        configuration: configuration) {
                        await direct.send(
                            originalPayload,
                            to: originalAddress,
                            from: flow,
                            deadline: deadline)
                        record(flow: flow, destination: originalAddress, routedDestination: originalAddress)
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

/// The lifecycle rules that keep a macOS UDP socket usable across capture
/// transitions.
///
/// Network Extension owns the proxy flow, but the application still owns the
/// socket above it. In particular, mDNSResponder reuses resolver sockets. An
/// error or idle timeout below one does not make mDNSResponder replace it; the
/// next send fails with EINVAL. Datagram flows therefore stay admitted while
/// capture is paused and send directly for that interval, and port-53 flows do
/// not get the generic association idle timeout.
enum DatagramFlowContinuity {
    static let survivesCapturePause = true
    private static let ordinaryIdleTimeoutSeconds: TimeInterval = 120

    static func idleTimeoutSeconds(for initialDestination: SOCKSAddress) -> TimeInterval {
        initialDestination.port == 53 ? 0 : ordinaryIdleTimeoutSeconds
    }

    static func routesDirect(
        capturePaused: Bool,
        destination: SOCKSAddress,
        configuration: ProviderConfiguration
    ) -> Bool {
        capturePaused || configuration.reservedDestination(
            host: destination.host, port: destination.port)
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
    private var nextPrune = Date.distantPast
    private let maxEntries: Int
    private let ttlSeconds: TimeInterval
    private let randomIdentifier: @Sendable () -> UInt16

    init(
        maxEntries: Int = 4096,
        ttlSeconds: TimeInterval = 30,
        randomIdentifier: @escaping @Sendable () -> UInt16 = {
            UInt16.random(in: UInt16.min ... UInt16.max)
        }
    ) {
        self.maxEntries = maxEntries
        self.ttlSeconds = ttlSeconds
        self.randomIdentifier = randomIdentifier
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

    /// Picks the private transaction ID a rewritten query will carry.
    ///
    /// The ID has to be drawn at random, not counted out. A resolver client
    /// picks its own ID unpredictably so that an attacker who cannot see the
    /// query cannot forge an answer to it (RFC 5452); rewriting replaces that
    /// ID with this one, so anything less than the same unpredictability hands
    /// every captured lookup on the machine a weaker answer than it would have
    /// had unproxied.
    private func allocateID() -> UInt16? {
        // Outstanding queries are bounded far below the 16-bit space, so the
        // first draw is almost always free.
        for _ in 0 ..< 8 {
            let candidate = randomIdentifier()
            if entries[candidate] == nil { return candidate }
        }
        // Reached only when the space is unusually crowded. Walk upward from a
        // random start rather than from zero, so even the fallback does not
        // settle into a sequence someone can follow.
        var candidate = randomIdentifier()
        for _ in 0 ... UInt16.max {
            if entries[candidate] == nil { return candidate }
            candidate &+= 1
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
