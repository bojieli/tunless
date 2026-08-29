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
    /// Names learned from the DNS this provider relayed, used to give a flow
    /// back the hostname its application never told the kernel about.
    private let observedNames = ObservedNames()
    /// Transaction IDs currently relayed to the trusted resolver, which is what
    /// lets an application's own query to that resolver be captured without the
    /// upstream's forwarded copy closing a loop. See `ResolverLoopGuard`.
    private let resolverLoopGuard = ResolverLoopGuard()
    private var activeFlows: [UUID: ActiveFlow] = [:]
    private var stopping = false
    private let lock = NSLock()
    private var health = CaptureHealth()
    private var healthTimer: DispatchSourceTimer?
    private var pathMonitor: NWPathMonitor?
    private var pathIsSatisfied = true
    private var rejectedFlows: UInt64 = 0
    /// The resolver capture last carried a port-53 flow to, when no override is
    /// configured. See `DNSHealthProbe.CarriedResolver`.
    private var carriedResolver: DNSHealthProbe.CarriedResolver?
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
        let carried = carriedResolver
        lock.unlock()
        guard !stoppingNow else { return }
        apply(probation)
        Task { [weak self] in
            guard let self else { return }
            let outcome = await DNSHealthProbe.run(configuration: selected, carried: carried)
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
            // Streams are closed so the application sees the connection end
            // and retries, which now goes direct. Datagram flows are left
            // alone. Their sockets outlive this session — mDNSResponder holds
            // one resolver socket per delegated client for as long as it runs
            // — and a flow the provider closes is a socket macOS will not
            // reroute and will not replace: every later send on it fails
            // locally, so name resolution ends for that client until the
            // resolver is restarted. Ending the session releases the diverted
            // sockets; closing their flows first is what prevents that.
            if !record.survivesCapturePause {
                record.flow.closeReadWithError(SOCKSError.closed)
                record.flow.closeWriteWithError(SOCKSError.closed)
            }
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
        //
        // macOS supplies `remoteHostname` only for a name it resolved on the
        // application's behalf. An application with its own resolver — every
        // Chromium browser, Firefox, anything with a built-in DNS client —
        // never tells the kernel a name at all, so the flow arrives as a bare
        // address and everything the proxy decides by name is lost. Capture
        // relayed that application's query a moment ago, so ask what the answer
        // said before giving up and going out on the address.
        let routeHost =
            SOCKSAddress.usableHostname(tcp.remoteHostname)
            ?? SOCKSAddress.usableHostname(observedNames.lookup(host: originalDestination.host))
            ?? originalDestination.host
        let requestedDestination = SOCKSAddress(host: routeHost, port: originalDestination.port)
        let routedDestination = selected.routedDestination(for: requestedDestination)
        noteCarriedResolver(originalDestination, overUDP: false)
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
            executablePath: Self.executablePath(auditToken: flow.metaData.sourceAppAuditToken),
            isDatagram: true)
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

    /// Relays one datagram flow, for as long as the application keeps its
    /// socket open.
    ///
    /// The flow outlives the upstream on purpose. macOS hands a datagram flow
    /// to the provider once and does not hand it over again: a socket whose
    /// flow was closed underneath it is not re-captured and not released back
    /// to the kernel, it is finished, and every later send on it fails
    /// locally. `mDNSResponder` is the case that matters, because it holds one
    /// long-lived resolver socket per delegated client and never replaces it —
    /// so a flow closed under one of those sockets ends name resolution for
    /// that client until the daemon is restarted, while every other client on
    /// the host keeps resolving and hides the failure.
    ///
    /// An upstream that stops answering is therefore not a reason to end the
    /// flow. It is a reason to carry the datagrams the way the kernel would
    /// have, which is what capture already promises whenever it declines
    /// something, and to keep trying the upstream underneath. The flow ends
    /// when the application closes its socket, or when the provider stops.
    private func handleUDP(
        _ flow: NEAppProxyUDPFlow,
        initialDestination: SOCKSAddress,
        configuration: ProviderConfiguration
    ) async {
        let routedForTelemetry = configuration.routedDestination(for: initialDestination)
        let writer = FlowWriter(flow: flow)
        let direct = DirectDatagramRelay(sink: writer)
        let dnsResponses = DNSResponseMap(
            maxEntries: 4096, ttlSeconds: 30, observedNames: observedNames,
            loopGuard: resolverLoopGuard)
        // mDNSResponder keeps its UDP resolver sockets for much longer than an
        // individual lookup, so port-53 flows carry no association idle limit.
        // Ordinary UDP keeps the bounded two-minute one, which now retires the
        // upstream association rather than the flow above it.
        let association = UDPAssociation(
            configuration: configuration,
            sink: writer,
            dnsResponses: dnsResponses,
            idleTimeoutSeconds: DatagramFlowContinuity.idleTimeoutSeconds(for: initialDestination))
        var event: String
        do {
            try Task.checkCancellation()
            try await open(flow)
            event = await pumpDatagrams(
                flow,
                association: association,
                direct: direct,
                configuration: configuration,
                dnsResponses: dnsResponses)
        } catch is CancellationError {
            event = "cancelled-during-setup"
        } catch {
            event = "setup-error:\(error)"
        }
        await association.shutDown()
        await direct.cancelAll()
        await writer.cancel()
        // Nothing is closed here, with an error or without one. Every way this
        // loop ends is already a way the flow is over: the application closed
        // its socket, or the provider is stopping and Network Extension is
        // tearing its flows down itself. Closing on top of that is the one
        // thing that turns a recoverable moment into a permanently unusable
        // application socket, and a close the provider did not perform is a
        // close macOS can undo.
        recordCompletion(
            flow: flow,
            protocolName: "udp-completion",
            destination: initialDestination,
            routedDestination: routedForTelemetry,
            event: event)
    }

    /// Reads from the flow and places each datagram on the transport that can
    /// carry it. The single reader of the flow, and the only thing that ends
    /// it: everything below can fail and be rebuilt without the application
    /// seeing anything but a lost datagram, which UDP already tolerates.
    private func pumpDatagrams(
        _ flow: NEAppProxyUDPFlow,
        association: UDPAssociation,
        direct: DirectDatagramRelay,
        configuration: ProviderConfiguration,
        dnsResponses: DNSResponseMap
    ) async -> String {
        while !Task.isCancelled {
            let packets: [(Data, Network.NWEndpoint)]
            do {
                packets = try await readDatagrams(flow)
            } catch {
                if Task.isCancelled { return "cancelled" }
                let flowError = error as NSError
                if flowError.domain == "NEAppProxyFlowErrorDomain" {
                    return "application-eof:\(flowError.code)"
                }
                return "application-read:\(error)"
            }
            if packets.isEmpty { return "application-eof:empty-read" }
            for (payload, endpoint) in packets {
                guard let original = Self.address(endpoint) else { continue }
                await deliver(
                    payload,
                    to: original,
                    from: flow,
                    association: association,
                    direct: direct,
                    configuration: configuration,
                    dnsResponses: dnsResponses)
            }
        }
        return "cancelled"
    }

    /// Sends one datagram, through the upstream when it can carry it and
    /// directly when it cannot.
    ///
    /// The direct route is not a fallback bolted on here: it is the same path
    /// a flow takes while capture is paused, and the same one a reserved
    /// destination has always taken. What is new is that an upstream failure
    /// reaches it too, instead of reaching the application's socket.
    private func deliver(
        _ payload: Data,
        to original: SOCKSAddress,
        from flow: NEAppProxyUDPFlow,
        association: UDPAssociation,
        direct: DirectDatagramRelay,
        configuration: ProviderConfiguration,
        dnsResponses: DNSResponseMap
    ) async {
        func sendDirect(_ reason: String?) async {
            await direct.send(payload, to: original)
            record(flow: flow, destination: original, routedDestination: original)
            if let reason {
                Self.logDirectFallback(reason: reason, destination: original)
            }
        }
        if DatagramFlowContinuity.routesDirect(
            capturePaused: decliningFlows(),
            destination: original,
            configuration: configuration) {
            await sendDirect(nil)
            return
        }
        // The upstream's own forwarded copy of a query capture is relaying goes
        // direct, which is what keeps claiming an application's query to the
        // trusted resolver from turning into a loop. Everything about this
        // datagram looks like an ordinary lookup except the transaction ID,
        // which capture assigned and is still holding open.
        if original.port == 53, configuration.dnsHost != nil,
            Self.sameResolver(original, configuration: configuration),
            resolverLoopGuard.isRelayedQuery(payload)
        {
            await sendDirect(nil)
            return
        }
        // A name the local network owns stays with the resolver that can answer
        // it, and goes there the way it would have gone if capture had never
        // claimed the flow. Redirecting it to a trusted public resolver does not
        // produce a safer answer, it produces no answer: the printer, the NAS
        // and the router's own name exist only on this network. This is not a
        // degradation, so it is not logged as one.
        if original.port == 53, configuration.dnsHost != nil,
            LocalNames.queryIsLocal(payload, extraSuffixes: configuration.localDomains ?? [])
        {
            await sendDirect(nil)
            return
        }
        guard await association.establish() else {
            await sendDirect("upstream unavailable")
            return
        }
        // The transaction ID is only rewritten once the datagram is actually
        // going through the upstream. Rewriting first and then falling back
        // would hand the resolver a query carrying an ID it never chose.
        let routed = payload.count >= 12
            ? configuration.routedDestination(for: original)
            : original
        let prepared = await dnsResponses.prepare(query: payload, original: original, routed: routed)
        await association.remember(destination: original)
        var frame = Data([0, 0, 0])
        guard let encoded = try? routed.encoded() else { return }
        frame.append(encoded)
        frame.append(prepared)
        if await association.send(frame) {
            noteCarriedResolver(original, overUDP: true)
            record(flow: flow, destination: original, routedDestination: routed)
        } else {
            await sendDirect("upstream send failed")
        }
    }

    /// Says once per interval that datagrams are going direct, so an operator
    /// reading the log sees the degradation without a busy socket turning it
    /// into a flood.
    private static func logDirectFallback(reason: String, destination: SOCKSAddress) {
        let now = Date()
        directFallbackLock.lock()
        let due = now.timeIntervalSince(lastDirectFallbackLog) >= 30
        if due { lastDirectFallbackLog = now }
        directFallbackLock.unlock()
        guard due else { return }
        log.notice(
            "\(reason, privacy: .public): datagrams for \(destination.host, privacy: .public):\(destination.port, privacy: .public) are going direct, as they would if tunless were not installed. The application's socket is kept open")
    }

    private static let directFallbackLock = NSLock()
    private nonisolated(unsafe) static var lastDirectFallbackLog = Date.distantPast

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

    /// Remembers a resolver capture is relaying on an application's behalf.
    ///
    /// Only recorded while no override is configured. With one, the probe
    /// already knows which resolver to ask, and that resolver is reserved from
    /// capture so its flows never arrive here in the first place.
    private func noteCarriedResolver(_ destination: SOCKSAddress, overUDP: Bool) {
        guard destination.port == 53 else { return }
        lock.lock()
        if configuration.dnsHost == nil {
            carriedResolver = DNSHealthProbe.CarriedResolver(
                address: destination, overUDP: overUDP)
        }
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

    /// Whether a destination is the trusted resolver this provider rewrites to.
    private static func sameResolver(
        _ destination: SOCKSAddress, configuration: ProviderConfiguration
    ) -> Bool {
        guard let host = configuration.dnsHost, let port = configuration.dnsPort else { return false }
        return destination.port == port && ProviderConfiguration.sameHost(destination.host, host)
    }

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
                // Streams are closed so the application sees the failure and
                // retries directly. A datagram flow is left alone even here:
                // the open timing out says nothing about the socket above it,
                // and closing the flow would end that socket for good. The
                // handler unwinds either way.
                if flow is NEAppProxyTCPFlow {
                    flow.closeReadWithError(error)
                    flow.closeWriteWithError(error)
                }
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

/// Where a datagram addressed to the application is handed over.
///
/// The upstream association and the direct relay both produce replies, and
/// neither should know which kind of flow — or, in a test, which kind of
/// recorder — is on the other side of them.
protocol DatagramSink: Sendable {
    func write(_ payload: Data, from source: SOCKSAddress) async
}

/// The one writer into a datagram flow.
///
/// `NEAppProxyUDPFlow.writeDatagrams` must not be called again until its
/// completion handler has run, and a flow now has two sources of replies: the
/// upstream association and the direct relay that carries what the upstream
/// cannot. Both go through here, so at most one write is ever outstanding and
/// neither has to know the other exists.
actor FlowWriter: DatagramSink {
    private let flow: NEAppProxyUDPFlow
    private var pending: [(Data, Network.NWEndpoint)] = []
    private var writing = false
    private var cancelled = false
    /// How many replies may wait for the flow to accept them.
    ///
    /// Only one write may be outstanding, so a sender faster than the flow
    /// drains would otherwise grow this without limit and turn one busy socket
    /// into unbounded memory inside the extension. Past this point the oldest
    /// reply is dropped: these are datagrams, the sender already tolerates
    /// loss, and dropping the stale one keeps the answers still worth having.
    private let maxPending = 64
    private(set) var droppedReplies = 0

    init(flow: NEAppProxyUDPFlow) {
        self.flow = flow
    }

    func write(_ payload: Data, from source: SOCKSAddress) {
        guard !cancelled, let port = Network.NWEndpoint.Port(rawValue: source.port) else { return }
        let endpoint = Network.NWEndpoint.hostPort(
            host: Network.NWEndpoint.Host(source.host), port: port)
        enqueue((payload, endpoint))
    }

    func cancel() {
        cancelled = true
        pending.removeAll()
    }

    private func enqueue(_ datagram: (Data, Network.NWEndpoint)) {
        pending.append(datagram)
        if pending.count > maxPending {
            pending.removeFirst(pending.count - maxPending)
            droppedReplies += 1
        }
        guard !writing else { return }
        writing = true
        drain()
    }

    private func drain() {
        guard !pending.isEmpty, !cancelled else {
            writing = false
            return
        }
        let batch = pending
        pending.removeAll(keepingCapacity: true)
        flow.writeDatagrams(batch) { [weak self] _ in
            Task { await self?.drain() }
        }
    }
}

/// One SOCKS5 UDP association, rebuilt as often as the upstream needs it to
/// be.
///
/// The association is the disposable half of a datagram flow. It is
/// established on demand, torn down when the upstream drops it or when nothing
/// has used it for a while, and established again on the next datagram — all
/// without the application above ever losing its socket. That inversion is the
/// point: the old shape tied the two together, so a proxy restart, a node
/// switch, or ten seconds of a busy mixed port ended the flow, and ending the
/// flow ended the socket.
actor UDPAssociation {
    private enum State {
        case idle
        case opening
        case ready(Live)
        case failed(Date)
    }

    private final class Live {
        let control: SOCKSConnection
        let datagrams: NWConnection
        var pump: Task<Void, Never>?
        var watcher: Task<Void, Never>?

        init(control: SOCKSConnection, datagrams: NWConnection) {
            self.control = control
            self.datagrams = datagrams
        }
    }

    private let configuration: ProviderConfiguration
    private let sink: any DatagramSink
    private let dnsResponses: DNSResponseMap
    private let idleTimeoutSeconds: TimeInterval
    private var state = State.idle
    private var lastActivity = Date()
    private var idleTimer: Task<Void, Never>?
    private var shuttingDown = false
    /// Destinations the application addressed through this association, kept
    /// only so a flow that genuinely queries the override resolver itself is
    /// not mistaken for one that never asked. Bounded, and only ever consulted
    /// for that one address, so a socket talking to hundreds of peers neither
    /// grows it without limit nor loses replies once it is full.
    private var addressed: Set<String> = []
    private let maxAddressed = 32
    /// How long a failed association waits before the next datagram tries
    /// again, so an upstream that is down is not dialled once per query, and
    /// how long one dial may take. Both are injectable because a test that has
    /// to watch a rebuild otherwise has to outwait them: on a slow machine a
    /// dial to a dead port hangs to the full timeout rather than being refused,
    /// and the test then races the sum of the two.
    private let retryBackoffSeconds: TimeInterval
    private let handshakeTimeoutSeconds: TimeInterval

    init(
        configuration: ProviderConfiguration,
        sink: any DatagramSink,
        dnsResponses: DNSResponseMap,
        idleTimeoutSeconds: TimeInterval,
        retryBackoffSeconds: TimeInterval = 5,
        handshakeTimeoutSeconds: TimeInterval = 10
    ) {
        self.configuration = configuration
        self.sink = sink
        self.dnsResponses = dnsResponses
        self.idleTimeoutSeconds = idleTimeoutSeconds
        self.retryBackoffSeconds = retryBackoffSeconds
        self.handshakeTimeoutSeconds = handshakeTimeoutSeconds
    }

    /// Makes sure an association exists, returning whether one is available
    /// now. A failure is remembered rather than raised: the caller sends the
    /// datagram directly instead, and asks again later.
    ///
    /// The caller waits for the handshake rather than being handed a "not
    /// yet". Returning early and relaying the first datagram directly would
    /// send it to the resolver the application named rather than the one the
    /// operator chose, and short-lived resolver sockets — a browser opens one
    /// per lookup — would take that path almost every time, quietly turning
    /// the DNS override off. The wait is bounded by the handshake timeout.
    func establish() async -> Bool {
        switch state {
        case .ready: return true
        case .opening: return false
        case let .failed(at):
            guard Date().timeIntervalSince(at) >= retryBackoffSeconds else { return false }
        case .idle: break
        }
        guard !shuttingDown, !Task.isCancelled else { return false }
        state = .opening
        let selected = configuration
        let control = SOCKSConnection(configuration: selected)
        do {
            var relay = try await control.open(
                configuration: selected,
                command: 3,
                destination: SOCKSAddress(host: "0.0.0.0", port: 0),
                timeoutSeconds: handshakeTimeoutSeconds)
            if Self.unspecified(relay.host)
                || (Self.loopback(relay.host) && !Self.loopback(selected.upstreamHost)) {
                relay = SOCKSAddress(host: selected.upstreamHost, port: relay.port)
            }
            guard relay.port > 0,
                  IPv4Address(relay.host) != nil || IPv6Address(relay.host) != nil,
                  let port = NWEndpoint.Port(rawValue: relay.port)
            else { throw SOCKSError.invalidAddress }
            // The provider may have been told to stop while the handshake was
            // in flight, and an association nobody will read from is a leak.
            guard !shuttingDown else {
                await control.cancel()
                state = .idle
                return false
            }
            let datagrams = NWConnection(
                host: NWEndpoint.Host(relay.host), port: port, using: .udp)
            datagrams.start(queue: .global(qos: .userInitiated))
            let live = Live(control: control, datagrams: datagrams)
            state = .ready(live)
            lastActivity = Date()
            live.pump = Task { [weak self] in await self?.receiveLoop(live) }
            live.watcher = Task { [weak self] in await self?.watchControl(live) }
            startIdleTimer()
            return true
        } catch {
            await control.cancel()
            state = shuttingDown ? .idle : .failed(Date())
            return false
        }
    }

    func remember(destination: SOCKSAddress) {
        guard addressed.count < maxAddressed else { return }
        addressed.insert("\(destination.host):\(destination.port)")
    }

    func send(_ frame: Data) async -> Bool {
        guard case let .ready(live) = state else { return false }
        lastActivity = Date()
        do {
            try await Self.send(frame, on: live.datagrams)
            return true
        } catch {
            noteUpstreamEnded(live)
            return false
        }
    }

    func shutDown() {
        shuttingDown = true
        idleTimer?.cancel()
        idleTimer = nil
        tearDown(remembering: .idle)
    }

    /// What the association is doing, for tests that have to observe a rebuild
    /// rather than infer one.
    var isReady: Bool {
        if case .ready = state { return true }
        return false
    }

    /// Watches the association's control connection.
    ///
    /// A SOCKS5 UDP association lives exactly as long as the TCP connection
    /// that requested it, so the proxy closing that connection — a restart, a
    /// node switch, its own idle limit — retires the relay whether or not
    /// anything else notices. Nothing else does notice: datagrams to a dead
    /// relay are still accepted locally, so without this the flow would go on
    /// sending into a socket nobody is reading. Any traffic on the control
    /// connection means the same thing, since a well-behaved upstream sends
    /// none.
    private func watchControl(_ live: Live) async {
        _ = try? await live.control.receiveSome()
        guard !Task.isCancelled else { return }
        noteUpstreamEnded(live)
    }

    /// Carries replies up into the flow until the association ends.
    private func receiveLoop(_ live: Live) async {
        while !Task.isCancelled {
            do {
                let frame = try await Self.receive(on: live.datagrams)
                guard frame.count > 3, frame[0] == 0, frame[1] == 0, frame[2] == 0 else { continue }
                var offset = 3
                let source = try SOCKSAddress.decode(frame, offset: &offset)
                let payload = Data(frame[offset...])
                await deliverReply(payload, from: source)
            } catch {
                noteUpstreamEnded(live)
                return
            }
        }
    }

    /// Hands one reply up, unless nothing on this flow can have asked for it.
    ///
    /// The only replies worth withholding are the ones that arrive from the
    /// resolver the DNS override rewrites to and answer no query it rewrote:
    /// those carry a transaction ID the application never chose, from an
    /// address it never wrote to, and the application's own resolver traffic
    /// went out under different identifiers entirely. Everything else is
    /// delivered. In particular an unconnected socket may address more peers
    /// than any bookkeeping here should try to remember, and dropping a reply
    /// because a set filled up would break a working application to tidy up
    /// after a case that cannot occur on it.
    private func deliverReply(_ payload: Data, from source: SOCKSAddress) async {
        lastActivity = Date()
        let restored = await dnsResponses.restore(response: payload, receivedFrom: source)
        if !restored.matched, isOverrideResolver(source),
           !addressed.contains("\(source.host):\(source.port)") {
            return
        }
        await sink.write(restored.payload, from: restored.source)
    }

    private func isOverrideResolver(_ source: SOCKSAddress) -> Bool {
        guard let host = configuration.dnsHost, let port = configuration.dnsPort else { return false }
        return source.port == port && source.host == host
    }

    private func noteUpstreamEnded(_ live: Live) {
        guard case let .ready(current) = state, current === live else { return }
        tearDown(remembering: .failed(Date()))
    }

    /// Retires an association that nothing has used, freeing the upstream
    /// connection and the relay socket while leaving the flow — and therefore
    /// the application's socket — untouched. The next datagram opens a new one.
    private func startIdleTimer() {
        guard idleTimeoutSeconds > 0 else { return }
        idleTimer?.cancel()
        idleTimer = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let remaining = await self.remainingIdleTime()
                if remaining <= 0 {
                    await self.retireIfIdle()
                    return
                }
                try? await Task.sleep(nanoseconds: UInt64(remaining * 1_000_000_000))
            }
        }
    }

    private func remainingIdleTime() -> TimeInterval {
        guard idleTimeoutSeconds > 0 else { return .greatestFiniteMagnitude }
        return idleTimeoutSeconds - Date().timeIntervalSince(lastActivity)
    }

    private func retireIfIdle() {
        guard case .ready = state, remainingIdleTime() <= 0 else { return }
        tearDown(remembering: .idle)
    }

    private func tearDown(remembering next: State) {
        if case let .ready(live) = state {
            live.pump?.cancel()
            live.watcher?.cancel()
            live.datagrams.cancel()
            let control = live.control
            Task { await control.cancel() }
        }
        state = next
        idleTimer?.cancel()
        idleTimer = nil
    }

    private static func send(_ data: Data, on connection: NWConnection) async throws {
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

    private static func receive(on connection: NWConnection) async throws -> Data {
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

    private static func unspecified(_ host: String) -> Bool { host == "0.0.0.0" || host == "::" }

    private static func loopback(_ host: String) -> Bool {
        if host.lowercased() == "localhost" { return true }
        if let address = IPv4Address(host) { return address.rawValue.first == 127 }
        if let address = IPv6Address(host) { return address.rawValue == IPv6Address("::1")!.rawValue }
        return false
    }
}

/// The lifecycle rules that keep a macOS UDP socket usable across capture
/// transitions.
///
/// Network Extension owns the proxy flow, but the application still owns the
/// socket above it, and the two do not have the same lifetime. Closing a
/// datagram flow does not hand its socket back to the kernel and does not get
/// it a replacement flow: the socket is finished, and every later send on it
/// fails locally — EPIPE on an ordinary connected socket, EINVAL on the
/// resolver sockets mDNSResponder holds. mDNSResponder never replaces one, so
/// that ends name resolution for the client the socket belongs to while the
/// rest of the host keeps resolving.
///
/// So a datagram flow is closed for exactly one reason: the application
/// finished with its socket. Capture pauses, upstream failures, and idle
/// expiry all act on the transport underneath instead, which the application
/// cannot see. Port-53 flows additionally carry no association idle limit,
/// since a resolver socket is idle between lookups by design.
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
        /// Whether this response answered a query the map had rewritten.
        ///
        /// A miss is not automatically a response to throw away — a flow that
        /// asked its own resolver directly was never rewritten in the first
        /// place — but it is the difference the caller needs in order to tell
        /// those apart from a datagram nothing on this flow asked for.
        let matched: Bool
    }

    private struct Entry {
        let originalID: UInt16
        let original: SOCKSAddress
        let routed: SOCKSAddress
        let expires: Date
        /// The rewritten query, retained only while an observer is attached and
        /// only up to `maxRememberedQuery` bytes. See `rememberQuery`.
        let query: Data?
    }

    private var entries: [UInt16: Entry] = [:]
    private var nextPrune = Date.distantPast
    private let maxEntries: Int
    private let ttlSeconds: TimeInterval
    private let randomIdentifier: @Sendable () -> UInt16
    private let observedNames: ObservedNames?
    private let loopGuard: ResolverLoopGuard?

    /// Bounds the copy of a query held for observation. A question section
    /// larger than this is not one whose answer is worth remembering an address
    /// for, and the bound keeps a saturated map from holding megabytes of
    /// queries that have not been answered yet.
    private static let maxRememberedQuery = 512

    init(
        maxEntries: Int = 4096,
        ttlSeconds: TimeInterval = 30,
        randomIdentifier: @escaping @Sendable () -> UInt16 = {
            UInt16.random(in: UInt16.min ... UInt16.max)
        },
        observedNames: ObservedNames? = nil,
        loopGuard: ResolverLoopGuard? = nil
    ) {
        self.maxEntries = maxEntries
        self.ttlSeconds = ttlSeconds
        self.randomIdentifier = randomIdentifier
        self.observedNames = observedNames
        self.loopGuard = loopGuard
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
        let rewritten = Self.replacingIdentifier(in: query, with: translatedID)
        entries[translatedID] = Entry(
            originalID: originalID,
            original: original,
            routed: routed,
            expires: now.addingTimeInterval(ttlSeconds),
            // The rewritten copy, not the application's original: the answer
            // comes back carrying the translated ID, and pairing a query with an
            // answer means matching it.
            query: rememberQuery(rewritten))
        // Registered before the datagram leaves, so the upstream's forwarded
        // copy can never arrive ahead of the record that identifies it.
        loopGuard?.register(translatedID)
        return rewritten
    }

    /// Keeps the outbound message when there is an observer to feed.
    ///
    /// Only queries rewritten to the trusted resolver are remembered, so only
    /// their answers are ever observed. That is the point rather than an
    /// accident: these associations decide which hostname a later flow is
    /// proxied under, so learning one from an answer that arrived on the
    /// network's own path would let whoever supplied that answer choose the
    /// name — the poisoning this path exists to route around, re-entering one
    /// layer up.
    private func rememberQuery(_ query: Data) -> Data? {
        guard observedNames != nil, query.count <= Self.maxRememberedQuery else { return nil }
        return query
    }

    func restore(response: Data, receivedFrom source: SOCKSAddress) -> RestoredResponse {
        guard response.count >= 12, let translatedID = Self.identifier(in: response) else {
            return RestoredResponse(payload: response, source: source, matched: false)
        }
        let now = Date()
        guard let entry = entries[translatedID], now < entry.expires, entry.routed == source else {
            if let entry = entries[translatedID], now >= entry.expires {
                entries.removeValue(forKey: translatedID)
            }
            return RestoredResponse(payload: response, source: source, matched: false)
        }
        entries.removeValue(forKey: translatedID)
        loopGuard?.release(translatedID)
        if let observedNames, let query = entry.query {
            // The response still carries the translated ID here, which is the
            // ID the remembered query carries, so the observer's own matching
            // check sees the pair as the exchange it was.
            observedNames.observe(query: query, reply: response)
        }
        return RestoredResponse(
            payload: Self.replacingIdentifier(in: response, with: entry.originalID),
            source: entry.original,
            matched: true)
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
