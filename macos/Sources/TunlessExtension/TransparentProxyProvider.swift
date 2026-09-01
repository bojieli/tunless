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

    private enum LaunchResult {
        case started
        case rejectedAtCeiling(ceiling: Int, total: UInt64)
        case stopping
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
    /// UDP application flows cannot safely be rejected or closed on this
    /// platform, so the configurable ceiling applies to TCP relay work only.
    private var activeTCPFlows = 0
    private var stopping = false
    private let lock = NSLock()
    private var health = CaptureHealth()
    private var healthTimer: DispatchSourceTimer?
    private var pathMonitor: NWPathMonitor?
    private var pathIsSatisfied = true
    /// The first path callback establishes this baseline; later changes advance
    /// both health's probe generation and the transport epoch.
    private var pathGeneration = NetworkPathGeneration()
    private let networkEpoch = NetworkEpoch()
    private var recoveryProbeWorkItem: DispatchWorkItem?
    /// Invalidates callbacks from a canceled monitor/timer/provider session.
    private var watchdogSession: UInt64 = 0
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
    /// The provider re-proves DNS on a timer so an upstream outage is visible
    /// and its disposable transports can be rebuilt. A degraded session stays
    /// fail-closed for proxy-eligible traffic; health is an alarm and recovery
    /// trigger, not permission to bypass the proxy.
    private func startHealthWatchdog() {
        // A provider can be reconfigured without being torn down. Do not leave
        // an old monitor/timer or an old path baseline influencing the new
        // configuration.
        stopHealthWatchdog()
        networkEpoch.advance()
        lock.lock()
        watchdogSession &+= 1
        let session = watchdogSession
        let watchdogEnabled = configuration.disableHealthWatchdog != true
        health.arm(at: Date())
        pathGeneration = NetworkPathGeneration()
        pathIsSatisfied = true
        lock.unlock()

        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let identity = NetworkPathIdentity(path: path)
            let now = Date()
            var decision = CaptureHealth.Decision.unchanged
            var changed = false
            var generation: UInt64 = 0
            var recoveryDelay: TimeInterval = 15
            self.lock.lock()
            guard self.watchdogSession == session, !self.stopping else {
                self.lock.unlock()
                return
            }
            let healthEnabled = self.configuration.disableHealthWatchdog != true
            self.pathIsSatisfied = path.status == .satisfied
            changed = self.pathGeneration.update(identity)
            if changed {
                // The path can change while retaining the same interface name
                // (Wi-Fi -> Personal Hotspot is the common example). Every
                // meaningful identity change retires all old UDP relays.
                self.networkEpoch.advance()
                if healthEnabled {
                    decision = self.health.networkDidChange(at: now)
                }
                generation = self.pathGeneration.generation
                recoveryDelay = self.health.networkChangeGraceSeconds
            }
            self.lock.unlock()
            guard changed else { return }
            guard self.recycleStreamsForNetworkChange(watchdogSession: session) else { return }
            self.note("network path changed (generation \(generation)); rebuilding upstream transports")
            if healthEnabled {
                self.apply(decision, watchdogSession: session)
                self.scheduleRecoveryProbe(after: recoveryDelay, session: session)
            }
        }
        monitor.start(queue: healthQueue)
        lock.lock()
        if watchdogSession == session, !stopping {
            pathMonitor = monitor
        } else {
            monitor.cancel()
        }
        lock.unlock()

        guard watchdogEnabled else { return }

        let timer = DispatchSource.makeTimerSource(queue: healthQueue)
        timer.schedule(
            deadline: .now() + .seconds(Self.healthIntervalSeconds),
            repeating: .seconds(Self.healthIntervalSeconds))
        timer.setEventHandler { [weak self] in self?.runHealthCheck(session: session) }
        timer.resume()
        lock.lock()
        if watchdogSession == session, !stopping {
            healthTimer = timer
        } else {
            timer.cancel()
        }
        lock.unlock()
    }

    /// Records a probe result under the lock. Kept out of the async caller so
    /// the lock is never held across a suspension point.
    private func observeHealth(
        outcome: DNSProbeOutcome,
        pathSatisfied: Bool,
        generation: UInt64,
        session: UInt64
    ) -> CaptureHealth.Decision {
        lock.lock()
        defer { lock.unlock() }
        guard session == watchdogSession,
              generation == health.networkGeneration,
              !stopping else { return .unchanged }
        return health.observe(
            succeeded: outcome.healthy,
            detail: outcome.detail,
            pathSatisfied: pathSatisfied,
            at: Date(),
            generation: generation)
    }

    private func stopHealthWatchdog() {
        lock.lock()
        watchdogSession &+= 1
        let recovery = recoveryProbeWorkItem
        recoveryProbeWorkItem = nil
        let timer = healthTimer
        healthTimer = nil
        let monitor = pathMonitor
        pathMonitor = nil
        lock.unlock()
        recovery?.cancel()
        timer?.cancel()
        monitor?.cancel()
    }

    /// Runs one probe after the path-transition grace period instead of
    /// waiting for the regular 30-second tick. The generation check in
    /// `observeHealth` makes a superseded scheduled probe harmless.
    private func scheduleRecoveryProbe(after delay: TimeInterval, session: UInt64) {
        let item = DispatchWorkItem { [weak self] in
            self?.runHealthCheck(session: session)
        }
        lock.lock()
        guard session == watchdogSession, !stopping else {
            lock.unlock()
            item.cancel()
            return
        }
        let previous = recoveryProbeWorkItem
        recoveryProbeWorkItem = item
        lock.unlock()
        previous?.cancel()
        healthQueue.asyncAfter(deadline: .now() + max(1, delay), execute: item)
    }

    private func runHealthCheck(session: UInt64) {
        lock.lock()
        guard session == watchdogSession,
              configuration.disableHealthWatchdog != true,
              !stopping else {
            lock.unlock()
            return
        }
        let selected = configuration
        let satisfied = pathIsSatisfied
        let generation = health.networkGeneration
        let probation = health.probationDecision(at: Date())
        let carried = carriedResolver
        lock.unlock()
        apply(probation, watchdogSession: session)
        Task { [weak self] in
            guard let self else { return }
            let outcome = await DNSHealthProbe.run(configuration: selected, carried: carried)
            self.apply(
                self.observeHealth(
                    outcome: outcome,
                    pathSatisfied: satisfied,
                    generation: generation,
                    session: session),
                watchdogSession: session)
        }
    }

    /// The system is about to sleep.
    ///
    /// Sleep takes the network down, so every probe from here until the wake
    /// would fail for a reason that has nothing to do with the upstream.
    /// Older builds treated those failures as permission to decline flows, so
    /// the state outlived sleep and the laptop woke with DNS unprotected. The
    /// current provider ignores the evidence and invalidates transports only.
    public override func sleep(completionHandler: @escaping () -> Void) {
        networkEpoch.advance()
        lock.lock()
        health.systemWillSleep()
        let recovery = recoveryProbeWorkItem
        recoveryProbeWorkItem = nil
        lock.unlock()
        recovery?.cancel()
        recycleStreamsForNetworkChange()
        completionHandler()
    }

    /// The system woke. Interfaces, routes, and the upstream's own connections
    /// come back over several seconds, so probe results are ignored for a grace
    /// period rather than counted against the upstream.
    public override func wake() {
        networkEpoch.advance()
        lock.lock()
        health.systemDidWake(at: Date())
        let session = watchdogSession
        let healthEnabled = configuration.disableHealthWatchdog != true
        let recoveryDelay = health.wakeGraceSeconds
        lock.unlock()
        recycleStreamsForNetworkChange()
        if healthEnabled {
            scheduleRecoveryProbe(after: recoveryDelay, session: session)
        }
    }

    private func apply(
        _ decision: CaptureHealth.Decision,
        watchdogSession session: UInt64
    ) {
        switch decision {
        case .unchanged: break
        case let .pause(reason): standDown(reason, watchdogSession: session)
        case .resume: standUp(watchdogSession: session)
        }
    }

    /// Marks the upstream unhealthy and tears down streams that cannot be
    /// repaired in place.
    ///
    /// Capture remains installed while health is degraded. Returning
    /// `false` from a flow handler would hand a proxy-eligible connection to
    /// the kernel and silently bypass the proxy, which is the failure this
    /// state machine is meant to make visible. New TCP flows are therefore
    /// still claimed and fail/retry through SOCKS; UDP flows stay open and
    /// drop individual datagrams until their association can be rebuilt.
    private func standDown(_ reason: String, watchdogSession session: UInt64) {
        lock.lock()
        guard !stopping, session == watchdogSession else {
            lock.unlock()
            return
        }
        let records = Array(activeFlows.values)
        lock.unlock()
        // Long-lived UDP flows cannot be closed and are not kept in a registry
        // of disposable associations. Advancing their shared epoch retires a
        // silently dead relay on the next datagram without touching the
        // application-owned socket above it.
        networkEpoch.advance()
        // Streams already relaying through an upstream that cannot carry them
        // are not going to recover in place; closing them lets applications
        // retry through the still-installed capture path. Keep datagram flows
        // alive: macOS owns long-lived UDP resolver sockets and continues using
        // them after a transparent-proxy flow is error-closed. The association
        // underneath them is disposable and will be rebuilt instead.
        for record in records where !record.survivesCapturePause {
            record.flow.closeReadWithError(SOCKSError.closed)
            record.flow.closeWriteWithError(SOCKSError.closed)
            record.task.cancel()
        }
        note("capture degraded: \(reason). Proxy-eligible flows remain captured"
            + " and retry; reserved/local traffic keeps its direct route")
    }

    private func standUp(watchdogSession session: UInt64) {
        lock.lock()
        let current = !stopping && session == watchdogSession
        lock.unlock()
        guard current else { return }
        // A successful probe uses a fresh transport. Make long-lived flows do
        // the same rather than retaining an association created while health
        // was degraded.
        networkEpoch.advance()
        note("upstream recovered: capture remained active; rebuilding disposable datagram transports")
    }

    /// Existing SOCKS streams are tied to the route on which they were
    /// opened. Close them on a path transition so applications retry through
    /// the current path; unlike a handler returning `false`, that retry is
    /// still claimed by this provider and cannot silently bypass the proxy.
    @discardableResult
    private func recycleStreamsForNetworkChange(
        watchdogSession session: UInt64? = nil
    ) -> Bool {
        lock.lock()
        if let session, (session != watchdogSession || stopping) {
            lock.unlock()
            return false
        }
        let records = Array(activeFlows.values)
        lock.unlock()
        for record in records where !record.survivesCapturePause {
            record.flow.closeReadWithError(SOCKSError.closed)
            record.flow.closeWriteWithError(SOCKSError.closed)
            record.task.cancel()
        }
        return true
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

    /// Health as the launcher reports it. A degraded session still captures
    /// proxy-eligible flows, so status names both facts rather than claiming
    /// the provider has stood aside.
    private func healthSnapshot() -> Data? {
        lock.lock()
        let snapshot = CaptureHealthReport(
            capturing: !stopping,
            pauseReason: health.pauseReason,
            confirmed: health.confirmed,
            consecutiveFailures: health.consecutiveFailures,
            activeFlows: activeFlows.count,
            rejectedFlows: rejectedFlows)
        lock.unlock()
        return try? JSONEncoder().encode(snapshot)
    }

    public override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // Close admission before cancelling callbacks or advancing the epoch.
        // Otherwise a flow can pass `launch` in the teardown window, after the
        // active-flow snapshot has been taken, and leave stop waiting on a set
        // that does not include it.
        lock.lock()
        stopping = true
        let records = Array(activeFlows.values)
        lock.unlock()
        stopHealthWatchdog()
        // Prevent a transport that is still unwinding from being reused if a
        // new provider session is started quickly after this one stops.
        networkEpoch.advance()
        for record in records {
            // Streams are closed so the application sees the connection end
            // and retries through the next provider session. Datagram flows
            // are left alone. Their sockets outlive this session —
            // mDNSResponder holds one resolver socket per delegated client for
            // as long as it runs — and a flow the provider closes is a socket
            // macOS will not reroute and will not replace. Ending the session
            // releases the diverted sockets; closing their flows first is what
            // prevents that.
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
        let result = launch(flow: flow, operation: { [weak self] in
            await self?.handleTCP(
                tcp,
                originalDestination: originalDestination,
                routedDestination: routedDestination,
                configuration: selected)
        })
        switch result {
        case .started:
            noteCarriedResolver(originalDestination, overUDP: false)
            record(flow: flow, destination: originalDestination, routedDestination: routedDestination)
            return true
        case .rejectedAtCeiling:
            rejectTCPAtCeiling(tcp)
            record(
                flow: flow,
                destination: originalDestination,
                routedDestination: routedDestination,
                route: .dropped,
                event: "rejected:flow-ceiling")
            return true
        case .stopping:
            return false
        }
    }

    public func handleNewUDPFlow(
        _ flow: NEAppProxyUDPFlow,
        initialRemoteFlowEndpoint remoteEndpoint: Network.NWEndpoint
    ) -> Bool {
        guard let destination = Self.address(remoteEndpoint) else { return false }
        let selected = configurationSnapshot()
        let executablePath = Self.executablePath(auditToken: flow.metaData.sourceAppAuditToken)
        let signingIdentifier = flow.metaData.sourceAppSigningIdentifier
        guard selected.captures(
            host: destination.host,
            port: destination.port,
            signingIdentifier: signingIdentifier,
            executablePath: executablePath,
            isDatagram: true)
        else { return false }
        let result = launch(
            flow: flow,
            survivesCapturePause: DatagramFlowContinuity.survivesCapturePause,
            operation: { [weak self] in
                await self?.handleUDP(
                    flow,
                    initialDestination: destination,
                    configuration: selected,
                    signingIdentifier: signingIdentifier,
                    executablePath: executablePath)
            })
        // UDP is deliberately outside the TCP relay ceiling, because closing
        // or declining an application-owned datagram flow either destroys its
        // socket or sends it direct. The only remaining non-start case is an
        // actual provider shutdown, when Network Extension is removing capture.
        if case .started = result { return true }
        return false
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
        guard !stopping else {
            lock.unlock()
            completionHandler?(nil)
            return
        }
        if configuration == validated {
            lock.unlock()
            // The launcher sends the complete configuration. Re-acknowledging
            // an identical value must not reset health probation or recycle
            // every live transport.
            completionHandler?(Data([1]))
            return
        }
        configuration = validated
        // A learned resolver belongs to the configuration that carried it.
        // Keeping it across an update can make the new watchdog probe a target
        // selected by rules that are no longer installed.
        carriedResolver = nil
        lock.unlock()
        startHealthWatchdog()
        recycleStreamsForNetworkChange()
        note("configuration updated; rebuilt upstream transport state")
        completionHandler?(Data([1]))
    }

    private func launch(
        flow: NEAppProxyFlow,
        survivesCapturePause: Bool = false,
        operation: @escaping @Sendable () async -> Void
    ) -> LaunchResult {
        lock.lock()
        guard !stopping else {
            lock.unlock()
            return .stopping
        }
        let ceiling = configuration.flowCeiling
        if !survivesCapturePause, activeTCPFlows >= ceiling {
            let total = rejectedFlows &+ 1
            rejectedFlows = total
            lock.unlock()
            // Log the first rejection and powers of two, so a local connection
            // flood cannot turn the safety limit into an unbounded log flood.
            if total == 1 || total & (total - 1) == 0 {
                Self.log.notice(
                    "TCP flow refused at the concurrency ceiling \(ceiling, privacy: .public); refused \(total, privacy: .public) so far. The flow remains captured and cannot bypass the proxy")
            }
            return .rejectedAtCeiling(ceiling: ceiling, total: total)
        }
        let identifier = UUID()
        let task = Task { [weak self] in
            await operation()
            self?.finishFlow(identifier)
        }
        activeFlows[identifier] = ActiveFlow(
            flow: flow, task: task, survivesCapturePause: survivesCapturePause)
        if !survivesCapturePause { activeTCPFlows += 1 }
        lock.unlock()
        return .started
    }

    private func finishFlow(_ identifier: UUID) {
        lock.lock()
        if let record = activeFlows.removeValue(forKey: identifier),
           !record.survivesCapturePause,
           activeTCPFlows > 0 {
            activeTCPFlows -= 1
        }
        lock.unlock()
    }

    /// Claims an overloaded TCP flow and reports a refusal to the application.
    /// Returning false here would mean "route directly" for a transparent
    /// proxy, turning a local resource limit into a silent privacy bypass.
    private func rejectTCPAtCeiling(_ flow: NEAppProxyTCPFlow) {
        let error = NSError(
            domain: NEAppProxyErrorDomain,
            code: 6, // NEAppProxyFlowError.refused
            userInfo: [NSLocalizedDescriptionKey: "Tunless TCP flow ceiling reached"])
        flow.open(withLocalFlowEndpoint: nil) { _ in
            flow.closeReadWithError(error)
            flow.closeWriteWithError(error)
        }
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
            route: .proxied,
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
    /// flow. Proxy-eligible datagrams stay captured and are dropped until the
    /// disposable association can be rebuilt; only explicit reserved and local
    /// exceptions use the direct relay. The flow ends when the application
    /// closes its socket, or when the provider stops.
    private func handleUDP(
        _ flow: NEAppProxyUDPFlow,
        initialDestination: SOCKSAddress,
        configuration: ProviderConfiguration,
        signingIdentifier: String,
        executablePath: String?
    ) async {
        let writer = FlowWriter(flow: flow)
        let direct = DirectDatagramRelay(sink: writer, networkEpoch: networkEpoch)
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
            idleTimeoutSeconds: DatagramFlowContinuity.idleTimeoutSeconds(for: initialDestination),
            networkEpoch: networkEpoch)
        var event: String
        do {
            try Task.checkCancellation()
            try await open(flow)
            event = await pumpDatagrams(
                flow,
                association: association,
                direct: direct,
                dnsResponses: dnsResponses,
                signingIdentifier: signingIdentifier,
                executablePath: executablePath)
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
            routedDestination: configurationSnapshot().routedDestination(for: initialDestination),
            // One unconnected UDP flow may contain proxied, intentionally
            // direct, and dropped datagrams. Its terminal event has no single
            // route, so do not mislabel the whole flow as proxied.
            route: nil,
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
        dnsResponses: DNSResponseMap,
        signingIdentifier: String,
        executablePath: String?
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
                let selected = configurationSnapshot()
                await deliver(
                    payload,
                    to: original,
                    from: flow,
                    association: association,
                    direct: direct,
                    configuration: selected,
                    dnsResponses: dnsResponses,
                    signingIdentifier: signingIdentifier,
                    executablePath: executablePath,
                    retriedAfterNetworkChange: false)
            }
        }
        return "cancelled"
    }

    /// Sends one datagram through the upstream, or directly only when the
    /// destination is structurally outside SOCKS (for example multicast or a
    /// split-horizon local name). An upstream failure is *not* a direct-route
    /// decision: the flow stays captured, the datagram is dropped, and a later
    /// packet gets another opportunity after the association backoff.
    private func deliver(
        _ payload: Data,
        to original: SOCKSAddress,
        from flow: NEAppProxyUDPFlow,
        association: UDPAssociation,
        direct: DirectDatagramRelay,
        configuration: ProviderConfiguration,
        dnsResponses: DNSResponseMap,
        signingIdentifier: String,
        executablePath: String?,
        retriedAfterNetworkChange: Bool
    ) async {
        let attemptEpoch = networkEpoch.current
        await association.updateConfiguration(configuration)

        func retryOnNewNetwork() async -> Bool {
            guard !retriedAfterNetworkChange,
                  networkEpoch.current != attemptEpoch else { return false }
            await deliver(
                payload,
                to: original,
                from: flow,
                association: association,
                direct: direct,
                configuration: configurationSnapshot(),
                dnsResponses: dnsResponses,
                signingIdentifier: signingIdentifier,
                executablePath: executablePath,
                retriedAfterNetworkChange: true)
            return true
        }

        func sendDirect(_ reason: String) async {
            if await direct.send(payload, to: original) {
                record(
                    flow: flow,
                    destination: original,
                    routedDestination: original,
                    route: .direct,
                    event: "direct:\(reason)")
            } else {
                record(
                    flow: flow,
                    destination: original,
                    routedDestination: original,
                    route: .dropped,
                    event: "dropped:direct-send-failed:\(reason)")
            }
        }
        // An unconnected UDP socket may address a destination other than the
        // one that admitted its flow, and a live configuration update may
        // narrow the process or destination scope. Re-evaluate each datagram so
        // an explicit exclusion remains an intentional direct route instead of
        // being trapped inside an already-accepted flow.
        if let reason = DatagramFlowContinuity.directReasonForOwnedFlow(
            destination: original,
            configuration: configuration,
            signingIdentifier: signingIdentifier,
            executablePath: executablePath)
        {
            await sendDirect(reason)
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
            await sendDirect("resolver-loop-guard")
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
            await sendDirect("local-name")
            return
        }
        guard await association.establish() else {
            if await retryOnNewNetwork() { return }
            recordDroppedDatagram(
                flow: flow,
                destination: original,
                routedDestination: configuration.routedDestination(for: original),
                reason: "upstream-unavailable")
            return
        }
        // The transaction ID is only rewritten once the datagram is actually
        // going through the upstream. Rewriting first and then falling back
        // would hand the resolver a query carrying an ID it never chose.
        let routed = payload.count >= 12
            ? configuration.routedDestination(for: original)
            : original
        // A query already addressed to the trusted resolver is rewritten to
        // itself, so nothing about it differs from the datagram the upstream
        // will forward — and the loop guard works by recognising an identifier
        // capture assigned. Ask for one anyway on exactly those flows, or
        // claiming them reopens the loop the address reservation used to close.
        let policed = original.port == 53 && Self.sameResolver(original, configuration: configuration)
        let prepared = await dnsResponses.prepareForSend(
            query: payload, original: original, routed: routed, policed: policed)
        guard prepared.canSend else {
            recordDroppedDatagram(
                flow: flow,
                destination: original,
                routedDestination: routed,
                reason: "resolver-loop-guard-unavailable")
            return
        }
        await association.remember(destination: original)
        var frame = Data([0, 0, 0])
        guard let encoded = try? routed.encoded() else {
            await dnsResponses.abandon(prepared)
            return
        }
        frame.append(encoded)
        frame.append(prepared.payload)
        if await association.send(frame) {
            noteCarriedResolver(original, overUDP: true)
            record(
                flow: flow,
                destination: original,
                routedDestination: routed,
                route: .proxied)
        } else {
            await dnsResponses.abandon(prepared)
            // A path transition can invalidate the association between the
            // establish and send calls. Rebuild the route and frame from the
            // latest configuration exactly once; an ordinary upstream failure
            // remains behind the association's retry backoff.
            if await retryOnNewNetwork() { return }
            recordDroppedDatagram(
                flow: flow,
                destination: original,
                routedDestination: routed,
                reason: "upstream-send-failed")
        }
    }

    /// Says once per interval that a proxy-eligible datagram was dropped and
    /// will be retried. This keeps the failure visible without turning a busy
    /// resolver socket into an unbounded log stream.
    private static func logDroppedDatagram(reason: String, destination: SOCKSAddress) {
        let now = Date()
        droppedDatagramLogLock.lock()
        let due = now.timeIntervalSince(lastDroppedDatagramLog) >= 30
        if due { lastDroppedDatagramLog = now }
        droppedDatagramLogLock.unlock()
        guard due else { return }
        log.notice(
            "\(reason, privacy: .public): datagrams for \(destination.host, privacy: .public):\(destination.port, privacy: .public) stay captured and are being retried through the upstream")
    }

    private func recordDroppedDatagram(
        flow: NEAppProxyFlow,
        destination: SOCKSAddress,
        routedDestination: SOCKSAddress,
        reason: String
    ) {
        record(
            flow: flow,
            destination: destination,
            routedDestination: routedDestination,
            route: .dropped,
            event: "retrying:\(reason)")
        Self.logDroppedDatagram(reason: reason, destination: destination)
    }

    private static let droppedDatagramLogLock = NSLock()
    private nonisolated(unsafe) static var lastDroppedDatagramLog = Date.distantPast

    private func record(
        flow: NEAppProxyFlow,
        destination: SOCKSAddress,
        routedDestination: SOCKSAddress,
        route: FlowRoute = .proxied,
        event: String? = nil
    ) {
        let routed = routedDestination == destination ? nil : "\(routedDestination.host):\(routedDestination.port)"
        appendTelemetry(FlowTelemetry(
            protocolName: flow is NEAppProxyTCPFlow ? "tcp" : "udp",
            destination: "\(destination.host):\(destination.port)",
            routedDestination: routed,
            route: route,
            hostname: flow.remoteHostname,
            signingIdentifier: flow.metaData.sourceAppSigningIdentifier,
            executablePath: Self.executablePath(auditToken: flow.metaData.sourceAppAuditToken),
            timestamp: Date(),
            event: event))
    }

    private func recordCompletion(
        flow: NEAppProxyFlow,
        protocolName: String,
        destination: SOCKSAddress,
        routedDestination: SOCKSAddress,
        route: FlowRoute?,
        event: String
    ) {
        let routed = routedDestination == destination ? nil : "\(routedDestination.host):\(routedDestination.port)"
        appendTelemetry(FlowTelemetry(
            protocolName: protocolName,
            destination: "\(destination.host):\(destination.port)",
            routedDestination: routed,
            route: route,
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
                // retries through the still-installed capture path. A datagram
                // flow is left alone even here:
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
        case failed(Date, epoch: UInt64)
    }

    private final class Live {
        let control: SOCKSConnection
        let datagrams: NWConnection
        let epoch: UInt64
        var pump: Task<Void, Never>?
        var watcher: Task<Void, Never>?

        init(control: SOCKSConnection, datagrams: NWConnection, epoch: UInt64) {
            self.control = control
            self.datagrams = datagrams
            self.epoch = epoch
        }
    }

    private var configuration: ProviderConfiguration
    private let sink: any DatagramSink
    private let dnsResponses: DNSResponseMap
    private let idleTimeoutSeconds: TimeInterval
    private let networkEpoch: NetworkEpoch
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
        networkEpoch: NetworkEpoch = NetworkEpoch(),
        retryBackoffSeconds: TimeInterval = 5,
        handshakeTimeoutSeconds: TimeInterval = 10
    ) {
        self.configuration = configuration
        self.sink = sink
        self.dnsResponses = dnsResponses
        self.idleTimeoutSeconds = idleTimeoutSeconds
        self.networkEpoch = networkEpoch
        self.retryBackoffSeconds = retryBackoffSeconds
        self.handshakeTimeoutSeconds = handshakeTimeoutSeconds
    }

    /// Applies a live provider configuration to this long-lived application
    /// flow. The flow itself cannot be replaced safely, but every upstream
    /// object beneath it can: retire the old association now and let the next
    /// `establish` use the new endpoint, credentials, resolver, and rules.
    func updateConfiguration(_ updated: ProviderConfiguration) {
        guard updated != configuration else { return }
        configuration = updated
        addressed.removeAll(keepingCapacity: true)
        tearDown(remembering: .idle)
    }

    /// Makes sure an association exists, returning whether one is available
    /// now. A failure is remembered rather than raised: the caller drops the
    /// datagram (the flow stays open) and asks again later.
    ///
    /// The caller waits for the handshake rather than being handed a "not
    /// yet". Returning early and relaying the first datagram directly would
    /// send it to the resolver the application named rather than the one the
    /// operator chose, and short-lived resolver sockets — a browser opens one
    /// per lookup — would take that path almost every time, quietly turning
    /// the DNS override off. The wait is bounded by the handshake timeout.
    func establish() async -> Bool {
        let currentEpoch = networkEpoch.current
        invalidateStaleAssociation(currentEpoch: currentEpoch)
        switch state {
        case let .ready(live): return live.epoch == currentEpoch
        case .opening: return false
        case let .failed(at, epoch):
            // A failure recorded on an old path must not impose its backoff on
            // the new path. `invalidateStaleAssociation` normally handles this
            // before the switch; keeping the guard here makes the invariant
            // explicit if the state changes while an actor turn is resumed.
            guard epoch == currentEpoch else {
                state = .idle
                break
            }
            guard Date().timeIntervalSince(at) >= retryBackoffSeconds else { return false }
        case .idle: break
        }
        guard !shuttingDown, !Task.isCancelled else { return false }
        state = .opening
        let selected = configuration
        let openingEpoch = currentEpoch
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
            guard !shuttingDown, networkEpoch.current == openingEpoch else {
                await control.cancel()
                state = .idle
                return false
            }
            let datagrams = NWConnection(
                host: NWEndpoint.Host(relay.host), port: port, using: .udp)
            datagrams.start(queue: .global(qos: .userInitiated))
            let live = Live(control: control, datagrams: datagrams, epoch: openingEpoch)
            state = .ready(live)
            lastActivity = Date()
            live.pump = Task { [weak self] in await self?.receiveLoop(live) }
            live.watcher = Task { [weak self] in await self?.watchControl(live) }
            startIdleTimer()
            return true
        } catch {
            await control.cancel()
            state = shuttingDown || networkEpoch.current != openingEpoch
                ? .idle
                : .failed(Date(), epoch: openingEpoch)
            return false
        }
    }

    func remember(destination: SOCKSAddress) {
        guard addressed.count < maxAddressed else { return }
        addressed.insert("\(destination.host):\(destination.port)")
    }

    func send(_ frame: Data) async -> Bool {
        let currentEpoch = networkEpoch.current
        guard case let .ready(live) = state else { return false }
        guard live.epoch == currentEpoch else {
            tearDown(remembering: .idle)
            return false
        }
        lastActivity = Date()
        do {
            try await Self.send(frame, on: live.datagrams)
            guard networkEpoch.current == live.epoch,
                  case let .ready(current) = state,
                  current === live else {
                noteUpstreamEnded(live)
                return false
            }
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
        if case let .ready(live) = state, live.epoch == networkEpoch.current { return true }
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
                guard live.epoch == networkEpoch.current else {
                    noteUpstreamEnded(live)
                    return
                }
                guard frame.count > 3, frame[0] == 0, frame[1] == 0, frame[2] == 0 else { continue }
                var offset = 3
                let source = try SOCKSAddress.decode(frame, offset: &offset)
                let payload = Data(frame[offset...])
                await deliverReply(payload, from: source, epoch: live.epoch)
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
    private func deliverReply(
        _ payload: Data,
        from source: SOCKSAddress,
        epoch: UInt64
    ) async {
        guard networkEpoch.current == epoch else {
            // Do not hand a reply from a relay bound to the previous network
            // to an application that is now using the new path.
            return
        }
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
        return source.port == port && ProviderConfiguration.sameHost(source.host, host)
    }

    private func noteUpstreamEnded(_ live: Live) {
        guard case let .ready(current) = state, current === live else { return }
        let currentEpoch = networkEpoch.current
        tearDown(remembering: live.epoch == currentEpoch
            ? .failed(Date(), epoch: currentEpoch)
            : .idle)
    }

    /// Retires a ready/failed state that belongs to an older network epoch.
    ///
    /// This is lazy by design: the provider does not keep a strong registry of
    /// every UDP flow just to tear them down on a path callback. The next
    /// datagram (or a stale reply/control notification) reaches this actor and
    /// performs the same teardown before any bytes can be sent on the old
    /// socket.
    private func invalidateStaleAssociation(currentEpoch: UInt64) {
        switch state {
        case let .ready(live) where live.epoch != currentEpoch:
            tearDown(remembering: .idle)
        case let .failed(_, epoch) where epoch != currentEpoch:
            state = .idle
        default:
            break
        }
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
/// finished with its socket. Health degradation, upstream failures, and idle
/// expiry all act on the transport underneath instead, which the application
/// cannot see. Port-53 flows additionally carry no association idle limit,
/// since a resolver socket is idle between lookups by design.
enum DatagramFlowContinuity {
    enum RouteDecision: Equatable, Sendable {
        case proxied
        case direct(reason: String)
        case dropped(reason: String)
    }

    static let survivesCapturePause = true
    private static let ordinaryIdleTimeoutSeconds: TimeInterval = 120

    static func idleTimeoutSeconds(for initialDestination: SOCKSAddress) -> TimeInterval {
        initialDestination.port == 53 ? 0 : ordinaryIdleTimeoutSeconds
    }

    /// Returns the direct exception, if any, that is inherent to the
    /// destination rather than caused by an upstream outage.
    static func structuralDirectReason(
        destination: SOCKSAddress,
        configuration: ProviderConfiguration
    ) -> String? {
        guard configuration.reservedDestination(
            host: destination.host, port: destination.port, isDatagram: true)
        else { return nil }
        return "reserved-destination"
    }

    /// Direct-route reason for a datagram inside a flow the provider already
    /// owns.
    ///
    /// Unconnected UDP sockets can address many peers, and configuration may
    /// change while such a socket remains open. Admission of the first peer is
    /// therefore not permission to proxy every later peer: reserved targets
    /// and explicit process/destination exclusions retain their deliberate
    /// direct semantics on every datagram.
    static func directReasonForOwnedFlow(
        destination: SOCKSAddress,
        configuration: ProviderConfiguration,
        signingIdentifier: String,
        executablePath: String? = nil
    ) -> String? {
        if let reason = structuralDirectReason(
            destination: destination, configuration: configuration) {
            return reason
        }
        guard configuration.captures(
            host: destination.host,
            port: destination.port,
            signingIdentifier: signingIdentifier,
            executablePath: executablePath,
            isDatagram: true)
        else { return "capture-scope-exclusion" }
        return nil
    }

    /// The routing decision for an already-accepted datagram.
    ///
    /// `capturePaused` is intentionally not a direct-route trigger. A health
    /// pause means the upstream is unhealthy; handing the packet to the local
    /// network at that point is the browser/DNS bypass this provider is meant
    /// to prevent. The flow remains captured and the packet is dropped until a
    /// later retry can use the rebuilt association.
    static func route(
        capturePaused: Bool,
        destination: SOCKSAddress,
        configuration: ProviderConfiguration,
        upstreamAvailable: Bool
    ) -> RouteDecision {
        _ = capturePaused
        if let reason = structuralDirectReason(
            destination: destination, configuration: configuration) {
            return .direct(reason: reason)
        }
        return upstreamAvailable ? .proxied : .dropped(reason: "upstream-unavailable")
    }

    /// Compatibility predicate for the older call sites and tests. A health
    /// pause is deliberately ignored: only a structural exception is direct.
    static func routesDirect(
        capturePaused: Bool,
        destination: SOCKSAddress,
        configuration: ProviderConfiguration
    ) -> Bool {
        _ = capturePaused
        return structuralDirectReason(
            destination: destination, configuration: configuration) != nil
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
    struct PreparedQuery: Sendable {
        let payload: Data
        /// False means sending could recurse through the capture path because
        /// no bounded loop-guard registration was available.
        let canSend: Bool
        fileprivate let translatedID: UInt16?
    }

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

    /// `policed` forces an identifier to be assigned even when the destination is
    /// unchanged, so that the loop guard can recognise the upstream's forwarded
    /// copy of a query aimed at the trusted resolver itself.
    func prepare(
        query: Data, original: SOCKSAddress, routed: SOCKSAddress, policed: Bool = false
    ) -> Data {
        prepareForSend(
            query: query, original: original, routed: routed, policed: policed).payload
    }

    /// Prepares a query and returns the exact map entry that belongs to this
    /// send attempt. The token lets a caller undo the registration when the UDP
    /// frame never leaves; otherwise a failed send can leave a loop-guard ID
    /// behind and a colliding application query may be misclassified as the
    /// upstream's forwarded copy and sent direct.
    func prepareForSend(
        query: Data, original: SOCKSAddress, routed: SOCKSAddress, policed: Bool = false
    ) -> PreparedQuery {
        let needsTranslation = routed != original || policed
        guard needsTranslation, query.count >= 12 else {
            return PreparedQuery(payload: query, canSend: true, translatedID: nil)
        }
        guard maxEntries > 0 else {
            return PreparedQuery(
                payload: query, canSend: loopGuard == nil, translatedID: nil)
        }
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
        guard let translatedID = allocateID() else {
            return PreparedQuery(
                payload: query, canSend: loopGuard == nil, translatedID: nil)
        }
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
        if let loopGuard, !loopGuard.register(translatedID) {
            entries.removeValue(forKey: translatedID)
            return PreparedQuery(payload: query, canSend: false, translatedID: nil)
        }
        return PreparedQuery(payload: rewritten, canSend: true, translatedID: translatedID)
    }

    /// Forgets a query whose UDP frame was not accepted by the association.
    /// Only the token returned by `prepareForSend` can remove an entry, so an
    /// unchanged application transaction ID can never erase another exchange.
    func abandon(_ prepared: PreparedQuery) {
        guard let translatedID = prepared.translatedID,
              entries.removeValue(forKey: translatedID) != nil else { return }
        loopGuard?.release(translatedID)
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
