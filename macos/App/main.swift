import AppKit
import Darwin
import Foundation
import Network
import NetworkExtension
import SystemExtensions

private let usage = """
Usage:
  Tunless start [options]
  Tunless check [options]
  Tunless status
  Tunless stop
  Tunless cleanup
  Tunless telemetry

Tunless replaces only transparent capture. A SOCKS5 application such as
Clash Verge, mihomo, or sing-box continues to own rules, nodes, and transport.

Options:
  --preset clash-verge       Add the Clash Verge loop-prevention exclusions.
                             Defaults its upstream to 127.0.0.1:7897.
  --upstream HOST:PORT       SOCKS5 or mixed listener used as the upstream.
  --dns-upstream IP:PORT     Trusted resolver for captured port-53 traffic.
  --disable-dns-override     Preserve each application's original resolver.
  --skip-verify              Do not verify DNS after start, and do not roll
                             capture back automatically if it fails.
  --no-default-exclusions    Capture private, CGNAT, and fake-IP ranges, which
                             are excluded by default.
  --no-health-watchdog       Keep capture on even after the upstream stops
                             resolving names.
  --max-flows N              Most flows to hold at once (default 4096).
                             Flows past the ceiling go direct.
  --include-process GLOB     Capture a signing identifier (repeatable).
  --exclude-process GLOB     Exclude a signing identifier (repeatable).
  --include-destination CIDR Capture a destination prefix (repeatable).
  --exclude-destination CIDR Exclude a destination prefix (repeatable).
  --cleanup                  Legacy spelling of the cleanup command.
  -h, --help                 Show this help.
  --version                  Show app and build version.

Examples:
  Tunless check --preset clash-verge --upstream 127.0.0.1:7897
  Tunless start --preset clash-verge --upstream 127.0.0.1:7897
  Tunless status
  Tunless cleanup

Capture never claims loopback, link-local, multicast, the upstream itself, or
the resolver the upstream was asked to query. Those are what a host needs to
stay reachable and what tunless itself relays through, so they are reserved by
the provider rather than left to an exclusion flag. Private, CGNAT, and fake-IP
ranges are excluded by default too; --include-destination overrides that per
prefix.

start refuses to enable capture when the upstream cannot relay DNS, and rolls
capture back automatically if name resolution does not work once capture is on.
Capture then stays accountable: the provider re-proves resolution on a timer,
stands aside on its own if that stops working, and resumes when the upstream
recovers. Sleep never counts against the upstream. status reports what capture
is actually doing in its capture field, since a paused session still reads as
connected.

Use stop for an ordinary shutdown. Cleanup is the fail-safe recovery command:
it stops capture, removes every Tunless proxy configuration, and deactivates
the Tunless Network Extension.
If recovery commands cannot respond, disable Tunless under System Settings >
General > Login Items & Extensions > Network Extensions.

Legacy --stop, --cleanup, --check, --status, and --telemetry flags remain supported.
"""

private func write(_ text: String, to handle: FileHandle) {
    handle.write(Data(text.utf8))
}

private func terminate(_ code: Int32) -> Never {
    fflush(stdout)
    fflush(stderr)
    Darwin.exit(code)
}

private func versionFields() -> (version: String, build: String) {
    let info = Bundle.main.infoDictionary ?? [:]
    return (
        info["CFBundleShortVersionString"] as? String ?? "dev",
        info["CFBundleVersion"] as? String ?? "dev")
}

private let launcherArguments: LauncherArguments
do {
    launcherArguments = try LauncherArguments()
} catch {
    write("Tunless: \(error.localizedDescription)\n\n\(usage)\n", to: .standardError)
    terminate(2)
}

switch launcherArguments.action {
case .help:
    write("\(usage)\n", to: .standardOutput)
    terminate(0)
case .version:
    let fields = versionFields()
    write("Tunless \(fields.version) (\(fields.build))\n", to: .standardOutput)
    terminate(0)
default: break
}

private struct CheckReport: Codable {
    let ok: Bool
    let preset: String?
    let upstream: String
    let detail: String
    let dns: DNSRelayReport?
}

private struct StatusReport: Codable {
    let status: String
    let enabled: Bool
    let launcherVersion: String
    let launcherBuild: String
    let upstream: String?
    let dnsUpstream: String?
    let preset: String?
    /// What the provider is doing with flows right now.
    ///
    /// A capture that stood aside keeps its session connected, because the
    /// session is what keeps the watchdog probing, so `status` alone reports
    /// `connected` either way. Without this field a paused capture is
    /// indistinguishable from a working one.
    let capture: String?

    enum CodingKeys: String, CodingKey {
        case status
        case enabled
        case upstream
        case preset
        case capture
        case launcherVersion = "launcher_version"
        case launcherBuild = "launcher_build"
        case dnsUpstream = "dns_upstream"
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, OSSystemExtensionRequestDelegate {
    private static let providerBundleIdentifier = "com.bojieli.tunless.TunlessProxy"
    private let arguments: LauncherArguments
    private var preflight: SOCKSPreflight?
    private var operationDeadline: DispatchSourceTimer?
    private var cleanupPreferenceErrors: [String] = []
    /// The configuration actually deployed, which carries what preflight
    /// learned about the upstream on top of what the operator asked for.
    private var effectiveConfiguration: LauncherConfiguration?

    init(arguments: LauncherArguments) {
        self.arguments = arguments
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        switch arguments.action {
        case .start:
            // Preflight always runs, preset or not. The documented manual
            // invocation carries no preset, and it needs the DNS guard just as
            // much: without it, an upstream that cannot relay DNS is only
            // discovered after capture has already taken resolution down.
            performPreflight(startAfterSuccess: true)
        case .check: performPreflight(startAfterSuccess: false)
        case .status: fetchStatus()
        case .stop:
            armOperationDeadline(for: "stop")
            stopProxy(removeConfiguration: false)
        case .cleanup:
            armOperationDeadline(for: "cleanup")
            stopProxy(removeConfiguration: true)
        case .telemetry: fetchTelemetry()
        case .help, .version: terminate(0)
        }
    }

    private func performPreflight(startAfterSuccess: Bool) {
        guard let configuration = arguments.configuration else {
            write("Tunless: missing start configuration\n", to: .standardError)
            terminate(2)
        }
        for pattern in configuration.ambiguousProcessPatterns {
            write(
                "Tunless: process pattern '\(pattern)' is the signing identifier every unbundled"
                    + " binary reports, so it matches unrelated programs. Match the executable"
                    + " instead, for example --exclude-process '/opt/homebrew/*/xray'. Run"
                    + " --telemetry to see the executable behind each captured flow.\n",
                to: .standardError)
        }
        let checker = SOCKSPreflight(configuration: configuration)
        preflight = checker
        checker.run { [weak self] result in
            guard let self else { return }
            self.preflight = nil
            switch result {
            case .success:
                let dns = checker.dnsReport
                if let dns, !dns.udpRelayWorks {
                    // Not fatal: applications can retry over TCP. Say so
                    // plainly, because it changes what to expect after start.
                    write("Tunless: \(dns.summary).\n", to: .standardError)
                }
                if startAfterSuccess {
                    // Hand the provider what preflight observed, so its
                    // watchdog probes the transports this upstream actually
                    // offered rather than assuming TCP is the whole story.
                    self.effectiveConfiguration = configuration.expectingUDPRelay(dns?.udpRelayWorks ?? false)
                    self.activateExtension()
                } else {
                    self.writeJSON(CheckReport(
                        ok: true,
                        preset: self.arguments.preset?.rawValue,
                        upstream: configuration.upstreamAddress,
                        detail: dns.map { "SOCKS5 negotiation passed; \($0.summary)" }
                            ?? "SOCKS5 negotiation passed; DNS override disabled",
                        dns: dns))
                    terminate(0)
                }
            case let .failure(error):
                if startAfterSuccess {
                    let hint = self.arguments.preset == .clashVerge
                        ? " Start Clash Verge and confirm its mixed/SOCKS port, then retry."
                        : " Confirm the upstream is listening and can relay DNS, then retry."
                    write("Tunless: \(error.localizedDescription).\(hint)\n", to: .standardError)
                } else {
                    self.writeJSON(CheckReport(
                        ok: false,
                        preset: self.arguments.preset?.rawValue,
                        upstream: configuration.upstreamAddress,
                        detail: error.localizedDescription,
                        dns: checker.dnsReport))
                }
                terminate(1)
            }
        }
    }

    private func activateExtension() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.providerBundleIdentifier,
            queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        if arguments.action == .cleanup {
            switch result {
            case .completed:
                reportCleanup(deactivation: "the Network Extension was deactivated")
            case .willCompleteAfterReboot:
                reportCleanup(deactivation: "Network Extension deactivation will complete after restart")
            @unknown default:
                reportCleanup(extensionError: "system extension returned an unknown deactivation result")
            }
            return
        }
        switch result {
        case .completed: configureProxy()
        case .willCompleteAfterReboot:
            write(
                "Tunless system extension will finish installing after the next restart; then run the same start command again.\n",
                to: .standardOutput)
            terminate(0)
        @unknown default:
            write("Tunless: system extension returned an unknown activation result\n", to: .standardError)
            terminate(1)
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        if arguments.action == .cleanup {
            let nsError = error as NSError
            if nsError.domain == OSSystemExtensionErrorDomain
                && nsError.code == OSSystemExtensionError.Code.extensionNotFound.rawValue {
                reportCleanup(deactivation: "the Network Extension was not installed")
            } else {
                reportCleanup(extensionError: "deactivate Network Extension: \(error.localizedDescription)")
            }
            return
        }
        write("Tunless: extension activation failed: \(error.localizedDescription)\n", to: .standardError)
        terminate(1)
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        if arguments.action == .cleanup {
            write(
                "Tunless capture is already off. Approve Network Extension removal in System Settings if prompted.\n",
                to: .standardError)
            return
        }
        write(
            "Approve Tunless in System Settings > General > Login Items & Extensions > Network Extensions.\n",
            to: .standardError)
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction { .replace }

    private func configureProxy() {
        guard let configuration = effectiveConfiguration ?? arguments.configuration else {
            write("Tunless: missing start configuration\n", to: .standardError)
            terminate(2)
        }
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error { self.fail("load proxy preferences", error: error) }
            let manager = managers?.first(where: Self.isTunlessManager) ?? NETransparentProxyManager()
            guard let encoded = try? JSONEncoder().encode(configuration) else {
                write("Tunless: could not encode proxy configuration\n", to: .standardError)
                terminate(1)
            }
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerBundleIdentifier
            proto.serverAddress = "tunless"
            proto.providerConfiguration = ["configuration": encoded]
            manager.protocolConfiguration = proto
            manager.localizedDescription = "tunless"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                if let error { self.fail("save proxy preferences", error: error) }
                manager.loadFromPreferences { error in
                    if let error { self.fail("reload proxy preferences", error: error) }
                    self.deploy(configuration, encoded: encoded, to: manager)
                }
            }
        }
    }

    /// Gets `configuration` into the running provider, or restarts it so the
    /// provider reads the saved configuration itself.
    ///
    /// A provider only reads `providerConfiguration` in `startProxy`, so a
    /// `start` against an already-running session has to hand the new
    /// configuration over as a message — and that message can be refused. It
    /// used to be sent with its reply discarded, so an update the provider
    /// rejected, or a session that was reasserting rather than connected, left
    /// capture running the previous rules while `start` reported success. An
    /// operator narrowing capture to one application would have been told it
    /// worked while everything stayed captured.
    ///
    /// So believe the provider rather than the send: it answers a single byte
    /// when it has taken the configuration, and anything else means restart.
    private func deploy(
        _ configuration: LauncherConfiguration,
        encoded: Data,
        to manager: NETransparentProxyManager
    ) {
        guard manager.connection.status == .connected,
              let session = manager.connection as? NETunnelProviderSession else {
            restart(configuration, on: manager)
            return
        }
        do {
            try session.sendProviderMessage(encoded) { response in
                guard response == Data([1]) else {
                    write(
                        "Tunless: the running proxy did not accept the new configuration;"
                            + " restarting it so the configuration you asked for is the one in effect.\n",
                        to: .standardError)
                    self.restart(configuration, on: manager)
                    return
                }
                self.reportStarted(configuration, manager: manager)
            }
        } catch {
            restart(configuration, on: manager)
        }
    }

    /// Stops the session if it is running and starts it again, so `startProxy`
    /// reads the configuration that was just saved. Capture is off in between,
    /// which means flows go direct — the same safe direction as any other
    /// moment tunless is not running.
    private func restart(_ configuration: LauncherConfiguration, on manager: NETransparentProxyManager) {
        if manager.connection.status != .disconnected && manager.connection.status != .invalid {
            manager.connection.stopVPNTunnel()
        }
        waitUntilStopped(manager, attemptsRemaining: 40) {
            do {
                try manager.connection.startVPNTunnel()
                self.reportStarted(configuration, manager: manager)
            } catch {
                self.fail("start transparent proxy", error: error)
            }
        }
    }

    private func waitUntilStopped(
        _ manager: NETransparentProxyManager,
        attemptsRemaining: Int,
        then next: @escaping () -> Void
    ) {
        let status = manager.connection.status
        if status == .disconnected || status == .invalid || attemptsRemaining <= 0 {
            next()
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
            self.waitUntilStopped(manager, attemptsRemaining: attemptsRemaining - 1, then: next)
        }
    }

    private func reportStarted(_ configuration: LauncherConfiguration, manager: NETransparentProxyManager) {
        // Capture is live now. Verify that name resolution still works through
        // the real datapath before declaring success, and roll capture back if
        // it does not. Preflight tested the upstream directly; only this check
        // exercises the provider itself, and a stall here is what leaves a host
        // unable to resolve anything.
        guard !arguments.skipVerify, configuration.dnsHost != nil else {
            // The provider is holding capture on probation and disables it
            // unless something confirms resolution. Nothing here is going to,
            // so say so explicitly rather than letting the window expire under
            // a start that was asked to skip verification.
            confirmHealthy(manager)
            announceStarted(configuration)
            return
        }
        armOperationDeadline(for: "start verification", seconds: 25)
        DNSDatapathCheck.run(timeout: 8) { [weak self] resolved in
            guard let self else { return }
            self.cancelOperationDeadline()
            if resolved {
                self.confirmHealthy(manager)
                self.announceStarted(configuration)
                return
            }
            write(
                "Tunless: capture started but DNS did not resolve through it;"
                    + " rolling capture back so the host keeps working.\n",
                to: .standardError)
            self.rollBackAfterFailedVerification()
        }
    }

    /// Tells the provider that resolution was proved through the live
    /// datapath, which ends the probation window it armed when capture
    /// started. Sent best-effort: the launcher exits either way, and a
    /// provider that never hears it disables capture, which is the safe
    /// direction to fail in.
    private func confirmHealthy(_ manager: NETransparentProxyManager) {
        guard let session = manager.connection as? NETunnelProviderSession else { return }
        try? session.sendProviderMessage(ControlMessage.confirmHealthy.encoded) { _ in }
    }

    private func announceStarted(_ configuration: LauncherConfiguration) {
        let preset = arguments.preset.map { " using \($0.rawValue) preset" } ?? ""
        write("Tunless configured\(preset); SOCKS5 upstream \(configuration.upstreamAddress).\n", to: .standardOutput)
        terminate(0)
    }

    /// Disables capture after a failed post-start verification, then exits
    /// non-zero. This is the automatic equivalent of running `stop`.
    private func rollBackAfterFailedVerification() {
        armOperationDeadline(for: "rollback")
        NETransparentProxyManager.loadAllFromPreferences { managers, _ in
            let owned = (managers ?? []).filter(Self.isTunlessManager)
            for manager in owned {
                manager.connection.stopVPNTunnel()
                manager.isEnabled = false
            }
            self.persistRolledBackManagers(owned, at: 0)
        }
    }

    private func persistRolledBackManagers(_ managers: [NETransparentProxyManager], at index: Int) {
        guard index < managers.count else {
            cancelOperationDeadline()
            write(
                "Tunless: capture is off and the previous network path is restored."
                    + " Run check to test the upstream before starting again.\n",
                to: .standardError)
            terminate(1)
        }
        managers[index].saveToPreferences { _ in
            self.persistRolledBackManagers(managers, at: index + 1)
        }
    }

    private func fetchStatus() {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error { self.fail("load proxy preferences", error: error) }
            let fields = versionFields()
            guard let manager = managers?.first(where: Self.isTunlessManager) else {
                self.writeJSON(StatusReport(
                    status: "not-configured",
                    enabled: false,
                    launcherVersion: fields.version,
                    launcherBuild: fields.build,
                    upstream: nil,
                    dnsUpstream: nil,
                    preset: nil,
                    capture: nil))
                terminate(0)
            }
            let configuration = self.savedConfiguration(manager)
            self.captureHealth(manager) { capture in
                self.writeJSON(StatusReport(
                    status: Self.statusName(manager.connection.status),
                    enabled: manager.isEnabled,
                    launcherVersion: fields.version,
                    launcherBuild: fields.build,
                    upstream: configuration?.upstreamAddress,
                    dnsUpstream: Self.dnsAddress(configuration),
                    preset: Self.presetName(configuration),
                    capture: capture))
                terminate(0)
            }
        }
    }

    /// Asks the running provider whether it is claiming flows. Answers `nil`
    /// when there is no provider to ask, and gives up rather than hanging so
    /// `status` still reports something useful if the provider is wedged.
    private func captureHealth(
        _ manager: NETransparentProxyManager,
        completion: @escaping (String?) -> Void
    ) {
        // The reply and the deadline race, and whichever wins writes the
        // report and exits, so this must answer exactly once.
        var settled = false
        let settle: (String?) -> Void = { summary in
            guard !settled else { return }
            settled = true
            completion(summary)
        }
        guard manager.connection.status == .connected,
              let session = manager.connection as? NETunnelProviderSession
        else {
            settle(nil)
            return
        }
        do {
            try session.sendProviderMessage(ControlMessage.queryHealth.encoded) { data in
                guard let data,
                      let report = try? JSONDecoder().decode(CaptureHealthReport.self, from: data)
                else {
                    settle(nil)
                    return
                }
                settle(report.summary)
            }
        } catch {
            settle(nil)
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { settle(nil) }
    }

    private func savedConfiguration(_ manager: NETransparentProxyManager) -> LauncherConfiguration? {
        guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
              let encoded = proto.providerConfiguration?["configuration"] as? Data else { return nil }
        return try? JSONDecoder().decode(LauncherConfiguration.self, from: encoded)
    }

    private static func dnsAddress(_ configuration: LauncherConfiguration?) -> String? {
        guard let host = configuration?.dnsHost, let port = configuration?.dnsPort else { return nil }
        return IPv6Address(host) == nil ? "\(host):\(port)" : "[\(host)]:\(port)"
    }

    private static func presetName(_ configuration: LauncherConfiguration?) -> String? {
        guard let excluded = configuration?.excludeProcesses,
              LauncherPreset.clashVerge.excludedProcesses.allSatisfy(excluded.contains) else { return nil }
        return LauncherPreset.clashVerge.rawValue
    }

    private static func statusName(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid: return "invalid"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "reasserting"
        case .disconnecting: return "disconnecting"
        @unknown default: return "unknown"
        }
    }

    private func fetchTelemetry() {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error { self.fail("load proxy preferences", error: error) }
            guard let manager = managers?.first(where: Self.isTunlessManager),
                  manager.connection.status == .connected,
                  let session = manager.connection as? NETunnelProviderSession else {
                write("Tunless: transparent proxy is not running\n", to: .standardError)
                terminate(1)
            }
            do {
                try session.sendProviderMessage(Data()) { response in
                    if let response { FileHandle.standardOutput.write(response) }
                    write("\n", to: .standardOutput)
                    terminate(0)
                }
            } catch {
                self.fail("read transparent proxy telemetry", error: error)
            }
        }
    }

    private static func isTunlessManager(_ manager: NETransparentProxyManager) -> Bool {
        if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
            return proto.providerBundleIdentifier == providerBundleIdentifier
        }
        // Retain an exact-label fallback only for a damaged legacy Tunless
        // manager that has already lost its protocol configuration.
        return manager.localizedDescription == "tunless"
    }

    private func stopProxy(removeConfiguration: Bool) {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error { self.fail("load proxy preferences", error: error) }
            let ownedManagers = (managers ?? []).filter(Self.isTunlessManager)
            guard !ownedManagers.isEmpty else {
                if removeConfiguration {
                    self.deactivateExtension()
                } else {
                    self.cancelOperationDeadline()
                    write("Tunless is not configured.\n", to: .standardOutput)
                    terminate(0)
                }
                return
            }

            // Stop every owned session before waiting on preference I/O. This is
            // deliberately broader than the normal single-manager happy path so
            // stale duplicate configurations cannot continue capturing traffic.
            for manager in ownedManagers {
                manager.connection.stopVPNTunnel()
                manager.isEnabled = false
            }
            self.persistStoppedManagers(
                ownedManagers,
                at: 0,
                removeConfiguration: removeConfiguration,
                errors: [])
        }
    }

    private func persistStoppedManagers(
        _ managers: [NETransparentProxyManager],
        at index: Int,
        removeConfiguration: Bool,
        errors: [String]
    ) {
        guard index < managers.count else {
            if removeConfiguration {
                cleanupPreferenceErrors = errors
                deactivateExtension()
                return
            }
            cancelOperationDeadline()
            if !errors.isEmpty {
                write(
                    "Tunless: capture was stopped, but disable was not persisted: \(errors.joined(separator: "; "))\n",
                    to: .standardError)
                terminate(1)
            }
            write("Tunless stopped; capture is off.\n", to: .standardOutput)
            terminate(0)
        }

        let manager = managers[index]
        manager.saveToPreferences { saveError in
            var nextErrors = errors
            if let saveError, !removeConfiguration {
                nextErrors.append("disable configuration \(index + 1): \(saveError.localizedDescription)")
            }
            guard removeConfiguration else {
                self.persistStoppedManagers(
                    managers,
                    at: index + 1,
                    removeConfiguration: false,
                    errors: nextErrors)
                return
            }
            manager.removeFromPreferences { removeError in
                if let removeError {
                    if let saveError {
                        nextErrors.append("disable configuration \(index + 1): \(saveError.localizedDescription)")
                    }
                    nextErrors.append("remove configuration \(index + 1): \(removeError.localizedDescription)")
                }
                self.persistStoppedManagers(
                    managers,
                    at: index + 1,
                    removeConfiguration: true,
                    errors: nextErrors)
            }
        }
    }

    private func deactivateExtension() {
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: Self.providerBundleIdentifier,
            queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    private func reportCleanup(deactivation: String? = nil, extensionError: String? = nil) {
        cancelOperationDeadline()
        var errors = cleanupPreferenceErrors
        if let extensionError { errors.append(extensionError) }
        if !errors.isEmpty {
            write(
                "Tunless: capture is off, but cleanup was incomplete: \(errors.joined(separator: "; "))\n",
                to: .standardError)
            terminate(1)
        }
        let detail = deactivation.map { "; \($0)" } ?? ""
        write(
            "Tunless cleanup complete; capture is off, proxy configurations were removed\(detail).\n",
            to: .standardOutput)
        terminate(0)
    }

    private func armOperationDeadline(for operation: String, seconds: TimeInterval = 15) {
        let timer = DispatchSource.makeTimerSource(queue: .main)
        timer.schedule(deadline: .now() + seconds)
        timer.setEventHandler {
            write(
                "Tunless: \(operation) timed out after \(Int(seconds)) seconds; run the bundled tunless-cleanup recovery script.\n",
                to: .standardError)
            terminate(1)
        }
        timer.resume()
        operationDeadline = timer
    }

    private func cancelOperationDeadline() {
        operationDeadline?.cancel()
        operationDeadline = nil
    }

    private func writeJSON<T: Encodable>(_ value: T) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(value) else {
            write("Tunless: could not encode command output\n", to: .standardError)
            terminate(1)
        }
        FileHandle.standardOutput.write(data)
        write("\n", to: .standardOutput)
    }

    private func fail(_ operation: String, error: Error) -> Never {
        write("Tunless: \(operation): \(error.localizedDescription)\n", to: .standardError)
        terminate(1)
    }
}

let app = NSApplication.shared
let delegate = AppDelegate(arguments: launcherArguments)
app.delegate = delegate
app.run()
