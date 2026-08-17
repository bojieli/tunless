import AppKit
import NetworkExtension
import SystemExtensions

private struct LauncherConfiguration: Codable {
    let upstreamHost: String
    let upstreamPort: UInt16
    let username: String?
    let password: String?
    let includeProcesses: [String]?
    let excludeProcesses: [String]?
    let includeDestinations: [String]?
    let excludeDestinations: [String]?

    init() {
        let upstream = Self.option("--upstream") ?? ProcessInfo.processInfo.environment["TUNLESS_UPSTREAM"] ?? "127.0.0.1:7890"
        let components = URLComponents(string: upstream.contains("://") ? upstream : "socks5://\(upstream)")
        upstreamHost = components?.host ?? "127.0.0.1"
        upstreamPort = UInt16(components?.port ?? 7890)
        username = components?.user
        password = components?.password
        includeProcesses = Self.list("--include-process", environment: "TUNLESS_INCLUDE_PROCESS")
        excludeProcesses = Self.list("--exclude-process", environment: "TUNLESS_EXCLUDE_PROCESS")
        includeDestinations = Self.list("--include-destination", environment: "TUNLESS_INCLUDE_DESTINATION")
        excludeDestinations = Self.list("--exclude-destination", environment: "TUNLESS_EXCLUDE_DESTINATION")
    }

    private static func option(_ name: String) -> String? {
        for (index, argument) in CommandLine.arguments.enumerated() {
            if argument.hasPrefix("\(name)=") { return String(argument.dropFirst(name.count + 1)) }
            if argument == name, index + 1 < CommandLine.arguments.count { return CommandLine.arguments[index + 1] }
        }
        return nil
    }

    private static func list(_ option: String, environment: String) -> [String]? {
        var values: [String] = []
        for (index, argument) in CommandLine.arguments.enumerated() {
            if argument.hasPrefix("\(option)=") { values.append(String(argument.dropFirst(option.count + 1))) }
            else if argument == option, index + 1 < CommandLine.arguments.count { values.append(CommandLine.arguments[index + 1]) }
        }
        if let value = ProcessInfo.processInfo.environment[environment], !value.isEmpty {
            values.append(contentsOf: value.split(separator: ",").map(String.init))
        }
        return values.isEmpty ? nil : values
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, OSSystemExtensionRequestDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        if CommandLine.arguments.contains("--stop") {
            stopProxy()
            return
        }
        if CommandLine.arguments.contains("--telemetry") {
            fetchTelemetry()
            return
        }
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: "com.bojieli.tunless.TunlessProxy",
            queue: .main)
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        configureProxy()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        NSLog("tunless extension activation failed: \(error)")
        NSApp.terminate(nil)
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        NSLog("Approve the tunless system extension in System Settings")
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction { .replace }

    private func configureProxy() {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error { NSLog("load proxy preferences: \(error)"); NSApp.terminate(nil); return }
            let manager = managers?.first(where: { $0.localizedDescription == "tunless" }) ?? NETransparentProxyManager()
            let configuration = LauncherConfiguration()
            guard let encoded = try? JSONEncoder().encode(configuration) else { NSLog("encode proxy configuration failed"); NSApp.terminate(nil); return }
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.bojieli.tunless.TunlessProxy"
            proto.serverAddress = "tunless"
            proto.providerConfiguration = ["configuration": encoded]
            manager.protocolConfiguration = proto
            manager.localizedDescription = "tunless"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                if let error { NSLog("save proxy preferences: \(error)"); NSApp.terminate(nil); return }
                manager.loadFromPreferences { error in
                    if let error { NSLog("reload proxy preferences: \(error)"); NSApp.terminate(nil); return }
                    if manager.connection.status == .connected, let session = manager.connection as? NETunnelProviderSession {
                        do { try session.sendProviderMessage(encoded) { _ in NSApp.terminate(nil) } }
                        catch { NSLog("update transparent proxy: \(error)"); NSApp.terminate(nil) }
                    } else {
                        do { try manager.connection.startVPNTunnel() }
                        catch { NSLog("start transparent proxy: \(error)") }
                        NSApp.terminate(nil)
                    }
                }
            }
        }
    }

    private func fetchTelemetry() {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error { NSLog("load proxy preferences: \(error)"); NSApp.terminate(nil); return }
            guard let manager = managers?.first(where: { $0.localizedDescription == "tunless" }), manager.connection.status == .connected, let session = manager.connection as? NETunnelProviderSession else {
                NSLog("tunless transparent proxy is not running"); NSApp.terminate(nil); return
            }
            do {
                try session.sendProviderMessage(Data()) { response in
                    if let response {
                        FileHandle.standardOutput.write(response)
                        FileHandle.standardOutput.write(Data("\n".utf8))
                    }
                    NSApp.terminate(nil)
                }
            } catch { NSLog("read transparent proxy telemetry: \(error)"); NSApp.terminate(nil) }
        }
    }

    private func stopProxy() {
        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error { NSLog("load proxy preferences: \(error)"); NSApp.terminate(nil); return }
            guard let manager = managers?.first(where: { $0.localizedDescription == "tunless" }) else { NSApp.terminate(nil); return }
            manager.connection.stopVPNTunnel()
            manager.isEnabled = false
            manager.saveToPreferences { error in
                if let error { NSLog("disable transparent proxy: \(error)") }
                NSApp.terminate(nil)
            }
        }
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
