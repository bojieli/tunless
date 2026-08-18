import AppKit
import Network
import NetworkExtension
import SystemExtensions

private struct LauncherConfiguration: Codable {
    let upstreamHost: String
    let upstreamPort: UInt16
    let username: String?
    let password: String?
    let dnsHost: String?
    let dnsPort: UInt16?
    let includeProcesses: [String]?
    let excludeProcesses: [String]?
    let includeDestinations: [String]?
    let excludeDestinations: [String]?

	private enum ConfigurationError: Error { case invalidUpstream, invalidDNSUpstream, credentialsTooLong }

	init() throws {
        let upstream = Self.option("--upstream") ?? ProcessInfo.processInfo.environment["TUNLESS_UPSTREAM"] ?? "127.0.0.1:7890"
        let components = URLComponents(string: upstream.contains("://") ? upstream : "socks5://\(upstream)")
		guard let components,let scheme=components.scheme,["socks5","socks5h"].contains(scheme),let host=components.host,!host.isEmpty,let port=components.port,port>0,port<=65535,components.path.isEmpty,components.query==nil,components.fragment==nil else{throw ConfigurationError.invalidUpstream}
		upstreamHost = host
		upstreamPort = UInt16(port)
		username = components.user
		password = components.password
		guard (username?.utf8.count ?? 0)<=255,(password?.utf8.count ?? 0)<=255 else{throw ConfigurationError.credentialsTooLong}
        let disableDNSOverride = try Self.booleanOption("--disable-dns-override", environment: "TUNLESS_DISABLE_DNS_OVERRIDE")
        if disableDNSOverride {
            self.dnsHost = nil
            self.dnsPort = nil
        } else {
            let dns = Self.option("--dns-upstream") ?? ProcessInfo.processInfo.environment["TUNLESS_DNS_UPSTREAM"] ?? "1.1.1.1:53"
            let dnsComponents = URLComponents(string: dns.contains("://") ? dns : "dns://\(dns)")
            guard let dnsComponents, dnsComponents.scheme == "dns", let dnsHost = dnsComponents.host, !dnsHost.isEmpty,
                IPv4Address(dnsHost) != nil || IPv6Address(dnsHost) != nil,
                let dnsPort = dnsComponents.port, dnsPort > 0, dnsPort <= 65535,
                dnsComponents.user == nil, dnsComponents.password == nil, dnsComponents.path.isEmpty,
                dnsComponents.query == nil, dnsComponents.fragment == nil else { throw ConfigurationError.invalidDNSUpstream }
            self.dnsHost = dnsHost
            self.dnsPort = UInt16(dnsPort)
        }
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

    private static func booleanOption(_ name: String, environment: String) throws -> Bool {
        var raw: String?
        for argument in CommandLine.arguments {
            if argument == name { raw = "true" }
            else if argument.hasPrefix("\(name)=") { raw = String(argument.dropFirst(name.count + 1)) }
        }
        if raw == nil { raw = ProcessInfo.processInfo.environment[environment] }
        guard let raw else { return false }
        switch raw.lowercased() {
        case "1", "true", "yes", "on": return true
        case "0", "false", "no", "off": return false
        default: throw ConfigurationError.invalidDNSUpstream
        }
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
			let configuration:LauncherConfiguration
			do{configuration=try LauncherConfiguration()}catch{NSLog("invalid proxy configuration: \(error)");NSApp.terminate(nil);return}
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
