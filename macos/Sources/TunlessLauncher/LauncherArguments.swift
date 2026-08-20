import Foundation
import Network

enum LauncherAction: String, Equatable {
    case start
    case stop
    case cleanup
    case check
    case status
    case telemetry
    case help
    case version
}

enum LauncherPreset: String, Equatable {
    case clashVerge = "clash-verge"

    var defaultUpstream: String {
        switch self {
        case .clashVerge: return "127.0.0.1:7897"
        }
    }

    var excludedProcesses: [String] {
        switch self {
        case .clashVerge:
            return ["verge-mihomo", "io.github.clash-verge-rev.*"]
        }
    }
}

struct LauncherConfiguration: Codable, Equatable {
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

    var upstreamAddress: String {
        let host = IPv6Address(upstreamHost) == nil ? upstreamHost : "[\(upstreamHost)]"
        return "\(host):\(upstreamPort)"
    }
}

struct LauncherArguments: Equatable {
    let action: LauncherAction
    let preset: LauncherPreset?
    let configuration: LauncherConfiguration?
    /// Skips the post-start DNS verification and its automatic rollback.
    let skipVerify: Bool

    init(
        arguments: [String] = CommandLine.arguments,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) throws {
        var selectedAction = LauncherAction.start
        var actionWasSelected = false
        var presetName: String?
        var upstreamOption: String?
        var dnsOption: String?
        var disableDNSOverride: Bool?
        var includeProcesses: [String] = []
        var excludeProcesses: [String] = []
        var includeDestinations: [String] = []
        var excludeDestinations: [String] = []
        var skipVerifyOption: Bool?

        func select(_ action: LauncherAction) throws {
            if actionWasSelected && selectedAction != action {
                throw LauncherArgumentError.conflictingActions(selectedAction.rawValue, action.rawValue)
            }
            selectedAction = action
            actionWasSelected = true
        }

        func value(after index: Int, for option: String) throws -> String {
            let next = index + 1
            guard next < arguments.count, !arguments[next].hasPrefix("--") else {
                throw LauncherArgumentError.missingValue(option)
            }
            return arguments[next]
        }

        var index = 1
        while index < arguments.count {
            let argument = arguments[index]
            if let action = LauncherAction(rawValue: argument) {
                try select(action)
                index += 1
                continue
            }
            switch argument {
            case "-h", "--help": try select(.help)
            case "--version": try select(.version)
            case "--stop": try select(.stop)
            case "--cleanup": try select(.cleanup)
            case "--check": try select(.check)
            case "--status": try select(.status)
            case "--telemetry": try select(.telemetry)
            case "--disable-dns-override": disableDNSOverride = true
            case "--skip-verify": skipVerifyOption = true
            case "--preset":
                presetName = try value(after: index, for: argument)
                index += 1
            case "--upstream":
                upstreamOption = try value(after: index, for: argument)
                index += 1
            case "--dns-upstream":
                dnsOption = try value(after: index, for: argument)
                index += 1
            case "--include-process":
                includeProcesses.append(try value(after: index, for: argument))
                index += 1
            case "--exclude-process":
                excludeProcesses.append(try value(after: index, for: argument))
                index += 1
            case "--include-destination":
                includeDestinations.append(try value(after: index, for: argument))
                index += 1
            case "--exclude-destination":
                excludeDestinations.append(try value(after: index, for: argument))
                index += 1
            default:
                if let pair = Self.optionPair(argument) {
                    switch pair.name {
                    case "--preset": presetName = pair.value
                    case "--upstream": upstreamOption = pair.value
                    case "--dns-upstream": dnsOption = pair.value
                    case "--disable-dns-override": disableDNSOverride = try Self.boolean(pair.value, name: pair.name)
                    case "--skip-verify": skipVerifyOption = try Self.boolean(pair.value, name: pair.name)
                    case "--include-process": includeProcesses.append(pair.value)
                    case "--exclude-process": excludeProcesses.append(pair.value)
                    case "--include-destination": includeDestinations.append(pair.value)
                    case "--exclude-destination": excludeDestinations.append(pair.value)
                    default: throw LauncherArgumentError.unknownOption(pair.name)
                    }
                } else if argument.hasPrefix("-") {
                    throw LauncherArgumentError.unknownOption(argument)
                } else {
                    throw LauncherArgumentError.unexpectedArgument(argument)
                }
            }
            index += 1
        }

        action = selectedAction
        if let presetName {
            guard let parsed = LauncherPreset(rawValue: presetName) else {
                throw LauncherArgumentError.unknownPreset(presetName)
            }
            preset = parsed
        } else {
            preset = nil
        }

        if skipVerifyOption == nil, let raw = environment["TUNLESS_SKIP_VERIFY"] {
            skipVerifyOption = try Self.boolean(raw, name: "TUNLESS_SKIP_VERIFY")
        }
        skipVerify = skipVerifyOption ?? false

        guard selectedAction == .start || selectedAction == .check else {
            configuration = nil
            return
        }

        let upstream = upstreamOption
            ?? environment["TUNLESS_UPSTREAM"]
            ?? preset?.defaultUpstream
            ?? "127.0.0.1:7890"
        let components = URLComponents(string: upstream.contains("://") ? upstream : "socks5://\(upstream)")
        guard let components,
              let scheme = components.scheme,
              ["socks5", "socks5h"].contains(scheme),
              let upstreamHost = components.host,
              !upstreamHost.isEmpty,
              let parsedPort = components.port,
              parsedPort > 0,
              parsedPort <= 65_535,
              components.path.isEmpty,
              components.query == nil,
              components.fragment == nil else {
            throw LauncherArgumentError.invalidUpstream(upstream)
        }
        let username = components.user
        let password = components.password
        guard (username?.utf8.count ?? 0) <= 255, (password?.utf8.count ?? 0) <= 255 else {
            throw LauncherArgumentError.credentialsTooLong
        }

        if disableDNSOverride == nil, let raw = environment["TUNLESS_DISABLE_DNS_OVERRIDE"] {
            disableDNSOverride = try Self.boolean(raw, name: "TUNLESS_DISABLE_DNS_OVERRIDE")
        }
        let dnsHost: String?
        let dnsPort: UInt16?
        if disableDNSOverride == true {
            dnsHost = nil
            dnsPort = nil
        } else {
            let dns = dnsOption ?? environment["TUNLESS_DNS_UPSTREAM"] ?? "1.1.1.1:53"
            let dnsComponents = URLComponents(string: dns.contains("://") ? dns : "dns://\(dns)")
            guard let dnsComponents,
                  dnsComponents.scheme == "dns",
                  let parsedDNSHost = dnsComponents.host,
                  !parsedDNSHost.isEmpty,
                  IPv4Address(parsedDNSHost) != nil || IPv6Address(parsedDNSHost) != nil,
                  let parsedDNSPort = dnsComponents.port,
                  parsedDNSPort > 0,
                  parsedDNSPort <= 65_535,
                  dnsComponents.user == nil,
                  dnsComponents.password == nil,
                  dnsComponents.path.isEmpty,
                  dnsComponents.query == nil,
                  dnsComponents.fragment == nil else {
                throw LauncherArgumentError.invalidDNSUpstream(dns)
            }
            dnsHost = parsedDNSHost
            dnsPort = UInt16(parsedDNSPort)
        }

        includeProcesses.append(contentsOf: Self.environmentList("TUNLESS_INCLUDE_PROCESS", environment: environment))
        excludeProcesses.append(contentsOf: Self.environmentList("TUNLESS_EXCLUDE_PROCESS", environment: environment))
        includeDestinations.append(contentsOf: Self.environmentList("TUNLESS_INCLUDE_DESTINATION", environment: environment))
        excludeDestinations.append(contentsOf: Self.environmentList("TUNLESS_EXCLUDE_DESTINATION", environment: environment))
        if let preset {
            excludeProcesses.insert(contentsOf: preset.excludedProcesses, at: 0)
        }

        configuration = LauncherConfiguration(
            upstreamHost: upstreamHost,
            upstreamPort: UInt16(parsedPort),
            username: username,
            password: password,
            dnsHost: dnsHost,
            dnsPort: dnsPort,
            includeProcesses: Self.optionalUnique(includeProcesses),
            excludeProcesses: Self.optionalUnique(excludeProcesses),
            includeDestinations: Self.optionalUnique(includeDestinations),
            excludeDestinations: Self.optionalUnique(excludeDestinations))
    }

    private static func optionPair(_ argument: String) -> (name: String, value: String)? {
        guard argument.hasPrefix("--"), let separator = argument.firstIndex(of: "=") else { return nil }
        return (String(argument[..<separator]), String(argument[argument.index(after: separator)...]))
    }

    private static func boolean(_ raw: String, name: String) throws -> Bool {
        switch raw.lowercased() {
        case "1", "true", "yes", "on": return true
        case "0", "false", "no", "off": return false
        default: throw LauncherArgumentError.invalidBoolean(name, raw)
        }
    }

    private static func environmentList(_ name: String, environment: [String: String]) -> [String] {
        guard let value = environment[name], !value.isEmpty else { return [] }
        return value.split(separator: ",").map(String.init)
    }

    private static func optionalUnique(_ values: [String]) -> [String]? {
        var seen: Set<String> = []
        let unique = values.filter { seen.insert($0).inserted }
        return unique.isEmpty ? nil : unique
    }
}

enum LauncherArgumentError: LocalizedError, Equatable {
    case conflictingActions(String, String)
    case missingValue(String)
    case unknownOption(String)
    case unexpectedArgument(String)
    case unknownPreset(String)
    case invalidBoolean(String, String)
    case invalidUpstream(String)
    case invalidDNSUpstream(String)
    case credentialsTooLong

    var errorDescription: String? {
        switch self {
        case let .conflictingActions(first, second): return "commands \(first) and \(second) cannot be used together"
        case let .missingValue(option): return "\(option) requires a value"
        case let .unknownOption(option): return "unknown option \(option)"
        case let .unexpectedArgument(argument): return "unexpected argument \(argument)"
        case let .unknownPreset(preset): return "unknown preset \(preset); supported presets: clash-verge"
        case let .invalidBoolean(name, value): return "\(name) must be a boolean, got \(value)"
        case let .invalidUpstream(value): return "invalid SOCKS5 upstream \(value); expected host:port or socks5://[user:pass@]host:port"
        case let .invalidDNSUpstream(value): return "invalid DNS upstream \(value); expected a numeric IP:port"
        case .credentialsTooLong: return "SOCKS5 username and password must each be at most 255 bytes"
        }
    }
}
