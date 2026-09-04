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

/// Destination prefixes excluded unless the operator asks otherwise.
///
/// These are not reachability-critical the way the provider's reserved
/// prefixes are — a proxy that fronts a private network is a legitimate
/// configuration — but capturing them is wrong far more often than it is
/// right, and getting it wrong takes the LAN, the local resolver, or the
/// upstream's own fake-IP mapping off the host. Safety belongs in the default,
/// not in a documented list of flags the operator has to retype; a host that
/// needs one of these captured can say so with `--include-destination`, which
/// removes it from this set.
enum DefaultExclusions {
    static let destinations = [
        // RFC 1918 and RFC 4193: the LAN, whose router and resolver are the
        // path back to a working network when capture goes wrong.
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
        // RFC 6598 carrier-grade NAT, used by many home gateways.
        "100.64.0.0/10",
        // The fake-IP range mihomo and sing-box mint answers from. Such an
        // address is meaningful only to the resolver that issued it, so
        // proxying it produces a connection that opens and then transfers
        // nothing.
        "198.18.0.0/15",
    ]
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
	/// Strict mode: claim sockets even when the application explicitly scoped
	/// them to a network interface. The default leaves those sockets direct.
	let captureBoundFlows: Bool?
    let disableHealthWatchdog: Bool?
    let maxConcurrentFlows: Int?
    /// Whether preflight proved the upstream relays DNS over UDP. Filled in
    /// after the probe runs, so the provider's watchdog knows what working
    /// looked like at start rather than assuming TCP is the whole story.
    var expectUDPRelay: Bool?
    /// Name suffixes the DNS override leaves with the application's own
    /// resolver, on top of the reserved and private name spaces the provider
    /// recognises without being told.
    let localDomains: [String]?
    /// A resolver reached without the proxy, enabling answer-based selection
    /// together with `directPrefixes`.
    let directDNSHost: String?
    let directDNSPort: UInt16?
    /// Name suffixes answered by the direct resolver without adjudication.
    let directDomains: [String]?
    /// Name suffixes answered only by the trusted resolver, never asked on the
    /// direct path.
    let trustedDomains: [String]?
    /// Addresses that make an answer from the direct resolver credible.
    ///
    /// The launcher reads the list files and passes their contents, rather than
    /// passing a path for the extension to open. A system extension runs
    /// sandboxed and outside the operator's session; handing it a path is
    /// handing it something it may not be able to read and cannot report well
    /// when it cannot. The parse errors belong where the operator can see them,
    /// which is here.
    let directPrefixes: [String]?

    /// A copy that records what the DNS preflight observed about UDP.
    func expectingUDPRelay(_ expected: Bool) -> LauncherConfiguration {
        var copy = self
        copy.expectUDPRelay = expected
        return copy
    }

    /// Process patterns that name a toolchain default rather than a program.
    ///
    /// `a.out` is what every unbundled binary reports, so a rule written
    /// against it silently covers unrelated programs. Callers warn rather than
    /// refuse, because the operator may genuinely mean all of them.
    var ambiguousProcessPatterns: [String] {
        let ambiguous: Set<String> = ["a.out", "-"]
        return ((includeProcesses ?? []) + (excludeProcesses ?? [])).filter { ambiguous.contains($0) }
    }

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
    /// Whether the safe destination defaults were added to the exclusions.
    let usesDefaultExclusions: Bool

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
        var localDomains: [String] = []
        var directDomains: [String] = []
        var trustedDomains: [String] = []
        var directPrefixes: [String] = []
        var directDNSOption: String?
        var directDomainFile: String?
        var trustedDomainFile: String?
        var directPrefixFile: String?
        var skipVerifyOption: Bool?
        var defaultExclusionsOption: Bool?
		var captureBoundFlowsOption: Bool?
        var disableWatchdogOption: Bool?
        var maxFlowsOption: Int?

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
            case "--no-default-exclusions": defaultExclusionsOption = false
			case "--capture-bound-flows": captureBoundFlowsOption = true
            case "--no-health-watchdog": disableWatchdogOption = true
            case "--max-flows":
                maxFlowsOption = try Self.flowCeiling(try value(after: index, for: argument))
                index += 1
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
            case "--local-domain":
                localDomains.append(try value(after: index, for: argument))
                index += 1
            case "--direct-domain":
                directDomains.append(try value(after: index, for: argument))
                index += 1
            case "--trusted-domain":
                trustedDomains.append(try value(after: index, for: argument))
                index += 1
            case "--dns-direct-prefix":
                directPrefixes.append(try value(after: index, for: argument))
                index += 1
            case "--dns-direct":
                directDNSOption = try value(after: index, for: argument)
                index += 1
            case "--direct-domain-file":
                directDomainFile = try value(after: index, for: argument)
                index += 1
            case "--trusted-domain-file":
                trustedDomainFile = try value(after: index, for: argument)
                index += 1
            case "--dns-direct-prefix-file":
                directPrefixFile = try value(after: index, for: argument)
                index += 1
            default:
                if let pair = Self.optionPair(argument) {
                    switch pair.name {
                    case "--preset": presetName = pair.value
                    case "--upstream": upstreamOption = pair.value
                    case "--dns-upstream": dnsOption = pair.value
                    case "--disable-dns-override": disableDNSOverride = try Self.boolean(pair.value, name: pair.name)
                    case "--skip-verify": skipVerifyOption = try Self.boolean(pair.value, name: pair.name)
                    case "--no-default-exclusions":
                        defaultExclusionsOption = !(try Self.boolean(pair.value, name: pair.name))
					case "--capture-bound-flows":
						captureBoundFlowsOption = try Self.boolean(pair.value, name: pair.name)
                    case "--no-health-watchdog":
                        disableWatchdogOption = try Self.boolean(pair.value, name: pair.name)
                    case "--max-flows": maxFlowsOption = try Self.flowCeiling(pair.value)
                    case "--include-process": includeProcesses.append(pair.value)
                    case "--exclude-process": excludeProcesses.append(pair.value)
                    case "--include-destination": includeDestinations.append(pair.value)
                    case "--exclude-destination": excludeDestinations.append(pair.value)
                    case "--local-domain": localDomains.append(pair.value)
                    case "--direct-domain": directDomains.append(pair.value)
                    case "--trusted-domain": trustedDomains.append(pair.value)
                    case "--dns-direct-prefix": directPrefixes.append(pair.value)
                    case "--dns-direct": directDNSOption = pair.value
                    case "--direct-domain-file": directDomainFile = pair.value
                    case "--trusted-domain-file": trustedDomainFile = pair.value
                    case "--dns-direct-prefix-file": directPrefixFile = pair.value
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
            usesDefaultExclusions = false
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
        localDomains.append(contentsOf: Self.environmentList("TUNLESS_LOCAL_DOMAIN", environment: environment))
        directDomains.append(contentsOf: Self.environmentList("TUNLESS_DIRECT_DOMAIN", environment: environment))
        trustedDomains.append(contentsOf: Self.environmentList("TUNLESS_TRUSTED_DOMAIN", environment: environment))
        directPrefixes.append(contentsOf: Self.environmentList("TUNLESS_DNS_DIRECT_PREFIX", environment: environment))
        if directDNSOption == nil { directDNSOption = environment["TUNLESS_DNS_DIRECT"] }
        if directDomainFile == nil { directDomainFile = environment["TUNLESS_DIRECT_DOMAIN_FILE"] }
        if trustedDomainFile == nil { trustedDomainFile = environment["TUNLESS_TRUSTED_DOMAIN_FILE"] }
        if directPrefixFile == nil { directPrefixFile = environment["TUNLESS_DNS_DIRECT_PREFIX_FILE"] }
        if let path = directDomainFile {
            directDomains.append(contentsOf: try Self.readListFile(path, option: "--direct-domain-file"))
        }
        if let path = trustedDomainFile {
            trustedDomains.append(contentsOf: try Self.readListFile(path, option: "--trusted-domain-file"))
        }
        if let path = directPrefixFile {
            directPrefixes.append(contentsOf: try Self.readListFile(path, option: "--dns-direct-prefix-file"))
        }
        if let preset {
            excludeProcesses.insert(contentsOf: preset.excludedProcesses, at: 0)
        }

        if maxFlowsOption == nil, let raw = environment["TUNLESS_MAX_FLOWS"] {
            maxFlowsOption = try Self.flowCeiling(raw)
        }
		if captureBoundFlowsOption == nil, let raw = environment["TUNLESS_CAPTURE_BOUND_FLOWS"] {
			captureBoundFlowsOption = try Self.boolean(raw, name: "TUNLESS_CAPTURE_BOUND_FLOWS")
		}
        if disableWatchdogOption == nil, let raw = environment["TUNLESS_NO_HEALTH_WATCHDOG"] {
            disableWatchdogOption = try Self.boolean(raw, name: "TUNLESS_NO_HEALTH_WATCHDOG")
        }
        if defaultExclusionsOption == nil, let raw = environment["TUNLESS_NO_DEFAULT_EXCLUSIONS"] {
            defaultExclusionsOption = !(try Self.boolean(raw, name: "TUNLESS_NO_DEFAULT_EXCLUSIONS"))
        }
        usesDefaultExclusions = defaultExclusionsOption ?? true
        if usesDefaultExclusions {
            // An explicit include wins: naming a prefix is the operator saying
            // they want it captured, and a default must not silently override
            // what was asked for.
            let requested = Set(includeDestinations)
            excludeDestinations.append(
                contentsOf: DefaultExclusions.destinations.filter { !requested.contains($0) })
        }

        // The direct resolver and its credible-address set are validated here
        // rather than in the extension, because every incoherent combination
        // has a runtime appearance identical to the feature working perfectly
        // and finding nothing to do — which is the one failure an operator
        // cannot distinguish by looking.
        var directDNSHost: String?
        var directDNSPort: UInt16?
        if let directDNS = directDNSOption, !directDNS.isEmpty {
            guard disableDNSOverride != true else {
                throw LauncherArgumentError.directResolverWithoutOverride
            }
            let parts = directDNS.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count >= 2, let port = UInt16(parts[parts.count - 1]), port > 0 else {
                throw LauncherArgumentError.invalidDirectResolver(directDNS)
            }
            var host = parts.dropLast().joined(separator: ":")
            if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
            guard !host.isEmpty, IPv4Address(host) != nil || IPv6Address(host) != nil else {
                throw LauncherArgumentError.invalidDirectResolver(directDNS)
            }
            guard !directPrefixes.isEmpty else {
                throw LauncherArgumentError.directResolverWithoutPrefixes
            }
            directDNSHost = host
            directDNSPort = port
        } else if !directPrefixes.isEmpty {
            throw LauncherArgumentError.prefixesWithoutDirectResolver
        }
        for prefix in directPrefixes where !Self.validDirectPrefix(prefix) {
            throw LauncherArgumentError.invalidDirectPrefix(prefix)
        }
        // A list is thousands of lines nobody reads. A line that cannot mean
        // anything has to be reported, not skipped: skipping it produces a
        // policy that is quietly missing an entry the operator believes is
        // there.
        for suffix in directDomains + trustedDomains where !Self.validDomainSuffix(suffix) {
            throw LauncherArgumentError.invalidDomainSuffix(suffix)
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
            excludeDestinations: Self.optionalUnique(excludeDestinations),
			captureBoundFlows: captureBoundFlowsOption,
            disableHealthWatchdog: disableWatchdogOption,
            maxConcurrentFlows: maxFlowsOption,
            expectUDPRelay: nil,
            localDomains: Self.optionalUnique(localDomains),
            directDNSHost: directDNSHost,
            directDNSPort: directDNSPort,
            directDomains: Self.optionalUnique(directDomains),
            trustedDomains: Self.optionalUnique(trustedDomains),
            directPrefixes: Self.optionalUnique(directPrefixes))
    }

    /// Reads a list file: one entry per line, blanks and comments skipped, an
    /// inline comment ending a line.
    ///
    /// Nothing else about the format is negotiable. This reads a list, not a
    /// configuration language, and the moment it parses somebody else's file
    /// format it owns that format's next revision.
    static func readListFile(_ path: String, option: String) throws -> [String] {
        guard let contents = try? String(contentsOfFile: path, encoding: .utf8) else {
            throw LauncherArgumentError.unreadableList(option, path)
        }
        var entries: [String] = []
        for line in contents.split(separator: "\n", omittingEmptySubsequences: false) {
            var entry = String(line)
            if let cut = entry.firstIndex(where: { $0 == "#" || $0 == ";" }) {
                entry = String(entry[..<cut])
            }
            let trimmed = entry.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            entries.append(trimmed)
            // Bounded so that a path pointed at the wrong file fails with a
            // clear message instead of being read into memory.
            if entries.count > 1_048_576 {
                throw LauncherArgumentError.unreadableList(option, path)
            }
        }
        return entries
    }

    /// Whether an entry is a usable name suffix.
    ///
    /// Matched on label boundaries later, so an empty label, an over-long one,
    /// or embedded whitespace cannot mean anything and is refused here rather
    /// than dropped where nobody sees it. A trailing root label is fine: it is
    /// valid FQDN syntax and plenty of generated lists carry it.
    static func validDomainSuffix(_ entry: String) -> Bool {
        var candidate = entry.trimmingCharacters(in: .whitespaces).lowercased()
        while candidate.hasSuffix(".") { candidate.removeLast() }
        guard !candidate.isEmpty else { return false }
        guard !candidate.contains(where: { $0 == " " || $0 == "\t" }) else { return false }
        let labels = candidate.split(separator: ".", omittingEmptySubsequences: false)
        return !labels.contains { $0.isEmpty || $0.utf8.count > 63 }
    }

    /// Whether an entry is a CIDR prefix or a bare address.
    ///
    /// A bare address is accepted as a host route, because a hand-written
    /// exception list is easier to read without a /32 on every line and every
    /// line that omits one plainly means the single address.
    static func validDirectPrefix(_ entry: String) -> Bool {
        let trimmed = entry.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return false }
        let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let host = String(parts[0])
        let width: Int
        if IPv4Address(host) != nil {
            width = 32
        } else if IPv6Address(host) != nil {
            width = 128
        } else {
            return false
        }
        guard parts.count == 2 else { return true }
        guard let bits = Int(parts[1]), bits >= 0, bits <= width else { return false }
        return true
    }

    private static func optionPair(_ argument: String) -> (name: String, value: String)? {
        guard argument.hasPrefix("--"), let separator = argument.firstIndex(of: "=") else { return nil }
        return (String(argument[..<separator]), String(argument[argument.index(after: separator)...]))
    }

    private static func flowCeiling(_ raw: String) throws -> Int {
        guard let value = Int(raw), value > 0 else { throw LauncherArgumentError.invalidFlowCeiling(raw) }
        return value
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
    case invalidFlowCeiling(String)
    case invalidDirectResolver(String)
    case unreadableList(String, String)
    case directResolverWithoutPrefixes
    case prefixesWithoutDirectResolver
    case directResolverWithoutOverride
    case invalidDirectPrefix(String)
    case invalidDomainSuffix(String)

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
        case let .invalidFlowCeiling(value): return "--max-flows must be a positive integer, got \(value)"
        case let .invalidDirectResolver(value): return "invalid --dns-direct \(value); expected a numeric IP:port"
        case let .unreadableList(option, path): return "\(option) could not read \(path)"
        case .directResolverWithoutPrefixes:
            return "--dns-direct needs --dns-direct-prefix or --dns-direct-prefix-file: without addresses to judge by, no direct answer can ever be believed"
        case .prefixesWithoutDirectResolver:
            return "--dns-direct-prefix needs --dns-direct: prefixes judge answers from a direct resolver, and no direct resolver is configured"
        case .directResolverWithoutOverride:
            return "--disable-dns-override leaves every query with the application's own resolver, so --dns-direct has nothing to route"
        case let .invalidDirectPrefix(value): return "invalid --dns-direct-prefix \(value); expected a CIDR prefix or a bare address"
        case let .invalidDomainSuffix(value): return "invalid name suffix \(value); expected a domain name such as example.com"
        }
    }
}
