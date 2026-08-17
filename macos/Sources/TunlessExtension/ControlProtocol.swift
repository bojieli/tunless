import Foundation
import Network
import NetworkExtension

public struct ProviderConfiguration: Codable, Sendable {
    public var upstreamHost: String
    public var upstreamPort: UInt16
    public var username: String?
    public var password: String?
	public var includeProcesses: [String]?
	public var excludeProcesses: [String]?
	public var includeDestinations: [String]?
	public var excludeDestinations: [String]?

    public init(upstreamHost: String, upstreamPort: UInt16, username: String? = nil, password: String? = nil, includeProcesses: [String]? = nil, excludeProcesses: [String]? = nil, includeDestinations: [String]? = nil, excludeDestinations: [String]? = nil) {
        self.upstreamHost = upstreamHost
        self.upstreamPort = upstreamPort
        self.username = username
        self.password = password
		self.includeProcesses = includeProcesses
		self.excludeProcesses = excludeProcesses
		self.includeDestinations = includeDestinations
		self.excludeDestinations = excludeDestinations
    }

	func captures(host: String, signingIdentifier: String) -> Bool {
		if Self.matchesAny(signingIdentifier, patterns: excludeProcesses ?? []) || Self.matchesAnyPrefix(host, prefixes: excludeDestinations ?? []) { return false }
		if let patterns = includeProcesses, !patterns.isEmpty, !Self.matchesAny(signingIdentifier, patterns: patterns) { return false }
		if let prefixes = includeDestinations, !prefixes.isEmpty, !Self.matchesAnyPrefix(host, prefixes: prefixes) { return false }
		return true
	}

	private static func matchesAny(_ value: String, patterns: [String]) -> Bool {
		patterns.contains { wildcard($0, matches: value) }
	}

	private static func wildcard(_ pattern: String, matches value: String) -> Bool {
		let p = Array(pattern), v = Array(value)
		var previous = Array(repeating: false, count: v.count + 1)
		previous[0] = true
		for token in p {
			var next = Array(repeating: false, count: v.count + 1)
			if token == "*" { next[0] = previous[0] }
			if !v.isEmpty {
				for index in 1...v.count {
					if token == "*" { next[index] = previous[index] || next[index - 1] }
					else if token == "?" || token == v[index - 1] { next[index] = previous[index - 1] }
				}
			}
			previous = next
		}
		return previous[v.count]
	}

	private static func matchesAnyPrefix(_ host: String, prefixes: [String]) -> Bool {
		guard let address = IPv4Address(host)?.rawValue ?? IPv6Address(host)?.rawValue else { return false }
		return prefixes.contains { text in
			let pieces = text.split(separator: "/", maxSplits: 1)
			guard pieces.count == 2, let bits = Int(pieces[1]), let network = IPv4Address(String(pieces[0]))?.rawValue ?? IPv6Address(String(pieces[0]))?.rawValue, network.count == address.count, bits >= 0, bits <= address.count * 8 else { return false }
			let whole = bits / 8, remainder = bits % 8
			if whole > 0 && address.prefix(whole) != network.prefix(whole) { return false }
			if remainder == 0 { return true }
			let mask = UInt8(256 - (1 << (8 - remainder)))
			return address[whole] & mask == network[whole] & mask
		}
	}
}

public struct FlowTelemetry: Codable, Sendable {
    public var protocolName: String
    public var destination: String
    public var hostname: String?
    public var signingIdentifier: String
    public var timestamp: Date
}

enum ControlRequest: Codable { case configuration, telemetry }
