import Foundation
import Network
import NetworkExtension

public struct ProviderConfiguration: Codable, Sendable {
    public var upstreamHost: String
    public var upstreamPort: UInt16
    public var username: String?
    public var password: String?
	public var dnsHost: String?
	public var dnsPort: UInt16?
	public var includeProcesses: [String]?
	public var excludeProcesses: [String]?
	public var includeDestinations: [String]?
	public var excludeDestinations: [String]?
	/// Turns off the provider's own DNS health watchdog.
	///
	/// The watchdog is what makes capture give the network back when the
	/// upstream stops resolving, so this is deliberately awkward to reach: it
	/// exists for a host that would rather keep capture on through an outage
	/// than have it disabled underneath a running workload.
	public var disableHealthWatchdog: Bool?
	/// Most flows the provider will hold at once.
	///
	/// A misbehaving or merely busy application can open flows faster than the
	/// upstream retires them, and every one of them costs the extension a task
	/// and a SOCKS connection. macOS reports an extension that spends too much
	/// CPU and can terminate it, so an unbounded flow rate turns one noisy
	/// process into a capture outage for the whole host. Rejecting past a
	/// ceiling degrades that application instead, and a rejected flow is not
	/// dropped: it goes direct, exactly as it would if tunless were not
	/// installed. The portable core has enforced the same ceiling from the
	/// start; this brings the provider in line.
	public var maxConcurrentFlows: Int?

    public init(upstreamHost: String, upstreamPort: UInt16, username: String? = nil, password: String? = nil, dnsHost: String? = nil, dnsPort: UInt16? = nil, includeProcesses: [String]? = nil, excludeProcesses: [String]? = nil, includeDestinations: [String]? = nil, excludeDestinations: [String]? = nil, disableHealthWatchdog: Bool? = nil, maxConcurrentFlows: Int? = nil) {
        self.upstreamHost = upstreamHost
        self.upstreamPort = upstreamPort
        self.username = username
        self.password = password
		self.dnsHost = dnsHost
		self.dnsPort = dnsPort
		self.includeProcesses = includeProcesses
		self.excludeProcesses = excludeProcesses
		self.includeDestinations = includeDestinations
		self.excludeDestinations = excludeDestinations
		self.disableHealthWatchdog = disableHealthWatchdog
		self.maxConcurrentFlows = maxConcurrentFlows
    }

	func validated() throws -> ProviderConfiguration {
		guard !upstreamHost.isEmpty, upstreamPort > 0 else { throw ConfigurationError.invalidUpstream }
		guard (username?.utf8.count ?? 0) <= 255, (password?.utf8.count ?? 0) <= 255 else { throw ConfigurationError.credentialsTooLong }
		guard (dnsHost == nil) == (dnsPort == nil) else { throw ConfigurationError.invalidDNSUpstream }
		if let dnsHost, let dnsPort {
			guard dnsPort > 0, IPv4Address(dnsHost) != nil || IPv6Address(dnsHost) != nil else { throw ConfigurationError.invalidDNSUpstream }
		}
		if let maxConcurrentFlows, maxConcurrentFlows < 1 { throw ConfigurationError.invalidFlowCeiling }
		for prefix in (includeDestinations ?? []) + (excludeDestinations ?? []) {
			guard Self.validPrefix(prefix) else { throw ConfigurationError.invalidDestinationPrefix(prefix) }
		}
		return self
	}

	func captures(host: String, port: UInt16, signingIdentifier: String) -> Bool {
		if reservedDestination(host: host, port: port) { return false }
		if Self.matchesAny(signingIdentifier, patterns: excludeProcesses ?? []) || Self.matchesAnyPrefix(host, prefixes: excludeDestinations ?? []) { return false }
		if let patterns = includeProcesses, !patterns.isEmpty, !Self.matchesAny(signingIdentifier, patterns: patterns) { return false }
		if let prefixes = includeDestinations, !prefixes.isEmpty, !Self.matchesAnyPrefix(host, prefixes: prefixes) { return false }
		return true
	}

	/// Destinations capture must never claim, whatever the configuration says.
	///
	/// Every operator-facing exclusion is a flag someone has to remember, and
	/// the documented list is eight of them. A missing one is not discovered
	/// until capture has already taken the host off the network, which is the
	/// point at which it is hardest to fix. These paths are therefore reserved
	/// by the provider itself, so a forgotten flag, a stale saved
	/// configuration, or an over-broad `--include-destination` cannot reach
	/// them. They fall into two groups: the addresses a host needs in order to
	/// stay reachable at all, and the two addresses tunless itself relays
	/// through.
	func reservedDestination(host: String, port: UInt16) -> Bool {
		// Sending traffic aimed at the proxy back into the proxy is the loop in
		// its simplest form; the upstream is datapath, not traffic.
		if Self.sameHost(host, upstreamHost) { return true }
		// The resolver this provider rewrites captured port-53 flows to. When
		// the upstream dials it to answer one of those rewritten queries, that
		// flow must go direct: capturing it hands the query back to the same
		// upstream that is waiting on it, and every DNS lookup on the host
		// recurses instead of resolving. This is what a name-based process
		// exclusion is trying to prevent, without depending on the operator
		// naming the right process.
		if let dnsHost, let dnsPort, port == dnsPort, Self.sameHost(host, dnsHost) { return true }
		return Self.matchesAnyPrefix(host, prefixes: Self.reservedPrefixes)
	}

	/// Loopback and unspecified addresses mean nothing on the far side of a
	/// proxy. Link-local carries DHCP fallback, mDNS, and router discovery, and
	/// multicast and broadcast are not routable through SOCKS at all: proxying
	/// any of them removes reachability rather than adding a route.
	static let reservedPrefixes = [
		"127.0.0.0/8", "0.0.0.0/32", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
		"::1/128", "::/128", "fe80::/10", "ff00::/8",
	]

	/// Compares two destinations as addresses when both parse, and as text
	/// otherwise, so a hostname upstream still matches itself.
	private static func sameHost(_ lhs: String, _ rhs: String) -> Bool {
		if let left = IPv4Address(lhs)?.rawValue ?? IPv6Address(lhs)?.rawValue,
		   let right = IPv4Address(rhs)?.rawValue ?? IPv6Address(rhs)?.rawValue {
			return left == right
		}
		return lhs.caseInsensitiveCompare(rhs) == .orderedSame
	}

	/// The ceiling actually applied, defaulting to the portable core's.
	var flowCeiling: Int { maxConcurrentFlows ?? 4096 }

	func routedDestination(for destination: SOCKSAddress) -> SOCKSAddress {
		guard destination.port == 53, let dnsHost, let dnsPort else { return destination }
		return SOCKSAddress(host: dnsHost, port: dnsPort)
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

	private static func validPrefix(_ text: String) -> Bool {
		let pieces = text.split(separator: "/", maxSplits: 1)
		guard pieces.count == 2, let bits = Int(pieces[1]), let network = IPv4Address(String(pieces[0]))?.rawValue ?? IPv6Address(String(pieces[0]))?.rawValue else { return false }
		return bits >= 0 && bits <= network.count * 8
	}
}

enum ConfigurationError: Error, Equatable {
	case invalidUpstream
	case invalidDNSUpstream
	case credentialsTooLong
	case invalidDestinationPrefix(String)
	case invalidFlowCeiling
}

public struct FlowTelemetry: Codable, Sendable {
    public var protocolName: String
    public var destination: String
	public var routedDestination: String?
    public var hostname: String?
    public var signingIdentifier: String
    public var timestamp: Date
	public var event: String?
}

enum ControlRequest: Codable { case configuration, telemetry }
