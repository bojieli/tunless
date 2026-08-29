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
	/// Whether preflight proved this upstream relays DNS over UDP.
	///
	/// The health watchdog needs to know what "working" looked like at start.
	/// An upstream that never offered UDP ASSOCIATE is a degraded but documented
	/// state the operator was warned about; one that offered it and stopped has
	/// broken the transport nearly every resolver client uses, and a watchdog
	/// that only probes TCP would call that healthy.
	public var expectUDPRelay: Bool?
	/// Name suffixes the DNS override leaves with the application's own
	/// resolver, in addition to the reserved and private name spaces
	/// `LocalNames` recognises on its own. A split-horizon `corp.example.com`
	/// is the shape no built-in list can predict.
	public var localDomains: [String]?

    public init(upstreamHost: String, upstreamPort: UInt16, username: String? = nil, password: String? = nil, dnsHost: String? = nil, dnsPort: UInt16? = nil, includeProcesses: [String]? = nil, excludeProcesses: [String]? = nil, includeDestinations: [String]? = nil, excludeDestinations: [String]? = nil, disableHealthWatchdog: Bool? = nil, maxConcurrentFlows: Int? = nil, expectUDPRelay: Bool? = nil, localDomains: [String]? = nil) {
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
		self.expectUDPRelay = expectUDPRelay
		self.localDomains = localDomains
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

	func captures(host: String, port: UInt16, signingIdentifier: String, executablePath: String? = nil, isDatagram: Bool = false) -> Bool {
		if reservedDestination(host: host, port: port, isDatagram: isDatagram) { return false }
		// A stream to a resolver on this network is declined, and the reason is
		// that the route has to be chosen before the name is visible. A datagram
		// carries its question in the first packet, so a name only the local
		// network can answer is recognised and sent to the resolver that has it.
		// A DNS-over-TCP connection announces nothing at connect time, so
		// capturing it means committing to the trusted resolver for whatever it
		// turns out to ask — which breaks exactly the names the local resolver
		// exists for. Leaving it alone costs the override a transport that stub
		// resolvers use only for answers too large to fit in a datagram.
		if port == 53, !isDatagram, dnsHost != nil,
			Self.matchesAnyPrefix(host, prefixes: Self.networkResolverPrefixes) {
			return false
		}
		let identity = Self.identities(signingIdentifier: signingIdentifier, executablePath: executablePath)
		if Self.matchesAny(identity, patterns: excludeProcesses ?? []) { return false }
		if let patterns = includeProcesses, !patterns.isEmpty, !Self.matchesAny(identity, patterns: patterns) { return false }
		if destinationRulesApply(port: port) {
			if Self.matchesAnyPrefix(host, prefixes: excludeDestinations ?? []) { return false }
			if let prefixes = includeDestinations, !prefixes.isEmpty, !Self.matchesAnyPrefix(host, prefixes: prefixes) { return false }
		}
		return true
	}

	/// Whether the operator's destination selection governs a flow to this port.
	///
	/// It governs every flow but one. A resolver's address is not a destination
	/// the application chose to reach — it is a resolver the network handed out,
	/// and replacing it with a trusted one is the entire point of the DNS
	/// override. Judging a port-53 flow by that address therefore asks the wrong
	/// question, and answers it in the direction that breaks silently: a home
	/// network hands out the router as the resolver, the router is inside
	/// `192.168.0.0/16`, that range is excluded by default so that capture is
	/// not put in front of somebody's own LAN, and the override is left
	/// structurally unable to see the one flow it exists for. Nothing reports an
	/// error. Queries go out on the network's own path, come back with whatever
	/// that path chose to answer, and every name on the host resolves to it.
	///
	/// Process rules still apply, and so does the reserved set. They are how the
	/// upstream is kept out of its own datapath, and a port-53 flow from the
	/// upstream is precisely the flow that must not be handed back to it.
	func destinationRulesApply(port: UInt16) -> Bool {
		guard port == 53, dnsHost != nil, dnsPort != nil else { return true }
		return false
	}

	/// Everything a process-selection pattern may legitimately match.
	///
	/// A signing identifier alone is not an identity. Binaries built without a
	/// bundle — every Homebrew tool, most Go and Rust programs — report the
	/// linker's default, so a local `xray` and any number of unrelated programs
	/// all arrive as `a.out`. Excluding that name is a shotgun, and naming the
	/// upstream's process correctly depends on how someone happened to package
	/// it. Matching the executable path and its basename as well makes the
	/// selection say what it means: `--exclude-process /opt/homebrew/*/xray`
	/// picks out one program, whatever it calls itself.
	static func identities(signingIdentifier: String, executablePath: String?) -> [String] {
		var values = [signingIdentifier]
		if let executablePath, !executablePath.isEmpty {
			values.append(executablePath)
			let base = (executablePath as NSString).lastPathComponent
			if !base.isEmpty, base != executablePath { values.append(base) }
		}
		return values
	}

	/// Signing identifiers that identify nothing, because a toolchain default
	/// gave them to every unbundled binary on the machine.
	static let ambiguousIdentifiers: Set<String> = ["a.out", "", "-"]

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
	func reservedDestination(host: String, port: UInt16, isDatagram: Bool = false) -> Bool {
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
		// The trusted resolver is reserved for every transport but the one the
		// loop guard can police. A captured datagram carries the transaction ID
		// capture assigned it, so the upstream's own forwarded copy is
		// recognisable and sent direct, which leaves an application's query to
		// the same resolver free to be claimed like any other. A stream carries
		// nothing to recognise at connect time, so it stays reserved.
		if let dnsHost, let dnsPort, port == dnsPort, Self.sameHost(host, dnsHost),
			!(isDatagram && port == 53)
		{
			return true
		}
		return Self.matchesAnyPrefix(host, prefixes: reservedPrefixes(port: port))
	}

	/// The reserved set as it applies to one port.
	///
	/// Two of these prefixes are reserved for reasons that are about the flow's
	/// destination being unreachable through a proxy, and two are about the
	/// traffic that normally goes there. Link-local is the second kind: it
	/// carries DHCP, mDNS and router discovery, none of which is on port 53 —
	/// and a router that advertises itself as the resolver over IPv6 does so at
	/// a link-local address, which makes it exactly the resolver whose answers
	/// the override exists to replace. So a port-53 flow is judged only against
	/// the addresses that cannot be carried at all.
	///
	/// Loopback stays reserved even for DNS. A local stub resolver is a real
	/// configuration and capturing it would be defensible, but the SOCKS
	/// upstream is almost always on loopback too, and the upstream is reserved
	/// by host rather than by host and port. Leaving loopback alone keeps the
	/// rule the same whether the upstream is local or not, which matters more
	/// here than reaching one more resolver.
	func reservedPrefixes(port: UInt16) -> [String] {
		guard port == 53, dnsHost != nil, dnsPort != nil else { return Self.reservedPrefixes }
		return Self.unroutablePrefixes
	}

	/// Loopback and unspecified addresses mean nothing on the far side of a
	/// proxy. Link-local carries DHCP fallback, mDNS, and router discovery, and
	/// multicast and broadcast are not routable through SOCKS at all: proxying
	/// any of them removes reachability rather than adding a route.
	static let reservedPrefixes = [
		"127.0.0.0/8", "0.0.0.0/32", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
		"::1/128", "::/128", "fe80::/10", "ff00::/8",
	]

	/// Where a resolver handed out by this network lives: the private ranges,
	/// carrier-grade NAT, loopback, and link-local. Used only to decide that a
	/// DNS-over-TCP connection to one of them is left alone; see `captures`.
	static let networkResolverPrefixes = [
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
		"127.0.0.0/8", "169.254.0.0/16",
		"fc00::/7", "::1/128", "fe80::/10",
	]

	/// The subset of `reservedPrefixes` that no proxy could carry whatever the
	/// traffic was: nothing answers at the unspecified address, and multicast
	/// and broadcast have no meaning on the far side of a SOCKS connection.
	static let unroutablePrefixes = [
		"127.0.0.0/8", "0.0.0.0/32", "224.0.0.0/4", "255.255.255.255/32",
		"::1/128", "::/128", "ff00::/8",
	]

	/// Compares two destinations as addresses when both parse, and as text
	/// otherwise, so a hostname upstream still matches itself.
	static func sameHost(_ lhs: String, _ rhs: String) -> Bool {
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

	private static func matchesAny(_ values: [String], patterns: [String]) -> Bool {
		patterns.contains { pattern in values.contains { wildcard(pattern, matches: $0) } }
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
	/// The executable behind the flow, when the audit token resolves to one.
	///
	/// Without it an operator reading telemetry sees `a.out` and has no way to
	/// tell which program that is, let alone write an exclusion for it.
	public var executablePath: String?
    public var timestamp: Date
	public var event: String?
}

enum ControlRequest: Codable { case configuration, telemetry }
