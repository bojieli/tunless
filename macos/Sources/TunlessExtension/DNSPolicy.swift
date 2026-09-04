import Foundation
import Network

/// Decides which resolver answers a captured DNS query, and which of two
/// answers to believe when both were asked.
///
/// Capture rewrites port-53 flows to a trusted resolver reached through the
/// proxy, so that an answer from the network the host happens to be on cannot
/// decide where a connection goes. That is the right default and it stays the
/// default. It has two costs that this type exists to let an operator buy back,
/// deliberately and one at a time.
///
/// The first is locality. A resolver on the far side of a tunnel answers a
/// geographically aware name from where the tunnel exits, so a service that
/// would have handed this host a nearby address hands it a distant one instead.
/// The name resolved correctly and the connection is slow.
///
/// The second is availability. When every lookup on the host goes through one
/// proxy, that proxy going down does not degrade name resolution, it ends it —
/// including for the destinations an operator already excluded from capture and
/// which would otherwise still be reachable. The routes are fine. Nothing can
/// learn an address to use them with.
///
/// Two mechanisms answer those, and they decide at different moments. A name
/// list decides from the question, before anything leaves the host: exact,
/// free, and limited to the names someone thought to list. An address set
/// decides from the answer, by asking both resolvers and believing the direct
/// one only when it names an address inside a set the operator supplied: it
/// catches every name nobody listed, at the cost of one query on the direct
/// path per unlisted name. They compose, the lists deciding first.
///
/// The Go side of the project carries the same policy in
/// `internal/dnspolicy`, and the two are meant to agree name for name and
/// verdict for verdict.
enum DNSRoute: String, Sendable {
    /// The trusted resolver, through the proxy. The default for everything, and
    /// the behaviour of the datapath before this type existed.
    case trusted
    /// The direct resolver, or the resolver the application chose when none is
    /// configured. Served without adjudication.
    case direct
    /// The resolver the application chose, because the name has no answer
    /// anywhere else. See `LocalNames`.
    case local
    /// Both resolvers, with the answers deciding. See `DNSPolicy.adjudicate`.
    case adjudicate
}

/// Why a route was chosen. Not decoration: with four layers and two
/// operator-supplied lists, "which layer decided this" is the question every
/// misroute investigation starts from, and it is what the counters are keyed on.
enum DNSDecisionReason: String, Sendable {
    case unreadableQuery = "unreadable-query"
    case localName = "local-name"
    case directList = "direct-list"
    case trustedList = "trusted-list"
    case noDirectResolver = "no-direct-resolver"
    case notAddressQuery = "not-an-address-query"
    case unlisted
}

struct DNSDecision: Sendable, Equatable {
    let route: DNSRoute
    let reason: DNSDecisionReason
    /// The list entry that matched, when one did.
    let suffix: String?

    init(route: DNSRoute, reason: DNSDecisionReason, suffix: String? = nil) {
        self.route = route
        self.reason = reason
        self.suffix = suffix
    }
}

/// Maps name suffixes to routes, answering with the longest one that matches.
///
/// Longest match rather than list order, because that is what every resolver an
/// operator already runs does — dnsmasq, mosdns and systemd-resolved all
/// resolve an overlap by specificity — and because the overlap has an obvious
/// intended meaning that order would get wrong. Someone who sends
/// `example.com` down the direct path and `secret.example.com` through the
/// tunnel has said something precise, and a set that resolved that by which
/// file loaded first would silently do the opposite of it.
///
/// The trie is over labels rather than characters, so `notexample.com` cannot
/// match `example.com` by sharing a suffix that does not start at a label
/// boundary.
struct DNSSuffixSet: Sendable {
    private final class Node: @unchecked Sendable {
        var children: [String: Node] = [:]
        var route: DNSRoute?
        var suffix: String?
    }

    private let root = Node()
    private(set) var count = 0

    init() {}

    init(direct: [String], trusted: [String]) {
        // The trusted list is added first so a duplicate resolves toward the
        // tunnel; see `add`.
        for suffix in trusted { add(suffix, route: .trusted) }
        for suffix in direct { add(suffix, route: .direct) }
    }

    /// Records one suffix.
    ///
    /// A suffix already present keeps `.trusted` if either entry asked for it.
    /// That is the tie-break for an exact duplicate across the two lists, and it
    /// breaks toward the tunnel on purpose: the direct list is the one an
    /// operator downloads with thousands of entries in it, the trusted list is
    /// the one they write by hand to carve exceptions out of it, and a collision
    /// between a list you audited and one you did not should resolve in favour
    /// of the audited one. It also fails safe — a name that ends up on the
    /// tunnel by accident is slow, and one that ends up on the direct path by
    /// accident is exposed.
    mutating func add(_ suffix: String, route: DNSRoute) {
        let canonical = LocalNames.canonical(suffix)
        guard !canonical.isEmpty else { return }
        let labels = canonical.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard !labels.contains(where: { $0.isEmpty || $0.utf8.count > 63 }) else { return }
        var node = root
        for label in labels.reversed() {
            if let existing = node.children[label] {
                node = existing
                continue
            }
            let child = Node()
            node.children[label] = child
            node = child
        }
        if node.route == nil {
            node.route = route
            node.suffix = canonical
            count += 1
            return
        }
        if node.route != route { node.route = .trusted }
    }

    /// Returns the route of the longest suffix covering `name`.
    func match(_ name: String) -> (route: DNSRoute, suffix: String)? {
        guard count > 0 else { return nil }
        let canonical = LocalNames.canonical(name)
        guard !canonical.isEmpty else { return nil }
        var node = root
        var best: (DNSRoute, String)?
        for label in canonical.split(separator: ".").map(String.init).reversed() {
            guard let child = node.children[label] else { break }
            node = child
            if let route = node.route, let suffix = node.suffix { best = (route, suffix) }
        }
        guard let best else { return nil }
        return (route: best.0, suffix: best.1)
    }
}

/// The set of addresses that make an answer from the direct resolver credible.
///
/// Stored as merged, sorted ranges rather than as the prefix list it was built
/// from, and searched by bisection. The lists operators actually supply here run
/// to five figures — a national address allocation is around nine thousand v4
/// prefixes before v6 — and this is consulted once per address in every
/// adjudicated answer. A linear scan would put tens of thousands of comparisons
/// inside the lookup path, which is the one place in this project that must not
/// become the reason a page is slow.
///
/// Merging is not only an optimisation. Supplied lists routinely contain
/// adjacent and overlapping prefixes, and collapsing them means the bisection
/// cannot land between two entries that jointly cover the address.
struct DNSPrefixSet: Sendable {
    fileprivate struct AddressRange: Sendable {
        let low: [UInt8]
        var high: [UInt8]
    }

    private var v4: [AddressRange] = []
    private var v6: [AddressRange] = []

    init() {}

    init(prefixes: [String]) {
        var four: [AddressRange] = []
        var six: [AddressRange] = []
        for entry in prefixes {
            guard let range = Self.parse(entry) else { continue }
            if range.low.count == 4 { four.append(range) } else { six.append(range) }
        }
        v4 = Self.merge(four)
        v6 = Self.merge(six)
    }

    var isEmpty: Bool { v4.isEmpty && v6.isEmpty }

    /// How many disjoint ranges remain after merging. Reported at startup and in
    /// diagnostics so an operator can see that a file with fifty thousand lines
    /// in it produced a set with something in it.
    var count: Int { v4.count + v6.count }

    /// Whether `address` falls in the set. An IPv4-mapped IPv6 address is judged
    /// as the IPv4 address it carries, because that is the address a connection
    /// to it would use.
    func contains(_ address: Data) -> Bool {
        var octets = [UInt8](address)
        if octets.count == 16, Self.isMappedV4(octets) { octets = Array(octets[12 ..< 16]) }
        let ranges = octets.count == 4 ? v4 : v6
        guard !ranges.isEmpty, octets.count == 4 || octets.count == 16 else { return false }
        // The first range whose low end is above the address cannot contain it,
        // so the one before it is the only candidate.
        var low = 0
        var high = ranges.count
        while low < high {
            let middle = (low + high) / 2
            if Self.compare(ranges[middle].low, octets) > 0 { high = middle } else { low = middle + 1 }
        }
        guard low > 0 else { return false }
        return Self.compare(ranges[low - 1].high, octets) >= 0
    }

    /// Parses a CIDR prefix, or a bare address as a host route. A hand-written
    /// exception list is easier to read without a /32 on every line, and every
    /// line that omits one plainly means the single address.
    fileprivate static func parse(_ entry: String) -> AddressRange? {
        let trimmed = entry.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let host = String(parts[0])
        guard let raw = IPv4Address(host)?.rawValue ?? IPv6Address(host)?.rawValue else { return nil }
        var octets = [UInt8](raw)
        // A mapped v4 prefix is the v4 prefix it carries, because that is the
        // address a connection to it would use and the address an answer
        // carries it as.
        if octets.count == 16, isMappedV4(octets) { octets = Array(octets[12 ..< 16]) }
        let width = octets.count * 8
        var bits = width
        if parts.count == 2 {
            guard let requested = Int(parts[1]), requested >= 0, requested <= width else { return nil }
            bits = requested
        }
        for index in bits ..< width { octets[index / 8] &= ~(UInt8(1) << (7 - index % 8)) }
        var high = octets
        for index in bits ..< width { high[index / 8] |= UInt8(1) << (7 - index % 8) }
        return AddressRange(low: octets, high: high)
    }

    /// Whether a valid entry parses, for configuration validation.
    static func isValidPrefix(_ entry: String) -> Bool { parse(entry) != nil }

    private static func merge(_ ranges: [AddressRange]) -> [AddressRange] {
        guard ranges.count > 1 else { return ranges }
        let sorted = ranges.sorted { compare($0.low, $1.low) < 0 }
        var merged: [AddressRange] = [sorted[0]]
        for next in sorted.dropFirst() {
            let last = merged[merged.count - 1]
            // Adjacent counts as overlapping: 10.0.0.0/24 and 10.0.1.0/24 leave
            // no address between them, and keeping them apart would only add a
            // range for the bisection to cross.
            if compare(next.low, last.high) <= 0 || next.low == successor(last.high) {
                if compare(next.high, last.high) > 0 { merged[merged.count - 1].high = next.high }
                continue
            }
            merged.append(next)
        }
        return merged
    }

    /// The next address after `octets`, or nil at the top of the family.
    private static func successor(_ octets: [UInt8]) -> [UInt8]? {
        var next = octets
        var index = next.count - 1
        while index >= 0 {
            if next[index] < 0xff {
                next[index] += 1
                return next
            }
            next[index] = 0
            index -= 1
        }
        return nil
    }

    private static func compare(_ lhs: [UInt8], _ rhs: [UInt8]) -> Int {
        guard lhs.count == rhs.count else { return lhs.count < rhs.count ? -1 : 1 }
        for (left, right) in zip(lhs, rhs) where left != right { return left < right ? -1 : 1 }
        return 0
    }

    private static func isMappedV4(_ octets: [UInt8]) -> Bool {
        octets[0 ..< 10].allSatisfy { $0 == 0 } && octets[10] == 0xff && octets[11] == 0xff
    }
}

/// What an adjudication has concluded so far.
enum DNSVerdict: String, Sendable {
    case wait
    /// Return the direct resolver's reply to the application.
    case serveDirect = "serve-direct"
    /// Return the trusted resolver's reply.
    case serveTrusted = "serve-trusted"
    /// Return SERVFAIL, chosen over serving an answer that could be wrong in the
    /// direction that matters.
    case refuse
    /// Return nothing, leaving the application's own resolver to retry the way
    /// it would against any resolver that did not answer.
    case drop
}

enum DNSVerdictReason: String, Sendable {
    case directInSet = "direct-in-set"
    case directOutOfSet = "direct-out-of-set"
    case directNoAnswer = "direct-no-answer"
    case trustedOnly = "trusted-only"
    case suspectAnswerRefused = "suspect-answer-refused"
    case noReply = "no-reply"
}

/// The state of one adjudication: what each half has produced and whether it is
/// still able to produce anything.
struct DNSExchange: Sendable {
    var direct: Data?
    var trusted: Data?
    /// Reports that the half will produce nothing further, whether because it
    /// answered or because it failed.
    var directDone = false
    var trustedDone = false
    /// Reports that `directReplyWindow` has elapsed, so the direct half can no
    /// longer change the outcome even if it has not formally finished.
    var directWindowClosed = false
    var deadlineReached = false
}

struct DNSPolicy: Sendable {
    /// The operator's split-horizon zones, added to the reserved and private
    /// name spaces `LocalNames` recognises on its own.
    var localDomains: [String] = []
    var suffixes = DNSSuffixSet()
    var prefixes = DNSPrefixSet()
    /// The resolver reached without the proxy. Nil means a `.direct` query goes
    /// to the resolver the application chose, which is what makes the name lists
    /// useful on their own.
    var directResolver: SOCKSAddress?

    /// Bounds how long an adjudication waits for the direct resolver once the
    /// trusted one has already answered usably.
    ///
    /// Waiting at all is what keeps the outcome from depending on a race. If the
    /// first answer to arrive won, the same name would resolve differently on a
    /// busy network than on an idle one, and a policy whose result depends on
    /// timing cannot be reasoned about or tested. Bounding the wait is what
    /// keeps that from costing a round trip on every lookup when the direct
    /// resolver is not answering at all: it is by construction the near one, so
    /// a reply that has not arrived within this window was not going to improve
    /// the answer.
    static let directReplyWindow: TimeInterval = 0.8
    /// Bounds the whole exchange. Past it the query is decided on whatever
    /// arrived, which is usually nothing.
    static let adjudicationDeadline: TimeInterval = 4

    /// Whether this policy ever asks two resolvers. Both halves are required: a
    /// direct resolver to ask, and a prefix set to judge with.
    var adjudicates: Bool { directResolver != nil && !prefixes.isEmpty }

    /// Picks the resolver for one raw query.
    ///
    /// The layers are checked in an order that is not a preference ranking.
    /// Local names come first because they are a different category rather than
    /// a stronger opinion: those names have no answer anywhere but the resolver
    /// the application asked, so no list and no address set can make another
    /// resolver right for them. Everything after that is preference, and there
    /// longest-suffix match decides, not the order the lists were given in.
    func decide(_ query: Data) -> DNSDecision {
        guard let message = DNSMessage.parse(query), !message.questions.isEmpty else {
            return DNSDecision(route: .trusted, reason: .unreadableQuery)
        }
        // A query mixing a local name with a public one is not local: half of it
        // would be unanswerable by the local resolver, and the local resolver is
        // the only place the whole message can go.
        if message.questions.allSatisfy({ LocalNames.isLocal($0.name, extraSuffixes: localDomains) }) {
            return DNSDecision(route: .local, reason: .localName)
        }
        if let listed = listRoute(message.questions) {
            switch listed.route {
            case .direct:
                return DNSDecision(route: .direct, reason: .directList, suffix: listed.suffix)
            case .trusted:
                return DNSDecision(route: .trusted, reason: .trustedList, suffix: listed.suffix)
            default:
                break
            }
        }
        guard adjudicates else {
            return DNSDecision(route: .trusted, reason: .noDirectResolver)
        }
        // Adjudication reads addresses out of the answer and tests them against
        // the prefix set, so a question with no address to test cannot be
        // adjudicated. Those go to the trusted resolver rather than to a coin
        // flip.
        //
        // HTTPS and SVCB are the ones that matter here, and not because they are
        // unusual: a browser asks for them on every navigation, and the record
        // carries the encrypted-client-hello configuration. Serving one from the
        // direct path hands whoever answered it the ability to strip ECH, which
        // is a downgrade this project would be inflicting rather than
        // preventing.
        for question in message.questions
        where question.type != DNSMessage.typeA && question.type != DNSMessage.typeAAAA {
            return DNSDecision(route: .trusted, reason: .notAddressQuery)
        }
        return DNSDecision(route: .adjudicate, reason: .unlisted)
    }

    /// Matches the question names against the operator's name lists.
    ///
    /// Every name in the message has to agree. A message whose names would take
    /// different routes cannot be sent twice — it is one datagram with one
    /// transaction ID — so there is no route that serves it, and the caller
    /// falls through to the default rather than picking one name's answer over
    /// another's.
    private func listRoute(_ questions: [DNSMessage.Question]) -> (route: DNSRoute, suffix: String)? {
        guard let first = questions.first, let matched = suffixes.match(first.name) else { return nil }
        for question in questions.dropFirst() {
            guard let other = suffixes.match(question.name), other.route == matched.route else {
                return nil
            }
        }
        return matched
    }

    /// Decides what to do with the answers so far.
    ///
    /// An answer from the direct resolver is believed when it names an address
    /// inside the operator's set, and that decision is made the moment it
    /// arrives. Nothing the trusted resolver could say would change it, so
    /// nothing waits for it, and the names an operator cares about most — the
    /// ones near enough for the set to cover — resolve at the speed of the near
    /// resolver and do not depend on the tunnel being up at all.
    ///
    /// An answer naming addresses outside the set is not served. It may be a
    /// perfectly good answer for a service that is genuinely far away, and it
    /// may be an injected one; from the addresses alone those are the same
    /// message. So the trusted resolver decides, which is what would have
    /// happened without any of this.
    ///
    /// An answer naming no address at all is a third case, and the one worth
    /// being careful about. Refusing it costs real traffic: every AAAA lookup
    /// for a v4-only host returns no address, and treating that as suspect would
    /// put a tunnel round trip in front of half of every dual-stack
    /// application's lookups, and fail them outright while the tunnel is down.
    /// Serving it cannot misroute a connection, because there is no address in
    /// it to connect to — the worst an injected one can do is deny a name, and
    /// refusing it denies the same name just as thoroughly. So it is served once
    /// the trusted resolver has been given its chance and could not take it, and
    /// not before: while the tunnel is up, a forged NXDOMAIN still loses to the
    /// real answer.
    func adjudicate(_ exchange: DNSExchange) -> (verdict: DNSVerdict, reason: DNSVerdictReason?) {
        if let direct = exchange.direct, answersInSet(direct) {
            return (.serveDirect, .directInSet)
        }
        // The direct half can still change the outcome until it settles or its
        // window closes, so nothing is concluded from the trusted half alone.
        let directSettled = exchange.directDone || exchange.directWindowClosed || exchange.deadlineReached
        guard directSettled else { return (.wait, nil) }
        if Self.replyUsable(exchange.trusted) {
            return (.serveTrusted, exchange.direct != nil ? .directOutOfSet : .trustedOnly)
        }
        guard exchange.trustedDone || exchange.deadlineReached else { return (.wait, nil) }
        guard let direct = exchange.direct else { return (.drop, .noReply) }
        if Self.addresses(in: direct).isEmpty {
            return (.serveDirect, .directNoAnswer)
        }
        return (.refuse, .suspectAnswerRefused)
    }

    /// Whether a reply names at least one address the operator said the direct
    /// resolver answers credibly for.
    ///
    /// One address is enough rather than all of them. A content network
    /// routinely answers with a mixed set, and requiring every address to be
    /// inside would reject the correct nearby answer for containing one distant
    /// member of the same rotation.
    func answersInSet(_ reply: Data) -> Bool {
        guard Self.replyUsable(reply) else { return false }
        return Self.addresses(in: reply).contains { prefixes.contains($0) }
    }

    /// The A and AAAA addresses a reply carries.
    ///
    /// Only the answer section is read. Additional and authority records are not
    /// what the application will connect to, and believing an address because of
    /// a section the querier did not ask about is how a resolver gets poisoned
    /// by a record it never requested.
    static func addresses(in reply: Data) -> [Data] {
        guard let message = DNSMessage.parse(reply) else { return [] }
        return message.answers.compactMap { (answer: DNSMessage.Answer) -> Data? in
            guard answer.type == DNSMessage.typeA || answer.type == DNSMessage.typeAAAA else {
                return nil
            }
            return answer.address
        }
    }

    /// Whether `reply` can be the answer to `query`.
    ///
    /// Deliberately looser than `DNSMessage.answers`, which additionally
    /// requires a successful response code because it guards what may enter the
    /// address-to-name map. An adjudication has to be able to see a denial:
    /// NXDOMAIN is a real answer with a real meaning here, and a forged one is
    /// exactly what the trusted half is being asked to overrule.
    static func isReply(_ reply: Data, to query: Data) -> Bool {
        guard query.count >= 12 else { return true }
        guard reply.count >= 12 else { return false }
        let replyBytes = [UInt8](reply.prefix(3))
        let queryBytes = [UInt8](query.prefix(2))
        return replyBytes[0] == queryBytes[0] && replyBytes[1] == queryBytes[1]
            && replyBytes[2] & 0x80 != 0
    }

    /// Whether a message is an answer a client can act on.
    ///
    /// NOERROR and NXDOMAIN are answers: one says where the name points, the
    /// other says it points nowhere, and a resolver client caches and acts on
    /// both. SERVFAIL and REFUSED are the resolver reporting that it could not
    /// answer, which is not a result to prefer over asking somewhere else.
    static func replyUsable(_ reply: Data?) -> Bool {
        guard let reply, reply.count >= 12 else { return false }
        let bytes = [UInt8](reply.prefix(4))
        guard bytes[2] & 0x80 != 0 else { return false }
        let code = bytes[3] & 0x0f
        return code == 0 || code == 3
    }

    /// The SERVFAIL returned to the application when neither resolver produced
    /// an answer worth believing.
    ///
    /// SERVFAIL rather than silence, and rather than the suspect answer. Silence
    /// makes a decision look like a dead network and costs the client its full
    /// retry schedule before it finds out. The suspect answer is the thing this
    /// whole path exists not to serve. SERVFAIL says the resolver could not
    /// answer, which is exactly true, and every stub resolver already knows what
    /// to do with it — including not caching it, so a lookup retried after the
    /// tunnel returns gets the real answer rather than a remembered failure.
    ///
    /// The question section is echoed and everything after it dropped. A
    /// response has to carry the question to be matched to its query; the
    /// answer, authority and additional sections of the query are not ours to
    /// repeat.
    static func refusal(for query: Data) -> Data? {
        guard let end = questionSectionEnd(query) else { return nil }
        var reply = [UInt8](query.prefix(end))
        // QR set, opcode and RD preserved, AA and TC cleared.
        reply[2] = (reply[2] & 0x79) | 0x80
        // RA set, Z and AD/CD cleared, RCODE 2 (SERVFAIL).
        reply[3] = 0x80 | 0x02
        for index in 6 ..< 12 { reply[index] = 0 }
        return Data(reply)
    }

    /// The offset just past the last question.
    ///
    /// The names are walked rather than parsed, and a compression pointer ends
    /// the walk unsuccessfully. A pointer in a question section is malformed —
    /// there is nothing earlier in the message for it to point at — and
    /// following one is how a name walker is turned into a loop.
    private static func questionSectionEnd(_ query: Data) -> Int? {
        let bytes = [UInt8](query)
        guard bytes.count >= 12 else { return nil }
        let count = Int(UInt16(bytes[4]) << 8 | UInt16(bytes[5]))
        guard count > 0, count <= 8 else { return nil }
        var offset = 12
        for _ in 0 ..< count {
            while true {
                guard offset < bytes.count else { return nil }
                let length = Int(bytes[offset])
                guard length & 0xc0 == 0 else { return nil }
                offset += 1 + length
                if length == 0 { break }
            }
            offset += 4
            guard offset <= bytes.count else { return nil }
        }
        return offset
    }
}
