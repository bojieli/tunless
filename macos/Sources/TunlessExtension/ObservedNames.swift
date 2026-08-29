import Foundation
import Network

/// Remembers which name each address was answered for, so a flow that arrives
/// without one can be proxied under the name the application actually asked
/// for.
///
/// macOS attaches `remoteHostname` to a flow only when the name was resolved
/// through the system resolver. An application with its own resolver — every
/// Chromium browser, Firefox, anything built on its own DNS client — bypasses
/// that, so its flows arrive as bare addresses and the proxy behind capture
/// loses every rule it has that is written about names. That is not a small
/// loss on a network that answers DNS falsely: the address in the flow is
/// whatever the network said, and relaying it faithfully relays the lie.
///
/// This closes it from the other end. Capture is already relaying those
/// queries, so the answers pass through here on their way back, and an address
/// seen in one of them can be given its name again when the connection to it
/// opens a moment later.
///
/// It is worth being precise about how this differs from the fake-IP scheme it
/// replaces, because the mechanism looks similar and the failure modes are
/// opposite. A fake IP means nothing to anyone but the process that minted it,
/// so an application holding one after its mapping is gone connects
/// successfully and then transfers nothing. Every address here is real. If the
/// association has expired, or two names claim it, or it was never seen, the
/// flow simply goes out on the address it already had — which still works, and
/// only loses rule-by-name. Nothing is invented, so nothing can outlive the
/// truth behind it.
final class ObservedNames: @unchecked Sendable {
    private let lock = NSLock()
    /// Address bytes to the names claiming them, each with its own expiry.
    private var records: [Data: [String: Date]] = [:]
    private var recordCount = 0
    private let maxRecords: Int
    private let now: @Sendable () -> Date

    /// Bounds how long one answer may keep claiming an address, whatever TTL it
    /// carried, and how short a claim may be.
    ///
    /// The floor is not cosmetic. An association is recorded when the answer
    /// arrives and read when the connection opens, and those are different
    /// moments: a browser resolves once and then opens connections over the
    /// seconds that follow, for the page and for every subresource on it.
    /// Honouring a one-second TTL literally means the first connection is
    /// recognised and the rest are not — `news.ycombinator.com` publishes a TTL
    /// of exactly one second, and was measured losing its name every time.
    ///
    /// Holding a short-lived answer for half a minute is safe in a way that
    /// holding a fake address is not. The risk being bounded is that an address
    /// is reassigned to somebody else and inherits the old name's routing, which
    /// does not happen inside thirty seconds; and if it somehow did, the flow
    /// still reaches a real address that still works.
    private static let maxTTL: TimeInterval = 24 * 60 * 60
    private static let minTTL: TimeInterval = 30
    /// Bounds on one message, so that a crafted answer cannot spend the whole
    /// table on itself.
    private static let maxNamesPerMessage = 256
    private static let maxAssociationsPerMessage = 4096

    init(maxRecords: Int = 65536, now: @escaping @Sendable () -> Date = { Date() }) {
        self.maxRecords = maxRecords
        self.now = now
    }

    /// Records the addresses in `reply` under the name `query` asked for.
    ///
    /// Only exchanges that went to the trusted resolver should reach this. An
    /// association learned from an answer that arrived on the network's own
    /// path would let whoever supplied that answer choose the name a later flow
    /// is proxied under, which is the poisoning this exists to route around,
    /// re-entering one layer up.
    func observe(query: Data, reply: Data) {
        guard maxRecords > 0,
            let question = DNSMessage.parse(query),
            let answer = DNSMessage.parse(reply),
            answer.answers(question)
        else { return }
        let moment = now()
        let associations = Self.associations(question: question, answer: answer, now: moment)
        guard !associations.isEmpty else { return }
        lock.lock()
        defer { lock.unlock() }
        prune(moment)
        for association in associations {
            if records[association.address]?[association.name] == nil {
                guard recordCount < maxRecords else { return }
                recordCount += 1
            }
            records[association.address, default: [:]][association.name] = association.expires
        }
    }

    /// The name last answered for `host`, or nil when there is not exactly one.
    ///
    /// Two live names for one address is the ordinary shape of shared hosting
    /// and of a CDN, and there is no way to tell from the address which of them
    /// this flow is for. Guessing would route somebody's connection under
    /// somebody else's rules, so an ambiguous address is treated as an unknown
    /// one and the flow keeps its address.
    func lookup(host: String) -> String? {
        guard let key = Self.addressKey(host) else { return nil }
        let moment = now()
        lock.lock()
        defer { lock.unlock() }
        guard var names = records[key] else { return nil }
        var found: String?
        for (name, expires) in names {
            if moment >= expires {
                names.removeValue(forKey: name)
                if recordCount > 0 { recordCount -= 1 }
                continue
            }
            if let found, found != name {
                records[key] = names
                return nil
            }
            found = name
        }
        if names.isEmpty {
            records.removeValue(forKey: key)
        } else {
            records[key] = names
        }
        return found
    }

    func count() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return recordCount
    }

    private struct Association {
        let address: Data
        let name: String
        let expires: Date
    }

    /// Attributes each address in the answer to a name that was asked for,
    /// directly or through the answer's own CNAME chain.
    ///
    /// Merely appearing in the answer section is not enough. A response may
    /// carry records for names nobody asked about, and letting those into the
    /// table would let one lookup decide the name of a flow to an unrelated
    /// address.
    private static func associations(
        question: DNSMessage, answer: DNSMessage, now: Date
    ) -> [Association] {
        var aliases: [String: (target: String, expires: Date)] = [:]
        for record in answer.answers
        where record.type == DNSMessage.typeCNAME && record.klass == DNSMessage.classIN {
            guard let target = record.canonicalName else { continue }
            let expires = now.addingTimeInterval(clampedTTL(record.ttl))
            if let existing = aliases[record.name] {
                if existing.target != target {
                    // Conflicting aliases are not safe to attribute either way.
                    aliases[record.name] = (target: "", expires: existing.expires)
                } else if expires < existing.expires {
                    aliases[record.name] = (target: target, expires: expires)
                }
            } else {
                aliases[record.name] = (target: target, expires: expires)
            }
        }
        struct Origin {
            let name: String
            let type: UInt16
            let expires: Date?
        }
        var origins: [String: [Origin]] = [:]
        var seen = Set<String>()
        for asked in question.questions {
            guard asked.klass == DNSMessage.classIN,
                asked.type == DNSMessage.typeA || asked.type == DNSMessage.typeAAAA,
                seen.count < maxNamesPerMessage, seen.insert(asked.name).inserted
            else { continue }
            var current = asked.name
            var chainExpires: Date?
            var visited = Set<String>()
            var terminated = false
            for _ in 0 ... answer.answers.count {
                guard visited.insert(current).inserted else { break }
                guard let next = aliases[current] else {
                    terminated = true
                    break
                }
                // An alias that conflicted with itself ends the chain unusable.
                guard !next.target.isEmpty else { break }
                if chainExpires == nil || next.expires < chainExpires! {
                    chainExpires = next.expires
                }
                current = next.target
            }
            guard terminated else { continue }
            // Only the terminal owner may carry address records.
            origins[current, default: []].append(
                Origin(name: asked.name, type: asked.type, expires: chainExpires))
        }
        var associations: [Association] = []
        for record in answer.answers {
            guard record.klass == DNSMessage.classIN, let address = record.address else { continue }
            let expected: UInt16 = address.count == 4 ? DNSMessage.typeA : DNSMessage.typeAAAA
            guard record.type == expected, let claimants = origins[record.name] else { continue }
            let addressExpires = now.addingTimeInterval(clampedTTL(record.ttl))
            for origin in claimants where origin.type == expected {
                guard associations.count < maxAssociationsPerMessage else { return associations }
                var expires = addressExpires
                if let chain = origin.expires, chain < expires { expires = chain }
                associations.append(
                    Association(address: address, name: origin.name, expires: expires))
            }
            if associations.count >= maxAssociationsPerMessage { break }
        }
        return associations
    }

    private static func clampedTTL(_ value: UInt32) -> TimeInterval {
        min(max(TimeInterval(value), minTTL), maxTTL)
    }

    /// The lookup key for a flow's destination.
    ///
    /// Flows name their destination as text, and the same address has several
    /// spellings — a zone identifier on a link-local address, an IPv4-mapped
    /// IPv6 form of an address the answer carried as four bytes. Keying on the
    /// bytes rather than the text means the association is found whichever
    /// spelling arrives.
    static func addressKey(_ host: String) -> Data? {
        if let value = IPv4Address(host) { return value.rawValue }
        guard let value = IPv6Address(host) else { return nil }
        let bytes = value.rawValue
        guard bytes.count == 16 else { return nil }
        let mappedPrefix = Data([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
        if bytes.prefix(12) == mappedPrefix { return Data(bytes.suffix(4)) }
        return bytes
    }

    private func prune(_ moment: Date) {
        for (address, names) in records {
            var live = names
            for (name, expires) in names where moment >= expires {
                live.removeValue(forKey: name)
                if recordCount > 0 { recordCount -= 1 }
            }
            if live.isEmpty {
                records.removeValue(forKey: address)
            } else if live.count != names.count {
                records[address] = live
            }
        }
    }
}
