import Foundation
import Network

/// Enough of the DNS wire format to answer two questions about a message the
/// provider is already relaying: which names it asks for, and which addresses
/// came back for them.
///
/// This is not a resolver and does not want to become one. It reads what is in
/// front of it, refuses anything it cannot read, and every bound it applies is
/// there because the bytes arrive from the network: a message may be crafted,
/// so a compression pointer may point backwards forever, a length may claim
/// more than the datagram holds, and a header may promise more records than it
/// carries. Each of those ends the parse rather than the process.
struct DNSMessage {
    struct Question {
        let name: String
        let type: UInt16
        let klass: UInt16
    }

    struct Answer {
        let name: String
        let type: UInt16
        let klass: UInt16
        let ttl: UInt32
        /// The address for an A or AAAA record, in its canonical byte form.
        let address: Data?
        /// The target of a CNAME record.
        let canonicalName: String?
    }

    static let typeA: UInt16 = 1
    static let typeAAAA: UInt16 = 28
    static let typeCNAME: UInt16 = 5
    static let classIN: UInt16 = 1

    let identifier: UInt16
    let isResponse: Bool
    let responseCode: UInt8
    let questions: [Question]
    let answers: [Answer]

    /// The largest number of records read from one message, across the question
    /// and answer sections together. A real answer is far below this; the bound
    /// keeps a header claiming 65535 records from turning one datagram into a
    /// long parse.
    private static let maxRecords = 64
    /// Compression pointers may only ever point backwards, so following more
    /// than this many of them means the message is looping.
    private static let maxPointerJumps = 32
    private static let maxNameLength = 255

    static func parse(_ data: Data) -> DNSMessage? {
        let bytes = [UInt8](data)
        guard bytes.count >= 12 else { return nil }
        let identifier = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
        let isResponse = bytes[2] & 0x80 != 0
        let responseCode = bytes[3] & 0x0f
        let questionCount = Int(UInt16(bytes[4]) << 8 | UInt16(bytes[5]))
        let answerCount = Int(UInt16(bytes[6]) << 8 | UInt16(bytes[7]))
        var cursor = 12
        var questions: [Question] = []
        var budget = maxRecords
        for _ in 0 ..< questionCount {
            guard budget > 0 else { break }
            budget -= 1
            guard let (name, next) = readName(bytes, at: cursor), next + 4 <= bytes.count else {
                return nil
            }
            questions.append(
                Question(
                    name: name,
                    type: UInt16(bytes[next]) << 8 | UInt16(bytes[next + 1]),
                    klass: UInt16(bytes[next + 2]) << 8 | UInt16(bytes[next + 3])))
            cursor = next + 4
        }
        var answers: [Answer] = []
        for _ in 0 ..< answerCount {
            guard budget > 0 else { break }
            budget -= 1
            guard let (name, next) = readName(bytes, at: cursor), next + 10 <= bytes.count else {
                break
            }
            let type = UInt16(bytes[next]) << 8 | UInt16(bytes[next + 1])
            let klass = UInt16(bytes[next + 2]) << 8 | UInt16(bytes[next + 3])
            let ttl =
                UInt32(bytes[next + 4]) << 24 | UInt32(bytes[next + 5]) << 16
                | UInt32(bytes[next + 6]) << 8 | UInt32(bytes[next + 7])
            let dataLength = Int(UInt16(bytes[next + 8]) << 8 | UInt16(bytes[next + 9]))
            let dataStart = next + 10
            guard dataStart + dataLength <= bytes.count else { break }
            var address: Data?
            var canonicalName: String?
            switch (type, dataLength) {
            case (typeA, 4), (typeAAAA, 16):
                address = Data(bytes[dataStart ..< dataStart + dataLength])
            case (typeCNAME, _):
                canonicalName = readName(bytes, at: dataStart)?.0
            default:
                break
            }
            answers.append(
                Answer(
                    name: name, type: type, klass: klass, ttl: ttl,
                    address: address, canonicalName: canonicalName))
            cursor = dataStart + dataLength
        }
        return DNSMessage(
            identifier: identifier,
            isResponse: isResponse,
            responseCode: responseCode,
            questions: questions,
            answers: answers)
    }

    /// Reads one name, returning it in lowercase without its root label, and the
    /// offset just past the name in the record being read.
    ///
    /// A name reached through a compression pointer ends at the pointer, not at
    /// wherever the pointed-to name ends, so the returned offset is always the
    /// one the caller should continue from.
    private static func readName(_ bytes: [UInt8], at start: Int) -> (String, Int)? {
        var labels: [String] = []
        var cursor = start
        var afterPointer: Int?
        var jumps = 0
        var length = 0
        while cursor < bytes.count {
            let marker = bytes[cursor]
            if marker & 0xc0 == 0xc0 {
                guard cursor + 1 < bytes.count else { return nil }
                let target = Int(UInt16(marker & 0x3f) << 8 | UInt16(bytes[cursor + 1]))
                // Only a backward pointer can terminate, and only a bounded
                // number of them can be followed.
                guard target < cursor, jumps < maxPointerJumps else { return nil }
                jumps += 1
                if afterPointer == nil { afterPointer = cursor + 2 }
                cursor = target
                continue
            }
            guard marker & 0xc0 == 0 else { return nil }
            let labelLength = Int(marker)
            if labelLength == 0 {
                let name = labels.joined(separator: ".")
                return (name, afterPointer ?? cursor + 1)
            }
            guard cursor + 1 + labelLength <= bytes.count else { return nil }
            length += labelLength + 1
            guard length <= maxNameLength else { return nil }
            let label = String(decoding: bytes[cursor + 1 ..< cursor + 1 + labelLength], as: UTF8.self)
            labels.append(label.lowercased())
            cursor += 1 + labelLength
        }
        return nil
    }

    /// Reports whether this message can be the answer to `query`.
    ///
    /// The check mirrors what a resolver client does for itself: same
    /// transaction ID, the response bit set, a successful response code, and the
    /// same questions in the same order. An answer that fails it is not
    /// necessarily hostile — a `SERVFAIL` fails it too — but it carries no
    /// association worth remembering either way.
    func answers(_ query: DNSMessage) -> Bool {
        guard !query.isResponse, isResponse, responseCode == 0,
            identifier == query.identifier, !query.questions.isEmpty,
            questions.count == query.questions.count
        else { return false }
        for (asked, echoed) in zip(query.questions, questions) {
            guard asked.name == echoed.name, asked.type == echoed.type,
                asked.klass == echoed.klass
            else { return false }
        }
        return true
    }
}

/// Which names only the resolver an application chose can answer.
///
/// Capture rewrites port-53 flows to a trusted resolver so that a poisoned
/// answer from the network the host is on cannot decide where a connection
/// goes. That is right for every name whose answer is the same everywhere, and
/// wrong for every name that exists only on this network: a trusted public
/// resolver has never heard of `nas.lan`, and neither has the proxy behind it.
/// Sending those queries away is how a working DNS override still breaks the
/// printer.
///
/// The Go side of the project carries the same lists in `internal/dnsname`, and
/// the two are meant to agree.
enum LocalNames {
    /// Name spaces whose answers are defined by the local network. The first
    /// group is reserved by RFC — `localhost` and `invalid` (RFC 6761), `local`
    /// (RFC 6762), `test` (RFC 6761), `home.arpa` (RFC 8375). The second is
    /// withheld from delegation and used privately in practice, which makes
    /// forwarding it a lookup that cannot succeed and can only leak the name.
    static let suffixes = [
        "localhost", "local", "invalid", "test", "home.arpa",
        "internal", "intranet", "private", "corp", "home", "lan", "localdomain",
    ]

    /// Reverse zones for address ranges that are not globally unique. A PTR
    /// lookup for 192.168.1.1 has a different right answer on every network.
    static let reverseSuffixes = [
        "10.in-addr.arpa", "127.in-addr.arpa", "168.192.in-addr.arpa", "254.169.in-addr.arpa",
        "c.f.ip6.arpa", "d.f.ip6.arpa",
        "8.e.f.ip6.arpa", "9.e.f.ip6.arpa", "a.e.f.ip6.arpa", "b.e.f.ip6.arpa",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
    ]

    static func canonical(_ name: String) -> String {
        var value = name.lowercased()
        while value.hasSuffix(".") { value.removeLast() }
        return value
    }

    /// Whether `name` must stay with the resolver the application asked.
    ///
    /// `extraSuffixes` carries operator-supplied domains, for a network whose
    /// internal names live under a name that is also a real public zone. A
    /// split-horizon `corp.example.com` is the usual shape, and no list of
    /// reserved names can predict it.
    static func isLocal(_ name: String, extraSuffixes: [String] = []) -> Bool {
        let value = canonical(name)
        guard !value.isEmpty else { return false }
        // An unqualified name has no meaning outside the search domains of the
        // resolver that was asked.
        if !value.contains(".") { return true }
        // 172.16.0.0/12 is the one private range whose reverse zone is not a
        // whole number of labels, so it is matched arithmetically.
        if value.hasSuffix(".172.in-addr.arpa") {
            let head = String(value.dropLast(".172.in-addr.arpa".count))
            if let last = head.split(separator: ".").last, let octet = Int(last),
                (16 ... 31).contains(octet)
            {
                return true
            }
        }
        for suffix in reverseSuffixes where hasSuffix(value, suffix) { return true }
        for suffix in suffixes where hasSuffix(value, suffix) { return true }
        for suffix in extraSuffixes {
            let candidate = canonical(suffix)
            if !candidate.isEmpty, hasSuffix(value, candidate) { return true }
        }
        return false
    }

    /// Whether a raw query asks only for names the local resolver owns.
    ///
    /// A query carrying no readable question is not local. That is the safe
    /// direction: an unreadable query sent to the trusted resolver fails a
    /// lookup, while one left on a poisoned path fails a connection.
    static func queryIsLocal(_ payload: Data, extraSuffixes: [String] = []) -> Bool {
        guard let message = DNSMessage.parse(payload), !message.questions.isEmpty else {
            return false
        }
        return message.questions.allSatisfy { isLocal($0.name, extraSuffixes: extraSuffixes) }
    }

    /// Matches on label boundaries, so `notlocal.example` does not match `local`
    /// while `printer.local` does.
    private static func hasSuffix(_ name: String, _ suffix: String) -> Bool {
        name == suffix || (name.count > suffix.count && name.hasSuffix("." + suffix))
    }
}
