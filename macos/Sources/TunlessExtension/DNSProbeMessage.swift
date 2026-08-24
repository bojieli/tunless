import Foundation

/// Wire framing for the DNS reachability probes used before and after capture
/// is enabled.
///
/// A probe only has to prove that a resolver answered through the path under
/// test. It does not have to prove that a particular name exists, so any
/// well-formed response carrying the probe's transaction ID counts as success,
/// including `NXDOMAIN` and `SERVFAIL`. That keeps the probe from depending on
/// a specific zone staying resolvable, and keeps a filtered answer from being
/// misread as a broken datapath.
public enum DNSProbeMessage {
    /// Name queried by the probes. It exists only to carry a question section;
    /// the response code is deliberately not inspected.
    public static let probeName = "example.com"

    /// Builds an A query for `name` with recursion desired.
    public static func query(name: String = probeName, transactionID: UInt16) -> Data {
        var message = Data()
        message.append(UInt8(transactionID >> 8))
        message.append(UInt8(transactionID & 0xff))
        message.append(contentsOf: [0x01, 0x00])  // recursion desired
        message.append(contentsOf: [0x00, 0x01])  // one question
        message.append(contentsOf: [0x00, 0x00])  // no answers
        message.append(contentsOf: [0x00, 0x00])  // no authority records
        message.append(contentsOf: [0x00, 0x00])  // no additional records
        for label in name.split(separator: ".") {
            let bytes = Data(label.utf8)
            guard !bytes.isEmpty, bytes.count <= 63 else { continue }
            message.append(UInt8(bytes.count))
            message.append(bytes)
        }
        message.append(0x00)                      // root label
        message.append(contentsOf: [0x00, 0x01])  // QTYPE A
        message.append(contentsOf: [0x00, 0x01])  // QCLASS IN
        return message
    }

    /// True when `data` is a DNS response to the query identified by
    /// `transactionID`. Any response code is accepted; see the type comment.
    public static func isResponse(_ data: Data, transactionID: UInt16) -> Bool {
        guard data.count >= 12 else { return false }
        let bytes = [UInt8](data.prefix(12))
        let identifier = UInt16(bytes[0]) << 8 | UInt16(bytes[1])
        guard identifier == transactionID else { return false }
        return bytes[2] & 0x80 != 0  // QR bit: this is a response
    }

    /// Frames a query for DNS over TCP, which carries a two-byte length prefix.
    public static func tcpFramed(_ message: Data) -> Data {
        var framed = Data()
        framed.append(UInt8(message.count >> 8))
        framed.append(UInt8(message.count & 0xff))
        framed.append(message)
        return framed
    }

    /// Length of the message that follows a two-byte DNS-over-TCP prefix.
    public static func tcpPayloadLength(_ prefix: Data) -> Int? {
        guard prefix.count >= 2 else { return nil }
        let bytes = [UInt8](prefix.prefix(2))
        return Int(UInt16(bytes[0]) << 8 | UInt16(bytes[1]))
    }
}
