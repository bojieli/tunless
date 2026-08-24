import Foundation

/// Messages the launcher sends to a running provider.
///
/// Configuration updates are JSON objects and telemetry requests are empty, so
/// a single byte that is neither is unambiguous against both.
public enum ControlMessage: UInt8 {
    /// Name resolution was verified through the live datapath.
    case confirmHealthy = 0x01

    public var encoded: Data { Data([rawValue]) }

    public static func decode(_ data: Data) -> ControlMessage? {
        guard data.count == 1, let first = data.first else { return nil }
        return ControlMessage(rawValue: first)
    }
}
