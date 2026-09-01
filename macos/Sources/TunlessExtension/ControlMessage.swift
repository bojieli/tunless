import Foundation

/// Messages the launcher sends to a running provider.
///
/// Configuration updates are JSON objects and telemetry requests are empty, so
/// a single byte that is neither is unambiguous against both.
public enum ControlMessage: UInt8 {
    /// Name resolution was verified through the live datapath.
    case confirmHealthy = 0x01
    /// Asks whether capture is currently claiming flows, and why not.
    case queryHealth = 0x02

    public var encoded: Data { Data([rawValue]) }

    public static func decode(_ data: Data) -> ControlMessage? {
        guard data.count == 1, let first = data.first else { return nil }
        return ControlMessage(rawValue: first)
    }
}

/// Capture health as the provider reports it to the launcher.
///
/// An upstream-degraded capture keeps its NetworkExtension session connected
/// and continues claiming eligible flows. The manager's own status therefore
/// cannot describe datapath health; this report names both facts.
public struct CaptureHealthReport: Codable, Sendable {
    public let capturing: Bool
    public let pauseReason: String?
    public let confirmed: Bool
    public let consecutiveFailures: Int
    /// Flows held right now, and TCP flows refused (while remaining captured)
    /// at the ceiling since start. A rising count is the signal that one
    /// application is opening streams faster than the upstream retires them.
    public let activeFlows: Int?
    public let rejectedFlows: UInt64?

    public init(
        capturing: Bool,
        pauseReason: String?,
        confirmed: Bool,
        consecutiveFailures: Int,
        activeFlows: Int? = nil,
        rejectedFlows: UInt64? = nil
    ) {
        self.capturing = capturing
        self.pauseReason = pauseReason
        self.confirmed = confirmed
        self.consecutiveFailures = consecutiveFailures
        self.activeFlows = activeFlows
        self.rejectedFlows = rejectedFlows
    }

    public var summary: String {
        var text: String
        if capturing {
            if let pauseReason {
                text = "capturing (degraded: \(pauseReason))"
            } else {
                text = confirmed ? "capturing" : "capturing (unconfirmed)"
            }
        } else {
            text = "paused: " + (pauseReason ?? "reason unavailable")
        }
        if let activeFlows { text += ", \(activeFlows) active" }
        if let rejectedFlows, rejectedFlows > 0 { text += ", \(rejectedFlows) refused at the ceiling" }
        return text
    }
}
