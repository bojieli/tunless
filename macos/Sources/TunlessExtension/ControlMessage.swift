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
/// A paused capture keeps its NetworkExtension session connected, because the
/// session is what keeps the watchdog probing. That makes the manager's own
/// status a poor signal: it says "connected" either way. This is the signal.
public struct CaptureHealthReport: Codable, Sendable {
    public let capturing: Bool
    public let pauseReason: String?
    public let confirmed: Bool
    public let consecutiveFailures: Int

    public init(capturing: Bool, pauseReason: String?, confirmed: Bool, consecutiveFailures: Int) {
        self.capturing = capturing
        self.pauseReason = pauseReason
        self.confirmed = confirmed
        self.consecutiveFailures = consecutiveFailures
    }

    public var summary: String {
        if capturing { return confirmed ? "capturing" : "capturing (unconfirmed)" }
        return "paused: " + (pauseReason ?? "reason unavailable")
    }
}
