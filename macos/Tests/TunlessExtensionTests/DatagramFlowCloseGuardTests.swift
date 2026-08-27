import XCTest
@testable import TunlessExtension

/// The one rule the datagram path cannot lose: the provider never closes a
/// flow whose socket the application still owns.
///
/// macOS hands a datagram flow over once. Closing it does not return the socket
/// above to the kernel and does not get it another flow — the socket is
/// finished, and every later send on it fails locally. `mDNSResponder` holds
/// one resolver socket per delegated client and never replaces it, so a single
/// close ends name resolution for that one client until the daemon restarts,
/// while the rest of the host resolves normally and hides it. That cost 5h18m
/// of a working machine's DNS before anyone knew what to look at.
///
/// Prose in [docs/MACOS.md] has never stopped anyone adding a close, so this
/// reads the provider instead. Every `closeReadWithError` and
/// `closeWriteWithError` call has to be one of two things: inside a function
/// that takes an `NEAppProxyTCPFlow`, where the type makes it safe, or guarded
/// by `survivesCapturePause` / an `is NEAppProxyTCPFlow` test a few lines
/// above. A close added to the datagram path is neither, and fails here.
final class DatagramFlowCloseGuardTests: XCTestCase {
    func testEveryFlowCloseIsTCPOnly() throws {
        let source = try String(contentsOfFile: Self.providerPath, encoding: .utf8)
        let lines = source.components(separatedBy: "\n")
        var enclosingIsTCP = false
        var recentGuard = 0
        var unguarded: [String] = []

        for (index, line) in lines.enumerated() {
            if line.contains("func ") && line.contains("(") {
                // A new function: it is TCP-safe only if the flow it takes is.
                enclosingIsTCP = line.contains("NEAppProxyTCPFlow")
            }
            // Multi-line signatures put the type on its own line.
            if line.contains("NEAppProxyTCPFlow") { enclosingIsTCP = true }
            if line.contains("survivesCapturePause") || line.contains("is NEAppProxyTCPFlow") {
                recentGuard = index
            }
            guard line.contains("closeReadWithError") || line.contains("closeWriteWithError") else {
                continue
            }
            let guarded = enclosingIsTCP || index - recentGuard <= 8
            if !guarded {
                unguarded.append("line \(index + 1): \(line.trimmingCharacters(in: .whitespaces))")
            }
        }

        XCTAssertTrue(
            unguarded.isEmpty,
            """
            A flow close was added where it can reach a datagram flow:
            \(unguarded.joined(separator: "\n"))

            Closing a datagram flow ends the application's socket for good — the
            kernel will not re-capture it and will not release it. Retire the
            upstream association instead and leave the flow open; see
            DatagramFlowContinuity and docs/MACOS.md.
            """)
    }

    /// Fails if the rule above is ever satisfied vacuously, which would make
    /// this test a comment.
    func testTheGuardIsActuallyReadingCalls() throws {
        let source = try String(contentsOfFile: Self.providerPath, encoding: .utf8)
        let closes = source.components(separatedBy: "closeReadWithError").count - 1
        XCTAssertGreaterThan(
            closes, 0, "the provider closes no flows at all, so this guard is checking nothing")
    }

    private static var providerPath: String {
        // From Tests/TunlessExtensionTests/ up to macos/, then into Sources.
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Sources/TunlessExtension/TransparentProxyProvider.swift")
            .path
    }
}
