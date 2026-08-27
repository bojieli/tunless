import XCTest

/// The bundle version has one source, and it is not the file that looks like it.
///
/// `Info.plist` is xcodegen output. Editing it is what a maintainer reaches for
/// and what a reviewer approves, and the next `xcodegen generate` puts it back
/// — so the build keeps declaring the old number while carrying new code. macOS
/// keys system-extension replacement on that number, so the install then leaves
/// the earlier binary running and the launcher reports a version nobody is
/// running. Build 14 shipped twice that way.
///
/// This fails when the two disagree, which is exactly the window where the
/// mistake is invisible.
final class BundleVersionTests: XCTestCase {
    func testGeneratedPlistsMatchTheProjectSpec() throws {
        let spec = try String(contentsOfFile: Self.path("project.yml"), encoding: .utf8)
        let declared = Self.values(of: #"CFBundleVersion: "(\d+)""#, in: spec)
        XCTAssertEqual(
            declared.count, 2,
            "project.yml should declare CFBundleVersion for the app and the extension")
        XCTAssertEqual(
            Set(declared).count, 1,
            "the app and the extension must ship the same build number, found \(declared)")

        for plist in ["App/Info.plist", "Extension/Info.plist"] {
            let contents = try String(contentsOfFile: Self.path(plist), encoding: .utf8)
            let generated = Self.values(
                of: #"<key>CFBundleVersion</key>\s*<string>(\d+)</string>"#, in: contents)
            XCTAssertEqual(
                generated, [declared[0]],
                """
                \(plist) declares \(generated) and macos/project.yml declares \
                \(declared[0]). project.yml is the source; the plist is generated \
                from it. Bump it there and re-run `xcodegen generate`.
                """)
        }
    }

    private static func values(of pattern: String, in text: String) -> [String] {
        guard let expression = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(text.startIndex ..< text.endIndex, in: text)
        return expression.matches(in: text, range: range).compactMap { match in
            Range(match.range(at: 1), in: text).map { String(text[$0]) }
        }
    }

    private static func path(_ relative: String) -> String {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent(relative)
            .path
    }
}
