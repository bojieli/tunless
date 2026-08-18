// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "TunlessMac",
    platforms: [.macOS(.v15)],
    products: [.library(name: "TunlessExtension", targets: ["TunlessExtension"])],
    targets: [
        .target(name: "TunlessExtension"),
        .target(name: "TunlessLauncher"),
        .testTarget(name: "TunlessExtensionTests", dependencies: ["TunlessExtension"]),
        .testTarget(name: "TunlessLauncherTests", dependencies: ["TunlessLauncher"]),
    ],
    swiftLanguageModes: [.v5]
)
