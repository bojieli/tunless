// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "TunlessMac",
    platforms: [.macOS(.v15)],
    products: [.library(name: "TunlessExtension", targets: ["TunlessExtension"])],
    targets: [
        .target(name: "TunlessExtension"),
        .testTarget(name: "TunlessExtensionTests", dependencies: ["TunlessExtension"]),
    ],
    swiftLanguageModes: [.v5]
)
