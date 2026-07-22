// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "PropagareMac",
    defaultLocalization: "en",
    platforms: [
        .macOS(.v15),
    ],
    products: [
        .executable(name: "Propagare", targets: ["Propagare"]),
        .executable(name: "PropagareSafetyChecks", targets: ["PropagareSafetyChecks"]),
    ],
    targets: [
        .target(name: "PropagareSafety"),
        .executableTarget(
            name: "Propagare",
            dependencies: ["PropagareSafety"],
            resources: [.process("Resources")]
        ),
        .executableTarget(
            name: "PropagareSafetyChecks",
            dependencies: ["PropagareSafety"]
        ),
    ]
)
