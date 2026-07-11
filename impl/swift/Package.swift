// swift-tools-version:5.9
// N-PAMP Swift reference (draft-bubblefish-npamp-00). Pure-Swift OPEN-layer wire
// implementation built on swift-crypto (portable AES-256-GCM + HKDF on Linux/Apple).
import PackageDescription

let package = Package(
    name: "Npamp",
    products: [
        .library(name: "Npamp", targets: ["Npamp"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(name: "Npamp", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .executableTarget(name: "npamp-vectors", dependencies: ["Npamp"]),
        .executableTarget(name: "npamp-conformance", dependencies: ["Npamp"]),
        .executableTarget(name: "npamp-kat", dependencies: ["Npamp"]),
        .executableTarget(name: "npamp-handshake-kat", dependencies: ["Npamp"]),
        .executableTarget(name: "npamp-handshake-flow-kat", dependencies: ["Npamp"]),
        .executableTarget(name: "npamp-adapter", dependencies: ["Npamp"]),
        .executableTarget(name: "npamp-example", dependencies: ["Npamp"]),
    ]
)
