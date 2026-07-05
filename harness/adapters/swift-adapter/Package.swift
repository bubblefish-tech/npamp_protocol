// swift-tools-version:6.0
// N-PAMP conformance adapter (Swift "testee"). Depends on the OPEN Swift reference
// implementation via a local path dependency and calls its real public API
// (Npamp.crc32c, Npamp.Frame.headerPrefix/unmarshal, Npamp.sealAes256Gcm,
// Npamp.openAes256Gcm). No primitive is reimplemented here — the adapter only
// translates the length-prefixed JSON conformance contract into reference calls.
import PackageDescription

let package = Package(
    name: "NpampAdapter",
    dependencies: [
        // Local path to the OPEN Swift reference implementation package (impl/swift),
        // whose SwiftPM identity is its directory name "swift". This adapter deliberately
        // lives in harness/adapters/swift-adapter (identity "swift-adapter") so its own
        // identity does NOT collide with impl/swift under SwiftPM's last-path-component
        // identity rule; the product reference below therefore resolves unambiguously.
        .package(path: "../../../impl/swift"),
    ],
    targets: [
        .executableTarget(
            name: "npamp-adapter",
            dependencies: [.product(name: "Npamp", package: "swift")]
        ),
    ]
)
