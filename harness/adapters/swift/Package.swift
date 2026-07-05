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
        // Local path to the OPEN Swift reference implementation package (impl/swift).
        // Its directory name "swift" collides with THIS adapter package's own directory
        // (harness/adapters/swift) under SwiftPM's last-path-component identity rule, so
        // `package: "swift"` resolves back to this package. Give the dependency an explicit
        // identity ("Npamp", its declared package name) to disambiguate.
        .package(name: "Npamp", path: "../../../impl/swift"),
    ],
    targets: [
        .executableTarget(
            name: "npamp-adapter",
            dependencies: [.product(name: "Npamp", package: "Npamp")]
        ),
    ]
)
