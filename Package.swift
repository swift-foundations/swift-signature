// swift-tools-version: 6.3.3

import PackageDescription

// swift-signature — asymmetric message signing, RS256-first.
//
// SHA-2 is consumed by composing swift-standards/swift-fips-180-4, the
// Institute's sole SHA-2 owner (ruling R37; ruling 4 of principal
// amendment 3, swift-institute/.github#85). No hash arithmetic lives
// here. The asymmetric primitive is the platform key facility, reached
// only behind a platform condition.
let package = Package(
    name: "swift-signature",
    platforms: [
        .macOS("27"),
        .iOS("27"),
        .tvOS("27"),
        .watchOS("27"),
        .visionOS("27"),
    ],
    products: [
        .library(
            name: "Signature",
            targets: ["Signature"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/swift-primitives/swift-byte-primitives.git", branch: "main"),
        .package(url: "https://github.com/swift-ietf/swift-rfc-4648.git", branch: "main"),
        .package(url: "https://github.com/swift-standards/swift-fips-180-4.git", branch: "main"),
    ],
    targets: [
        .target(
            name: "Signature",
            dependencies: [
                .product(name: "Byte Primitives", package: "swift-byte-primitives"),
                .product(name: "RFC 4648", package: "swift-rfc-4648"),
                .product(name: "FIPS 180-4", package: "swift-fips-180-4"),
            ]
        ),
        .testTarget(
            name: "Signature Tests",
            dependencies: [
                .target(name: "Signature"),
                .product(name: "RFC 4648", package: "swift-rfc-4648"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

for target in package.targets where ![.system, .binary, .plugin, .macro].contains(target.type) {
    let ecosystem: [SwiftSetting] = [
        .strictMemorySafety(),
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
        .enableUpcomingFeature("MemberImportVisibility"),
        .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
        .enableExperimentalFeature("LifetimeDependence"),
        .enableExperimentalFeature("Lifetimes"),
        .enableExperimentalFeature("SuppressedAssociatedTypes"),
        .enableUpcomingFeature("InferIsolatedConformances"),
        .enableUpcomingFeature("LifetimeDependence"),
    ]

    let package: [SwiftSetting] = []

    target.swiftSettings = (target.swiftSettings ?? []) + ecosystem + package
}
