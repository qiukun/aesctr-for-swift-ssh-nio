// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "aesctr-for-swift-ssh-nio",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    products: [
        .library(
            name: "aesctr-for-swift-ssh-nio",
            targets: ["aesctr-for-swift-ssh-nio"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio-ssh.git", from: "0.8.0"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.56.0"),
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "NIOSSHClient",
            dependencies: [
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
            ]
        ),
        .target(
            name: "aesctr-for-swift-ssh-nio"),
        .testTarget(
            name: "aesctr-for-swift-ssh-nioTests",
            dependencies: ["aesctr-for-swift-ssh-nio"]),
    ]
)
