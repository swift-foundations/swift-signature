// ===----------------------------------------------------------------------===//
//
// This source file is part of the swift-signature open source project
//
// Copyright (c) 2026 Coen ten Thije Boonkkamp and the swift-signature project authors
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// ===----------------------------------------------------------------------===//

extension Signature.RS256 {
    /// Everything that can go wrong producing an RS256 signature.
    ///
    /// **No case carries key material or a key location.** The signing key
    /// is credential-equivalent; cases describe *what* failed, never *with
    /// what* or *from where*.
    public enum Error: Swift.Error, Equatable, CustomStringConvertible {
        /// The key's DER bytes were rejected by the platform key facility.
        case malformedKey
        /// The platform has no signing facility this build can reach.
        case unsupportedPlatform
        /// Signing failed inside the platform's key facility.
        case signing(Swift.String)
    }
}

extension Signature.RS256.Error {
    public var description: Swift.String {
        switch self {
        case .malformedKey:
            "the signing key is not an RSA private key the platform facility can import"
        case .unsupportedPlatform:
            "this platform has no signing facility reachable from this build"
        case .signing(let message): "cannot sign the message: \(message)"
        }
    }
}
