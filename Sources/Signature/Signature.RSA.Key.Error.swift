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

extension Signature.RSA.Key {
    /// Everything that can go wrong importing a private key.
    ///
    /// **No case carries key material or a key location.** A private key is
    /// credential-equivalent, and a diagnostic that quotes its bytes or
    /// names where it came from turns every error report, log, and pasted
    /// transcript into a disclosure. The one case therefore says only that
    /// the input is not importable.
    public enum Error: Swift.Error, Equatable, CustomStringConvertible {
        /// The input is not a PEM-armoured RSA private key this can import.
        case malformed
    }
}

extension Signature.RSA.Key.Error {
    public var description: Swift.String {
        switch self {
        case .malformed: "the input is not a PEM-armoured RSA private key this can import"
        }
    }
}
