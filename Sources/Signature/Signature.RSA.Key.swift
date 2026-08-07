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

public import Byte_Primitives
internal import RFC_4648

extension Signature.RSA {
    /// A private key in the DER encoding the platform signing facility
    /// imports.
    ///
    /// The bytes are PKCS#1 `RSAPrivateKey`. GitHub hands out keys in that
    /// armour (`BEGIN RSA PRIVATE KEY`); a key that has been through a
    /// conversion tool arrives wrapped in PKCS#8 `PrivateKeyInfo`, so both
    /// are accepted and the wrapper is peeled here rather than at the call
    /// site.
    public struct Key {
        public let der: [Byte]

        public init(der: [Byte]) {
            self.der = der
        }
    }
}

extension Signature.RSA.Key {
    /// Extracts the DER body from PEM armour.
    ///
    /// Nothing derived from the key is ever put in a thrown message: a
    /// diagnostic quoting "the byte at offset N" of a private key is a
    /// disclosure, so failures say only that the input is not importable.
    public init(pem: Swift.String) throws(Error) {
        var body = ""
        var inside = false
        var pkcs8 = false
        for line in pem.split(separator: "\n", omittingEmptySubsequences: true) {
            let trimmed = Self.trimmed(line)
            if trimmed.hasPrefix("-----BEGIN") {
                inside = true
                pkcs8 = !trimmed.contains("RSA PRIVATE KEY")
                continue
            }
            if trimmed.hasPrefix("-----END") { break }
            if inside { body += trimmed }
        }
        guard inside, !body.isEmpty, let decoded = [Byte](base64Encoded: body) else {
            throw .malformed
        }
        self.der = pkcs8 ? try Self.unwrap(decoded) : decoded
    }

    /// Peels PKCS#8 `PrivateKeyInfo` down to the PKCS#1 `RSAPrivateKey` its
    /// final OCTET STRING carries.
    ///
    /// A minimal DER walk — SEQUENCE, INTEGER version, SEQUENCE algorithm,
    /// OCTET STRING key — sufficient for exactly this structure and no more.
    public static func unwrap(_ der: [Byte]) throws(Error) -> [Byte] {
        var cursor = 0

        func length() throws(Error) -> Swift.Int {
            guard cursor < der.count else { throw .malformed }
            let first = der[cursor]
            cursor += 1
            guard first & 0x80 != 0 else { return Swift.Int(first) }
            let count = Swift.Int(first & 0x7F)
            guard count > 0, count <= 4, cursor + count <= der.count else { throw .malformed }
            var value = 0
            for _ in 0..<count {
                value = value << 8 | Swift.Int(der[cursor])
                cursor += 1
            }
            return value
        }

        func expect(_ tag: Byte) throws(Error) -> Swift.Int {
            guard cursor < der.count, der[cursor] == tag else { throw .malformed }
            cursor += 1
            return try length()
        }

        _ = try expect(0x30)  // PrivateKeyInfo
        let versionLength = try expect(0x02)  // version
        cursor += versionLength
        let algorithmLength = try expect(0x30)  // privateKeyAlgorithm
        cursor += algorithmLength
        let keyLength = try expect(0x04)  // privateKey
        guard cursor >= 0, cursor + keyLength <= der.count else { throw .malformed }
        return Array(der[cursor..<(cursor + keyLength)])
    }

    /// Drops leading and trailing ASCII whitespace and newlines.
    private static func trimmed(_ line: Swift.Substring) -> Swift.String {
        var slice = line
        while let first = slice.first,
            first == " " || first == "\n" || first == "\r" || first == "\t"
        {
            slice = slice.dropFirst()
        }
        while let last = slice.last,
            last == " " || last == "\n" || last == "\r" || last == "\t"
        {
            slice = slice.dropLast()
        }
        return Swift.String(slice)
    }
}
