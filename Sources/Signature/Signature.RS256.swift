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
internal import FIPS_180_4

#if canImport(Security)
    private import Security
#endif

extension Signature {
    /// RS256 (RFC 7518 §3.3): RSASSA-PKCS1-v1_5 over SHA-256.
    ///
    /// The SHA-256 digest is composed from FIPS 180-4 — the Institute's
    /// sole SHA-2 owner (ruling R37) — and only the digest is handed to
    /// the platform key facility, which contributes exactly the RSA
    /// primitive. On a platform without a reachable key facility, signing
    /// throws rather than pretending.
    public enum RS256 {}
}

extension Signature.RS256 {
    /// Signs `message` with `key` under RSASSA-PKCS1-v1_5 over SHA-256.
    ///
    /// The digest of `message` is computed by FIPS 180-4; the platform
    /// facility signs the digest (`rsaSignatureDigestPKCS1v15SHA256`),
    /// which is byte-identical to signing the message under the
    /// message-level algorithm. No key material crosses a process
    /// boundary, is written anywhere, or appears in a process argument.
    public static func sign(
        message: [Byte],
        key: Signature.RSA.Key
    ) throws(Error) -> [Byte] {
        #if canImport(Security)
            let attributes = try dictionary(
                keys: [kSecAttrKeyType, kSecAttrKeyClass],
                values: [kSecAttrKeyTypeRSA, kSecAttrKeyClassPrivate]
            )
            let keyData = try data(key.der)
            let digestData = try data(FIPS_180_4.SHA256.digest(message).bytes)

            var failure: Unmanaged<CFError>?
            guard
                let secKey = unsafe SecKeyCreateWithData(keyData, attributes, &failure)
            else {
                unsafe failure?.release()
                throw .malformedKey
            }
            guard
                let signature = unsafe SecKeyCreateSignature(
                    secKey,
                    .rsaSignatureDigestPKCS1v15SHA256,
                    digestData,
                    &failure
                )
            else {
                // The CFError's own message can name the key facility's view of
                // the key; report the failure without it.
                unsafe failure?.release()
                throw .signing("the platform key facility rejected the message")
            }

            let count = CFDataGetLength(signature)
            var bytes = [Byte](repeating: 0, count: count)
            bytes.withUnsafeMutableBufferPointer { buffer in
                guard let base = unsafe buffer.baseAddress else { return }
                unsafe CFDataGetBytes(signature, CFRangeMake(0, count), base)
            }
            return bytes
        #else
            throw .unsupportedPlatform
        #endif
    }
}

#if canImport(Security)
    extension Signature.RS256 {
        /// A `CFData` over `bytes`, copied rather than borrowed so its lifetime
        /// is independent of the caller's array.
        private static func data(_ bytes: [Byte]) throws(Error) -> CFData {
            let value = bytes.withUnsafeBufferPointer { buffer in
                unsafe CFDataCreate(kCFAllocatorDefault, buffer.baseAddress, buffer.count)
            }
            guard let value else { throw .signing("cannot allocate the request payload") }
            return value
        }

        /// A `CFDictionary` of CoreFoundation constants.
        ///
        /// Built by hand because the usual `[CFString: Any] as CFDictionary`
        /// bridge is Foundation's, and this target does not import Foundation.
        private static func dictionary(
            keys: [CFString],
            values: [CFString]
        ) throws(Error) -> CFDictionary {
            var keyCallbacks = kCFTypeDictionaryKeyCallBacks
            var valueCallbacks = kCFTypeDictionaryValueCallBacks
            var keyPointers = unsafe keys.map {
                unsafe UnsafeRawPointer(Unmanaged.passUnretained($0).toOpaque())
                    as UnsafeRawPointer?
            }
            var valuePointers = unsafe values.map {
                unsafe UnsafeRawPointer(Unmanaged.passUnretained($0).toOpaque())
                    as UnsafeRawPointer?
            }
            let value = unsafe CFDictionaryCreate(
                kCFAllocatorDefault,
                &keyPointers,
                &valuePointers,
                keys.count,
                &keyCallbacks,
                &valueCallbacks
            )
            guard let value else { throw .signing("cannot allocate the key attributes") }
            return value
        }
    }
#endif
