import Byte_Primitives
import RFC_4648
import Testing

@testable import Signature

#if canImport(Security)
    import Security
#endif

extension Signature {
    @Suite
    struct Test {
        @Suite
        struct Unit {
            @Test
            func `peels the PKCS8 wrapper off an RSA private key`() throws {

                let der: [UInt8] = [
                    0x30, 0x1B,
                    0x02, 0x01, 0x00,
                    0x30, 0x0D,
                    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
                    0x05, 0x00,
                    0x04, 0x03, 0x01, 0x02, 0x03,
                ]
                let unwrapped = try Signature.RSA.Key.unwrap(der.map { Byte($0) })
                #expect(unwrapped == [1, 2, 3].map { Byte(UInt8($0)) })
            }

            @Test
            func `keeps PKCS1 armour bytes as they arrive`() throws {
                let body: [UInt8] = [0x30, 0x03, 0x02, 0x01, 0x00]
                let base64 = "MAMCAQA="
                let key = try Signature.RSA.Key(
                    pem: "-----BEGIN RSA PRIVATE KEY-----\n\(base64)\n-----END RSA PRIVATE KEY-----"
                )
                #expect(key.der == body.map { Byte($0) })
            }
        }

        @Suite
        struct `Edge Case` {
            @Test
            func `refuses input that is not PEM-armoured`() {
                #expect(throws: Signature.RSA.Key.Error.malformed) {
                    try Signature.RSA.Key(pem: "not a key")
                }
                #expect(throws: Signature.RSA.Key.Error.malformed) {
                    try Signature.RSA.Key(
                        pem: "-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----"
                    )
                }
            }

            #if canImport(Security)
                @Test
                func `refuses DER the platform facility cannot import`() {
                    #expect(throws: Signature.RS256.Error.malformedKey) {
                        try Signature.RS256.sign(
                            message: [Byte]("message".utf8),
                            key: Signature.RSA.Key(der: [1, 2, 3].map { Byte(UInt8($0)) })
                        )
                    }
                }
            #else
                @Test
                func `reports the missing platform facility`() {
                    #expect(throws: Signature.RS256.Error.unsupportedPlatform) {
                        try Signature.RS256.sign(
                            message: [Byte]("message".utf8),
                            key: Signature.RSA.Key(der: [])
                        )
                    }
                }
            #endif
        }

        @Suite
        struct Integration {
            #if canImport(Security)

                @Test
                func `signs a message the platform facility verifies at message level`() throws {
                    var failure: Unmanaged<CFError>?
                    var bits = 2048
                    let size = unsafe CFNumberCreate(kCFAllocatorDefault, .intType, &bits)!
                    let attributes = try #require(
                        Self.dictionary(
                            keys: [kSecAttrKeyType, kSecAttrKeySizeInBits],
                            values: [kSecAttrKeyTypeRSA, size]
                        )
                    )
                    let generated = try #require(
                        unsafe SecKeyCreateRandomKey(attributes, &failure)
                    )
                    let exported = try #require(
                        unsafe SecKeyCopyExternalRepresentation(generated, &failure)
                    )
                    let count = CFDataGetLength(exported)
                    var der = [Byte](repeating: 0, count: count)
                    der.withUnsafeMutableBufferPointer { buffer in
                        guard let base = unsafe buffer.baseAddress else { return }
                        unsafe CFDataGetBytes(exported, CFRangeMake(0, count), base)
                    }

                    let pem =
                        "-----BEGIN RSA PRIVATE KEY-----\n"
                        + der.base64.encoded()
                        + "\n-----END RSA PRIVATE KEY-----"
                    let key = try Signature.RSA.Key(pem: pem)
                    #expect(key.der == der)

                    let message = [Byte]("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.claims".utf8)
                    let signature = try Signature.RS256.sign(message: message, key: key)

                    let publicKey = try #require(SecKeyCopyPublicKey(generated))
                    let messageData = try #require(Self.data(message))
                    let signatureData = try #require(Self.data(signature))
                    let verified = unsafe SecKeyVerifySignature(
                        publicKey,
                        .rsaSignatureMessagePKCS1v15SHA256,
                        messageData,
                        signatureData,
                        &failure
                    )
                    unsafe failure?.release()
                    #expect(verified)
                }

                private static func data(_ bytes: [Byte]) -> CFData? {
                    bytes.withUnsafeBufferPointer { buffer in
                        unsafe CFDataCreate(kCFAllocatorDefault, buffer.baseAddress, buffer.count)
                    }
                }

                private static func dictionary(
                    keys: [CFString],
                    values: [CFTypeRef]
                ) -> CFDictionary? {
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
                    return unsafe CFDictionaryCreate(
                        kCFAllocatorDefault,
                        &keyPointers,
                        &valuePointers,
                        keys.count,
                        &keyCallbacks,
                        &valueCallbacks
                    )
                }
            #endif
        }
    }
}
