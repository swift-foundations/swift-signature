public import Byte
internal import FIPS_180_4

#if canImport(Security)
    private import Security
#endif

extension Signature {

    public enum RS256 {}
}

extension Signature.RS256 {

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

                unsafe failure?.release()
                throw .signing("the platform key facility rejected the message")
            }

            let count = CFDataGetLength(signature)
            var bytes = [Byte](repeating: 0, count: count)
            bytes.withUnsafeMutableBufferPointer { buffer in
                guard let base = buffer.baseAddress else { return }
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

        private static func data(_ bytes: [Byte]) throws(Error) -> CFData {
            let value = bytes.withUnsafeBufferPointer { buffer in
                unsafe CFDataCreate(kCFAllocatorDefault, buffer.baseAddress, buffer.count)
            }
            guard let value else { throw .signing("cannot allocate the request payload") }
            return value
        }

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
