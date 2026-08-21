public import Byte_Primitives
internal import RFC_4648

extension Signature.RSA {

    public struct Key {
        public let der: [Byte]

        public init(der: [Byte]) {
            self.der = der
        }
    }
}

extension Signature.RSA.Key {

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

        _ = try expect(0x30)
        let versionLength = try expect(0x02)
        cursor += versionLength
        let algorithmLength = try expect(0x30)
        cursor += algorithmLength
        let keyLength = try expect(0x04)
        guard cursor >= 0, cursor + keyLength <= der.count else { throw .malformed }
        return Array(der[cursor..<(cursor + keyLength)])
    }

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
