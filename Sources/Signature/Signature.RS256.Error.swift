extension Signature.RS256 {

    public enum Error: Swift.Error, Equatable, CustomStringConvertible {

        case malformedKey

        case unsupportedPlatform

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
