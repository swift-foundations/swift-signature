extension Signature.RSA.Key {

    public enum Error: Swift.Error, Equatable, CustomStringConvertible {

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
