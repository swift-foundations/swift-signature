# swift-signature

![Development Status](https://img.shields.io/badge/status-active--development-blue.svg)

Asymmetric message signing, RS256-first: PEM→DER private-key parsing and RSASSA-PKCS1-v1_5 over SHA-256, composing FIPS 180-4 for the digest.

## Overview

This package owns asymmetric signing for the Institute. `Signature.RSA.Key` imports a PEM-armoured RSA private key (PKCS#1 directly, or PKCS#8 with the wrapper peeled), and `Signature.RS256.sign(message:key:)` produces the RSASSA-PKCS1-v1_5-over-SHA-256 signature RFC 7518 §3.3 names `RS256` — the algorithm a GitHub App assertion requires.

Two disciplines are load-bearing:

- **SHA-2 is composed, never implemented.** Digests come from [swift-fips-180-4](https://github.com/swift-standards/swift-fips-180-4), the Institute's sole SHA-2 owner (ruling R37). Only the digest reaches the platform, under the digest-level algorithm.
- **The asymmetric primitive is the platform key facility, behind a platform condition.** On a platform without a reachable facility, signing throws `.unsupportedPlatform` rather than pretending. No key material crosses a process boundary, is written anywhere, appears in a process argument, or is quoted by any diagnostic.

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/swift-foundations/swift-signature.git", branch: "main")
]
```

## Usage

```swift
import Signature

let key = try Signature.RSA.Key(pem: pem)
let signature = try Signature.RS256.sign(message: [Byte](signingInput.utf8), key: key)
```
