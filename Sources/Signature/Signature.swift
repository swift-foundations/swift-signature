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

/// Asymmetric message signing.
///
/// RS256-first: RSASSA-PKCS1-v1_5 over SHA-256 — the algorithm RFC 7518
/// §3.3 names `RS256`, and the one a GitHub App assertion requires.
///
/// Two disciplines govern everything under this namespace:
///
/// - **SHA-2 is composed, never implemented.** Digests come from
///   FIPS 180-4 (`swift-standards/swift-fips-180-4`), the Institute's
///   sole SHA-2 owner (ruling R37). No hash arithmetic lives here.
/// - **The asymmetric primitive is the platform key facility**, reached
///   only behind a platform condition. No key material crosses a
///   process boundary, is written anywhere, or appears in a process
///   argument — and no diagnostic ever quotes key bytes or a key
///   location.
public enum Signature {}
