# Changelog

All notable changes to this project. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may change the wire format; this one does not).

## [0.2.0] - 2026-10-06

Crate `device-pairing` 0.2.0 and npm `@codai/device-pairing` 0.2.0. Default derivations are byte-identical to 0.1.0: `ts/test/vectors.json` is unchanged and a trust store sealed by 0.1.0 opens and re-seals to the same bytes (test).

### Added

- `Domain`: every domain-separation string (code, SAS, trust-store MAC, SPAKE2 identity, confirmation, session) in one const-constructible struct; `Domain::DEFAULT` is the 0.1 set. `_in` variants take a domain: `short_code_from_token_in`, `sas_digits_in`, `PairingWindow::open_in` / `with_ttl_in`, `CodeExchange::start_in`, `TrustStore::seal_in` / `open_in`. Lets an app with an older scheme (dashy) adopt the crate without invalidating installed pairings.
- `PairingWindow::token_string` (RFC 4648 base32, no padding) and `PairingWindow::verify_token` for QR flows; `PairingWindow::verify_code` for apps that compare a typed code directly. One attempt per window, constant-time, case-insensitive.
- `PeerRecord` trait and generic `TrustStore<P = TrustedPeer>`, so an app keeps its own peer schema; `TrustStore::new`. The sealed JSON shape is unchanged.
- `CONFIRM_LEN` is now re-exported.
- `ffi/`: workspace crate `device-pairing-ffi` (not published) with UniFFI 0.32 Kotlin bindings (`ro.codai.devicepairing`): `PairingWindow`, `CodeExchange`, `Confirmation`, `TrustStore`, `TrustedPeerRecord`, `PairingException`, `sasDigits`, `normaliseCode`, `codeAlphabet`, `codeLength`.
- Kotlin JVM test without Gradle (`ffi/kotlin/run-tests.ps1` / `.sh`) and a CI `kotlin` job; CI also lints and tests the FFI crate and type-checks it for `aarch64-linux-android`.

### Changed

- The release workflow tests and publishes only the core crate (`-p device-pairing`).

## [0.1.0] - 2026-10-06

### Added

- `PairingWindow`: one-shot, 120 s pairing window with an 8-character code from a 30-symbol alphabet.
- `CodeExchange` / `Confirmed`: symmetric SPAKE2 (Ed25519) over the code, both identity keys bound, direction-bound key confirmation.
- `sas_digits`: 6-digit short authentication string.
- `TrustStore`: paired peers as JSON sealed with a BLAKE3 keyed MAC.
- `net` (feature `iroh`): `join` / `accept` over an iroh QUIC stream.
- `@codai/device-pairing` (TypeScript): code formatting, validation and SAS, checked against shared test vectors.

[0.2.0]: https://github.com/dragos-catalin/device-pairing/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/dragos-catalin/device-pairing/releases/tag/v0.1.0
