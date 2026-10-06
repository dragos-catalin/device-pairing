# device-pairing

Pair a phone, a desktop and a TV with a short code, once, in one Rust crate.

## Problem

Every app that links two of my devices rewrote pairing: dashy (desktop ↔ phone ↔ TV), titi, vitals, scrin, vsrchat, abridge. Each copy made its own choices about code length, retries, how the code binds to the device keys and how the list of paired devices is stored. Pairing is where a small mistake (a retryable code, a code not bound to the connection, a trust list anyone can append to) turns into "anyone on the Wi-Fi can pair".

## Approach

One crate, sans-IO at the core so it works from Tauri, a CLI, Android/TV over UniFFI or a server, plus an optional iroh transport:

| Piece           | What it does                                                                                                                                                          |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PairingWindow` | A one-shot window on the device that shows the code: 8 characters from a 30-symbol alphabet with no `0 1 I L O U`, 120 s TTL. Any attempt, right or wrong, closes it. |
| `CodeExchange`  | SPAKE2 (Ed25519, symmetric) over the code, with both devices' identity keys bound into the exchange, then key confirmation in both directions.                        |
| `sas_digits`    | A 6-digit short authentication string for flows without a shared code; the user compares or types it.                                                                 |
| `TrustStore`    | Paired devices as JSON sealed with a BLAKE3 keyed MAC derived from the local identity secret. A bad MAC refuses to load.                                              |
| `net` (`iroh`)  | `join` and `accept` run the exchange over an iroh QUIC stream (ALPN `device-pairing/1`), where TLS proves each endpoint id.                                           |
| `Domain`        | Every domain-separation string in one place, so an app with its own older scheme keeps its codes, SAS digits and sealed trust stores valid.                          |
| `ts/`           | `@codai/device-pairing`: code formatting, validation and SAS in TypeScript, checked byte for byte against Rust test vectors.                                          |
| `ffi/`          | `device-pairing-ffi`: UniFFI bindings, Kotlin package `ro.codai.devicepairing` (Android, Wear OS, Google TV, JVM).                                                     |

```rust
// Host (TV): show window.code(), then on an incoming connection:
let mut window = PairingWindow::open();
let paired = device_pairing::net::accept(&endpoint, conn, &mut window).await?;
trust.insert(TrustedPeer { id: hex(&paired.peer_id), name, method: "code".into(), /* ... */ });

// Joiner (phone): the user typed the code.
let paired = device_pairing::net::join(&endpoint, host_addr, &typed_code).await?;
```

With another transport, drive `CodeExchange` yourself: send `message()` (33 bytes), `finish()` with the peer's, send `tag()` (32 bytes), `verify_peer()` with the peer's tag.

For a QR flow, put `window.token_string()` (base32) in the code and check what the scanner presents with `window.verify_token()`; for apps that compare a typed code directly over an already-authenticated transport, `window.verify_code()`. Both are one attempt per window, like everything else.

## Migrating an existing scheme (`Domain`)

Every BLAKE3 context and SPAKE2 identity prefix the crate uses lives in a `Domain`. The plain functions use `Domain::DEFAULT` (byte-identical to 0.1); each has an `_in` variant that takes a domain: `short_code_from_token_in`, `sas_digits_in`, `PairingWindow::open_in` / `with_ttl_in`, `CodeExchange::start_in`, `TrustStore::seal_in` / `open_in`.

An app that already shipped its own pairing sets its old strings, so the codes it shows, the SAS digits its users compare and the trust stores already on disk stay valid. dashy's pre-crate scheme uses the same derivations with different contexts:

```rust
use device_pairing::{Domain, PairingWindow, PeerRecord, TrustStore};

const DASHY: Domain = Domain {
		code_context: "dashy-pairing-code-v1",
		sas_domain: b"dashy-sas-v1",
		trust_mac_context: "dashy trust-store v1",
		..Domain::DEFAULT
};

let window = PairingWindow::open_in(&DASHY);
// dashy keeps its own peer type: implement PeerRecord (id, is_revoked, set_revoked).
let store = TrustStore::<DashyPeer>::open_in(&DASHY, &sealed, &identity_secret)?;
```

`TrustStore<P = TrustedPeer>` is generic over any `PeerRecord`; the sealed JSON is always `{"peers":{"<id>": <peer>}}`, so a store written by the app's old code opens unchanged. A new app should pick its own unique strings, or keep `Domain::DEFAULT`.

## Kotlin (UniFFI)

`ffi/` is a separate workspace crate (`device-pairing-ffi`, not published) that exports the sans-IO core through UniFFI 0.32 proc-macros. The app moves the bytes over its own transport.

```text
cargo build -p device-pairing-ffi --release
cargo run -p device-pairing-ffi --bin uniffi-bindgen -- generate \
	--library target/release/libdevice_pairing_ffi.so --language kotlin --out-dir ffi/kotlin/generated
```

The generated sources are not committed; CI regenerates them. The Kotlin surface:

```kotlin
import ro.codai.devicepairing.*

// Host (TV): show window.code(), or window.token() in a QR code.
val window = PairingWindow()                 // or PairingWindow.withTtlSecs(300uL)
val code = window.beginAttempt()             // one attempt; throws PairingException.Consumed after

// Both sides, ids = the 32-byte identity keys the transport authenticates.
val x = CodeExchange.start(code /* or what the user typed */, localId, remoteId)
send(x.message())                            // 33 bytes
val c = x.finish(receive())
send(c.tag())                                // 32 bytes
val sessionKey = c.verifyPeer(receive())     // 32 bytes, or PairingException.Mismatch

val store = TrustStore.open(sealed, secret)  // PairingException.BadTrustStore if tampered
store.insert(TrustedPeerRecord(id, name, "code", nowMs, null, "{}", false))
val bytes = store.seal(secret)
```

Also exported: `verifyToken`, `verifyCode`, `verifySas`, `nonce`, `isExpired`, `isConsumed`, `sasDigits`, `normaliseCode`, `codeAlphabet`, `codeLength`. Errors are `PairingException.{Mismatch, Expired, Consumed, Protocol, InvalidInput, BadTrustStore}`. Byte arguments are `ByteArray`; wrong lengths throw `InvalidInput` before touching any state.

The JVM test needs only a JDK and cargo: `pwsh ffi/kotlin/run-tests.ps1` (or `bash ffi/kotlin/run-tests.sh`) downloads kotlinc and JNA into `ffi/kotlin/.cache`, generates the bindings, compiles them with `ffi/kotlin/test/PairingTest.kt` and runs an end-to-end pairing, mismatch, one-shot, SAS and trust-store checks against the native library.

## Threat model

**Protects against**

- **A network attacker who sees everything** (same Wi-Fi, relay operator): SPAKE2 reveals nothing about the code, so there is no offline guessing.
- **An active man in the middle**: one online guess per window, about 1 in 6.5 × 10¹¹ for a random code, and a failed guess closes the window. Both identity keys are bound into the exchange, so relaying between two honest devices fails key confirmation even when the code is right.
- **Reflection and replay**: a reflected PAKE message or confirmation tag is refused; every window uses a fresh token.
- **Silent insertion into the trust list**: the store is MAC'd with a key derived from the device secret.
- **Malformed input across the FFI boundary**: identity keys, nonces and secrets are length-checked before they reach the core; a bad length throws `InvalidInput` and does not consume a window.

**Does not protect against**

- **Shoulder surfing** within the 120 s window. Someone who reads the code and connects first pairs instead of you; the legitimate device then fails and the user sees it.
- **A compromised device**: its identity secret also opens its trust store.
- **Malware on the same OS user**: it can read the identity secret unless the app keeps it in the OS keystore.
- **Revocation across devices**: revoking is local. Tell the other device over a live session, or revoke on both.
- **Secrets in the JVM heap**: through the Kotlin bindings the session key, the trust-store secret and the code cross into the JVM as `ByteArray` / `String`, which cannot be zeroized reliably. Hold them briefly, and keep the identity secret in the Android Keystore rather than in app storage.
- **Shared domains**: a custom `Domain` that reuses another app's contexts couples the two (same token gives the same code, same secret gives the same MAC key). Choose unique contexts.
- The crate has not had an external audit. SPAKE2 comes from RustCrypto `spake2` 0.4, BLAKE3 from the reference crate.

## Build

```text
cargo test --features iroh        # unit + loopback iroh pairing + TS vectors check
cargo test --workspace --features iroh   # the above plus the FFI wrapper
pwsh ffi/kotlin/run-tests.ps1     # Kotlin bindings on the JVM (needs a JDK)
cd ts; pnpm install; pnpm test    # TypeScript half against the same vectors
UPDATE_VECTORS=1 cargo test --test vectors   # regenerate ts/test/vectors.json
```

## Roadmap

- Done in 0.2: UniFFI bindings for Kotlin (Android, Wear OS, Google TV), tested on the JVM.
- Swift bindings (iOS) from the same `ffi/` crate.
- An AAR / Maven artifact with the native libraries for each Android ABI.
- QR payload format (endpoint address + code) shared across apps.
- Migrate dashy, titi and vitals onto the crate.

## Status

0.2: the exchange, window (code, QR token, SAS), trust store and `Domain` migration path are tested, including a real pairing between two iroh endpoints on loopback and an end-to-end pairing through the Kotlin bindings on the JVM. Default derivations are unchanged from 0.1 (pinned by test vectors and a 0.1-sealed trust store). The wire format may change before 1.0. See [CHANGELOG.md](CHANGELOG.md). Part of [dragoscatalin.ro/lab](https://dragoscatalin.ro/lab). MIT licensed.
