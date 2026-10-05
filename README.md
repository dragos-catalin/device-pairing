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
| `ts/`           | `@codai/device-pairing`: code formatting, validation and SAS in TypeScript, checked byte for byte against Rust test vectors.                                          |

```rust
// Host (TV): show window.code(), then on an incoming connection:
let mut window = PairingWindow::open();
let paired = device_pairing::net::accept(&endpoint, conn, &mut window).await?;
trust.insert(TrustedPeer { id: hex(&paired.peer_id), name, method: "code".into(), /* ... */ });

// Joiner (phone): the user typed the code.
let paired = device_pairing::net::join(&endpoint, host_addr, &typed_code).await?;
```

With another transport, drive `CodeExchange` yourself: send `message()` (33 bytes), `finish()` with the peer's, send `tag()` (32 bytes), `verify_peer()` with the peer's tag.

## Threat model

**Protects against**

- **A network attacker who sees everything** (same Wi-Fi, relay operator): SPAKE2 reveals nothing about the code, so there is no offline guessing.
- **An active man in the middle**: one online guess per window, about 1 in 6.5 × 10¹¹ for a random code, and a failed guess closes the window. Both identity keys are bound into the exchange, so relaying between two honest devices fails key confirmation even when the code is right.
- **Reflection and replay**: a reflected PAKE message or confirmation tag is refused; every window uses a fresh token.
- **Silent insertion into the trust list**: the store is MAC'd with a key derived from the device secret.

**Does not protect against**

- **Shoulder surfing** within the 120 s window. Someone who reads the code and connects first pairs instead of you; the legitimate device then fails and the user sees it.
- **A compromised device**: its identity secret also opens its trust store.
- **Malware on the same OS user**: it can read the identity secret unless the app keeps it in the OS keystore.
- **Revocation across devices**: revoking is local. Tell the other device over a live session, or revoke on both.
- The crate has not had an external audit. SPAKE2 comes from RustCrypto `spake2` 0.4, BLAKE3 from the reference crate.

## Build

```text
cargo test --features iroh        # unit + loopback iroh pairing + TS vectors check
cd ts; pnpm install; pnpm test    # TypeScript half against the same vectors
UPDATE_VECTORS=1 cargo test --test vectors   # regenerate ts/test/vectors.json
```

## Roadmap

- UniFFI bindings for Kotlin (Android, Wear OS, Google TV) and Swift.
- QR payload format (endpoint address + code) shared across apps.
- Migrate dashy, titi and vitals onto the crate.

## Status

0.1: the exchange, window, SAS and trust store are tested, including a real pairing between two iroh endpoints on loopback. The wire format may change before 1.0. Part of [dragoscatalin.ro/lab](https://dragoscatalin.ro/lab). MIT licensed.
