//! Pair two devices with a short code a human reads off one screen and types
//! on the other.
//!
//! The pieces are transport-agnostic (sans-IO) so the same crate serves a
//! desktop, a phone over `UniFFI`, a TV app and a CLI:
//!
//! - [`PairingWindow`]: a one-shot, time-limited window on the device that
//!   shows the code. Any attempt, right or wrong, consumes it.
//! - [`CodeExchange`]: SPAKE2 over the code, then key confirmation bound to
//!   both devices' long-term identity keys. A man in the middle gets exactly
//!   one guess per window and learns nothing about the code from a failure.
//! - [`sas_digits`]: a short authentication string for flows that have no
//!   shared code (the user compares two 6-digit numbers instead).
//! - [`TrustStore`]: the list of paired peers, sealed with a keyed MAC so a
//!   silently inserted key is refused at load.
//! - `net` (feature `iroh`): the exchange over an iroh QUIC connection, where
//!   iroh's TLS proves each side holds the key for its endpoint id.
//! - [`Domain`]: every domain-separation string in one place, so an app that
//!   ran its own scheme before can adopt the crate without breaking the codes,
//!   SAS digits and sealed trust stores it already has. Functions without an
//!   `_in` suffix use [`Domain::DEFAULT`].

mod code;
mod domain;
mod error;
mod exchange;
mod trust;
mod window;

#[cfg(feature = "iroh")]
pub mod net;

pub use code::{
    CODE_ALPHABET, CODE_LEN, SAS_DIGITS, normalise_code, sas_digits, sas_digits_in,
    short_code_from_token, short_code_from_token_in,
};
pub use domain::Domain;
pub use error::PairError;
pub use exchange::{CONFIRM_LEN, CodeExchange, Confirmed, PAKE_MSG_LEN};
pub use trust::{PeerRecord, TrustError, TrustStore, TrustedPeer};
pub use window::{PAIRING_TTL, PairingWindow};

/// Milliseconds since the Unix epoch, for trust-store timestamps.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
