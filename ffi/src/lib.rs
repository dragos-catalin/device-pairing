//! `UniFFI` bindings for [`device_pairing`] (Kotlin package `ro.codai.devicepairing`).
//!
//! The surface is the sans-IO core: the app moves the bytes over its own
//! transport. Everything is synchronous. Byte arguments are `Vec<u8>` so
//! Kotlin sees `ByteArray`, and every fixed-length input (identity keys,
//! nonces, secrets) is checked at the boundary.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use device_pairing as dp;

uniffi::setup_scaffolding!("device_pairing");

/// Why a call failed. Kotlin: `PairingException`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum PairingError {
    /// The code, token or SAS did not match, or key confirmation failed.
    #[error("the code did not match")]
    Mismatch,
    /// The pairing window expired.
    #[error("the pairing window expired")]
    Expired,
    /// The window or exchange step was already used.
    #[error("already used")]
    Consumed,
    /// The peer sent something malformed.
    #[error("protocol error: {reason}")]
    Protocol {
        /// What was wrong.
        reason: String,
    },
    /// An argument had the wrong length or format.
    #[error("invalid input: {reason}")]
    InvalidInput {
        /// What was wrong.
        reason: String,
    },
    /// A sealed trust store failed its integrity check or did not parse.
    #[error("bad trust store: {reason}")]
    BadTrustStore {
        /// What was wrong.
        reason: String,
    },
}

impl From<dp::PairError> for PairingError {
    fn from(e: dp::PairError) -> Self {
        match e {
            dp::PairError::Mismatch => Self::Mismatch,
            dp::PairError::Expired => Self::Expired,
            dp::PairError::Consumed => Self::Consumed,
            dp::PairError::Protocol(reason) => Self::Protocol { reason },
            dp::PairError::Network(reason) => Self::Protocol {
                reason: format!("network: {reason}"),
            },
        }
    }
}

impl From<dp::TrustError> for PairingError {
    fn from(e: dp::TrustError) -> Self {
        Self::BadTrustStore {
            reason: e.to_string(),
        }
    }
}

fn fixed<const N: usize>(what: &str, bytes: &[u8]) -> Result<[u8; N], PairingError> {
    bytes.try_into().map_err(|_| PairingError::InvalidInput {
        reason: format!("{what} must be {N} bytes, got {}", bytes.len()),
    })
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A one-shot, time-limited pairing window on the device that shows the code.
#[derive(Debug, uniffi::Object)]
pub struct PairingWindow {
    inner: Mutex<dp::PairingWindow>,
}

#[uniffi::export]
impl PairingWindow {
    /// Open a window with a fresh token and the default 120 s TTL.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(dp::PairingWindow::open()),
        })
    }

    /// Open a window with a custom TTL in seconds.
    #[uniffi::constructor]
    pub fn with_ttl_secs(secs: u64) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(dp::PairingWindow::with_ttl(Duration::from_secs(secs))),
        })
    }

    /// The 8-character code to show on screen.
    pub fn code(&self) -> String {
        lock(&self.inner).code()
    }

    /// The full token (base32, upper-case, no padding) for a QR code.
    pub fn token(&self) -> String {
        lock(&self.inner).token_string()
    }

    /// The 16-byte nonce for the SAS flow; send it to the peer.
    pub fn nonce(&self) -> Vec<u8> {
        lock(&self.inner).nonce().to_vec()
    }

    /// Whether the TTL has passed.
    pub fn is_expired(&self) -> bool {
        lock(&self.inner).is_expired()
    }

    /// Whether an attempt already used this window.
    pub fn is_consumed(&self) -> bool {
        lock(&self.inner).is_consumed()
    }

    /// Start the one attempt; returns the code to feed into `CodeExchange`.
    ///
    /// # Errors
    /// `Consumed` on a second call, `Expired` after the TTL.
    pub fn begin_attempt(&self) -> Result<String, PairingError> {
        Ok(lock(&self.inner).begin_attempt()?.to_string())
    }

    /// Verify a scanned QR token. One attempt.
    ///
    /// # Errors
    /// `Mismatch`, `Consumed` or `Expired`.
    pub fn verify_token(&self, presented: String) -> Result<(), PairingError> {
        Ok(lock(&self.inner).verify_token(&presented)?)
    }

    /// Compare a typed code directly. One attempt.
    ///
    /// # Errors
    /// `Mismatch`, `Consumed` or `Expired`.
    pub fn verify_code(&self, typed: String) -> Result<(), PairingError> {
        Ok(lock(&self.inner).verify_code(&typed)?)
    }

    /// Verify a typed SAS for the given 32-byte identity keys. One attempt.
    ///
    /// # Errors
    /// `InvalidInput` for a wrong id length (the window is not consumed),
    /// otherwise `Mismatch`, `Consumed` or `Expired`.
    pub fn verify_sas(
        &self,
        typed: String,
        local_id: Vec<u8>,
        remote_id: Vec<u8>,
    ) -> Result<(), PairingError> {
        let local = fixed::<32>("local_id", &local_id)?;
        let remote = fixed::<32>("remote_id", &remote_id)?;
        Ok(lock(&self.inner).verify_sas(&typed, &local, &remote)?)
    }
}

/// SPAKE2 over the code, bound to both 32-byte identity keys.
#[derive(Debug, uniffi::Object)]
pub struct CodeExchange {
    message: Vec<u8>,
    inner: Mutex<Option<dp::CodeExchange>>,
}

#[uniffi::export]
impl CodeExchange {
    /// Start the exchange. `code` may be as typed (case, dashes, spaces ignored).
    ///
    /// # Errors
    /// `InvalidInput` when an id is not 32 bytes.
    #[uniffi::constructor]
    pub fn start(
        code: String,
        local_id: Vec<u8>,
        remote_id: Vec<u8>,
    ) -> Result<Arc<Self>, PairingError> {
        let local = fixed::<32>("local_id", &local_id)?;
        let remote = fixed::<32>("remote_id", &remote_id)?;
        let x = dp::CodeExchange::start(&code, &local, &remote);
        Ok(Arc::new(Self {
            message: x.message().to_vec(),
            inner: Mutex::new(Some(x)),
        }))
    }

    /// The 33-byte message to send to the peer.
    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }

    /// Consume the peer's message. Can be called once.
    ///
    /// # Errors
    /// `Protocol` for a malformed or reflected message, `Consumed` on a second call.
    pub fn finish(&self, peer_message: Vec<u8>) -> Result<Arc<Confirmation>, PairingError> {
        let x = lock(&self.inner).take().ok_or(PairingError::Consumed)?;
        let confirmed = x.finish(&peer_message)?;
        Ok(Arc::new(Confirmation {
            tag: confirmed.tag().to_vec(),
            inner: Mutex::new(Some(confirmed)),
        }))
    }
}

/// SPAKE2 finished; nothing is trusted until the peer's tag verifies.
#[derive(Debug, uniffi::Object)]
pub struct Confirmation {
    tag: Vec<u8>,
    inner: Mutex<Option<dp::Confirmed>>,
}

#[uniffi::export]
impl Confirmation {
    /// Our 32-byte confirmation tag, to send to the peer.
    pub fn tag(&self) -> Vec<u8> {
        self.tag.clone()
    }

    /// Check the peer's tag; returns the shared 32-byte session key. Can be called once.
    ///
    /// # Errors
    /// `Mismatch` when the codes differed or someone sat in the middle; `Consumed` on a second call.
    pub fn verify_peer(&self, peer_tag: Vec<u8>) -> Result<Vec<u8>, PairingError> {
        let c = lock(&self.inner).take().ok_or(PairingError::Consumed)?;
        Ok(c.verify_peer(&peer_tag)?.to_vec())
    }
}

/// Upper-case and drop everything but ASCII letters and digits.
#[uniffi::export]
pub fn normalise_code(input: String) -> String {
    dp::normalise_code(&input)
}

/// Six SAS digits over a 16-byte nonce and two 32-byte ids (order-independent).
///
/// # Errors
/// `InvalidInput` on a wrong length.
#[uniffi::export]
pub fn sas_digits(nonce: Vec<u8>, id_a: Vec<u8>, id_b: Vec<u8>) -> Result<String, PairingError> {
    let nonce = fixed::<16>("nonce", &nonce)?;
    let a = fixed::<32>("id_a", &id_a)?;
    let b = fixed::<32>("id_b", &id_b)?;
    Ok(dp::sas_digits(&nonce, &a, &b))
}

/// The characters a code is made of.
#[uniffi::export]
pub fn code_alphabet() -> String {
    String::from_utf8_lossy(dp::CODE_ALPHABET).into_owned()
}

/// The number of characters in a code.
#[uniffi::export]
pub fn code_length() -> u32 {
    u32::try_from(dp::CODE_LEN).unwrap_or(u32::MAX)
}

/// A paired device (the crate's default `TrustedPeer`), `meta` as JSON text.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TrustedPeerRecord {
    /// The peer's identity key, encoded (opaque).
    pub id: String,
    /// Human name.
    pub name: String,
    /// How it was paired, e.g. `code`, `qr`, `sas`.
    pub method: String,
    /// When it was paired (ms since epoch).
    pub paired_at_ms: u64,
    /// Last time it connected, if ever.
    pub last_seen_ms: Option<u64>,
    /// Application data as JSON text (empty means `null`). Covered by the MAC.
    pub meta_json: String,
    /// Revoked peers stay listed.
    pub revoked: bool,
}

impl TryFrom<TrustedPeerRecord> for dp::TrustedPeer {
    type Error = PairingError;
    fn try_from(r: TrustedPeerRecord) -> Result<Self, PairingError> {
        let meta = if r.meta_json.trim().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&r.meta_json).map_err(|e| PairingError::InvalidInput {
                reason: format!("meta_json: {e}"),
            })?
        };
        Ok(Self {
            id: r.id,
            name: r.name,
            method: r.method,
            paired_at_ms: r.paired_at_ms,
            last_seen_ms: r.last_seen_ms,
            meta,
            revoked: r.revoked,
        })
    }
}

impl From<&dp::TrustedPeer> for TrustedPeerRecord {
    fn from(p: &dp::TrustedPeer) -> Self {
        Self {
            id: p.id.clone(),
            name: p.name.clone(),
            method: p.method.clone(),
            paired_at_ms: p.paired_at_ms,
            last_seen_ms: p.last_seen_ms,
            meta_json: p.meta.to_string(),
            revoked: p.revoked,
        }
    }
}

/// The paired-device list, sealed with a MAC keyed by a 32-byte local secret.
#[derive(Debug, uniffi::Object)]
pub struct TrustStore {
    inner: Mutex<dp::TrustStore>,
}

#[uniffi::export]
impl TrustStore {
    /// An empty store.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(dp::TrustStore::default()),
        })
    }

    /// Verify and parse a sealed store.
    ///
    /// # Errors
    /// `InvalidInput` for a secret that is not 32 bytes, `BadTrustStore` on a bad MAC or malformed body.
    #[uniffi::constructor]
    pub fn open(sealed: Vec<u8>, secret: Vec<u8>) -> Result<Arc<Self>, PairingError> {
        let secret = fixed::<32>("secret", &secret)?;
        Ok(Arc::new(Self {
            inner: Mutex::new(dp::TrustStore::open(&sealed, &secret)?),
        }))
    }

    /// Serialise with the integrity tag.
    ///
    /// # Errors
    /// `InvalidInput` for a secret that is not 32 bytes.
    pub fn seal(&self, secret: Vec<u8>) -> Result<Vec<u8>, PairingError> {
        let secret = fixed::<32>("secret", &secret)?;
        Ok(lock(&self.inner).seal(&secret))
    }

    /// Add or replace a peer.
    ///
    /// # Errors
    /// `InvalidInput` when `meta_json` is not valid JSON.
    pub fn insert(&self, peer: TrustedPeerRecord) -> Result<(), PairingError> {
        let peer = dp::TrustedPeer::try_from(peer)?;
        lock(&self.inner).insert(peer);
        Ok(())
    }

    /// Mark a peer revoked; false when unknown.
    pub fn revoke(&self, id: String) -> bool {
        lock(&self.inner).revoke(&id)
    }

    /// True when `id` is paired and not revoked.
    pub fn is_trusted(&self, id: String) -> bool {
        lock(&self.inner).is_trusted(&id)
    }

    /// All peers, revoked ones included, ordered by id.
    pub fn peers(&self) -> Vec<TrustedPeerRecord> {
        lock(&self.inner).peers.values().map(Into::into).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(
        code_a: &str,
        code_b: &str,
    ) -> (Result<Vec<u8>, PairingError>, Result<Vec<u8>, PairingError>) {
        let (a, b) = (vec![1u8; 32], vec![2u8; 32]);
        let xa = CodeExchange::start(code_a.into(), a.clone(), b.clone()).unwrap();
        let xb = CodeExchange::start(code_b.into(), b, a).unwrap();
        let ca = xa.finish(xb.message()).unwrap();
        let cb = xb.finish(xa.message()).unwrap();
        (ca.verify_peer(cb.tag()), cb.verify_peer(ca.tag()))
    }

    #[test]
    fn two_sided_pairing_through_the_objects() {
        let window = PairingWindow::new();
        let shown = window.code();
        let code = window.begin_attempt().unwrap();
        assert_eq!(code, shown);
        let typed = format!("{}-{}", &shown[..4], &shown[4..]).to_lowercase();
        let (ka, kb) = exchange(&code, &typed);
        let (ka, kb) = (ka.unwrap(), kb.unwrap());
        assert_eq!(ka.len(), 32);
        assert_eq!(ka, kb);
        assert_eq!(window.begin_attempt(), Err(PairingError::Consumed));
    }

    #[test]
    fn wrong_code_fails_both_sides() {
        let (ka, kb) = exchange("ABCDEFGH", "ABCDEFGJ");
        assert_eq!(ka, Err(PairingError::Mismatch));
        assert_eq!(kb, Err(PairingError::Mismatch));
    }

    #[test]
    fn steps_are_one_shot_and_inputs_checked() {
        let xa = CodeExchange::start("ABCDEFGH".into(), vec![1; 32], vec![2; 32]).unwrap();
        let xb = CodeExchange::start("ABCDEFGH".into(), vec![2; 32], vec![1; 32]).unwrap();
        let c = xa.finish(xb.message()).unwrap();
        assert_eq!(
            xa.finish(xb.message()).map(|_| ()),
            Err(PairingError::Consumed)
        );
        let _ = c.verify_peer(vec![0; 32]);
        assert_eq!(c.verify_peer(vec![0; 32]), Err(PairingError::Consumed));
        assert!(matches!(
            CodeExchange::start("X".into(), vec![1; 31], vec![2; 32]),
            Err(PairingError::InvalidInput { .. })
        ));
        assert!(matches!(
            xb.finish(vec![0; 5]),
            Err(PairingError::Protocol { .. })
        ));
        assert!(matches!(
            sas_digits(vec![0; 15], vec![1; 32], vec![2; 32]),
            Err(PairingError::InvalidInput { .. })
        ));
    }

    #[test]
    fn window_token_code_and_sas() {
        let qr = PairingWindow::new();
        let token = qr.token();
        assert_eq!(qr.verify_token(token.to_lowercase()), Ok(()));
        assert!(qr.is_consumed());

        let typed = PairingWindow::with_ttl_secs(60);
        let code = typed.code();
        assert_eq!(typed.verify_code(code.to_lowercase()), Ok(()));

        let window = PairingWindow::new();
        let (id_a, id_b) = (vec![1u8; 32], vec![2u8; 32]);
        assert!(matches!(
            window.verify_sas(String::new(), vec![1; 3], id_b.clone()),
            Err(PairingError::InvalidInput { .. })
        ));
        assert!(!window.is_consumed());
        let sas = sas_digits(window.nonce(), id_b.clone(), id_a.clone()).unwrap();
        assert_eq!(
            sas,
            sas_digits(window.nonce(), id_a.clone(), id_b.clone()).unwrap()
        );
        assert_eq!(window.verify_sas(sas, id_a, id_b), Ok(()));
        assert_eq!(code_length(), 8);
        assert_eq!(code_alphabet().len(), 30);
        assert_eq!(normalise_code("ab-cd".into()), "ABCD");
    }

    #[test]
    fn trust_store_round_trip_and_tamper() {
        let s = TrustStore::new();
        s.insert(TrustedPeerRecord {
            id: "abc".into(),
            name: "TV".into(),
            method: "code".into(),
            paired_at_ms: 1,
            last_seen_ms: None,
            meta_json: r#"{"platform":"android-tv"}"#.into(),
            revoked: false,
        })
        .unwrap();
        let secret = vec![9u8; 32];
        let mut sealed = s.seal(secret.clone()).unwrap();
        let back = TrustStore::open(sealed.clone(), secret.clone()).unwrap();
        assert_eq!(back.peers(), s.peers());
        assert!(back.is_trusted("abc".into()));
        assert!(back.revoke("abc".into()));
        assert!(!back.is_trusted("abc".into()));
        sealed[40] ^= 1;
        assert!(matches!(
            TrustStore::open(sealed, secret),
            Err(PairingError::BadTrustStore { .. })
        ));
        assert!(matches!(
            TrustStore::open(vec![], vec![0; 3]),
            Err(PairingError::InvalidInput { .. })
        ));
    }
}
