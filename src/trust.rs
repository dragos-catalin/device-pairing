use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::Domain;

/// A peer entry an app stores in a [`TrustStore`]. Implement it for your own
/// type to keep an existing on-disk schema; [`TrustedPeer`] is the default.
pub trait PeerRecord: Serialize + DeserializeOwned + Clone {
    /// The key the peer is stored under (its identity key, encoded).
    fn id(&self) -> &str;
    /// Whether the peer was revoked.
    fn is_revoked(&self) -> bool;
    /// Mark the peer revoked.
    fn set_revoked(&mut self);
}

/// A paired device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedPeer {
    /// The peer's identity key, lower-case hex or base32 (opaque to this crate).
    pub id: String,
    /// Human name shown in a device list.
    pub name: String,
    /// How it was paired, e.g. `"code"`, `"qr"`, `"sas"`.
    pub method: String,
    /// When it was paired (ms since epoch).
    pub paired_at_ms: u64,
    /// Last time it connected, if ever.
    pub last_seen_ms: Option<u64>,
    /// Application data (addresses, platform, ...). Covered by the MAC.
    #[serde(default)]
    pub meta: serde_json::Value,
    /// Revoked peers stay listed so a revoke is not undone by re-sync.
    pub revoked: bool,
}

impl PeerRecord for TrustedPeer {
    fn id(&self) -> &str {
        &self.id
    }
    fn is_revoked(&self) -> bool {
        self.revoked
    }
    fn set_revoked(&mut self) {
        self.revoked = true;
    }
}

/// The list of peers allowed to connect.
///
/// It needs integrity, not secrecy: the attack is a silently inserted key.
/// Sealed as `MAC(32) || JSON` with a BLAKE3 keyed hash under a key derived
/// from the local identity secret. A bad MAC refuses to load rather than
/// falling back to an empty list.
///
/// The JSON is `{"peers":{"<id>":<peer>,...}}` whatever `P` is, so an app
/// with its own peer type keeps reading stores it wrote before adopting
/// this crate (set [`Domain::trust_mac_context`] to its old context too).
/// Construct a custom-typed store with [`TrustStore::new`] or
/// `TrustStore::<MyPeer>::open_in(..)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustStore<P = TrustedPeer> {
    /// Peers by id.
    pub peers: BTreeMap<String, P>,
}

impl Default for TrustStore<TrustedPeer> {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a sealed store could not be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// The MAC did not verify: tampered, or sealed by another identity.
    #[error("trust store integrity check failed")]
    BadMac,
    /// Too short or not JSON.
    #[error("trust store is malformed")]
    Malformed,
}

fn mac(domain: &Domain, secret: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let key = zeroize::Zeroizing::new(blake3::derive_key(domain.trust_mac_context, secret));
    *blake3::keyed_hash(&key, body).as_bytes()
}

impl TrustStore<TrustedPeer> {
    /// Verify and parse a sealed store ([`Domain::DEFAULT`]).
    ///
    /// # Errors
    /// [`TrustError::BadMac`] or [`TrustError::Malformed`].
    pub fn open(sealed: &[u8], secret: &[u8; 32]) -> Result<Self, TrustError> {
        Self::open_in(&Domain::DEFAULT, sealed, secret)
    }
}

impl<P: PeerRecord> TrustStore<P> {
    /// An empty store.
    pub fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
        }
    }

    /// True when `id` is paired and not revoked.
    pub fn is_trusted(&self, id: &str) -> bool {
        self.peers.get(id).is_some_and(|p| !p.is_revoked())
    }

    /// Add or replace a peer.
    pub fn insert(&mut self, peer: P) {
        self.peers.insert(peer.id().to_owned(), peer);
    }

    /// Mark a peer revoked. Returns false when it was unknown.
    pub fn revoke(&mut self, id: &str) -> bool {
        self.peers.get_mut(id).is_some_and(|p| {
            p.set_revoked();
            true
        })
    }

    /// Serialise with an integrity tag keyed by the local identity secret
    /// ([`Domain::DEFAULT`]).
    pub fn seal(&self, secret: &[u8; 32]) -> Vec<u8> {
        self.seal_in(&Domain::DEFAULT, secret)
    }

    /// [`TrustStore::seal`] with the MAC key derived under `domain`.
    pub fn seal_in(&self, domain: &Domain, secret: &[u8; 32]) -> Vec<u8> {
        let body = serde_json::to_vec(self).unwrap_or_default();
        let mut out = Vec::with_capacity(32 + body.len());
        out.extend_from_slice(&mac(domain, secret, &body));
        out.extend_from_slice(&body);
        out
    }

    /// Verify and parse a sealed store, MAC key derived under `domain`.
    ///
    /// # Errors
    /// [`TrustError::BadMac`] or [`TrustError::Malformed`].
    pub fn open_in(domain: &Domain, sealed: &[u8], secret: &[u8; 32]) -> Result<Self, TrustError> {
        if sealed.len() < 32 {
            return Err(TrustError::Malformed);
        }
        let (tag, body) = sealed.split_at(32);
        if !crate::constant_time_eq(tag, &mac(domain, secret, body)) {
            return Err(TrustError::BadMac);
        }
        serde_json::from_slice(body).map_err(|_| TrustError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: &str) -> TrustedPeer {
        TrustedPeer {
            id: id.into(),
            name: "TV".into(),
            method: "code".into(),
            paired_at_ms: 1,
            last_seen_ms: None,
            meta: serde_json::json!({ "platform": "android-tv" }),
            revoked: false,
        }
    }

    #[test]
    fn tampering_and_wrong_identity_are_refused() {
        let mut s = TrustStore::default();
        s.insert(peer("abc"));
        let mut sealed = s.seal(&[9; 32]);
        assert_eq!(TrustStore::open(&sealed, &[9; 32]), Ok(s.clone()));
        assert_eq!(TrustStore::open(&sealed, &[8; 32]), Err(TrustError::BadMac));
        sealed[40] ^= 1;
        assert_eq!(TrustStore::open(&sealed, &[9; 32]), Err(TrustError::BadMac));
        assert_eq!(
            TrustStore::open(&[0; 3], &[9; 32]),
            Err(TrustError::Malformed)
        );
    }

    #[test]
    fn revoke() {
        let mut s = TrustStore::default();
        s.insert(peer("abc"));
        assert!(s.is_trusted("abc"));
        assert!(s.revoke("abc"));
        assert!(!s.is_trusted("abc"));
        assert!(!s.revoke("zzz"));
    }

    /// Sealed by 0.1.0 (`TrustStore::seal(&[7; 32])`), captured before the
    /// generic refactor. Must keep opening, byte for byte.
    const SEALED_V0_1: &str = "16c03f761f6d6bfda0706616c7a72d5c820726687152c3a35c25dbecdf2a81e27b227065657273223a7b22613162326333223a7b226964223a22613162326333222c226e616d65223a224c6976696e6720726f6f6d205456222c226d6574686f64223a22636f6465222c2270616972656441744d73223a313738303030303030303030302c226c6173745365656e4d73223a313738303030303130303030302c226d657461223a7b226164647273223a5b223139322e3136382e312e32303a37303030225d2c22706c6174666f726d223a22616e64726f69642d7476227d2c227265766f6b6564223a66616c73657d2c22643465356636223a7b226964223a22643465356636222c226e616d65223a2250686f6e65222c226d6574686f64223a227172222c2270616972656441744d73223a313738303030303230303030302c226c6173745365656e4d73223a6e756c6c2c226d657461223a6e756c6c2c227265766f6b6564223a747275657d7d7d";

    #[test]
    fn store_sealed_by_0_1_still_opens_and_reseals_identically() {
        let sealed = data_encoding::HEXLOWER
            .decode(SEALED_V0_1.as_bytes())
            .unwrap();
        let s = TrustStore::open(&sealed, &[7; 32]).unwrap();
        assert!(s.is_trusted("a1b2c3"));
        assert!(!s.is_trusted("d4e5f6"));
        assert_eq!(s.peers["a1b2c3"].name, "Living room TV");
        assert_eq!(s.seal(&[7; 32]), sealed);
        assert_eq!(s.seal_in(&Domain::DEFAULT, &[7; 32]), sealed);
    }

    #[test]
    fn domain_changes_the_mac() {
        const OTHER: Domain = Domain {
            trust_mac_context: "other trust-store v1",
            ..Domain::DEFAULT
        };
        let mut s = TrustStore::default();
        s.insert(peer("abc"));
        let sealed = s.seal_in(&OTHER, &[9; 32]);
        assert_ne!(sealed[..32], s.seal(&[9; 32])[..32]);
        assert_eq!(
            TrustStore::open_in(&OTHER, &sealed, &[9; 32]),
            Ok(s.clone())
        );
        assert_eq!(TrustStore::open(&sealed, &[9; 32]), Err(TrustError::BadMac));
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AppPeer {
        id: String,
        paired_with: String,
        last_addr: Option<serde_json::Value>,
        revoked: bool,
    }

    impl PeerRecord for AppPeer {
        fn id(&self) -> &str {
            &self.id
        }
        fn is_revoked(&self) -> bool {
            self.revoked
        }
        fn set_revoked(&mut self) {
            self.revoked = true;
        }
    }

    #[test]
    fn custom_peer_type_round_trips_and_rejects_tampering() {
        const APP: Domain = Domain {
            trust_mac_context: "dashy trust-store v1",
            ..Domain::DEFAULT
        };
        let mut s = TrustStore::<AppPeer>::new();
        s.insert(AppPeer {
            id: "xyz".into(),
            paired_with: "qr".into(),
            last_addr: Some(serde_json::json!({ "ip": "10.0.0.2" })),
            revoked: false,
        });
        let mut sealed = s.seal_in(&APP, &[5; 32]);
        let body = std::str::from_utf8(&sealed[32..]).unwrap();
        assert!(body.starts_with(r#"{"peers":{"xyz":{"id":"xyz","pairedWith":"qr""#));
        let back = TrustStore::<AppPeer>::open_in(&APP, &sealed, &[5; 32]).unwrap();
        assert_eq!(back, s);
        assert!(back.is_trusted("xyz"));
        let mut r = back.clone();
        assert!(r.revoke("xyz"));
        assert!(!r.is_trusted("xyz"));

        let last = sealed.len() - 3;
        sealed[last] ^= 1;
        assert_eq!(
            TrustStore::<AppPeer>::open_in(&APP, &sealed, &[5; 32]),
            Err(TrustError::BadMac)
        );
        sealed[last] ^= 1;
        assert_eq!(
            TrustStore::<AppPeer>::open_in(&APP, &sealed, &[6; 32]),
            Err(TrustError::BadMac)
        );
    }
}
