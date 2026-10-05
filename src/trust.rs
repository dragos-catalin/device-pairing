use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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

/// The list of peers allowed to connect.
///
/// It needs integrity, not secrecy: the attack is a silently inserted key.
/// Sealed as `MAC(32) || JSON` with a BLAKE3 keyed hash under a key derived
/// from the local identity secret. A bad MAC refuses to load rather than
/// falling back to an empty list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustStore {
    /// Peers by id.
    pub peers: BTreeMap<String, TrustedPeer>,
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

const MAC_CONTEXT: &str = "device-pairing 2026 trust-store v1";

fn mac(secret: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let key = blake3::derive_key(MAC_CONTEXT, secret);
    *blake3::keyed_hash(&key, body).as_bytes()
}

impl TrustStore {
    /// True when `id` is paired and not revoked.
    pub fn is_trusted(&self, id: &str) -> bool {
        self.peers.get(id).is_some_and(|p| !p.revoked)
    }

    /// Add or replace a peer.
    pub fn insert(&mut self, peer: TrustedPeer) {
        self.peers.insert(peer.id.clone(), peer);
    }

    /// Mark a peer revoked. Returns false when it was unknown.
    pub fn revoke(&mut self, id: &str) -> bool {
        self.peers.get_mut(id).is_some_and(|p| {
            p.revoked = true;
            true
        })
    }

    /// Serialise with an integrity tag keyed by the local identity secret.
    pub fn seal(&self, secret: &[u8; 32]) -> Vec<u8> {
        let body = serde_json::to_vec(self).unwrap_or_default();
        let mut out = Vec::with_capacity(32 + body.len());
        out.extend_from_slice(&mac(secret, &body));
        out.extend_from_slice(&body);
        out
    }

    /// Verify and parse a sealed store.
    ///
    /// # Errors
    /// [`TrustError::BadMac`] or [`TrustError::Malformed`].
    pub fn open(sealed: &[u8], secret: &[u8; 32]) -> Result<Self, TrustError> {
        if sealed.len() < 32 {
            return Err(TrustError::Malformed);
        }
        let (tag, body) = sealed.split_at(32);
        if !crate::constant_time_eq(tag, &mac(secret, body)) {
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
}
