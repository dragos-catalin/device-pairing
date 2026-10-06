use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use crate::code::normalise_code;
use crate::{Domain, PairError};

/// Length of the SPAKE2 message each side sends (1-byte side tag + point).
pub const PAKE_MSG_LEN: usize = 33;
/// Length of the key-confirmation tag each side sends.
pub const CONFIRM_LEN: usize = 32;

/// SPAKE2 over the short code, bound to both devices' identity keys.
///
/// Both sides call [`CodeExchange::start`], send [`CodeExchange::message`],
/// call [`CodeExchange::finish`] with the peer's message, send the returned
/// confirmation tag, and call [`Confirmed::verify_peer`] with the peer's tag.
///
/// The identity keys are the long-term public keys the transport already
/// authenticates (for iroh: the endpoint ids, proven by TLS). Binding them
/// into SPAKE2 means a man in the middle who relays between two honest
/// devices cannot complete the exchange even if he could see the code later.
pub struct CodeExchange {
    state: Spake2<Ed25519Group>,
    msg: Vec<u8>,
    local: [u8; 32],
    remote: [u8; 32],
    domain: Domain,
}

impl std::fmt::Debug for CodeExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeExchange").finish_non_exhaustive()
    }
}

fn sorted<'a>(a: &'a [u8; 32], b: &'a [u8; 32]) -> (&'a [u8; 32], &'a [u8; 32]) {
    if a <= b { (a, b) } else { (b, a) }
}

impl CodeExchange {
    /// Start the exchange with the code (as shown or as typed; it is
    /// normalised), under [`Domain::DEFAULT`].
    pub fn start(code: &str, local_id: &[u8; 32], remote_id: &[u8; 32]) -> Self {
        Self::start_in(&Domain::DEFAULT, code, local_id, remote_id)
    }

    /// [`CodeExchange::start`] under `domain`. Both sides must use the same domain.
    pub fn start_in(
        domain: &Domain,
        code: &str,
        local_id: &[u8; 32],
        remote_id: &[u8; 32],
    ) -> Self {
        let pw = Zeroizing::new(normalise_code(code));
        let (lo, hi) = sorted(local_id, remote_id);
        let mut ident = Vec::with_capacity(domain.pake_identity.len() + 64);
        ident.extend_from_slice(domain.pake_identity);
        ident.extend_from_slice(lo);
        ident.extend_from_slice(hi);
        let (state, msg) = Spake2::<Ed25519Group>::start_symmetric(
            &Password::new(pw.as_bytes()),
            &Identity::new(&ident),
        );
        Self {
            state,
            msg,
            local: *local_id,
            remote: *remote_id,
            domain: *domain,
        }
    }

    /// The message to send to the peer.
    pub fn message(&self) -> &[u8] {
        &self.msg
    }

    /// Consume the peer's message. Returns the confirmation state; send
    /// [`Confirmed::tag`] to the peer before trusting anything.
    ///
    /// # Errors
    /// [`PairError::Protocol`] when the peer message is malformed or a reflection of ours.
    pub fn finish(self, peer_msg: &[u8]) -> Result<Confirmed, PairError> {
        if peer_msg.len() != PAKE_MSG_LEN {
            return Err(PairError::Protocol(format!(
                "expected a {PAKE_MSG_LEN}-byte message"
            )));
        }
        if peer_msg == self.msg.as_slice() {
            return Err(PairError::Protocol("peer reflected our message".into()));
        }
        let key = Zeroizing::new(
            self.state
                .finish(peer_msg)
                .map_err(|e| PairError::Protocol(format!("{e:?}")))?,
        );
        let confirm_key = Zeroizing::new(blake3::derive_key(self.domain.confirm_context, &key));
        let session_key = Zeroizing::new(blake3::derive_key(self.domain.session_context, &key));
        Ok(Confirmed {
            confirm_key,
            session_key,
            local: self.local,
            remote: self.remote,
        })
    }
}

/// SPAKE2 finished; keys are not trusted until both tags verify.
pub struct Confirmed {
    confirm_key: Zeroizing<[u8; 32]>,
    session_key: Zeroizing<[u8; 32]>,
    local: [u8; 32],
    remote: [u8; 32],
}

impl std::fmt::Debug for Confirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Confirmed").finish_non_exhaustive()
    }
}

/// Direction-bound tag: `sender` proves it derived the key, for `receiver`.
/// Different inputs per direction, so a tag cannot be reflected back.
fn tag(key: &[u8; 32], sender: &[u8; 32], receiver: &[u8; 32]) -> [u8; CONFIRM_LEN] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(sender);
    h.update(receiver);
    *h.finalize().as_bytes()
}

impl Confirmed {
    /// Our key-confirmation tag, to send to the peer.
    pub fn tag(&self) -> [u8; CONFIRM_LEN] {
        tag(&self.confirm_key, &self.local, &self.remote)
    }

    /// Check the peer's tag. On success returns a 32-byte session key both
    /// sides share (e.g. to seal the first message, or as a pairing receipt).
    ///
    /// # Errors
    /// [`PairError::Mismatch`] when the codes differed or someone sat in the middle.
    pub fn verify_peer(self, peer_tag: &[u8]) -> Result<Zeroizing<[u8; 32]>, PairError> {
        let expected = tag(&self.confirm_key, &self.remote, &self.local);
        if crate::constant_time_eq(peer_tag, &expected) {
            Ok(self.session_key)
        } else {
            Err(PairError::Mismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(
        code_a: &str,
        code_b: &str,
        a: [u8; 32],
        b: [u8; 32],
    ) -> (Result<[u8; 32], PairError>, Result<[u8; 32], PairError>) {
        let xa = CodeExchange::start(code_a, &a, &b);
        let xb = CodeExchange::start(code_b, &b, &a);
        let (ma, mb) = (xa.message().to_vec(), xb.message().to_vec());
        let ca = xa.finish(&mb).unwrap();
        let cb = xb.finish(&ma).unwrap();
        let (ta, tb) = (ca.tag(), cb.tag());
        (
            ca.verify_peer(&tb).map(|k| *k),
            cb.verify_peer(&ta).map(|k| *k),
        )
    }

    #[test]
    fn same_code_agrees_on_a_session_key() {
        let (a, b) = run("ABCD-EFGH", "abcd efgh", [1; 32], [2; 32]);
        assert_eq!(a.clone().unwrap(), b.unwrap());
        assert_ne!(a.unwrap(), [0; 32]);
    }

    #[test]
    fn different_code_fails_on_both_sides() {
        let (a, b) = run("ABCDEFGH", "ABCDEFGJ", [1; 32], [2; 32]);
        assert_eq!(a, Err(PairError::Mismatch));
        assert_eq!(b, Err(PairError::Mismatch));
    }

    #[test]
    fn a_relay_with_swapped_identities_fails() {
        // Mallory relays A<->B but presents her own id M to each side.
        let (ida, idb, idm) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let xa = CodeExchange::start("ABCDEFGH", &ida, &idm); // A thinks it talks to M
        let xb = CodeExchange::start("ABCDEFGH", &idb, &idm); // B thinks it talks to M
        let (ma, mb) = (xa.message().to_vec(), xb.message().to_vec());
        let ca = xa.finish(&mb).unwrap();
        let cb = xb.finish(&ma).unwrap();
        assert_eq!(
            ca.verify_peer(&cb.tag()).map(|_| ()),
            Err(PairError::Mismatch)
        );
    }

    #[test]
    fn reflected_message_and_tag_are_refused() {
        let x = CodeExchange::start("ABCDEFGH", &[1; 32], &[2; 32]);
        let m = x.message().to_vec();
        assert!(matches!(x.finish(&m), Err(PairError::Protocol(_))));

        let xa = CodeExchange::start("ABCDEFGH", &[1; 32], &[2; 32]);
        let xb = CodeExchange::start("ABCDEFGH", &[2; 32], &[1; 32]);
        let mb = xb.message().to_vec();
        let ca = xa.finish(&mb).unwrap();
        let own = ca.tag();
        assert_eq!(ca.verify_peer(&own).map(|_| ()), Err(PairError::Mismatch));
    }

    #[test]
    fn malformed_message_is_a_protocol_error() {
        let x = CodeExchange::start("ABCDEFGH", &[1; 32], &[2; 32]);
        assert!(matches!(x.finish(&[0; 5]), Err(PairError::Protocol(_))));
    }

    #[test]
    fn domains_must_match_and_change_the_key() {
        const OTHER: Domain = Domain {
            pake_identity: b"other-app-v1",
            confirm_context: "other confirm",
            session_context: "other session",
            ..Domain::DEFAULT
        };
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let pair = |da: &Domain, db: &Domain| {
            let xa = CodeExchange::start_in(da, "ABCDEFGH", &a, &b);
            let xb = CodeExchange::start_in(db, "ABCDEFGH", &b, &a);
            let (ma, mb) = (xa.message().to_vec(), xb.message().to_vec());
            let ca = xa.finish(&mb).unwrap();
            let cb = xb.finish(&ma).unwrap();
            let (ta, tb) = (ca.tag(), cb.tag());
            (
                ca.verify_peer(&tb).map(|k| *k),
                cb.verify_peer(&ta).map(|k| *k),
            )
        };
        let (k1, k2) = pair(&OTHER, &OTHER);
        assert_eq!(k1.clone().unwrap(), k2.unwrap());
        let (d1, _) = pair(&Domain::DEFAULT, &Domain::DEFAULT);
        assert_ne!(k1.unwrap(), d1.unwrap());
        let (m1, m2) = pair(&OTHER, &Domain::DEFAULT);
        assert_eq!(m1, Err(PairError::Mismatch));
        assert_eq!(m2, Err(PairError::Mismatch));
    }
}
