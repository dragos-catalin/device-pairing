use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::code::{normalise_code, sas_digits_in, short_code_from_token_in};
use crate::{Domain, PairError};

/// How long a window stays open.
pub const PAIRING_TTL: Duration = Duration::from_secs(120);

/// One pairing attempt on the device that shows the code.
///
/// The window allows exactly one attempt. This is the control the whole
/// scheme rests on: SPAKE2 limits an attacker to one online guess per run,
/// and the window limits runs to one per code shown.
#[derive(Debug)]
pub struct PairingWindow {
    token: Zeroizing<[u8; 16]>,
    nonce: [u8; 16],
    opened: Instant,
    ttl: Duration,
    consumed: bool,
    domain: Domain,
}

impl PairingWindow {
    /// Open a window with a fresh random token and the default TTL.
    pub fn open() -> Self {
        Self::with_ttl_in(&Domain::DEFAULT, PAIRING_TTL)
    }

    /// Open a window with a custom TTL (tests, or a longer TV flow).
    pub fn with_ttl(ttl: Duration) -> Self {
        Self::with_ttl_in(&Domain::DEFAULT, ttl)
    }

    /// [`PairingWindow::open`] under `domain` (code and SAS derivation).
    pub fn open_in(domain: &Domain) -> Self {
        Self::with_ttl_in(domain, PAIRING_TTL)
    }

    /// [`PairingWindow::with_ttl`] under `domain`.
    pub fn with_ttl_in(domain: &Domain, ttl: Duration) -> Self {
        let mut token = [0u8; 16];
        let mut nonce = [0u8; 16];
        rand::fill(&mut token);
        rand::fill(&mut nonce);
        Self {
            token: Zeroizing::new(token),
            nonce,
            opened: Instant::now(),
            ttl,
            consumed: false,
            domain: *domain,
        }
    }

    /// The code to show on screen (and to put in a QR code).
    pub fn code(&self) -> String {
        short_code_from_token_in(&self.domain, &self.token)
    }

    /// The full 16-byte token as RFC 4648 base32 (upper-case, no padding),
    /// for a QR code. Whoever presents it gets the window's one attempt; see
    /// [`PairingWindow::verify_token`].
    pub fn token_string(&self) -> String {
        data_encoding::BASE32_NOPAD.encode(&*self.token)
    }

    /// Nonce for the SAS flow; send it to the peer.
    pub fn nonce(&self) -> &[u8; 16] {
        &self.nonce
    }

    /// Whether the TTL has passed.
    pub fn is_expired(&self) -> bool {
        self.opened.elapsed() > self.ttl
    }

    /// Whether an attempt already used this window.
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// Consume the window for one attempt, checking it was open.
    fn take_attempt(&mut self) -> Result<(), PairError> {
        if self.consumed {
            return Err(PairError::Consumed);
        }
        self.consumed = true;
        if self.is_expired() {
            return Err(PairError::Expired);
        }
        Ok(())
    }

    /// Start the one attempt: returns the code to feed into
    /// [`crate::CodeExchange`] and consumes the window, whatever happens next.
    ///
    /// # Errors
    /// [`PairError::Consumed`] on a second call, [`PairError::Expired`] after the TTL.
    pub fn begin_attempt(&mut self) -> Result<Zeroizing<String>, PairError> {
        self.take_attempt()?;
        Ok(Zeroizing::new(self.code()))
    }

    /// Verify a QR token (the [`PairingWindow::token_string`] the peer
    /// scanned). One attempt: right or wrong, the window is consumed.
    /// Surrounding whitespace and letter case are ignored.
    ///
    /// # Errors
    /// [`PairError::Mismatch`], [`PairError::Consumed`] or [`PairError::Expired`].
    pub fn verify_token(&mut self, presented: &str) -> Result<(), PairError> {
        self.take_attempt()?;
        let upper = Zeroizing::new(presented.trim().to_ascii_uppercase());
        let Ok(bytes) = data_encoding::BASE32_NOPAD.decode(upper.as_bytes()) else {
            return Err(PairError::Mismatch);
        };
        let bytes = Zeroizing::new(bytes);
        if crate::constant_time_eq(&bytes, &*self.token) {
            Ok(())
        } else {
            Err(PairError::Mismatch)
        }
    }

    /// Compare a typed code directly, for apps that admit a peer on the code
    /// alone (the transport already authenticates both ends). Prefer
    /// [`crate::CodeExchange`] when the peer is reached over an
    /// unauthenticated channel. One attempt; input is normalised with
    /// [`normalise_code`].
    ///
    /// # Errors
    /// [`PairError::Mismatch`], [`PairError::Consumed`] or [`PairError::Expired`].
    pub fn verify_code(&mut self, typed: &str) -> Result<(), PairError> {
        self.take_attempt()?;
        let typed = Zeroizing::new(normalise_code(typed));
        let expected = Zeroizing::new(self.code());
        if crate::constant_time_eq(typed.as_bytes(), expected.as_bytes()) {
            Ok(())
        } else {
            Err(PairError::Mismatch)
        }
    }

    /// Verify a SAS the user typed (flows without a shared code). One attempt.
    ///
    /// # Errors
    /// [`PairError::Mismatch`], [`PairError::Consumed`] or [`PairError::Expired`].
    pub fn verify_sas(
        &mut self,
        typed: &str,
        local_id: &[u8; 32],
        remote_id: &[u8; 32],
    ) -> Result<(), PairError> {
        self.take_attempt()?;
        let expected = sas_digits_in(&self.domain, &self.nonce, local_id, remote_id);
        if crate::constant_time_eq(typed.trim().as_bytes(), expected.as_bytes()) {
            Ok(())
        } else {
            Err(PairError::Mismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sas_digits;

    #[test]
    fn one_attempt_per_window() {
        let mut w = PairingWindow::open();
        let code = w.code();
        assert_eq!(w.begin_attempt().map(|c| c.to_string()), Ok(code));
        assert_eq!(
            w.begin_attempt().map(|c| c.to_string()),
            Err(PairError::Consumed)
        );
    }

    #[test]
    fn expired_window_refuses_and_is_consumed() {
        let mut w = PairingWindow::with_ttl(Duration::ZERO);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            w.begin_attempt().map(|c| c.to_string()),
            Err(PairError::Expired)
        );
        assert!(w.is_consumed());
    }

    #[test]
    fn wrong_sas_burns_the_window() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let mut w = PairingWindow::open();
        let real = sas_digits(w.nonce(), &a, &b);
        let wrong = if real == "000000" { "000001" } else { "000000" };
        assert_eq!(w.verify_sas(wrong, &a, &b), Err(PairError::Mismatch));
        assert_eq!(w.verify_sas(&real, &a, &b), Err(PairError::Consumed));

        let mut w2 = PairingWindow::open();
        let real2 = sas_digits(w2.nonce(), &a, &b);
        assert_eq!(w2.verify_sas(&real2, &b, &a), Ok(()));
    }

    #[test]
    fn token_is_one_shot_and_case_insensitive() {
        let mut w = PairingWindow::open();
        let t = w.token_string();
        assert_eq!(t.len(), 26);
        assert!(
            t.bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
        );
        assert_eq!(w.verify_token(&format!("  {}\n", t.to_lowercase())), Ok(()));
        assert_eq!(w.verify_token(&t), Err(PairError::Consumed));
    }

    #[test]
    fn wrong_or_garbage_token_burns_the_window() {
        let mut w = PairingWindow::open();
        let t = w.token_string();
        let mut wrong = t.clone().into_bytes();
        wrong[0] = if wrong[0] == b'A' { b'B' } else { b'A' };
        let wrong = String::from_utf8(wrong).unwrap();
        assert_eq!(w.verify_token(&wrong), Err(PairError::Mismatch));
        assert_eq!(w.verify_token(&t), Err(PairError::Consumed));

        let mut w2 = PairingWindow::open();
        assert_eq!(w2.verify_token("not base32 !"), Err(PairError::Mismatch));
        assert!(w2.is_consumed());
    }

    #[test]
    fn typed_code_is_one_shot_and_normalised() {
        let mut w = PairingWindow::open();
        let c = w.code();
        let typed = format!("{}-{}", &c[..4], &c[4..]).to_lowercase();
        assert_eq!(w.verify_code(&typed), Ok(()));
        assert_eq!(w.verify_code(&c), Err(PairError::Consumed));

        let mut w2 = PairingWindow::open();
        let c2 = w2.code();
        assert_eq!(
            w2.verify_code("22222222"),
            if c2 == "22222222" {
                Ok(())
            } else {
                Err(PairError::Mismatch)
            }
        );
        assert_eq!(w2.verify_code(&c2), Err(PairError::Consumed));
    }

    #[test]
    fn expired_window_refuses_token_and_code() {
        let mut w = PairingWindow::with_ttl(Duration::ZERO);
        std::thread::sleep(Duration::from_millis(5));
        let t = w.token_string();
        assert_eq!(w.verify_token(&t), Err(PairError::Expired));
        let mut w = PairingWindow::with_ttl(Duration::ZERO);
        std::thread::sleep(Duration::from_millis(5));
        let c = w.code();
        assert_eq!(w.verify_code(&c), Err(PairError::Expired));
    }

    #[test]
    fn window_domain_drives_code_and_sas() {
        const OTHER: Domain = Domain {
            code_context: "other code",
            sas_domain: b"other sas",
            ..Domain::DEFAULT
        };
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let mut w = PairingWindow::open_in(&OTHER);
        let token: [u8; 16] = data_encoding::BASE32_NOPAD
            .decode(w.token_string().as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(w.code(), short_code_from_token_in(&OTHER, &token));
        let sas = sas_digits_in(&OTHER, w.nonce(), &a, &b);
        assert_eq!(w.verify_sas(&sas, &a, &b), Ok(()));
    }
}
