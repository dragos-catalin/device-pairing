use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::code::short_code_from_token;
use crate::{PairError, sas_digits};

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
}

impl PairingWindow {
    /// Open a window with a fresh random token and the default TTL.
    pub fn open() -> Self {
        Self::with_ttl(PAIRING_TTL)
    }

    /// Open a window with a custom TTL (tests, or a longer TV flow).
    pub fn with_ttl(ttl: Duration) -> Self {
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
        }
    }

    /// The code to show on screen (and to put in a QR code).
    pub fn code(&self) -> String {
        short_code_from_token(&self.token)
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

    /// Start the one attempt: returns the code to feed into
    /// [`crate::CodeExchange`] and consumes the window, whatever happens next.
    ///
    /// # Errors
    /// [`PairError::Consumed`] on a second call, [`PairError::Expired`] after the TTL.
    pub fn begin_attempt(&mut self) -> Result<Zeroizing<String>, PairError> {
        if self.consumed {
            return Err(PairError::Consumed);
        }
        self.consumed = true;
        if self.is_expired() {
            return Err(PairError::Expired);
        }
        Ok(Zeroizing::new(self.code()))
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
        if self.consumed {
            return Err(PairError::Consumed);
        }
        self.consumed = true;
        if self.is_expired() {
            return Err(PairError::Expired);
        }
        let expected = sas_digits(&self.nonce, local_id, remote_id);
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
}
