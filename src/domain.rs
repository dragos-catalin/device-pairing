/// Every domain-separation string the crate feeds into BLAKE3 or SPAKE2.
///
/// [`Domain::DEFAULT`] is what the crate uses when you call the functions
/// without an `_in` suffix; those calls are byte-identical to 0.1.
///
/// An app that already ran its own pairing scheme before adopting this crate
/// sets its old contexts here, so the codes it shows, the SAS digits it
/// compares and the trust stores it sealed stay valid after the switch:
///
/// ```
/// use device_pairing::{Domain, PairingWindow};
///
/// // dashy's pre-crate scheme: same derivations, different strings.
/// const DASHY: Domain = Domain {
///     code_context: "dashy-pairing-code-v1",
///     sas_domain: b"dashy-sas-v1",
///     trust_mac_context: "dashy trust-store v1",
///     ..Domain::DEFAULT
/// };
///
/// let window = PairingWindow::open_in(&DASHY);
/// assert_eq!(window.code().len(), device_pairing::CODE_LEN);
/// ```
///
/// Choose unique strings for a new app. Two apps sharing a context share
/// codes, SAS digits and trust-store keys for the same inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Domain {
    /// BLAKE3 `derive_key` context turning a window token into the short code.
    pub code_context: &'static str,
    /// Prefix hashed before the SAS transcript.
    pub sas_domain: &'static [u8],
    /// BLAKE3 `derive_key` context for the trust-store MAC key.
    pub trust_mac_context: &'static str,
    /// Prefix of the SPAKE2 identity (followed by both sorted identity keys).
    pub pake_identity: &'static [u8],
    /// BLAKE3 `derive_key` context for the key-confirmation key.
    pub confirm_context: &'static str,
    /// BLAKE3 `derive_key` context for the session key.
    pub session_context: &'static str,
}

impl Domain {
    /// The crate's own contexts (identical to 0.1).
    pub const DEFAULT: Self = Self {
        code_context: "device-pairing 2026 code v1",
        sas_domain: b"device-pairing-sas-v1",
        trust_mac_context: "device-pairing 2026 trust-store v1",
        pake_identity: b"device-pairing-v1",
        confirm_context: "device-pairing 2026 confirm v1",
        session_context: "device-pairing 2026 session v1",
    };
}

impl Default for Domain {
    fn default() -> Self {
        Self::DEFAULT
    }
}
