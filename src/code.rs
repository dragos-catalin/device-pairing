/// Characters in the typable code. No `I`, `L`, `O`, `U`, `0` or `1`: it is
/// read off one screen and typed into another by a human who confuses them.
pub const CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Length of the typable code (~39 bits). SPAKE2 makes an online guess the
/// only attack, and the window allows one guess, so length only has to
/// survive being typed.
pub const CODE_LEN: usize = 8;
/// Digits in a short authentication string.
pub const SAS_DIGITS: usize = 6;

const CODE_CONTEXT: &str = "device-pairing 2026 code v1";
const SAS_DOMAIN: &[u8] = b"device-pairing-sas-v1";

/// The human code derived from a window's random token.
pub fn short_code_from_token(token: &[u8; 16]) -> String {
    let key = blake3::derive_key(CODE_CONTEXT, token);
    blake3::hash(&key)
        .as_bytes()
        .iter()
        .take(CODE_LEN)
        .map(|b| CODE_ALPHABET[*b as usize % CODE_ALPHABET.len()] as char)
        .collect()
}

/// Upper-case and drop spaces, dashes and anything outside the alphabet's
/// character class, so `abcd-efgh` and `ABCD EFGH` are the same code.
pub fn normalise_code(input: &str) -> String {
    input
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// `SAS_DIGITS` decimal digits over a pairing transcript. The two ids are
/// sorted first, so both sides compute the same value whoever dialled.
pub fn sas_digits(nonce: &[u8; 16], id_a: &[u8; 32], id_b: &[u8; 32]) -> String {
    let (lo, hi) = if id_a <= id_b {
        (id_a, id_b)
    } else {
        (id_b, id_a)
    };
    let mut h = blake3::Hasher::new();
    h.update(SAS_DOMAIN);
    h.update(nonce);
    h.update(lo);
    h.update(hi);
    let out = h.finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&out.as_bytes()[..8]);
    let modulus = 10u64.pow(u32::try_from(SAS_DIGITS).unwrap_or(6));
    format!(
        "{:0width$}",
        u64::from_le_bytes(first) % modulus,
        width = SAS_DIGITS
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_is_symmetric_and_nonce_bound() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert_eq!(sas_digits(&[0; 16], &a, &b), sas_digits(&[0; 16], &b, &a));
        assert_ne!(sas_digits(&[0; 16], &a, &b), sas_digits(&[1; 16], &a, &b));
        assert_eq!(sas_digits(&[0; 16], &a, &b).len(), SAS_DIGITS);
    }

    #[test]
    fn code_uses_only_the_alphabet() {
        let c = short_code_from_token(&[7; 16]);
        assert_eq!(c.len(), CODE_LEN);
        assert!(c.bytes().all(|b| CODE_ALPHABET.contains(&b)));
        assert_eq!(normalise_code(&c.to_lowercase()), c);
        assert_eq!(normalise_code("ab-cd ef"), "ABCDEF");
    }
}
