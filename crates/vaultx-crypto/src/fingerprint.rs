//! Keyed fingerprints over secret values.
//!
//! Fingerprints are `HMAC-SHA256(fingerprint_key, secret)` rendered as
//! lowercase hex. A keyed construction is mandatory here: a raw
//! `SHA-256(secret)` would be vulnerable to rainbow-table attacks against
//! low-entropy secrets, while the HMAC output is indistinguishable from
//! random without the per-project fingerprint key.
//!
//! Verification uses [`subtle::ConstantTimeEq`] so the comparison does not
//! leak information through timing.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::envelope::FingerprintKey;

type HmacSha256 = Hmac<Sha256>;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Computes the lowercase-hex HMAC-SHA256 fingerprint of `secret` under
/// `key`.
///
/// The same key and secret always yield the same fingerprint, which is what
/// makes fingerprints usable for duplicate detection without storing or
/// exposing the secret itself.
pub fn keyed_fingerprint(key: &FingerprintKey, secret: &[u8]) -> String {
    key.expose(|key_bytes| to_hex(&hmac_sha256(key_bytes, secret)))
}

/// Verifies that `expected` (lowercase hex) matches the fingerprint of
/// `secret` under `key`, using constant-time comparison.
pub fn verify_fingerprint(key: &FingerprintKey, secret: &[u8], expected: &str) -> bool {
    let computed = key.expose(|key_bytes| to_hex(&hmac_sha256(key_bytes, secret)));
    let computed = computed.into_bytes();
    let expected = expected.as_bytes();
    if computed.len() != expected.len() {
        return false;
    }
    bool::from(computed.ct_eq(expected))
}

fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any nonzero length");
    mac.update(data);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

fn to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        hex.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_key_and_secret() {
        let key = FingerprintKey::generate();
        assert_eq!(
            keyed_fingerprint(&key, b"same secret"),
            keyed_fingerprint(&key, b"same secret")
        );
    }

    #[test]
    fn differs_across_keys() {
        let fp_a = keyed_fingerprint(&FingerprintKey::generate(), b"shared value");
        let fp_b = keyed_fingerprint(&FingerprintKey::generate(), b"shared value");
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn differs_across_secrets() {
        let key = FingerprintKey::generate();
        assert_ne!(
            keyed_fingerprint(&key, b"secret one"),
            keyed_fingerprint(&key, b"secret two")
        );
    }

    #[test]
    fn verify_true_for_matching_fingerprint() {
        let key = FingerprintKey::generate();
        let secret = b"duplicate-detection-input";
        let fp = keyed_fingerprint(&key, secret);
        assert!(verify_fingerprint(&key, secret, &fp));
    }

    #[test]
    fn verify_false_for_wrong_secret() {
        let key = FingerprintKey::generate();
        let fp = keyed_fingerprint(&key, b"real secret");
        assert!(!verify_fingerprint(&key, b"other secret", &fp));
    }

    #[test]
    fn verify_false_for_wrong_key() {
        let secret = b"stable input";
        let fp = keyed_fingerprint(&FingerprintKey::generate(), secret);
        assert!(!verify_fingerprint(
            &FingerprintKey::generate(),
            secret,
            &fp
        ));
    }

    #[test]
    fn verify_is_length_safe() {
        let key = FingerprintKey::generate();
        let fp = keyed_fingerprint(&key, b"x");
        assert!(!verify_fingerprint(&key, b"x", ""));
        assert!(!verify_fingerprint(&key, b"x", &fp[..63]));
        assert!(!verify_fingerprint(&key, b"x", &format!("{fp}0")));
    }

    #[test]
    fn fingerprint_shape_is_lowercase_hex_sha256_len() {
        let fp = keyed_fingerprint(&FingerprintKey::generate(), b"shape check");
        assert_eq!(fp.len(), 64);
        assert!(fp
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }
}
