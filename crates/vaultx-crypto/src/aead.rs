//! AES-256-GCM authenticated encryption.
//!
//! Nonce strategy: every call to [`encrypt`] draws a **fresh random 96-bit
//! nonce** from the OS RNG. With random nonces the NIST SP 800-38D collision
//! bound applies **per key**: a given key must stay far below ~2^32
//! encryptions. Vaultx respects this because secret-revision DEKs are
//! effectively single-use — each revision gets its own DEK wrapped under the
//! project key, so DEK message counts are tiny. A `ProjectKey` accumulates
//! wraps over the project lifetime, but realistic volumes remain many orders
//! of magnitude below the bound.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesGcmNonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CryptoError, CryptoResult};

/// A 32-byte AES-256 key held inside a zeroizing buffer.
pub struct AeadKey(Zeroizing<[u8; 32]>);

impl AeadKey {
    /// Generates a fresh random key from the OS RNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    /// Adopts caller-provided key material.
    ///
    /// # Warning
    /// The bytes are copied into a zeroizing buffer, but the caller-supplied
    /// source buffer itself is **not** scrubbed by this constructor; zeroize
    /// it separately if it held secret material.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*bytes))
    }

    /// Runs `f` with access to the raw key bytes. This is the only way to
    /// read them.
    pub fn expose<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        f(&self.0)
    }
}

impl std::fmt::Debug for AeadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AeadKey(<redacted>)")
    }
}

/// A 96-bit AES-GCM nonce. Nonces are public data and safe to store or
/// serialize alongside ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nonce([u8; 12]);

impl Nonce {
    /// Generates a fresh random nonce from the OS RNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 12];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Adopts caller-provided nonce bytes.
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Raw nonce bytes, suitable for persisting next to ciphertext.
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// Authenticated ciphertext plus the nonce used to produce it. Contains no
/// plaintext, so deriving `Serialize`/`Deserialize` is safe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextBundle {
    /// Nonce used for this ciphertext; must be supplied unchanged to
    /// [`decrypt`].
    pub nonce: Nonce,
    /// Ciphertext with the 16-byte GCM authentication tag appended.
    pub ciphertext: Vec<u8>,
}

/// Encrypts `plaintext` under `key`, binding `aad` as associated data.
///
/// A fresh random nonce is drawn per call (see module docs for the safety
/// argument). The returned bundle must be persisted atomically: losing the
/// nonce makes decryption impossible.
pub fn encrypt(key: &AeadKey, plaintext: &[u8], aad: &[u8]) -> CryptoResult<CiphertextBundle> {
    let cipher = build_cipher(key)?;
    let nonce = Nonce::generate();
    let gcm_nonce = AesGcmNonce::from_slice(nonce.as_bytes());
    let ciphertext = cipher
        .encrypt(
            gcm_nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(CiphertextBundle { nonce, ciphertext })
}

/// Decrypts `bundle` under `key`, verifying it against `aad`.
///
/// Returns [`CryptoError::DecryptionFailed`] if the key, nonce, ciphertext,
/// or associated data does not match what was used at encryption time.
///
/// The recovered plaintext is wrapped in [`Zeroizing`] so it is scrubbed on
/// drop; keep it inside this regime (or convert it into a
/// [`crate::secret::SecretBytes`]) rather than unwrapping to a bare buffer.
pub fn decrypt(
    key: &AeadKey,
    bundle: &CiphertextBundle,
    aad: &[u8],
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    let cipher = build_cipher(key)?;
    let gcm_nonce = AesGcmNonce::from_slice(bundle.nonce.as_bytes());
    cipher
        .decrypt(
            gcm_nonce,
            Payload {
                msg: &bundle.ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::DecryptionFailed)
}

fn build_cipher(key: &AeadKey) -> CryptoResult<Aes256Gcm> {
    key.expose(|bytes| Aes256Gcm::new_from_slice(&bytes[..]))
        .map_err(|_| CryptoError::EncryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = AeadKey::generate();
        let plaintext = b"attack at dawn";
        let aad = b"vaultx:test:v1";
        let bundle = encrypt(&key, plaintext, aad).expect("encrypt");
        assert_ne!(bundle.ciphertext, plaintext.to_vec());
        let recovered = decrypt(&key, &bundle, aad).expect("decrypt");
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = AeadKey::generate();
        let aad = b"aad";
        let mut bundle = encrypt(&key, b"secret payload", aad).expect("encrypt");
        let last = bundle.ciphertext.len() - 1;
        bundle.ciphertext[last] ^= 0x01;
        let err = decrypt(&key, &bundle, aad).expect_err("tampered ciphertext must fail");
        assert!(matches!(err, CryptoError::DecryptionFailed));
    }

    #[test]
    fn wrong_aad_fails() {
        let key = AeadKey::generate();
        let bundle = encrypt(&key, b"secret payload", b"binding:a").expect("encrypt");
        let err = decrypt(&key, &bundle, b"binding:b").expect_err("wrong aad must fail");
        assert!(matches!(err, CryptoError::DecryptionFailed));
    }

    #[test]
    fn wrong_key_fails() {
        let bundle = encrypt(&AeadKey::generate(), b"secret payload", b"aad").expect("encrypt");
        let err =
            decrypt(&AeadKey::generate(), &bundle, b"aad").expect_err("different key must fail");
        assert!(matches!(err, CryptoError::DecryptionFailed));
    }

    #[test]
    fn same_plaintext_produces_distinct_nonces_and_ciphertexts() {
        let key = AeadKey::generate();
        let first = encrypt(&key, b"identical", b"aad").expect("encrypt 1");
        let second = encrypt(&key, b"identical", b"aad").expect("encrypt 2");
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let key = AeadKey::generate();
        let aad = b"aad";
        let bundle = encrypt(&key, b"", aad).expect("encrypt empty");
        // GCM still appends a 16-byte tag even for empty plaintext.
        assert_eq!(bundle.ciphertext.len(), 16);
        let recovered = decrypt(&key, &bundle, aad).expect("decrypt empty");
        assert!(recovered.is_empty());
    }

    #[test]
    fn ciphertext_bundle_serializes_without_plaintext_leakage_concerns() {
        let key = AeadKey::generate();
        let bundle = encrypt(&key, b"round trip", b"aad").expect("encrypt");
        let json = serde_json::to_string(&bundle).expect("serialize");
        let parsed: CiphertextBundle = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, bundle);
        let recovered = decrypt(&key, &parsed, b"aad").expect("decrypt after round-trip");
        assert_eq!(recovered.as_slice(), b"round trip".as_slice());
    }
}
