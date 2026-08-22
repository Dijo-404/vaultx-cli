//! Ed25519 signing and verification.
//!
//! Thin, secret-safe wrappers over `ed25519_dalek` v2. With the crate's
//! `zeroize` feature enabled (see workspace dependencies), `SigningKey`
//! implements `ZeroizeOnDrop`, so the private half is scrubbed when the pair
//! drops; the pair type deliberately does **not** implement `Clone` so key
//! material never silently duplicates. Public keys are freely copyable and
//! serializable.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, CryptoResult};

/// An Ed25519 signature over an arbitrary message. Signatures are public
/// data, so deriving serialization traits is safe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBytes(pub Vec<u8>);

/// An Ed25519 keypair for signing.
///
/// The inner `ed25519_dalek::SigningKey` zeroizes itself on drop
/// (`zeroize` feature). The type is not `Clone`: keep exactly one owner per
/// identity.
pub struct SigningKeyPair(SigningKey);

impl SigningKeyPair {
    /// Generates a fresh random Ed25519 keypair from the OS RNG.
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    /// Signs `msg`, returning the detached signature.
    pub fn sign(&self, msg: &[u8]) -> SignatureBytes {
        SignatureBytes(self.0.sign(msg).to_bytes().to_vec())
    }

    /// Returns the matching public key.
    pub fn verifying_public_key(&self) -> VerifyingPublicKey {
        VerifyingPublicKey(self.0.verifying_key())
    }
}

impl std::fmt::Debug for SigningKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKeyPair(<redacted>)")
    }
}

/// An Ed25519 verification (public) key. Public data; safe to store,
/// clone, and serialize.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifyingPublicKey(VerifyingKey);

impl VerifyingPublicKey {
    /// Derives the public key belonging to a signing keypair.
    pub fn from_signing(pair: &SigningKeyPair) -> Self {
        pair.verifying_public_key()
    }

    /// Reconstructs a public key from its 32-byte compressed form.
    pub fn from_bytes(bytes: &[u8; 32]) -> CryptoResult<Self> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| CryptoError::SignatureInvalid)
    }

    /// 32-byte compressed form of this public key, suitable for storage or
    /// transmission.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

/// Verifies that `sig` is a valid signature of `msg` under `public`.
///
/// Returns [`CryptoError::SignatureInvalid`] if the signature bytes are
/// malformed or verification fails.
pub fn verify(public: &VerifyingPublicKey, msg: &[u8], sig: &SignatureBytes) -> CryptoResult<()> {
    let signature = Signature::from_slice(&sig.0).map_err(|_| CryptoError::SignatureInvalid)?;
    public
        .0
        .verify(msg, &signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let pair = SigningKeyPair::generate();
        let public = VerifyingPublicKey::from_signing(&pair);
        let msg = b"manifest content";
        let sig = pair.sign(msg);
        verify(&public, msg, &sig).expect("valid signature must verify");
    }

    #[test]
    fn tampered_message_fails() {
        let pair = SigningKeyPair::generate();
        let public = VerifyingPublicKey::from_signing(&pair);
        let sig = pair.sign(b"original message");
        let err = verify(&public, b"tampered message", &sig)
            .expect_err("modified message must not verify");
        assert!(matches!(err, CryptoError::SignatureInvalid));
    }

    #[test]
    fn wrong_key_fails() {
        let signer = SigningKeyPair::generate();
        let other = SigningKeyPair::generate();
        let public = VerifyingPublicKey::from_signing(&other);
        let sig = signer.sign(b"signed by someone else");
        let err = verify(&public, b"signed by someone else", &sig)
            .expect_err("wrong public key must not verify");
        assert!(matches!(err, CryptoError::SignatureInvalid));
    }

    #[test]
    fn malformed_signature_bytes_fail() {
        let pair = SigningKeyPair::generate();
        let public = VerifyingPublicKey::from_signing(&pair);
        let err = verify(&public, b"msg", &SignatureBytes(vec![0u8; 10]))
            .expect_err("short signature must be rejected");
        assert!(matches!(err, CryptoError::SignatureInvalid));
    }

    #[test]
    fn debug_of_signing_key_pair_is_redacted() {
        let rendered = format!("{:?}", SigningKeyPair::generate());
        assert_eq!(rendered, "SigningKeyPair(<redacted>)");
    }

    #[test]
    fn public_key_bytes_round_trip() {
        let pair = SigningKeyPair::generate();
        let original = VerifyingPublicKey::from_signing(&pair);
        let restored = VerifyingPublicKey::from_bytes(&original.to_bytes()).expect("rebuild");
        assert_eq!(restored, original);
    }

    #[test]
    fn signature_bytes_serialize() {
        let pair = SigningKeyPair::generate();
        let sig = pair.sign(b"serializable");
        let json = serde_json::to_string(&sig).expect("serialize");
        let parsed: SignatureBytes = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, sig);
        verify(
            &VerifyingPublicKey::from_signing(&pair),
            b"serializable",
            &parsed,
        )
        .expect("deserialized signature must still verify");
    }
}
