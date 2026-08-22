//! Ed25519 signing and verification.
//!
//! Thin, secret-safe wrappers over `ed25519_dalek` v2. With the crate's
//! `zeroize` feature enabled (see workspace dependencies), `SigningKey`
//! implements `ZeroizeOnDrop`, so the private half is scrubbed when the pair
//! drops; the pair type deliberately does **not** implement `Clone` so key
//! material never silently duplicates. Public keys are freely copyable and
//! serializable.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
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

    /// Reconstructs a keypair deterministically from its 32-byte seed.
    ///
    /// Any 32 bytes form a valid Ed25519 seed, so construction cannot
    /// fail today; the [`Result`] keeps the signature stable should key
    /// derivation ever gain validation requirements. Same seed in, same
    /// verifying key and signatures out — this is what makes persisted
    /// signing identities possible without widening seed access.
    pub fn from_seed(seed: &[u8; 32]) -> CryptoResult<Self> {
        Ok(Self(SigningKey::from_bytes(seed)))
    }

    /// Signs `msg`, returning the detached signature.
    pub fn sign(&self, msg: &[u8]) -> SignatureBytes {
        SignatureBytes(self.0.sign(msg).to_bytes().to_vec())
    }

    /// Returns the matching public key.
    pub fn verifying_public_key(&self) -> VerifyingPublicKey {
        VerifyingPublicKey(self.0.verifying_key())
    }

    /// Releases the 32-byte signing seed to `f` and returns its result,
    /// mirroring the crate's closure-only exposure pattern
    /// ([`crate::secret::SecretBytes::expose`]). The seed never appears
    /// in logs, debug output, or serialization; callers holding the bytes
    /// own their protection.
    pub fn expose_seed<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        f(&self.0.to_bytes())
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
/// Uses Ed25519ph-style **strict verification** (`verify_strict`), which in
/// addition to the standard equation check rejects non-canonical signatures
/// with small-order or non-canonical `R`/`S` components, preventing
/// signature malleability.
///
/// Returns [`CryptoError::SignatureInvalid`] if the signature bytes are
/// malformed or verification fails.
pub fn verify(public: &VerifyingPublicKey, msg: &[u8], sig: &SignatureBytes) -> CryptoResult<()> {
    let signature = Signature::from_slice(&sig.0).map_err(|_| CryptoError::SignatureInvalid)?;
    public
        .0
        .verify_strict(msg, &signature)
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
    fn from_seed_is_deterministic_across_instances() {
        let seed = [7u8; 32];
        let first = SigningKeyPair::from_seed(&seed).expect("seed is always valid");
        let second = SigningKeyPair::from_seed(&seed).expect("seed is always valid");

        assert_eq!(
            first.verifying_public_key(),
            second.verifying_public_key(),
            "same seed must reconstruct the same verifying key"
        );
        let msg = b"deterministic message";
        assert_eq!(
            first.sign(msg),
            second.sign(msg),
            "same seed must produce identical signatures"
        );

        // A different seed yields a different identity.
        let other = SigningKeyPair::from_seed(&[8u8; 32]).unwrap();
        assert_ne!(first.verifying_public_key(), other.verifying_public_key());
    }

    #[test]
    fn expose_seed_round_trips_through_from_seed() {
        let original = SigningKeyPair::generate();
        let mut captured: Option<[u8; 32]> = None;
        original.expose_seed(|seed| captured = Some(*seed));
        let seed = captured.expect("closure receives the seed");

        let restored = SigningKeyPair::from_seed(&seed).expect("round trip");
        assert_eq!(
            original.verifying_public_key(),
            restored.verifying_public_key()
        );
        let msg = b"round-trip message";
        assert_eq!(original.sign(msg), restored.sign(msg));

        // The closure-only pattern still supports scoped use and
        // transformation without leaking the seed through Debug.
        let len = original.expose_seed(|seed| seed.len());
        assert_eq!(len, 32);
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
