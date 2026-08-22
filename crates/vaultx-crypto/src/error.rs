//! Errors produced by cryptographic operations.
//!
//! Invariants:
//! - no variant ever carries secret material (plaintext, keys, or nonces
//!   bound to secrets);
//! - every [`std::fmt::Display`] string is static and safe to log.

use thiserror::Error;

/// Error type for all operations in [`crate`].
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Encryption failed for a non-authentication reason (for example an
    /// invalid key length handed to the AEAD).
    #[error("encryption failed")]
    EncryptionFailed,

    /// Decryption failed. This covers authentication-tag mismatches,
    /// wrong keys, wrong associated data, and malformed ciphertexts.
    #[error("decryption failed")]
    DecryptionFailed,

    /// Key material could not be generated.
    #[error("key generation failed")]
    KeyGenerationFailed,

    /// A signature did not verify against the message and public key.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// An unwrapping operation failed: wrong parent key, tampered wrapped
    /// blob, or purpose confusion between wrap contexts.
    #[error("key unwrap failed")]
    UnwrapFailed,

    /// The key provider backend failed. The payload is a provider-specific,
    /// secret-free description of the failure.
    #[error("key provider error: {0}")]
    ProviderError(String),
}

/// Convenience alias used throughout [`crate`].
pub type CryptoResult<T> = Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_strings_are_static_and_secret_free() {
        assert_eq!(
            CryptoError::EncryptionFailed.to_string(),
            "encryption failed"
        );
        assert_eq!(
            CryptoError::DecryptionFailed.to_string(),
            "decryption failed"
        );
        assert_eq!(
            CryptoError::KeyGenerationFailed.to_string(),
            "key generation failed"
        );
        assert_eq!(
            CryptoError::SignatureInvalid.to_string(),
            "signature verification failed"
        );
        assert_eq!(CryptoError::UnwrapFailed.to_string(), "key unwrap failed");
        assert_eq!(
            CryptoError::ProviderError("backend offline".to_string()).to_string(),
            "key provider error: backend offline"
        );
    }
}
