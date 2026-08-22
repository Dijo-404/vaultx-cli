//! Cryptographic primitives for vaultx.
//!
//! This crate centralizes every cryptographic operation used by the vault:
//!
//! - [`aead`]: AES-256-GCM authenticated encryption with per-message
//!   random nonces and associated-data binding.
//! - [`envelope`]: the key hierarchy — a root wrapping key wraps project
//!   keys, which in turn wrap secret-revision DEKs and fingerprint keys
//!   (`root → project → dek/fingerprint`).
//! - [`fingerprint`]: HMAC-SHA256 keyed fingerprints (never a raw hash of a
//!   secret) with constant-time verification.
//! - [`signature`]: Ed25519 signing and verification.
//! - [`secret`]: secret-safe wrapper types ([`secret::SecretBytes`],
//!   [`secret::SecretString`]) that zeroize on drop, redact themselves from
//!   debug/display output, and only release plaintext through narrow
//!   closures.
//! - [`provider`]: the [`provider::KeyProvider`] abstraction over wrapping-
//!   key access, plus an in-memory implementation for tests and development.
//! - [`error`]: the shared [`error::CryptoError`] type; no variant ever
//!   carries secret material.
//!
//! No custom cryptographic primitives are implemented here: everything is
//! composition of audited crates (aes-gcm, ed25519-dalek, hmac/sha2,
//! subtle, rand_core/getrandom, zeroize).

pub mod aead;
pub mod envelope;
pub mod error;
pub mod fingerprint;
pub mod provider;
pub mod secret;
pub mod signature;
