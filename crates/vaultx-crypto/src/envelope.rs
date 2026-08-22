//! Envelope key-wrapping hierarchy.
//!
//! ```text
//! RootKey ──wraps──▶ ProjectKey ──wraps──▶ Dek (per secret revision)
//!                                  └──────▶ FingerprintKey
//! ```
//!
//! Wrapping is AES-256-GCM where the parent key encrypts the raw 32-byte
//! child key. Each wrap function hardcodes its own purpose-bound associated
//! data (e.g. `"vaultx:wrap:v1:project"`) so callers cannot mix purposes:
//! unwrapping a blob through the wrong function fails GCM authentication and
//! is rejected as [`CryptoError::UnwrapFailed`]. The cross-level confusion
//! cases are additionally rejected at compile time because [`RootKey`] and
//! [`ProjectKey`] are distinct types.

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::aead::{AeadKey, CiphertextBundle};
use crate::error::{CryptoError, CryptoResult};

/// Purpose-bound associated data for wrapping a project key under the root.
const PROJECT_WRAP_AAD: &[u8] = b"vaultx:wrap:v1:project";
/// Purpose-bound associated data for wrapping a DEK under a project key.
const DEK_WRAP_AAD: &[u8] = b"vaultx:wrap:v1:dek";
/// Purpose-bound associated data for wrapping a fingerprint key under a
/// project key.
const FINGERPRINT_WRAP_AAD: &[u8] = b"vaultx:wrap:v1:fingerprint";

/// Length in bytes of every key type wrapped by this module.
const KEY_LEN: usize = 32;

/// The root wrapping key of a workspace. In production this lives in native
/// secure credential storage; here it is an in-process zeroized buffer.
pub struct RootKey(Zeroizing<[u8; 32]>);

impl RootKey {
    /// Generates a fresh random root key from the OS RNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    /// Adopts caller-provided root key material (e.g. loaded from secure
    /// storage).
    ///
    /// # Warning
    /// The bytes are copied into a zeroizing buffer, but the caller-supplied
    /// source buffer itself is **not** scrubbed by this constructor; zeroize
    /// it separately if it held secret material.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*bytes))
    }

    /// Runs `f` with access to the raw root key bytes.
    pub fn expose<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        f(&self.0)
    }
}

impl std::fmt::Debug for RootKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RootKey(<redacted>)")
    }
}

/// Per-project content-encryption key. Reuses the AEAD key type since
/// project keys encrypt data with AES-256-GCM exactly like other AEAD keys.
pub type ProjectKey = AeadKey;

/// Data-encryption key for a single secret revision.
pub struct Dek(Zeroizing<[u8; 32]>);

impl Dek {
    /// Generates a fresh random DEK from the OS RNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(Zeroizing::new(bytes))
    }

    /// Adopts caller-provided DEK material.
    ///
    /// # Warning
    /// The bytes are copied into a zeroizing buffer, but the caller-supplied
    /// source buffer itself is **not** scrubbed by this constructor; zeroize
    /// it separately if it held secret material.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(Zeroizing::new(*bytes))
    }

    /// Runs `f` with access to the raw DEK bytes.
    pub fn expose<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        f(&self.0)
    }
}

impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Dek(<redacted>)")
    }
}

/// Key used to compute keyed fingerprints over secret values. Never used to
/// encrypt; see [`crate::fingerprint`].
pub struct FingerprintKey(Zeroizing<[u8; 32]>);

impl FingerprintKey {
    /// Generates a fresh random fingerprint key from the OS RNG.
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

    /// Runs `f` with access to the raw key bytes.
    pub fn expose<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        f(&self.0)
    }
}

impl std::fmt::Debug for FingerprintKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FingerprintKey(<redacted>)")
    }
}

/// A wrapped child key. Holds no purpose tag on purpose: each `unwrap_*`
/// function below applies its own hardcoded purpose AAD, so blobs cannot be
/// reinterpreted in another wrap context. Contains no plaintext, so deriving
/// serialization traits is safe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    /// Nonce used while wrapping.
    pub nonce: crate::aead::Nonce,
    /// Wrapped child-key ciphertext (32-byte key + 16-byte GCM tag).
    pub ciphertext: Vec<u8>,
}

/// Wraps a project key under the root key.
pub fn wrap_project_key(root: &RootKey, project_key: &ProjectKey) -> CryptoResult<WrappedKey> {
    root.expose(|root_bytes| {
        project_key.expose(|child| wrap_child(root_bytes, child, PROJECT_WRAP_AAD))
    })
}

/// Unwraps a project key previously wrapped by [`wrap_project_key`].
///
/// Any authentication failure — wrong root key, tampered blob, or a blob
/// produced by a different wrap purpose — yields [`CryptoError::UnwrapFailed`].
pub fn unwrap_project_key(root: &RootKey, wrapped: &WrappedKey) -> CryptoResult<ProjectKey> {
    root.expose(|root_bytes| {
        unwrap_child(
            root_bytes,
            wrapped,
            PROJECT_WRAP_AAD,
            ProjectKey::from_bytes,
        )
    })
}

/// Wraps a secret-revision DEK under a project key.
pub fn wrap_dek(project_key: &ProjectKey, dek: &Dek) -> CryptoResult<WrappedKey> {
    project_key.expose(|kek| dek.expose(|child| wrap_child(kek, child, DEK_WRAP_AAD)))
}

/// Unwraps a DEK previously wrapped by [`wrap_dek`].
pub fn unwrap_dek(project_key: &ProjectKey, wrapped: &WrappedKey) -> CryptoResult<Dek> {
    project_key.expose(|kek| unwrap_child(kek, wrapped, DEK_WRAP_AAD, Dek::from_bytes))
}

/// Wraps a fingerprint key under a project key.
pub fn wrap_fingerprint_key(
    project_key: &ProjectKey,
    fingerprint_key: &FingerprintKey,
) -> CryptoResult<WrappedKey> {
    project_key
        .expose(|kek| fingerprint_key.expose(|child| wrap_child(kek, child, FINGERPRINT_WRAP_AAD)))
}

/// Unwraps a fingerprint key previously wrapped by
/// [`wrap_fingerprint_key`].
pub fn unwrap_fingerprint_key(
    project_key: &ProjectKey,
    wrapped: &WrappedKey,
) -> CryptoResult<FingerprintKey> {
    project_key.expose(|kek| {
        unwrap_child(
            kek,
            wrapped,
            FINGERPRINT_WRAP_AAD,
            FingerprintKey::from_bytes,
        )
    })
}

fn wrap_child(
    kek: &[u8; 32],
    child: &[u8; 32],
    purpose_aad: &'static [u8],
) -> CryptoResult<WrappedKey> {
    let kek = AeadKey::from_bytes(kek);
    let bundle = crate::aead::encrypt(&kek, child, purpose_aad)?;
    Ok(WrappedKey {
        nonce: bundle.nonce,
        ciphertext: bundle.ciphertext,
    })
}

fn unwrap_child<R>(
    kek: &[u8; 32],
    wrapped: &WrappedKey,
    purpose_aad: &'static [u8],
    materialize: impl FnOnce(&[u8; 32]) -> R,
) -> CryptoResult<R> {
    let bundle = CiphertextBundle {
        nonce: wrapped.nonce,
        ciphertext: wrapped.ciphertext.clone(),
    };
    let kek = AeadKey::from_bytes(kek);
    let plaintext =
        crate::aead::decrypt(&kek, &bundle, purpose_aad).map_err(|_| CryptoError::UnwrapFailed)?;
    if plaintext.len() != KEY_LEN {
        return Err(CryptoError::UnwrapFailed);
    }
    // Borrow straight into the zeroized plaintext buffer and hand the slice
    // to `materialize`, which adopts the bytes into its own `Zeroizing`
    // storage: raw key bytes are never copied into an unscrubbed intermediate.
    let child: &[u8; 32] = plaintext
        .as_slice()
        .try_into()
        .expect("length checked above");
    Ok(materialize(child))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_key_wrap_unwrap_round_trip() {
        let root = RootKey::generate();
        let project_key = ProjectKey::generate();
        let wrapped = wrap_project_key(&root, &project_key).expect("wrap");
        assert_ne!(
            wrapped.ciphertext,
            project_key.expose(|b| b.to_vec()),
            "wrapped form must not equal raw key"
        );
        let restored = unwrap_project_key(&root, &wrapped).expect("unwrap");
        let same = restored.expose(|a| project_key.expose(|b| a == b));
        assert!(same);
    }

    #[test]
    fn dek_wrap_unwrap_round_trip() {
        let project_key = ProjectKey::generate();
        let dek = Dek::generate();
        let wrapped = wrap_dek(&project_key, &dek).expect("wrap");
        let restored = unwrap_dek(&project_key, &wrapped).expect("unwrap");
        let same = restored.expose(|a| dek.expose(|b| a == b));
        assert!(same);
    }

    #[test]
    fn fingerprint_key_wrap_unwrap_round_trip() {
        let project_key = ProjectKey::generate();
        let fpk = FingerprintKey::generate();
        let wrapped = wrap_fingerprint_key(&project_key, &fpk).expect("wrap");
        let restored = unwrap_fingerprint_key(&project_key, &wrapped).expect("unwrap");
        let same = restored.expose(|a| fpk.expose(|b| a == b));
        assert!(same);
    }

    #[test]
    fn unwrap_with_wrong_parent_key_fails() {
        // Wrong root for a wrapped project key.
        let root_a = RootKey::generate();
        let root_b = RootKey::generate();
        let wrapped = wrap_project_key(&root_a, &ProjectKey::generate()).expect("wrap");
        let err = unwrap_project_key(&root_b, &wrapped).expect_err("wrong root must fail");
        assert!(matches!(err, CryptoError::UnwrapFailed));

        // Wrong project key for a wrapped DEK.
        let wrapped_dek = wrap_dek(&ProjectKey::generate(), &Dek::generate()).expect("wrap");
        let err =
            unwrap_dek(&ProjectKey::generate(), &wrapped_dek).expect_err("wrong parent must fail");
        assert!(matches!(err, CryptoError::UnwrapFailed));

        // Wrong project key for a wrapped fingerprint key.
        let wrapped_fp = wrap_fingerprint_key(&ProjectKey::generate(), &FingerprintKey::generate())
            .expect("wrap");
        let err = unwrap_fingerprint_key(&ProjectKey::generate(), &wrapped_fp)
            .expect_err("wrong parent must fail");
        assert!(matches!(err, CryptoError::UnwrapFailed));
    }

    #[test]
    fn purpose_confusion_is_rejected() {
        // Same parent key, different wrap purposes must not be interchangeable:
        // a DEK blob unwrapped as a fingerprint key fails even though the KEK
        // matches.
        let project_key = ProjectKey::generate();
        let wrapped_dek = wrap_dek(&project_key, &Dek::generate()).expect("wrap dek");
        let err = unwrap_fingerprint_key(&project_key, &wrapped_dek)
            .expect_err("dek blob must not unwrap as fingerprint key");
        assert!(matches!(err, CryptoError::UnwrapFailed));

        let wrapped_fp =
            wrap_fingerprint_key(&project_key, &FingerprintKey::generate()).expect("wrap fpk");
        let err = unwrap_dek(&project_key, &wrapped_fp)
            .expect_err("fingerprint blob must not unwrap as dek");
        assert!(matches!(err, CryptoError::UnwrapFailed));
    }

    #[test]
    fn tampered_wrapped_blob_fails() {
        let root = RootKey::generate();
        let mut wrapped = wrap_project_key(&root, &ProjectKey::generate()).expect("wrap");
        let last = wrapped.ciphertext.len() - 1;
        wrapped.ciphertext[last] ^= 0xFF;
        let err = unwrap_project_key(&root, &wrapped).expect_err("tampered blob must fail");
        assert!(matches!(err, CryptoError::UnwrapFailed));
    }
}
