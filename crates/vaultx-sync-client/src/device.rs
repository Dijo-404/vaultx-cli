//! Device identity: Ed25519 keys persisted through the secure-key storage
//! seam (plan §29).
//!
//! [`vaultx_keyring::WrappingKeyProvider`] already models "obtain or create
//! a 32-byte secret behind local secure-key storage", so the device seed
//! rides on it directly — production swaps in an OS-keychain provider,
//! tests inject [`vaultx_keyring::InMemoryKeyStore`]. The signing pair
//! itself is [`vaultx_crypto::signature::SigningKeyPair`]; nothing here
//! reimplements cryptography.
//!
//! Trust note: the server's copy of this public key is trusted-by-server
//! advisory pinning material. A compromised control plane can register and
//! serve its own key; device signatures give tamper-evidence, not defense
//! against a hostile control plane (see crate docs).

use std::sync::Arc;

use vaultx_control_plane::protocol::{device_attestation_message, DeviceIdentity};
use vaultx_crypto::error::CryptoResult;
use vaultx_crypto::signature::SigningKeyPair;
use vaultx_keyring::WrappingKeyProvider;
use vaultx_types::ProjectId;

/// Source of the device signing identity, backed by any wrapping-key
/// provider.
#[derive(Clone)]
pub struct DeviceKeySource {
    provider: Arc<dyn WrappingKeyProvider>,
}

impl std::fmt::Debug for DeviceKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DeviceKeySource(<provider>)")
    }
}

impl DeviceKeySource {
    /// Binds the source to `provider`.
    #[must_use]
    pub fn new(provider: Arc<dyn WrappingKeyProvider>) -> Self {
        Self { provider }
    }

    /// Loads the persisted device signing key, creating and persisting the
    /// seed on first use through the provider's write-tolerant read.
    ///
    /// # Errors
    /// Propagates [`vaultx_crypto::error::CryptoError`] from the provider.
    pub fn signing_key(&self) -> CryptoResult<SigningKeyPair> {
        let root = self.provider.obtain()?;
        root.expose(SigningKeyPair::from_seed)
    }

    /// Produces the signed device attestation for `project` required by
    /// the sync protocol's query-missing request (plan §28).
    ///
    /// # Errors
    /// Propagates key-loading failures from [`Self::signing_key`].
    pub fn attestation(&self, project: &ProjectId) -> CryptoResult<DeviceIdentity> {
        let key = self.signing_key()?;
        let public_key_hex = hex::encode(key.verifying_public_key().to_bytes());
        let message = device_attestation_message(project, &public_key_hex);
        let signature = key.sign(&message);
        Ok(DeviceIdentity {
            public_key_hex,
            signature_hex: hex::encode(signature.0),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use vaultx_control_plane::protocol::DeviceIdentity;
    use vaultx_crypto::signature::verify as verify_signature;
    use vaultx_crypto::signature::VerifyingPublicKey;
    use vaultx_keyring::{FileKeyStore, InMemoryKeyStore};

    use super::*;

    #[test]
    fn seed_persists_across_sources_through_the_provider() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("root.key");
        let first = DeviceKeySource::new(Arc::new(FileKeyStore::new(&path)));
        let project = ProjectId::parse("proj_device_test").expect("valid");
        let identity_a: DeviceIdentity = first.attestation(&project).expect("attest");

        // A brand-new source over the same backing store reconstructs the
        // same identity deterministically.
        let second = DeviceKeySource::new(Arc::new(FileKeyStore::new(&path)));
        let identity_b: DeviceIdentity = second.attestation(&project).expect("attest");
        assert_eq!(identity_a.public_key_hex, identity_b.public_key_hex);
        assert_eq!(identity_a.signature_hex, identity_b.signature_hex);

        // A different backing store yields a different device identity.
        let stranger = DeviceKeySource::new(Arc::new(InMemoryKeyStore::new()));
        let identity_c: DeviceIdentity = stranger.attestation(&project).expect("attest");
        assert_ne!(identity_a.public_key_hex, identity_c.public_key_hex);
    }

    #[test]
    fn attestation_verifies_against_the_registered_public_key() {
        let source = DeviceKeySource::new(Arc::new(InMemoryKeyStore::new()));
        let project = ProjectId::parse("proj_device_test").expect("valid");
        let identity: DeviceIdentity = source.attestation(&project).expect("attest");

        let key_bytes: [u8; 32] = hex::decode(&identity.public_key_hex)
            .expect("hex")
            .try_into()
            .expect("32 bytes");
        let public = VerifyingPublicKey::from_bytes(&key_bytes).expect("valid key");
        let message = device_attestation_message(&project, &identity.public_key_hex);
        let signature = vaultx_crypto::signature::SignatureBytes(
            hex::decode(&identity.signature_hex).expect("hex"),
        );
        verify_signature(&public, &message, &signature).expect("must verify");

        let other_project = ProjectId::parse("proj_other").expect("valid");
        let wrong_message = device_attestation_message(&other_project, &identity.public_key_hex);
        assert!(verify_signature(&public, &wrong_message, &signature).is_err());
    }
}
