//! [`FileDeviceKeySource`]: a [`WrappingKeyProvider`] reading/writing
//! `.vaultx/device.key`.
//!
//! This is the exact file and hex-seed format `vaultx-core`'s history
//! service uses for commit signatures, so one device identity signs
//! commits and attests sync — regardless of whether the caller is the
//! CLI or the TUI.

use std::path::PathBuf;

use vaultx_crypto::envelope::RootKey;
use vaultx_crypto::error::CryptoError;
use vaultx_crypto::signature::SigningKeyPair;
use vaultx_keyring::WrappingKeyProvider;

use crate::files::write_private;

/// Device-key provider backed by `<vault-dir>/device.key`; creates and
/// persists the seed on first use, reloads it afterwards.
#[derive(Clone, Debug)]
pub struct FileDeviceKeySource(PathBuf);

impl FileDeviceKeySource {
    /// Binds the provider to a concrete key file path.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    fn parse_seed(text: &str) -> Result<RootKey, CryptoError> {
        let bytes = hex::decode(text.trim()).map_err(|err| {
            CryptoError::ProviderError(format!("device key is not valid hex ({err})"))
        })?;
        let seed: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
            CryptoError::ProviderError(format!("expected 32 seed bytes, found {}", bytes.len()))
        })?;
        Ok(RootKey::from_bytes(&seed))
    }
}

impl WrappingKeyProvider for FileDeviceKeySource {
    fn obtain(&self) -> Result<RootKey, CryptoError> {
        match std::fs::read_to_string(&self.0) {
            Ok(text) => Self::parse_seed(&text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let pair = SigningKeyPair::generate();
                let mut seed_hex = String::new();
                pair.expose_seed(|seed| seed_hex = hex::encode(seed));
                write_private(&self.0, &format!("{seed_hex}\n")).map_err(|err| {
                    CryptoError::ProviderError(format!("cannot persist device key: {err}"))
                })?;
                Self::parse_seed(&seed_hex)
            }
            Err(err) => Err(CryptoError::ProviderError(format!(
                "cannot read device key: {err}"
            ))),
        }
    }

    fn load(&self) -> Result<RootKey, CryptoError> {
        let text = std::fs::read_to_string(&self.0)
            .map_err(|err| CryptoError::ProviderError(format!("cannot read device key: {err}")))?;
        Self::parse_seed(&text)
    }
}
