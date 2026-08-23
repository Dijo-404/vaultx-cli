//! Credential resolution seam (plan §18 "vault access").
//!
//! The engine asks a [`CredentialSource`] for three things about one
//! logical reference: its plaintext material ([`SecretBytes`]), which
//! injection template it uses, and its non-secret placement metadata.
//! Plaintext exists **only** inside the resolution result and the
//! subsequent injection scope — never in engine state, logs, errors, or
//! responses (INV-002/003/018).
//!
//! [`InMemoryCredentialSource`] stands in for the encrypted vault until
//! the repository integration task lands; production sources will
//! decrypt inside this boundary.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use vaultx_crypto::secret::SecretBytes;
use vaultx_types::{CredentialRef, EnvironmentId};

use crate::error::BrokerError;
use crate::inject::{CredentialMetadata, InjectionTemplateId};

/// Resolution seam for brokered credentials.
pub trait CredentialSource: Send + Sync {
    /// Resolves the plaintext material of `credential` for use within
    /// `environment`. The returned handle zeroizes on drop and redacts
    /// itself from debug output; callers may only observe plaintext via
    /// narrow closures.
    ///
    /// # Errors
    /// Returns [`BrokerError::UnknownCredential`] for unknown logical
    /// references (carrying the logical id only).
    fn resolve(
        &self,
        credential: &CredentialRef,
        environment: &EnvironmentId,
    ) -> Result<SecretBytes, BrokerError>;

    /// Returns the injection template bound to `credential`.
    ///
    /// # Errors
    /// Same as [`CredentialSource::resolve`].
    fn template_for(&self, credential: &CredentialRef) -> Result<InjectionTemplateId, BrokerError>;

    /// Environment-scoped template lookup. Sources that scope bindings
    /// per environment must override this; the default ignores the
    /// environment for backward compatibility with flat sources.
    ///
    /// # Errors
    /// Same as [`CredentialSource::resolve`].
    fn template_for_in_env(
        &self,
        credential: &CredentialRef,
        _environment: &EnvironmentId,
    ) -> Result<InjectionTemplateId, BrokerError> {
        self.template_for(credential)
    }

    /// Returns the non-secret placement metadata of `credential`.
    /// Defaults to empty metadata for sources that store none.
    ///
    /// # Errors
    /// Same as [`CredentialSource::resolve`].
    fn metadata_for(&self, _credential: &CredentialRef) -> Result<CredentialMetadata, BrokerError> {
        Ok(CredentialMetadata::default())
    }
}

#[derive(Debug)]
struct StoredEntry {
    secret: SecretBytes,
    template: InjectionTemplateId,
    metadata: CredentialMetadata,
}

/// Thread-safe in-memory [`CredentialSource`] for tests and development.
///
/// Plaintext lives here only because this type *is* the vault stand-in:
/// entries are inserted explicitly by tests/bootstrap code, and reads
/// hand out fresh zeroizing copies rather than aliases.
#[derive(Debug, Default)]
pub struct InMemoryCredentialSource {
    entries: Mutex<HashMap<CredentialRef, StoredEntry>>,
}

impl InMemoryCredentialSource {
    /// Creates an empty source.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or replaces a credential entry.
    pub fn insert(
        &self,
        credential: CredentialRef,
        secret: SecretBytes,
        template: InjectionTemplateId,
        metadata: CredentialMetadata,
    ) {
        let mut entries = self.lock();
        entries.insert(
            credential,
            StoredEntry {
                secret,
                template,
                metadata,
            },
        );
    }

    /// True when the logical reference exists.
    #[must_use]
    pub fn contains(&self, credential: &CredentialRef) -> bool {
        self.lock().contains_key(credential)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<CredentialRef, StoredEntry>> {
        // Plain map state carries no recoverable invariant; unwrap poisons
        // like the rest of the workspace.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn unknown(credential: &CredentialRef) -> BrokerError {
    BrokerError::UnknownCredential(credential.to_string())
}

impl CredentialSource for InMemoryCredentialSource {
    fn resolve(
        &self,
        credential: &CredentialRef,
        _environment: &EnvironmentId,
    ) -> Result<SecretBytes, BrokerError> {
        let entries = self.lock();
        let entry = entries.get(credential).ok_or_else(|| unknown(credential))?;
        // Fresh copy out of the store: the resolved value zeroes when the
        // caller drops it, independent of storage lifetime.
        Ok(entry.secret.expose(SecretBytes::from_bytes))
    }

    fn template_for(&self, credential: &CredentialRef) -> Result<InjectionTemplateId, BrokerError> {
        let entries = self.lock();
        let entry = entries.get(credential).ok_or_else(|| unknown(credential))?;
        Ok(entry.template)
    }

    fn metadata_for(&self, credential: &CredentialRef) -> Result<CredentialMetadata, BrokerError> {
        let entries = self.lock();
        let entry = entries.get(credential).ok_or_else(|| unknown(credential))?;
        Ok(entry.metadata.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY_SECRET: &str = "CANARY_RESOLVED_SECRET_9f8";

    fn source() -> InMemoryCredentialSource {
        let source = InMemoryCredentialSource::new();
        let metadata = CredentialMetadata {
            username: Some("svc-bot".to_owned()),
            ..CredentialMetadata::default()
        };
        source.insert(
            CredentialRef::parse("github-work-token").unwrap(),
            SecretBytes::from_bytes(CANARY_SECRET.as_bytes()),
            InjectionTemplateId::GithubBearer,
            metadata,
        );
        source
    }

    fn environment() -> EnvironmentId {
        EnvironmentId::parse("env_development").unwrap()
    }

    #[test]
    fn resolve_returns_matching_material() {
        let source = source();
        let credential = CredentialRef::parse("github-work-token").unwrap();
        let secret = source.resolve(&credential, &environment()).unwrap();
        assert_eq!(
            secret.expose(|bytes| bytes.to_vec()),
            CANARY_SECRET.as_bytes()
        );
    }

    #[test]
    fn resolve_unknown_credential_fails_with_logical_id_only() {
        let source = source();
        let ghost = CredentialRef::parse("ghost-token").unwrap();
        let err = source.resolve(&ghost, &environment()).unwrap_err();
        assert!(
            matches!(&err, BrokerError::UnknownCredential(id) if id == "ghost-token"),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            "unknown credential reference `ghost-token`"
        );
        assert!(!err.to_string().contains(CANARY_SECRET));
    }

    #[test]
    fn template_lookup_matches_inserted_entry_and_unknown_fails() {
        let source = source();
        let credential = CredentialRef::parse("github-work-token").unwrap();
        assert_eq!(
            source.template_for(&credential).unwrap(),
            InjectionTemplateId::GithubBearer
        );
        let ghost = CredentialRef::parse("ghost-token").unwrap();
        assert!(source.template_for(&ghost).is_err());
    }

    #[test]
    fn metadata_lookup_returns_stored_values_and_defaults_to_empty() {
        let source = source();
        let credential = CredentialRef::parse("github-work-token").unwrap();
        assert_eq!(
            source
                .metadata_for(&credential)
                .unwrap()
                .username
                .as_deref(),
            Some("svc-bot")
        );

        // A source without stored metadata yields the default (all None).
        let bare = InMemoryCredentialSource::new();
        bare.insert(
            CredentialRef::parse("plain-token").unwrap(),
            SecretBytes::from_bytes(b"v"),
            InjectionTemplateId::Bearer,
            CredentialMetadata::default(),
        );
        let plain = CredentialRef::parse("plain-token").unwrap();
        assert_eq!(
            bare.metadata_for(&plain).unwrap(),
            CredentialMetadata::default()
        );
    }

    #[test]
    fn resolved_secret_is_independent_copy_of_storage() {
        let source = source();
        let credential = CredentialRef::parse("github-work-token").unwrap();
        let first = source.resolve(&credential, &environment()).unwrap();
        drop(first);
        // Storage still resolves after a previous result was dropped.
        let second = source.resolve(&credential, &environment()).unwrap();
        assert!(!second.is_empty());
    }

    #[test]
    fn debug_output_of_source_never_reveals_secrets() {
        let source = source();
        let debugged = format!("{source:?}");
        assert!(!debugged.contains(CANARY_SECRET));
    }
}
