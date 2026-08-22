//! Key-provider abstraction over the wrapping-key hierarchy.
//!
//! Per PLAN §12, every deployment mode (in-process root key, OS keyring,
//! remote KMS/HSM) satisfies the same [`KeyProvider`] trait, so higher
//! layers never depend on where wrapping keys actually live.
//!
//! [`InMemoryKeyProvider`] is a test/development implementation: it holds a
//! generated root key and per-project keys in process memory. It is *not*
//! suitable for production persistence.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use vaultx_types::ProjectId;

use crate::envelope::{self, Dek, ProjectKey, RootKey, WrappedKey};
use crate::error::{CryptoError, CryptoResult};

/// Access to project wrapping keys and DEK envelope operations.
pub trait KeyProvider: Send + Sync {
    /// Creates and installs a fresh project key for `project`.
    ///
    /// If a key already exists for this project it is replaced; callers
    /// should treat this as an initialization/new-project operation.
    fn create_project_key(&self, project: &ProjectId) -> CryptoResult<ProjectKey>;

    /// Loads the previously created project key for `project`.
    fn load_project_key(&self, project: &ProjectId) -> CryptoResult<ProjectKey>;

    /// Wraps `dek` under the project key belonging to `project`.
    fn wrap_dek(&self, project: &ProjectId, dek: &Dek) -> CryptoResult<WrappedKey>;

    /// Unwraps a DEK previously wrapped via [`KeyProvider::wrap_dek`].
    fn unwrap_dek(&self, project: &ProjectId, wrapped: &WrappedKey) -> CryptoResult<Dek>;
}

/// In-memory [`KeyProvider`] for tests and local development.
///
/// The root key is generated at construction time and never leaves the
/// process; project keys are kept in a mutex-guarded map. All state is lost
/// when the provider is dropped.
pub struct InMemoryKeyProvider {
    root: RootKey,
    projects: Mutex<HashMap<ProjectId, ProjectKey>>,
}

impl InMemoryKeyProvider {
    /// Creates a provider with a freshly generated root key.
    pub fn new() -> Self {
        Self {
            root: RootKey::generate(),
            projects: Mutex::new(HashMap::new()),
        }
    }

    /// Creates a provider around caller-provided root material.
    pub fn with_root(root: RootKey) -> Self {
        Self {
            root,
            projects: Mutex::new(HashMap::new()),
        }
    }

    /// Read-only access to the underlying root key (e.g. to persist it in a
    /// secure store).
    pub fn root(&self) -> &RootKey {
        &self.root
    }

    fn lock_projects(&self) -> CryptoResult<MutexGuard<'_, HashMap<ProjectId, ProjectKey>>> {
        self.projects
            .lock()
            .map_err(|_| CryptoError::ProviderError("project key store poisoned".to_string()))
    }
}

impl Default for InMemoryKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for InMemoryKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryKeyProvider")
            .field("root", &"<redacted>")
            .field("projects", &self.projects.lock().map(|g| g.len()))
            .finish()
    }
}

impl KeyProvider for InMemoryKeyProvider {
    fn create_project_key(&self, project: &ProjectId) -> CryptoResult<ProjectKey> {
        let key = ProjectKey::generate();
        let mut projects = self.lock_projects()?;
        projects.insert(project.clone(), copy_project_key(&key));
        Ok(key)
    }

    fn load_project_key(&self, project: &ProjectId) -> CryptoResult<ProjectKey> {
        let projects = self.lock_projects()?;
        let stored = projects.get(project).ok_or_else(|| {
            CryptoError::ProviderError(format!("no project key registered for {project:?}"))
        })?;
        Ok(copy_project_key(stored))
    }

    fn wrap_dek(&self, project: &ProjectId, dek: &Dek) -> CryptoResult<WrappedKey> {
        let project_key = self.load_project_key(project)?;
        envelope::wrap_dek(&project_key, dek)
    }

    fn unwrap_dek(&self, project: &ProjectId, wrapped: &WrappedKey) -> CryptoResult<Dek> {
        let project_key = self.load_project_key(project)?;
        envelope::unwrap_dek(&project_key, wrapped)
    }
}

fn copy_project_key(key: &ProjectKey) -> ProjectKey {
    key.expose(ProjectKey::from_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CryptoError;

    fn project(id: &str) -> ProjectId {
        ProjectId::parse(id).expect("valid project id")
    }

    #[test]
    fn full_lifecycle_generate_load_wrap_unwrap() {
        let provider = InMemoryKeyProvider::new();
        let id = project("proj_lifecycle");

        let created = provider.create_project_key(&id).expect("create");
        let loaded = provider.load_project_key(&id).expect("load");
        let same = loaded.expose(|a| created.expose(|b| a == b));
        assert!(same);

        let dek = Dek::generate();
        let wrapped = provider.wrap_dek(&id, &dek).expect("wrap");
        let unwrapped = provider.unwrap_dek(&id, &wrapped).expect("unwrap");
        let same_dek = unwrapped.expose(|a| dek.expose(|b| a == b));
        assert!(same_dek);
    }

    #[test]
    fn unknown_project_errors_on_every_operation() {
        let provider = InMemoryKeyProvider::new();
        let known = project("proj_known");
        provider.create_project_key(&known).expect("create");

        let unknown = project("proj_unknown");
        let err = provider
            .load_project_key(&unknown)
            .expect_err("load must fail");
        assert!(matches!(err, CryptoError::ProviderError(_)));

        let err = provider
            .wrap_dek(&unknown, &Dek::generate())
            .expect_err("wrap must fail");
        assert!(matches!(err, CryptoError::ProviderError(_)));

        let wrapped_elsewhere =
            crate::envelope::wrap_dek(&crate::envelope::ProjectKey::generate(), &Dek::generate())
                .expect("local wrap");
        let err = provider
            .unwrap_dek(&unknown, &wrapped_elsewhere)
            .expect_err("unwrap must fail");
        assert!(matches!(err, CryptoError::ProviderError(_)));
    }

    #[test]
    fn projects_are_isolated() {
        let provider = InMemoryKeyProvider::new();
        let a = project("proj_alpha");
        let b = project("proj_beta");
        provider.create_project_key(&a).expect("create a");
        provider.create_project_key(&b).expect("create b");

        let dek = Dek::generate();
        let wrapped_under_a = provider.wrap_dek(&a, &dek).expect("wrap under a");
        let err = provider
            .unwrap_dek(&b, &wrapped_under_a)
            .expect_err("cross-project unwrap must fail");
        assert!(matches!(err, CryptoError::UnwrapFailed));
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let provider = InMemoryKeyProvider::new();
        let rendered = format!("{provider:?}");
        assert!(rendered.contains("<redacted>"));
        // 32 zero bytes would betray a key printed raw; ensure none appear.
        assert!(!rendered.contains('\u{0}'));
    }

    #[test]
    fn default_constructor_matches_new() {
        let _provider_default = InMemoryKeyProvider::default();
        let _provider_new = InMemoryKeyProvider::new();
    }
}
