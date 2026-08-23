//! [`SecretService`]: encrypted secret-value storage outside the
//! content-addressed object store.
//!
//! # Layout
//!
//! ```text
//! <root>/.vaultx/root.key          root wrapping key (dev fallback; see vaultx-keyring)
//! <root>/.vaultx/keys/project.json wrapped project + fingerprint keys
//! <root>/.vaultx/secrets/<secret_id>/<revision_id>.json  revision records
//! ```
//!
//! # Invariants honored here
//!
//! * INV-001 — plaintext secret values never become content-addressed
//!   repository objects: ciphertext + metadata records live under
//!   `.vaultx/secrets/`, and manifest entries reference revision IDs only.
//! * INV-012 — plaintext never appears in error messages, `Debug` output,
//!   or log lines; [`SecretString`](vaultx_crypto::secret::SecretString)
//!   redacts itself and every error variant carries identifiers at most.
//! * INV-013 — history is never mutated: destroying a revision rewrites
//!   only that record's state/shred fields, never repository objects,
//!   refs, or other revisions.
//! * INV-020 — [`SecretService::reveal_secret`] exists solely for trusted
//!   local paths (the future `vaultx run`); agent/broker-client surfaces
//!   must never call it.
//!
//! # Key hierarchy wiring
//!
//! On first use the service loads-or-creates the 32-byte root key from its
//! configured [`WrappingKeyProvider`] (default: [`FileKeyStore`] at
//! `.vaultx/root.key`, a development fallback), then either initializes
//! `.vaultx/keys/project.json` with freshly generated project and
//! fingerprint keys wrapped under that root, or unwraps the existing pair.
//! A wrong root key surfaces as [`CoreError::ProjectKey`] and never
//! overwrites the stored file. Unwrapped keys are cached per process on
//! the [`ProjectContext`].
//!
//! Every revision is written with a fresh random DEK and a fresh random
//! nonce (single-use DEKs keep the AES-GCM random-nonce bound trivially
//! safe), and the AEAD associated data binds project id, secret id,
//! revision id, kind, and format version together.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError};

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use vaultx_crypto::aead::{CiphertextBundle, Nonce};
use vaultx_crypto::envelope::{self, Dek, FingerprintKey, ProjectKey, WrappedKey};
use vaultx_crypto::error::{CryptoError, CryptoResult};
use vaultx_crypto::fingerprint;
use vaultx_crypto::secret::SecretString;
use vaultx_keyring::{FileKeyStore, WrappingKeyProvider};
use vaultx_repository::ManifestEntry;
use vaultx_types::model::{InjectionTemplateId, VariableKind};
use vaultx_types::{
    CredentialRef, EnvironmentId, ProjectId, ProviderName, SecretId, SecretRevisionId, VariableName,
};

use crate::error::{CoreError, CoreResult};
use crate::project::ProjectContext;

/// Directory holding encrypted secret revision records.
pub(crate) const SECRETS_DIR_NAME: &str = "secrets";
/// Directory holding wrapped project vault keys.
pub(crate) const KEYS_DIR_NAME: &str = "keys";
/// File name of the wrapped project/fingerprint key bundle inside the
/// keys directory.
const PROJECT_KEY_FILE: &str = "project.json";
/// File name of the default (development-fallback) root wrapping key.
pub(crate) const ROOT_KEY_FILE: &str = "root.key";
/// Format version stamped into every persisted secret-layer structure.
const FORMAT_VERSION: u32 = 1;
/// Placeholder project id for single-project local repositories (matches
/// the convention used by environment promotion audit events).
const LOCAL_PROJECT_ID: &str = "proj_local";

/// Lifecycle state of a secret revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRevisionState {
    /// Current usable value.
    Active,
    /// Superseded by a newer revision; ciphertext remains auditable.
    Revoked,
    /// Recovery material shredded; value permanently unrecoverable.
    Destroyed,
}

impl std::fmt::Display for SecretRevisionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Destroyed => "destroyed",
        })
    }
}

/// Broker-side binding attached to brokered secret revisions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokeredBinding {
    /// Logical credential reference at the broker.
    pub credential_ref: CredentialRef,
    /// How the value is injected into outbound requests.
    pub injection: InjectionTemplateId,
    /// Optional provider hint used by the injector registry.
    pub provider_hint: Option<ProviderName>,
}

/// Associated data binding one ciphertext to exactly one project /
/// secret / revision / kind combination.
///
/// Serialized to canonical JSON bytes before each AEAD call, so tampering
/// with any bound field (or swapping records between files) fails
/// authentication instead of decrypting into the wrong context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRevisionAad {
    /// Owning project.
    pub project_id: ProjectId,
    /// Secret entry this revision belongs to.
    pub secret_id: SecretId,
    /// This revision's id.
    pub revision_id: SecretRevisionId,
    /// Secret category (`secret` / `brokered`).
    pub kind: VariableKind,
    /// On-disk format version.
    pub format_version: u32,
}

impl SecretRevisionAad {
    fn canonical_bytes(&self) -> CoreResult<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }
}

/// One encrypted secret revision record on disk.
///
/// Holds no plaintext: the value exists only as AES-256-GCM ciphertext
/// under a per-revision DEK that is itself wrapped under the project key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSecretRevision {
    /// Revision id (file name stem).
    pub id: SecretRevisionId,
    /// Owning secret entry.
    pub secret_id: SecretId,
    /// Variable name this value is bound to.
    pub name: VariableName,
    /// Environment this value belongs to.
    pub environment: EnvironmentId,
    /// Secret category.
    pub kind: VariableKind,
    /// Present when `kind` is [`VariableKind::Brokered`].
    #[serde(default)]
    pub brokered: Option<BrokeredBinding>,
    /// Lifecycle state.
    pub state: SecretRevisionState,
    /// Creation time in unix seconds.
    pub created_at: u64,
    /// Creation time in unix nanoseconds; disambiguates revisions written
    /// within the same second so "latest" selection stays deterministic.
    #[serde(default)]
    pub created_nanos: u64,
    /// Hex-encoded ciphertext (GCM tag included).
    pub ciphertext_hex: String,
    /// Hex-encoded 12-byte AEAD nonce drawn fresh per encryption.
    pub nonce_hex: String,
    /// Hex-encoded JSON of the DEK wrapped under the project key; emptied
    /// when the revision is destroyed.
    pub wrapped_dek_hex: String,
    /// Associated data the ciphertext is authenticated against.
    pub aad: SecretRevisionAad,
    /// Keyed HMAC-SHA256 fingerprint of the plaintext (safe to display).
    pub fingerprint_hex: String,
    /// Set when recovery material has been irreversibly shredded.
    #[serde(default)]
    pub shredded: bool,
}

/// Wrapped project and fingerprint keys persisted at
/// `.vaultx/keys/project.json`. Contains no raw key material.
#[derive(Debug, Serialize, Deserialize)]
struct StoredProjectKeys {
    format_version: u32,
    project_nonce_hex: String,
    project_ciphertext_hex: String,
    fingerprint_nonce_hex: String,
    fingerprint_ciphertext_hex: String,
}

/// Cache entry stored on the [`ProjectContext`]: the unwrapped keys
/// together with a clone of the provider that unwrapped them, so cache
/// identity is a live `Arc::ptr_eq` comparison rather than a reusable
/// address.
pub(crate) struct CachedProjectKeys {
    /// Identity half of the cache key; kept alive so `Arc::ptr_eq`
    /// comparisons stay sound across allocator reuse.
    pub(crate) provider: std::sync::Arc<dyn WrappingKeyProvider>,
    /// Keys unwrapped by `provider`.
    pub(crate) keys: std::sync::Arc<ProjectKeys>,
}

impl std::fmt::Debug for CachedProjectKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CachedProjectKeys(<redacted>)")
    }
}

/// Unwrapped in-process copy of the project vault keys.
pub(crate) struct ProjectKeys {
    /// Content-encryption key wrapping every revision DEK.
    project: ProjectKey,
    /// Key computing non-invertible plaintext fingerprints.
    fingerprint: FingerprintKey,
}

impl std::fmt::Debug for ProjectKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProjectKeys(<redacted>)")
    }
}

/// One row of [`SecretMetadata::history`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretRevisionInfo {
    /// Revision id.
    pub id: SecretRevisionId,
    /// Lifecycle state.
    pub state: SecretRevisionState,
    /// Creation time in unix seconds.
    pub created_at: u64,
}

/// Metadata about one secret — everything except its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretMetadata {
    /// Secret entry id.
    pub secret_id: SecretId,
    /// Variable name.
    pub name: VariableName,
    /// Environment id.
    pub environment: EnvironmentId,
    /// Id of the latest revision.
    pub current_revision: SecretRevisionId,
    /// State of the latest revision.
    pub state: SecretRevisionState,
    /// Secret category.
    pub kind: VariableKind,
    /// Broker binding when the latest revision is brokered.
    pub brokered: Option<BrokeredBinding>,
    /// Fingerprint of the current plaintext (keyed, non-invertible).
    pub fingerprint_hex: String,
    /// Creation time of the latest revision in unix seconds.
    pub created_at: u64,
    /// Revisions of this secret entry, oldest first.
    pub history: Vec<SecretRevisionInfo>,
}

/// One row of [`SecretService::list_secrets`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretListEntry {
    /// Variable name.
    pub name: VariableName,
    /// Secret category.
    pub kind: VariableKind,
    /// State of the latest revision.
    pub state: SecretRevisionState,
}

/// Everything needed to mint one encrypted revision.
struct RevisionInput<'a> {
    name: &'a VariableName,
    secret_id: &'a SecretId,
    env: &'a EnvironmentId,
    kind: VariableKind,
    binding: Option<BrokeredBinding>,
    bytes: &'a [u8],
}

/// Encrypted secret-value operations: set / rotate / destroy / metadata /
/// reveal / list.
#[derive(Clone)]
pub struct SecretService<'a> {
    ctx: &'a ProjectContext,
    root_store: Arc<dyn WrappingKeyProvider>,
}

impl<'a> SecretService<'a> {
    /// Builds a service operating on `ctx` using the default development
    /// root-key store at `<project>/.vaultx/root.key`.
    ///
    /// Production deployments should inject an OS-keychain-backed provider
    /// through [`SecretService::with_root_store`] instead.
    #[must_use]
    pub fn new(ctx: &'a ProjectContext) -> Self {
        Self::with_root_store(
            ctx,
            Arc::new(FileKeyStore::new(ctx.vault_dir().join(ROOT_KEY_FILE))),
        )
    }

    /// Builds a service around an explicit root-key provider.
    #[must_use]
    pub fn with_root_store(
        ctx: &'a ProjectContext,
        root_store: Arc<dyn WrappingKeyProvider>,
    ) -> Self {
        Self { ctx, root_store }
    }

    /// Encrypts and stores a new revision for `name` in `env_bare_name`,
    /// creating the secret entry on first write and staging the manifest
    /// binding ([`ManifestEntry::Secret`] or [`ManifestEntry::Brokered`]).
    ///
    /// Writing over an existing active/revoked secret reuses its entry;
    /// writing over a destroyed secret provisions a **fresh** entry (the
    /// destroyed lineage stays destroyed). Empty plaintext is refused.
    ///
    /// # Errors
    /// * [`CoreError::InvalidVariableName`] on malformed names.
    /// * [`CoreError::EmptySecretValue`] on empty plaintext.
    /// * [`CoreError::InconsistentBinding`] when `kind` and `brokered`
    ///   disagree or `kind` is not `Secret`/`Brokered`.
    /// * Propagates key-hierarchy, crypto, staging, and I/O failures.
    pub fn set_secret(
        &self,
        name: &str,
        plaintext: &SecretString,
        kind: VariableKind,
        env_bare_name: &str,
        brokered: Option<BrokeredBinding>,
    ) -> CoreResult<SecretRevisionId> {
        let parsed = parse_name(name)?;
        let env = environment_id(env_bare_name)?;
        let binding = validate_binding(kind, brokered, name)?;
        let bytes = plaintext_bytes(plaintext)?;
        let secret_id = match self.latest_record(&parsed, &env)? {
            Some((id, latest)) if latest.state != SecretRevisionState::Destroyed => id,
            _ => new_secret_id()?,
        };
        self.write_revision(
            RevisionInput {
                name: &parsed,
                secret_id: &secret_id,
                env: &env,
                kind,
                binding,
                bytes: &bytes,
            },
            None,
        )
    }

    /// Stores a new revision for an existing secret, revoking the previous
    /// latest revision. Kind and brokered binding carry over.
    ///
    /// # Errors
    /// * [`CoreError::SecretNotFound`] when nothing is bound to `name`.
    /// * [`CoreError::SecretDestroyed`] when the latest revision is
    ///   destroyed (rotation would imply continuity that no longer exists;
    ///   use [`SecretService::set_secret`] to provision afresh).
    /// * [`CoreError::EmptySecretValue`] on empty plaintext.
    /// * Propagates key-hierarchy, crypto, staging, and I/O failures.
    pub fn rotate_secret(
        &self,
        name: &str,
        new_plaintext: &SecretString,
        env_bare_name: &str,
    ) -> CoreResult<SecretRevisionId> {
        let parsed = parse_name(name)?;
        let env = environment_id(env_bare_name)?;
        let bytes = plaintext_bytes(new_plaintext)?;
        let Some((secret_id, latest)) = self.latest_record(&parsed, &env)? else {
            return Err(CoreError::SecretNotFound(name.to_owned()));
        };
        if latest.state == SecretRevisionState::Destroyed {
            return Err(CoreError::SecretDestroyed(name.to_owned()));
        }
        self.write_revision(
            RevisionInput {
                name: &parsed,
                secret_id: &secret_id,
                env: &env,
                kind: latest.kind,
                binding: latest.brokered.clone(),
                bytes: &bytes,
            },
            Some(latest),
        )
    }

    /// Marks the latest revision destroyed and irreversibly shreds its
    /// recovery material (the wrapped DEK field is emptied and the record
    /// flagged `shredded`). Historical metadata stays auditable.
    /// Destroying an already-destroyed secret is a no-op. The staged or
    /// committed manifest binding deliberately keeps pointing at the
    /// destroyed revision so the destruction is visible in history
    /// (INV-013).
    ///
    /// # Errors
    /// * [`CoreError::SecretNotFound`] when nothing is bound to `name`.
    /// * Propagates record persistence failures.
    pub fn destroy_secret(&self, name: &str, env_bare_name: &str) -> CoreResult<()> {
        let parsed = parse_name(name)?;
        let env = environment_id(env_bare_name)?;
        let Some((_, mut latest)) = self.latest_record(&parsed, &env)? else {
            return Err(CoreError::SecretNotFound(name.to_owned()));
        };
        if latest.state == SecretRevisionState::Destroyed {
            return Ok(());
        }
        latest.state = SecretRevisionState::Destroyed;
        latest.wrapped_dek_hex = String::new();
        latest.shredded = true;
        self.save_record(&latest)
    }

    /// Collects everything known about a secret except its value:
    /// identity, current state, kind, binding, keyed fingerprint, and the
    /// per-entry revision history (oldest first).
    ///
    /// # Errors
    /// * [`CoreError::SecretNotFound`] when nothing is bound to `name`.
    /// * Propagates record decode failures.
    pub fn secret_metadata(&self, name: &str, env_bare_name: &str) -> CoreResult<SecretMetadata> {
        let parsed = parse_name(name)?;
        let env = environment_id(env_bare_name)?;
        let records = self.records_for(&parsed, &env)?;
        let latest = pick_latest(&records)
            .cloned()
            .ok_or_else(|| CoreError::SecretNotFound(name.to_owned()))?;
        let lineage: Vec<&EncryptedSecretRevision> = records
            .iter()
            .filter(|record| record.secret_id == latest.secret_id)
            .collect();
        let history = lineage
            .iter()
            .map(|record| SecretRevisionInfo {
                id: record.id.clone(),
                state: record.state,
                created_at: record.created_at,
            })
            .collect();
        Ok(SecretMetadata {
            secret_id: latest.secret_id.clone(),
            name: latest.name.clone(),
            environment: latest.environment.clone(),
            current_revision: latest.id.clone(),
            state: latest.state,
            kind: latest.kind,
            brokered: latest.brokered.clone(),
            fingerprint_hex: latest.fingerprint_hex.clone(),
            created_at: latest.created_at,
            history,
        })
    }

    /// Decrypts the latest active value of a secret.
    ///
    /// Trusted-path only ([INV-020]): agent and broker-client surfaces
    /// must never call this. The recovered buffer is zeroized on drop.
    ///
    /// # Errors
    /// * [`CoreError::SecretNotFound`] when nothing is bound to `name`.
    /// * [`CoreError::SecretDestroyed`] when the latest revision is
    ///   destroyed.
    /// * Propagates AEAD unwrap/decrypt failures for tampered or corrupt
    ///   records.
    pub fn reveal_secret(&self, name: &str, env_bare_name: &str) -> CoreResult<Zeroizing<Vec<u8>>> {
        let parsed = parse_name(name)?;
        let env = environment_id(env_bare_name)?;
        let Some((_, latest)) = self.latest_record(&parsed, &env)? else {
            return Err(CoreError::SecretNotFound(name.to_owned()));
        };
        if latest.state == SecretRevisionState::Destroyed {
            return Err(CoreError::SecretDestroyed(name.to_owned()));
        }
        self.decrypt_record(&latest)
    }

    /// Lists secrets bound in one environment (names, kinds, states only),
    /// sorted by name. Never returns values.
    ///
    /// # Errors
    /// * Propagates record decode failures.
    pub fn list_secrets(&self, env_bare_name: &str) -> CoreResult<Vec<SecretListEntry>> {
        let env = environment_id(env_bare_name)?;
        // scan_records returns ascending order, so later records win the
        // per-name slot and end up as "latest".
        let mut latest_by_name: std::collections::BTreeMap<String, EncryptedSecretRevision> =
            std::collections::BTreeMap::new();
        for record in self.scan_records(Some(&env))? {
            latest_by_name.insert(record.name.as_str().to_owned(), record);
        }
        Ok(latest_by_name
            .into_values()
            .map(|record| SecretListEntry {
                name: record.name.clone(),
                kind: record.kind,
                state: record.state,
            })
            .collect())
    }

    // ---- key hierarchy ----

    /// Returns the cached project keys, but only when they were unwrapped
    /// by this service's own root-key provider (identity compared via
    /// [`Arc::ptr_eq`]; the slot holds a clone of the provider, so the
    /// comparison stays sound across drop-and-reallocate address reuse).
    /// A different provider installed on the same context forces a reload
    /// instead of silently reusing foreign keys.
    fn cached_keys(&self) -> CoreResult<Arc<ProjectKeys>> {
        let mut slot = self
            .ctx
            .project_key_slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(cached) = slot.as_ref() {
            if Arc::ptr_eq(&cached.provider, &self.root_store) {
                return Ok(Arc::clone(&cached.keys));
            }
        }
        let keys = Arc::new(self.load_or_init_keys()?);
        *slot = Some(CachedProjectKeys {
            provider: Arc::clone(&self.root_store),
            keys: Arc::clone(&keys),
        });
        Ok(keys)
    }

    fn load_or_init_keys(&self) -> CoreResult<ProjectKeys> {
        let root = self.root_store.obtain()?;
        let path = self.keys_path();
        if let Some(keys) = self.read_project_keys(&root)? {
            return Ok(keys);
        }
        // Absent: mint a candidate bundle and publish it without
        // clobbering a racing writer's bundle.
        let (keys, stored) = Self::new_key_bundle(&root)?;
        let bytes = serde_json::to_vec_pretty(&stored)?;
        match publish_file_no_clobber(&path, &bytes) {
            Ok(()) => Ok(keys),
            // Lost the race: adopt the winner's bundle — it is wrapped
            // under the same shared root, so it unwraps cleanly.
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                self.read_project_keys(&root)?.ok_or_else(|| {
                    CoreError::ProjectKey("key bundle vanished between create and read".to_owned())
                })
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Reads and unwraps `.vaultx/keys/project.json`; `Ok(None)` when the
    /// file does not exist. Malformed material errors as
    /// [`CoreError::ProjectKey`] and never overwrites the stored file.
    fn read_project_keys(
        &self,
        root: &vaultx_crypto::envelope::RootKey,
    ) -> CoreResult<Option<ProjectKeys>> {
        let text = match std::fs::read_to_string(self.keys_path()) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        let stored: StoredProjectKeys = serde_json::from_str(&text).map_err(|err| {
            CoreError::ProjectKey(format!("unreadable ({err}); refusing to overwrite"))
        })?;
        if stored.format_version != FORMAT_VERSION {
            return Err(CoreError::ProjectKey(format!(
                "unsupported format version {}",
                stored.format_version
            )));
        }
        let project_wrapped = decode_stored_wrapped(
            &stored.project_nonce_hex,
            &stored.project_ciphertext_hex,
            "project key",
        )?;
        let project = envelope::unwrap_project_key(root, &project_wrapped).map_err(|_| {
            CoreError::ProjectKey(
                "cannot unwrap the project key with the configured root key".to_owned(),
            )
        })?;
        let fingerprint_wrapped = decode_stored_wrapped(
            &stored.fingerprint_nonce_hex,
            &stored.fingerprint_ciphertext_hex,
            "fingerprint key",
        )?;
        let fingerprint_key = envelope::unwrap_fingerprint_key(&project, &fingerprint_wrapped)
            .map_err(|_| {
                CoreError::ProjectKey(
                    "cannot unwrap the fingerprint key with the project key".to_owned(),
                )
            })?;
        Ok(Some(ProjectKeys {
            project,
            fingerprint: fingerprint_key,
        }))
    }

    /// Fresh random project/fingerprint pair together with its persisted
    /// (wrapped) form. Does not touch the filesystem.
    fn new_key_bundle(
        root: &vaultx_crypto::envelope::RootKey,
    ) -> CoreResult<(ProjectKeys, StoredProjectKeys)> {
        let project = ProjectKey::generate();
        let fpk = FingerprintKey::generate();
        let wrapped_project = envelope::wrap_project_key(root, &project)?;
        let wrapped_fpk = envelope::wrap_fingerprint_key(&project, &fpk)?;
        Ok((
            ProjectKeys {
                project,
                fingerprint: fpk,
            },
            StoredProjectKeys {
                format_version: FORMAT_VERSION,
                project_nonce_hex: hex::encode(wrapped_project.nonce.as_bytes()),
                project_ciphertext_hex: hex::encode(&wrapped_project.ciphertext),
                fingerprint_nonce_hex: hex::encode(wrapped_fpk.nonce.as_bytes()),
                fingerprint_ciphertext_hex: hex::encode(&wrapped_fpk.ciphertext),
            },
        ))
    }

    // ---- revision plumbing ----

    /// Encrypts `bytes` into a fresh revision record and persists it,
    /// optionally revoking `previous` first, then stages the manifest
    /// binding.
    fn write_revision(
        &self,
        input: RevisionInput<'_>,
        previous: Option<EncryptedSecretRevision>,
    ) -> CoreResult<SecretRevisionId> {
        let keys = self.cached_keys()?;
        let revision_id = new_revision_id()?;
        let dek = Dek::generate();
        let aad = SecretRevisionAad {
            project_id: ProjectId::parse(LOCAL_PROJECT_ID)?,
            secret_id: input.secret_id.clone(),
            revision_id: revision_id.clone(),
            kind: input.kind,
            format_version: FORMAT_VERSION,
        };
        let aad_bytes = aad.canonical_bytes()?;
        let bundle = envelope::encrypt_with_dek(&dek, input.bytes, &aad_bytes)?;
        let wrapped_dek = envelope::wrap_dek(&keys.project, &dek)?;
        let record = EncryptedSecretRevision {
            id: revision_id.clone(),
            secret_id: input.secret_id.clone(),
            name: input.name.clone(),
            environment: input.env.clone(),
            kind: input.kind,
            brokered: input.binding.clone(),
            state: SecretRevisionState::Active,
            created_at: unix_now(),
            created_nanos: unix_nanos(),
            ciphertext_hex: hex::encode(&bundle.ciphertext),
            nonce_hex: hex::encode(bundle.nonce.as_bytes()),
            wrapped_dek_hex: encode_wrapped(&wrapped_dek),
            aad,
            fingerprint_hex: fingerprint::keyed_fingerprint(&keys.fingerprint, input.bytes),
            shredded: false,
        };
        // Publish the replacement before revoking the predecessor so a
        // crash leaves two actives (latest-by-timestamp wins) rather than
        // none.
        self.save_record(&record)?;
        if let Some(mut old) = previous {
            old.state = SecretRevisionState::Revoked;
            self.save_record(&old)?;
        }
        self.stage_binding(input.name, input.binding.as_ref(), &revision_id)?;
        Ok(revision_id)
    }

    fn stage_binding(
        &self,
        name: &VariableName,
        binding: Option<&BrokeredBinding>,
        revision_id: &SecretRevisionId,
    ) -> CoreResult<()> {
        let entry = match binding {
            // Binding data is validated before a record is written, so
            // this arm covers every brokered write.
            Some(b) => ManifestEntry::Brokered {
                credential: b.credential_ref.clone(),
                revision: revision_id.clone(),
            },
            _ => ManifestEntry::Secret {
                revision: revision_id.clone(),
            },
        };
        Ok(self.ctx.repository().add(name.clone(), entry)?)
    }

    fn decrypt_record(&self, record: &EncryptedSecretRevision) -> CoreResult<Zeroizing<Vec<u8>>> {
        let keys = self.cached_keys()?;
        let wrapped = decode_wrapped_json(&record.wrapped_dek_hex)?;
        let dek = envelope::unwrap_dek(&keys.project, &wrapped)?;
        let bundle = CiphertextBundle {
            nonce: decode_nonce(&record.nonce_hex).map_err(|_| CryptoError::DecryptionFailed)?,
            ciphertext: decode_hex(&record.ciphertext_hex)
                .map_err(|_| CryptoError::DecryptionFailed)?,
        };
        let aad_bytes = record.aad.canonical_bytes()?;
        let plaintext = envelope::decrypt_with_dek(&dek, &bundle, &aad_bytes)?;
        if !fingerprint::verify_fingerprint(&keys.fingerprint, &plaintext, &record.fingerprint_hex)
        {
            return Err(CryptoError::DecryptionFailed.into());
        }
        Ok(plaintext)
    }

    // ---- record scanning / persistence ----

    fn secrets_dir(&self) -> PathBuf {
        self.ctx.vault_dir().join(SECRETS_DIR_NAME)
    }

    fn keys_path(&self) -> PathBuf {
        self.ctx
            .vault_dir()
            .join(KEYS_DIR_NAME)
            .join(PROJECT_KEY_FILE)
    }

    fn save_record(&self, record: &EncryptedSecretRevision) -> CoreResult<()> {
        let path = self
            .secrets_dir()
            .join(record.secret_id.as_str())
            .join(format!("{}.json", record.id.as_str()));
        write_atomic(&path, serde_json::to_vec_pretty(record)?.as_slice())?;
        Ok(())
    }

    /// Loads every record visible in the requested environment (or all
    /// environments when `env` is `None`), sorted oldest first.
    fn scan_records(
        &self,
        env: Option<&EnvironmentId>,
    ) -> CoreResult<Vec<EncryptedSecretRevision>> {
        let root = self.secrets_dir();
        let mut records = Vec::new();
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            // No secrets written yet.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(records),
            Err(err) => return Err(err.into()),
        };
        for dir in entries {
            let dir = dir?;
            let files = match std::fs::read_dir(dir.path()) {
                Ok(files) => files,
                // Not a per-secret directory after all.
                Err(err) if err.kind() == std::io::ErrorKind::NotADirectory => continue,
                Err(err) => return Err(err.into()),
            };
            for file in files {
                let path = file?.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                    continue;
                }
                let text = std::fs::read_to_string(&path)?;
                let record: EncryptedSecretRevision =
                    serde_json::from_str(&text).map_err(|err| {
                        CoreError::Json(serde_json::Error::io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("corrupt secret record {}: {err}", path.display()),
                        )))
                    })?;
                if env.is_none_or(|wanted| wanted == &record.environment) {
                    records.push(record);
                }
            }
        }
        records.sort_by_key(ordering_key);
        Ok(records)
    }

    fn records_for(
        &self,
        name: &VariableName,
        env: &EnvironmentId,
    ) -> CoreResult<Vec<EncryptedSecretRevision>> {
        Ok(self
            .scan_records(Some(env))?
            .into_iter()
            .filter(|record| &record.name == name)
            .collect())
    }

    /// Latest record for `(name, env)` together with its secret id.
    fn latest_record(
        &self,
        name: &VariableName,
        env: &EnvironmentId,
    ) -> CoreResult<Option<(SecretId, EncryptedSecretRevision)>> {
        let records = self.records_for(name, env)?;
        Ok(pick_latest(&records).map(|latest| (latest.secret_id.clone(), latest.clone())))
    }
}

fn parse_name(name: &str) -> CoreResult<VariableName> {
    VariableName::parse(name).map_err(|_| CoreError::InvalidVariableName(name.to_owned()))
}

/// Maps a bare environment name onto its prefixed id, mirroring the
/// naming rules used by environment refs.
fn environment_id(bare: &str) -> CoreResult<EnvironmentId> {
    Ok(EnvironmentId::parse(&format!("env_{bare}"))?)
}

/// Enforces the `Secret`/`Brokered` ⇄ binding correspondence.
fn validate_binding(
    kind: VariableKind,
    brokered: Option<BrokeredBinding>,
    name: &str,
) -> CoreResult<Option<BrokeredBinding>> {
    match kind {
        VariableKind::Brokered => Ok(Some(brokered.ok_or_else(|| {
            CoreError::InconsistentBinding(format!(
                "`brokered` kind requires a brokered binding for `{name}`"
            ))
        })?)),
        VariableKind::Secret => {
            if brokered.is_some() {
                return Err(CoreError::InconsistentBinding(format!(
                    "plain secret `{name}` cannot carry a brokered binding"
                )));
            }
            Ok(None)
        }
        other => Err(CoreError::InconsistentBinding(format!(
            "unsupported secret kind `{other:?}` for `{name}`"
        ))),
    }
}

fn plaintext_bytes(plaintext: &SecretString) -> CoreResult<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(plaintext.expose_str(|value| value.as_bytes().to_vec()));
    if bytes.is_empty() {
        Err(CoreError::EmptySecretValue)
    } else {
        Ok(bytes)
    }
}

fn ordering_key(record: &EncryptedSecretRevision) -> (u64, u64, String) {
    (
        record.created_nanos,
        record.created_at,
        record.id.as_str().to_owned(),
    )
}

fn pick_latest(records: &[EncryptedSecretRevision]) -> Option<&EncryptedSecretRevision> {
    records
        .iter()
        .max_by(|a, b| ordering_key(a).cmp(&ordering_key(b)))
}

fn new_secret_id() -> CoreResult<SecretId> {
    Ok(SecretId::parse(&format!("sec_{}", random_suffix()))?)
}

fn new_revision_id() -> CoreResult<SecretRevisionId> {
    Ok(SecretRevisionId::parse(&format!(
        "sec_rev_{}",
        random_suffix()
    ))?)
}

fn random_suffix() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn unix_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// Hex-encodes a wrapped child key. JSON form keeps nonce + ciphertext
/// together and validates structurally on decode.
fn encode_wrapped(wrapped: &WrappedKey) -> String {
    match serde_json::to_vec(wrapped) {
        Ok(bytes) => hex::encode(bytes),
        // WrappedKey serialization cannot fail in practice; an empty blob
        // fails loudly (UnwrapFailed) on decode instead of corrupting data
        // silently.
        Err(_) => String::new(),
    }
}

/// Decodes a wrapped key from the `(nonce_hex, ciphertext_hex)` field
/// pair used by `.vaultx/keys/project.json`, mapping malformed material
/// onto [`CoreError::ProjectKey`] (not a crypto failure).
fn decode_stored_wrapped(
    nonce_hex: &str,
    ciphertext_hex: &str,
    field: &str,
) -> CoreResult<WrappedKey> {
    let nonce = decode_nonce(nonce_hex)
        .map_err(|_| CoreError::ProjectKey(format!("malformed `{field}` nonce")))?;
    let ciphertext = hex::decode(ciphertext_hex.trim())
        .map_err(|_| CoreError::ProjectKey(format!("malformed `{field}` ciphertext")))?;
    Ok(WrappedKey { nonce, ciphertext })
}

/// Decodes a wrapped key from the hex-encoded JSON form used inside
/// revision records.
fn decode_wrapped_json(hex_str: &str) -> CryptoResult<WrappedKey> {
    let bytes = decode_hex(hex_str)?;
    serde_json::from_slice(&bytes).map_err(|_| CryptoError::UnwrapFailed)
}

fn decode_nonce(hex_str: &str) -> CryptoResult<Nonce> {
    let bytes = decode_hex(hex_str)?;
    let raw: [u8; 12] = bytes
        .try_into()
        .map_err(|_| CryptoError::DecryptionFailed)?;
    Ok(Nonce::from_bytes(raw))
}

fn decode_hex(hex_str: &str) -> CryptoResult<Vec<u8>> {
    hex::decode(hex_str.trim()).map_err(|_| CryptoError::DecryptionFailed)
}

/// Writes `bytes` to `path` atomically (temp file + rename after fsync),
/// with owner-only permissions on unix (defense-in-depth parity with the
/// root key file; contents are ciphertext or wrapped keys).
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp_path = path.with_file_name(format!(
        ".tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    {
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)?
        };
        #[cfg(not(unix))]
        let mut file = std::fs::File::create(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&temp_path, path)
}

/// Publishes `bytes` at `path` only if `path` does not exist yet, with
/// owner-only permissions on unix. The temp-then-hard-link sequence is
/// atomic against concurrent publishers: losing a race fails with
/// [`std::io::ErrorKind::AlreadyExists`] instead of clobbering the
/// winner's bytes.
fn publish_file_no_clobber(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp_path = path.with_file_name(format!(
        ".tmp-new-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    ));
    write_atomic(&temp_path, bytes)?;
    match std::fs::hard_link(&temp_path, path) {
        Ok(()) => {
            let _ = std::fs::remove_file(&temp_path);
            Ok(())
        }
        Err(err) => {
            let _ = std::fs::remove_file(&temp_path);
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const CANARY: &str = "CANARY-hunter2-ZZ9pluralZalpha";
    const PLAIN_ONE: &str = "zebra-first-value";
    const PLAIN_TWO: &str = "yankee-second-value";

    /// Fresh project + a root-key store in its own temp dir so tests can
    /// point second services at different (wrong) roots.
    struct Fixture {
        _project_dir: tempfile::TempDir,
        _store_dir: tempfile::TempDir,
        ctx: ProjectContext,
        store_path: PathBuf,
    }

    fn fixture() -> Fixture {
        let project_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let ctx = ProjectContext::init(project_dir.path()).unwrap();
        let store_path = store_dir.path().join("root.key");
        Fixture {
            _project_dir: project_dir,
            _store_dir: store_dir,
            ctx,
            store_path,
        }
    }

    fn service(fx: &Fixture) -> SecretService<'_> {
        SecretService::with_root_store(&fx.ctx, Arc::new(FileKeyStore::new(&fx.store_path)))
    }

    fn secret(value: &str) -> SecretString {
        SecretString::copy_from(value)
    }

    fn record_paths(vault_dir: &Path, suffix: &str) -> Vec<PathBuf> {
        let secrets_root = vault_dir.join(SECRETS_DIR_NAME);
        let mut found = Vec::new();
        let mut stack = vec![secrets_root];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.to_string_lossy().ends_with(suffix) {
                    found.push(path);
                }
            }
        }
        found
    }

    fn read_record(path: &Path) -> EncryptedSecretRevision {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn set_reveal_roundtrip_persists_across_reopen() {
        let fx = fixture();
        let svc = service(&fx);
        let revision = svc
            .set_secret(
                "DB_PASSWORD",
                &secret(CANARY),
                VariableKind::Secret,
                "dev",
                None,
            )
            .unwrap();
        assert!(revision.as_str().starts_with("sec_rev_"));

        let revealed = svc.reveal_secret("DB_PASSWORD", "dev").unwrap();
        assert_eq!(revealed.as_slice(), CANARY.as_bytes());

        // Reopen the whole context; values and keys survive.
        let reopened = ProjectContext::open(fx.ctx.root()).unwrap();
        let svc =
            SecretService::with_root_store(&reopened, Arc::new(FileKeyStore::new(&fx.store_path)));
        assert_eq!(
            svc.reveal_secret("DB_PASSWORD", "dev").unwrap().as_slice(),
            CANARY.as_bytes()
        );
    }

    #[test]
    fn rotate_revokes_old_and_reveal_returns_new_value() {
        let fx = fixture();
        let svc = service(&fx);
        svc.set_secret(
            "API_KEY",
            &secret("first-value"),
            VariableKind::Secret,
            "prod",
            None,
        )
        .unwrap();
        let new_revision = svc
            .rotate_secret("API_KEY", &secret("second-value"), "prod")
            .unwrap();

        assert_eq!(
            svc.reveal_secret("API_KEY", "prod").unwrap().as_slice(),
            b"second-value"
        );
        let metadata = svc.secret_metadata("API_KEY", "prod").unwrap();
        assert_eq!(metadata.current_revision, new_revision);
        let states: Vec<(SecretRevisionState, usize)> = vec![
            (
                SecretRevisionState::Revoked,
                metadata
                    .history
                    .iter()
                    .filter(|r| r.state == SecretRevisionState::Revoked)
                    .count(),
            ),
            (
                SecretRevisionState::Active,
                metadata
                    .history
                    .iter()
                    .filter(|r| r.state == SecretRevisionState::Active)
                    .count(),
            ),
        ];
        assert_eq!(states[0], (SecretRevisionState::Revoked, 1));
        assert_eq!(states[1], (SecretRevisionState::Active, 1));
    }

    #[test]
    fn destroy_shreds_recovery_material_and_blocks_reveal() {
        let fx = fixture();
        let svc = service(&fx);
        svc.set_secret(
            "TOKEN",
            &secret("shred-me"),
            VariableKind::Secret,
            "dev",
            None,
        )
        .unwrap();
        svc.destroy_secret("TOKEN", "dev").unwrap();

        match svc.reveal_secret("TOKEN", "dev") {
            Err(CoreError::SecretDestroyed(name)) => assert_eq!(name, "TOKEN"),
            other => panic!("expected SecretDestroyed, got {other:?}"),
        }
        // Idempotent.
        assert!(svc.destroy_secret("TOKEN", "dev").is_ok());
        // Rotation is refused after destruction.
        assert!(matches!(
            svc.rotate_secret("TOKEN", &secret("x"), "dev"),
            Err(CoreError::SecretDestroyed(_))
        ));

        // The stored record carries the shred markers and no wrapped DEK.
        let records: Vec<_> = record_paths(fx.ctx.vault_dir(), ".json")
            .into_iter()
            .map(|p| read_record(&p))
            .collect();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].state, SecretRevisionState::Destroyed);
        assert!(records[0].shredded);
        assert_eq!(records[0].wrapped_dek_hex, "");
    }

    #[test]
    fn set_after_destroy_provisions_a_fresh_entry() {
        let fx = fixture();
        let svc = service(&fx);
        svc.set_secret("TOKEN", &secret("v1"), VariableKind::Secret, "dev", None)
            .unwrap();
        let old_metadata = svc.secret_metadata("TOKEN", "dev").unwrap();
        svc.destroy_secret("TOKEN", "dev").unwrap();

        svc.set_secret("TOKEN", &secret("v2"), VariableKind::Secret, "dev", None)
            .unwrap();
        let metadata = svc.secret_metadata("TOKEN", "dev").unwrap();
        assert_ne!(metadata.secret_id, old_metadata.secret_id);
        assert_eq!(metadata.state, SecretRevisionState::Active);
        assert_eq!(svc.reveal_secret("TOKEN", "dev").unwrap().as_slice(), b"v2");
        // Old lineage untouched.
        let old_records: Vec<_> = record_paths(
            fx.ctx.vault_dir(),
            &format!("{}.json", old_metadata.current_revision),
        )
        .into_iter()
        .map(|p| read_record(&p))
        .collect();
        assert_eq!(old_records[0].state, SecretRevisionState::Destroyed);
    }

    #[test]
    fn metadata_reports_history_states_without_values() {
        let fx = fixture();
        let svc = service(&fx);
        svc.set_secret(
            "KEY_A",
            &secret(PLAIN_ONE),
            VariableKind::Secret,
            "dev",
            None,
        )
        .unwrap();
        svc.rotate_secret("KEY_A", &secret(PLAIN_TWO), "dev")
            .unwrap();
        let metadata = svc.secret_metadata("KEY_A", "dev").unwrap();

        assert_eq!(metadata.name.as_str(), "KEY_A");
        assert_eq!(metadata.environment.as_str(), "env_dev");
        assert_eq!(metadata.state, SecretRevisionState::Active);
        assert_eq!(metadata.kind, VariableKind::Secret);
        assert!(metadata.brokered.is_none());
        assert_eq!(metadata.history.len(), 2);
        // Oldest first ordering with matching states.
        assert!(metadata.history[0].created_at <= metadata.history[1].created_at);
        assert_eq!(metadata.history[0].state, SecretRevisionState::Revoked);
        assert_eq!(metadata.history[1].state, SecretRevisionState::Active);

        // Metadata rendering never contains plaintext.
        let rendered = format!("{metadata:?}");
        assert!(!rendered.contains(PLAIN_ONE) && !rendered.contains(PLAIN_TWO));
    }

    #[test]
    fn empty_plaintext_is_refused_everywhere() {
        let fx = fixture();
        let svc = service(&fx);
        assert!(matches!(
            svc.set_secret("EMPTY", &secret(""), VariableKind::Secret, "dev", None),
            Err(CoreError::EmptySecretValue)
        ));
        svc.set_secret("REAL", &secret("value"), VariableKind::Secret, "dev", None)
            .unwrap();
        assert!(matches!(
            svc.rotate_secret("REAL", &secret(""), "dev"),
            Err(CoreError::EmptySecretValue)
        ));
    }

    #[test]
    fn unknown_names_surface_distinct_errors() {
        let fx = fixture();
        let svc = service(&fx);
        assert!(matches!(
            svc.reveal_secret("MISSING", "dev"),
            Err(CoreError::SecretNotFound(_))
        ));
        assert!(matches!(
            svc.secret_metadata("MISSING", "dev"),
            Err(CoreError::SecretNotFound(_))
        ));
        assert!(matches!(
            svc.rotate_secret("MISSING", &secret("v"), "dev"),
            Err(CoreError::SecretNotFound(_))
        ));
        assert!(matches!(
            svc.destroy_secret("MISSING", "dev"),
            Err(CoreError::SecretNotFound(_))
        ));
    }

    #[test]
    fn binding_validation_rejects_mismatches() {
        let fx = fixture();
        let svc = service(&fx);
        let binding = BrokeredBinding {
            credential_ref: CredentialRef::parse("github-token").unwrap(),
            injection: InjectionTemplateId::Bearer,
            provider_hint: None,
        };
        // Plain secret carrying a binding is inconsistent...
        assert!(matches!(
            svc.set_secret(
                "PLAIN",
                &secret("v"),
                VariableKind::Secret,
                "dev",
                Some(binding.clone())
            ),
            Err(CoreError::InconsistentBinding(_))
        ));
        // ...brokered without one too.
        assert!(matches!(
            svc.set_secret(
                "BROKERED",
                &secret("v"),
                VariableKind::Brokered,
                "dev",
                None
            ),
            Err(CoreError::InconsistentBinding(_))
        ));
        // Non-secret kinds are rejected outright.
        assert!(matches!(
            svc.set_secret("CONFIGY", &secret("v"), VariableKind::Config, "dev", None),
            Err(CoreError::InconsistentBinding(_))
        ));
    }

    #[test]
    fn brokered_binding_round_trips_with_staging_entry() {
        let fx = fixture();
        let svc = service(&fx);
        let binding = BrokeredBinding {
            credential_ref: CredentialRef::parse("github-token").unwrap(),
            injection: InjectionTemplateId::GithubBearer,
            provider_hint: Some(ProviderName::parse("github").unwrap()),
        };
        svc.set_secret(
            "GITHUB_TOKEN",
            &secret("gh-value"),
            VariableKind::Brokered,
            "dev",
            Some(binding),
        )
        .unwrap();

        assert_eq!(
            svc.reveal_secret("GITHUB_TOKEN", "dev").unwrap().as_slice(),
            b"gh-value"
        );
        let metadata = svc.secret_metadata("GITHUB_TOKEN", "dev").unwrap();
        assert_eq!(metadata.kind, VariableKind::Brokered);
        let staged = vaultx_repository::StagingIndex::load(fx.ctx.vault_dir()).unwrap();
        match staged
            .entries()
            .get(&VariableName::parse("GITHUB_TOKEN").unwrap())
        {
            Some(vaultx_repository::StagedChange::Set(ManifestEntry::Brokered {
                credential,
                ..
            })) => assert_eq!(credential.as_str(), "github-token"),
            other => panic!("expected brokered staging entry, got {other:?}"),
        }
    }

    #[test]
    fn wrong_root_key_cannot_open_existing_project_keys() {
        let fx = fixture();
        {
            let svc = service(&fx);
            svc.set_secret("K", &secret("v"), VariableKind::Secret, "dev", None)
                .unwrap();
        }
        // A fresh root store means an unrelated root key.
        let other_dir = tempfile::tempdir().unwrap();
        let wrong_store = FileKeyStore::new(other_dir.path().join("root.key"));
        let reopened = ProjectContext::open(fx.ctx.root()).unwrap();
        let svc = SecretService::with_root_store(&reopened, Arc::new(wrong_store));
        match svc.reveal_secret("K", "dev") {
            Err(CoreError::ProjectKey(reason)) => {
                assert!(reason.contains("cannot unwrap"), "got: {reason}");
            }
            other => panic!("expected ProjectKey error, got {other:?}"),
        }
        // The stored key file was not overwritten by the failed attempt.
        let stored =
            std::fs::read_to_string(fx.ctx.vault_dir().join(KEYS_DIR_NAME).join("project.json"))
                .unwrap();
        assert!(stored.contains("\"format_version\": 1"));
    }

    #[test]
    fn tampered_aad_field_rejects_decryption() {
        let fx = fixture();
        let svc = service(&fx);
        svc.set_secret(
            "TAMPER",
            &secret("payload"),
            VariableKind::Secret,
            "dev",
            None,
        )
        .unwrap();
        let metadata = svc.secret_metadata("TAMPER", "dev").unwrap();
        let path = fx
            .ctx
            .vault_dir()
            .join(SECRETS_DIR_NAME)
            .join(metadata.secret_id.as_str())
            .join(format!("{}.json", metadata.current_revision));

        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        value["aad"]["format_version"] = serde_json::json!(99);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let err = svc.reveal_secret("TAMPER", "dev").unwrap_err();
        assert!(matches!(
            err,
            CoreError::Crypto(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn tampered_wrapped_dek_rejects_unwrap() {
        let fx = fixture();
        let svc = service(&fx);
        svc.set_secret(
            "SHRED_TAMPER",
            &secret("payload"),
            VariableKind::Secret,
            "dev",
            None,
        )
        .unwrap();
        let metadata = svc.secret_metadata("SHRED_TAMPER", "dev").unwrap();
        let path = fx
            .ctx
            .vault_dir()
            .join(SECRETS_DIR_NAME)
            .join(metadata.secret_id.as_str())
            .join(format!("{}.json", metadata.current_revision));

        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        value["wrapped_dek_hex"] = serde_json::json!("00");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        let err = svc.reveal_secret("SHRED_TAMPER", "dev").unwrap_err();
        assert!(matches!(err, CoreError::Crypto(CryptoError::UnwrapFailed)));
    }

    #[test]
    fn fresh_nonce_per_write_of_the_same_value() {
        let fx = fixture();
        let svc = service(&fx);
        let first = svc
            .set_secret("NONCEY", &secret(CANARY), VariableKind::Secret, "dev", None)
            .unwrap();
        let second = svc.rotate_secret("NONCEY", &secret(CANARY), "dev").unwrap();
        let first_record =
            read_record(&record_paths(fx.ctx.vault_dir(), &format!("{}.json", first))[0]);
        let second_record =
            read_record(&record_paths(fx.ctx.vault_dir(), &format!("{}.json", second))[0]);
        assert_ne!(first_record.nonce_hex, second_record.nonce_hex);
        assert_ne!(first_record.ciphertext_hex, second_record.ciphertext_hex);
    }

    #[test]
    fn fingerprint_stable_across_rotations_distinct_across_values() {
        let fx = fixture();
        let svc = service(&fx);
        svc.set_secret(
            "STABLE",
            &secret("same-value"),
            VariableKind::Secret,
            "dev",
            None,
        )
        .unwrap();
        let fp_one = svc
            .secret_metadata("STABLE", "dev")
            .unwrap()
            .fingerprint_hex;
        svc.rotate_secret("STABLE", &secret("same-value"), "dev")
            .unwrap();
        let fp_two = svc
            .secret_metadata("STABLE", "dev")
            .unwrap()
            .fingerprint_hex;
        assert_eq!(fp_one, fp_two);

        svc.set_secret(
            "OTHER",
            &secret("different"),
            VariableKind::Secret,
            "dev",
            None,
        )
        .unwrap();
        let fp_other = svc.secret_metadata("OTHER", "dev").unwrap().fingerprint_hex;
        assert_ne!(fp_one, fp_other);
        // Fingerprints are lowercase hex SHA-256 length.
        assert_eq!(fp_one.len(), 64);
    }

    #[test]
    fn list_secrets_filters_environment_and_sorts_by_name() {
        let fx = fixture();
        let svc = service(&fx);
        svc.set_secret("B_VAR", &secret("1"), VariableKind::Secret, "dev", None)
            .unwrap();
        svc.set_secret("A_VAR", &secret("2"), VariableKind::Secret, "dev", None)
            .unwrap();
        svc.set_secret("P_VAR", &secret("3"), VariableKind::Secret, "prod", None)
            .unwrap();
        svc.rotate_secret("A_VAR", &secret("4"), "dev").unwrap();

        let dev = svc.list_secrets("dev").unwrap();
        assert_eq!(
            dev.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            vec!["A_VAR", "B_VAR"]
        );
        assert_eq!(dev[0].state, SecretRevisionState::Active);
        assert_eq!(dev[1].kind, VariableKind::Secret);
        assert_eq!(svc.list_secrets("prod").unwrap()[0].name.as_str(), "P_VAR");
        assert!(svc.list_secrets("staging").unwrap().is_empty());
    }

    #[test]
    fn canary_value_never_leaks_through_errors_or_debug_output() {
        let fx = fixture();
        let svc = service(&fx);
        svc.set_secret("LEAKY", &secret(CANARY), VariableKind::Secret, "dev", None)
            .unwrap();
        svc.rotate_secret("LEAKY", &secret(CANARY), "dev").unwrap();

        // Successful paths return redacted types only.
        assert!(!format!("{:?}", secret(CANARY)).contains(CANARY));
        let revealed = svc.reveal_secret("LEAKY", "dev").unwrap();
        assert!(!format!("{revealed:?}").contains(CANARY));

        // Error renderings across every failure class.
        let mut rendered = String::new();
        rendered.push_str(&format!(
            "{:?}",
            svc.reveal_secret("MISSING", "dev").unwrap_err()
        ));
        rendered.push_str(&svc.reveal_secret("MISSING", "dev").unwrap_err().to_string());
        rendered.push_str(&format!(
            "{:?}",
            svc.set_secret("X", &secret(""), VariableKind::Secret, "dev", None)
                .unwrap_err()
        ));
        rendered.push_str(
            &svc.set_secret("X", &secret(""), VariableKind::Secret, "dev", None)
                .unwrap_err()
                .to_string(),
        );
        rendered.push_str(&format!(
            "{:?}",
            svc.secret_metadata("MISSING", "dev").unwrap_err()
        ));
        svc.destroy_secret("LEAKY", "dev").unwrap();
        rendered.push_str(&format!(
            "{:?}",
            svc.reveal_secret("LEAKY", "dev").unwrap_err()
        ));
        rendered.push_str(&svc.reveal_secret("LEAKY", "dev").unwrap_err().to_string());

        // Wrong-root-key failure rendering.
        let other_dir = tempfile::tempdir().unwrap();
        let reopened = ProjectContext::open(fx.ctx.root()).unwrap();
        let wrong = SecretService::with_root_store(
            &reopened,
            Arc::new(FileKeyStore::new(other_dir.path().join("other.key"))),
        );
        rendered.push_str(&format!(
            "{:?}",
            wrong.reveal_secret("LEAKY", "dev").unwrap_err()
        ));

        assert!(!rendered.contains(CANARY), "canary leaked via errors");

        // Nothing on disk under .vaultx embeds the plaintext either.
        let mut blob = Vec::new();
        collect_bytes(fx.ctx.vault_dir(), &mut blob);
        let needle = CANARY.as_bytes();
        assert!(!blob.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn inv001_plaintext_never_enters_the_content_addressed_object_store() {
        let fx = fixture();
        let svc = service(&fx);
        svc.set_secret(
            "INV001",
            &secret(CANARY),
            VariableKind::Brokered,
            "dev",
            Some(BrokeredBinding {
                credential_ref: CredentialRef::parse("inv-cred").unwrap(),
                injection: InjectionTemplateId::ApiKeyHeader,
                provider_hint: None,
            }),
        )
        .unwrap();
        // Commit so the content-addressed store holds real objects
        // (manifest + commit) that could have swallowed the value.
        crate::history::HistoryService::new(&fx.ctx)
            .commit("inv001 probe", "user:t")
            .unwrap();

        let objects_dir = fx.ctx.vault_dir().join("objects");
        let mut blob = Vec::new();
        collect_bytes(&objects_dir, &mut blob);
        assert!(!blob.is_empty(), "objects must exist after commit");
        let needle = CANARY.as_bytes();
        assert!(!blob.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn cache_is_keyed_to_the_provider_that_populated_it() {
        let fx = fixture();
        // Both providers stay alive for the whole test: identity is a
        // live Arc comparison (Arc::ptr_eq), not an address that could be
        // recycled by the allocator.
        let first = service(&fx);
        let other_dir = tempfile::tempdir().unwrap();
        let second_provider: Arc<dyn WrappingKeyProvider> =
            Arc::new(FileKeyStore::new(other_dir.path().join("root.key")));
        assert!(!Arc::ptr_eq(&second_provider, &first.root_store));

        first
            .set_secret("K", &secret("v"), VariableKind::Secret, "dev", None)
            .unwrap();

        // A second provider with unrelated root material over the SAME
        // context must not silently reuse the first provider's cached
        // keys; it has to reload and then fails loudly.
        let second = SecretService::with_root_store(&fx.ctx, Arc::clone(&second_provider));
        match second.reveal_secret("K", "dev") {
            Err(CoreError::ProjectKey(_)) => {}
            other => panic!("expected ProjectKey error, got {other:?}"),
        }

        // The original provider still works off its cache entry.
        assert!(first.reveal_secret("K", "dev").is_ok());
    }

    #[test]
    fn same_provider_reuses_cached_keys_without_reload() {
        let fx = fixture();
        let svc = service(&fx);
        svc.set_secret("K", &secret("v"), VariableKind::Secret, "dev", None)
            .unwrap();
        assert!(svc.reveal_secret("K", "dev").is_ok(), "cache populated");

        // Remove the persisted bundle behind the cache's back. A cache
        // hit must serve subsequent operations from memory alone; a
        // reload would fail on the missing file.
        std::fs::remove_file(fx.ctx.vault_dir().join(KEYS_DIR_NAME).join("project.json")).unwrap();
        assert!(
            svc.reveal_secret("K", "dev").is_ok(),
            "same provider must reuse its cached keys"
        );
    }

    #[test]
    fn malformed_project_key_material_errors_as_project_key() {
        let fx = fixture();
        service(&fx)
            .set_secret("K", &secret("v"), VariableKind::Secret, "dev", None)
            .unwrap();
        let path = fx.ctx.vault_dir().join(KEYS_DIR_NAME).join("project.json");
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        value["project_ciphertext_hex"] = serde_json::json!("zz-not-hex");
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

        // Fresh provider identity forces a reload from disk.
        let svc = service(&fx);
        match svc.reveal_secret("K", "dev") {
            Err(CoreError::ProjectKey(reason)) => {
                assert!(reason.contains("malformed"), "got: {reason}");
            }
            other => panic!("expected ProjectKey error, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn revision_records_and_project_keys_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let fx = fixture();
        service(&fx)
            .set_secret("PERMS", &secret("v"), VariableKind::Secret, "dev", None)
            .unwrap();

        let metadata = service(&fx).secret_metadata("PERMS", "dev").unwrap();
        let record = fx
            .ctx
            .vault_dir()
            .join(SECRETS_DIR_NAME)
            .join(metadata.secret_id.as_str())
            .join(format!("{}.json", metadata.current_revision));
        let record_mode = std::fs::metadata(record).unwrap().permissions().mode();
        assert_eq!(record_mode & 0o777, 0o600);

        let keys = fx.ctx.vault_dir().join(KEYS_DIR_NAME).join("project.json");
        let keys_mode = std::fs::metadata(keys).unwrap().permissions().mode();
        assert_eq!(keys_mode & 0o777, 0o600);
    }

    fn collect_bytes(dir: &Path, out: &mut Vec<u8>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_bytes(&path, out);
            } else if let Ok(bytes) = std::fs::read(&path) {
                out.extend_from_slice(&bytes);
            }
        }
    }
}
