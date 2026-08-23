//! Root wrapping-key storage for vaultx.
//!
//! [`WrappingKeyProvider`] is the seam between the envelope key
//! hierarchy ([`vaultx_crypto::envelope`]) and wherever the 32-byte root
//! wrapping key actually lives: an OS keychain, a KMS/HSM, or (development
//! only) a plain file. Higher layers depend on the trait alone, so the
//! production backend swaps in behind identical signatures.
//!
//! Implementations provided here:
//!
//! - [`InMemoryKeyStore`]: process-lifetime storage for tests.
//! - [`FileKeyStore`]: **development fallback** storing the root key
//!   hex-encoded in one file with owner-only permissions. This does **not**
//!   satisfy the strict threat model — any process running as the same user
//!   can read the file, and backups leak it verbatim. An OS-keychain-backed
//!   provider (macOS Keychain / Windows Credential Manager / Linux Secret
//!   Service) is the production path behind the same trait; the `keyring`
//!   ecosystem crate is deliberately not pulled in here to avoid its
//!   system-library dependencies.
//!
//! Errors reuse [`CryptoError`] (always the [`CryptoError::ProviderError`]
//! variant) so callers handle a single error family end-to-end; payloads
//! never contain key material.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rand_core::{OsRng, RngCore};
use vaultx_crypto::envelope::RootKey;
use vaultx_crypto::error::{CryptoError, CryptoResult};

/// Access to a workspace's 32-byte root wrapping key.
///
/// `obtain` is the write-tolerant read used by provisioning flows: it
/// creates and persists a fresh key on first use. `load` is the strict
/// read used everywhere else: a missing key is an error, never something
/// silently replaced.
pub trait WrappingKeyProvider: Send + Sync {
    /// Returns the root wrapping key, creating it on first use.
    ///
    /// # Errors
    /// Propagates provider/storage failures.
    fn obtain(&self) -> CryptoResult<RootKey>;

    /// Returns the previously created root wrapping key without creating
    /// one.
    ///
    /// # Errors
    /// A missing or corrupt key surfaces as [`CryptoError::ProviderError`].
    fn load(&self) -> CryptoResult<RootKey>;
}

/// In-memory [`WrappingKeyProvider`] holding one root key per process.
///
/// The key is generated lazily by [`WrappingKeyProvider::obtain`] and lost
/// when the store drops. Intended for tests and ephemeral tooling only.
pub struct InMemoryKeyStore {
    key: Mutex<Option<RootKey>>,
}

impl InMemoryKeyStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            key: Mutex::new(None),
        }
    }
}

impl Default for InMemoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for InMemoryKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryKeyStore")
            .field("key", &"<redacted>")
            .finish()
    }
}

impl WrappingKeyProvider for InMemoryKeyStore {
    fn obtain(&self) -> CryptoResult<RootKey> {
        let mut slot = self
            .key
            .lock()
            .map_err(|_| CryptoError::ProviderError("in-memory key store poisoned".to_owned()))?;
        match slot.as_ref() {
            Some(key) => Ok(key.expose(RootKey::from_bytes)),
            None => {
                let key = RootKey::generate();
                *slot = Some(key.expose(RootKey::from_bytes));
                Ok(key)
            }
        }
    }

    fn load(&self) -> CryptoResult<RootKey> {
        let slot = self
            .key
            .lock()
            .map_err(|_| CryptoError::ProviderError("in-memory key store poisoned".to_owned()))?;
        slot.as_ref()
            .map(|key| key.expose(RootKey::from_bytes))
            .ok_or_else(|| {
                CryptoError::ProviderError("no root wrapping key has been created yet".to_owned())
            })
    }
}

/// File-backed [`WrappingKeyProvider`] storing the root key hex-encoded
/// at a fixed path with owner-only permissions (`0600` on unix).
///
/// # Development fallback
///
/// This store does **not** satisfy the strict threat model: the key sits
/// unencrypted on disk, readable by anything running as the owning user,
/// and leaks through filesystem backups. It exists so local projects work
/// out of the box; production deployments must supply an OS-keychain- or
/// KMS-backed implementation of [`WrappingKeyProvider`].
///
/// Corruption handling is deliberately conservative: an unreadable or
/// malformed key file is an error on every operation and is never
/// rewritten automatically — replacing a root key invalidates every
/// wrapped project key, so that decision belongs to the operator.
#[derive(Debug)]
pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    /// Creates a store rooted at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The backing file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl WrappingKeyProvider for FileKeyStore {
    fn obtain(&self) -> CryptoResult<RootKey> {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        // Exclusive create: two concurrent initializations must not fork
        // the vault by both "winning" the exists() check and truncating
        // each other's key. Losing the race adopts the stored key.
        match create_private_file_exclusive(&self.path, &format!("{}\n", hex::encode(bytes))) {
            Ok(()) => Ok(RootKey::from_bytes(&bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => self.load(),
            Err(err) => Err(CryptoError::ProviderError(format!(
                "cannot create {}: {err}",
                self.path.display()
            ))),
        }
    }

    fn load(&self) -> CryptoResult<RootKey> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(CryptoError::ProviderError(format!(
                    "no root wrapping key file at {}",
                    self.path.display()
                )));
            }
            Err(err) => {
                return Err(CryptoError::ProviderError(format!(
                    "cannot read {}: {err}",
                    self.path.display()
                )));
            }
        };
        let bytes = decode_key_text(&text, &self.path)?;
        // Defense in depth: re-assert owner-only mode on every load in
        // case an external process loosened it between sessions.
        enforce_private_permissions(&self.path).map_err(|err| {
            CryptoError::ProviderError(format!(
                "cannot tighten permissions on {}: {err}",
                self.path.display()
            ))
        })?;
        Ok(RootKey::from_bytes(&bytes))
    }
}

fn decode_key_text(text: &str, path: &Path) -> CryptoResult<[u8; 32]> {
    let corrupt = |reason: String| {
        CryptoError::ProviderError(format!(
            "root key file {} is unusable ({reason}); refusing to overwrite it",
            path.display()
        ))
    };
    let bytes = hex::decode(text.trim()).map_err(|err| corrupt(format!("not hex: {err}")))?;
    bytes
        .try_into()
        .map_err(|raw: Vec<u8>| corrupt(format!("expected 32 bytes, found {}", raw.len())))
}

/// Creates `path` with `contents` only if it does not exist yet, with
/// owner-only permissions on unix. Fails with
/// [`std::io::ErrorKind::AlreadyExists`] when another writer got there
/// first.
fn create_private_file_exclusive(path: &Path, contents: &str) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        // Best-effort emulation where the exclusive-create mode flag is
        // unavailable; the check-then-write window is platform-limited.
        if path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "key file already exists",
            ));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, contents)
    }
}

fn enforce_private_permissions(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_store_obtains_once_then_loads_same_key() {
        let store = InMemoryKeyStore::new();
        assert!(
            matches!(store.load(), Err(CryptoError::ProviderError(_))),
            "load before create must fail"
        );
        let obtained = store.obtain().expect("obtain");
        let loaded = store.load().expect("load");
        assert!(loaded.expose(|a| obtained.expose(|b| a == b)));
        let again = store.obtain().expect("re-obtain");
        assert!(again.expose(|a| obtained.expose(|b| a == b)));
    }

    #[test]
    fn debug_output_never_contains_key_material() {
        let rendered = format!("{:?}", InMemoryKeyStore::new());
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains('\u{0}'));
    }

    #[test]
    fn file_store_round_trips_and_persists_across_instances() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys").join("root.key");
        let created = FileKeyStore::new(&path).obtain().expect("create");
        assert!(path.exists());

        let reloaded = FileKeyStore::new(&path).load().expect("reload");
        assert!(reloaded.expose(|a| created.expose(|b| a == b)));

        // obtain on an existing file must return the stored key, not a
        // fresh one.
        let again = FileKeyStore::new(&path).obtain().expect("obtain existing");
        assert!(again.expose(|a| created.expose(|b| a == b)));
    }

    #[cfg(unix)]
    #[test]
    fn file_store_enforces_owner_only_permissions_on_create_and_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root.key");

        FileKeyStore::new(&path).obtain().expect("create");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        // Loosen behind the store's back; the next load re-asserts 0600.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        FileKeyStore::new(&path).load().expect("load");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn corrupt_file_errors_and_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root.key");
        std::fs::write(&path, "definitely-not-hex!\n").unwrap();

        for op in ["obtain", "load"] {
            let err = match op {
                "obtain" => FileKeyStore::new(&path).obtain().unwrap_err(),
                _ => FileKeyStore::new(&path).load().unwrap_err(),
            };
            assert!(matches!(err, CryptoError::ProviderError(msg) if msg.contains("unusable")));
        }

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, "definitely-not-hex!\n", "file must be untouched");
    }

    #[test]
    fn wrong_length_file_errors_without_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root.key");
        std::fs::write(&path, format!("{}\n", hex::encode([7u8; 16]))).unwrap();
        let err = FileKeyStore::new(&path).load().unwrap_err();
        assert!(
            matches!(err, CryptoError::ProviderError(ref msg) if msg.contains("expected 32 bytes")),
            "got: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            hex::encode([7u8; 16])
        );
    }

    #[test]
    fn load_before_creation_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = FileKeyStore::new(dir.path().join("absent.key"))
            .load()
            .unwrap_err();
        assert!(
            matches!(err, CryptoError::ProviderError(ref msg) if msg.contains("no root wrapping key file")),
            "got: {err}"
        );
    }

    #[test]
    fn obtain_adopts_the_stored_key_when_creation_races() {
        // Simulates losing the exclusive-create race: the file already
        // holds a key, so obtain must return it rather than forking a
        // fresh one over it.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root.key");
        std::fs::write(&path, format!("{}\n", hex::encode([0x42u8; 32]))).unwrap();

        let key = FileKeyStore::new(&path).obtain().expect("obtain existing");
        assert!(key.expose(|bytes| bytes == &[0x42u8; 32]));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap().trim(),
            hex::encode([0x42u8; 32]),
            "stored key must be untouched"
        );
    }
}
