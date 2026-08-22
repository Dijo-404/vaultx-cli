//! Content-addressed filesystem object store.
//!
//! Objects live under `<root>/sha256/<ab>/<remaining 62 hex chars>`, where
//! `ab` is the first two characters of the object's SHA-256 digest. Writes
//! are atomic (temp file + `rename`) and reads always re-hash the stored
//! bytes, so any on-disk tampering is detected as
//! [`RepoError::CorruptObject`]. The store is content-addressed: it refuses
//! to overwrite an existing path with different content.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use vaultx_types::ObjectId;

use crate::error::RepoError;
use crate::object::{hash_canonical, ObjectEnvelope, OBJECT_FORMAT_VERSION};

/// Filesystem-backed content-addressed object store.
#[derive(Clone, Debug)]
pub struct FileSystemObjectStore {
    root: PathBuf,
}

impl FileSystemObjectStore {
    /// Creates a store handle rooted at `root` (typically
    /// `.vaultx/objects`). No directories are created until first use.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Root directory of this store.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// On-disk path for `id`: `<root>/sha256/<2-char dir>/<62-char rest>`.
    ///
    /// Only well-formed 64-hex digests can ever exist on disk, so a
    /// malformed ID reports [`RepoError::ObjectNotFound`] rather than
    /// corruption — nothing can be stored under such an address.
    fn path_for(&self, id: &ObjectId) -> Result<PathBuf, RepoError> {
        let digest = id
            .as_str()
            .strip_prefix(ObjectId::PREFIX)
            .ok_or_else(|| RepoError::ObjectNotFound(id.clone()))?;
        if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(RepoError::ObjectNotFound(id.clone()));
        }
        let mut path = self.root.join("sha256").join(&digest[..2]);
        path.push(&digest[2..]);
        Ok(path)
    }

    /// Stores `envelope` and returns its content-derived [`ObjectId`].
    ///
    /// Writing is atomic: bytes go to a uniquely named temp file in the
    /// target directory followed by `rename`. If an object with the same ID
    /// already exists it must contain identical canonical bytes — anything
    /// else is treated as corruption and refused.
    ///
    /// # Errors
    /// * [`RepoError::CorruptObject`] when existing content at the target
    ///   path differs from what this call would write.
    /// * [`RepoError::Io`] on filesystem failures.
    pub fn put(&self, envelope: &ObjectEnvelope) -> Result<ObjectId, RepoError> {
        if envelope.format != OBJECT_FORMAT_VERSION {
            return Err(RepoError::ManifestMismatch(format!(
                "unsupported envelope format {} (expected {OBJECT_FORMAT_VERSION})",
                envelope.format
            )));
        }
        let canonical = envelope.canonical_bytes()?;
        let id = crate::object::object_id(&canonical)?;
        let path = self.path_for(&id)?;

        if path.exists() {
            let existing = fs::read(&path)?;
            return if existing == canonical {
                Ok(id) // Idempotent re-store of identical content.
            } else {
                Err(RepoError::CorruptObject {
                    id,
                    reason: "refusing overwrite: existing content differs".to_owned(),
                })
            };
        }

        fs::create_dir_all(path.parent().expect("path has parent"))?;
        let temp_path = path.with_file_name(format!(
            ".tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        {
            let mut file = fs::File::create(&temp_path)?;
            file.write_all(&canonical)?;
            file.sync_all()?;
        }
        // Atomic publication; replace-on-race is safe because both writers
        // hold identical canonical bytes for this ID.
        fs::rename(&temp_path, &path)?;
        Ok(id)
    }

    /// Loads the object with hash verification over the raw stored bytes.
    ///
    /// # Errors
    /// * [`RepoError::ObjectNotFound`] when no object exists under `id`.
    /// * [`RepoError::CorruptObject`] when stored bytes fail hash or decode
    ///   verification.
    ///
    /// # Concurrency note (TOCTOU)
    /// If a concurrent process removes the object after the existence
    /// check, the read fails with `Io(NotFound)`; under content addressing
    /// this is benign (the content is gone, not damaged).
    pub fn get(&self, id: &ObjectId) -> Result<ObjectEnvelope, RepoError> {
        let path = self.path_for(id)?;
        if !path.exists() {
            return Err(RepoError::ObjectNotFound(id.clone()));
        }
        let stored = fs::read(&path)?;

        // Integrity gate #1: hash of file bytes must equal the ID's digest.
        // The ID itself encodes the expected digest (obj_<64 hex>).
        let expected_hex = &id.as_str()[ObjectId::PREFIX.len()..];
        let actual_hex = hex::encode(hash_canonical(&stored));
        if actual_hex != expected_hex {
            return Err(RepoError::CorruptObject {
                id: id.clone(),
                reason: format!("sha256 mismatch (found {actual_hex})"),
            });
        }

        // Integrity gate #2: bytes must decode as a well-formed envelope.
        let envelope: ObjectEnvelope =
            serde_json::from_slice(&stored).map_err(|e| RepoError::CorruptObject {
                id: id.clone(),
                reason: format!("payload does not decode: {e}"),
            })?;
        Ok(envelope)
    }

    /// True when an object with this ID exists on disk.
    ///
    /// # Concurrency note (TOCTOU)
    /// Under a concurrent writer a checked path may vanish between this
    /// probe and a subsequent [`FileSystemObjectStore::get`]; that read
    /// then fails with a benign `Io(NotFound)` — content addressing makes
    /// such objects unrecoverable-by-design, never partially readable.
    #[must_use]
    pub fn exists(&self, id: &ObjectId) -> bool {
        self.path_for(id).is_ok_and(|p| p.exists())
    }

    /// Verifies every object in the store: each stored file's SHA-256 must
    /// match its content-addressed location and decode as an envelope.
    ///
    /// Only genuine object entries are considered: shard directories hold
    /// exactly `<2-hex>/<62-hex>` files, so dot-prefixed leftovers (e.g.
    /// `.tmp-<pid>-<nanos>` from a crashed writer) and any non-hex names
    /// are skipped rather than misparsed.
    ///
    /// Traversal order is deterministic (sorted paths) so repeated runs
    /// report the same first failure.
    ///
    /// # Errors
    /// The first corrupt or unreadable object encountered.
    pub fn verify_all(&self) -> Result<(), RepoError> {
        let shard_root = self.root.join("sha256");
        if !shard_root.exists() {
            return Ok(()); // Empty store verifies trivially.
        }
        let mut shards: Vec<_> = fs::read_dir(&shard_root)?.filter_map(|e| e.ok()).collect();
        shards.sort_by_key(|entry| entry.file_name());
        for shard in shards {
            let shard_name = shard.file_name().to_string_lossy().into_owned();
            if !is_hex_of_len(&shard_name, 2) {
                continue; // Stray directory, not a shard.
            }
            let mut objects: Vec<_> = fs::read_dir(shard.path())?.filter_map(|e| e.ok()).collect();
            objects.sort_by_key(|entry| entry.file_name());
            for object in objects {
                let name = object.file_name().to_string_lossy().into_owned();
                // Skip crash leftovers (.tmp-...) and anything that is not
                // a real <hex-62> object file.
                if name.starts_with('.') || !is_hex_of_len(&name, 62) {
                    continue;
                }
                let id = ObjectId::parse(&format!("{}{shard_name}{name}", ObjectId::PREFIX))?;
                self.get(&id)?;
            }
        }
        Ok(())
    }
}

/// True when `value` is exactly `len` lowercase hex characters.
fn is_hex_of_len(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, FileSystemObjectStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemObjectStore::new(dir.path().join("objects"));
        (dir, store)
    }

    fn sample_envelope(payload: &[u8]) -> ObjectEnvelope {
        ObjectEnvelope::new(crate::object::ObjectType::ConfigValue, payload.to_vec())
    }

    #[test]
    fn put_and_get_round_trip_is_stable() {
        let (_guard, store) = temp_store();
        let envelope = sample_envelope(br#"{"value":"hello"}"#);

        let first = store.put(&envelope).unwrap();
        let second = store.put(&envelope).unwrap(); // Idempotent.
        assert_eq!(first, second);
        assert!(first.as_str().starts_with("obj_"));

        let loaded = store.get(&first).unwrap();
        assert_eq!(loaded, envelope);
        assert!(store.exists(&first));
    }

    #[test]
    fn storage_layout_uses_two_char_shard_dirs() {
        let (_guard, store) = temp_store();
        let envelope = sample_envelope(b"layout");
        let id = store.put(&envelope).unwrap();

        let digest = &id.as_str()["obj_".len()..];
        let expected = store
            .root()
            .join("sha256")
            .join(&digest[..2])
            .join(&digest[2..]);
        assert!(
            expected.is_file(),
            "expected object at {}",
            expected.display()
        );
    }

    #[test]
    fn get_missing_object_is_object_not_found() {
        let (_guard, store) = temp_store();
        let missing = ObjectId::parse("obj_deadbeef").unwrap();
        assert!(matches!(
            store.get(&missing),
            Err(RepoError::ObjectNotFound(_))
        ));
        assert!(!store.exists(&missing));
    }

    #[test]
    fn tampered_file_fails_hash_verification() {
        let (_guard, store) = temp_store();
        let envelope = sample_envelope(b"original bytes");
        let id = store.put(&envelope).unwrap();

        // Corrupt the stored file directly (simulating on-disk tampering).
        let digest = &id.as_str()["obj_".len()..];
        let path = store
            .root()
            .join("sha256")
            .join(&digest[..2])
            .join(&digest[2..]);
        std::fs::write(&path, b"tampered bytes").unwrap();

        match store.get(&id) {
            Err(RepoError::CorruptObject { reason, .. }) => {
                assert!(reason.contains("mismatch"), "reason was: {reason}");
            }
            other => panic!("expected corruption error, got {other:?}"),
        }
    }

    #[test]
    fn put_refuses_overwrite_with_different_content() {
        let (_guard, store) = temp_store();
        let id = store.put(&sample_envelope(b"good")).unwrap();

        // Plant different content under the same content address.
        let digest = &id.as_str()["obj_".len()..];
        let path = store
            .root()
            .join("sha256")
            .join(&digest[..2])
            .join(&digest[2..]);
        std::fs::write(&path, b"planted different content").unwrap();

        match store.put(&sample_envelope(b"good")) {
            Err(RepoError::CorruptObject { reason, .. }) => {
                assert!(reason.contains("refusing overwrite"));
            }
            other => panic!("expected refusal, got {other:?}"),
        }
    }

    #[test]
    fn verify_all_passes_on_clean_store_and_flags_corruption() {
        let (_guard, store) = temp_store();
        store.put(&sample_envelope(b"a")).unwrap();
        store.put(&sample_envelope(b"b")).unwrap();
        store
            .put(&crate::object::ObjectEnvelope::new(
                crate::object::ObjectType::Manifest,
                br#"{"entries":{}}"#.to_vec(),
            ))
            .unwrap();
        store.verify_all().expect("clean store must verify");

        // Tamper with one object.
        let tampered_id = store.put(&sample_envelope(b"c")).unwrap();
        let digest = &tampered_id.as_str()[4..];
        let path = store
            .root()
            .join("sha256")
            .join(&digest[..2])
            .join(&digest[2..]);
        std::fs::write(&path, b"corrupted").unwrap();

        assert!(matches!(
            store.verify_all(),
            Err(RepoError::CorruptObject { .. })
        ));
    }

    #[test]
    fn verify_all_tolerates_empty_store() {
        let (_guard, store) = temp_store();
        store.verify_all().expect("empty store verifies");
    }

    #[test]
    fn verify_all_ignores_leftover_temp_files_and_strays() {
        let (_guard, store) = temp_store();
        let id = store.put(&sample_envelope(b"real object")).unwrap();
        store.verify_all().expect("clean store verifies");

        // Simulate a crashed writer: temp file left inside a shard dir.
        let digest = &id.as_str()[4..];
        let shard_dir = store.root().join("sha256").join(&digest[..2]);
        std::fs::write(shard_dir.join(".tmp-123-456"), b"partial bytes").unwrap();

        // And a couple of unrelated strays at other levels.
        std::fs::write(store.root().join("sha256").join("zz"), b"not a shard").unwrap();
        let other_shard = store.root().join("sha256").join(&digest[..2]);
        std::fs::write(other_shard.join("NOTHEX"), b"garbage").unwrap();

        // The sweep must succeed: only genuine <hex62> objects are checked.
        store
            .verify_all()
            .expect("temp leftovers must not break verify_all");
        assert!(store.get(&id).is_ok(), "real object still readable");
    }

    #[test]
    fn rejects_malformed_ids_as_unaddressable() {
        let (_guard, store) = temp_store();
        // Valid prefix but non-hex content cannot be produced through the
        // public API of vaultx-types, so exercise the private guard via a
        // hand-built id string through parse (lowercase alnum passes there).
        // Such an id is simply unaddressable: nothing can exist there.
        let weird = ObjectId::parse("obj_zzzz").unwrap();
        assert!(matches!(
            store.get(&weird),
            Err(RepoError::ObjectNotFound(_))
        ));
        assert!(!store.exists(&weird));
    }

    #[test]
    fn rejects_unsupported_envelope_format() {
        let (_guard, store) = temp_store();
        let bad = ObjectEnvelope {
            format: 99,
            ..sample_envelope(b"x")
        };
        assert!(matches!(
            store.put(&bad),
            Err(RepoError::ManifestMismatch(_))
        ));
    }
}
