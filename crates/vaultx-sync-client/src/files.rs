//! Hardened local-file helpers shared by every surface that stores
//! control-plane state (session token, remote config, device key, sync
//! watermark).
//!
//! Writes are atomic (exclusive owner-only temp file + rename) so
//! concurrent readers never observe torn JSON; secret destinations get an
//! owner-only (0700) directory first.

use std::path::{Path, PathBuf};

/// Fresh unpredictable temp-file candidate next to `path` (never a
/// symlink target: creation uses `create_new`, which refuses existing
/// entries including symlinks).
fn tmp_candidate(path: &Path) -> PathBuf {
    let mut entropy = [0u8; 8];
    getrandom::getrandom(&mut entropy).expect("OS randomness unavailable");
    let name = path
        .file_name()
        .map_or_else(|| "file".to_owned(), |n| n.to_string_lossy().into_owned());
    path.with_file_name(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        hex::encode(entropy)
    ))
}

/// Writes `contents` to `path` atomically: creates an exclusive
/// (`create_new`) owner-only temp file via `candidate` and renames it
/// over the destination. Name collisions are retried with fresh
/// candidates; any other error aborts.
///
/// # Errors
/// Propagates filesystem failures.
pub fn write_atomic_via<F>(
    path: &Path,
    contents: &str,
    mut candidate: F,
) -> Result<(), std::io::Error>
where
    F: FnMut() -> PathBuf,
{
    for _ in 0..16 {
        let tmp = candidate();
        #[cfg(unix)]
        let opened = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
        };
        #[cfg(not(unix))]
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp);
        match opened {
            Ok(mut file) => {
                use std::io::Write as _;
                file.write_all(contents.as_bytes())?;
                drop(file);
                return match std::fs::rename(&tmp, path) {
                    Ok(()) => Ok(()),
                    Err(err) => {
                        let _ = std::fs::remove_file(&tmp);
                        Err(err)
                    }
                };
            }
            // Predicted name lost a race (or was planted): try a new one.
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::other(
        "could not create a unique temporary file after 16 attempts",
    ))
}

/// Writes `contents` atomically (exclusive temp file + rename) so
/// concurrent readers never observe torn JSON.
///
/// # Errors
/// Propagates filesystem failures.
pub fn write_atomic(path: &Path, contents: &str) -> Result<(), std::io::Error> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("configuration path has no parent directory"))?;
    std::fs::create_dir_all(parent)?;
    write_atomic_via(path, contents, || tmp_candidate(path))
}

/// Ensures `dir` exists with owner-only permissions (0700 on unix) —
/// applied to the runtime session directory before any token lands
/// there.
///
/// # Errors
/// Propagates filesystem failures and permission tightening failures.
pub fn ensure_private_dir(dir: &Path) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(dir)?;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
    Ok(())
}

/// Writes secret material (`path`, `contents`) atomically into an
/// owner-only private directory.
///
/// # Errors
/// Propagates filesystem failures.
pub fn write_private(path: &Path, contents: &str) -> Result<(), std::io::Error> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("secret path has no parent directory"))?;
    ensure_private_dir(parent)?;
    write_atomic(path, contents)
}
