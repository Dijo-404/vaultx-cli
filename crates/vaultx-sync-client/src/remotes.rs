//! `.vaultx/remote.json` — the token-free record of which control plane
//! each named remote points at and which project it mirrors.
//!
//! One reader lives here so the CLI and the TUI cannot drift apart on
//! parsing or resolution rules. The file deliberately carries only
//! non-secret coordinates (server URL, project id); the session token
//! never enters any repository file (see [`crate::session`]).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::files::write_atomic;
use crate::setup_error::{io_message, SyncSetupError, SyncSetupResult};

/// Name assumed by `push`/`pull`/`sync` when no remote is requested and
/// more than one remote exists.
pub const DEFAULT_REMOTE_NAME: &str = "origin";

/// Conventional remote configuration file inside `.vaultx`.
const REMOTE_FILE: &str = "remote.json";

/// One named remote: where the control plane is and which project this
/// repository synchronizes with. Deliberately token-free.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteEntry {
    /// Base URL of the control plane.
    pub server: String,
    /// Typed project id on the control plane.
    pub project_id: String,
}

/// Contents of `.vaultx/remote.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteConfig {
    /// Named remotes in insertion-stable (BTree) order.
    #[serde(default)]
    pub remotes: BTreeMap<String, RemoteEntry>,
}

/// Path of the remote configuration for a project vault dir.
#[must_use]
pub fn remote_config_path(vault_dir: &Path) -> PathBuf {
    vault_dir.join(REMOTE_FILE)
}

/// Reads `.vaultx/remote.json`. A missing file is an empty configuration
/// (never an error); a corrupt one is a hard error because silently
/// ignoring it would hide misconfiguration.
///
/// # Errors
/// [`SyncSetupError::Io`] when the file exists but cannot be read or
/// parsed; the message names the file.
pub fn load_remote_config(vault_dir: &Path) -> SyncSetupResult<RemoteConfig> {
    let path = remote_config_path(vault_dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RemoteConfig::default());
        }
        Err(err) => return Err(SyncSetupError::Io(err)),
    };
    serde_json::from_str(&text).map_err(|err| {
        io_message(format!(
            "remote config `{}` is corrupt ({err}); delete it and re-run `vaultx remote add`",
            path.display()
        ))
    })
}

/// Writes `.vaultx/remote.json` atomically.
///
/// # Errors
/// [`SyncSetupError::Io`] on serialization or filesystem failure.
pub fn save_remote_config(vault_dir: &Path, config: &RemoteConfig) -> SyncSetupResult<()> {
    let json = serde_json::to_string_pretty(config)
        .map_err(|_| io_message("remote config serialization failed"))?;
    write_atomic(&remote_config_path(vault_dir), &json).map_err(SyncSetupError::Io)
}

/// Resolves the remote entry to use: an explicit name must exist; an
/// omitted name resolves `origin` first, then falls back to the sole
/// configured remote.
///
/// # Errors
/// [`SyncSetupError::Usage`] when nothing resolvable is configured.
pub fn resolve_remote(
    vault_dir: &Path,
    requested: Option<&str>,
) -> SyncSetupResult<(String, RemoteEntry)> {
    let config = load_remote_config(vault_dir)?;
    match requested {
        Some(name) => config.remotes.get(name).map_or_else(
            || {
                Err(SyncSetupError::Usage(format!(
                    "no remote named `{name}`; run `vaultx remote list`"
                )))
            },
            |entry| Ok((name.to_owned(), entry.clone())),
        ),
        None => {
            if let Some(entry) = config.remotes.get(DEFAULT_REMOTE_NAME) {
                return Ok((DEFAULT_REMOTE_NAME.to_owned(), entry.clone()));
            }
            if config.remotes.len() == 1 {
                let (name, entry) = config
                    .remotes
                    .iter()
                    .next()
                    .expect("exactly one remote checked");
                return Ok((name.clone(), entry.clone()));
            }
            Err(SyncSetupError::Usage(
                "no remote configured; run `vaultx remote add <NAME> --project <PROJECT_ID>`"
                    .to_owned(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(server: &str, project: &str) -> RemoteEntry {
        RemoteEntry {
            server: server.to_owned(),
            project_id: project.to_owned(),
        }
    }

    #[test]
    fn config_round_trips_and_missing_files_default_to_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Missing file reads as an empty configuration.
        assert_eq!(
            load_remote_config(dir.path()).expect("missing file is empty config"),
            RemoteConfig::default()
        );

        let mut config = RemoteConfig::default();
        config.remotes.insert(
            "origin".to_owned(),
            entry("https://cp.example.com", "proj_x"),
        );
        save_remote_config(dir.path(), &config).expect("save");

        let loaded = load_remote_config(dir.path()).expect("reload");
        assert_eq!(
            loaded.remotes.get("origin").expect("origin"),
            &entry("https://cp.example.com", "proj_x")
        );
    }

    #[test]
    fn resolve_remote_prefers_origin_then_sole_remote_then_refuses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = dir.path();

        let mut config = RemoteConfig::default();
        config
            .remotes
            .insert("eu".to_owned(), entry("https://eu", "proj_eu"));
        save_remote_config(vault, &config).expect("save");

        // Sole remote resolves when nothing is requested...
        let (name, _) = resolve_remote(vault, None).expect("sole remote");
        assert_eq!(name, "eu");

        // ...but an explicit unknown name is refused.
        let requested = resolve_remote(vault, Some("ghost"));
        assert!(matches!(requested, Err(SyncSetupError::Usage(_))));

        // With two remotes, omission requires `origin`.
        config
            .remotes
            .insert("us".to_owned(), entry("https://us", "proj_us"));
        save_remote_config(vault, &config).expect("save two");
        assert!(resolve_remote(vault, None).is_err());

        config.remotes.insert(
            DEFAULT_REMOTE_NAME.to_owned(),
            entry("https://cp", "proj_o"),
        );
        save_remote_config(vault, &config).expect("save three");
        let (name, _) = resolve_remote(vault, None).expect("origin wins");
        assert_eq!(name, DEFAULT_REMOTE_NAME);
    }

    #[test]
    fn corrupt_remote_config_is_a_hard_error_naming_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(remote_config_path(dir.path()), "{ not json").expect("corrupt file");
        let err = load_remote_config(dir.path()).expect_err("must fail");
        assert!(err.to_string().contains("remote.json"));
    }
}
