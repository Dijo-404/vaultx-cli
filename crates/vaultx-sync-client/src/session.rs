//! Live login credentials: `$XDG_RUNTIME_DIR/vaultx/session.json`
//! (mode 0600), shared verbatim by the CLI and the TUI.
//!
//! INV-012: the session token never enters any repository file or
//! rendered output. It lives in a tmpfs-backed location on conforming
//! systems that is wiped at reboot — hence re-login after every boot.
//! [`StoredSession`]'s `Debug` impl redacts the token and no rendering
//! path ever receives it.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::files::write_private;
use crate::setup_error::{io_message, SyncSetupError, SyncSetupResult};

/// Directory (under `$XDG_RUNTIME_DIR`) holding the live session token.
const RUNTIME_SUBDIR: &str = "vaultx";

/// Live login credentials. The token is secret: `Debug` redacts it and
/// no rendering path ever receives it. Serialized only to the 0600
/// runtime session file, never into any repository.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSession {
    /// Base URL of the control plane this token authenticates against.
    pub server: String,
    /// Bearer token; never logged, rendered, or stored elsewhere.
    pub token: String,
}

impl std::fmt::Debug for StoredSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredSession")
            .field("server", &self.server)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// `$XDG_RUNTIME_DIR/vaultx/session.json`; falls back to the system temp
/// directory when `XDG_RUNTIME_DIR` is unset.
#[must_use]
pub fn session_path() -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    base.join(RUNTIME_SUBDIR).join("session.json")
}

/// Loads the stored session, if the user is logged in.
///
/// # Errors
/// [`SyncSetupError::Usage`] when no session file exists (with the
/// actionable login hint) and [`SyncSetupError::Io`] when it is corrupt.
pub fn load_session() -> SyncSetupResult<StoredSession> {
    let text = std::fs::read_to_string(session_path()).map_err(|_| {
        SyncSetupError::Usage("not logged in; run `vaultx login --server <URL>` first".to_owned())
    })?;
    serde_json::from_str::<StoredSession>(&text)
        .map_err(|_| io_message("stored session is corrupt; run `vaultx login` again"))
}

/// Persists the session atomically into an owner-only private directory.
///
/// # Errors
/// [`SyncSetupError::Io`] on serialization or filesystem failure.
pub fn store_session(session: &StoredSession) -> SyncSetupResult<()> {
    let json =
        serde_json::to_string(session).map_err(|_| io_message("session serialization failed"))?;
    write_private(&session_path(), &json).map_err(SyncSetupError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_session_debug_never_reveals_the_token() {
        let session = StoredSession {
            server: "https://cp.example.com".to_owned(),
            token: "vxs_super_secret_canary".to_owned(),
        };
        let rendered = format!("{session:?}");
        assert!(!rendered.contains("vxs_super_secret_canary"));
        assert!(rendered.contains("<redacted>"));

        // Serialization is JSON-only for the 0600 file; it must carry the
        // exact fields and nothing else.
        let json = serde_json::to_string(&session).expect("serialize");
        assert_eq!(
            serde_json::from_str::<StoredSession>(&json).expect("deserialize"),
            StoredSession {
                server: "https://cp.example.com".to_owned(),
                token: "vxs_super_secret_canary".to_owned(),
            }
        );
    }
}
