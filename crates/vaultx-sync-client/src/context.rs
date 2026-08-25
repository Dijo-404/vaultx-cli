//! One-call assembly of a ready-to-use sync client (plan §39/§45):
//! session + remote resolution + hardened transport + local workspace +
//! device identity.
//!
//! This is the shared seam the CLI and the TUI both drive, so push/pull/
//! sync behave identically on either surface and there is exactly one
//! implementation of the pairing rules (a stale remote/server pair must
//! never receive another plane's token).

use std::path::Path;

use vaultx_types::ProjectId;

use crate::client::{ControlPlaneSyncClient, SyncOptions};
use crate::device::DeviceKeySource;
use crate::device_file::FileDeviceKeySource;
use crate::error::SyncResultOf;
use crate::http::HttpTransport;
use crate::local::FsWorkspace;
use crate::remotes::resolve_remote;
use crate::session::load_session;
use crate::setup_error::{io_message, SyncSetupError, SyncSetupResult};
use crate::transport::ControlPlaneTransport;

/// Everything one push/pull/sync run needs.
pub struct OpenSyncContext<T: ControlPlaneTransport> {
    /// Client wired to the resolved control plane and local workspace.
    pub client: ControlPlaneSyncClient<T, FsWorkspace>,
    /// Typed project id of the resolved remote.
    pub project_id: ProjectId,
    /// The project's `.vaultx` directory (callers persist their own
    /// watermarks next to it).
    pub vault_dir: std::path::PathBuf,
}

impl<T: ControlPlaneTransport> std::fmt::Debug for OpenSyncContext<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenSyncContext")
            .field("project_id", &self.project_id)
            .field("vault_dir", &self.vault_dir)
            .finish_non_exhaustive()
    }
}

/// Resolves session + remote and builds a [`ControlPlaneSyncClient`]
/// over the hardened reqwest transport.
///
/// # Errors
/// [`crate::SyncSetupError`] for login/remote configuration problems;
/// workspace-open failures surface as [`crate::SyncError`]s flattened
/// into `Io` messages exactly like the historical CLI mapping.
pub fn open_sync_context(
    root: &Path,
    vault_dir: &Path,
    requested_remote: Option<&str>,
    authorize_protected_environments: bool,
) -> SyncSetupResult<OpenSyncContext<HttpTransport>> {
    // Login is the more fundamental prerequisite: report it first so a
    // completely unconfigured project gets the actionable message.
    let session = load_session()?;
    let (_, entry) = resolve_remote(vault_dir, requested_remote)?;
    // A stale remote/server pairing must never receive another plane's
    // token: after re-login to a different control plane, old remotes
    // have to be re-added explicitly.
    if entry.server != session.server {
        return Err(SyncSetupError::Usage(format!(
            "remote is bound to {} but the stored login is for {}; \
             re-run `vaultx remote add` or `vaultx login`",
            entry.server, session.server
        )));
    }
    let project_id = ProjectId::parse(&entry.project_id)
        .map_err(|_| io_message("configured remote holds a malformed project id"))?;
    let transport = HttpTransport::new(&entry.server, &session.token)?;
    let workspace = FsWorkspace::open(root).map_err(|err| io_message(err.to_string()))?;
    let keys = DeviceKeySource::new(std::sync::Arc::new(FileDeviceKeySource::new(
        vault_dir.join("device.key"),
    )));
    let options = SyncOptions {
        authorize_protected_environments,
    };
    Ok(OpenSyncContext {
        client: ControlPlaneSyncClient::with_options(transport, workspace, keys, options),
        project_id,
        vault_dir: vault_dir.to_path_buf(),
    })
}

/// Convenience alias for the concrete reqwest-backed context.
pub type HttpSyncContext = OpenSyncContext<HttpTransport>;

/// Runs one sync operation against the opened context. Kept here so
/// callers never have to touch transport types directly.
///
/// # Errors
/// Propagates [`crate::SyncError`] from `op`.
pub async fn run_sync_operation<F>(
    ctx: &HttpSyncContext,
    op: impl FnOnce(&HttpSyncContext) -> F,
) -> SyncResultOf<crate::SyncResult>
where
    F: std::future::Future<Output = SyncResultOf<crate::SyncResult>>,
{
    op(ctx).await
}
