//! Team-sync command surface (plan §39/§45): control-plane login,
//! named remotes, workspace administration, push/pull/sync, local audit
//! listing, and client-side audit upload.
//!
//! Credential handling (INV-012): the session token never enters any
//! repository file or rendered output. It lives in
//! `$XDG_RUNTIME_DIR/vaultx/session.json` (mode 0600), a tmpfs-backed
//! location on conforming systems that is wiped at reboot — hence
//! re-login after every boot. Only non-secret coordinates (server URL,
//! project id) are stored under `.vaultx/remote.json`. No OS-keyring
//! helper exists in `vaultx-keyring` (only dev/test stores), so the
//! runtime-directory choice is deliberate.
//!
//! The device signing identity for sync attestations reuses
//! `.vaultx/device.key` — the same seed commit signing uses — so pushed
//! commits verify against the attesting device's registered key.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vaultx_audit::{AppendStore as _, AuditEvent, JsonlAppendStore};
use vaultx_control_plane::protocol::WorkspaceView;
use vaultx_core::CoreError;
use vaultx_crypto::envelope::RootKey;
use vaultx_crypto::error::CryptoError;
use vaultx_crypto::signature::SigningKeyPair;
use vaultx_http::{classify_ip, Classification};
use vaultx_keyring::WrappingKeyProvider;
use vaultx_sync_client::transport::{ControlPlaneTransport, TransportRequest, TransportResponse};
use vaultx_sync_client::{
    ControlPlaneSyncClient, DeviceKeySource, FsWorkspace, IngestEvent, SyncError, SyncOptions,
    SyncResult, SyncService,
};

use crate::cli::{CliError, PullStrategy};

/// Name assumed by `push`/`pull`/`sync` when `--remote` is omitted and
/// more than one remote exists.
pub(crate) const DEFAULT_REMOTE_NAME: &str = "origin";

/// Conventional remote configuration file inside `.vaultx`.
const REMOTE_FILE: &str = "remote.json";
/// Tracks how much of the local audit log has been uploaded remotely.
const SYNC_STATE_FILE: &str = "sync-state.json";
/// Directory (under `$XDG_RUNTIME_DIR`) holding the live session token.
const RUNTIME_SUBDIR: &str = "vaultx";

/// Outbound connect timeout (mirrors the broker transport).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-read timeout (mirrors the broker transport).
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Whole-request ceiling (mirrors the broker transport).
const TOTAL_TIMEOUT: Duration = Duration::from_secs(60);
/// Hard ceiling on any single control-plane response body.
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Maximum events per audit-ingest POST so large backlogs converge
/// within the control plane's list/body limits.
const AUDIT_UPLOAD_CHUNK: usize = 1_000;

/// One named remote: where the control plane is and which project this
/// repository synchronizes with. Deliberately token-free.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RemoteEntry {
    /// Base URL of the control plane.
    pub server: String,
    /// Typed project id on the control plane.
    pub project_id: String,
}

/// Contents of `.vaultx/remote.json`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct RemoteConfig {
    #[serde(default)]
    remotes: BTreeMap<String, RemoteEntry>,
}

/// Live login credentials. The token is secret: `Debug` redacts it and
/// no rendering path ever receives it. Serialized only to the 0600
/// runtime session file, never into any repository.
#[derive(Clone, Serialize, Deserialize)]
struct StoredSession {
    server: String,
    token: String,
}

impl std::fmt::Debug for StoredSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredSession")
            .field("server", &self.server)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Watermark for client-side audit upload (`--with-audit`). Audit
/// sequences start at 0, so "nothing uploaded yet" must be distinct
/// from "everything through 0 uploaded": `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct SyncState {
    #[serde(default)]
    last_uploaded_sequence: Option<u64>,
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

fn map_io(err: std::io::Error) -> CliError {
    CliError::Runtime(CoreError::Io(err))
}

fn usage(message: impl Into<String>) -> CliError {
    CliError::Usage(message.into())
}

fn runtime_message(message: impl Into<String>) -> CliError {
    CliError::Runtime(CoreError::Io(std::io::Error::other(message.into())))
}

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
pub(crate) fn write_atomic_via<F>(
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
fn write_atomic(path: &Path, contents: &str) -> Result<(), CliError> {
    let parent = path.parent().ok_or_else(|| {
        map_io(std::io::Error::other(
            "configuration path has no parent directory",
        ))
    })?;
    std::fs::create_dir_all(parent).map_err(map_io)?;
    write_atomic_via(path, contents, || tmp_candidate(path)).map_err(map_io)
}

/// Ensures `dir` exists with owner-only permissions (0700 on unix) —
/// applied to the runtime session directory before any token lands
/// there.
fn ensure_private_dir(dir: &Path) -> Result<(), CliError> {
    std::fs::create_dir_all(dir).map_err(map_io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(dir).map_err(map_io)?;
        if metadata.permissions().mode() & 0o777 != 0o700 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(map_io)?;
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
fn write_private(path: &Path, contents: &str) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| map_io(std::io::Error::other("secret path has no parent directory")))?;
    ensure_private_dir(parent)?;
    write_atomic(path, contents)
}

/// `$XDG_RUNTIME_DIR/vaultx/session.json`; falls back to the system temp
/// directory when `XDG_RUNTIME_DIR` is unset.
pub(crate) fn session_path() -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR").map_or_else(std::env::temp_dir, PathBuf::from);
    base.join(RUNTIME_SUBDIR).join("session.json")
}

fn load_session() -> Result<StoredSession, CliError> {
    let text = std::fs::read_to_string(session_path())
        .map_err(|_| usage("not logged in; run `vaultx login --server <URL>` first"))?;
    serde_json::from_str::<StoredSession>(&text)
        .map_err(|_| runtime_message("stored session is corrupt; run `vaultx login` again"))
}

fn store_session(session: &StoredSession) -> Result<(), CliError> {
    let json = serde_json::to_string(session)
        .map_err(|_| runtime_message("session serialization failed"))?;
    write_atomic(&session_path(), &json)
}

fn load_remote_config(vault_dir: &Path) -> Result<RemoteConfig, CliError> {
    let path = vault_dir.join(REMOTE_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RemoteConfig::default());
        }
        Err(err) => return Err(map_io(err)),
    };
    serde_json::from_str(&text).map_err(|err| {
        runtime_message(format!(
            "remote config `{}` is corrupt ({err}); delete it and re-run `vaultx remote add`",
            path.display()
        ))
    })
}

fn save_remote_config(vault_dir: &Path, config: &RemoteConfig) -> Result<(), CliError> {
    let json = serde_json::to_string_pretty(config)
        .map_err(|_| runtime_message("remote config serialization failed"))?;
    write_atomic(&vault_dir.join(REMOTE_FILE), &json)
}

/// Loads the audit-upload watermark. A missing file starts fresh; a
/// corrupt one is a hard error — silently resetting it would re-upload
/// the whole log as duplicate server-side events.
fn load_sync_state(vault_dir: &Path) -> Result<SyncState, CliError> {
    let path = vault_dir.join(SYNC_STATE_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SyncState::default());
        }
        Err(err) => return Err(map_io(err)),
    };
    serde_json::from_str(&text).map_err(|err| {
        runtime_message(format!(
            "sync state `{}` is corrupt ({err}); delete it to re-upload from the start",
            path.display()
        ))
    })
}

fn save_sync_state(vault_dir: &Path, state: &SyncState) -> Result<(), CliError> {
    let json = serde_json::to_string(state)
        .map_err(|_| runtime_message("sync state serialization failed"))?;
    write_atomic(&vault_dir.join(SYNC_STATE_FILE), &json)
}

/// Resolves the remote entry to use: the explicit name must exist; an
/// omitted name resolves `origin` first, then falls back to the sole
/// configured remote.
fn resolve_remote(
    vault_dir: &Path,
    requested: Option<&str>,
) -> Result<(String, RemoteEntry), CliError> {
    let config = load_remote_config(vault_dir)?;
    match requested {
        Some(name) => config.remotes.get(name).map_or_else(
            || {
                Err(usage(format!(
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
            Err(usage(
                "no remote configured; run `vaultx remote add <NAME> --project <PROJECT_ID>`",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// [`ControlPlaneTransport`] backed by reqwest (rustls only, mirroring
/// the broker transport's hardened client). The bearer token rides only
/// in the Authorization header and never appears in error strings or
/// [`Debug`] output.
#[derive(Clone)]
struct HttpTransport {
    client: reqwest::Client,
    server: String,
    bearer: Arc<String>,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("server", &self.server)
            .field("bearer", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl HttpTransport {
    fn new(server: &str, token: &str) -> Result<Self, CliError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .build()
            .map_err(|err| runtime_message(format!("cannot build HTTP client: {err}")))?;
        Ok(Self {
            client,
            server: server.trim_end_matches('/').to_owned(),
            bearer: Arc::new(token.to_owned()),
        })
    }

    fn url(&self, request: &TransportRequest) -> String {
        format!("{}{}", self.server, request.path)
    }
}

impl ControlPlaneTransport for HttpTransport {
    async fn send(&self, request: TransportRequest) -> Result<TransportResponse, SyncError> {
        let url = self.url(&request);
        let builder = match request.method {
            "GET" => self.client.get(&url),
            "POST" => self.client.post(&url),
            "PUT" => self.client.put(&url),
            _ => return Err(SyncError::Protocol("unsupported method")),
        };
        let mut outgoing = builder.bearer_auth(self.bearer.as_str());
        if let Some(body) = request.json_body {
            outgoing = outgoing
                .header("content-type", "application/json")
                .body(body);
        }
        let response = outgoing.send().await.map_err(|err| {
            // err Display carries method+URL only — headers (and therefore
            // the bearer token) are never embedded.
            SyncError::Transport(err.to_string())
        })?;
        let status = response.status().as_u16();
        // Cap the read so a hostile/misbehaving proxy cannot exhaust
        // memory with an unbounded body.
        let body = read_capped(response, MAX_RESPONSE_BYTES).await?;
        Ok(TransportResponse { status, body })
    }
}

/// Reads a response body up to `cap` bytes; anything larger is a
/// protocol error rather than an OOM.
async fn read_capped(mut response: reqwest::Response, cap: usize) -> Result<String, SyncError> {
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| SyncError::Transport(err.to_string()))?
    {
        if bytes.len() + chunk.len() > cap {
            return Err(SyncError::Protocol("response body exceeds size limit"));
        }
        bytes.extend_from_slice(&chunk);
    }
    String::from_utf8(bytes).map_err(|_| SyncError::Protocol("response body is not valid UTF-8"))
}

/// Wraps a [`SyncError`] into the CLI error family without echoing any
/// wire material (SyncError displays are already secret-free).
fn map_sync_error(err: SyncError) -> CliError {
    runtime_message(err.to_string())
}

// ---------------------------------------------------------------------------
// Device identity
// ---------------------------------------------------------------------------

/// [`WrappingKeyProvider`] reading/writing `.vaultx/device.key` — the
/// exact file and hex-seed format `vaultx-core`'s history service uses
/// for commit signatures, so one identity signs commits and attests sync.
struct ProjectDeviceKey(PathBuf);

impl ProjectDeviceKey {
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

impl WrappingKeyProvider for ProjectDeviceKey {
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

// ---------------------------------------------------------------------------
// Sync plumbing shared by push / pull / sync / audit upload
// ---------------------------------------------------------------------------

struct SyncContext {
    client: ControlPlaneSyncClient<HttpTransport, FsWorkspace>,
    project_id: vaultx_types::ProjectId,
    vault_dir: PathBuf,
    audit_path: PathBuf,
}

fn open_sync_context(
    services: &vaultx_core::VaultxServices,
    requested_remote: Option<&str>,
    authorize_protected: bool,
) -> Result<SyncContext, CliError> {
    let ctx = services.context();
    // Login is the more fundamental prerequisite: report it first so a
    // completely unconfigured project gets the actionable message.
    let session = load_session()?;
    let (_, entry) = resolve_remote(ctx.vault_dir(), requested_remote)?;
    // A stale remote/server pairing must never receive another plane's
    // token: after re-login to a different control plane, old remotes
    // have to be re-added explicitly.
    if entry.server != session.server {
        return Err(usage(format!(
            "remote is bound to {} but the stored login is for {}; \
             re-run `vaultx remote add` or `vaultx login`",
            entry.server, session.server
        )));
    }
    let project_id = vaultx_types::ProjectId::parse(&entry.project_id)
        .map_err(|_| runtime_message("configured remote holds a malformed project id"))?;
    let transport = HttpTransport::new(&entry.server, &session.token)?;
    let workspace = FsWorkspace::open(ctx.root()).map_err(map_sync_error)?;
    let keys = DeviceKeySource::new(Arc::new(ProjectDeviceKey(
        ctx.vault_dir().join("device.key"),
    )));
    let options = SyncOptions {
        authorize_protected_environments: authorize_protected,
    };
    Ok(SyncContext {
        client: ControlPlaneSyncClient::with_options(transport, workspace, keys, options),
        project_id,
        vault_dir: ctx.vault_dir().to_path_buf(),
        audit_path: ctx.audit_path(),
    })
}

fn run_push(ctx: &SyncContext) -> Result<SyncResult, CliError> {
    crate::cli::run_async(ctx.client.push(ctx.project_id.clone())).map_err(map_sync_error)
}

fn run_pull(ctx: &SyncContext) -> Result<SyncResult, CliError> {
    crate::cli::run_async(ctx.client.pull(ctx.project_id.clone())).map_err(map_sync_error)
}

/// Uploads local audit events past the persisted watermark in bounded
/// chunks. The watermark advances to the highest ACCEPTED sequence, so
/// rejected events are skipped-with-reason and never wedge later
/// uploads; accepted prefixes are never re-sent.
fn upload_pending_audit(ctx: &SyncContext) -> Result<String, CliError> {
    let state = load_sync_state(&ctx.vault_dir)?;
    let store = JsonlAppendStore::open(&ctx.audit_path);
    let events = store
        .query(&vaultx_audit::AuditFilter::default())
        .map_err(|err| runtime_message(format!("local audit log unreadable: {err}")))?;
    let pending: Vec<&AuditEvent> = events
        .iter()
        .filter(|event| {
            state
                .last_uploaded_sequence
                .is_none_or(|uploaded| event.sequence > uploaded)
        })
        .collect();
    if pending.is_empty() {
        return Ok("audit: nothing new to upload".to_owned());
    }
    let mut total_accepted = 0usize;
    let mut skipped: Vec<(u64, String)> = Vec::new();
    let mut watermark = state.last_uploaded_sequence;
    for chunk in pending.chunks(AUDIT_UPLOAD_CHUNK) {
        let batch: Vec<IngestEvent> = chunk.iter().map(|e| ingest_event_of(e)).collect();
        let result = crate::cli::run_async(
            ctx.client
                .upload_audit_events(ctx.project_id.clone(), batch),
        )
        .map_err(map_sync_error)?;
        let rejected: std::collections::HashMap<usize, &str> = result
            .rejected
            .iter()
            .map(|r| (r.index, r.reason.as_str()))
            .collect();
        // Skipped events are reported once and deliberately never
        // retried: the watermark rides to this chunk's end so one
        // poison record cannot wedge every later upload.
        let (chunk_accepted, chunk_skipped) = reconcile_chunk(&chunk_sequences(chunk), &rejected);
        total_accepted += chunk_accepted;
        skipped.extend(chunk_skipped);
        if let Some(end) = chunk.last().map(|e| e.sequence) {
            watermark = Some(watermark.map_or(end, |hi| hi.max(end)));
        }
    }
    save_sync_state(
        &ctx.vault_dir,
        &SyncState {
            last_uploaded_sequence: watermark,
        },
    )?;
    Ok(render_audit_upload(total_accepted, &skipped))
}

fn render_audit_upload(accepted: usize, skipped: &[(u64, String)]) -> String {
    let mut line = format!("audit: uploaded {accepted} event(s)");
    if !skipped.is_empty() {
        line.push_str(&format!(", {} rejected (skipped)", skipped.len()));
        for (sequence, reason) in skipped.iter().take(3) {
            line.push_str(&format!("; seq {sequence}: {reason}"));
        }
        if skipped.len() > 3 {
            line.push_str(&format!("; … and {} more", skipped.len() - 3));
        }
    }
    line
}

/// Sequences of one upload chunk, in submission order.
fn chunk_sequences(chunk: &[&AuditEvent]) -> Vec<u64> {
    chunk.iter().map(|event| event.sequence).collect()
}

/// Pure reconciliation of one server response against its submitted
/// sequences: returns how many events were accepted and which
/// `(sequence, reason)` pairs were rejected by position.
pub(crate) fn reconcile_chunk(
    sequences: &[u64],
    rejected: &std::collections::HashMap<usize, &str>,
) -> (usize, Vec<(u64, String)>) {
    let mut skipped = Vec::new();
    for (index, sequence) in sequences.iter().enumerate() {
        if let Some(reason) = rejected.get(&index) {
            skipped.push((*sequence, (*reason).to_owned()));
        }
    }
    (sequences.len() - skipped.len(), skipped)
}

fn ingest_event_of(event: &AuditEvent) -> IngestEvent {
    let decision = match &event.decision {
        vaultx_audit::AuditDecision::Allow => serde_json::json!("allow"),
        vaultx_audit::AuditDecision::Deny { reason } => {
            serde_json::json!({ "deny": reason })
        }
    };
    IngestEvent {
        actor: event.actor.as_str().to_owned(),
        action: audit_action_label(event.action).to_owned(),
        detail: serde_json::json!({
            "sequence": event.sequence,
            "decision": decision,
        }),
    }
}

/// Dotted labels matching the TUI's audit rendering so both surfaces use
/// identical vocabulary.
pub(crate) fn audit_action_label(action: vaultx_audit::AuditAction) -> &'static str {
    use vaultx_audit::AuditAction as A;
    match action {
        A::HttpRequest => "http.request",
        A::SessionCreated => "session.created",
        A::SessionRevoked => "session.revoked",
        A::SecretSet => "secret.set",
        A::SecretRotate => "secret.rotate",
        A::SecretDestroy => "secret.destroy",
        A::ConfigCommitted => "config.committed",
        A::PolicyUpdated => "policy.updated",
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

/// `vaultx login --server URL [--token -|TOKEN]`.
///
/// Verifies the token with an authenticated `GET /workspaces` probe
/// before storing anything. Output reports how much the probe can see;
/// the control plane's lightweight routes carry no principal identity,
/// so "who" is reported as workspace visibility.
pub(crate) fn cmd_login(server: &str, token_arg: Option<&str>) -> Result<String, CliError> {
    if server.trim().is_empty() {
        return Err(usage("--server requires a base URL"));
    }
    let normalized = normalize_server(server)?;
    let token = match token_arg {
        Some("-") => read_stdin_token()?,
        Some(explicit) => explicit.trim().to_owned(),
        None => rpassword::prompt_password("session token (vxs_…): ")
            .map_err(|err| usage(format!("cannot read token: {err}")))?
            .trim()
            .to_owned(),
    };
    if token.is_empty() {
        return Err(usage("a non-empty session token is required"));
    }

    let transport = HttpTransport::new(&normalized, &token)?;
    let response = crate::cli::run_async(transport.send(TransportRequest::get("/workspaces")))
        .map_err(map_sync_error)?;
    if !response.is_success() {
        return Err(runtime_message(format!(
            "control plane rejected the session token with status {}",
            response.status
        )));
    }
    let workspaces: Vec<WorkspaceView> = serde_json::from_str(&response.body).unwrap_or_default();

    store_session(&StoredSession {
        server: normalized.clone(),
        token,
    })?;
    Ok(format!(
        "authenticated against {normalized}; {} workspace(s) visible; credentials stored \
         (re-login required after reboot)",
        workspaces.len()
    ))
}

/// Accepts `http(s)://host[:port]` bases only; anything else is refused
/// before any credential material moves.
pub(crate) fn normalize_server(raw: &str) -> Result<String, CliError> {
    let trimmed = raw.trim().trim_end_matches('/');
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return Err(usage("--server expects an http:// or https:// base URL"));
    }
    // Bearer tokens never travel over plaintext http except to a
    // loopback control plane (local development servers).
    if let Some(rest) = trimmed.strip_prefix("http://") {
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        // Bracketed IPv6 keeps its colons; strip them for classification.
        let host = authority
            .rsplit_once(':')
            .map_or(authority, |(host, _port)| host);
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host)
            .to_ascii_lowercase();
        let loopback = host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .ok()
                .is_some_and(|ip| classify_ip(ip) == Classification::Loopback);
        if !loopback {
            return Err(usage(
                "remote control planes require https:// (plain http is only allowed for localhost)",
            ));
        }
    }
    Ok(trimmed.to_owned())
}

fn read_stdin_token() -> Result<String, CliError> {
    use std::io::Read as _;
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|err| usage(format!("cannot read token from stdin: {err}")))?;
    Ok(buf.trim().to_owned())
}

/// `vaultx remote add <NAME> --project <PROJECT_ID>`.
pub(crate) fn cmd_remote_add(
    services: &vaultx_core::VaultxServices,
    name: &str,
    project_id: &str,
) -> Result<String, CliError> {
    let name = validate_remote_name(name)?;
    let parsed_project = vaultx_types::ProjectId::parse(project_id)
        .map_err(|_| usage(format!("invalid project id `{project_id}`")))?;
    let session = load_session()?;

    // Early verification: the stored session must actually see this
    // project, so typos fail here instead of at the next push.
    let transport = HttpTransport::new(&session.server, &session.token)?;
    let response = crate::cli::run_async(
        transport.send(TransportRequest::get(format!("/projects/{parsed_project}"))),
    )
    .map_err(map_sync_error)?;
    if !response.is_success() {
        return Err(runtime_message(format!(
            "control plane rejected project `{parsed_project}` with status {}; \
             check membership and id",
            response.status
        )));
    }

    let vault_dir = services.context().vault_dir().to_path_buf();
    let mut config = load_remote_config(&vault_dir)?;
    if config.remotes.contains_key(&name) {
        return Err(usage(format!(
            "remote `{name}` already exists; remove it first"
        )));
    }
    config.remotes.insert(
        name.clone(),
        RemoteEntry {
            server: session.server,
            project_id: parsed_project.to_string(),
        },
    );
    save_remote_config(&vault_dir, &config)?;
    Ok(format!("remote `{name}` -> {parsed_project}"))
}

fn validate_remote_name(name: &str) -> Result<String, CliError> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if valid {
        Ok(name.to_owned())
    } else {
        Err(usage(
            "remote names are lowercase alphanumerics with `-`/`_` (max 64)",
        ))
    }
}

/// `vaultx remote list`.
pub(crate) fn cmd_remote_list(services: &vaultx_core::VaultxServices) -> Result<String, CliError> {
    let config = load_remote_config(services.context().vault_dir())?;
    if config.remotes.is_empty() {
        return Ok("no remotes configured".to_owned());
    }
    let rows: Vec<Vec<String>> = config
        .remotes
        .iter()
        .map(|(name, entry)| vec![name.clone(), entry.project_id.clone(), entry.server.clone()])
        .collect();
    Ok(crate::output::render_table(
        &["NAME", "PROJECT", "SERVER"],
        &rows,
    ))
}

/// `vaultx remote agents [--remote NAME]` — lists agent identities
/// registered on the remote project (plan §29 team identity).
pub(crate) fn cmd_remote_agents(
    services: &vaultx_core::VaultxServices,
    remote: Option<&str>,
) -> Result<String, CliError> {
    let ctx = open_sync_context(services, remote, false)?;
    let agents = crate::cli::run_async(ctx.client.list_remote_agents(ctx.project_id.clone()))
        .map_err(map_sync_error)?;
    if agents.is_empty() {
        return Ok("no agent identities registered on the remote".to_owned());
    }
    let rows: Vec<Vec<String>> = agents
        .iter()
        .map(|agent| {
            vec![
                agent.agent_id.to_string(),
                agent.display_name.to_string(),
                (!agent.revoked).to_string(),
            ]
        })
        .collect();
    Ok(crate::output::render_table(
        &["ID", "NAME", "ENABLED"],
        &rows,
    ))
}

/// `vaultx remote remove <NAME>`.
pub(crate) fn cmd_remote_remove(
    services: &vaultx_core::VaultxServices,
    name: &str,
) -> Result<String, CliError> {
    let vault_dir = services.context().vault_dir().to_path_buf();
    let mut config = load_remote_config(&vault_dir)?;
    if config.remotes.remove(name).is_none() {
        return Err(usage(format!("no remote named `{name}`")));
    }
    save_remote_config(&vault_dir, &config)?;
    Ok(format!("removed remote `{name}`"))
}

/// `vaultx workspace list` — thin GET /workspaces through the transport.
pub(crate) fn cmd_workspace_list() -> Result<String, CliError> {
    let session = load_session()?;
    let transport = HttpTransport::new(&session.server, &session.token)?;
    let response = crate::cli::run_async(transport.send(TransportRequest::get("/workspaces")))
        .map_err(map_sync_error)?;
    if !response.is_success() {
        return Err(runtime_message(format!(
            "control plane returned status {}",
            response.status
        )));
    }
    let workspaces: Vec<WorkspaceView> = serde_json::from_str(&response.body)
        .map_err(|_| runtime_message("malformed workspace listing"))?;
    if workspaces.is_empty() {
        return Ok("no workspaces visible".to_owned());
    }
    let rows: Vec<Vec<String>> = workspaces
        .iter()
        .map(|workspace| vec![workspace.id.to_string(), workspace.name.clone()])
        .collect();
    Ok(crate::output::render_table(&["ID", "NAME"], &rows))
}

/// `vaultx workspace create <NAME>` — thin POST /workspaces.
pub(crate) fn cmd_workspace_create(name: &str) -> Result<String, CliError> {
    let session = load_session()?;
    let transport = HttpTransport::new(&session.server, &session.token)?;
    // The server mints its own typed id; the body id is a required-but-
    // ignored placeholder shaped to pass deserialization.
    let body = serde_json::json!({ "id": "ws_placeholder", "name": name });
    let response = crate::cli::run_async(
        transport.send(TransportRequest::post("/workspaces", body.to_string())),
    )
    .map_err(map_sync_error)?;
    if !response.is_success() {
        return Err(runtime_message(format!(
            "control plane refused workspace creation with status {}",
            response.status
        )));
    }
    let created: WorkspaceView = serde_json::from_str(&response.body)
        .map_err(|_| runtime_message("malformed workspace response"))?;
    Ok(format!(
        "created workspace `{}` ({})",
        created.name, created.id
    ))
}

/// Shared tail of push/pull/sync: renders and escalates conflicts.
fn finish(
    result_label: &str,
    result: &SyncResult,
    strategy: PullStrategy,
) -> Result<String, CliError> {
    let rendered = crate::output::render_sync_result(result_label, result);
    if result.conflicts.is_empty() || strategy == PullStrategy::Ours {
        return Ok(rendered);
    }
    Err(CliError::Conflicts(rendered))
}

/// `vaultx push [--with-audit] [--remote NAME] [--authorize-protected]`.
pub(crate) fn cmd_push(
    services: &vaultx_core::VaultxServices,
    with_audit: bool,
    remote: Option<&str>,
    authorize_protected: bool,
) -> Result<String, CliError> {
    let ctx = open_sync_context(services, remote, authorize_protected)?;
    let result = run_push(&ctx)?;
    let mut out = finish("push", &result, PullStrategy::FastForward)?;
    if with_audit {
        // A failed audit upload must not hide the push summary that
        // already succeeded: the summary rides inside the error payload.
        match upload_pending_audit(&ctx) {
            Ok(audit_line) => {
                out.push('\n');
                out.push_str(&audit_line);
            }
            Err(err) => return Err(CliError::Diagnostics(format!("{out}\n{err}"))),
        }
    }
    Ok(out)
}

/// `vaultx pull [--strategy fast-forward|ours]`.
pub(crate) fn cmd_pull(
    services: &vaultx_core::VaultxServices,
    strategy: PullStrategy,
    remote: Option<&str>,
    authorize_protected: bool,
) -> Result<String, CliError> {
    let ctx = open_sync_context(services, remote, authorize_protected)?;
    let result = run_pull(&ctx)?;
    finish("pull", &result, strategy)
}

/// `vaultx sync` — push then pull, single summary.
pub(crate) fn cmd_sync(
    services: &vaultx_core::VaultxServices,
    strategy: PullStrategy,
    remote: Option<&str>,
    authorize_protected: bool,
) -> Result<String, CliError> {
    let ctx = open_sync_context(services, remote, authorize_protected)?;
    let pushed = run_push(&ctx)?;
    let pulled = run_pull(&ctx)?;
    let combined = SyncResult {
        uploaded: pushed.uploaded,
        downloaded: pulled.downloaded,
        conflicts: {
            let mut all = pushed.conflicts;
            all.extend(pulled.conflicts);
            all
        },
        policies_applied: pulled.policies_applied,
    };
    finish("sync", &combined, strategy)
}

/// `vaultx audit list [--actor X] [--outcome allow|deny] [--limit N]`.
///
/// Reads the local JSONL chain only; filters apply client-side.
pub(crate) fn cmd_audit_list(
    services: &vaultx_core::VaultxServices,
    actor: Option<&str>,
    outcome_allow: Option<bool>,
    limit: Option<usize>,
) -> Result<String, CliError> {
    let actor_principal = match actor {
        Some(raw) => Some(
            vaultx_policy::Principal::parse(raw)
                .map_err(|_| usage(format!("invalid actor principal `{raw}`")))?,
        ),
        None => None,
    };
    let store = JsonlAppendStore::open(services.context().audit_path());
    let events = store
        .query(&vaultx_audit::AuditFilter {
            actor: actor_principal,
            decision_allow: outcome_allow,
            limit,
            ..vaultx_audit::AuditFilter::default()
        })
        .map_err(|err| runtime_message(format!("local audit log unreadable: {err}")))?;
    if events.is_empty() {
        return Ok("no audit events".to_owned());
    }
    let rows: Vec<Vec<String>> = events
        .iter()
        .map(|event| {
            let (outcome, reason) = match &event.decision {
                vaultx_audit::AuditDecision::Allow => ("allow".to_owned(), "-".to_owned()),
                vaultx_audit::AuditDecision::Deny { reason } => ("deny".to_owned(), reason.clone()),
            };
            vec![
                event.sequence.to_string(),
                event.actor.as_str().to_owned(),
                audit_action_label(event.action).to_owned(),
                outcome,
                reason,
            ]
        })
        .collect();
    Ok(crate::output::render_table(
        &["SEQ", "ACTOR", "ACTION", "OUTCOME", "REASON"],
        &rows,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_names_are_validated() {
        assert!(validate_remote_name("origin").is_ok());
        assert!(validate_remote_name("prod-eu_1").is_ok());
        assert!(validate_remote_name("").is_err());
        assert!(validate_remote_name("Has Space").is_err());
        assert!(validate_remote_name("../escape").is_err());
    }

    #[test]
    fn server_urls_must_be_http_s() {
        assert!(normalize_server("https://vaultx.example.com").is_ok());
        assert!(normalize_server("http://127.0.0.1:8080/").is_ok());
        assert_eq!(
            normalize_server("https://vaultx.example.com/").unwrap(),
            "https://vaultx.example.com"
        );
        assert!(normalize_server("ftp://host").is_err());
        assert!(normalize_server("vaultx.example.com").is_err());
    }

    #[test]
    fn device_key_provider_round_trips_the_history_format() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("device.key");
        let provider = ProjectDeviceKey(path.clone());

        let created = provider.obtain().expect("first obtain creates");
        // Same file, second source: identical identity.
        let reloaded = ProjectDeviceKey(path).load().expect("reload");
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        created.expose(|s| a.copy_from_slice(s));
        reloaded.expose(|s| b.copy_from_slice(s));
        assert_eq!(a, b);

        // Corrupt seeds are refused, never silently replaced.
        std::fs::write(dir.path().join("bad"), "zzz").unwrap();
        assert!(ProjectDeviceKey(dir.path().join("bad")).load().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn session_files_get_owner_only_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.json");
        write_atomic(&path, "{\"server\":\"https://x\",\"token\":\"vxs_t\"}").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
