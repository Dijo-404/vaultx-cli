//! Team-sync command surface (plan §39/§45): control-plane login,
//! named remotes, workspace administration, push/pull/sync, local audit
//! listing, and client-side audit upload.
//!
//! Credential handling (INV-012): the session token never enters any
//! repository file or rendered output. It lives in
//! `$XDG_RUNTIME_DIR/vaultx/session.json` (mode 0600) — see
//! [`vaultx_sync_client::session`], which owns that file along with
//! `.vaultx/remote.json`, the hardened reqwest transport, and the device
//! identity so the CLI and the TUI share ONE hardened implementation.
//!
//! What remains here is purely the command surface: argument handling,
//! output rendering, audit-upload watermarking, and CLI error mapping.
//! The device signing identity for sync attestations reuses
//! `.vaultx/device.key` — the same seed commit signing uses — so pushed
//! commits verify against the attesting device's registered key.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use vaultx_audit::{AppendStore as _, AuditEvent, JsonlAppendStore};
use vaultx_control_plane::protocol::WorkspaceView;
use vaultx_core::CoreError;
use vaultx_http::{classify_ip, Classification};
use vaultx_sync_client::client::ControlPlaneSyncClient;
use vaultx_sync_client::context::open_sync_context as open_shared_sync_context;
use vaultx_sync_client::error::SyncError;
use vaultx_sync_client::files::write_atomic;
use vaultx_sync_client::http::HttpTransport;
use vaultx_sync_client::local::FsWorkspace;
use vaultx_sync_client::remotes::{load_remote_config, save_remote_config, RemoteEntry};
use vaultx_sync_client::session::{load_session, store_session, StoredSession};
use vaultx_sync_client::setup_error::SyncSetupError;
use vaultx_sync_client::transport::{ControlPlaneTransport as _, TransportRequest};
use vaultx_sync_client::{IngestEvent, SyncResult, SyncService};

use crate::cli::{CliError, PullStrategy};

/// Tracks how much of the local audit log has been uploaded remotely.
const SYNC_STATE_FILE: &str = "sync-state.json";

/// Maximum events per audit-ingest POST so large backlogs converge
/// within the control plane's list/body limits.
const AUDIT_UPLOAD_CHUNK: usize = 1_000;

// ---------------------------------------------------------------------------
// Error mapping
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

/// Maps the shared sync-setup error family onto the CLI's, preserving
/// the usage/runtime split that drives exit codes.
fn map_setup_error(err: SyncSetupError) -> CliError {
    match err {
        SyncSetupError::Usage(message) => CliError::Usage(message),
        SyncSetupError::Io(io) => CliError::Runtime(CoreError::Io(io)),
    }
}

/// Wraps a [`SyncError`] into the CLI error family without echoing any
/// wire material (SyncError displays are already secret-free).
fn map_sync_error(err: SyncError) -> CliError {
    runtime_message(err.to_string())
}

// ---------------------------------------------------------------------------
// Audit-upload watermark (CLI-only concern)
// ---------------------------------------------------------------------------

/// Watermark for client-side audit upload (`--with-audit`). Audit
/// sequences start at 0, so "nothing uploaded yet" must be distinct
/// from "everything through 0 uploaded": `None`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct SyncState {
    #[serde(default)]
    last_uploaded_sequence: Option<u64>,
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
    write_atomic(&vault_dir.join(SYNC_STATE_FILE), &json).map_err(map_io)
}

// ---------------------------------------------------------------------------
// Sync plumbing shared by push / pull / sync / audit upload
// ---------------------------------------------------------------------------

/// CLI-side view over the shared [`vaultx_sync_client::context`]
/// assembly, extended with the audit path the `--with-audit` uploader
/// streams from.
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
    let shared = open_shared_sync_context(
        ctx.root(),
        ctx.vault_dir(),
        requested_remote,
        authorize_protected,
    )
    .map_err(map_setup_error)?;
    Ok(SyncContext {
        client: shared.client,
        project_id: shared.project_id,
        vault_dir: shared.vault_dir,
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
        let rejected: HashMap<usize, &str> = result
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
    rejected: &HashMap<usize, &str>,
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

    let transport = HttpTransport::new(&normalized, &token).map_err(map_setup_error)?;
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
    })
    .map_err(map_setup_error)?;
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
        // Bracketed IPv6 keeps its colons; take the inside of the
        // brackets. Bare hosts drop a `:port` suffix.
        let host = if let Some(rest) = authority.strip_prefix('[') {
            rest.split_once(']').map_or(rest, |(h, _)| h)
        } else {
            authority.rsplit_once(':').map_or(authority, |(h, _)| h)
        };
        let host = host.to_ascii_lowercase();
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
    let session = load_session().map_err(map_setup_error)?;

    // Early verification: the stored session must actually see this
    // project, so typos fail here instead of at the next push.
    let transport = HttpTransport::new(&session.server, &session.token).map_err(map_setup_error)?;
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
    let mut config = load_remote_config(&vault_dir).map_err(map_setup_error)?;
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
    save_remote_config(&vault_dir, &config).map_err(map_setup_error)?;
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
    let config = load_remote_config(services.context().vault_dir()).map_err(map_setup_error)?;
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
    let mut config = load_remote_config(&vault_dir).map_err(map_setup_error)?;
    if config.remotes.remove(name).is_none() {
        return Err(usage(format!("no remote named `{name}`")));
    }
    save_remote_config(&vault_dir, &config).map_err(map_setup_error)?;
    Ok(format!("removed remote `{name}`"))
}

/// `vaultx workspace list` — thin GET /workspaces through the transport.
pub(crate) fn cmd_workspace_list() -> Result<String, CliError> {
    let session = load_session().map_err(map_setup_error)?;
    let transport = HttpTransport::new(&session.server, &session.token).map_err(map_setup_error)?;
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
    let session = load_session().map_err(map_setup_error)?;
    let transport = HttpTransport::new(&session.server, &session.token).map_err(map_setup_error)?;
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
    let combined = crate::cli::run_async(vaultx_sync_client::push_then_pull(
        &ctx.client,
        ctx.project_id.clone(),
    ))
    .map_err(map_sync_error)?;
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
    use vaultx_sync_client::DeviceKeySource;

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

    #[cfg(unix)]
    #[test]
    fn session_files_get_owner_only_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.json");
        vaultx_sync_client::files::write_atomic(
            &path,
            "{\"server\":\"https://x\",\"token\":\"vxs_t\"}",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn device_key_source_round_trips_the_history_format() {
        let dir = tempfile::tempdir().expect("tempdir");
        let source = || vaultx_sync_client::FileDeviceKeySource::new(dir.path().join("device.key"));

        let created = DeviceKeySource::new(std::sync::Arc::new(source()))
            .signing_key()
            .expect("first obtain creates");

        // Same file, second source: identical identity.
        let reloaded = DeviceKeySource::new(std::sync::Arc::new(source()))
            .signing_key()
            .expect("reload");
        assert_eq!(
            created.verifying_public_key().to_bytes(),
            reloaded.verifying_public_key().to_bytes()
        );

        // Corrupt seeds are refused, never silently replaced.
        std::fs::write(dir.path().join("bad"), "zzz").unwrap();
        assert!(DeviceKeySource::new(std::sync::Arc::new(
            vaultx_sync_client::FileDeviceKeySource::new(dir.path().join("bad"))
        ))
        .signing_key()
        .is_err());
    }

    #[test]
    fn setup_errors_keep_the_usage_runtime_split() {
        assert!(matches!(
            map_setup_error(SyncSetupError::Usage("hint".to_owned())),
            CliError::Usage(_)
        ));
        assert!(matches!(
            map_setup_error(SyncSetupError::Io(std::io::Error::other("boom"))),
            CliError::Runtime(_)
        ));
    }
}
