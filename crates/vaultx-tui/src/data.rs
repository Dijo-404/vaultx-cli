//! Snapshot loading: maps `vaultx-core` / broker / audit services onto
//! the plain owned rows the state machine renders.
//!
//! The loader is the only place that touches domain services. Every
//! fallible piece degrades individually — a missing broker, audit file,
//! session store, or pack tree yields empty data plus a status note,
//! never a crashed UI.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use vaultx_audit::{AppendStore as _, AuditEvent, AuditFilter, JsonlAppendStore};
use vaultx_broker::{FileSessionStore, SessionStore as _};
use vaultx_core::{DiffEntry, VaultxServices};
use vaultx_policy_packs::{load_pack, pack_files};
use vaultx_types::{AgentId, CommitId, ObjectId};

use crate::mask::{self, RedactedLine};
use crate::state::{
    AgentDetail, AgentRow, AgentsData, AuditRow, BrokerStatus, EnvRow, HistoryRow, LoadedState,
    OutcomeFilter, RemoteRow, SessionRow, SessionStatus, Snapshot, SyncData, VariableRow,
};

/// Default environment when `--env` is omitted (mirrors the CLI).
pub const DEFAULT_ENV: &str = "development";
/// Maximum audit events loaded per refresh.
pub const AUDIT_LIMIT: usize = 200;
/// Recent history rows shown in the dashboard pane.
const HISTORY_LIMIT: usize = 50;
/// Broker probe budget; a wedged endpoint must not freeze startup.
const BROKER_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Reads project state through the application services.
#[derive(Clone, Debug)]
pub struct SnapshotSource<'a> {
    services: &'a VaultxServices,
    env: Option<String>,
}

/// Named bundle produced by [`SnapshotSource::load_agents`]: agent rows
/// plus the policy names and editor seed derived from the same documents.
struct AgentsSnapshot {
    agents: AgentsData,
    policy_names: Vec<String>,
    editor_seed: String,
}

/// Canonical location of the persistent session store within a project
/// (`<vault>/sessions.json`); shared by the snapshot loader and the
/// TUI's revoke path.
#[must_use]
pub fn session_store_path(services: &VaultxServices) -> PathBuf {
    services.context().vault_dir().join("sessions.json")
}

/// Opens the persistent session store for read/revoke paths.
///
/// # Errors
/// Returns the store's message when it cannot be opened.
pub fn open_session_store(services: &VaultxServices) -> Result<FileSessionStore, String> {
    FileSessionStore::open(session_store_path(services)).map_err(|e| e.to_string())
}

impl<'a> SnapshotSource<'a> {
    /// Builds a source over an opened project. Broker reachability is
    /// probed separately (once, at startup) rather than per refresh.
    #[must_use]
    pub fn new(services: &'a VaultxServices, env: Option<String>) -> Self {
        Self { services, env }
    }

    /// Loads everything one UI refresh needs. Never fails overall:
    /// individual pieces degrade into notes rendered on the status line.
    /// The broker probe is injected by the caller so refreshes never
    /// re-probe (and never block the render loop).
    #[must_use]
    pub fn load(&self, broker: BrokerStatus) -> LoadedState {
        let mut notes = Vec::new();
        let snapshot = self.load_snapshot(&mut notes);
        let diff = self.load_diff_lines(&mut notes);
        let agents_snapshot = self.load_agents(&mut notes);
        let audit = query_audit_rows(&self.audit_path(), OutcomeFilter::All, AUDIT_LIMIT)
            .unwrap_or_else(|reason| {
                notes.push(format!("audit unavailable: {reason}"));
                Vec::new()
            });
        let branches = self.load_branches(&mut notes);
        let sync = self.load_sync_data(&mut notes);

        LoadedState {
            snapshot: Snapshot { notes, ..snapshot },
            diff,
            agents: agents_snapshot.agents,
            audit,
            broker,
            policy_names: agents_snapshot.policy_names,
            editor_seed: agents_snapshot.editor_seed,
            branches,
            sync,
        }
    }

    fn audit_path(&self) -> PathBuf {
        self.services.context().audit_path()
    }

    fn load_snapshot(&self, notes: &mut Vec<String>) -> Snapshot {
        let mut snap = Snapshot {
            env: Some(self.env.clone().unwrap_or_else(|| DEFAULT_ENV.to_owned())),
            ..Snapshot::default()
        };

        match self.services.staging().status() {
            Ok(report) => {
                snap.branch = report.branch;
                snap.head_short = report.head_commit.as_ref().map(short_id);
                if let Some(head) = report.head_commit {
                    match self.services.history().show(&head) {
                        Ok(detail) => {
                            snap.variables = detail
                                .entries
                                .iter()
                                .map(|entry| VariableRow {
                                    name: entry.name.clone(),
                                    kind: entry.kind.to_owned(),
                                    reference: mask::mask_reference(entry.kind, &entry.reference),
                                })
                                .collect();
                        }
                        Err(err) => notes.push(format!("variables unavailable: {err}")),
                    }
                }
            }
            Err(err) => notes.push(format!("status unavailable: {err}")),
        }

        match self.services.environments().list_environments() {
            Ok(envs) => {
                snap.envs = envs
                    .into_iter()
                    .map(|env| EnvRow {
                        name: env.name,
                        protected: env.protected,
                        commit_short: env.commit.as_ref().map(short_id),
                    })
                    .collect();
            }
            Err(err) => notes.push(format!("environments unavailable: {err}")),
        }

        match self.services.history().log(HISTORY_LIMIT) {
            Ok(entries) => {
                snap.history = entries
                    .iter()
                    .map(|entry| HistoryRow {
                        short: short_id(&entry.id),
                        message: first_line(&entry.message),
                        author: entry.author.clone(),
                        delta: self.commit_delta(&entry.id),
                    })
                    .collect();
            }
            Err(err) => notes.push(format!("history unavailable: {err}")),
        }

        snap
    }

    /// Redacted secret/policy delta between one commit and its first
    /// parent; empty for root commits or when history lookup fails.
    fn commit_delta(&self, commit_id: &CommitId) -> Vec<RedactedLine> {
        let Ok(detail) = self.services.history().show(commit_id) else {
            return Vec::new();
        };
        let Some(parent) = detail.parents.first() else {
            return Vec::new();
        };
        self.services
            .history()
            .diff_commits(parent, commit_id)
            .map(|entries| redact_entries(self.services, &entries))
            .unwrap_or_default()
    }

    fn load_diff_lines(&self, notes: &mut Vec<String>) -> Vec<RedactedLine> {
        let entries = match self.services.history().diff_staged() {
            Ok(entries) => entries,
            Err(err) => {
                notes.push(format!("diff unavailable: {err}"));
                return Vec::new();
            }
        };
        redact_entries(self.services, &entries)
    }

    fn load_agents(&self, notes: &mut Vec<String>) -> AgentsSnapshot {
        let documents = match self.services.policies().load_policies() {
            Ok(documents) => documents,
            Err(err) => {
                notes.push(format!("policies unavailable: {err}"));
                Vec::new()
            }
        };

        let policy_names: Vec<String> = documents
            .iter()
            .map(|doc| doc.name.as_str().to_owned())
            .collect();
        let editor_seed = documents
            .first()
            .and_then(|doc| serde_yaml::to_string(doc).ok())
            .unwrap_or_default();

        let list: Vec<AgentRow> = match self.services.agents().list_agents() {
            Ok(summaries) => summaries
                .into_iter()
                .map(|agent| AgentRow {
                    name: agent.name,
                    enabled: agent.enabled,
                })
                .collect(),
            Err(err) => {
                notes.push(format!("agents unavailable: {err}"));
                Vec::new()
            }
        };

        let capabilities = self.load_capabilities(notes);

        // One audit read and one store open for the whole pass; rows are
        // partitioned per actor below instead of re-querying per agent.
        let now = unix_now_secs();
        let session_store = open_session_store(self.services);
        let mut audit_by_actor: BTreeMap<String, Vec<AuditRow>> = BTreeMap::new();
        if let Ok(rows) = query_audit_rows(&self.audit_path(), OutcomeFilter::All, AUDIT_LIMIT) {
            for row in rows {
                audit_by_actor
                    .entry(row.actor.clone())
                    .or_default()
                    .push(row);
            }
        }

        let mut details = BTreeMap::new();
        for row in &list {
            let Ok(full_id) = AgentId::parse(&format!("agent_{}", row.name)) else {
                continue;
            };
            let attached = attached_documents(self.services, &documents, row.name.as_str());
            let sessions = match &session_store {
                Ok(store) => load_session_rows(store, full_id.as_str(), now),
                Err(reason) => Err(reason.clone()),
            };
            let agent_prefix = format!("agent:{}", row.name);
            let audit = audit_by_actor
                .get(&agent_prefix)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .take(8)
                .collect();

            details.insert(
                row.name.clone(),
                AgentDetail {
                    full_id: full_id.as_str().to_owned(),
                    enabled: row.enabled,
                    environment: derive_environment(&sessions, self.env.as_deref()),
                    policies: attached
                        .iter()
                        .map(|doc| doc.name.as_str().to_owned())
                        .collect(),
                    credentials: union(attached.iter().map(|d| d.credential.as_str())),
                    allowed_hosts: union(documents_hosts(&attached)),
                    allowed_methods: union(attached_allow_methods(&attached)),
                    allowed_paths: union(attached_allow_paths(&attached)),
                    capabilities: capabilities.clone(),
                    sessions,
                    audit,
                },
            );
        }

        AgentsSnapshot {
            agents: AgentsData { list, details },
            policy_names,
            editor_seed,
        }
    }

    /// Branch names usable as promotion sources; a broken history store
    /// degrades to an empty list plus a note.
    fn load_branches(&self, notes: &mut Vec<String>) -> Vec<String> {
        match self.services.history().branches() {
            Ok(branches) => branches.into_iter().map(|(name, _)| name).collect(),
            Err(err) => {
                notes.push(format!("branches unavailable: {err}"));
                Vec::new()
            }
        }
    }

    /// Control-plane remotes and login presence for the sync view.
    /// Reads only token-free coordinates (`remote.json`); the session
    /// file's existence is checked without ever reading its contents.
    fn load_sync_data(&self, notes: &mut Vec<String>) -> SyncData {
        let remotes =
            match vaultx_sync_client::load_remote_config(self.services.context().vault_dir()) {
                Ok(config) => config
                    .remotes
                    .into_iter()
                    .map(|(name, entry)| RemoteRow {
                        name,
                        server: entry.server,
                        project_id: entry.project_id,
                    })
                    .collect(),
                Err(err) => {
                    notes.push(format!("remotes unavailable: {err}"));
                    Vec::new()
                }
            };
        SyncData {
            remotes,
            logged_in: vaultx_sync_client::session_path().is_file(),
        }
    }

    /// Semantic capability names from `<project>/policy-packs`; a missing
    /// or broken tree simply yields no capabilities.
    fn load_capabilities(&self, notes: &mut Vec<String>) -> Vec<String> {
        let dir = self.services.context().root().join("policy-packs");
        if !dir.is_dir() {
            return Vec::new();
        }
        let files = match pack_files(&dir) {
            Ok(files) => files,
            Err(err) => {
                notes.push(format!("policy packs unavailable: {err}"));
                return Vec::new();
            }
        };
        files
            .iter()
            .filter_map(|file| load_pack(file).ok().map(|pack| pack.name))
            .collect()
    }
}

/// Effective environment shown for one agent: its latest usable session's
/// environment, falling back to the active dashboard environment (or the
/// documented default when even that is unknown).
fn derive_environment(
    sessions: &Result<Vec<SessionRow>, String>,
    fallback: Option<&str>,
) -> String {
    if let Ok(rows) = sessions {
        let chosen = rows
            .iter()
            .find(|row| row.status == SessionStatus::Active)
            .or_else(|| rows.first());
        if let Some(row) = chosen {
            return row.environment.clone();
        }
    }
    fallback.unwrap_or(DEFAULT_ENV).to_owned()
}

/// Redacts manifest-diff entries, upgrading resolvable policy changes to
/// host/path/method deltas. Output is metadata-only by construction.
fn redact_entries(services: &VaultxServices, entries: &[DiffEntry]) -> Vec<RedactedLine> {
    let mut lines = Vec::new();
    for entry in entries {
        // Policy changes upgrade to host/path/method deltas whenever
        // both documents resolve from the repository object store;
        // otherwise they stay metadata-only object deltas.
        if let DiffEntry::PolicyChanged {
            old_policy_object,
            new_policy_object,
            ..
        } = entry
        {
            if let (Some(old), Some(new)) = (
                resolve_policy_document(services, old_policy_object),
                resolve_policy_document(services, new_policy_object),
            ) {
                lines.extend(mask::policy_delta(&old, &new));
                continue;
            }
        }
        lines.extend(mask::redact_diff(std::slice::from_ref(entry)));
    }
    lines
}

/// Policies governing one agent: those named on its identity file first,
/// falling back to principal matches when no explicit attachment exists.
fn attached_documents<'doc>(
    services: &VaultxServices,
    documents: &'doc [vaultx_policy::PolicyDocument],
    bare_name: &str,
) -> Vec<&'doc vaultx_policy::PolicyDocument> {
    let principal = format!("agent:{bare_name}");
    let by_principal: Vec<&vaultx_policy::PolicyDocument> = documents
        .iter()
        .filter(|doc| doc.principal.as_str() == principal)
        .collect();
    let Ok(identity) = services.agents().inspect(bare_name) else {
        return by_principal;
    };
    let by_name: Vec<&vaultx_policy::PolicyDocument> = documents
        .iter()
        .filter(|doc| identity.policy_names.iter().any(|n| n == &doc.name))
        .collect();
    if by_name.is_empty() {
        by_principal
    } else {
        by_name
    }
}

fn documents_hosts(docs: &[&vaultx_policy::PolicyDocument]) -> Vec<String> {
    docs.iter()
        .flat_map(|doc| doc.http.hosts.iter().map(String::as_str))
        .map(str::to_owned)
        .collect()
}

fn attached_allow_methods(docs: &[&vaultx_policy::PolicyDocument]) -> Vec<String> {
    docs.iter()
        .flat_map(|doc| doc.http.allow.iter())
        .flat_map(|rule| rule.methods.iter().map(|m| m.as_str()))
        .map(str::to_owned)
        .collect()
}

fn attached_allow_paths(docs: &[&vaultx_policy::PolicyDocument]) -> Vec<String> {
    docs.iter()
        .flat_map(|doc| doc.http.allow.iter())
        .flat_map(|rule| rule.paths.iter().map(String::as_str))
        .map(str::to_owned)
        .collect()
}

fn union<I>(values: I) -> Vec<String>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let mut out: Vec<String> = Vec::new();
    for value in values {
        let value = value.into();
        if !out.contains(&value) {
            out.push(value);
        }
    }
    out.sort();
    out
}

fn short_id(id: &CommitId) -> String {
    let text = id.as_str();
    let hex = text.strip_prefix("cmt_").unwrap_or(text);
    hex.chars().take(7).collect()
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or_default().to_owned()
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Decodes a stored policy document from the repository object store, or
/// `None` when the object is absent/undecodable as a policy document.
fn resolve_policy_document(
    services: &VaultxServices,
    object_id: &ObjectId,
) -> Option<vaultx_policy::PolicyDocument> {
    let envelope = services
        .context()
        .repository()
        .objects()
        .get(object_id)
        .ok()?;
    let payload: serde_json::Value = envelope.decode_payload().ok()?;
    serde_json::from_value(payload).ok()
}

/// Queries the local JSONL audit store with the given outcome filter.
///
/// # Errors
/// Returns the store's message when it cannot be read or parsed.
pub fn query_audit_rows(
    audit_path: &Path,
    filter: OutcomeFilter,
    limit: usize,
) -> Result<Vec<AuditRow>, String> {
    let store = JsonlAppendStore::open(audit_path);
    let filter = AuditFilter {
        decision_allow: filter.allows_only(),
        limit: Some(limit),
        ..AuditFilter::default()
    };
    let events = store.query(&filter).map_err(|e| e.to_string())?;
    Ok(events.iter().map(audit_row_from_event).collect())
}

fn audit_row_from_event(event: &AuditEvent) -> AuditRow {
    let (allowed, deny_reason) = match &event.decision {
        vaultx_audit::AuditDecision::Allow => (true, None),
        vaultx_audit::AuditDecision::Deny { reason } => (false, Some(reason.clone())),
    };
    AuditRow {
        sequence: event.sequence,
        actor: event.actor.as_str().to_owned(),
        action: action_label(event.action).to_owned(),
        allowed,
        deny_reason,
        destination: event
            .destination
            .as_ref()
            .map(|dest| format!("{}:{}{}", dest.host(), dest.port(), dest.path())),
    }
}

fn action_label(action: vaultx_audit::AuditAction) -> &'static str {
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

/// Classifies one agent's stored sessions into view rows against an
/// already-opened store (one open per refresh, not one per agent).
///
/// # Errors
/// Returns the store's message when records cannot be read or parsed.
pub fn load_session_rows(
    store: &FileSessionStore,
    agent_full_id: &str,
    now_secs: u64,
) -> Result<Vec<SessionRow>, String> {
    let agent = AgentId::parse(agent_full_id).map_err(|e| e.to_string())?;
    let records = store.list_for_agent(&agent).map_err(|e| e.to_string())?;
    Ok(records
        .into_iter()
        .map(|record| {
            let status = if record.revoked {
                SessionStatus::Revoked
            } else if record.expires_at_secs.is_some_and(|exp| exp <= now_secs) {
                SessionStatus::Expired
            } else {
                SessionStatus::Active
            };
            SessionRow {
                session_id: record.session_id.as_str().to_owned(),
                environment: record.environment.as_str().to_owned(),
                status,
            }
        })
        .collect())
}

/// Probes the broker endpoint so panes can degrade gracefully when it is
/// offline. Called once at startup by the terminal loop; refresh paths
/// reuse the stored result instead of re-probing.
#[must_use]
pub fn broker_status(socket: Option<&Path>) -> BrokerStatus {
    let endpoint = socket
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(vaultx_broker_client::default_endpoint()));
    match probe_endpoint(endpoint.clone()) {
        Ok(version) => BrokerStatus::Online(version),
        Err(reason) => BrokerStatus::Offline(format!("{} ({})", endpoint.display(), reason)),
    }
}

/// One shared runtime for the single startup probe; building a fresh
/// multi-thread runtime per call was the dominant refresh cost.
static PROBE_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn probe_runtime() -> &'static tokio::runtime::Runtime {
    PROBE_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("shared tokio runtime for the startup broker probe")
    })
}

/// Blocks on one async operation (sync push/pull/sync) using the shared
/// runtime so refresh paths and actions never spawn extra runtimes.
pub(crate) fn run_blocking<F: std::future::Future>(future: F) -> F::Output {
    probe_runtime().block_on(future)
}

fn probe_endpoint(endpoint: PathBuf) -> Result<String, String> {
    probe_runtime().block_on(async move {
        let attempt = async {
            let mut client = vaultx_broker_client::BrokerClient::connect(&endpoint)
                .await
                .map_err(|e| e.to_string())?;
            client.ping().await.map_err(|e| e.to_string())
        };
        tokio::time::timeout(BROKER_PROBE_TIMEOUT, attempt)
            .await
            .map_err(|_| "timed out".to_owned())?
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use vaultx_audit::{
        AuditAction, AuditDecision, CorrelationId, NewAuditEvent, SafeAuditMetadata,
    };
    use vaultx_policy::Principal;
    use vaultx_types::ProjectId;

    fn new_event(decision: AuditDecision) -> NewAuditEvent {
        NewAuditEvent {
            correlation_id: CorrelationId::parse("corr-tui").expect("valid correlation"),
            actor: Principal::parse("agent:bot").expect("valid principal"),
            project: ProjectId::parse("proj_tui").expect("valid project"),
            environment: None,
            action: AuditAction::HttpRequest,
            decision,
            credential: None,
            destination: None,
            capability: None,
            policy_ids: Vec::new(),
            metadata: SafeAuditMetadata::from_pairs([("http.method", "GET")])
                .expect("valid metadata"),
        }
    }

    #[test]
    fn derived_environment_prefers_active_session_then_fallback() {
        let session = |id: &str, env: &str, status: SessionStatus| SessionRow {
            session_id: id.to_owned(),
            environment: env.to_owned(),
            status,
        };

        let with_active = Ok(vec![
            session("s1", "legacy", SessionStatus::Expired),
            session("s2", "production", SessionStatus::Active),
        ]);
        assert_eq!(
            derive_environment(&with_active, Some("development")),
            "production"
        );

        let expired_only = Ok(vec![session("s1", "legacy", SessionStatus::Revoked)]);
        assert_eq!(
            derive_environment(&expired_only, Some("development")),
            "legacy"
        );

        assert_eq!(
            derive_environment(&Ok(Vec::new()), Some("development")),
            "development"
        );
        assert_eq!(
            derive_environment(&Err("store missing".to_owned()), None),
            DEFAULT_ENV
        );
    }

    #[test]
    fn outcome_filter_returns_only_matching_audit_rows() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("audit.jsonl");
        let store = JsonlAppendStore::open(&path);
        store
            .append(new_event(AuditDecision::Allow))
            .expect("append allow");
        store
            .append(new_event(
                AuditDecision::deny("path_not_allowed").expect("valid reason"),
            ))
            .expect("append deny");
        store
            .append(new_event(
                AuditDecision::deny("host_not_allowed").expect("valid reason"),
            ))
            .expect("append deny");

        assert_eq!(
            query_audit_rows(&path, OutcomeFilter::All, AUDIT_LIMIT)
                .expect("query")
                .len(),
            3
        );

        let allows = query_audit_rows(&path, OutcomeFilter::Allow, AUDIT_LIMIT).expect("query");
        assert_eq!(allows.len(), 1);
        assert!(allows.iter().all(|row| row.allowed));

        let denies = query_audit_rows(&path, OutcomeFilter::Deny, AUDIT_LIMIT).expect("query");
        assert_eq!(denies.len(), 2);
        assert!(denies.iter().all(|row| !row.allowed));
    }

    #[test]
    fn loader_fills_branches_environments_and_sync_view_data() {
        use vaultx_sync_client::files::write_atomic;

        let dir = TempDir::new().expect("temp dir");
        let services = vaultx_core::VaultxServices::init(dir.path()).expect("init project");

        // Seed a commit so a branch and an environment ref exist.
        services.config().set_config("A", "1").unwrap();
        services.history().commit("baseline", "user:e").unwrap();
        services
            .environments()
            .create_environment("development")
            .unwrap();
        services
            .environments()
            .protect_environment("development", true)
            .unwrap();

        // Token-free remote coordinates only; no session file exists.
        let mut config = vaultx_sync_client::RemoteConfig::default();
        config.remotes.insert(
            "origin".to_owned(),
            vaultx_sync_client::RemoteEntry {
                server: "https://cp.example.com".to_owned(),
                project_id: "proj_team".to_owned(),
            },
        );
        write_atomic(
            &services.context().vault_dir().join("remote.json"),
            &serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let loaded = SnapshotSource::new(&services, None).load(BrokerStatus::default());

        assert_eq!(loaded.branches, vec!["main".to_owned()]);
        assert_eq!(loaded.snapshot.envs.len(), 1);
        assert!(loaded.snapshot.envs[0].protected);
        assert!(!loaded.sync.remotes.is_empty());
        assert_eq!(loaded.sync.remotes[0].name, "origin");
        assert_eq!(loaded.sync.remotes[0].server, "https://cp.example.com");
        assert_eq!(
            loaded.sync.logged_in,
            vaultx_sync_client::session_path().is_file()
        );

        // A corrupt remote.json degrades to an empty list plus a note,
        // never a failed load.
        std::fs::write(services.context().vault_dir().join("remote.json"), "{bad").unwrap();
        let degraded = SnapshotSource::new(&services, None).load(BrokerStatus::default());
        assert!(degraded.sync.remotes.is_empty());
        assert!(degraded
            .snapshot
            .notes
            .iter()
            .any(|note| note.contains("remotes unavailable")));
    }
}
