//! [`ControlPlaneStore`] — the persistence seam covering the PostgreSQL
//! schema's data needs (plan §28) — and the hermetic in-memory
//! implementation used by all tests.
//!
//! Methods are synchronous so the in-memory backend needs no runtime
//! plumbing; a production PostgreSQL implementation would live behind the
//! same trait (the DDL under `migrations/` defines its schema).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use vaultx_types::{AgentId, AuditEventId, CommitId, ObjectId, PolicyName, ProjectId, WorkspaceId};

use crate::error::ControlPlaneError;
use crate::model::{
    DeviceRecord, PolicyDocument, Principal, ProjectRecord, RefNamespace, RefState, UserRecord,
    WorkspaceMembership, WorkspaceRecord,
};
use crate::protocol::{AgentView, AuditEventView, EnvironmentMetadata, ObjectEntryWire};

/// Result alias for store operations.
pub type StoreResult<T> = Result<T, ControlPlaneError>;

/// An agent session context recorded at issuance: subordinate to an
/// authenticated principal and a project-scoped policy binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSessionContext {
    /// Owning agent identity.
    pub agent_id: AgentId,
    /// Parent human/workload principal that minted the session.
    pub parent_principal: String,
    /// Project the session is scoped to.
    pub project: ProjectId,
}

/// Persistence contract for the control plane. All mutating operations are
/// idempotent-friendly where the domain allows it (objects dedupe by
/// content address; refs upsert).
pub trait ControlPlaneStore: Send + Sync {
    // ---- auth / users ----

    /// Returns the user record for `login`, if present.
    fn find_user(&self, login: &str) -> StoreResult<Option<UserRecord>>;

    /// Inserts or updates `user` keyed by login.
    ///
    /// # Errors
    /// Propagates storage failures.
    fn upsert_user(&self, user: &UserRecord) -> StoreResult<()>;

    /// Records `token -> principal` for later resolution. Production
    /// backends persist only a verifier of `token`.
    ///
    /// # Errors
    /// Propagates storage failures.
    fn issue_session(&self, token: &str, principal: &Principal) -> StoreResult<()>;

    /// Resolves a bearer token to its principal.
    fn resolve_token(&self, token: &str) -> StoreResult<Option<Principal>>;

    // ---- workspaces / membership / projects ----

    /// Creates `workspace`; the owner receives an `owner` membership.
    ///
    /// # Errors
    /// Propagates storage failures.
    fn create_workspace(&self, workspace: &WorkspaceRecord) -> StoreResult<()>;

    /// Lists workspaces `user` belongs to.
    fn list_workspaces_for_user(&self, user: &str) -> StoreResult<Vec<WorkspaceRecord>>;

    /// Adds or overwrites `user`'s membership role in `workspace`.
    ///
    /// # Errors
    /// Propagates storage failures.
    fn add_workspace_member(&self, membership: &WorkspaceMembership) -> StoreResult<()>;

    /// True when `user` holds any membership in `workspace`; missing
    /// workspace surfaces [`ControlPlaneError::NotFound`].
    fn is_workspace_member(&self, workspace: &WorkspaceId, user: &str) -> StoreResult<bool>;

    /// Creates `project`.
    ///
    /// # Errors
    /// Propagates storage failures.
    fn create_project(&self, project: &ProjectRecord) -> StoreResult<()>;

    /// Loads a project by typed id.
    fn get_project(&self, id: &ProjectId) -> StoreResult<Option<ProjectRecord>>;

    // ---- devices ----

    /// Registers `device`; first registration per public key wins.
    /// Returns true when newly registered.
    ///
    /// # Errors
    /// Propagates storage failures.
    fn register_device(&self, device: &DeviceRecord) -> StoreResult<bool>;

    /// Devices registered under `owner`.
    fn list_devices_for_user(&self, owner: &str) -> StoreResult<Vec<DeviceRecord>>;

    // ---- objects ----

    /// Stores an object entry after hash validation by the caller;
    /// returns true when newly stored, false for an identical duplicate.
    ///
    /// # Errors
    /// [`ControlPlaneError::HashMismatch`] when a different payload already
    /// exists under the same object id; propagates storage failures.
    fn put_object(&self, project: &ProjectId, entry: &ObjectEntryWire) -> StoreResult<bool>;

    /// All object ids held for `project`, sorted ascending.
    fn list_object_ids(&self, project: &ProjectId) -> StoreResult<Vec<ObjectId>>;

    /// Fetches the requested entries that exist, sorted by id.
    fn get_objects(
        &self,
        project: &ProjectId,
        ids: &[ObjectId],
    ) -> StoreResult<Vec<ObjectEntryWire>>;

    // ---- refs / environments ----

    /// Every ref state for `project`, sorted by (namespace, name).
    fn list_ref_states(&self, project: &ProjectId) -> StoreResult<Vec<RefState>>;

    /// Current value of one ref, if set.
    fn get_ref_state(
        &self,
        project: &ProjectId,
        namespace: RefNamespace,
        name: &str,
    ) -> StoreResult<Option<RefState>>;

    /// Unconditionally records `state` (protection/CAS checks belong to
    /// callers).
    ///
    /// # Errors
    /// Propagates storage failures.
    fn set_ref_state(&self, project: &ProjectId, state: &RefState) -> StoreResult<()>;

    /// Records environment protection metadata.
    ///
    /// # Errors
    /// Propagates storage failures.
    fn set_environment_protection(
        &self,
        project: &ProjectId,
        name: &str,
        protected: bool,
    ) -> StoreResult<()>;

    /// Protection flag for an environment ref; unprotected when unset.
    fn environment_protection(&self, project: &ProjectId, name: &str) -> StoreResult<bool>;

    /// All environment metadata rows for `project`.
    fn list_environments(&self, project: &ProjectId) -> StoreResult<Vec<EnvironmentMetadata>>;

    // ---- policies ----

    /// Upserts a named policy document.
    ///
    /// # Errors
    /// Propagates storage failures.
    fn upsert_policy(&self, project: &ProjectId, policy: &PolicyDocument) -> StoreResult<()>;

    /// All policy documents for `project`, sorted by name.
    fn list_policies(&self, project: &ProjectId) -> StoreResult<Vec<PolicyDocument>>;

    // ---- agents ----

    /// Registers an agent identity bound to its project.
    ///
    /// # Errors
    /// [`ControlPlaneError::Conflict`] when the identity already exists.
    fn create_agent_identity(
        &self,
        project: &ProjectId,
        agent_id: &AgentId,
        display_name: &str,
        policy_name: &PolicyName,
        created_by: &str,
    ) -> StoreResult<()>;

    /// Agent identities visible for `project`, sorted by id.
    fn list_agents(&self, project: &ProjectId) -> StoreResult<Vec<AgentView>>;

    /// Mints an agent session subordinate to `context`'s parent principal
    /// with bearer token `token`.
    ///
    /// # Errors
    /// Propagates storage failures.
    fn issue_agent_session(&self, token: &str, context: &AgentSessionContext) -> StoreResult<()>;

    /// Resolves an agent session token to its context.
    fn resolve_agent_session(&self, token: &str) -> StoreResult<Option<AgentSessionContext>>;

    // ---- audit ----

    /// Appends an immutable audit event.
    ///
    /// # Errors
    /// Propagates storage failures.
    fn append_audit_event(
        &self,
        project: Option<&ProjectId>,
        actor: &str,
        action: &str,
        detail_json: &str,
    ) -> StoreResult<AuditEventView>;

    /// Audit events for `project`, oldest first.
    fn list_audit_events(&self, project: &ProjectId) -> StoreResult<Vec<AuditEventView>>;

    // ---- sync state ----

    /// Records the last synced commit for `(project, device key)`.
    ///
    /// # Errors
    /// Propagates storage failures.
    fn update_sync_state(
        &self,
        project: &ProjectId,
        device_public_key_hex: &str,
        last_commit: Option<&CommitId>,
    ) -> StoreResult<()>;
}

/// Process-lifetime hermetic store intended for tests and ephemeral
/// tooling: sessions hold raw tokens in memory and everything evaporates
/// on drop. Share it by wrapping in `Arc` (as [`crate::router`] expects).
#[derive(Debug, Default)]
pub struct InMemoryControlPlaneStore {
    state: Mutex<StoreState>,
}

#[derive(Debug, Default)]
struct StoreState {
    users: BTreeMap<String, UserRecord>,
    sessions: BTreeMap<String, Principal>,
    workspaces: BTreeMap<String, WorkspaceRecord>,
    memberships: BTreeSet<(String, String)>,
    projects: BTreeMap<String, ProjectRecord>,
    devices: BTreeMap<String, DeviceRecord>,
    objects: BTreeMap<(String, String), ObjectEntryWire>,
    refs: BTreeMap<(String, u8, String), RefState>,
    environments: BTreeMap<(String, String), bool>,
    policies: BTreeMap<(String, String), PolicyDocument>,
    agents: BTreeMap<String, AgentRow>,
    agent_sessions: BTreeMap<String, AgentSessionContext>,
    audit: Vec<(Option<String>, AuditEventView)>,
    sync_state: BTreeMap<(String, String), Option<String>>,
}

#[derive(Debug)]
struct AgentRow {
    project: String,
    display_name: String,
    policy_name: String,
    revoked: bool,
}

impl InMemoryControlPlaneStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StoreState> {
        self.state
            .lock()
            .expect("control-plane store mutex poisoned")
    }

    fn namespace_rank(namespace: RefNamespace) -> u8 {
        match namespace {
            RefNamespace::Heads => 0,
            RefNamespace::Environments => 1,
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Fresh unique entity id with `prefix` (`ws_…`, `aud_…`).
///
/// # Errors
/// [`ControlPlaneError::Storage`] when entropy fails.
pub(crate) fn fresh_entity_id(prefix: &str) -> StoreResult<String> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| ControlPlaneError::Storage("id entropy unavailable".to_owned()))?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0u32, |d| d.subsec_nanos());
    Ok(format!("{prefix}{nanos:08x}{}", hex::encode(bytes)))
}

impl ControlPlaneStore for InMemoryControlPlaneStore {
    fn find_user(&self, login: &str) -> StoreResult<Option<UserRecord>> {
        Ok(self.lock().users.get(login).cloned())
    }

    fn upsert_user(&self, user: &UserRecord) -> StoreResult<()> {
        self.lock().users.insert(user.login.clone(), user.clone());
        Ok(())
    }

    fn issue_session(&self, token: &str, principal: &Principal) -> StoreResult<()> {
        self.lock()
            .sessions
            .insert(token.to_owned(), principal.clone());
        Ok(())
    }

    fn resolve_token(&self, token: &str) -> StoreResult<Option<Principal>> {
        Ok(self.lock().sessions.get(token).cloned())
    }

    fn create_workspace(&self, workspace: &WorkspaceRecord) -> StoreResult<()> {
        let mut state = self.lock();
        let id_key = workspace.id.as_str().to_owned();
        if state.workspaces.contains_key(&id_key) {
            return Ok(());
        }
        state.workspaces.insert(id_key.clone(), workspace.clone());
        state.memberships.insert((id_key, workspace.owner.clone()));
        Ok(())
    }

    fn list_workspaces_for_user(&self, user: &str) -> StoreResult<Vec<WorkspaceRecord>> {
        let state = self.lock();
        Ok(state
            .memberships
            .iter()
            .filter(|(_, member)| member == user)
            .filter_map(|(ws, _)| state.workspaces.get(ws))
            .cloned()
            .collect())
    }

    fn add_workspace_member(&self, membership: &WorkspaceMembership) -> StoreResult<()> {
        let mut state = self.lock();
        if !state.workspaces.contains_key(membership.workspace.as_str()) {
            return Err(ControlPlaneError::NotFound);
        }
        state.memberships.insert((
            membership.workspace.as_str().to_owned(),
            membership.user.clone(),
        ));
        Ok(())
    }

    fn is_workspace_member(&self, workspace: &WorkspaceId, user: &str) -> StoreResult<bool> {
        let state = self.lock();
        if !state.workspaces.contains_key(workspace.as_str()) {
            return Err(ControlPlaneError::NotFound);
        }
        Ok(state
            .memberships
            .contains(&(workspace.as_str().to_owned(), user.to_owned())))
    }

    fn create_project(&self, project: &ProjectRecord) -> StoreResult<()> {
        let mut state = self.lock();
        state
            .projects
            .insert(project.id.as_str().to_owned(), project.clone());
        Ok(())
    }

    fn get_project(&self, id: &ProjectId) -> StoreResult<Option<ProjectRecord>> {
        Ok(self.lock().projects.get(id.as_str()).cloned())
    }

    fn register_device(&self, device: &DeviceRecord) -> StoreResult<bool> {
        let mut state = self.lock();
        if state.devices.contains_key(&device.public_key_hex) {
            return Ok(false);
        }
        state
            .devices
            .insert(device.public_key_hex.clone(), device.clone());
        Ok(true)
    }

    fn list_devices_for_user(&self, owner: &str) -> StoreResult<Vec<DeviceRecord>> {
        let state = self.lock();
        Ok(state
            .devices
            .values()
            .filter(|d| d.owner == owner)
            .cloned()
            .collect())
    }

    fn put_object(&self, project: &ProjectId, entry: &ObjectEntryWire) -> StoreResult<bool> {
        let mut state = self.lock();
        let key = (project.as_str().to_owned(), entry.id.as_str().to_owned());
        match state.objects.get(&key) {
            Some(existing) => {
                if existing.envelope_json == entry.envelope_json {
                    Ok(false)
                } else {
                    Err(ControlPlaneError::HashMismatch)
                }
            }
            None => {
                state.objects.insert(key, entry.clone());
                Ok(true)
            }
        }
    }

    fn list_object_ids(&self, project: &ProjectId) -> StoreResult<Vec<ObjectId>> {
        let state = self.lock();
        let mut ids: Vec<ObjectId> = state
            .objects
            .keys()
            .filter(|(p, _)| p == project.as_str())
            .filter_map(|(_, oid)| ObjectId::parse(oid).ok())
            .collect();
        ids.sort();
        Ok(ids)
    }

    fn get_objects(
        &self,
        project: &ProjectId,
        ids: &[ObjectId],
    ) -> StoreResult<Vec<ObjectEntryWire>> {
        let wanted: BTreeSet<&str> = ids.iter().map(ObjectId::as_str).collect();
        let state = self.lock();
        let mut found = Vec::new();
        for ((project_key, oid), entry) in &state.objects {
            if project_key == project.as_str() && wanted.contains(oid.as_str()) {
                found.push(entry.clone());
            }
        }
        found.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(found)
    }

    fn list_ref_states(&self, project: &ProjectId) -> StoreResult<Vec<RefState>> {
        let state = self.lock();
        let mut refs: Vec<(u8, RefState)> = state
            .refs
            .iter()
            .filter(|((p, _, _), _)| p == project.as_str())
            .map(|((_, ns, _), r)| (*ns, r.clone()))
            .collect();
        refs.sort_by(|a, b| (&a.0, a.1.name.as_str()).cmp(&(&b.0, b.1.name.as_str())));
        Ok(refs.into_iter().map(|(_, r)| r).collect())
    }

    fn get_ref_state(
        &self,
        project: &ProjectId,
        namespace: RefNamespace,
        name: &str,
    ) -> StoreResult<Option<RefState>> {
        let state = self.lock();
        Ok(state
            .refs
            .get(&(
                project.as_str().to_owned(),
                Self::namespace_rank(namespace),
                name.to_owned(),
            ))
            .cloned())
    }

    fn set_ref_state(&self, project: &ProjectId, state_ref: &RefState) -> StoreResult<()> {
        self.lock().refs.insert(
            (
                project.as_str().to_owned(),
                Self::namespace_rank(state_ref.namespace),
                state_ref.name.clone(),
            ),
            state_ref.clone(),
        );
        Ok(())
    }

    fn set_environment_protection(
        &self,
        project: &ProjectId,
        name: &str,
        protected: bool,
    ) -> StoreResult<()> {
        self.lock()
            .environments
            .insert((project.as_str().to_owned(), name.to_owned()), protected);
        Ok(())
    }

    fn environment_protection(&self, project: &ProjectId, name: &str) -> StoreResult<bool> {
        Ok(self
            .lock()
            .environments
            .get(&(project.as_str().to_owned(), name.to_owned()))
            .copied()
            .unwrap_or(false))
    }

    fn list_environments(&self, project: &ProjectId) -> StoreResult<Vec<EnvironmentMetadata>> {
        let state = self.lock();
        let mut envs: Vec<EnvironmentMetadata> = state
            .environments
            .iter()
            .filter(|((p, _), _)| p == project.as_str())
            .map(|((_, name), protected)| EnvironmentMetadata {
                name: name.clone(),
                protected: *protected,
            })
            .collect();
        envs.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(envs)
    }

    fn upsert_policy(&self, project: &ProjectId, policy: &PolicyDocument) -> StoreResult<()> {
        self.lock().policies.insert(
            (project.as_str().to_owned(), policy.name.as_str().to_owned()),
            policy.clone(),
        );
        Ok(())
    }

    fn list_policies(&self, project: &ProjectId) -> StoreResult<Vec<PolicyDocument>> {
        let state = self.lock();
        let mut policies: Vec<PolicyDocument> = state
            .policies
            .iter()
            .filter(|((p, _), _)| p == project.as_str())
            .map(|(_, doc)| doc.clone())
            .collect();
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(policies)
    }

    fn create_agent_identity(
        &self,
        project: &ProjectId,
        agent_id: &AgentId,
        display_name: &str,
        policy_name: &PolicyName,
        _created_by: &str,
    ) -> StoreResult<()> {
        let mut state = self.lock();
        if state.agents.contains_key(agent_id.as_str()) {
            return Err(ControlPlaneError::Conflict(serde_json::json!({
                "error": "agent_already_exists"
            })));
        }
        state.agents.insert(
            agent_id.as_str().to_owned(),
            AgentRow {
                project: project.as_str().to_owned(),
                display_name: display_name.to_owned(),
                policy_name: policy_name.as_str().to_owned(),
                revoked: false,
            },
        );
        Ok(())
    }

    fn list_agents(&self, project: &ProjectId) -> StoreResult<Vec<AgentView>> {
        let state = self.lock();
        let mut views = Vec::new();
        for (agent_id, row) in &state.agents {
            if row.project != project.as_str() {
                continue;
            }
            views.push(AgentView {
                agent_id: AgentId::parse(agent_id)
                    .map_err(|_| ControlPlaneError::Storage("agent id".to_owned()))?,
                display_name: row.display_name.clone(),
                policy_name: PolicyName::parse(&row.policy_name)
                    .map_err(|_| ControlPlaneError::Storage("policy name".to_owned()))?,
                revoked: row.revoked,
            });
        }
        views.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
        Ok(views)
    }

    fn issue_agent_session(&self, token: &str, context: &AgentSessionContext) -> StoreResult<()> {
        self.lock()
            .agent_sessions
            .insert(token.to_owned(), context.clone());
        Ok(())
    }

    fn resolve_agent_session(&self, token: &str) -> StoreResult<Option<AgentSessionContext>> {
        Ok(self.lock().agent_sessions.get(token).cloned())
    }

    fn append_audit_event(
        &self,
        project: Option<&ProjectId>,
        actor: &str,
        action: &str,
        detail_json: &str,
    ) -> StoreResult<AuditEventView> {
        let event_id = fresh_entity_id(AuditEventId::PREFIX)?;
        let view = AuditEventView {
            event_id: AuditEventId::parse(&event_id)
                .map_err(|_| ControlPlaneError::Storage("audit id".to_owned()))?,
            actor: actor.to_owned(),
            action: action.to_owned(),
            detail: serde_json::from_str(detail_json)
                .map_err(|_| ControlPlaneError::Storage("audit detail".to_owned()))?,
            occurred_at_unix: now_unix(),
        };
        self.lock()
            .audit
            .push((project.map(|p| p.as_str().to_owned()), view.clone()));
        Ok(view)
    }

    fn list_audit_events(&self, project: &ProjectId) -> StoreResult<Vec<AuditEventView>> {
        let state = self.lock();
        Ok(state
            .audit
            .iter()
            .filter(|(p, _)| p.as_deref() == Some(project.as_str()))
            .map(|(_, v)| v.clone())
            .collect())
    }

    fn update_sync_state(
        &self,
        project: &ProjectId,
        device_public_key_hex: &str,
        last_commit: Option<&CommitId>,
    ) -> StoreResult<()> {
        self.lock().sync_state.insert(
            (
                project.as_str().to_owned(),
                device_public_key_hex.to_owned(),
            ),
            last_commit.map(CommitId::to_string),
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaultx_types::{ObjectId, ProjectId};

    use crate::auth::TokenClass;

    fn project() -> ProjectId {
        ProjectId::parse("proj_store_test").expect("valid")
    }

    fn entry(id_hex_tail: &str, body: &str) -> ObjectEntryWire {
        ObjectEntryWire {
            id: ObjectId::parse(&format!("obj_{id_hex_tail}")).expect("valid"),
            content_hash: id_hex_tail.to_owned(),
            envelope_json: body.to_owned(),
        }
    }

    #[test]
    fn user_and_session_round_trip() {
        let store = InMemoryControlPlaneStore::new();
        let user = UserRecord {
            login: "alice".to_owned(),
            display_name: None,
            verifier: "v".to_owned(),
        };
        store.upsert_user(&user).expect("upsert");
        assert_eq!(store.find_user("alice").unwrap(), Some(user));
        assert_eq!(store.find_user("bob").unwrap(), None);

        let principal = Principal {
            subject: "alice".to_owned(),
            class: TokenClass::ControlSession,
        };
        store.issue_session("vxs_t1", &principal).expect("issue");
        assert_eq!(store.resolve_token("vxs_t1").unwrap(), Some(principal));
        assert_eq!(store.resolve_token("missing").unwrap(), None);
    }

    #[test]
    fn objects_dedupe_identically_and_reject_divergent_content() {
        let store = InMemoryControlPlaneStore::new();
        let project = project();
        let e = entry("aa11", "{\"payload\":\"00\"}");
        assert!(store.put_object(&project, &e).unwrap());
        assert!(
            !store.put_object(&project, &e).unwrap(),
            "duplicate is no-op"
        );
        let divergent = entry("aa11", "{\"payload\":\"01\"}");
        assert!(matches!(
            store.put_object(&project, &divergent),
            Err(ControlPlaneError::HashMismatch)
        ));

        let other = entry("bb22", "{}");
        store.put_object(&project, &other).unwrap();
        let listed = store.list_object_ids(&project).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(store.get_objects(&project, &listed).unwrap().len(), 2);
    }

    #[test]
    fn refs_and_environments_round_trip_with_defaults() {
        let store = InMemoryControlPlaneStore::new();
        let project = project();
        assert!(!store
            .environment_protection(&project, "production")
            .unwrap());

        let head = RefState {
            namespace: RefNamespace::Heads,
            name: "main".to_owned(),
            commit: CommitId::parse("cmt_a").unwrap(),
            protected: false,
        };
        store.set_ref_state(&project, &head).unwrap();
        store
            .set_environment_protection(&project, "production", true)
            .unwrap();

        let env = RefState {
            namespace: RefNamespace::Environments,
            name: "production".to_owned(),
            commit: CommitId::parse("cmt_b").unwrap(),
            protected: true,
        };
        store.set_ref_state(&project, &env).unwrap();

        let listed = store.list_ref_states(&project).unwrap();
        assert_eq!(
            listed.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["main", "production"],
            "heads sort before environments"
        );
        assert_eq!(
            store
                .get_ref_state(&project, RefNamespace::Environments, "production")
                .unwrap(),
            Some(env)
        );
        assert!(store
            .environment_protection(&project, "production")
            .unwrap());

        let envs = store.list_environments(&project).unwrap();
        assert_eq!(envs.len(), 1);
        assert!(envs[0].protected);
    }

    #[test]
    fn agents_sessions_audit_and_sync_state() {
        let store = InMemoryControlPlaneStore::new();
        let project = project();
        let agent = AgentId::parse("agent_ci_bot").unwrap();
        let policy = PolicyName::parse("read_only").unwrap();

        store
            .create_agent_identity(&project, &agent, "ci-bot", &policy, "alice")
            .unwrap();
        assert!(matches!(
            store.create_agent_identity(&project, &agent, "dup", &policy, "alice"),
            Err(ControlPlaneError::Conflict(_))
        ));
        let views = store.list_agents(&project).unwrap();
        assert_eq!(views[0].policy_name, policy);

        let ctx = AgentSessionContext {
            agent_id: agent,
            parent_principal: "alice".to_owned(),
            project: project.clone(),
        };
        store.issue_agent_session("vxa_tok", &ctx).unwrap();
        assert_eq!(store.resolve_agent_session("vxa_tok").unwrap(), Some(ctx));

        let event = store
            .append_audit_event(Some(&project), "alice", "ref.update", "{}")
            .unwrap();
        assert!(event.event_id.as_str().starts_with("aud_"));
        assert_eq!(store.list_audit_events(&project).unwrap().len(), 1);

        let other_project = ProjectId::parse("proj_other").unwrap();
        assert!(store.list_audit_events(&other_project).unwrap().is_empty());

        store
            .update_sync_state(&project, "ab12", Some(&CommitId::parse("cmt_x").unwrap()))
            .unwrap();
    }
}
