//! Axum router implementing the plan §39 REST route surface.
//!
//! Every administrative route authorizes through
//! [`crate::auth::ADMIN_CLASSES`] (control-plane sessions only); the
//! data-plane sync route accepts [`crate::auth::SYNC_CLASSES`]. Agent
//! session tokens are therefore structurally unable to reach any route
//! here, satisfying the plan §39 route-surface separation note.

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use sha2::{Digest, Sha256};
use vaultx_crypto::signature::{verify as verify_signature, SignatureBytes, VerifyingPublicKey};
use vaultx_types::{AgentId, ObjectId, ProjectId};

use crate::auth;
use crate::error::ControlPlaneError;
use crate::model::{
    DeviceRecord, PolicyDocument, Principal, RefState, WorkspaceMembership, WorkspaceRecord,
};
use crate::protocol::{
    device_attestation_message, AgentView, AuditEventView, BatchObjectsRequest,
    BatchObjectsResponse, CreateAgentRequest, CreatedAgentResponse, DeviceKeyFingerprint,
    ObjectEntryWire, PutRefRequest, PutRefResponse, QueryMissingRequest, QueryMissingResponse,
    SessionRequest, SessionResponse, WorkspaceView,
};
use crate::store::{AgentSessionContext, ControlPlaneStore, RefCasOutcome};

/// Maximum accepted request body size (1 MiB).
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Maximum cardinality of list-typed request payloads.
const MAX_LIST_ITEMS: usize = 10_000;

/// Default per-response cap on `missing_objects` entries; clients loop
/// while responses report truncation.
const DEFAULT_MAX_MISSING_OBJECTS: usize = 10_000;

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    /// Persistence backend backing every handler.
    pub store: Arc<dyn ControlPlaneStore>,
    /// Per-response cap on `missing_objects` entries.
    pub max_missing_objects: usize,
}

impl AppState {
    /// Builds state with default response limits.
    #[must_use]
    pub fn new(store: Arc<dyn ControlPlaneStore>) -> Self {
        Self {
            store,
            max_missing_objects: DEFAULT_MAX_MISSING_OBJECTS,
        }
    }

    /// Overrides the per-response `missing_objects` cap (tests inject a
    /// tiny value to exercise the client's convergence loop).
    #[must_use]
    pub fn with_max_missing_objects(mut self, max_missing_objects: usize) -> Self {
        self.max_missing_objects = max_missing_objects;
        self
    }
}

/// Builds the control-plane router over `state`.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/auth/session", post(create_session))
        .route("/workspaces", get(list_workspaces).post(create_workspace))
        .route("/projects/{id}", get(get_project))
        .route("/projects/{id}/objects/batch", post(batch_objects))
        .route("/projects/{id}/objects/query-missing", post(query_missing))
        .route("/projects/{id}/refs", get(list_refs))
        .route("/projects/{id}/refs/{*name}", put(put_ref))
        .route("/projects/{id}/policies", get(list_policies))
        .route("/projects/{id}/policies/{name}", put(put_policy))
        .route("/projects/{id}/agents", get(list_agents).post(create_agent))
        .route("/projects/{id}/audit", get(project_audit))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

type HandlerResult<T> = Result<Json<T>, ControlPlaneError>;

/// Generates a fresh prefixed entity id and reparses it into its typed
/// form — the single home for the generate-then-reparse dance.
fn fresh_typed_id<T>(
    prefix: &str,
    parse: impl FnOnce(&str) -> Result<T, vaultx_types::TypeError>,
) -> Result<T, ControlPlaneError> {
    let raw = crate::store::fresh_entity_id(prefix)?;
    parse(&raw).map_err(|_| ControlPlaneError::Storage("entity id".to_owned()))
}

/// Loads `project` and enforces that `principal` belongs to its workspace.
fn require_project(
    store: &dyn ControlPlaneStore,
    principal: &Principal,
    project_id: &ProjectId,
) -> Result<crate::model::ProjectRecord, ControlPlaneError> {
    let project = store
        .get_project(project_id)?
        .ok_or(ControlPlaneError::NotFound)?;
    if !store.is_workspace_member(&project.workspace, &principal.subject)? {
        return Err(ControlPlaneError::Forbidden);
    }
    Ok(project)
}

async fn create_session(
    State(state): State<AppState>,
    Json(request): Json<SessionRequest>,
) -> HandlerResult<SessionResponse> {
    match request {
        SessionRequest::Password { username, password } => {
            let login = username.trim();
            if login.is_empty() || password.is_empty() {
                return Err(ControlPlaneError::BadRequest("credentials required"));
            }
            // No provisioning flow exists in this milestone: unknown users
            // are rejected outright. Users are created by direct store
            // construction (tooling/tests).
            let user = state
                .store
                .find_user(login)?
                .ok_or(ControlPlaneError::Unauthorized)?;
            if !auth::verify_verifier(&password, &user.verifier) {
                return Err(ControlPlaneError::Unauthorized);
            }
            let token = auth::mint_token(auth::TokenClass::ControlSession)?;
            state.store.issue_session(
                &token,
                &Principal {
                    subject: login.to_owned(),
                    class: auth::TokenClass::ControlSession,
                },
            )?;
            Ok(Json(SessionResponse {
                token,
                token_class: auth::TokenClass::ControlSession.wire_name().to_owned(),
            }))
        }
        SessionRequest::OidcExchange {
            provider,
            assertion,
        } => {
            if !is_provider_slug(&provider) || assertion.is_empty() {
                return Err(ControlPlaneError::BadRequest("invalid oidc exchange grant"));
            }
            let subject = auth::oidc_exchange_subject(&provider, &assertion);
            // Default deny: exchanges only mint workload sessions for
            // provider/subject pairs the store explicitly allowlisted.
            // Real JWKS verification of provider assertions remains a
            // documented production requirement.
            if !state.store.allows_oidc_subject(&provider, &subject) {
                return Err(ControlPlaneError::Unauthorized);
            }
            let token = auth::mint_token(auth::TokenClass::WorkloadExchange)?;
            state.store.issue_session(
                &token,
                &Principal {
                    subject,
                    class: auth::TokenClass::WorkloadExchange,
                },
            )?;
            Ok(Json(SessionResponse {
                token,
                token_class: auth::TokenClass::WorkloadExchange.wire_name().to_owned(),
            }))
        }
    }
}

fn is_provider_slug(provider: &str) -> bool {
    !provider.is_empty()
        && provider.len() <= 32
        && provider
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

async fn list_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> HandlerResult<Vec<WorkspaceView>> {
    let principal = auth::authorize(&*state.store, &headers, auth::ADMIN_CLASSES)?;
    let workspaces = state.store.list_workspaces_for_user(&principal.subject)?;
    Ok(Json(
        workspaces
            .into_iter()
            .map(|w| WorkspaceView {
                id: w.id,
                name: w.name,
            })
            .collect(),
    ))
}

async fn create_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<WorkspaceView>,
) -> HandlerResult<WorkspaceView> {
    let principal = auth::authorize(&*state.store, &headers, auth::ADMIN_CLASSES)?;
    let id = fresh_typed_id(
        vaultx_types::WorkspaceId::PREFIX,
        vaultx_types::WorkspaceId::parse,
    )?;
    let record = WorkspaceRecord {
        id: id.clone(),
        name: body.name,
        owner: principal.subject.clone(),
    };
    state.store.create_workspace(&record)?;
    state.store.add_workspace_member(&WorkspaceMembership {
        workspace: id.clone(),
        user: principal.subject,
        role: crate::model::ROLE_OWNER.to_owned(),
    })?;
    Ok(Json(WorkspaceView {
        id,
        name: record.name,
    }))
}

async fn get_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<ProjectId>,
) -> HandlerResult<crate::protocol::ProjectView> {
    let principal = auth::authorize(&*state.store, &headers, auth::ADMIN_CLASSES)?;
    let project = require_project(&*state.store, &principal, &project_id)?;
    Ok(Json(crate::protocol::ProjectView {
        id: project.id,
        workspace: project.workspace,
        name: project.name,
    }))
}

/// Validates an object entry's content hash against both its claimed hash
/// and its content-derived id.
fn validate_object_entry(entry: &ObjectEntryWire) -> Result<(), ControlPlaneError> {
    let expected_hex = entry
        .id
        .as_str()
        .strip_prefix(ObjectId::PREFIX)
        .unwrap_or("");
    if expected_hex.len() != 64 || entry.content_hash != expected_hex {
        return Err(ControlPlaneError::HashMismatch);
    }
    let mut hasher = Sha256::new();
    hasher.update(entry.envelope_json.as_bytes());
    let actual = hex::encode(hasher.finalize());
    if actual != expected_hex {
        return Err(ControlPlaneError::HashMismatch);
    }
    Ok(())
}

async fn batch_objects(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<ProjectId>,
    Json(body): Json<BatchObjectsRequest>,
) -> HandlerResult<BatchObjectsResponse> {
    let principal = auth::authorize(&*state.store, &headers, auth::ADMIN_CLASSES)?;
    require_project(&*state.store, &principal, &project_id)?;
    if body.entries.len() > MAX_LIST_ITEMS {
        return Err(ControlPlaneError::BadRequest("too many entries"));
    }

    let mut stored = 0usize;
    let mut duplicates = 0usize;
    for entry in &body.entries {
        validate_object_entry(entry)?;
        if state.store.put_object(&project_id, entry)? {
            stored += 1;
        } else {
            duplicates += 1;
        }
    }
    state.store.append_audit_event(
        Some(&project_id),
        &principal.subject,
        "objects.batch_upload",
        &serde_json::json!({ "stored": stored, "duplicates": duplicates }).to_string(),
    )?;
    Ok(Json(BatchObjectsResponse { stored, duplicates }))
}

async fn query_missing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<ProjectId>,
    Json(body): Json<QueryMissingRequest>,
) -> HandlerResult<QueryMissingResponse> {
    // Data-plane route: team sessions and OIDC-exchanged workload tokens
    // are accepted; agent tokens are rejected by class before lookup.
    let principal = auth::authorize(&*state.store, &headers, auth::SYNC_CLASSES)?;
    if body.project != project_id {
        return Err(ControlPlaneError::BadRequest("project mismatch"));
    }
    if body.known_object_ids.len() > MAX_LIST_ITEMS {
        return Err(ControlPlaneError::BadRequest("too many known object ids"));
    }
    let project = require_project(&*state.store, &principal, &project_id)?;

    verify_device_identity(&body.device, &project_id)?;
    // First-seen device keys register under the presenting principal so
    // commits stay attributable to a device identity (plan §29).
    state.store.register_device(&DeviceRecord {
        public_key_hex: body.device.public_key_hex.clone(),
        owner: principal.subject.clone(),
        label: None,
    })?;

    let mut server_key_fingerprints = Vec::new();
    for device in state.store.list_workspace_device_keys(&project.workspace)? {
        let key_bytes = device.validate_key()?;
        let mut hasher = Sha256::new();
        hasher.update(key_bytes);
        server_key_fingerprints.push(DeviceKeyFingerprint {
            fingerprint: hex::encode(hasher.finalize()),
            public_key_hex: device.public_key_hex,
        });
    }

    let known: std::collections::BTreeSet<&str> =
        body.known_object_ids.iter().map(ObjectId::as_str).collect();
    let remote_ids = state.store.list_object_ids(&project_id)?;
    let missing_ids: Vec<ObjectId> = remote_ids
        .iter()
        .filter(|id| !known.contains(id.as_str()))
        .cloned()
        .collect();
    let mut missing_objects = state.store.get_objects(&project_id, &missing_ids)?;
    // Cap per-response cardinality and say so; clients re-query (their
    // known set has advanced) until the flag clears.
    let missing_objects_truncated = missing_objects.len() > state.max_missing_objects;
    if missing_objects_truncated {
        missing_objects.truncate(state.max_missing_objects);
    }

    let mut remote_refs = state.store.list_ref_states(&project_id)?;
    for reference in &mut remote_refs {
        if reference.namespace == crate::model::RefNamespace::Environments {
            reference.protected = state
                .store
                .environment_protection(&project_id, &reference.name)?;
        }
    }

    let newest_head = remote_refs
        .iter()
        .find(|r| r.namespace == crate::model::RefNamespace::Heads && r.name == "main")
        .map(|r| r.commit.clone());

    state.store.update_sync_state(
        &project_id,
        &body.device.public_key_hex,
        newest_head.as_ref(),
    )?;
    state.store.append_audit_event(
        Some(&project_id),
        &principal.subject,
        "objects.query_missing",
        &serde_json::json!({
            "known_objects": body.known_object_ids.len(),
            "missing_returned": missing_objects.len(),
            "missing_truncated": missing_objects_truncated
        })
        .to_string(),
    )?;

    Ok(Json(QueryMissingResponse {
        missing_objects,
        missing_objects_truncated,
        remote_refs,
        remote_object_ids: remote_ids,
        policies: state.store.list_policies(&project_id)?,
        environments: state.store.list_environments(&project_id)?,
        server_key_fingerprints,
    }))
}

fn verify_device_identity(
    device: &crate::protocol::DeviceIdentity,
    project_id: &ProjectId,
) -> Result<(), ControlPlaneError> {
    let key_bytes = hex::decode(&device.public_key_hex)
        .map_err(|_| ControlPlaneError::BadRequest("device public key must be hex"))?;
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| ControlPlaneError::BadRequest("device public key must be 32 bytes"))?;
    let public = VerifyingPublicKey::from_bytes(&key)
        .map_err(|_| ControlPlaneError::BadRequest("device public key invalid"))?;
    let sig_bytes = hex::decode(&device.signature_hex)
        .map_err(|_| ControlPlaneError::BadRequest("device signature must be hex"))?;
    let message = device_attestation_message(project_id, &device.public_key_hex);
    verify_signature(&public, &message, &SignatureBytes(sig_bytes))
        .map_err(|_| ControlPlaneError::SignatureInvalid)
}

/// 409 body for a lost ref CAS race, carrying the server-side tip when
/// one exists so the loser can reconcile against it.
fn ref_conflict(current: Option<&RefState>) -> ControlPlaneError {
    ControlPlaneError::Conflict(serde_json::json!({
        "error": "ref_conflict",
        "current_commit": current.map(|c| c.commit.clone()),
    }))
}

async fn list_refs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<ProjectId>,
) -> HandlerResult<Vec<RefState>> {
    let principal = auth::authorize(&*state.store, &headers, auth::ADMIN_CLASSES)?;
    require_project(&*state.store, &principal, &project_id)?;
    Ok(Json(state.store.list_ref_states(&project_id)?))
}

async fn put_ref(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project_id, ref_name)): Path<(ProjectId, String)>,
    Json(body): Json<PutRefRequest>,
) -> HandlerResult<PutRefResponse> {
    let principal = auth::authorize(&*state.store, &headers, auth::ADMIN_CLASSES)?;
    require_project(&*state.store, &principal, &project_id)?;
    if vaultx_types::BranchRef::parse(&ref_name).is_err() {
        return Err(ControlPlaneError::BadRequest("invalid ref name"));
    }

    let current = state
        .store
        .get_ref_state(&project_id, body.namespace, &ref_name)?;

    // Protected environment refs reject unauthorized creation or update:
    // the protection registry is consulted by name regardless of whether
    // the ref exists yet, so a first write cannot bypass authorization.
    if body.namespace == crate::model::RefNamespace::Environments
        && state.store.environment_protection(&project_id, &ref_name)?
        && current.as_ref().is_none_or(|c| c.commit != body.commit)
        && !body.authorized
    {
        return Err(ControlPlaneError::Conflict(serde_json::json!({
            "error": "protected_environment_ref",
            "name": ref_name
        })));
    }

    // Atomic compare-and-swap: `base_commit: None` means "ref must not
    // exist", so concurrent create/update races are decided inside one
    // store step; losers surface a conflict carrying the winning tip.
    let next = match state.store.compare_and_swap_ref(
        &project_id,
        body.namespace,
        &ref_name,
        body.base_commit.as_ref(),
        &body.commit,
    )? {
        RefCasOutcome::Applied { next } => next,
        RefCasOutcome::Rejected { current } => return Err(ref_conflict(current.as_ref())),
    };

    state.store.append_audit_event(
        Some(&project_id),
        &principal.subject,
        "ref.update",
        &serde_json::json!({
            "ref": next.name,
            "namespace": next.namespace,
            "commit": next.commit.to_string()
        })
        .to_string(),
    )?;
    Ok(Json(PutRefResponse {
        commit: body.commit,
    }))
}

async fn list_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<ProjectId>,
) -> HandlerResult<Vec<PolicyDocument>> {
    let principal = auth::authorize(&*state.store, &headers, auth::ADMIN_CLASSES)?;
    require_project(&*state.store, &principal, &project_id)?;
    Ok(Json(state.store.list_policies(&project_id)?))
}

async fn put_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((project_id, policy_name)): Path<(ProjectId, String)>,
    Json(mut body): Json<PolicyDocument>,
) -> HandlerResult<PolicyDocument> {
    let principal = auth::authorize(&*state.store, &headers, auth::ADMIN_CLASSES)?;
    require_project(&*state.store, &principal, &project_id)?;
    let name = vaultx_types::PolicyName::parse(&policy_name)
        .map_err(|_| ControlPlaneError::BadRequest("invalid policy name"))?;
    if serde_json::from_str::<serde_json::Value>(&body.document_json).is_err() {
        return Err(ControlPlaneError::BadRequest(
            "policy document must be JSON",
        ));
    }
    body.name = name;
    state.store.upsert_policy(&project_id, &body)?;
    state.store.append_audit_event(
        Some(&project_id),
        &principal.subject,
        "policy.update",
        &serde_json::json!({ "policy": body.name.to_string() }).to_string(),
    )?;
    Ok(Json(body))
}

async fn list_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<ProjectId>,
) -> HandlerResult<Vec<AgentView>> {
    let principal = auth::authorize(&*state.store, &headers, auth::ADMIN_CLASSES)?;
    require_project(&*state.store, &principal, &project_id)?;
    Ok(Json(state.store.list_agents(&project_id)?))
}

async fn create_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<ProjectId>,
    Json(body): Json<CreateAgentRequest>,
) -> HandlerResult<CreatedAgentResponse> {
    let principal = auth::authorize(&*state.store, &headers, auth::ADMIN_CLASSES)?;
    require_project(&*state.store, &principal, &project_id)?;

    let agent_id = fresh_typed_id(AgentId::PREFIX, AgentId::parse)?;
    state.store.create_agent_identity(
        &project_id,
        &agent_id,
        body.display_name.as_str(),
        &body.policy_name,
        &principal.subject,
    )?;

    let token = auth::mint_token(auth::TokenClass::Agent)?;
    state.store.issue_agent_session(
        &token,
        &AgentSessionContext {
            agent_id: agent_id.clone(),
            parent_principal: principal.subject.clone(),
            project: project_id.clone(),
        },
    )?;
    state.store.append_audit_event(
        Some(&project_id),
        &principal.subject,
        "agent.created",
        &serde_json::json!({
            "agent_id": agent_id.to_string(),
            "policy": body.policy_name.to_string()
        })
        .to_string(),
    )?;

    Ok(Json(CreatedAgentResponse {
        agent_id,
        policy_name: body.policy_name,
        session_token: token,
    }))
}

async fn project_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(project_id): Path<ProjectId>,
) -> HandlerResult<Vec<AuditEventView>> {
    let principal = auth::authorize(&*state.store, &headers, auth::ADMIN_CLASSES)?;
    require_project(&*state.store, &principal, &project_id)?;
    Ok(Json(state.store.list_audit_events(&project_id)?))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use vaultx_crypto::signature::SigningKeyPair;
    use vaultx_types::ProjectId;

    use super::*;
    use crate::model::{RefNamespace, UserRecord, WorkspaceRecord};
    use crate::protocol::{
        device_attestation_message, ObjectEntryWire, PutRefRequest, SessionResponse,
    };
    use crate::store::InMemoryControlPlaneStore;

    const ALICE_TOKEN: &str = "vxs_alice_session";
    const AGENT_TOKEN: &str = "vxa_subordinate_agent";

    struct Fixture {
        app: Router,
        store: Arc<InMemoryControlPlaneStore>,
        project: ProjectId,
    }

    fn fixture() -> Fixture {
        let store = Arc::new(InMemoryControlPlaneStore::new());
        let ws_id = vaultx_types::WorkspaceId::parse("ws_api_test").expect("valid workspace id");
        let project_id = ProjectId::parse("proj_api_test").expect("valid project id");
        store
            .upsert_user(&UserRecord {
                login: "alice".to_owned(),
                display_name: None,
                verifier: crate::auth::hash_verifier("hunter2").expect("seed verifier"),
            })
            .expect("seed user");
        store
            .create_workspace(&WorkspaceRecord {
                id: ws_id.clone(),
                name: "acme".to_owned(),
                owner: "alice".to_owned(),
            })
            .expect("seed workspace");
        store
            .create_project(&crate::model::ProjectRecord {
                id: project_id.clone(),
                workspace: ws_id.clone(),
                name: "core".to_owned(),
            })
            .expect("seed project");
        store
            .issue_session(
                ALICE_TOKEN,
                &Principal {
                    subject: "alice".to_owned(),
                    class: crate::auth::TokenClass::ControlSession,
                },
            )
            .expect("seed session");
        let outsider_ws = vaultx_types::WorkspaceId::parse("ws_outsider").expect("valid");
        store
            .create_workspace(&WorkspaceRecord {
                id: outsider_ws,
                name: "other".to_owned(),
                owner: "mallory".to_owned(),
            })
            .expect("seed outsider workspace");

        Fixture {
            app: router(AppState::new(store.clone())),
            store,
            project: project_id,
        }
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<String>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let request = match body {
            Some(text) => builder
                .header("content-type", "application/json")
                .body(Body::from(text))
                .expect("request"),
            None => builder.body(Body::empty()).expect("request"),
        };
        let response = app.clone().oneshot(request).await.expect("infallible");
        let status = response.status();
        let bytes = BodyExt::collect(response.into_body())
            .await
            .expect("body")
            .to_bytes();
        let value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, value)
    }

    async fn password_session(app: &Router) -> String {
        let (status, value) = call(
            app,
            "POST",
            "/auth/session",
            None,
            Some(
                serde_json::json!({"kind":"password","username":"alice","password":"hunter2"})
                    .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let parsed: SessionResponse = serde_json::from_value(value).expect("session response");
        parsed.token
    }

    /// Builds a wire entry whose id and hash both match `payload`, the
    /// way a real repository would address canonical bytes.
    fn object_entry(payload: &str) -> ObjectEntryWire {
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let digest = hex::encode(hasher.finalize());
        ObjectEntryWire {
            id: vaultx_types::ObjectId::parse(&format!("obj_{digest}")).expect("hex digest"),
            content_hash: digest,
            envelope_json: payload.to_owned(),
        }
    }

    /// Builds a valid signed query-missing request body for `pair`.
    fn device_query(project: &ProjectId, pair: &SigningKeyPair) -> String {
        let public_hex = hex::encode(pair.verifying_public_key().to_bytes());
        let signature = pair.sign(&device_attestation_message(project, &public_hex));
        serde_json::json!({
            "known_object_ids": [],
            "known_refs": [],
            "project": project,
            "device": {
                "public_key_hex": public_hex,
                "signature_hex": hex::encode(signature.0)
            }
        })
        .to_string()
    }

    #[tokio::test]
    async fn wrong_password_is_unauthorized() {
        let fx = fixture();
        let (status, _) = call(
            &fx.app,
            "POST",
            "/auth/session",
            None,
            Some(
                serde_json::json!({"kind":"password","username":"alice","password":"nope"})
                    .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            fx.store.find_user("alice").unwrap().is_some(),
            "wrong password must not disturb the existing record"
        );
    }

    #[tokio::test]
    async fn unknown_user_is_unauthorized_without_provisioning() {
        let fx = fixture();
        let (status, value) = call(
            &fx.app,
            "POST",
            "/auth/session",
            None,
            Some(
                serde_json::json!({"kind":"password","username":"stranger","password":"pw"})
                    .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            fx.store.find_user("stranger").unwrap(),
            None,
            "unknown usernames must never be auto-created"
        );
        assert_eq!(value["error"]["code"], serde_json::json!("unauthorized"));
    }

    #[tokio::test]
    async fn password_session_can_list_workspaces() {
        let fx = fixture();
        let token = password_session(&fx.app).await;
        let (status, value) = call(&fx.app, "GET", "/workspaces", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value[0]["name"], "acme");
    }

    #[tokio::test]
    async fn garbage_token_is_unauthorized() {
        let fx = fixture();
        let (status, _) = call(&fx.app, "GET", "/workspaces", Some("totally-bogus"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unconfigured_oidc_exchange_is_unauthorized() {
        let fx = fixture();
        let (status, value) = call(
            &fx.app,
            "POST",
            "/auth/session",
            None,
            Some(
                serde_json::json!({
                    "kind": "oidc_exchange",
                    "provider": "github-actions",
                    "assertion": "eyJhbGciOiJSUzI1NiJ9.payload.sig"
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(value["error"]["code"], serde_json::json!("unauthorized"));
    }

    #[tokio::test]
    async fn oidc_exchange_issues_workload_token_rejected_on_admin_routes() {
        let fx = fixture();
        // Default deny: only explicitly allowlisted provider/subject pairs
        // mint workload sessions.
        let assertion = "eyJhbGciOiJSUzI1NiJ9.payload.sig";
        let subject = auth::oidc_exchange_subject("github-actions", assertion);
        fx.store.trust_oidc_subject("github-actions", &subject);

        let (status, value) = call(
            &fx.app,
            "POST",
            "/auth/session",
            None,
            Some(
                serde_json::json!({
                    "kind": "oidc_exchange",
                    "provider": "github-actions",
                    "assertion": assertion
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["token_class"], "workload_exchange");
        let workload_token = value["token"].as_str().expect("token").to_owned();

        // Workload tokens are data-plane credentials only.
        let (status, _) = call(&fx.app, "GET", "/workspaces", Some(&workload_token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // ...and on the object upload route.
        let uri = format!("/projects/{}/objects/batch", fx.project);
        let entry = object_entry("{\"payload\":\"00\"}");
        let (status, _) = call(
            &fx.app,
            "POST",
            &uri,
            Some(&workload_token),
            Some(serde_json::json!({"entries":[entry]}).to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn agent_token_rejected_on_every_admin_route() {
        let fx = fixture();
        let project = fx.project.to_string();
        for (method, uri, body) in [
            ("GET", "/workspaces".to_owned(), None),
            (
                "POST",
                "/workspaces".to_owned(),
                Some(r#"{"id":"ws_x","name":"x"}"#.to_owned()),
            ),
            ("GET", format!("/projects/{project}"), None),
            (
                "POST",
                format!("/projects/{project}/objects/batch"),
                Some(r#"{"entries":[]}"#.to_owned()),
            ),
            ("GET", format!("/projects/{project}/refs"), None),
            (
                "PUT",
                format!("/projects/{project}/refs/main"),
                Some(r#"{"namespace":"heads","commit":"cmt_main"}"#.to_owned()),
            ),
            ("GET", format!("/projects/{project}/policies"), None),
            (
                "PUT",
                format!("/projects/{project}/policies/read_only"),
                Some(r#"{"name":"read_only","document_json":"{}"}"#.to_owned()),
            ),
            ("GET", format!("/projects/{project}/agents"), None),
            (
                "POST",
                format!("/projects/{project}/agents"),
                Some(r#"{"display_name":"bot","policy_name":"read_only"}"#.to_owned()),
            ),
            ("GET", format!("/projects/{project}/audit"), None),
        ] {
            let (status, _) = call(&fx.app, method, &uri, Some(AGENT_TOKEN), body).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "agent token must not reach {method} {uri}"
            );
        }
    }

    #[tokio::test]
    async fn project_routes_require_workspace_membership() {
        let fx = fixture();
        // Mallory holds a valid session but no membership in the project's
        // workspace; sessions are minted by direct store seeding here
        // because no provisioning flow exists.
        let mallory_token = "vxs_mallory_session";
        fx.store
            .issue_session(
                mallory_token,
                &Principal {
                    subject: "mallory".to_owned(),
                    class: crate::auth::TokenClass::ControlSession,
                },
            )
            .unwrap();
        let uri = format!("/projects/{}", fx.project);
        let (status, _) = call(&fx.app, "GET", &uri, Some(mallory_token), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn batch_objects_validates_content_hashes() {
        let fx = fixture();
        let good = object_entry("{\"payload\":\"00\"}");
        let mut bad = object_entry("{\"payload\":\"01\"}");
        bad.content_hash = "00".repeat(32);
        let uri = format!("/projects/{}/objects/batch", fx.project);

        let (status, value) = call(
            &fx.app,
            "POST",
            &uri,
            Some(ALICE_TOKEN),
            Some(serde_json::json!({"entries":[good]}).to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["stored"], 1);

        let (status, _) = call(
            &fx.app,
            "POST",
            &uri,
            Some(ALICE_TOKEN),
            Some(serde_json::json!({"entries":[bad]}).to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn query_missing_rejects_invalid_device_signature() {
        let fx = fixture();
        let pair = SigningKeyPair::generate();
        let public_hex = hex::encode(pair.verifying_public_key().to_bytes());
        let forged = pair.sign(b"not the attestation message");
        let uri = format!("/projects/{}/objects/query-missing", fx.project);
        let (status, value) = call(
            &fx.app,
            "POST",
            &uri,
            Some(ALICE_TOKEN),
            Some(
                serde_json::json!({
                    "known_object_ids": [],
                    "known_refs": [],
                    "project": fx.project,
                    "device": {
                        "public_key_hex": public_hex,
                        "signature_hex": hex::encode(forged.0)
                    }
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            value["error"]["code"],
            serde_json::json!("signature_verification_failed")
        );
    }

    #[tokio::test]
    async fn query_missing_returns_missing_objects_and_metadata() {
        let fx = fixture();
        let stored = vec![
            object_entry("{\"payload\":\"00\"}"),
            object_entry("{\"payload\":\"01\"}"),
        ];
        let batch_uri = format!("/projects/{}/objects/batch", fx.project);
        let (status, _) = call(
            &fx.app,
            "POST",
            &batch_uri,
            Some(ALICE_TOKEN),
            Some(serde_json::json!({"entries": stored}).to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let pair = SigningKeyPair::generate();
        let public_hex = hex::encode(pair.verifying_public_key().to_bytes());
        let message = device_attestation_message(&fx.project, &public_hex);
        let signature = pair.sign(&message);
        let known = stored[0].id.clone();
        let uri = format!("/projects/{}/objects/query-missing", fx.project);
        let (status, value) = call(
            &fx.app,
            "POST",
            &uri,
            Some(ALICE_TOKEN),
            Some(
                serde_json::json!({
                    "known_object_ids": [known],
                    "known_refs": [],
                    "project": fx.project,
                    "device": {
                        "public_key_hex": public_hex,
                        "signature_hex": hex::encode(signature.0)
                    }
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["missing_objects"].as_array().expect("array").len(), 1);
        assert_eq!(
            value["missing_objects"][0]["id"],
            serde_json::json!(stored[1].id.to_string())
        );
        assert_eq!(
            value["remote_object_ids"]
                .as_array()
                .expect("remote ids")
                .len(),
            2
        );
        assert_eq!(value["remote_refs"].as_array().expect("refs").len(), 0);
        let keys = value["server_key_fingerprints"]
            .as_array()
            .expect("device keys served");
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys[0]["public_key_hex"],
            serde_json::json!(hex::encode(pair.verifying_public_key().to_bytes()))
        );
        let mut key_hasher = Sha256::new();
        let served_key = keys[0]["public_key_hex"].as_str().expect("key hex");
        key_hasher.update(hex::decode(served_key).expect("hex"));
        assert_eq!(
            keys[0]["fingerprint"],
            serde_json::json!(hex::encode(key_hasher.finalize()))
        );
        assert_eq!(fx.store.list_devices_for_user("alice").unwrap().len(), 1);
    }

    #[tokio::test]
    async fn query_missing_serves_all_workspace_member_device_keys() {
        let fx = fixture();
        let pair_a = SigningKeyPair::generate();
        let pair_b = SigningKeyPair::generate();

        // Alice registers her device through the sync flow.
        let uri = format!("/projects/{}/objects/query-missing", fx.project);
        let (status, _) = call(
            &fx.app,
            "POST",
            &uri,
            Some(ALICE_TOKEN),
            Some(device_query(&fx.project, &pair_a)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // A second workspace member registers theirs.
        fx.store
            .add_workspace_member(&WorkspaceMembership {
                workspace: vaultx_types::WorkspaceId::parse("ws_api_test").expect("valid"),
                user: "bob".to_owned(),
                role: crate::model::ROLE_MEMBER.to_owned(),
            })
            .unwrap();
        let bob_token = "vxs_bob_session";
        fx.store
            .issue_session(
                bob_token,
                &Principal {
                    subject: "bob".to_owned(),
                    class: crate::auth::TokenClass::ControlSession,
                },
            )
            .unwrap();
        let (status, _) = call(
            &fx.app,
            "POST",
            &uri,
            Some(bob_token),
            Some(device_query(&fx.project, &pair_b)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Both members' keys are served, deterministically ordered.
        let (status, value) = call(
            &fx.app,
            "POST",
            &uri,
            Some(ALICE_TOKEN),
            Some(device_query(&fx.project, &pair_a)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let keys = value["server_key_fingerprints"].as_array().expect("keys");
        let mut expected: Vec<String> = vec![&pair_a, &pair_b]
            .into_iter()
            .map(|p| hex::encode(p.verifying_public_key().to_bytes()))
            .collect();
        expected.sort();
        let served: Vec<String> = keys
            .iter()
            .map(|k| k["public_key_hex"].as_str().expect("key").to_owned())
            .collect();
        assert_eq!(served, expected);
    }

    #[tokio::test]
    async fn put_ref_cas_conflict_surfaces_409() {
        let fx = fixture();
        let base = vaultx_types::CommitId::parse("cmt_base").expect("valid");
        let next = vaultx_types::CommitId::parse("cmt_next").expect("valid");
        let other = vaultx_types::CommitId::parse("cmt_other").expect("valid");
        fx.store
            .set_ref_state(
                &fx.project,
                &crate::model::RefState {
                    namespace: RefNamespace::Heads,
                    name: "main".to_owned(),
                    commit: base.clone(),
                    protected: false,
                },
            )
            .unwrap();

        // Stale base -> 409 carrying the current commit; never auto-picked.
        let uri = format!("/projects/{}/refs/main", fx.project);
        let body = PutRefRequest {
            namespace: RefNamespace::Heads,
            commit: next.clone(),
            base_commit: Some(other),
            authorized: false,
        };
        let (status, value) = call(
            &fx.app,
            "PUT",
            &uri,
            Some(ALICE_TOKEN),
            Some(serde_json::to_string(&body).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(value["error"], "ref_conflict");
        assert_eq!(value["current_commit"], serde_json::json!(base.to_string()));

        // Correct base -> applied.
        let body = PutRefRequest {
            namespace: RefNamespace::Heads,
            commit: next.clone(),
            base_commit: Some(base),
            authorized: false,
        };
        let (status, _) = call(
            &fx.app,
            "PUT",
            &uri,
            Some(ALICE_TOKEN),
            Some(serde_json::to_string(&body).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_environment_ref_requires_authorization() {
        let fx = fixture();
        fx.store
            .set_environment_protection(&fx.project, "production", true)
            .unwrap();
        let first = vaultx_types::CommitId::parse("cmt_prod_first").expect("valid");
        fx.store
            .set_ref_state(
                &fx.project,
                &crate::model::RefState {
                    namespace: RefNamespace::Environments,
                    name: "production".to_owned(),
                    commit: first.clone(),
                    protected: true,
                },
            )
            .unwrap();
        let second = vaultx_types::CommitId::parse("cmt_prod_second").expect("valid");
        let uri = format!("/projects/{}/refs/production", fx.project);

        let unauthorized = PutRefRequest {
            namespace: RefNamespace::Environments,
            commit: second.clone(),
            base_commit: Some(first.clone()),
            authorized: false,
        };
        let (status, value) = call(
            &fx.app,
            "PUT",
            &uri,
            Some(ALICE_TOKEN),
            Some(serde_json::to_string(&unauthorized).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(value["error"], "protected_environment_ref");

        let authorized = PutRefRequest {
            namespace: RefNamespace::Environments,
            commit: second,
            base_commit: Some(first),
            authorized: true,
        };
        let (status, _) = call(
            &fx.app,
            "PUT",
            &uri,
            Some(ALICE_TOKEN),
            Some(serde_json::to_string(&authorized).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_environment_creation_requires_authorization() {
        let fx = fixture();
        // Protection is registered by name only; the ref does not exist yet.
        fx.store
            .set_environment_protection(&fx.project, "staging", true)
            .unwrap();
        let first = vaultx_types::CommitId::parse("cmt_stage_first").expect("valid");
        let uri = format!("/projects/{}/refs/staging", fx.project);

        // A first write creating a protected-named env ref still demands
        // authorization — creation cannot bypass the registry.
        let unauthorized = PutRefRequest {
            namespace: RefNamespace::Environments,
            commit: first.clone(),
            base_commit: None,
            authorized: false,
        };
        let (status, value) = call(
            &fx.app,
            "PUT",
            &uri,
            Some(ALICE_TOKEN),
            Some(serde_json::to_string(&unauthorized).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(value["error"], "protected_environment_ref");
        assert_eq!(
            fx.store
                .get_ref_state(&fx.project, RefNamespace::Environments, "staging")
                .unwrap(),
            None,
            "unauthorized creation must not land"
        );

        let authorized = PutRefRequest {
            namespace: RefNamespace::Environments,
            commit: first,
            base_commit: None,
            authorized: true,
        };
        let (status, _) = call(
            &fx.app,
            "PUT",
            &uri,
            Some(ALICE_TOKEN),
            Some(serde_json::to_string(&authorized).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(fx
            .store
            .get_ref_state(&fx.project, RefNamespace::Environments, "staging")
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn absent_ref_base_conflicts_once_created() {
        let fx = fixture();
        let winner = vaultx_types::CommitId::parse("cmt_race_win").expect("valid");
        let loser = vaultx_types::CommitId::parse("cmt_race_lose").expect("valid");
        let uri = format!("/projects/{}/refs/main", fx.project);

        // The first publisher claiming an absent ref wins.
        let create = PutRefRequest {
            namespace: RefNamespace::Heads,
            commit: winner.clone(),
            base_commit: None,
            authorized: false,
        };
        let (status, _) = call(
            &fx.app,
            "PUT",
            &uri,
            Some(ALICE_TOKEN),
            Some(serde_json::to_string(&create).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // A concurrent publisher also claiming "absent" loses with the
        // winning tip attached for reconciliation.
        let racing = PutRefRequest {
            namespace: RefNamespace::Heads,
            commit: loser.clone(),
            base_commit: None,
            authorized: false,
        };
        let (status, value) = call(
            &fx.app,
            "PUT",
            &uri,
            Some(ALICE_TOKEN),
            Some(serde_json::to_string(&racing).unwrap()),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(value["error"], "ref_conflict");
        assert_eq!(
            value["current_commit"],
            serde_json::json!(winner.to_string())
        );
        assert_eq!(
            fx.store
                .get_ref_state(&fx.project, RefNamespace::Heads, "main")
                .unwrap()
                .map(|r| r.commit),
            Some(winner)
        );
    }

    #[tokio::test]
    async fn audit_route_lists_recorded_events() {
        let fx = fixture();
        let pair = SigningKeyPair::generate();
        let public_hex = hex::encode(pair.verifying_public_key().to_bytes());
        let message = device_attestation_message(&fx.project, &public_hex);
        let signature = pair.sign(&message);
        let uri = format!("/projects/{}/objects/query-missing", fx.project);
        let (status, _) = call(
            &fx.app,
            "POST",
            &uri,
            Some(ALICE_TOKEN),
            Some(
                serde_json::json!({
                    "known_object_ids": [],
                    "known_refs": [],
                    "project": fx.project,
                    "device": {
                        "public_key_hex": public_hex,
                        "signature_hex": hex::encode(signature.0)
                    }
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let audit_uri = format!("/projects/{}/audit", fx.project);
        let (status, value) = call(&fx.app, "GET", &audit_uri, Some(ALICE_TOKEN), None).await;
        assert_eq!(status, StatusCode::OK);
        let events = value.as_array().expect("events");
        assert!(events
            .iter()
            .any(|e| e["action"] == "objects.query_missing"));
    }

    #[tokio::test]
    async fn concurrent_create_race_admits_exactly_one_writer() {
        let fx = fixture();
        let uri = format!("/projects/{}/refs/main", fx.project);
        let mut handles = Vec::new();
        for i in 0..8u32 {
            let app = fx.app.clone();
            let uri = uri.clone();
            handles.push(tokio::spawn(async move {
                let commit =
                    vaultx_types::CommitId::parse(&format!("cmt_create_{i:02}")).expect("valid");
                let body = PutRefRequest {
                    namespace: RefNamespace::Heads,
                    commit: commit.clone(),
                    base_commit: None,
                    authorized: false,
                };
                let (status, value) = call(
                    &app,
                    "PUT",
                    &uri,
                    Some(ALICE_TOKEN),
                    Some(serde_json::to_string(&body).expect("body")),
                )
                .await;
                (commit, status, value)
            }));
        }
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await.expect("task"));
        }
        let winners: Vec<_> = results
            .iter()
            .filter(|(_, s, _)| *s == StatusCode::OK)
            .collect();
        let losers: Vec<_> = results
            .iter()
            .filter(|(_, s, _)| *s == StatusCode::CONFLICT)
            .collect();
        assert_eq!(winners.len(), 1, "exactly one create may win");
        assert_eq!(losers.len(), 7);
        let winning_commit = &winners[0].0;
        for (_, _, value) in &losers {
            assert_eq!(value["error"], "ref_conflict");
            assert_eq!(
                value["current_commit"],
                serde_json::json!(winning_commit.to_string()),
                "losers must carry the winner's tip"
            );
        }
        assert_eq!(
            fx.store
                .get_ref_state(&fx.project, RefNamespace::Heads, "main")
                .unwrap()
                .map(|r| r.commit),
            Some(winning_commit.clone())
        );
    }

    #[tokio::test]
    async fn concurrent_update_race_admits_exactly_one_writer() {
        let fx = fixture();
        let base = vaultx_types::CommitId::parse("cmt_update_base").expect("valid");
        fx.store
            .set_ref_state(
                &fx.project,
                &crate::model::RefState {
                    namespace: RefNamespace::Heads,
                    name: "main".to_owned(),
                    commit: base.clone(),
                    protected: false,
                },
            )
            .unwrap();
        let uri = format!("/projects/{}/refs/main", fx.project);
        let mut handles = Vec::new();
        for i in 0..8u32 {
            let app = fx.app.clone();
            let uri = uri.clone();
            let base = base.clone();
            handles.push(tokio::spawn(async move {
                let commit =
                    vaultx_types::CommitId::parse(&format!("cmt_update_{i:02}")).expect("valid");
                let body = PutRefRequest {
                    namespace: RefNamespace::Heads,
                    commit: commit.clone(),
                    base_commit: Some(base),
                    authorized: false,
                };
                let (status, value) = call(
                    &app,
                    "PUT",
                    &uri,
                    Some(ALICE_TOKEN),
                    Some(serde_json::to_string(&body).expect("body")),
                )
                .await;
                (commit, status, value)
            }));
        }
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            results.push(handle.await.expect("task"));
        }
        let winners: Vec<_> = results
            .iter()
            .filter(|(_, s, _)| *s == StatusCode::OK)
            .collect();
        assert_eq!(winners.len(), 1, "exactly one update may win the CAS");
        let losing_tips_ok = results
            .iter()
            .filter(|(c, s, _)| c != &winners[0].0 && *s == StatusCode::CONFLICT)
            .all(|(_, _, value)| value["error"] == "ref_conflict");
        assert!(losing_tips_ok);
        assert_eq!(
            fx.store
                .get_ref_state(&fx.project, RefNamespace::Heads, "main")
                .unwrap()
                .map(|r| r.commit),
            Some(winners[0].0.clone())
        );
    }

    #[tokio::test]
    async fn oversize_known_object_id_list_is_rejected() {
        let fx = fixture();
        // Compact ids keep the raw body under the 1 MiB transport limit so
        // the request reaches the cardinality check itself.
        let known: Vec<String> = (0..=MAX_LIST_ITEMS)
            .map(|i| format!("obj_{i:064x}"))
            .collect();
        let body = serde_json::json!({
            "known_object_ids": known,
            "known_refs": [],
            "project": fx.project,
            "device": {
                "public_key_hex": "00",
                "signature_hex": "00"
            }
        })
        .to_string();
        assert!(
            body.len() < MAX_BODY_BYTES,
            "test payload must stay under the body limit to reach the cardinality check"
        );
        let uri = format!("/projects/{}/objects/query-missing", fx.project);
        let (status, _) = call(&fx.app, "POST", &uri, Some(ALICE_TOKEN), Some(body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn query_missing_flags_truncation_when_cap_hit() {
        let store = Arc::new(InMemoryControlPlaneStore::new());
        let ws_id = vaultx_types::WorkspaceId::parse("ws_api_test").expect("valid");
        let project_id = ProjectId::parse("proj_api_test").expect("valid");
        store
            .upsert_user(&UserRecord {
                login: "alice".to_owned(),
                display_name: None,
                verifier: crate::auth::hash_verifier("hunter2").expect("seed verifier"),
            })
            .unwrap();
        store
            .create_workspace(&WorkspaceRecord {
                id: ws_id.clone(),
                name: "acme".to_owned(),
                owner: "alice".to_owned(),
            })
            .unwrap();
        store
            .create_project(&crate::model::ProjectRecord {
                id: project_id.clone(),
                workspace: ws_id,
                name: "core".to_owned(),
            })
            .unwrap();
        store
            .issue_session(
                ALICE_TOKEN,
                &Principal {
                    subject: "alice".to_owned(),
                    class: crate::auth::TokenClass::ControlSession,
                },
            )
            .unwrap();

        // Tiny injected cap forces a truncated first response.
        let app = router(AppState::new(store).with_max_missing_objects(1));
        let stored = vec![
            object_entry("{\"payload\":\"00\"}"),
            object_entry("{\"payload\":\"01\"}"),
        ];
        let batch_uri = format!("/projects/{}/objects/batch", project_id);
        let (status, _) = call(
            &app,
            "POST",
            &batch_uri,
            Some(ALICE_TOKEN),
            Some(serde_json::json!({"entries": stored}).to_string()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let pair = SigningKeyPair::generate();
        let public_hex = hex::encode(pair.verifying_public_key().to_bytes());
        let message = device_attestation_message(&project_id, &public_hex);
        let signature = pair.sign(&message);
        let uri = format!("/projects/{}/objects/query-missing", project_id);
        let (status, value) = call(
            &app,
            "POST",
            &uri,
            Some(ALICE_TOKEN),
            Some(
                serde_json::json!({
                    "known_object_ids": [],
                    "known_refs": [],
                    "project": project_id,
                    "device": {
                        "public_key_hex": public_hex,
                        "signature_hex": hex::encode(signature.0)
                    }
                })
                .to_string(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            value["missing_objects"].as_array().expect("array").len(),
            1,
            "response must respect the cap"
        );
        assert_eq!(value["missing_objects_truncated"], true);
    }

    #[test]
    fn migrations_cover_every_core_table() {
        let sql = concat!(
            include_str!("../migrations/0001_identity_workspaces_projects.sql"),
            include_str!("../migrations/0002_sync_policies_agents_audit.sql"),
        );
        for table in [
            "users",
            "workspaces",
            "workspace_members",
            "projects",
            "devices",
            "project_members",
            "objects",
            "refs",
            "environments",
            "policies",
            "policy_bindings",
            "agent_identities",
            "agent_sessions",
            "audit_events",
            "sync_state",
        ] {
            assert!(
                sql.contains(&format!("CREATE TABLE {table}")),
                "migration DDL missing table `{table}`"
            );
        }
    }
}
