//! [`ControlPlaneSyncClient`] — the concrete [`SyncService`] driving the
//! plan §28 sync protocol against a control plane over any transport.
//!
//! Invariants enforced here (never delegated to the server):
//!
//! * every downloaded object is re-canonicalized and hashed independently;
//!   a mismatch aborts the pull before anything is applied;
//! * remote refs reconcile only by ancestry: fast-forward or explicit
//!   [`RefConflict`] — divergent histories are never silently picked
//!   between;
//! * protected environment refs refuse updates unless the client was
//!   explicitly configured with authorization for this run.

use std::collections::BTreeSet;

use serde::de::DeserializeOwned;
use vaultx_control_plane::model::RefState;
use vaultx_control_plane::protocol::{
    BatchObjectsRequest, BatchObjectsResponse, ObjectEntryWire, PutRefRequest, QueryMissingRequest,
    QueryMissingResponse,
};
use vaultx_crypto::signature::{verify as verify_signature, VerifyingPublicKey};
use vaultx_repository::object::{hash_canonical, ObjectEnvelope, ObjectType};
use vaultx_repository::Commit;
use vaultx_types::{CommitId, ObjectId, ProjectId};

use crate::device::DeviceKeySource;
use crate::error::{SyncError, SyncResultOf};
use crate::local::{is_ancestor_or_equal, LocalWorkspace};
use crate::transport::{ControlPlaneTransport, TransportRequest, TransportResponse};
use crate::{ConflictReason, RefConflict, SyncResult, SyncService};

/// Knobs controlling one client instance's behavior.
#[derive(Clone, Copy, Debug, Default)]
pub struct SyncOptions {
    /// When true, updates to protected environment refs carry explicit
    /// authorization and apply with override. Default: false — protected
    /// environments reject unauthorized updates.
    pub authorize_protected_environments: bool,
}

/// Sync client bound to one local workspace, one transport, and one device
/// identity.
#[derive(Clone, Debug)]
pub struct ControlPlaneSyncClient<T: ControlPlaneTransport, W: LocalWorkspace> {
    transport: T,
    workspace: W,
    keys: DeviceKeySource,
    options: SyncOptions,
}

impl<T: ControlPlaneTransport, W: LocalWorkspace> ControlPlaneSyncClient<T, W> {
    /// Builds a client over `workspace` with default options.
    #[must_use]
    pub fn new(transport: T, workspace: W, keys: DeviceKeySource) -> Self {
        Self {
            transport,
            workspace,
            keys,
            options: SyncOptions::default(),
        }
    }

    /// Builds a client with explicit options.
    #[must_use]
    pub fn with_options(
        transport: T,
        workspace: W,
        keys: DeviceKeySource,
        options: SyncOptions,
    ) -> Self {
        Self {
            transport,
            workspace,
            keys,
            options,
        }
    }

    /// The local workspace this client synchronizes.
    #[must_use]
    pub fn workspace(&self) -> &W {
        &self.workspace
    }

    async fn send(&self, request: TransportRequest) -> SyncResultOf<TransportResponse> {
        self.transport.send(request).await
    }

    /// Sends a typed request, decoding the 2xx response body as JSON.
    async fn send_json<Body: serde::Serialize, Response: DeserializeOwned>(
        &self,
        mut request: TransportRequest,
        body: Option<&Body>,
    ) -> SyncResultOf<Response> {
        if let Some(body) = body {
            request.json_body = Some(
                serde_json::to_string(body).map_err(|_| SyncError::Protocol("request encode"))?,
            );
        }
        let response = self.send(request).await?;
        if !response.is_success() {
            return Err(map_rejection(&response));
        }
        response.json()
    }

    /// Runs the query-missing probe shared by push and pull: declares
    /// known objects/refs plus signed device identity, receives missing
    /// objects, remote refs, policy/environment metadata, key material.
    async fn probe(&self, project: &ProjectId) -> SyncResultOf<QueryMissingResponse> {
        let known_object_ids = self.workspace.known_object_ids()?;
        let known_refs = self.workspace.all_refs()?;
        let device = self.keys.attestation(project).map_err(SyncError::Keyring)?;
        self.send_json(
            TransportRequest::post(
                format!("/projects/{project}/objects/query-missing"),
                String::new(),
            ),
            Some(&QueryMissingRequest {
                known_object_ids,
                known_refs,
                project: project.clone(),
                device,
            }),
        )
        .await
    }

    /// Verifies every returned object independently (canonical re-encode +
    /// SHA-256 + id agreement), plus commit signatures against the device
    /// keys served by the control plane; applies all only after every
    /// check passed. Unsigned content is accepted for back-compat with
    /// local-only repositories; any present signature that fails
    /// verification is fatal and aborts before anything is applied.
    async fn download_and_apply(&self, response: &QueryMissingResponse) -> SyncResultOf<usize> {
        let trusted_keys = trusted_device_keys(&response.server_key_fingerprints);
        let mut verified = Vec::with_capacity(response.missing_objects.len());
        for entry in &response.missing_objects {
            let envelope: ObjectEnvelope = serde_json::from_str(&entry.envelope_json)
                .map_err(|_| SyncError::Protocol("envelope decode"))?;
            let canonical = envelope.canonical_bytes()?;
            let digest = hex::encode(hash_canonical(&canonical));
            if digest != entry.content_hash || digest != digest_suffix(entry.id.as_str()) {
                return Err(SyncError::HashMismatch {
                    object: entry.id.to_string(),
                });
            }
            if envelope.object_type == ObjectType::Commit {
                verify_commit_signature(entry.id.as_str(), &envelope, &trusted_keys)?;
            }
            verified.push(envelope);
        }
        let mut downloaded = 0usize;
        for envelope in &verified {
            if self.workspace.apply_object(envelope)? {
                downloaded += 1;
            }
        }
        Ok(downloaded)
    }

    /// Applies one remote ref honoring local environment protection.
    async fn apply_with_protection(
        &self,
        remote: &RefState,
        conflicts: &mut Vec<RefConflict>,
    ) -> SyncResultOf<()> {
        match self.workspace.apply_ref(
            remote.namespace,
            &remote.name,
            &remote.commit,
            self.options.authorize_protected_environments,
        )? {
            crate::local::RefApplyOutcome::Applied
            | crate::local::RefApplyOutcome::AlreadyCurrent => {}
            crate::local::RefApplyOutcome::RefusedProtected => {
                conflicts.push(RefConflict {
                    namespace: remote.namespace,
                    name: remote.name.clone(),
                    local_commit: self.workspace.read_ref(remote.namespace, &remote.name)?,
                    remote_commit: Some(remote.commit.clone()),
                    reason: ConflictReason::ProtectedEnvironment,
                });
            }
        }
        Ok(())
    }

    /// Applies remote refs strictly by ancestry: fast-forward or explicit
    /// conflict; never an automatic pick between diverged revisions.
    async fn reconcile_remote_refs(
        &self,
        response: &QueryMissingResponse,
    ) -> SyncResultOf<Vec<RefConflict>> {
        let mut conflicts = Vec::new();
        for remote in &response.remote_refs {
            match self.workspace.read_ref(remote.namespace, &remote.name)? {
                Some(current) if current == remote.commit => {}
                Some(current) => {
                    if self.workspace.commit_parents(&remote.commit)?.is_none() {
                        conflicts.push(RefConflict {
                            namespace: remote.namespace,
                            name: remote.name.clone(),
                            local_commit: Some(current),
                            remote_commit: Some(remote.commit.clone()),
                            reason: ConflictReason::UnverifiableHistory,
                        });
                        continue;
                    }
                    let remote_ahead =
                        is_ancestor_or_equal(self.workspace(), &current, &remote.commit)?;
                    let local_ahead =
                        is_ancestor_or_equal(self.workspace(), &remote.commit, &current)?;
                    if remote_ahead {
                        // Fast-forward: monotonic adoption of the remote tip.
                        self.apply_with_protection(remote, &mut conflicts).await?;
                    } else if local_ahead {
                        // Local history already contains the remote tip;
                        // keep local; push publishes forward later.
                    } else {
                        // Diverged histories demand merge/reconciliation.
                        conflicts.push(RefConflict {
                            namespace: remote.namespace,
                            name: remote.name.clone(),
                            local_commit: Some(current),
                            remote_commit: Some(remote.commit.clone()),
                            reason: ConflictReason::Diverged,
                        });
                    }
                }
                None => self.apply_with_protection(remote, &mut conflicts).await?,
            }
        }
        Ok(conflicts)
    }

    /// Uploads objects the remote lacks after a local self-check that each
    /// envelope's canonical hash matches its content-derived id.
    async fn upload_missing_objects(
        &self,
        project: &ProjectId,
        remote_object_ids: &[ObjectId],
    ) -> SyncResultOf<usize> {
        let remote: BTreeSet<&str> = remote_object_ids.iter().map(ObjectId::as_str).collect();
        let mut entries = Vec::new();
        for id in self.workspace.known_object_ids()? {
            if remote.contains(id.as_str()) {
                continue;
            }
            let canonical = self
                .workspace
                .canonical_bytes(&id)?
                .ok_or(SyncError::Protocol("known object unreadable"))?;
            let digest = hex::encode(hash_canonical(&canonical));
            if digest != digest_suffix(id.as_str()) {
                return Err(SyncError::HashMismatch {
                    object: id.to_string(),
                });
            }
            entries.push(ObjectEntryWire {
                envelope_json: String::from_utf8(canonical)
                    .map_err(|_| SyncError::Protocol("non-utf8 canonical bytes"))?,
                id,
                content_hash: digest,
            });
        }
        if entries.is_empty() {
            return Ok(0);
        }
        let response: BatchObjectsResponse = self
            .send_json(
                TransportRequest::post(format!("/projects/{project}/objects/batch"), String::new()),
                Some(&BatchObjectsRequest { entries }),
            )
            .await?;
        Ok(response.stored)
    }

    /// Publishes local refs that differ remotely, using optimistic
    /// concurrency on the observed base; disagreements surface as
    /// conflicts rather than being forced or dropped. An absent remote is
    /// published with `base_commit: None`, and the server treats that as
    /// "ref must not exist" — so a concurrent first publisher loses the
    /// race cleanly with a 409 carrying the winning tip instead of
    /// clobbering it.
    async fn publish_local_refs(
        &self,
        project: &ProjectId,
        remote_refs: &[RefState],
        result: &mut SyncResult,
    ) -> SyncResultOf<()> {
        for reference in self.workspace.all_refs()? {
            let remote_state = remote_refs
                .iter()
                .find(|r| r.namespace == reference.namespace && r.name == reference.name);
            match remote_state {
                Some(r) if r.commit == reference.commit => {}
                other => {
                    let base_commit = other.map(|r| r.commit.clone());
                    // Ancestry guard before any network write: only
                    // fast-forwards are published; divergence is surfaced
                    // here instead of being forced or silently dropped.
                    let publishable = match &base_commit {
                        None => true,
                        Some(remote_tip) => {
                            if is_ancestor_or_equal(
                                self.workspace(),
                                remote_tip,
                                &reference.commit,
                            )? {
                                true
                            } else if is_ancestor_or_equal(
                                self.workspace(),
                                &reference.commit,
                                remote_tip,
                            )? {
                                continue; // Local behind: pull reconciles.
                            } else {
                                result.conflicts.push(RefConflict {
                                    namespace: reference.namespace,
                                    name: reference.name.clone(),
                                    local_commit: Some(reference.commit.clone()),
                                    remote_commit: Some(remote_tip.clone()),
                                    reason: ConflictReason::Diverged,
                                });
                                continue;
                            }
                        }
                    };
                    // BranchRef names are path-safe apart from `/`, which
                    // the server route captures via its `{*name}` wildcard.
                    let path = format!("/projects/{project}/refs/{}", reference.name);
                    if !publishable {
                        continue;
                    }
                    let wire_body = serde_json::to_string(&PutRefRequest {
                        namespace: reference.namespace,
                        commit: reference.commit.clone(),
                        base_commit: base_commit.clone(),
                        authorized: self.options.authorize_protected_environments,
                    })
                    .map_err(|_| SyncError::Protocol("request encode"))?;
                    let response = self.send(TransportRequest::put(path, wire_body)).await?;
                    if response.is_success() {
                        continue;
                    }
                    match response.status {
                        409 => {
                            let detail: serde_json::Value =
                                serde_json::from_str(&response.body).unwrap_or_default();
                            let server_current = detail["current_commit"]
                                .as_str()
                                .and_then(|raw| CommitId::parse(raw).ok());
                            let reason = if detail["error"] == "protected_environment_ref" {
                                ConflictReason::ProtectedEnvironment
                            } else {
                                ConflictReason::Diverged
                            };
                            result.conflicts.push(RefConflict {
                                namespace: reference.namespace,
                                name: reference.name.clone(),
                                local_commit: Some(reference.commit.clone()),
                                remote_commit: server_current.or(base_commit),
                                reason,
                            });
                        }
                        status => return Err(map_rejection(&response).with_status(status)),
                    }
                }
            }
        }
        Ok(())
    }
}

impl<T: ControlPlaneTransport, W: LocalWorkspace> SyncService for ControlPlaneSyncClient<T, W> {
    async fn pull(&self, project: ProjectId) -> Result<SyncResult, SyncError> {
        let mut result = SyncResult::clean();
        let response = self.probe(&project).await?;
        result.downloaded = self.download_and_apply(&response).await?;
        result.conflicts = self.reconcile_remote_refs(&response).await?;
        Ok(result)
    }

    async fn push(&self, project: ProjectId) -> Result<SyncResult, SyncError> {
        let mut result = SyncResult::clean();
        let response = self.probe(&project).await?;
        result.uploaded = self
            .upload_missing_objects(&project, &response.remote_object_ids)
            .await?;
        self.publish_local_refs(&project, &response.remote_refs, &mut result)
            .await?;
        Ok(result)
    }
}

/// Maps a non-2xx control-plane response to a client error. Only
/// structured `{"error":{"code":…}}` bodies are interpreted; anything
/// else falls back to the generic status-only variant so a hostile or
/// malformed body can never inject semantics.
fn map_rejection(response: &TransportResponse) -> SyncError {
    #[derive(serde::Deserialize)]
    struct ErrorBody {
        #[serde(rename = "error")]
        detail: ErrorDetail,
    }
    #[derive(serde::Deserialize)]
    struct ErrorDetail {
        code: String,
    }

    if let Ok(parsed) = serde_json::from_str::<ErrorBody>(&response.body) {
        if response.status == 401 && parsed.detail.code == "signature_verification_failed" {
            return SyncError::SignatureRejected;
        }
    }
    SyncError::Api {
        status: response.status,
    }
}

/// Decodes the trusted device public keys offered by the server, skipping
/// entries that do not decode (the server validated them at registration).
fn trusted_device_keys(
    fingerprints: &[vaultx_control_plane::protocol::DeviceKeyFingerprint],
) -> Vec<VerifyingPublicKey> {
    fingerprints
        .iter()
        .filter_map(|entry| {
            let bytes: [u8; 32] = hex::decode(&entry.public_key_hex).ok()?.try_into().ok()?;
            VerifyingPublicKey::from_bytes(&bytes).ok()
        })
        .collect()
}

/// Verifies a commit envelope's embedded signature against the trusted
/// device keys. An empty signature means unsigned and is accepted; any
/// non-empty signature must verify against at least one trusted key.
fn verify_commit_signature(
    object_id: &str,
    envelope: &ObjectEnvelope,
    trusted_keys: &[VerifyingPublicKey],
) -> SyncResultOf<()> {
    let commit: Commit = envelope
        .decode_payload()
        .map_err(|_| SyncError::Protocol("commit decode"))?;
    if commit.signature.0.is_empty() {
        return Ok(());
    }
    let payload = commit.sign_payload()?;
    let verified = trusted_keys
        .iter()
        .any(|key| verify_signature(key, &payload, &commit.signature).is_ok());
    if !verified {
        return Err(SyncError::SignatureVerificationFailed {
            object: object_id.to_owned(),
        });
    }
    Ok(())
}

impl SyncError {
    fn with_status(self, status: u16) -> Self {
        match self {
            Self::Api { .. } => Self::Api { status },
            other => other,
        }
    }
}

/// Hex digest portion of a content-derived id (`obj_<64 hex>`).
fn digest_suffix(id: &str) -> &str {
    &id[ObjectId::PREFIX.len()..]
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use vaultx_control_plane::api::AppState as ControlPlaneState;
    use vaultx_control_plane::model::{
        ProjectRecord, UserRecord, WorkspaceMembership, WorkspaceRecord,
    };
    use vaultx_control_plane::store::{ControlPlaneStore as _, InMemoryControlPlaneStore};
    use vaultx_crypto::signature::SigningKeyPair;
    use vaultx_keyring::InMemoryKeyStore;
    use vaultx_repository::{ManifestEntry, Repository};
    use vaultx_types::{IdentityRef, ObjectId, VariableName};

    use super::*;
    use crate::device::DeviceKeySource;
    use crate::{ConflictReason, FsWorkspace, RefNamespace, SyncOptions};

    const SESSION_TOKEN: &str = "vxs_sync_client_session";

    /// Delivers sync-client requests to an in-process control-plane router.
    /// The bearer token lives behind a mutex so tests can swap identities
    /// between calls.
    struct InProcess {
        app: axum::Router,
        bearer: std::sync::Mutex<String>,
    }

    impl InProcess {
        fn new(app: axum::Router, token: &str) -> Self {
            Self {
                app,
                bearer: std::sync::Mutex::new(token.to_owned()),
            }
        }
    }

    impl ControlPlaneTransport for InProcess {
        async fn send(&self, request: TransportRequest) -> SyncResultOf<TransportResponse> {
            let mut builder = Request::builder()
                .method(request.method)
                .uri(request.path.as_str())
                .header(
                    "authorization",
                    format!("Bearer {}", self.bearer.lock().expect("uncontended")),
                );
            if request.json_body.is_some() {
                builder = builder.header("content-type", "application/json");
            }
            let body = Body::from(request.json_body.unwrap_or_default());
            let response = self
                .app
                .clone()
                .oneshot(builder.body(body).expect("request"))
                .await
                .expect("infallible service");
            let status = response.status().as_u16();
            let bytes = BodyExt::collect(response.into_body())
                .await
                .expect("body")
                .to_bytes();
            Ok(TransportResponse {
                status,
                body: String::from_utf8_lossy(&bytes).into_owned(),
            })
        }
    }

    /// Wraps any transport and corrupts one hex byte inside a downloaded
    /// object payload so independent hash verification must catch it.
    struct TamperDownloadedObject<T: ControlPlaneTransport> {
        inner: T,
        tampered: std::sync::atomic::AtomicBool,
    }

    impl<T: ControlPlaneTransport> ControlPlaneTransport for TamperDownloadedObject<T> {
        async fn send(&self, request: TransportRequest) -> SyncResultOf<TransportResponse> {
            let response = self.inner.send(request).await?;
            if !self.tampered.load(std::sync::atomic::Ordering::SeqCst) {
                // Corrupt one hex nibble of the first downloaded object's
                // payload so independent verification must reject it.
                let mut value: serde_json::Value = match serde_json::from_str(&response.body) {
                    Ok(v) => v,
                    Err(_) => return Ok(response),
                };
                let payload = value
                    .get_mut("missing_objects")
                    .and_then(|entries| entries.as_array_mut())
                    .and_then(|entries| entries.first_mut())
                    .and_then(|entry| entry.get_mut("envelope_json"))
                    .and_then(|field| field.as_str().map(str::to_owned));
                let Some(envelope_json) = payload else {
                    return Ok(response);
                };
                // Flip the first payload-hex nibble (same length, still
                // valid hex) so only the content hash changes.
                let needle = "\"payload\":\"";
                let mut corrupted = envelope_json.clone();
                let Some(start) = corrupted.find(needle).map(|pos| pos + needle.len()) else {
                    return Ok(response);
                };
                let flipped = if corrupted.as_bytes()[start] == b'0' {
                    '1'
                } else {
                    '0'
                };
                corrupted.replace_range(start..start + 1, &flipped.to_string());
                if let Some(entry) = value
                    .get_mut("missing_objects")
                    .and_then(|entries| entries.as_array_mut())
                    .and_then(|entries| entries.first_mut())
                {
                    entry["envelope_json"] = serde_json::Value::String(corrupted);
                }
                self.tampered
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                return Ok(TransportResponse {
                    status: response.status,
                    body: value.to_string(),
                });
            }
            Ok(response)
        }
    }

    /// Corrupts the device signature on outgoing query-missing requests.
    struct TamperSignature<T: ControlPlaneTransport> {
        inner: T,
    }

    impl<T: ControlPlaneTransport> ControlPlaneTransport for TamperSignature<T> {
        async fn send(&self, request: TransportRequest) -> SyncResultOf<TransportResponse> {
            let mut request = request;
            if request.path.ends_with("/objects/query-missing") {
                if let Some(body) = request.json_body.take() {
                    let forged = body.replacen("\"signature_hex\":\"", "\"signature_hex\":\"00", 1);
                    request.json_body = Some(forged);
                }
            }
            self.inner.send(request).await
        }
    }

    /// Corrupts one hex digit inside a downloaded commit's signature so
    /// the envelope hash still matches but signature verification fails.
    struct TamperCommitSignature<T: ControlPlaneTransport> {
        inner: T,
    }

    impl<T: ControlPlaneTransport> ControlPlaneTransport for TamperCommitSignature<T> {
        async fn send(&self, request: TransportRequest) -> SyncResultOf<TransportResponse> {
            let is_query = request.path.ends_with("/objects/query-missing");
            let response = self.inner.send(request).await?;
            if !is_query {
                return Ok(response);
            }
            let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&response.body) else {
                return Ok(response);
            };
            let Some(entries) = value
                .get_mut("missing_objects")
                .and_then(|e| e.as_array_mut())
            else {
                return Ok(response);
            };
            const NEEDLE: &str = "\"signature\":[";
            for entry in entries {
                let Some(raw) = entry.get("envelope_json").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Ok(envelope) = serde_json::from_str::<ObjectEnvelope>(raw) else {
                    continue;
                };
                if envelope.object_type != ObjectType::Commit {
                    continue;
                }
                let mut payload =
                    String::from_utf8(envelope.payload).expect("commit payload is utf8 JSON");
                let Some(start) = payload.find(NEEDLE).map(|p| p + NEEDLE.len()) else {
                    continue;
                };
                // SignatureBytes renders as a JSON byte array; corrupting
                // the last digit of its first element keeps both the JSON
                // and the commit decodable while invalidating the
                // signature.
                let Some(rel) = payload[start..]
                    .bytes()
                    .position(|b| !b.is_ascii_digit())
                    .filter(|&n| n > 0)
                else {
                    continue;
                };
                let pos = start + rel - 1;
                let flipped = if payload.as_bytes()[pos] == b'0' {
                    '9'
                } else {
                    '0'
                };
                payload.replace_range(pos..pos + 1, &flipped.to_string());
                let tampered = ObjectEnvelope::new(ObjectType::Commit, payload.into_bytes());
                let canonical = tampered.canonical_bytes().expect("canonical");
                let digest = hex::encode(hash_canonical(&canonical));
                entry["id"] = serde_json::Value::String(format!("obj_{digest}"));
                entry["content_hash"] = serde_json::Value::String(digest);
                entry["envelope_json"] =
                    serde_json::Value::String(String::from_utf8(canonical).expect("utf8"));
                break;
            }
            Ok(TransportResponse {
                status: response.status,
                body: value.to_string(),
            })
        }
    }

    /// Plants a rival head ref into the store when it observes the first
    /// publish attempt, simulating another writer winning a create race.
    struct RaceSeeder<T: ControlPlaneTransport> {
        inner: T,
        store: Arc<InMemoryControlPlaneStore>,
        project: ProjectId,
        rival_tip: CommitId,
        seeded: std::sync::atomic::AtomicBool,
    }

    impl<T: ControlPlaneTransport> ControlPlaneTransport for RaceSeeder<T> {
        async fn send(&self, request: TransportRequest) -> SyncResultOf<TransportResponse> {
            let is_publish = request.method == "PUT"
                && request.path == format!("/projects/{}/refs/main", self.project);
            if is_publish && !self.seeded.swap(true, std::sync::atomic::Ordering::SeqCst) {
                self.store
                    .set_ref_state(
                        &self.project,
                        &vaultx_control_plane::model::RefState {
                            namespace: RefNamespace::Heads,
                            name: "main".to_owned(),
                            commit: self.rival_tip.clone(),
                            protected: false,
                        },
                    )
                    .expect("seed rival tip");
            }
            self.inner.send(request).await
        }
    }

    /// Test fixture: seeded control plane plus two local repositories.
    ///
    /// Each side's commit-signing key is derived from the same keystore
    /// backing its sync-client [`DeviceKeySource`], mirroring production
    /// where one device identity both signs commits and attests sync.
    struct World {
        store: Arc<InMemoryControlPlaneStore>,
        app: axum::Router,
        project: ProjectId,
        alice_dir: tempfile::TempDir,
        bob_dir: tempfile::TempDir,
        keys_a: Arc<dyn vaultx_keyring::WrappingKeyProvider>,
        keys_b: Arc<dyn vaultx_keyring::WrappingKeyProvider>,
        pair_a: SigningKeyPair,
        pair_b: SigningKeyPair,
    }

    /// Derives a signing key from the device identity persisted in
    /// `provider`, so commits and sync attestations share one identity.
    fn device_pair(provider: &Arc<dyn vaultx_keyring::WrappingKeyProvider>) -> SigningKeyPair {
        let root = provider.obtain().expect("root key");
        let mut seed = [0u8; 32];
        root.expose(|s| seed.copy_from_slice(s));
        SigningKeyPair::from_seed(&seed).expect("seed valid")
    }

    impl World {
        fn new() -> Self {
            let store = Arc::new(InMemoryControlPlaneStore::new());
            let workspace = vaultx_types::WorkspaceId::parse("ws_sync_world").expect("valid");
            let project = ProjectId::parse("proj_sync_world").expect("valid");
            store
                .upsert_user(&UserRecord {
                    login: "alice".to_owned(),
                    display_name: None,
                    verifier: "pw".to_owned(),
                })
                .expect("seed user");
            store
                .create_workspace(&WorkspaceRecord {
                    id: workspace.clone(),
                    name: "acme".to_owned(),
                    owner: "alice".to_owned(),
                })
                .expect("seed ws");
            store
                .create_project(&ProjectRecord {
                    id: project.clone(),
                    workspace: workspace.clone(),
                    name: "core".to_owned(),
                })
                .expect("seed project");
            store
                .issue_session(
                    SESSION_TOKEN,
                    &vaultx_control_plane::model::Principal {
                        subject: "alice".to_owned(),
                        class: vaultx_control_plane::auth::TokenClass::ControlSession,
                    },
                )
                .expect("seed session");

            let alice_dir = tempfile::tempdir().expect("tempdir");
            let bob_dir = tempfile::tempdir().expect("tempdir");
            Repository::init(alice_dir.path()).expect("init A");
            Repository::init(bob_dir.path()).expect("init B");
            let keys_a: Arc<dyn vaultx_keyring::WrappingKeyProvider> =
                Arc::new(InMemoryKeyStore::new());
            let keys_b: Arc<dyn vaultx_keyring::WrappingKeyProvider> =
                Arc::new(InMemoryKeyStore::new());
            Self {
                app: vaultx_control_plane::api::router(ControlPlaneState {
                    store: Arc::clone(&store) as Arc<dyn vaultx_control_plane::ControlPlaneStore>,
                }),
                store,
                project,
                alice_dir,
                bob_dir,
                pair_a: device_pair(&keys_a),
                pair_b: device_pair(&keys_b),
                keys_a,
                keys_b,
            }
        }

        fn transport(&self) -> InProcess {
            InProcess::new(self.app.clone(), SESSION_TOKEN)
        }

        fn client_a(&self) -> ControlPlaneSyncClient<InProcess, FsWorkspace> {
            let repo = Repository::open(self.alice_dir.path()).expect("open A");
            ControlPlaneSyncClient::new(
                self.transport(),
                FsWorkspace::open(repo.root()).expect("open"),
                DeviceKeySource::new(Arc::clone(&self.keys_a)),
            )
        }

        fn client_b(&self) -> ControlPlaneSyncClient<InProcess, FsWorkspace> {
            let repo = Repository::open(self.bob_dir.path()).expect("open B");
            ControlPlaneSyncClient::new(
                self.transport(),
                FsWorkspace::open(repo.root()).expect("open"),
                DeviceKeySource::new(Arc::clone(&self.keys_b)),
            )
        }

        fn commit(repo: &Repository, pair: &SigningKeyPair, name: &str, value: &str) -> CommitId {
            let value_id = repo
                .objects()
                .put(&vaultx_repository::ObjectEnvelope::new(
                    vaultx_repository::ObjectType::ConfigValue,
                    format!("{{\"value\":\"{value}\"}}").into_bytes(),
                ))
                .expect("config value");
            repo.add(
                VariableName::parse(name).expect("valid"),
                ManifestEntry::Config { object: value_id },
            )
            .expect("stage");
            repo.create_commit(
                &format!("set {name}"),
                IdentityRef::parse("user:tester").expect("valid"),
                pair,
            )
            .expect("commit")
        }

        fn open_a(&self) -> Repository {
            Repository::open(self.alice_dir.path()).expect("open A")
        }

        fn open_b(&self) -> Repository {
            Repository::open(self.bob_dir.path()).expect("open B")
        }
    }

    fn head_of(repo: &Repository, branch: &str) -> Option<CommitId> {
        repo.refs()
            .read_ref(vaultx_repository::RefNamespace::Heads, branch)
            .expect("ref")
    }

    #[tokio::test]
    async fn round_trip_push_pull_converges_both_directions() {
        let world = World::new();
        let project = world.project.clone();

        // A commits and pushes into the empty remote.
        let c1 = World::commit(&world.open_a(), &world.pair_a, "API_KEY", "v1");
        let pushed = world
            .client_a()
            .push(project.clone())
            .await
            .expect("push 1");
        assert!(pushed.is_converged());
        assert_eq!(pushed.uploaded, 3, "config + manifest + commit objects");
        assert_eq!(
            world
                .store
                .list_object_ids(&project)
                .expect("remote ids")
                .len(),
            3
        );

        // Empty B pulls everything down.
        let pulled_b = world
            .client_b()
            .pull(project.clone())
            .await
            .expect("pull B");
        assert!(pulled_b.is_converged());
        assert_eq!(pulled_b.downloaded, 3);
        assert_eq!(
            head_of(&world.open_b(), "main"),
            Some(c1.clone()),
            "B.main fast-forwarded to A's tip"
        );

        // B advances; A pulls the delta.
        let c2 = World::commit(&world.open_b(), &world.pair_b, "DB_HOST", "db.internal");
        let push_b = world
            .client_b()
            .push(project.clone())
            .await
            .expect("push B");
        assert!(push_b.is_converged());
        assert_eq!(push_b.uploaded, 3);

        let pull_a = world
            .client_a()
            .pull(project.clone())
            .await
            .expect("pull A2");
        assert!(pull_a.is_converged());
        assert_eq!(pull_a.downloaded, 3);
        assert_eq!(head_of(&world.open_a(), "main"), Some(c2));
        assert_eq!(
            head_of(&world.open_a(), "main"),
            head_of(&world.open_b(), "main")
        );

        // Both stores hold identical content-addressed object sets.
        let ids_a = world
            .client_a()
            .workspace()
            .known_object_ids()
            .expect("A ids");
        let ids_b = world
            .client_b()
            .workspace()
            .known_object_ids()
            .expect("B ids");
        let set_a: std::collections::BTreeSet<ObjectId> = ids_a.into_iter().collect();
        let let_set_b: std::collections::BTreeSet<ObjectId> = ids_b.into_iter().collect();
        assert_eq!(set_a, let_set_b);
    }

    #[tokio::test]
    async fn hash_mismatch_rejects_download_without_applying() {
        let world = World::new();
        let project = world.project.clone();
        World::commit(&world.open_a(), &world.pair_a, "API_KEY", "v1");
        world
            .client_a()
            .push(project.clone())
            .await
            .expect("seed push");

        let base = world.transport();
        let tampering = TamperDownloadedObject {
            inner: base,
            tampered: std::sync::atomic::AtomicBool::new(false),
        };
        let keys = DeviceKeySource::new(Arc::new(InMemoryKeyStore::new()));
        let repo_b = Repository::open(world.bob_dir.path()).expect("open B");
        let client = ControlPlaneSyncClient::new(
            tampering,
            FsWorkspace::open(repo_b.root()).expect("open"),
            keys,
        );

        let err = client.pull(project).await.expect_err("must fail");
        assert!(
            matches!(err, SyncError::HashMismatch { .. }),
            "expected HashMismatch, got {err}"
        );
        assert!(
            client
                .workspace()
                .known_object_ids()
                .expect("ids")
                .is_empty(),
            "nothing may be applied when verification fails"
        );
    }

    #[tokio::test]
    async fn device_signature_failure_is_rejected_by_server() {
        let world = World::new();
        let project = world.project.clone();
        let inner = world.transport();
        let keys = DeviceKeySource::new(Arc::new(InMemoryKeyStore::new()));
        let repo_a = Repository::open(world.alice_dir.path()).expect("open A");
        let client = ControlPlaneSyncClient::new(
            TamperSignature { inner },
            FsWorkspace::open(repo_a.root()).expect("open"),
            keys,
        );

        let err = client.pull(project).await.expect_err("server rejects");
        assert!(
            matches!(err, SyncError::SignatureRejected),
            "expected SignatureRejected, got {err}"
        );
        assert!(
            world
                .store
                .list_devices_for_user("alice")
                .unwrap()
                .is_empty(),
            "invalid identities must not register"
        );
    }

    #[tokio::test]
    async fn divergent_refs_surface_conflicts_without_auto_resolution() {
        let world = World::new();
        let project = world.project.clone();

        // Common history: A pushes c1; B pulls it.
        let base = World::commit(&world.open_a(), &world.pair_a, "COMMON", "base");
        world
            .client_a()
            .push(project.clone())
            .await
            .expect("push base");
        world
            .client_b()
            .pull(project.clone())
            .await
            .expect("pull base");

        // Both sides advance from the same ancestor.
        let local_a = World::commit(&world.open_a(), &world.pair_a, "A_ONLY", "a");
        let local_b = World::commit(&world.open_b(), &world.pair_b, "B_ONLY", "b");
        assert_ne!(local_a, local_b);

        world
            .client_a()
            .push(project.clone())
            .await
            .expect("push A");

        // B's push hits the CAS guard: server main is at local_a while B's
        // base is still `base`. The disagreement is surfaced — never chosen.
        let result = world
            .client_b()
            .push(project.clone())
            .await
            .expect("push B");
        assert_eq!(result.conflicts.len(), 1, "one ref conflict expected");
        let conflict = &result.conflicts[0];
        assert_eq!(conflict.namespace, RefNamespace::Heads);
        assert_eq!(conflict.name, "main");
        assert_eq!(conflict.local_commit, Some(local_b.clone()));
        assert_eq!(conflict.remote_commit, Some(local_a.clone()));
        assert_eq!(conflict.reason, ConflictReason::Diverged);

        // The server never adopted B's divergent tip...
        assert_eq!(
            world
                .store
                .get_ref_state(&project, RefNamespace::Heads, "main")
                .expect("state")
                .map(|r| r.commit),
            Some(local_a)
        );

        // ...and pulling on top of that surfaces the divergence locally too.
        let pull = world
            .client_b()
            .pull(project.clone())
            .await
            .expect("pull B");
        assert!(pull
            .conflicts
            .iter()
            .any(|c| c.reason == ConflictReason::Diverged));
        // B keeps its own tip; no silent pick occurred either direction.
        assert_eq!(head_of(&world.open_b(), "main"), Some(local_b));
        assert_ne!(head_of(&world.open_b(), "main"), Some(base));
    }

    #[tokio::test]
    async fn protected_environment_ref_rejects_unauthorized_update() {
        let world = World::new();
        let project = world.project.clone();

        // A creates two commits, publishes an env ref at the first, then
        // uploads both commits' objects (main moves only to the first).
        let repo = world.open_a();
        let c1 = World::commit(&repo, &world.pair_a, "ENV_VAR", "one");
        let _c2 = World::commit(&repo, &world.pair_a, "NEXT_VAR", "two");
        repo.refs()
            .write_env_ref("production", &c1, false)
            .expect("env ref");
        let push = world.client_a().push(project.clone()).await.expect("push");
        assert!(push.conflicts.is_empty());

        // Policy protects production — locally and remotely — and another
        // actor advances the remote env ref to the second commit.
        repo.refs()
            .write_env_protection(
                "production",
                &vaultx_repository::EnvironmentProtection { protected: true },
            )
            .expect("local protection");
        world
            .store
            .set_environment_protection(&project, "production", true)
            .expect("remote protect");
        let advanced = vaultx_control_plane::model::RefState {
            namespace: RefNamespace::Environments,
            name: "production".to_owned(),
            commit: _c2.clone(),
            protected: true,
        };
        world
            .store
            .set_ref_state(&project, &advanced)
            .expect("advance env");

        // Pull: local prod is protected and unauthorized overrides are off.
        let pull = world.client_a().pull(project.clone()).await.expect("pull");
        assert_eq!(pull.downloaded, 0, "objects already present");
        let conflict = pull
            .conflicts
            .iter()
            .find(|c| c.reason == ConflictReason::ProtectedEnvironment)
            .expect("protected-env conflict surfaced");
        assert_eq!(conflict.name, "production");
        assert_eq!(conflict.local_commit, Some(c1.clone()));
        assert_eq!(conflict.remote_commit, Some(_c2.clone()));
        // Local protected ref untouched.
        assert_eq!(
            world
                .open_a()
                .refs()
                .read_ref(vaultx_repository::RefNamespace::Environments, "production")
                .expect("read"),
            Some(c1)
        );

        // With explicit authorization the same update applies cleanly.
        let authorized = ControlPlaneSyncClient::with_options(
            world.transport(),
            FsWorkspace::open(world.open_a().root()).expect("open"),
            DeviceKeySource::new(Arc::new(InMemoryKeyStore::new())),
            SyncOptions {
                authorize_protected_environments: true,
            },
        );
        let result = authorized.pull(project).await.expect("authorized pull");
        assert!(result.is_converged());
        assert_eq!(
            world
                .open_a()
                .refs()
                .read_ref(vaultx_repository::RefNamespace::Environments, "production")
                .expect("read"),
            Some(_c2)
        );
    }

    #[tokio::test]
    async fn oidc_exchanged_workload_token_drives_the_data_plane() {
        let world = World::new();
        let project = world.project.clone();

        // Exchange a federated assertion for a workload session.
        let exchange = serde_json::json!({
            "kind": "oidc_exchange",
            "provider": "github-actions",
            "assertion": "federated-assertion-for-ci"
        });
        let anonymous = InProcess::new(world.app.clone(), "");
        let response = anonymous
            .send(TransportRequest::post(
                "/auth/session".to_owned(),
                exchange.to_string(),
            ))
            .await
            .expect("session call");
        assert!(response.is_success());
        let session: vaultx_control_plane::protocol::SessionResponse =
            response.json().expect("session body");
        assert_eq!(session.token_class, "workload_exchange");
        assert!(session.token.starts_with("vxw_"));

        // The workload principal needs workspace membership for the project.
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"federated-assertion-for-ci");
        let subject = format!("oidc:github-actions:{:.16}", hex::encode(hasher.finalize()));
        world
            .store
            .add_workspace_member(&WorkspaceMembership {
                workspace: vaultx_types::WorkspaceId::parse("ws_sync_world").expect("valid"),
                user: subject,
                role: "member".to_owned(),
            })
            .expect("membership");

        // Workload tokens are rejected on administrative routes...
        let workload = InProcess::new(world.app.clone(), &session.token);
        let admin_probe = workload
            .send(TransportRequest::get(format!("/projects/{project}/refs")))
            .await
            .expect("admin probe");
        assert_eq!(admin_probe.status, 403);

        // ...but accepted on the data-plane sync route.
        let keys = DeviceKeySource::new(Arc::new(InMemoryKeyStore::new()));
        let repo = Repository::open(world.alice_dir.path()).expect("open");
        let client = ControlPlaneSyncClient::new(
            workload,
            FsWorkspace::open(repo.root()).expect("open"),
            keys,
        );
        let result = client.pull(project).await.expect("workload pull");
        assert!(result.is_converged());
    }

    #[tokio::test]
    async fn tampered_commit_signature_aborts_pull_without_applying() {
        let world = World::new();
        let project = world.project.clone();
        World::commit(&world.open_a(), &world.pair_a, "API_KEY", "v1");
        world
            .client_a()
            .push(project.clone())
            .await
            .expect("seed push");

        let repo_b = Repository::open(world.bob_dir.path()).expect("open B");
        let client = ControlPlaneSyncClient::new(
            TamperCommitSignature {
                inner: world.transport(),
            },
            FsWorkspace::open(repo_b.root()).expect("open"),
            DeviceKeySource::new(Arc::new(InMemoryKeyStore::new())),
        );

        let err = client.pull(project).await.expect_err("must abort");
        assert!(
            matches!(err, SyncError::SignatureVerificationFailed { .. }),
            "expected SignatureVerificationFailed, got {err}"
        );
        assert!(
            client
                .workspace()
                .known_object_ids()
                .expect("ids")
                .is_empty(),
            "a failed signature must abort before anything is applied"
        );
    }

    #[tokio::test]
    async fn valid_signatures_verify_against_served_device_keys() {
        let world = World::new();
        let project = world.project.clone();
        World::commit(&world.open_a(), &world.pair_a, "API_KEY", "v1");
        world
            .client_a()
            .push(project.clone())
            .await
            .expect("seed push");

        // The pulled commit is signed by A's device key; verification only
        // passes because the server served that key as trusted material.
        let pulled = world.client_b().pull(project).await.expect("pull");
        assert!(pulled.is_converged());
        assert_eq!(pulled.downloaded, 3);
    }

    #[tokio::test]
    async fn unsigned_commit_objects_still_pull() {
        let world = World::new();
        let project = world.project.clone();
        World::commit(&world.open_a(), &world.pair_a, "API_KEY", "v1");
        world
            .client_a()
            .push(project.clone())
            .await
            .expect("seed push");

        // Inject a legacy unsigned commit object directly into the remote.
        let unsigned = Commit::new(
            Vec::new(),
            ObjectId::parse(&format!("obj_{}", "cd".repeat(32))).expect("valid shape"),
            IdentityRef::parse("user:legacy").expect("valid"),
            "unsigned legacy commit",
        );
        let envelope = ObjectEnvelope::new(
            ObjectType::Commit,
            serde_json::to_vec(&unsigned).expect("enc"),
        );
        let canonical = envelope.canonical_bytes().expect("canonical");
        let digest = hex::encode(hash_canonical(&canonical));
        let response = world
            .transport()
            .send(TransportRequest::post(
                format!("/projects/{project}/objects/batch"),
                serde_json::json!({"entries":[ObjectEntryWire {
                    id: ObjectId::parse(&format!("obj_{digest}")).expect("hex digest"),
                    content_hash: digest,
                    envelope_json: String::from_utf8(canonical).expect("utf8"),
                }]})
                .to_string(),
            ))
            .await
            .expect("upload");
        assert_eq!(response.status, 200);

        let pulled = world.client_b().pull(project).await.expect("pull");
        assert!(pulled.is_converged(), "unsigned content is accepted");
        assert_eq!(pulled.downloaded, 4);
    }

    #[tokio::test]
    async fn lost_create_race_surfaces_conflict_with_server_tip() {
        let world = World::new();
        let project = world.project.clone();
        let local_tip = World::commit(&world.open_a(), &world.pair_a, "A_VAR", "a");
        let rival_tip = CommitId::parse("cmt_rival_winner").expect("valid");

        let keys = DeviceKeySource::new(Arc::new(InMemoryKeyStore::new()));
        let repo = Repository::open(world.alice_dir.path()).expect("open A");
        let client = ControlPlaneSyncClient::new(
            RaceSeeder {
                inner: world.transport(),
                store: Arc::clone(&world.store),
                project: project.clone(),
                rival_tip: rival_tip.clone(),
                seeded: std::sync::atomic::AtomicBool::new(false),
            },
            FsWorkspace::open(repo.root()).expect("open"),
            keys,
        );

        // Both sides claim the ref is absent; the server-side create CAS
        // makes one side lose with the winning tip surfaced.
        let result = client.push(project.clone()).await.expect("push");
        assert!(!result.is_converged(), "the lost race must be surfaced");
        let conflict = &result.conflicts[0];
        assert_eq!(conflict.namespace, RefNamespace::Heads);
        assert_eq!(conflict.name, "main");
        assert_eq!(conflict.local_commit, Some(local_tip));
        assert_eq!(conflict.remote_commit, Some(rival_tip.clone()));
        assert_eq!(conflict.reason, ConflictReason::Diverged);

        // The winner was never clobbered by the loser's write.
        assert_eq!(
            world
                .store
                .get_ref_state(&project, RefNamespace::Heads, "main")
                .expect("state")
                .map(|r| r.commit),
            Some(rival_tip)
        );
    }

    #[test]
    fn rejection_maps_structured_signature_code_only() {
        let structured = TransportResponse {
            status: 401,
            body: r#"{"error":{"code":"signature_verification_failed","message":"signature verification failed"}}"#.to_owned(),
        };
        assert!(matches!(
            map_rejection(&structured),
            SyncError::SignatureRejected
        ));

        let other_code = TransportResponse {
            status: 422,
            body: r#"{"error":{"code":"hash_mismatch","message":"content hash mismatch"}}"#
                .to_owned(),
        };
        assert!(matches!(
            map_rejection(&other_code),
            SyncError::Api { status: 422 }
        ));

        let unstructured = TransportResponse {
            status: 401,
            body: "<html>gateway error</html>".to_owned(),
        };
        assert!(matches!(
            map_rejection(&unstructured),
            SyncError::Api { status: 401 }
        ));
    }
}
