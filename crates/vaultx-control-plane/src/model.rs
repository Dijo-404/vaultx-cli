//! Domain records shared between the REST surface and the store.

/// Which ref namespace a ref belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefNamespace {
    /// Regular branches.
    Heads,
    /// Deployable environments (protection-aware).
    Environments,
}

/// A control-plane user record. `verifier` holds a credential verifier
/// (a salted hash in production; the in-memory test store compares it
/// directly and never logs it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserRecord {
    /// Unique login name.
    pub login: String,
    /// Optional display name.
    pub display_name: Option<String>,
    /// Credential verifier compared at session creation.
    pub verifier: String,
}

/// A workspace owned by one user with member-based access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceRecord {
    /// Typed workspace identifier (`ws_…`).
    pub id: vaultx_types::WorkspaceId,
    /// Human-readable workspace name.
    pub name: String,
    /// Login of the owning user.
    pub owner: String,
}

/// Membership of a user in a workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceMembership {
    /// Workspace the membership belongs to.
    pub workspace: vaultx_types::WorkspaceId,
    /// Member login.
    pub user: String,
    /// Role string (`owner`, `member`, `viewer`).
    pub role: String,
}

/// Owner role string.
pub const ROLE_OWNER: &str = "owner";
/// Member role string.
pub const ROLE_MEMBER: &str = "member";

/// A project scoped to a workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectRecord {
    /// Typed project identifier (`proj_…`).
    pub id: vaultx_types::ProjectId,
    /// Owning workspace.
    pub workspace: vaultx_types::WorkspaceId,
    /// Human-readable project name.
    pub name: String,
}

/// A registered device signing key attributed to a user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceRecord {
    /// 32-byte Ed25519 public key, lowercase hex.
    pub public_key_hex: String,
    /// Owning user login.
    pub owner: String,
    /// Operator-supplied label.
    pub label: Option<String>,
}

impl DeviceRecord {
    /// Validates that `public_key_hex` decodes to a 32-byte key.
    ///
    /// # Errors
    /// [`crate::ControlPlaneError::BadRequest`] for any other shape.
    pub fn validate_key(&self) -> Result<[u8; 32], crate::error::ControlPlaneError> {
        let bytes = hex::decode(&self.public_key_hex).map_err(|_| {
            crate::error::ControlPlaneError::BadRequest("device public key must be hex")
        })?;
        bytes.try_into().map_err(|_| {
            crate::error::ControlPlaneError::BadRequest("device public key must be 32 bytes")
        })
    }
}

/// A ref as stored remotely, including environment protection metadata.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefState {
    /// Namespace of the ref.
    pub namespace: RefNamespace,
    /// Ref name within the namespace.
    pub name: String,
    /// Commit the ref points at.
    pub commit: vaultx_types::CommitId,
    /// Environment protection flag (always false for heads).
    #[serde(default)]
    pub protected: bool,
}

/// A policy document bound to a project by name.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PolicyDocument {
    /// Policy name (validated [`vaultx_types::PolicyName`] charset).
    pub name: vaultx_types::PolicyName,
    /// Canonical JSON text of the policy document.
    pub document_json: String,
}

/// An authenticated principal resolved from a bearer token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// Login of the human or workload behind the token.
    pub subject: String,
    /// Class of the presenting token.
    pub class: crate::auth::TokenClass,
}
