//! Shared strongly typed identifiers and DTOs.

pub mod error;
pub mod ids;
pub mod model;
pub mod names;

pub use error::TypeError;
pub use ids::{
    AgentId, AuditEventId, CommitId, CredentialRef, EnvironmentId, ObjectId, PolicyId, ProjectId,
    SecretId, SecretRevisionId, SessionId, WorkspaceId,
};
pub use model::{
    BrokeredCredential, InjectionTemplateId, VariableDefinition, VariableKind, VariableSource,
};
pub use names::{BranchRef, IdentityRef, PolicyName, ProviderName, VariableName};
