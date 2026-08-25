//! Remote control-plane service (plan §28/§39).
//!
//! Implements the Auth, Workspace, Project, Object sync, Ref, Policy,
//! Device key, Agent identity, and Audit services over a REST surface
//! backed by a swappable [`store::ControlPlaneStore`]. The in-memory
//! implementation is used by all tests; PostgreSQL DDL ships as embedded
//! migration SQL under `migrations/`.
//!
//! # Token classes
//!
//! Two bearer-token families exist and are never interchangeable
//! (plan §39 security note): [`crate::auth::TokenClass::ControlSession`] tokens gate the
//! administrative surface, while [`crate::auth::TokenClass::WorkloadExchange`] tokens
//! (federated/OIDC exchange) are accepted only on the data-plane sync
//! route. [`crate::auth::TokenClass::Agent`] session tokens are subordinate broker-style
//! credentials and are rejected on every control-plane route.

pub mod api;
pub mod auth;
pub mod error;
pub mod model;
pub mod protocol;
pub mod store;

use std::sync::Arc;

pub use error::ControlPlaneError;
pub use model::{PolicyDocument, ProjectRecord, RefNamespace, RefState, WorkspaceRecord};
pub use protocol::EnvironmentMetadata;
pub use store::{ControlPlaneStore, InMemoryControlPlaneStore};

/// Builds the control-plane REST router (plan §39 route surface) over
/// `store`.
pub fn router(store: Arc<dyn ControlPlaneStore>) -> axum::Router {
    api::router(api::AppState { store })
}
