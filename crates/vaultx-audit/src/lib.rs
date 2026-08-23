//! Structured audit event schema, local append-only storage interface,
//! remote ingestion interface, export, and redaction guarantees (plan
//! §27).
//!
//! Audit events capture authorization decisions without becoming a secret
//! exfiltration surface: the schema has no field for credential
//! plaintext, auth header values, unfiltered bodies or responses, or
//! bearer tokens; destinations carry host/port/path only; metadata keys
//! naming sensitive material are rejected. Integrity is provided through
//! chained SHA-256 hashes over canonical JSON.
//!
//! # Layout
//!
//! - [`event`]: [`AuditEvent`] schema, safe summary types,
//!   redaction-checked metadata, hash computation, id generation.
//! - [`store`]: [`AppendStore`] / [`RemoteIngest`] traits, filters, and
//!   the [`NoopRemoteIngest`] placeholder.
//! - [`jsonl`]: append-only JSONL store implementation and export helper.

pub mod error;
pub mod event;
pub mod jsonl;
pub mod store;

pub use error::AuditError;
pub use event::{
    generate_audit_event_id, AuditAction, AuditDecision, AuditEvent, CapabilityName, CorrelationId,
    NewAuditEvent, SafeAuditMetadata, SafeDestinationSummary,
};
pub use jsonl::{export_jsonl, JsonlAppendStore};
pub use store::{AppendStore, AuditFilter, NoopRemoteIngest, RemoteIngest};
