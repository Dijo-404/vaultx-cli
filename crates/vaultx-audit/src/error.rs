//! Error type shared by the vaultx audit crate.
//!
//! Every `Display` string is deliberately conservative: it names the
//! failure mode and, where a field name is carried, echoes only the
//! **key/field name** — never metadata values, never record contents — so
//! rendering an error into a log line can never leak secret material.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    /// Underlying file I/O failure while appending to or reading the
    /// audit store.
    #[error("audit store i/o failure: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization or deserialization of an audit event failed. The
    /// payload carries a structural diagnostic only (e.g. the serde
    /// message); it must not embed event content.
    #[error("audit event serialization failed")]
    Serialization(String),

    /// Hash-chain verification failed at the given sequence number.
    ///
    /// `reason` is authored by this crate ("linkage mismatch",
    /// "sequence gap", ...) and never quotes event content.
    #[error("audit hash chain broken at sequence {at_sequence}: {reason}")]
    ChainBroken {
        /// Stored sequence number of the first event that fails linkage.
        at_sequence: u64,
        /// Failure category, safe for display.
        reason: String,
    },

    /// A metadata entry (or other validated field) was rejected by the
    /// redaction validation rules. The key is echoed because keys are
    /// names, not values; the value itself is deliberately absent from
    /// this variant and from every `Display` output in this crate.
    #[error("audit metadata entry rejected for key `{key}`: {reason}")]
    InvalidMetadata {
        /// Rejected key or validated field name (`destination.host`,
        /// `correlation_id`, ...).
        key: String,
        /// Rule that was violated, safe for display.
        reason: String,
    },

    /// A stored JSONL line could not be parsed as an [`AuditEvent`](crate::event::AuditEvent)
    /// — typically a partial trailing write after a crash, or tampering.
    /// The reason describes the parse failure mode; it does not quote the
    /// record body.
    #[error("corrupt audit record at line {line}: {reason}")]
    CorruptRecord {
        /// 1-based line number within the store file.
        line: usize,
        /// Parse-failure description, safe for display.
        reason: String,
    },

    /// Secure randomness was unavailable while generating identifiers.
    #[error("secure random generation failed: {0}")]
    Entropy(String),
}
