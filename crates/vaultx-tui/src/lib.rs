//! Ratatui terminal UI application (plan §15, §38).
//!
//! `vaultx tui` opens a LazyGit-style dashboard over local project state:
//!
//! - **dashboard** — env/branch · variables · history panes plus an
//!   inspector and a contextual key-binding bar,
//! - **diff** — staged changes rendered through the redaction layer
//!   (revision deltas only; never secret plaintext),
//! - **agents** — identity, session state, environment, credential
//!   logical names (non-revealable), allowed hosts/methods/paths,
//!   semantic capabilities, recent allow/deny audit entries,
//! - **policy** — form/tree editing for common rules plus a raw YAML view
//!   with continuous validation; invalid documents are visibly flagged
//!   and can never be applied without explicit confirmation,
//! - **audit** — the local hash-chained trail filtered by allow/deny,
//! - **promote** — environment promotion: pick a source branch and a
//!   target environment (NAME / PROTECTED / PINNED COMMIT); protected
//!   targets require explicit confirmation and promote with force,
//! - **sync** — configured control-plane remotes with login presence
//!   plus push/pull/sync driven through the same hardened sync client
//!   the CLI uses (plan §38).
//!
//! # Architecture
//!
//! The crate is split so everything testable is headless:
//!
//! - `state` — pure state machine (`handle_key`/`handle_resize`
//!   returning `Effect`s),
//! - `mask` — masking helpers plus the diff-redaction functions whose
//!   output provably contains no secret content,
//! - `view` — layout computation and widget rendering, exercised via
//!   ratatui's `TestBackend`,
//! - `data` — snapshot loading from existing vaultx-core/broker/audit
//!   services (the TUI reimplements no domain logic),
//! - `backend` — crossterm plumbing only.

mod backend;
mod data;
mod error;
mod mask;
mod state;
mod view;

pub use backend::{run, TuiConfig};
pub use error::TuiError;
