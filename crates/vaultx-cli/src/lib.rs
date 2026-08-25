//! Clap command surface for the `vaultx` binary (plan §14).
//!
//! - `cli`: the derive structs ([`Cli`], [`Command`]), the CLI error
//!   type ([`CliError`]) with its exit-code contract, and [`dispatch`],
//!   which executes an already-parsed invocation against the
//!   application services in `vaultx-core`.
//! - `output`: presentation helpers rendering service results as
//!   aligned, secret-free text.
//! - `remoting`: the team-sync surface (login, remotes, workspaces,
//!   push/pull/sync, audit listing) over `vaultx-sync-client`.
//!
//! Handlers contain parsing and presentation logic only (INV-016):
//! every meaningful operation is delegated to a service crate.
//! `main.rs` stays thin — parse → dispatch → stdio/exit codes — so the
//! entire behavior is unit-testable by calling [`dispatch`] directly.

mod cli;
mod output;
#[cfg(test)]
mod tests;

pub mod remoting;

pub use cli::{
    dispatch, AgentCommand, AuditCommand, Cli, CliError, Command, EnvCommand, McpCommand,
    PackCommand, PolicyCommand, PullStrategy, RemoteCommand, SecretCommand, WorkspaceCommand,
};
