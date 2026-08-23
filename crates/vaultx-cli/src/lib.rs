//! Clap command surface for the `vaultx` binary (plan §14).
//!
//! - `cli`: the derive structs ([`Cli`], [`Command`]), the CLI error
//!   type ([`CliError`]) with its exit-code contract, and [`dispatch`],
//!   which executes an already-parsed invocation against the
//!   application services in `vaultx-core`.
//! - `output`: presentation helpers rendering service results as
//!   aligned, secret-free text.
//!
//! Handlers contain parsing and presentation logic only (INV-016):
//! every meaningful operation is delegated to a `vaultx-core` service.
//! `main.rs` stays thin — parse → dispatch → stdio/exit codes — so the
//! entire behavior is unit-testable by calling [`dispatch`] directly.

mod cli;
mod output;
#[cfg(test)]
mod tests;

pub use cli::{
    dispatch, AgentCommand, Cli, CliError, Command, EnvCommand, PolicyCommand, SecretCommand,
    StubArgs,
};
