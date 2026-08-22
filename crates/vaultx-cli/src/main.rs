//! Thin process wrapper for the `vaultx` binary.
//!
//! Parse → dispatch → stdio/exit codes. All behavior lives in
//! [`vaultx_cli::dispatch`] so it stays unit-testable; this file only
//! wires standard input/output and maps [`vaultx_cli::CliError`] onto
//! process exit codes:
//!
//! * 0 — success,
//! * 1 — runtime error (config/service failure) or malformed invocation,
//! * 2 — unsupported (not-yet-implemented) command group,
//! * 3 — not a vaultx repository.

use std::process::ExitCode;

use clap::Parser as _;

use vaultx_cli::{dispatch, Cli};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(&cli) {
        Ok(text) => {
            if !text.is_empty() {
                println!("{text}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("vaultx: {err}");
            ExitCode::from(u8::try_from(err.exit_code()).unwrap_or(1))
        }
    }
}
