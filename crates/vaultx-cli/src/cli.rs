//! Clap command definitions and the dispatch layer for the `vaultx`
//! CLI.
//!
//! [`dispatch`] takes an already-parsed [`Cli`] and returns either the
//! rendered output text or a [`CliError`]. Keeping dispatch free of any
//! process/stdio concerns makes every handler unit-testable without
//! spawning processes; `main.rs` only wires parsing, printing, and exit
//! codes.
//!
//! Handlers contain **parsing and presentation logic only** (plan §14,
//! INV-016): all meaningful work goes through `vaultx-core` services.
//! Command groups whose implementation is deferred are still declared so
//! their names stay reserved in `--help`; invoking one returns
//! [`CliError::NotImplemented`] (exit code 2).

use std::path::{Path, PathBuf};

use clap::{ArgAction, Args, Parser, Subcommand};
use thiserror::Error;

use vaultx_core::{
    BrokeredBinding, CommitSummary, CoreError, MergeOutcome, MergeStrategy, SecretString,
    VaultxServices,
};
use vaultx_types::model::{InjectionTemplateId, VariableKind};
use vaultx_types::{CommitId, CredentialRef, ProviderName, VariableName};

/// Default number of entries printed by `vaultx log` when `--limit` is
/// not given.
const DEFAULT_LOG_LIMIT: usize = 20;

/// Bare environment name used by secret commands when `--env` is omitted.
///
/// There is no persisted "current environment" concept yet (config values
/// are branch-scoped), so the conventional development environment is the
/// default; `--env <ENV>` overrides it per invocation.
const DEFAULT_SECRET_ENV: &str = "development";

/// Author identity used when a command does not take `--author`.
const DEFAULT_AUTHOR: &str = "unknown";

/// Errors surfaced by the CLI layer.
#[derive(Debug, Error)]
pub enum CliError {
    /// The command group exists in the plan but has no implementation in
    /// this build. Exit code 2.
    #[error("`{0}` is not implemented yet")]
    NotImplemented(&'static str),
    /// The command ran outside of an initialized vaultx project.
    /// Exit code 3.
    #[error("not a vaultx repository: {0}")]
    NotARepository(PathBuf),
    /// The invocation was malformed beyond what clap validates: missing
    /// required values, ambiguous commit-id prefixes, malformed
    /// assignments. Exit code 1.
    #[error("{0}")]
    Usage(String),
    /// A merge was refused; the payload is the grouped conflict report.
    /// Exit code 1 — refs and objects were left untouched.
    #[error("{0}")]
    Conflicts(String),
    /// Diagnostics finished with failures; the payload is the rendered
    /// report. Exit code 1.
    #[error("{0}")]
    Diagnostics(String),
    /// An underlying application service failed at runtime.
    /// Exit code 1.
    #[error(transparent)]
    Runtime(#[from] CoreError),
}

impl CliError {
    /// Process exit code for this error:
    ///
    /// * 1 — runtime or usage failure, merge conflicts, or failing
    ///   diagnostics,
    /// * 2 — not-yet-implemented command group,
    /// * 3 — target directory is not a vaultx repository.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Runtime(_) | Self::Usage(_) | Self::Conflicts(_) | Self::Diagnostics(_) => 1,
            Self::NotImplemented(_) => 2,
            Self::NotARepository(_) => 3,
        }
    }
}

/// Catch-all argument collector for planned-but-unimplemented command
/// groups. Everything after the group name is swallowed so a stub can be
/// invoked exactly like its future real form.
#[derive(Args, Debug)]
pub struct StubArgs {
    /// Trailing arguments (ignored by stubs).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
    pub args: Vec<String>,
}

/// The `vaultx` command-line interface.
#[derive(Parser, Debug)]
#[command(
    name = "vaultx",
    version,
    about = "Encrypted environment and configuration manager",
    long_about = None
)]
pub struct Cli {
    /// Project directory to operate on.
    #[arg(long, value_name = "PATH", global = true, default_value = ".")]
    pub project: PathBuf,

    /// Increase verbosity (repeatable). Parsed and ignored until the
    /// tracing layers land.
    #[arg(short = 'v', long, action = ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Command to execute.
    #[command(subcommand)]
    pub command: Command,
}

/// All `vaultx` subcommands.
///
/// Groups documented as *(planned)* parse their trailing arguments but
/// print a clear "not yet implemented" notice and exit with code 2;
/// their internals are deliberately not stubbed.
#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a new vaultx project in --project.
    Init,
    /// Show branch, head commit, and pending staged changes.
    Status,
    /// Run environment health checks.
    Doctor,

    /// Set one or more non-secret config values.
    Set {
        /// NAME=VALUE assignments (at least one).
        #[arg(required = true, value_name = "NAME=VALUE")]
        pairs: Vec<String>,
    },
    /// Print the resolved value of one config variable (staged overlay
    /// first).
    Get {
        /// Variable name.
        name: String,
    },
    /// Stage removal of one or more config variables.
    Unset {
        /// Variable names (at least one).
        #[arg(required = true, value_name = "NAME")]
        names: Vec<String>,
    },
    /// List committed config variables (HEAD manifest only).
    List,

    /// Import KEY=VALUE lines from an .env-style file.
    Import {
        /// Path of the file to import.
        file: PathBuf,
    },

    /// Confirm staged variables are part of the next commit.
    Add {
        /// Variable name to confirm.
        name: Option<String>,
        /// Confirm every currently staged variable.
        #[arg(long)]
        all: bool,
    },
    /// Drop staged intent for one or more variables.
    Restore {
        /// Variable names (at least one).
        #[arg(required = true, value_name = "NAME")]
        names: Vec<String>,
    },

    /// Commit the staging index (requires -m).
    Commit {
        /// Commit message.
        #[arg(short = 'm', long)]
        message: Option<String>,
        /// Author identity string.
        #[arg(long)]
        author: Option<String>,
    },

    /// Show recent commit history (newest first).
    Log {
        /// Maximum number of commits to print.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Show one commit selected by unique id prefix.
    Show {
        /// Full or partial commit id (`cmt_` prefix optional).
        prefix: String,
    },
    /// Metadata diff: staged changes (no args) or between two commits.
    Diff {
        /// First commit id prefix.
        a: Option<String>,
        /// Second commit id prefix.
        b: Option<String>,
    },

    /// List branches, or create one at HEAD.
    Branch {
        /// Name of the branch to create.
        name: Option<String>,
    },
    /// Switch the working project to a branch.
    Checkout {
        /// Branch name.
        name: String,
    },

    // ---- implemented groups ----
    /// Manage deployable environments.
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Manage local agent identities.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Manage authorization policies.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Store, rotate, inspect, or destroy encrypted secret values.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },

    /// Merge another branch into the current branch (or `--into` target).
    Merge {
        /// Branch to merge in.
        branch: String,
        /// Target branch (default: the current branch).
        #[arg(long, value_name = "BRANCH")]
        into: Option<String>,
        /// Auto-resolve non-secret conflicts by picking one side.
        #[arg(long, value_parser = parse_merge_strategy, value_name = "theirs|ours")]
        strategy: Option<MergeStrategy>,
        /// Permit merges that would remove variables bound by protected
        /// environments.
        #[arg(long)]
        allow_weaker_protection: bool,
    },
    /// Roll back to a historical state by appending a new commit
    /// (history is never rewritten).
    Rollback {
        /// Commit id prefix to restore, resolved against the current
        /// branch's first-parent log (default: HEAD's first parent).
        #[arg(long, value_name = "COMMIT")]
        to: Option<String>,
    },
    /// Move an environment onto a source ref's commit.
    Promote {
        /// Destination environment name (bare, e.g. `production`).
        #[arg(long, value_name = "ENV")]
        to: String,
        /// Source branch or environment (default: the current branch).
        #[arg(long, value_name = "REF")]
        from: Option<String>,
        /// Allow moving a protected environment.
        #[arg(long)]
        force: bool,
    },
    // ---- planned groups (exit code 2 notices) ----
    /// Run commands with resolved environment (planned).
    Run(StubArgs),
    /// Broker server/session operations (planned).
    Broker(StubArgs),
    /// Policy pack operations (planned).
    Pack(StubArgs),
    /// MCP server (planned).
    Mcp(StubArgs),
    /// Audit log inspection (planned).
    Audit(StubArgs),
    /// Remote repository configuration (planned).
    Remote(StubArgs),
    /// Authenticate against a remote workspace (planned).
    Login(StubArgs),
    /// Workspace management (planned).
    Workspace(StubArgs),
    /// Push local history upstream (planned).
    Push(StubArgs),
    /// Pull upstream history (planned).
    Pull(StubArgs),
    /// Synchronize with the control plane (planned).
    Sync(StubArgs),
}

/// `vaultx env <subcommand>`.
#[derive(Subcommand, Debug)]
pub enum EnvCommand {
    /// Create an environment pinned at the current HEAD.
    Create {
        /// Environment name (bare, e.g. `staging`).
        name: String,
    },
    /// Mark an environment protected (or unprotect it).
    Protect {
        /// Environment name.
        name: String,
        /// Remove protection instead of adding it.
        #[arg(long)]
        unprotect: bool,
    },
    /// List environments with protection state and pinned commit.
    List,
    /// Show protection, pinned commit, and captured entries.
    Inspect {
        /// Environment name.
        name: String,
    },
}

/// `vaultx agent <subcommand>`.
#[derive(Subcommand, Debug)]
pub enum AgentCommand {
    /// Register a new enabled agent identity.
    Create {
        /// Agent bare name (e.g. `ci-bot`).
        name: String,
    },
    /// List agents with enablement status.
    List,
    /// Show one agent identity file.
    Inspect {
        /// Agent bare name.
        name: String,
    },
    /// Disable an agent (v1 revocation semantics).
    Disable {
        /// Agent bare name.
        name: String,
    },
}

/// `vaultx policy <subcommand>` (save/edit arrive later).
#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// Validate every stored policy document.
    Validate,
    /// List policies as NAME / PRINCIPAL / CREDENTIAL columns.
    List,
}

/// `vaultx secret <subcommand>`.
///
/// Plaintext is never accepted as a command-line argument: commands read
/// it from stdin when the trailing `-` positional is given (exactly one
/// trailing newline is stripped), or via a hidden double prompt otherwise.
#[derive(Subcommand, Debug)]
pub enum SecretCommand {
    /// Store a new value for NAME, creating or replacing its binding.
    Set {
        /// Variable name.
        name: String,
        /// Read the plaintext from stdin instead of prompting.
        #[arg(value_name = "-")]
        stdin: Option<String>,
        /// Bind as a brokered credential instead of a plain secret.
        #[arg(long)]
        brokered: bool,
        /// Injection template (required with `--brokered`).
        #[arg(long, value_parser = parse_injection_template, value_name = "TEMPLATE")]
        injection: Option<InjectionTemplateId>,
        /// Optional provider hint for brokered credentials.
        #[arg(long, value_name = "NAME")]
        provider: Option<String>,
        /// Target environment (default: development).
        #[arg(long, value_name = "ENV")]
        env: Option<String>,
        /// Reserved annotation for future audit-event correlation.
        #[arg(short = 'm', long)]
        message: Option<String>,
    },
    /// Replace the value of NAME with a fresh revision (old one revoked).
    Rotate {
        /// Variable name.
        name: String,
        /// Read the plaintext from stdin instead of prompting.
        #[arg(value_name = "-")]
        stdin: Option<String>,
        /// Target environment (default: development).
        #[arg(long, value_name = "ENV")]
        env: Option<String>,
        /// Reserved annotation for future audit-event correlation.
        #[arg(short = 'm', long)]
        message: Option<String>,
    },
    /// Show metadata about NAME (never its value).
    Metadata {
        /// Variable name.
        name: String,
        /// Target environment (default: development).
        #[arg(long, value_name = "ENV")]
        env: Option<String>,
    },
    /// Irreversibly destroy NAME's current value and recovery material.
    Destroy {
        /// Variable name.
        name: String,
        /// Explicit confirmation; destruction cannot be undone.
        #[arg(long)]
        yes: bool,
        /// Target environment (default: development).
        #[arg(long, value_name = "ENV")]
        env: Option<String>,
    },
}

/// Executes an already-parsed invocation against the application
/// services selected by `cli.project`, returning the rendered output.
///
/// # Errors
/// See [`CliError`]: runtime failures carry [`CoreError`], deferred
/// groups return [`CliError::NotImplemented`], and open-based commands
/// outside a repository return [`CliError::NotARepository`].
pub fn dispatch(cli: &Cli) -> Result<String, CliError> {
    match &cli.command {
        // Project lifecycle.
        Command::Init => cmd_init(&cli.project),

        // Everything else requires an open project first.
        Command::Status => with_open(&cli.project, cmd_status),
        Command::Set { pairs } => with_open(&cli.project, |s| cmd_set(s, pairs)),
        Command::Get { name } => with_open(&cli.project, |s| cmd_get(s, name)),
        Command::Unset { names } => with_open(&cli.project, |s| cmd_unset(s, names)),
        Command::List => with_open(&cli.project, cmd_list),
        Command::Import { file } => with_open(&cli.project, |s| cmd_import(s, file)),
        Command::Add { name, all } => {
            with_open(&cli.project, |s| cmd_add(s, name.as_deref(), *all))
        }
        Command::Restore { names } => with_open(&cli.project, |s| cmd_restore(s, names)),

        Command::Commit { message, author } => with_open(&cli.project, |s| {
            cmd_commit(s, message.as_deref(), author.as_deref())
        }),
        Command::Log { limit } => with_open(&cli.project, |s| cmd_log(s, *limit)),
        Command::Show { prefix } => with_open(&cli.project, |s| cmd_show(s, prefix)),
        Command::Diff { a, b } => {
            with_open(&cli.project, |s| cmd_diff(s, a.as_deref(), b.as_deref()))
        }
        Command::Branch { name } => with_open(&cli.project, |s| cmd_branch(s, name.as_deref())),
        Command::Checkout { name } => with_open(&cli.project, |s| cmd_checkout(s, name)),

        Command::Env { command } => match command {
            EnvCommand::Create { name } => with_open(&cli.project, |s| cmd_env_create(s, name)),
            EnvCommand::Protect { name, unprotect } => {
                with_open(&cli.project, |s| cmd_env_protect(s, name, *unprotect))
            }
            EnvCommand::List => with_open(&cli.project, cmd_env_list),
            EnvCommand::Inspect { name } => with_open(&cli.project, |s| cmd_env_inspect(s, name)),
        },

        Command::Agent { command } => match command {
            AgentCommand::Create { name } => with_open(&cli.project, |s| cmd_agent_create(s, name)),
            AgentCommand::List => with_open(&cli.project, cmd_agent_list),
            AgentCommand::Inspect { name } => {
                with_open(&cli.project, |s| cmd_agent_inspect(s, name))
            }
            AgentCommand::Disable { name } => {
                with_open(&cli.project, |s| cmd_agent_disable(s, name))
            }
        },

        Command::Policy { command } => match command {
            PolicyCommand::Validate => with_open(&cli.project, cmd_policy_validate),
            PolicyCommand::List => with_open(&cli.project, cmd_policy_list),
        },

        Command::Secret { command } => match command {
            SecretCommand::Set {
                name,
                stdin,
                brokered,
                injection,
                provider,
                env,
                message: _,
            } => with_open(&cli.project, |s| {
                cmd_secret_set(
                    s,
                    name,
                    stdin.as_deref(),
                    *brokered,
                    *injection,
                    provider.as_deref(),
                    env.as_deref(),
                )
            }),
            SecretCommand::Rotate {
                name,
                stdin,
                env,
                message: _,
            } => with_open(&cli.project, |s| {
                cmd_secret_rotate(s, name, stdin.as_deref(), env.as_deref())
            }),
            SecretCommand::Metadata { name, env } => with_open(&cli.project, |s| {
                cmd_secret_metadata(s, name, env.as_deref())
            }),
            SecretCommand::Destroy { name, yes, env } => with_open(&cli.project, |s| {
                cmd_secret_destroy(s, name, *yes, env.as_deref())
            }),
        },

        // Implemented history/environment commands.
        Command::Doctor => with_open(&cli.project, cmd_doctor),
        Command::Merge {
            branch,
            into,
            strategy,
            allow_weaker_protection,
        } => with_open(&cli.project, |s| {
            cmd_merge(
                s,
                branch,
                into.as_deref(),
                *strategy,
                *allow_weaker_protection,
            )
        }),
        Command::Rollback { to } => with_open(&cli.project, |s| cmd_rollback(s, to.as_deref())),
        Command::Promote { to, from, force } => with_open(&cli.project, |s| {
            cmd_promote(s, to, from.as_deref(), *force)
        }),

        // Planned groups: reserved names, clear notices, exit code 2.
        Command::Run(_) => Err(CliError::NotImplemented("run")),
        Command::Broker(_) => Err(CliError::NotImplemented("broker")),
        Command::Pack(_) => Err(CliError::NotImplemented("pack")),
        Command::Mcp(_) => Err(CliError::NotImplemented("mcp")),
        Command::Audit(_) => Err(CliError::NotImplemented("audit")),
        Command::Remote(_) => Err(CliError::NotImplemented("remote")),
        Command::Login(_) => Err(CliError::NotImplemented("login")),
        Command::Workspace(_) => Err(CliError::NotImplemented("workspace")),
        Command::Push(_) => Err(CliError::NotImplemented("push")),
        Command::Pull(_) => Err(CliError::NotImplemented("pull")),
        Command::Sync(_) => Err(CliError::NotImplemented("sync")),
    }
}

/// Opens the project, mapping the not-a-repository case onto its own
/// exit-code class before running `body`.
fn with_open(
    project: &Path,
    body: impl FnOnce(&VaultxServices) -> Result<String, CliError>,
) -> Result<String, CliError> {
    let services = VaultxServices::open(project).map_err(|err| match err {
        CoreError::NotARepository(path) => CliError::NotARepository(path),
        other => other.into(),
    })?;
    body(&services)
}

fn cmd_init(project: &Path) -> Result<String, CliError> {
    VaultxServices::init(project).map_err(|err| match err {
        CoreError::NotARepository(path) => CliError::NotARepository(path),
        other => other.into(),
    })?;
    Ok(format!(
        "initialized empty vaultx project at {}",
        project.display()
    ))
}

fn cmd_status(services: &VaultxServices) -> Result<String, CliError> {
    let report = services.staging().status()?;
    Ok(crate::output::render_status(&report))
}

fn cmd_set(services: &VaultxServices, pairs: &[String]) -> Result<String, CliError> {
    let mut lines = Vec::with_capacity(pairs.len());
    for raw in pairs {
        let (name, value) = parse_assignment(raw)?;
        services.config().set_config(name, value)?;
        lines.push(format!("set {name}"));
    }
    Ok(lines.join("\n"))
}

fn cmd_get(services: &VaultxServices, name: &str) -> Result<String, CliError> {
    Ok(services.config().get_config(name)?)
}

fn cmd_unset(services: &VaultxServices, names: &[String]) -> Result<String, CliError> {
    let mut lines = Vec::with_capacity(names.len());
    for name in names {
        services.config().unset_config(name)?;
        lines.push(format!("unset {name}"));
    }
    Ok(lines.join("\n"))
}

fn cmd_list(services: &VaultxServices) -> Result<String, CliError> {
    let rows: Vec<Vec<String>> = services
        .config()
        .list_configs()?
        .into_iter()
        .map(|(name, value)| vec![name.to_string(), "config".to_owned(), value])
        .collect();
    Ok(crate::output::render_config_list(&rows))
}

fn cmd_import(services: &VaultxServices, file: &Path) -> Result<String, CliError> {
    // Read failures must name the file: bare OS messages ("No such file
    // or directory") would leave the operator guessing which input was
    // missing.
    let text = std::fs::read_to_string(file).map_err(|err| {
        CliError::Runtime(CoreError::Io(std::io::Error::new(
            err.kind(),
            format!("cannot read {}: {err}", file.display()),
        )))
    })?;
    // Tolerate UTF-8 BOMs emitted by Windows editors; otherwise the
    // marker glues onto the first variable's name and silently breaks it.
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let pairs = parse_env_file(text);
    let borrowed: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(n, v)| (n.as_str(), v.as_str()))
        .collect();
    let report = services.config().import_env_pairs(borrowed)?;
    Ok(crate::output::render_import_report(file, &report))
}

fn cmd_add(services: &VaultxServices, name: Option<&str>, all: bool) -> Result<String, CliError> {
    if !all {
        let Some(name) = name else {
            return Err(CliError::Usage("add requires NAME or --all".into()));
        };
        services.staging().add(name)?;
        return Ok(format!("added {name}"));
    }
    if name.is_some() {
        return Err(CliError::Usage(
            "add accepts either NAME or --all, not both".into(),
        ));
    }
    let staged = services.staging().status()?.staged_changes;
    if staged.is_empty() {
        return Ok("nothing staged".to_owned());
    }
    let mut lines = Vec::with_capacity(staged.len());
    for (variable, _) in &staged {
        services.staging().add(variable.as_str())?;
        lines.push(format!("added {variable}"));
    }
    Ok(lines.join("\n"))
}

fn cmd_restore(services: &VaultxServices, names: &[String]) -> Result<String, CliError> {
    let mut lines = Vec::with_capacity(names.len());
    for name in names {
        let had_intent = services.staging().restore(name)?;
        lines.push(if had_intent {
            format!("restored {name}")
        } else {
            format!("nothing staged for {name}")
        });
    }
    Ok(lines.join("\n"))
}

fn cmd_commit(
    services: &VaultxServices,
    message: Option<&str>,
    author: Option<&str>,
) -> Result<String, CliError> {
    let Some(message) = message else {
        return Err(CliError::Usage("commit requires -m <message>".into()));
    };
    let author = author.unwrap_or(DEFAULT_AUTHOR);
    let id = services.history().commit(message, author)?;
    Ok(format!("committed {id}"))
}

fn cmd_log(services: &VaultxServices, limit: Option<usize>) -> Result<String, CliError> {
    let entries = services.history().log(limit.unwrap_or(DEFAULT_LOG_LIMIT))?;
    Ok(crate::output::render_log(&entries))
}

fn cmd_show(services: &VaultxServices, prefix: &str) -> Result<String, CliError> {
    let log = services.history().log(usize::MAX)?;
    let id = resolve_commit_prefix(prefix, &log)?;
    let detail = services.history().show(&id)?;
    Ok(crate::output::render_commit_detail(&detail))
}

fn cmd_diff(
    services: &VaultxServices,
    a: Option<&str>,
    b: Option<&str>,
) -> Result<String, CliError> {
    match (a, b) {
        (None, None) => {
            let diff = services.history().diff_staged()?;
            Ok(crate::output::render_diff(&diff))
        }
        (Some(a), Some(b)) => {
            let log = services.history().log(usize::MAX)?;
            let first = resolve_commit_prefix(a, &log)?;
            let second = resolve_commit_prefix(b, &log)?;
            let diff = services.history().diff_commits(&first, &second)?;
            Ok(crate::output::render_diff(&diff))
        }
        _ => Err(CliError::Usage(
            "diff takes no arguments (staged diff) or exactly two commit ids".into(),
        )),
    }
}

fn cmd_branch(services: &VaultxServices, name: Option<&str>) -> Result<String, CliError> {
    match name {
        None => {
            let branches = services.history().branches()?;
            Ok(crate::output::render_branches(&branches))
        }
        Some(name) => {
            services.history().branch(name)?;
            Ok(format!("created branch {name}"))
        }
    }
}

fn cmd_checkout(services: &VaultxServices, name: &str) -> Result<String, CliError> {
    services.history().checkout(name)?;
    Ok(format!("switched to branch {name}"))
}

fn cmd_env_create(services: &VaultxServices, name: &str) -> Result<String, CliError> {
    let id = services.environments().create_environment(name)?;
    Ok(format!("created environment {name} ({id})"))
}

fn cmd_env_protect(
    services: &VaultxServices,
    name: &str,
    unprotect: bool,
) -> Result<String, CliError> {
    services
        .environments()
        .protect_environment(name, !unprotect)?;
    Ok(if unprotect {
        format!("{name} is now unprotected")
    } else {
        format!("{name} is now protected")
    })
}

fn cmd_env_list(services: &VaultxServices) -> Result<String, CliError> {
    let summaries = services.environments().list_environments()?;
    Ok(crate::output::render_environments(&summaries))
}

fn cmd_env_inspect(services: &VaultxServices, name: &str) -> Result<String, CliError> {
    let summary = services
        .environments()
        .list_environments()?
        .into_iter()
        .find(|env| env.name == name)
        .ok_or_else(|| CliError::Runtime(CoreError::EnvironmentNotFound(name.to_owned())))?;
    let Some(commit) = summary.commit else {
        return Err(CliError::Usage(format!(
            "environment `{name}` has no pinned commit"
        )));
    };
    let detail = services.history().show(&commit)?;
    Ok(crate::output::render_env_inspect(
        name,
        summary.protected,
        &commit,
        &detail.entries,
    ))
}

fn cmd_merge(
    services: &VaultxServices,
    theirs_branch: &str,
    into_target: Option<&str>,
    strategy: Option<MergeStrategy>,
    allow_weaker_protection: bool,
) -> Result<String, CliError> {
    match services.history().merge_branch(
        theirs_branch,
        into_target,
        strategy,
        allow_weaker_protection,
        DEFAULT_AUTHOR,
    )? {
        MergeOutcome::AlreadyUpToDate { target_branch } => {
            Ok(format!("merge: {target_branch} is already up to date"))
        }
        MergeOutcome::Committed {
            commit_id,
            target_branch,
        } => Ok(format!(
            "merged {theirs_branch} into {target_branch}\n{commit_id}"
        )),
        MergeOutcome::Conflicts(set) => Err(CliError::Conflicts(
            crate::output::render_merge_conflicts(&set),
        )),
    }
}

fn cmd_rollback(services: &VaultxServices, to: Option<&str>) -> Result<String, CliError> {
    let target = match to {
        Some(prefix) => {
            let log = services.history().log(usize::MAX)?;
            Some(resolve_commit_prefix(prefix, &log)?)
        }
        None => None,
    };
    let report = services
        .history()
        .rollback(target.as_ref(), DEFAULT_AUTHOR)?;
    Ok(crate::output::render_rollback(&report))
}

fn cmd_promote(
    services: &VaultxServices,
    to_env: &str,
    from_ref: Option<&str>,
    force: bool,
) -> Result<String, CliError> {
    let from = match from_ref {
        Some(reference) => reference.to_owned(),
        None => services
            .staging()
            .status()?
            .branch
            .ok_or_else(|| CliError::Usage("--from is required on a detached HEAD".into()))?,
    };
    services.environments().promote(&from, to_env, force)?;
    Ok(format!("promoted {from} -> {to_env}"))
}

fn cmd_doctor(services: &VaultxServices) -> Result<String, CliError> {
    use vaultx_core::CheckStatus;
    let outcomes = services.doctor().run();
    let rendered = vaultx_core::render_checks(&outcomes);
    if outcomes
        .iter()
        .any(|outcome| outcome.status == CheckStatus::Fail)
    {
        Err(CliError::Diagnostics(rendered))
    } else {
        Ok(rendered)
    }
}

fn cmd_agent_create(services: &VaultxServices, name: &str) -> Result<String, CliError> {
    let full_id = services.agents().create_agent(name)?;
    Ok(format!("created agent {name} ({full_id})"))
}

fn cmd_agent_list(services: &VaultxServices) -> Result<String, CliError> {
    let agents = services.agents().list_agents()?;
    Ok(crate::output::render_agents(&agents))
}

fn cmd_agent_inspect(services: &VaultxServices, name: &str) -> Result<String, CliError> {
    let file = services.agents().inspect(name)?;
    Ok(crate::output::render_agent_detail(&file))
}

fn cmd_agent_disable(services: &VaultxServices, name: &str) -> Result<String, CliError> {
    services.agents().disable(name)?;
    Ok(format!("disabled agent {name}"))
}

fn cmd_policy_validate(services: &VaultxServices) -> Result<String, CliError> {
    let results = services
        .policies()
        .validate_all()?
        .into_iter()
        .map(|result| result.map(|name| name.to_string()))
        .collect();
    Ok(crate::output::render_policy_validation(results))
}

fn cmd_policy_list(services: &VaultxServices) -> Result<String, CliError> {
    let documents = services.policies().load_policies()?;
    if documents.is_empty() {
        return Ok("no policies found".to_owned());
    }
    let rows: Vec<Vec<String>> = documents
        .iter()
        .map(|doc| {
            vec![
                doc.name.to_string(),
                doc.principal.to_string(),
                doc.credential.to_string(),
            ]
        })
        .collect();
    Ok(crate::output::render_table(
        &["NAME", "PRINCIPAL", "CREDENTIAL"],
        &rows,
    ))
}

fn cmd_secret_set(
    services: &VaultxServices,
    name: &str,
    stdin_flag: Option<&str>,
    brokered: bool,
    injection: Option<InjectionTemplateId>,
    provider: Option<&str>,
    env: Option<&str>,
) -> Result<String, CliError> {
    // Validate the name (and flag pairing) before any prompting so a
    // typo never collects a password it cannot use.
    VariableName::parse(name)
        .map_err(|_| CliError::Runtime(CoreError::InvalidVariableName(name.to_owned())))?;
    let (kind, binding) = build_secret_binding(name, brokered, injection, provider)?;
    let plaintext = acquire_plaintext(stdin_flag)?;
    let revision = services.secrets().set_secret(
        name,
        &plaintext,
        kind,
        env.unwrap_or(DEFAULT_SECRET_ENV),
        binding,
    )?;
    Ok(format!("set {name} ({revision})"))
}

fn cmd_secret_rotate(
    services: &VaultxServices,
    name: &str,
    stdin_flag: Option<&str>,
    env: Option<&str>,
) -> Result<String, CliError> {
    let plaintext = acquire_plaintext(stdin_flag)?;
    let revision =
        services
            .secrets()
            .rotate_secret(name, &plaintext, env.unwrap_or(DEFAULT_SECRET_ENV))?;
    Ok(format!("rotated {name} ({revision})"))
}

fn cmd_secret_metadata(
    services: &VaultxServices,
    name: &str,
    env: Option<&str>,
) -> Result<String, CliError> {
    let metadata = services
        .secrets()
        .secret_metadata(name, env.unwrap_or(DEFAULT_SECRET_ENV))?;
    Ok(crate::output::render_secret_metadata(&metadata))
}

fn cmd_secret_destroy(
    services: &VaultxServices,
    name: &str,
    yes: bool,
    env: Option<&str>,
) -> Result<String, CliError> {
    if !yes {
        return Err(CliError::Usage(
            "refusing to destroy without --yes; destruction irreversibly shreds the secret's \
             recovery material"
                .into(),
        ));
    }
    services
        .secrets()
        .destroy_secret(name, env.unwrap_or(DEFAULT_SECRET_ENV))?;
    Ok(format!(
        "destroyed {name}: its value and recovery material are irreversibly gone"
    ))
}

/// Translates `--brokered`/`--injection`/`--provider` flags into the
/// service-level kind + binding pair. Brokered credentials derive their
/// credential ref from the lowercased variable name (the CLI exposes no
/// separate credential namespace in v1).
fn build_secret_binding(
    name: &str,
    brokered: bool,
    injection: Option<InjectionTemplateId>,
    provider: Option<&str>,
) -> Result<(VariableKind, Option<BrokeredBinding>), CliError> {
    if !brokered {
        if injection.is_some() || provider.is_some() {
            return Err(CliError::Usage(
                "--injection/--provider require --brokered".into(),
            ));
        }
        return Ok((VariableKind::Secret, None));
    }
    let injection = injection
        .ok_or_else(|| CliError::Usage("--brokered requires --injection <TEMPLATE>".into()))?;
    let hint = match provider {
        None => None,
        Some(raw) => Some(ProviderName::parse(raw).map_err(|_| {
            CliError::Usage(format!(
                "`{raw}` is not a valid provider name (lowercase letters, digits, `-`)"
            ))
        })?),
    };
    let credential_ref = CredentialRef::parse(&name.to_ascii_lowercase()).map_err(|_| {
        CliError::Usage(format!(
            "variable name `{name}` cannot form a credential ref"
        ))
    })?;
    Ok((
        VariableKind::Brokered,
        Some(BrokeredBinding {
            credential_ref,
            injection,
            provider_hint: hint,
        }),
    ))
}

/// Obtains the secret plaintext either from stdin (`-`) or a hidden
/// double prompt. Command-line arguments are deliberately refused.
fn acquire_plaintext(stdin_flag: Option<&str>) -> Result<SecretString, CliError> {
    match stdin_flag {
        Some("-") => read_stdin_plaintext(),
        Some(other) => Err(CliError::Usage(format!(
            "unexpected positional `{other}`; only `-` (read the value from stdin) is accepted"
        ))),
        None => prompt_plaintext_twice(),
    }
}

fn read_stdin_plaintext() -> Result<SecretString, CliError> {
    use std::io::Read as _;
    use zeroize::Zeroize as _;
    let mut raw = String::new();
    if let Err(err) = std::io::stdin().lock().read_to_string(&mut raw) {
        // A failed read may still have appended partial bytes; scrub
        // before propagating.
        raw.zeroize();
        return Err(CliError::Usage(format!("cannot read stdin: {err}")));
    }
    // Strip exactly one trailing newline so `echo pw | vaultx ...` stores
    // the value without the echo's line terminator.
    let trimmed_len = raw
        .strip_suffix("\r\n")
        .or_else(|| raw.strip_suffix('\n'))
        .map_or(raw.len(), str::len);
    let secret = SecretString::new(raw[..trimmed_len].to_owned());
    // Scrub the unencrypted intermediate before it drops.
    raw.zeroize();
    Ok(secret)
}

fn prompt_plaintext_twice() -> Result<SecretString, CliError> {
    use zeroize::Zeroize as _;
    let mut first = rpassword::prompt_password("Enter secret value: ")
        .map_err(|err| CliError::Usage(format!("cannot read password: {err}")))?;
    let mut confirmed = match rpassword::prompt_password("Confirm secret value: ") {
        Ok(value) => value,
        Err(err) => {
            // The already-collected first value must never outlive this
            // function unscrubbed.
            first.zeroize();
            return Err(CliError::Usage(format!("cannot read password: {err}")));
        }
    };
    if first == confirmed {
        let secret = SecretString::new(first);
        confirmed.zeroize();
        Ok(secret)
    } else {
        first.zeroize();
        confirmed.zeroize();
        Err(CliError::Usage("Passwords do not match".into()))
    }
}

/// Parses an injection-template flag value (kebab-case, matching the
/// serde representation of [`InjectionTemplateId`]).
fn parse_injection_template(raw: &str) -> Result<InjectionTemplateId, String> {
    match raw {
        "bearer" => Ok(InjectionTemplateId::Bearer),
        "basic-password" => Ok(InjectionTemplateId::BasicPassword),
        "api-key-header" => Ok(InjectionTemplateId::ApiKeyHeader),
        "github-bearer" => Ok(InjectionTemplateId::GithubBearer),
        "query-parameter" => Ok(InjectionTemplateId::QueryParameter),
        "aws-sigv4" => Ok(InjectionTemplateId::AwsSigv4),
        "custom-static-header-plus-secret" => Ok(InjectionTemplateId::CustomStaticHeaderPlusSecret),
        other => Err(format!(
            "unknown injection template `{other}` (expected bearer, basic-password, \
             api-key-header, github-bearer, query-parameter, aws-sigv4, or \
             custom-static-header-plus-secret)"
        )),
    }
}

/// Parses the `--strategy` flag for merges (`theirs` or `ours`).
fn parse_merge_strategy(raw: &str) -> Result<MergeStrategy, String> {
    match raw {
        "theirs" => Ok(MergeStrategy::Theirs),
        "ours" => Ok(MergeStrategy::Ours),
        other => Err(format!(
            "unknown merge strategy `{other}` (expected `theirs` or `ours`)"
        )),
    }
}

/// Splits one `NAME=VALUE` assignment; the value may be empty but the
/// name must not be.
fn parse_assignment(raw: &str) -> Result<(&str, &str), CliError> {
    let Some((name, value)) = raw.split_once('=') else {
        return Err(CliError::Usage(format!("expected NAME=VALUE, got `{raw}`")));
    };
    let name = name.trim();
    if name.is_empty() {
        return Err(CliError::Usage(format!("expected NAME=VALUE, got `{raw}`")));
    }
    Ok((name, value))
}

/// Parses `.env`-style lines into `(NAME, VALUE)` pairs.
///
/// Blank lines and `#` comments are skipped; surrounding single or
/// double quotes are stripped from values; whitespace around names and
/// values is trimmed. Duplicate keys within one file collapse to a
/// single entry with the last value winning, so the import report lists
/// each name once. Malformed lines are dropped silently here — the
/// import classifier reports what it accepted, so callers wanting
/// line-level errors should pre-validate the file themselves.
fn parse_env_file(text: &str) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let value = strip_quotes(value.trim());
        match pairs.iter_mut().find(|(existing, _)| existing == name) {
            Some(slot) => slot.1 = value,
            None => pairs.push((name.to_owned(), value)),
        }
    }
    pairs
}

/// Removes one matching pair of surrounding single/double quotes.
fn strip_quotes(value: &str) -> String {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        value[1..value.len() - 1].to_owned()
    } else {
        value.to_owned()
    }
}

/// Resolves a user-supplied commit-id prefix against the given log
/// entries. Matching ignores the optional `cmt_` prefix and is
/// case-insensitive (canonical ids are lowercase hex, but operators
/// habitually paste uppercase from various tools). Zero matches and
/// ambiguous prefixes are usage errors; ambiguity lists the candidate
/// short ids.
fn resolve_commit_prefix(prefix: &str, log: &[CommitSummary]) -> Result<CommitId, CliError> {
    let raw = prefix.strip_prefix(CommitId::PREFIX).unwrap_or(prefix);
    if raw.is_empty() {
        return Err(CliError::Usage("commit id prefix must not be empty".into()));
    }
    let needle = raw.to_ascii_lowercase();
    let matches: Vec<&CommitSummary> = log
        .iter()
        .filter(|entry| {
            entry
                .id
                .as_str()
                .strip_prefix(CommitId::PREFIX)
                .is_some_and(|hex| hex.starts_with(&needle))
        })
        .collect();
    match matches.as_slice() {
        [] => Err(CliError::Usage(format!("no commit matches `{prefix}`"))),
        [only] => Ok(only.id.clone()),
        many => {
            let candidates = many
                .iter()
                .map(|entry| crate::output::short_commit_id(&entry.id))
                .collect::<Vec<_>>()
                .join(", ");
            Err(CliError::Usage(format!(
                "ambiguous prefix `{prefix}` matches {} commits: {candidates}",
                many.len()
            )))
        }
    }
}

#[cfg(test)]
mod helper_tests {
    use super::*;
    use vaultx_core::CommitSummary;

    fn summary(hex: &str) -> CommitSummary {
        CommitSummary {
            id: CommitId::parse(&format!("cmt_{hex}")).unwrap(),
            message: "m".to_owned(),
            author: "user:t".to_owned(),
            parents_len: 1,
        }
    }

    #[test]
    fn assignment_parsing_rejects_missing_or_empty_names() {
        assert_eq!(parse_assignment("PORT=8080").unwrap(), ("PORT", "8080"));
        assert_eq!(parse_assignment("EMPTY=").unwrap(), ("EMPTY", ""));
        assert!(matches!(
            parse_assignment("no-equals-sign"),
            Err(CliError::Usage(_))
        ));
        assert!(matches!(
            parse_assignment("=value"),
            Err(CliError::Usage(_))
        ));
    }

    #[test]
    fn env_file_parsing_skips_comments_strips_quotes_dedupes() {
        let pairs = parse_env_file(
            "\n# comment\nA=1\n  B = spaced value \nC=\"quoted\"\nD='single'\nE=\nA=last-wins\nno-equals\n=bad\n",
        );
        assert_eq!(
            pairs,
            vec![
                ("A".to_owned(), "last-wins".to_owned()),
                ("B".to_owned(), "spaced value".to_owned()),
                ("C".to_owned(), "quoted".to_owned()),
                ("D".to_owned(), "single".to_owned()),
                ("E".to_owned(), String::new()),
            ]
        );
    }

    #[test]
    fn injection_template_parsing_covers_all_templates_and_rejects_unknown() {
        for (raw, expected) in [
            ("bearer", InjectionTemplateId::Bearer),
            ("basic-password", InjectionTemplateId::BasicPassword),
            ("api-key-header", InjectionTemplateId::ApiKeyHeader),
            ("github-bearer", InjectionTemplateId::GithubBearer),
            ("query-parameter", InjectionTemplateId::QueryParameter),
            ("aws-sigv4", InjectionTemplateId::AwsSigv4),
            (
                "custom-static-header-plus-secret",
                InjectionTemplateId::CustomStaticHeaderPlusSecret,
            ),
        ] {
            assert_eq!(parse_injection_template(raw), Ok(expected), "{raw}");
        }
        let err = parse_injection_template("mystery-header").unwrap_err();
        assert!(
            err.contains("unknown injection template `mystery-header`"),
            "{err}"
        );
    }

    #[test]
    fn prefix_resolution_unique_ambiguous_and_empty() {
        let log = [summary("aaa111000000"), summary("aaa222000000")];

        // Unique match ignores the optional `cmt_` prefix and accepts
        // uppercase input (ids are stored lowercase).
        let id = resolve_commit_prefix("aaa111", &log).unwrap();
        assert_eq!(id, log[0].id);
        let id = resolve_commit_prefix("AAA111", &log).unwrap();
        assert_eq!(id, log[0].id);
        let id = resolve_commit_prefix("cmt_aaa111", &log).unwrap();
        assert_eq!(id, log[0].id);

        // Ambiguity lists both candidate short ids.
        let err = resolve_commit_prefix("aaa", &log).unwrap_err();
        assert!(
            matches!(&err, CliError::Usage(text)
                if text.contains("ambiguous prefix `aaa` matches 2 commits")
                    && text.contains(&crate::output::short_commit_id(&log[0].id))
                    && text.contains(&crate::output::short_commit_id(&log[1].id))),
            "got: {err:?}"
        );

        // Zero matches and the empty prefix are usage errors.
        assert!(matches!(
            resolve_commit_prefix("ffffff", &log),
            Err(CliError::Usage(text)) if text.contains("no commit matches")
        ));
        assert!(matches!(
            resolve_commit_prefix("", &log),
            Err(CliError::Usage(text)) if text.contains("must not be empty")
        ));
    }
}
