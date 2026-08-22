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

use vaultx_core::{CommitSummary, CoreError, VaultxServices};
use vaultx_types::CommitId;

/// Default number of entries printed by `vaultx log` when `--limit` is
/// not given.
const DEFAULT_LOG_LIMIT: usize = 20;

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
    /// An underlying application service failed at runtime.
    /// Exit code 1.
    #[error(transparent)]
    Runtime(#[from] CoreError),
}

impl CliError {
    /// Process exit code for this error:
    ///
    /// * 1 — runtime or usage failure,
    /// * 2 — not-yet-implemented command group,
    /// * 3 — target directory is not a vaultx repository.
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::Runtime(_) | Self::Usage(_) => 1,
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
    /// Environment health checks (planned).
    Doctor(StubArgs),

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

    // ---- planned groups (exit code 2 notices) ----
    /// Secret value operations (planned).
    Secret(StubArgs),
    /// Merge branch histories (planned).
    Merge(StubArgs),
    /// Roll back variables to a past state (planned).
    Rollback(StubArgs),
    /// Promote a ref onto an environment (planned).
    Promote(StubArgs),
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

        // Planned groups: reserved names, clear notices, exit code 2.
        Command::Doctor(_) => Err(CliError::NotImplemented("doctor")),
        Command::Secret(_) => Err(CliError::NotImplemented("secret")),
        Command::Merge(_) => Err(CliError::NotImplemented("merge")),
        Command::Rollback(_) => Err(CliError::NotImplemented("rollback")),
        Command::Promote(_) => Err(CliError::NotImplemented("promote")),
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
    let text = std::fs::read_to_string(file).map_err(CoreError::from)?;
    let pairs = parse_env_file(&text);
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
    let author = author.unwrap_or("unknown");
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
/// values is trimmed. Malformed lines are dropped silently here — the
/// import classifier reports what it accepted, so callers wanting
/// line-level errors should pre-validate the file themselves.
fn parse_env_file(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (name, value) = line.split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some((name.to_owned(), strip_quotes(value.trim())))
        })
        .collect()
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
/// case-sensitive. Zero matches and ambiguous prefixes are usage errors;
/// ambiguity lists the candidate short ids.
fn resolve_commit_prefix(prefix: &str, log: &[CommitSummary]) -> Result<CommitId, CliError> {
    let needle = prefix.strip_prefix(CommitId::PREFIX).unwrap_or(prefix);
    if needle.is_empty() {
        return Err(CliError::Usage("commit id prefix must not be empty".into()));
    }
    let matches: Vec<&CommitSummary> = log
        .iter()
        .filter(|entry| {
            entry
                .id
                .as_str()
                .strip_prefix(CommitId::PREFIX)
                .is_some_and(|hex| hex.starts_with(needle))
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
