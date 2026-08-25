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

use vaultx_broker::SessionStore as _;
use vaultx_core::{
    BrokeredBinding, CommitSummary, CoreError, MergeOutcome, MergeStrategy, SecretString,
    VaultxServices,
};
use vaultx_types::model::{InjectionTemplateId, VariableKind};
use vaultx_types::{CommitId, CredentialRef, ProviderName, VariableName};

/// Default directory scanned by `vaultx pack` commands (relative to the
/// project root).
const DEFAULT_PACKS_DIR: &str = "policy-packs";

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
    /// A policy denial returned by the broker. Exit code 4 — distinct
    /// from transport/usage failures so agents can branch on it.
    #[error("denied by policy: {0}")]
    Denied(String),
    /// A spawned child process exited nonzero under `vaultx run`.
    /// The exit code is the child's, clamped to 1..=255.
    #[error("child process exited with code {0}")]
    ChildExit(i32),
    /// An underlying application service failed at runtime.
    /// Exit code 1.
    #[error(transparent)]
    Runtime(#[from] CoreError),
    /// A policy pack operation failed (parse, validation, duplicate
    /// capability, missing directory). Exit code 1.
    #[error("{0}")]
    Pack(String),
}

impl CliError {
    /// Process exit code for this error:
    ///
    /// * 1 — runtime or usage failure, merge conflicts, failing
    ///   diagnostics, or policy pack failures,
    /// * 2 — not-yet-implemented command group,
    /// * 3 — target directory is not a vaultx repository,
    /// * 4 — brokered request denied by policy.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Runtime(_)
            | Self::Usage(_)
            | Self::Conflicts(_)
            | Self::Diagnostics(_)
            | Self::Pack(_) => 1,
            Self::Denied(_) => 4,
            Self::NotImplemented(_) => 2,
            Self::NotARepository(_) => 3,
            // The child's own status, clamped so it always fits the
            // process-exit contract (and never reports success).
            Self::ChildExit(code) => (*code).clamp(1, 255),
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

    /// Export committed variables as .env-style lines (plan §33): config
    /// values literally, protected values as inert placeholders unless
    /// the explicit reveal path is taken.
    Export {
        /// Output format (currently only `env`).
        #[arg(long, value_name = "FORMAT", default_value = "env")]
        format: String,
        /// Include decrypted plaintext of plain secrets after typed
        /// confirmation. Brokered credentials always stay placeholders.
        #[arg(long)]
        reveal_secrets: bool,
        /// Non-interactive consent for `--reveal-secrets`; replaces the
        /// typed confirmation when stdin is not a terminal.
        #[arg(long)]
        yes_i_want_plaintext_secrets: bool,
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
    // ---- implemented groups ----
    /// Run a command with committed config values injected as
    /// environment variables (secrets are never decrypted).
    Run {
        /// Environment whose pinned commit supplies the values (default:
        /// development).
        #[arg(long, value_name = "ENV")]
        env: Option<String>,
        /// Permit execution when the resolved variable set is empty.
        #[arg(long)]
        allow_empty: bool,
        /// Command to execute and its arguments, after `--`.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
    },
    /// Local broker process operations.
    Broker {
        #[command(subcommand)]
        command: BrokerCommand,
    },
    /// Manage declarative policy packs.
    Pack {
        #[command(subcommand)]
        command: PackCommand,
    },
    /// MCP server operations.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Audit repository integrity and optionally repair severed refs
    /// (plan §Recovery). Never mutates objects.
    Recover {
        /// Delete refs whose target commits are unresolvable, after
        /// listing them and requiring typed confirmation.
        #[arg(long)]
        fix: bool,
        /// Non-interactive consent for `--fix` ref deletion; replaces the
        /// typed confirmation when stdin is not a terminal.
        #[arg(long)]
        yes_delete_unresolvable_refs: bool,
    },
    /// Launch the interactive terminal UI dashboard.
    Tui {
        /// Environment whose pinned commit backs the dashboard (default:
        /// development).
        #[arg(long, value_name = "ENV")]
        env: Option<String>,
        /// Broker endpoint override (probed for agent/audit status lines;
        /// offline brokers degrade the UI instead of failing it).
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
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
    /// Create an agent session and print its capability token once.
    SessionCreate {
        /// Agent bare name owning the session.
        name: String,
        /// Environment the session operates in (default: development).
        #[arg(long, value_name = "ENV")]
        env: Option<String>,
        /// Optional time-to-live in seconds; expired sessions validate
        /// exactly like revoked ones.
        #[arg(long, value_name = "SECS")]
        ttl_secs: Option<u64>,
    },
    /// List an agent's stored sessions (verifier metadata only).
    SessionsList {
        /// Agent bare name.
        name: String,
    },
    /// Revoke one session by exact id (`sess_...`). Revocation is
    /// permanent.
    Revoke {
        /// Full session id to revoke.
        session_id: String,
    },
    /// Run a command in a sanitized brokered environment for one agent
    /// (plan §17).
    ///
    /// A scoped broker session is minted for the agent+environment and
    /// handed to the child only through its environment: committed
    /// config values plus `VAULTX_*` broker/identity metadata are
    /// injected, while every managed variable name (secret, brokered,
    /// dynamic) is stripped from the inherited parent environment. The
    /// child's exit code becomes vaultx's own.
    Run {
        /// Agent bare name owning the broker session.
        name: String,
        /// Environment whose pinned commit supplies config values and
        /// scopes the session (default: development).
        #[arg(long, value_name = "ENV")]
        env: Option<String>,
        /// Optional time-to-live in seconds for the minted broker
        /// session; expired sessions validate like revoked ones.
        #[arg(long, value_name = "SECS")]
        ttl_secs: Option<u64>,
        /// Command to execute and its arguments, after `--`.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "COMMAND"
        )]
        command: Vec<String>,
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

/// `vaultx broker <subcommand>`.
///
/// `serve` runs the local broker process over the plan's Unix-socket /
/// named-pipe endpoint; `status` probes it; `request` performs one
/// brokered exchange as an agent would.
///
/// The `Request` variant is boxed: its many string options dwarf the
/// other variants and clap derives a large struct for it.
#[derive(Subcommand, Debug)]
pub enum BrokerCommand {
    /// Bind the IPC endpoint and serve until Ctrl-C.
    Serve {
        /// Endpoint override (default:
        /// `$XDG_RUNTIME_DIR/vaultx/local/broker.sock` or platform pipe).
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Probe the broker endpoint and print its version.
    Status {
        /// Endpoint override.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Perform one brokered HTTP request through the endpoint.
    Request(Box<BrokerRequestArgs>),
}

/// Flag bundle behind `vaultx broker request` (boxed in
/// [`BrokerCommand`] to keep the enum small).
#[derive(Args, Debug)]
pub struct BrokerRequestArgs {
    /// Raw capability token printed by `agent session create`, or `-`
    /// to read it from stdin (recommended: argv values land in shell
    /// history and process listings).
    #[arg(long)]
    session: String,
    /// Logical credential reference to resolve.
    #[arg(long)]
    credential: String,
    /// Outbound HTTP method.
    #[arg(long, default_value = "GET")]
    method: String,
    /// Destination URL (canonicalized and policy-checked remotely).
    #[arg(long)]
    url: String,
    /// Extra caller headers as NAME=VALUE (repeatable). Sensitive
    /// names are stripped by the broker regardless.
    #[arg(long = "header", value_name = "NAME=VALUE")]
    headers: Vec<String>,
    /// UTF-8 request body.
    #[arg(long, conflicts_with_all = ["data_binary", "data_base64"])]
    data: Option<String>,
    /// Raw request body read from @FILE.
    #[arg(long, value_name = "@FILE", conflicts_with_all = ["data", "data_base64"])]
    data_binary: Option<String>,
    /// Base64-encoded request body.
    #[arg(long, conflicts_with_all = ["data", "data_binary"])]
    data_base64: Option<String>,
    /// Informational capability name (never used for authorization).
    #[arg(long)]
    capability_hint: Option<String>,
    /// Endpoint override.
    #[arg(long, value_name = "PATH")]
    socket: Option<PathBuf>,
}

/// `vaultx pack <subcommand>`.
///
/// All commands operate on a directory of pack YAML files (default:
/// `<project>/policy-packs`) and never require an initialized vaultx
/// repository — packs are plain files usable before `vaultx init`.
#[derive(Subcommand, Debug)]
pub enum PackCommand {
    /// List packs as NAME / PROVIDER / INJECTION / HOSTS columns.
    List {
        /// Directory to scan instead of `<project>/policy-packs`.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
    /// Render one parsed pack, selected by capability name.
    Inspect {
        /// Capability name, e.g. `github.pull_request.create`.
        name: String,
        /// Directory to scan instead of `<project>/policy-packs`.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
    /// Parse, validate, and compile every pack; per-file report, nonzero
    /// exit on any failure.
    Validate {
        /// Directory to scan instead of `<project>/policy-packs`.
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
    /// Validate FILE and copy it into the pack tree as
    /// `<provider>/<capability-last-segment>.yaml`.
    Add {
        /// Pack file to install.
        file: PathBuf,
        /// Pack tree root (default: `<project>/policy-packs`).
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
        /// Overwrite an existing pack file with the same target path.
        #[arg(long)]
        force: bool,
    },
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

/// `vaultx mcp <subcommand>`.
#[derive(Subcommand, Debug)]
pub enum McpCommand {
    /// Serve MCP tools over stdio JSON-RPC for one agent.
    ///
    /// A broker session is minted at startup (its token is held in
    /// memory only); the process answers `initialize`, `tools/list`, and
    /// `tools/call` until stdin closes.
    Serve {
        /// Agent bare name whose session backs every tool call.
        #[arg(long)]
        agent: String,
        /// Environment the session operates in (default: development).
        #[arg(long, value_name = "ENV")]
        env: Option<String>,
        /// Broker endpoint override.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
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
        Command::Export {
            format,
            reveal_secrets,
            yes_i_want_plaintext_secrets,
        } => with_open(&cli.project, |s| {
            cmd_export(s, format, *reveal_secrets, *yes_i_want_plaintext_secrets)
        }),
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
            AgentCommand::SessionCreate {
                name,
                env,
                ttl_secs,
            } => with_open(&cli.project, |s| {
                cmd_agent_session_create(s, name, env.as_deref(), *ttl_secs)
            }),
            AgentCommand::SessionsList { name } => {
                with_open(&cli.project, |s| cmd_agent_sessions_list(s, name))
            }
            AgentCommand::Revoke { session_id } => {
                with_open(&cli.project, |s| cmd_agent_session_revoke(s, session_id))
            }
            AgentCommand::Run {
                name,
                env,
                ttl_secs,
                command,
            } => with_open(&cli.project, |s| {
                cmd_agent_run(s, name, env.as_deref(), *ttl_secs, command)
            }),
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
        Command::Doctor => with_open(&cli.project, |s| cmd_doctor(&cli.project, s)),
        Command::Recover {
            fix,
            yes_delete_unresolvable_refs,
        } => with_open(&cli.project, |s| {
            cmd_recover(s, *fix, *yes_delete_unresolvable_refs)
        }),
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

        // Trusted workload execution (plan §16).
        Command::Run {
            env,
            allow_empty,
            command,
        } => with_open(&cli.project, |s| {
            cmd_run(s, env.as_deref(), *allow_empty, command)
        }),
        Command::Broker { command } => match command {
            BrokerCommand::Serve { socket } => {
                let services = VaultxServices::open(&cli.project).map_err(|err| match err {
                    CoreError::NotARepository(path) => CliError::NotARepository(path),
                    other => other.into(),
                })?;
                cmd_broker_serve(services, socket.as_deref())
            }
            BrokerCommand::Status { socket } => cmd_broker_status(&cli.project, socket.as_deref()),
            BrokerCommand::Request(args) => cmd_broker_request(
                &cli.project,
                args.socket.as_deref(),
                &args.session,
                &args.credential,
                &args.method,
                &args.url,
                &args.headers,
                args.data.as_deref(),
                args.data_binary.as_deref(),
                args.data_base64.as_deref(),
                args.capability_hint.as_deref(),
            ),
        },
        Command::Pack { command } => match command {
            PackCommand::List { dir } => cmd_pack_list(&resolve_pack_dir(&cli.project, dir)),
            PackCommand::Inspect { name, dir } => {
                cmd_pack_inspect(&resolve_pack_dir(&cli.project, dir), name)
            }
            PackCommand::Validate { dir } => {
                cmd_pack_validate(&resolve_pack_dir(&cli.project, dir))
            }
            PackCommand::Add { file, dir, force } => {
                cmd_pack_add(&resolve_pack_dir(&cli.project, dir), file, *force)
            }
        },
        Command::Mcp { command } => match command {
            McpCommand::Serve { agent, env, socket } => {
                cmd_mcp_serve(&cli.project, agent, env.as_deref(), socket.as_deref())
            }
        },
        Command::Tui { env, socket } => cmd_tui(&cli.project, env.as_deref(), socket.as_deref()),
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

/// Resolves the pack tree root: an explicit `--dir` wins, otherwise
/// `<project>/policy-packs`.
fn resolve_pack_dir(project: &Path, dir: &Option<PathBuf>) -> PathBuf {
    dir.clone()
        .unwrap_or_else(|| project.join(DEFAULT_PACKS_DIR))
}

/// Maps a directory-scan failure onto a CLI error, giving a missing pack
/// directory its own friendly message.
fn map_dir_error(dir: &Path, err: vaultx_policy_packs::PackError) -> CliError {
    match err {
        vaultx_policy_packs::PackError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
            CliError::Pack(format!(
                "policy pack directory {} does not exist",
                dir.display()
            ))
        }
        other => CliError::Pack(other.to_string()),
    }
}

fn cmd_pack_list(dir: &Path) -> Result<String, CliError> {
    let packs = vaultx_policy_packs::load_pack_dir(dir).map_err(|err| map_dir_error(dir, err))?;
    if packs.is_empty() {
        return Ok("no policy packs found".to_owned());
    }
    let rows: Vec<Vec<String>> = packs
        .iter()
        .map(|pack| {
            vec![
                pack.name.clone(),
                pack.provider.to_string(),
                crate::output::injection_label(pack.credential.injection).to_owned(),
                pack.request.hosts.len().to_string(),
            ]
        })
        .collect();
    Ok(crate::output::render_table(
        &["NAME", "PROVIDER", "INJECTION", "HOSTS"],
        &rows,
    ))
}

/// Renders one pack by capability name. Broken sibling packs are skipped,
/// never fatal: only the target file's own failure (or its absence)
/// produces an error.
fn cmd_pack_inspect(dir: &Path, name: &str) -> Result<String, CliError> {
    let files = vaultx_policy_packs::pack_files(dir).map_err(|err| map_dir_error(dir, err))?;
    let mut first_broken: Option<(PathBuf, vaultx_policy_packs::PackError)> = None;
    for file in files {
        match vaultx_policy_packs::load_pack(&file) {
            Ok(pack) if pack.name == name => {
                return Ok(crate::output::render_pack_inspect(&pack));
            }
            Ok(_) => {}
            Err(err) => {
                first_broken.get_or_insert((file, err));
            }
        }
    }
    Err(match first_broken {
        Some((file, err)) => CliError::Pack(format!("{}: {err}", file.display())),
        None => CliError::Pack(format!(
            "no policy pack named `{name}` in {}",
            dir.display()
        )),
    })
}

fn cmd_pack_validate(dir: &Path) -> Result<String, CliError> {
    let files = vaultx_policy_packs::pack_files(dir).map_err(|err| map_dir_error(dir, err))?;
    if files.is_empty() {
        return Ok("no policy packs found".to_owned());
    }
    let mut lines = Vec::with_capacity(files.len());
    let mut failures = 0;
    for file in &files {
        match vaultx_policy_packs::load_pack(file)
            .and_then(|pack| vaultx_policy_packs::compile(&pack).map(|_| pack))
        {
            Ok(pack) => lines.push(format!("{}: ok ({})", file.display(), pack.name)),
            Err(err) => {
                failures += 1;
                lines.push(format!("{}: ERROR {}", file.display(), err));
            }
        }
    }
    let report = lines.join("\n");
    if failures > 0 {
        return Err(CliError::Pack(report));
    }
    Ok(report)
}

fn cmd_pack_add(dir: &Path, file: &Path, force: bool) -> Result<String, CliError> {
    // Validate (and compile, exercising every invariant gate) before
    // touching the destination.
    let pack =
        vaultx_policy_packs::load_pack(file).map_err(|err| CliError::Pack(err.to_string()))?;
    vaultx_policy_packs::compile(&pack).map_err(|err| CliError::Pack(err.to_string()))?;

    let capability_last_segment = pack.name.rsplit('.').next().unwrap_or_default();
    if capability_last_segment.is_empty() {
        return Err(CliError::Pack(format!(
            "capability name `{}` has no usable final segment",
            pack.name
        )));
    }
    let target = dir
        .join(pack.provider.as_str())
        .join(format!("{capability_last_segment}.yaml"));
    if target.exists() {
        let existing = vaultx_policy_packs::load_pack(&target).ok();
        match (existing.as_ref(), force) {
            (Some(_), false) => {
                return Err(CliError::Usage(format!(
                    "{} already exists; pass --force to overwrite",
                    target.display()
                )));
            }
            // --force may replace the same capability's bytes, but it can
            // never silently swap one capability for another that happens
            // to share the derived filename.
            (Some(existing), true) if existing.name != pack.name => {
                return Err(CliError::Usage(format!(
                    "{} holds capability `{}`; refusing to replace it with `{}` even under \
                     --force",
                    target.display(),
                    existing.name,
                    pack.name
                )));
            }
            _ => {}
        }
    }
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| CliError::Pack(format!("cannot create {}: {err}", parent.display())))?;
    }
    std::fs::copy(file, &target)
        .map_err(|err| CliError::Pack(format!("cannot copy into {}: {err}", target.display())))?;
    Ok(format!("added {} -> {}", pack.name, target.display()))
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

/// Executes `COMMAND` (plan §16) with committed config values from the
/// environment's pinned commit injected as extra environment variables.
///
/// Secrets, brokered credentials, and dynamic providers are skipped
/// entirely — they are never decrypted into a child environment. The
/// child inherits the parent environment; its exit status becomes the
/// dispatch outcome: zero prints nothing extra, nonzero maps onto
/// [`CliError::ChildExit`].
fn cmd_run(
    services: &VaultxServices,
    env: Option<&str>,
    allow_empty: bool,
    command: &[String],
) -> Result<String, CliError> {
    let bare = env.unwrap_or(DEFAULT_SECRET_ENV);
    let summary = services
        .environments()
        .list_environments()?
        .into_iter()
        .find(|candidate| candidate.name == bare)
        .ok_or_else(|| CliError::Usage(format!("unknown environment `{bare}`")))?;
    let Some(commit) = summary.commit else {
        return Err(CliError::Usage(format!(
            "environment `{bare}` has no pinned commit"
        )));
    };
    let values = services.history().committed_config_values(&commit)?;
    if values.is_empty() && !allow_empty {
        return Err(CliError::Usage(format!(
            "environment `{bare}` resolves no config variables; pass --allow-empty to run anyway"
        )));
    }
    let (program, args) = command
        .split_first()
        .ok_or_else(|| CliError::Usage("run requires a command after `--`".into()))?;

    let mut child = std::process::Command::new(program);
    child.args(args);
    for (name, value) in values {
        child.env(name, value);
    }
    let status = child.status().map_err(|err| {
        CliError::Runtime(CoreError::Io(std::io::Error::other(format!(
            "cannot execute {program}: {err}"
        ))))
    })?;
    match status.code() {
        Some(0) => Ok(String::new()),
        Some(code) => Err(CliError::ChildExit(code)),
        // Killed by a signal (unix): report the conventional 128+N code.
        #[cfg(unix)]
        None => {
            use std::os::unix::process::ExitStatusExt as _;
            let signal = status.signal().unwrap_or(0);
            Err(CliError::ChildExit(128 + signal))
        }
        // No exit-code concept on this platform; fall back to failure.
        #[cfg(not(unix))]
        None => Err(CliError::ChildExit(1)),
    }
}

/// Broker probe timeout; a wedged broker must not stall diagnostics.
const BROKER_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Async core of the broker connectivity probe (kept separate so tests
/// can drive it on their own runtime).
async fn probe_broker_async(endpoint: PathBuf) -> vaultx_core::BrokerProbe {
    let attempt = async {
        let mut client = vaultx_broker_client::BrokerClient::connect(&endpoint)
            .await
            .map_err(|err| err.to_string())?;
        client.ping().await.map_err(|err| err.to_string())
    };
    match tokio::time::timeout(BROKER_PROBE_TIMEOUT, attempt).await {
        Ok(Ok(version)) => vaultx_core::BrokerProbe::Reachable { version },
        Ok(Err(reason)) => vaultx_core::BrokerProbe::Unreachable { reason },
        Err(_) => vaultx_core::BrokerProbe::Unreachable {
            reason: "timed out".to_owned(),
        },
    }
}

/// One-shot lightweight IPC handshake against `endpoint`.
fn broker_probe(endpoint: &Path) -> vaultx_core::BrokerProbe {
    run_async(probe_broker_async(endpoint.to_path_buf()))
}

fn cmd_doctor(project: &Path, services: &VaultxServices) -> Result<String, CliError> {
    use vaultx_core::CheckStatus;
    let endpoint = resolve_endpoint(project, None);
    let probe = broker_probe(&endpoint);
    let outcomes = services
        .doctor()
        .with_broker_probe(endpoint.display().to_string(), probe)
        .run();
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

/// Typed confirmation phrase required before plaintext secret export.
pub(crate) const REVEAL_CONFIRMATION_PHRASE: &str = "REVEAL";
/// Typed confirmation phrase required before deleting unresolvable refs.
pub(crate) const DELETE_REFS_CONFIRMATION_PHRASE: &str = "DELETE";

/// Trimmed exact match (case-sensitive) comparison of a typed
/// confirmation line.
#[must_use]
pub(crate) fn typed_confirmation_matches(typed: &str, phrase: &str) -> bool {
    typed.trim() == phrase
}

/// High-friction authorization gate shared by every disclosure or
/// destructive path: interactive terminals must type an explicit phrase;
/// non-interactive callers must pass the dedicated consent flag.
///
/// The prompt goes to stderr because stdout carries command output.
fn authorize_high_friction_action(
    description: &str,
    phrase: &str,
    non_interactive_consent: bool,
    consent_flag: &str,
) -> Result<(), CliError> {
    use std::io::IsTerminal as _;
    if !std::io::stdin().is_terminal() {
        return if non_interactive_consent {
            Ok(())
        } else {
            Err(CliError::Usage(format!(
                "{description} requires explicit authorization; on a non-interactive terminal \
                 pass {consent_flag} to accept"
            )))
        };
    }
    eprintln!("WARNING: this action is high-friction by design.");
    eprintln!("{description}");
    eprintln!("Type {phrase} to confirm:");
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|err| CliError::Usage(format!("cannot read confirmation: {err}")))?;
    if typed_confirmation_matches(&line, phrase) {
        Ok(())
    } else {
        Err(CliError::Usage(
            "confirmation phrase did not match; action refused".into(),
        ))
    }
}

/// Plan §33 export over the HEAD manifest. Safe mode renders config
/// values literally and everything protected as placeholders; the reveal
/// path additionally decrypts plain secrets but never brokered
/// credentials.
fn cmd_export(
    services: &VaultxServices,
    format: &str,
    reveal_secrets: bool,
    yes_i_want_plaintext_secrets: bool,
) -> Result<String, CliError> {
    if format != "env" {
        return Err(CliError::Usage(format!(
            "unsupported export format `{format}` (only `env`)"
        )));
    }
    if reveal_secrets {
        authorize_high_friction_action(
            "Exporting plaintext secret values. Anyone with access to this output gains the \
             real credentials.",
            REVEAL_CONFIRMATION_PHRASE,
            yes_i_want_plaintext_secrets,
            "--yes-i-want-plaintext-secrets",
        )?;
    }
    let entries = services.export().export(reveal_secrets)?;
    if entries.is_empty() {
        return Ok("nothing committed to export".to_owned());
    }
    Ok(entries
        .iter()
        .map(vaultx_core::render_export_entry)
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Plan §Recovery audit; `--fix` deletes listed unresolvable refs only
/// after confirmation and never touches objects.
fn cmd_recover(
    services: &VaultxServices,
    fix: bool,
    yes_delete_unresolvable_refs: bool,
) -> Result<String, CliError> {
    let mut report = services.recovery().audit()?;
    let mut removed = 0usize;
    let mut skipped = 0usize;
    if fix && !report.unresolvable_refs.is_empty() {
        let listing = report
            .unresolvable_refs
            .iter()
            .map(|r| format!("{}/{} -> {}", r.namespace.label(), r.name, r.commit))
            .collect::<Vec<_>>()
            .join(", ");
        authorize_high_friction_action(
            &format!(
                "Deleting {count} unresolvable ref(s): {listing}. History objects are never \
                 modified.",
                count = report.unresolvable_refs.len()
            ),
            DELETE_REFS_CONFIRMATION_PHRASE,
            yes_delete_unresolvable_refs,
            "--yes-delete-unresolvable-refs",
        )?;
        let targets = std::mem::take(&mut report.unresolvable_refs);
        let outcome = services.recovery().fix_unresolvable_refs(&targets)?;
        removed = outcome.removed;
        skipped = outcome.skipped;
    }
    // Re-audit after repairs so the verdict reflects post-fix state.
    if removed > 0 {
        report = services.recovery().audit()?;
    }
    let rendered = crate::output::render_recovery_report(&report, removed, skipped);
    if report.is_clean() {
        Ok(rendered)
    } else {
        Err(CliError::Diagnostics(rendered))
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

fn map_session_error(err: vaultx_broker::BrokerError) -> CliError {
    CliError::Runtime(CoreError::Io(std::io::Error::other(err.to_string())))
}

/// Opens (creating if needed) the persistent session store under
/// `<project>/.vaultx/sessions.json`.
fn open_session_store(
    services: &VaultxServices,
) -> Result<vaultx_broker::FileSessionStore, CliError> {
    let path = services.context().vault_dir().join("sessions.json");
    vaultx_broker::FileSessionStore::open(path)
        .map_err(|err| CliError::Runtime(CoreError::Io(std::io::Error::other(err.to_string()))))
}

fn environment_id_for(
    bare: Option<&str>,
) -> Result<(String, vaultx_types::EnvironmentId), CliError> {
    let bare = bare.unwrap_or(DEFAULT_SECRET_ENV);
    let id = vaultx_types::EnvironmentId::parse(&format!("env_{bare}"))
        .map_err(|_| CliError::Usage(format!("`{bare}` is not a valid environment name")))?;
    Ok((bare.to_owned(), id))
}

#[allow(clippy::type_complexity)]
fn cmd_agent_session_create(
    services: &VaultxServices,
    name: &str,
    env: Option<&str>,
    ttl_secs: Option<u64>,
) -> Result<String, CliError> {
    // Refuse sessions for unknown or disabled agents before minting a
    // token the broker would immediately reject.
    let summary = services
        .agents()
        .list_agents()?
        .into_iter()
        .find(|agent| agent.name == name)
        .ok_or_else(|| CliError::Usage(format!("unknown agent `{name}`")))?;
    if !summary.enabled {
        return Err(CliError::Usage(format!(
            "agent `{name}` is disabled; enable it before creating sessions"
        )));
    }
    let agent_id = services.agents().inspect(name)?;

    let store = open_session_store(services)?;
    let (env_name, environment) = environment_id_for(env)?;
    let (session_id, raw_token) = store
        .create_expiring(&agent_id.name, &environment, ttl_secs)
        .map_err(map_session_error)?;

    let expiry_note = match ttl_secs {
        Some(secs) => format!("expires in {secs}s"),
        None => "no expiry".to_owned(),
    };
    Ok(format!(
        "created session {session_id} for {name} in {env_name} ({expiry_note})\n\nCAPABILITY TOKEN (shown once; it cannot be recovered):\n{raw_token}"
    ))
}

fn cmd_agent_sessions_list(services: &VaultxServices, name: &str) -> Result<String, CliError> {
    // Existence check first so the failure names the agent, not a bare
    // "no such file" from the identity store.
    let _ = services
        .agents()
        .list_agents()?
        .into_iter()
        .find(|agent| agent.name == name)
        .ok_or_else(|| CliError::Usage(format!("unknown agent `{name}`")))?;
    let agent_id = services.agents().inspect(name)?;

    let records = open_session_store(services)?
        .list_for_agent(&agent_id.name)
        .map_err(map_session_error)?;
    if records.is_empty() {
        return Ok(format!("no sessions for {name}"));
    }
    Ok(crate::output::render_sessions(name, &records))
}

fn cmd_agent_session_revoke(
    services: &VaultxServices,
    session_id: &str,
) -> Result<String, CliError> {
    let id = vaultx_types::SessionId::parse(session_id)
        .map_err(|_| CliError::Usage("expected a full session id (`sess_...`)".into()))?;
    open_session_store(services)?
        .revoke(&id)
        .map_err(|err| match err {
            vaultx_broker::BrokerError::InvalidSession => {
                CliError::Usage(format!("no such session `{session_id}`"))
            }
            other => CliError::Runtime(CoreError::Io(std::io::Error::other(other.to_string()))),
        })?;
    Ok(format!("revoked {id}"))
}

/// Project id every local service binds to; mirrors
/// `broker_source::build_production_engine`.
const LOCAL_PROJECT_ID: &str = "proj_local";

/// Executes `COMMAND` for one agent inside a sanitized brokered
/// environment (plan §17).
///
/// The child receives, through its environment only:
///
/// * committed plain config values of the environment's pinned commit
///   (same resolution as [`cmd_run`]; secrets and brokered credentials
///   are never materialized),
/// * `VAULTX_BROKER_ENDPOINT`, `VAULTX_BROKER_SESSION` (the raw
///   capability token), and agent/project/environment identity vars.
///
/// Every managed variable name in the pinned manifest is scrubbed from
/// the inherited parent environment regardless of kind — by-construction
/// via `env_clear`, so a polluted parent value can never survive. No
/// plaintext `.env` file is written. The child's exit status maps onto
/// dispatch exactly like [`cmd_run`] does.
fn cmd_agent_run(
    services: &VaultxServices,
    name: &str,
    env: Option<&str>,
    ttl_secs: Option<u64>,
    command: &[String],
) -> Result<String, CliError> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| CliError::Usage("agent run requires a command after `--`".into()))?;

    // Refuse unknown or disabled agents before minting any session
    // material (same gate as `agent session create`).
    let summary = services
        .agents()
        .list_agents()?
        .into_iter()
        .find(|agent| agent.name == name)
        .ok_or_else(|| CliError::Usage(format!("unknown agent `{name}`")))?;
    if !summary.enabled {
        return Err(CliError::Usage(format!(
            "agent `{name}` is disabled; enable it before creating sessions"
        )));
    }
    let agent_id = services.agents().inspect(name)?;

    let bare_env = env.unwrap_or(DEFAULT_SECRET_ENV);
    let pinned = services
        .environments()
        .list_environments()?
        .into_iter()
        .find(|candidate| candidate.name == bare_env)
        .ok_or_else(|| CliError::Runtime(CoreError::EnvironmentNotFound(bare_env.to_owned())))?;
    let Some(commit) = pinned.commit else {
        return Err(CliError::Usage(format!(
            "environment `{bare_env}` has no pinned commit"
        )));
    };
    let config_values = services.history().committed_config_values(&commit)?;
    // Every managed name in the pinned manifest is scrubbed from the
    // inherited environment, whatever kind it carries.
    let managed_names: std::collections::HashSet<String> = services
        .history()
        .show(&commit)?
        .entries
        .into_iter()
        .map(|entry| entry.name)
        .collect();

    // Scoped session through the same store as `agent session create`.
    let (_, environment_id) = environment_id_for(env)?;
    let (_session_id, raw_token) = open_session_store(services)?
        .create_expiring(&agent_id.name, &environment_id, ttl_secs)
        .map_err(map_session_error)?;

    // Child environment assembled fully in memory; nothing touches disk.
    let mut child_env: std::collections::HashMap<std::ffi::OsString, std::ffi::OsString> =
        std::env::vars_os()
            .filter(|(key, _)| !managed_names.contains(key.to_string_lossy().as_ref()))
            .collect();
    for (name, value) in config_values {
        child_env.insert(name.into(), value.into());
    }
    child_env.insert(
        "VAULTX_BROKER_ENDPOINT".into(),
        vaultx_broker_client::default_endpoint().into(),
    );
    child_env.insert("VAULTX_BROKER_SESSION".into(), raw_token.into());
    child_env.insert("VAULTX_AGENT".into(), name.into());
    child_env.insert("VAULTX_PROJECT".into(), LOCAL_PROJECT_ID.into());
    child_env.insert("VAULTX_ENVIRONMENT".into(), bare_env.into());

    // Exact-by-construction inheritance: env_clear + insert so no
    // managed name from the parent can leak through the OS default.
    let mut child = std::process::Command::new(program);
    child.args(args).env_clear();
    for (key, value) in &child_env {
        child.env(key, value);
    }
    let status = child.status().map_err(|err| {
        CliError::Runtime(CoreError::Io(std::io::Error::other(format!(
            "cannot execute {program}: {err}"
        ))))
    })?;
    match status.code() {
        Some(0) => Ok(String::new()),
        Some(code) => Err(CliError::ChildExit(code)),
        // Killed by a signal (unix): report the conventional 128+N code.
        #[cfg(unix)]
        None => {
            use std::os::unix::process::ExitStatusExt as _;
            let signal = status.signal().unwrap_or(0);
            Err(CliError::ChildExit(128 + signal))
        }
        // No exit-code concept on this platform; fall back to failure.
        #[cfg(not(unix))]
        None => Err(CliError::ChildExit(1)),
    }
}

/// Runs `future` to completion on a private multi-thread runtime. The
/// CLI is otherwise synchronous; only broker process operations need a
/// reactor.
fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(future)
}

/// Consumes the facade so the engine can share one [`ProjectContext`]
/// behind an `Arc` across threads.
fn cmd_broker_serve(services: VaultxServices, socket: Option<&Path>) -> Result<String, CliError> {
    let ctx = std::sync::Arc::new(services.into_context());
    let engine = vaultx_core::broker_source::build_production_engine(&ctx)
        .map_err(|err| CliError::Runtime(CoreError::Io(std::io::Error::other(err.to_string()))))?;

    // Bind inside the runtime: tokio listener construction requires a
    // reactor context.
    let socket_path = socket.map(Path::to_path_buf);
    let outcome = run_async(async move {
        let server = vaultx_broker::BrokerServer::bind(
            std::sync::Arc::new(engine),
            "local",
            vaultx_broker::ServerConfig {
                socket_path,
                max_connections: 0,
            },
        )
        .map_err(|err| CliError::Runtime(CoreError::Io(std::io::Error::other(err.to_string()))))?;
        println!("vaultx broker listening on {}", server.path().display());
        // The trigger must outlive the server: `serve` consumes it, so
        // capture the sender clone first or Ctrl-C could never fire.
        let trigger = server.shutdown_trigger();
        // Run the accept loop on the blocking pool: the engine (and its
        // transport's owned runtime) must DROP off the async reactor,
        // which forbids dropping runtimes in place.
        let reactor = tokio::runtime::Handle::current();
        let serve = tokio::task::spawn_blocking(move || reactor.block_on(server.serve()));
        // Graceful exit on both interactive stop (SIGINT) and service
        // manager stop (SIGTERM): the socket file is unlinked by
        // `serve`, so a killed-but-not-shutdown broker must not leave a
        // stale endpoint behind.
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate())
                .map_err(|err| CliError::Runtime(CoreError::Io(err)))?;
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        trigger();
        eprintln!("vaultx broker shutting down");
        match serve.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(CliError::Runtime(CoreError::Io(std::io::Error::other(
                err.to_string(),
            )))),
            Err(join) => Err(CliError::Runtime(CoreError::Io(std::io::Error::other(
                join.to_string(),
            )))),
        }
    });
    outcome?;
    Ok("stopped".to_owned())
}

/// Serves the MCP stdio server (plan §26). The project is opened first
/// so a bad directory maps onto the exit-3 class; everything else is
/// delegated to `vaultx-mcp`, which owns its own runtime needs.
fn cmd_mcp_serve(
    project: &Path,
    agent: &str,
    env: Option<&str>,
    socket: Option<&Path>,
) -> Result<String, CliError> {
    VaultxServices::open(project).map_err(|err| match err {
        CoreError::NotARepository(path) => CliError::NotARepository(path),
        other => other.into(),
    })?;
    let config = vaultx_mcp::ServeConfig {
        project: project.to_path_buf(),
        agent: agent.to_owned(),
        env: env.map(str::to_owned),
        socket: socket.map(Path::to_path_buf),
    };
    run_async(vaultx_mcp::serve(config))
        .map_err(|err| CliError::Runtime(CoreError::Io(std::io::Error::other(err.to_string()))))?;
    Ok(String::new())
}

/// Launches the interactive TUI (plan §15/§38). The project is opened
/// here so a bad directory maps onto the exit-3 class, and the opened
/// services are handed to the UI instead of being reopened inside it.
fn cmd_tui(project: &Path, env: Option<&str>, socket: Option<&Path>) -> Result<String, CliError> {
    let services = VaultxServices::open(project).map_err(|err| match err {
        CoreError::NotARepository(path) => CliError::NotARepository(path),
        other => other.into(),
    })?;
    vaultx_tui::run(&vaultx_tui::TuiConfig {
        services: std::sync::Arc::new(services),
        env: env.map(str::to_owned),
        socket: socket.map(Path::to_path_buf),
    })
    .map_err(|err| CliError::Runtime(CoreError::Io(std::io::Error::other(err.to_string()))))?;
    Ok(String::new())
}

fn resolve_endpoint(_project: &Path, socket: Option<&Path>) -> PathBuf {
    match socket {
        Some(path) => path.to_path_buf(),
        None => PathBuf::from(vaultx_broker_client::default_endpoint()),
    }
}

fn map_client_error(err: vaultx_broker_client::ClientError) -> CliError {
    let text = err.to_string();
    CliError::Runtime(CoreError::Io(std::io::Error::other(text)))
}

fn cmd_broker_status(project: &Path, socket: Option<&Path>) -> Result<String, CliError> {
    let _ = project;
    let endpoint = resolve_endpoint(project, socket);
    let shown = endpoint.display().to_string();
    run_async(async move {
        let mut client = vaultx_broker_client::BrokerClient::connect(&endpoint)
            .await
            .map_err(map_client_error)?;
        client.ping().await.map_err(map_client_error)
    })
    .map(|version| format!("broker reachable at {shown} (version {version})"))
}

#[allow(clippy::too_many_arguments)]
fn cmd_broker_request(
    project: &Path,
    socket: Option<&Path>,
    session_token: &str,
    credential: &str,
    method: &str,
    url: &str,
    headers: &[String],
    data: Option<&str>,
    data_binary: Option<&str>,
    data_base64: Option<&str>,
    capability_hint: Option<&str>,
) -> Result<String, CliError> {
    use base64::Engine as _;
    let endpoint = resolve_endpoint(project, socket);

    let session_token = match session_token {
        "-" => {
            use std::io::Read as _;
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(|err| CliError::Usage(format!("cannot read session token: {err}")))?;
            let trimmed = buf
                .strip_suffix("\r\n")
                .or_else(|| buf.strip_suffix('\n'))
                .unwrap_or(&buf);
            trimmed.to_owned()
        }
        other => other.to_owned(),
    };

    let http_method = parse_http_method(method)?;
    let parsed_credential = CredentialRef::parse(credential)
        .map_err(|_| CliError::Usage(format!("invalid credential ref `{credential}`")))?;

    let mut header_pairs = Vec::new();
    for raw in headers {
        let (name, value) = raw
            .split_once('=')
            .ok_or_else(|| CliError::Usage(format!("expected --header NAME=VALUE, got `{raw}`")))?;
        header_pairs.push((name.to_ascii_lowercase(), value.to_owned()));
    }

    let body = match (data, data_binary, data_base64) {
        (Some(text), _, _) => vaultx_broker::BrokerBody::Bytes {
            data: text.as_bytes().to_vec(),
        },
        (_, Some(at_file), _) => {
            let path = at_file
                .strip_prefix('@')
                .ok_or_else(|| CliError::Usage("--data-binary expects @FILE".into()))?;
            std::fs::read(path)
                .map(|data| vaultx_broker::BrokerBody::Bytes { data })
                .map_err(|err| CliError::Runtime(CoreError::Io(err)))?
        }
        (_, _, Some(encoded)) => vaultx_broker::BrokerBody::Bytes {
            data: base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| CliError::Usage("--data-base64 expects valid base64".into()))?,
        },
        _ => vaultx_broker::BrokerBody::None,
    };

    let request = vaultx_broker::BrokerRequest {
        protocol: vaultx_broker::PROTOCOL_VERSION,
        // The token crosses the wire once; it never enters diagnostics.
        session_token: session_token.to_owned(),
        credential: parsed_credential,
        method: http_method,
        url: url.to_owned(),
        headers: header_pairs,
        body,
        capability_hint: capability_hint.map(str::to_owned),
    };

    let response = run_async(async move {
        let mut client = vaultx_broker_client::BrokerClient::connect(&endpoint)
            .await
            .map_err(map_client_error)?;
        client.request(request).await.map_err(map_client_error)
    })?;

    match response.decision {
        vaultx_broker::Decision::Allow => Ok(crate::output::render_broker_response(&response)),
        vaultx_broker::Decision::Deny { reason, policy } => Err(CliError::Denied(match policy {
            Some(name) => format!("{reason} (policy: {name})"),
            None => reason,
        })),
    }
}

/// Parses the `--method` flag against the policy layer's verb set so
/// unsupported methods fail before any I/O starts.
fn parse_http_method(raw: &str) -> Result<vaultx_policy::HttpMethod, CliError> {
    use vaultx_policy::HttpMethod;
    match raw.to_ascii_uppercase().as_str() {
        "GET" => Ok(HttpMethod::GET),
        "POST" => Ok(HttpMethod::POST),
        "PUT" => Ok(HttpMethod::PUT),
        "PATCH" => Ok(HttpMethod::PATCH),
        "DELETE" => Ok(HttpMethod::DELETE),
        "HEAD" => Ok(HttpMethod::HEAD),
        "OPTIONS" => Ok(HttpMethod::OPTIONS),
        other => Err(CliError::Usage(format!(
            "`{other}` is not a supported HTTP method"
        ))),
    }
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
