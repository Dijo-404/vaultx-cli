//! Integration-style tests driving [`dispatch`] directly with
//! constructed [`Cli`] values against real temporary projects. No
//! processes are spawned: handlers are pure parse+present functions over
//! core services, so output strings and error variants can be asserted
//! without stdio.

use std::path::{Path, PathBuf};

use vaultx_core::CoreError;
use vaultx_types::CommitId;

use crate::{
    dispatch, AgentCommand, Cli, CliError, Command, EnvCommand, PolicyCommand, SecretCommand,
    StubArgs,
};

/// Builds a `Cli` pointing at `project` with the given command.
fn cli(project: &Path, command: Command) -> Cli {
    Cli {
        project: project.to_path_buf(),
        verbose: 0,
        command,
    }
}

fn init_in(root: &Path) {
    dispatch(&cli(root, Command::Init)).expect("init succeeds");
}

#[test]
fn init_creates_repo_and_open_commands_then_succeed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let out = dispatch(&cli(root, Command::Init)).unwrap();
    assert!(out.contains("initialized"), "got: {out}");
    assert!(root.join(".vaultx").is_dir());

    // Open-based commands succeed right after init.
    let status = dispatch(&cli(root, Command::Status)).unwrap();
    assert!(status.contains("branch:"), "got: {status}");

    // Re-init is a runtime failure (exit 1), not a crash.
    match dispatch(&cli(root, Command::Init)) {
        Err(CliError::Runtime(CoreError::AlreadyInitialized(_))) => {}
        other => panic!("expected AlreadyInitialized, got {other:?}"),
    }

    // Outside a repository maps onto the exit-3 class.
    let empty = tempfile::tempdir().unwrap();
    let err = dispatch(&cli(empty.path(), Command::Status)).unwrap_err();
    assert!(matches!(err, CliError::NotARepository(_)));
    assert_eq!(err.exit_code(), 3);
}

#[test]
fn set_get_round_trip_and_list_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    // set stages immediately; get resolves through the staged overlay.
    let out = dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["PORT=8080".into()],
        },
    ))
    .unwrap();
    assert_eq!(out, "set PORT");

    let value = dispatch(&cli(
        root,
        Command::Get {
            name: "PORT".into(),
        },
    ))
    .unwrap();
    assert_eq!(value, "8080");

    // list reflects HEAD only: empty before the first commit.
    let listed = dispatch(&cli(root, Command::List)).unwrap();
    assert!(listed.contains("no config variables committed"));

    commit_ok(root, "seed", None);
    let listed = dispatch(&cli(root, Command::List)).unwrap();
    assert!(listed.contains("PORT"));
    assert!(listed.contains("8080"));

    // unset hides the variable from get even though HEAD still binds it.
    dispatch(&cli(
        root,
        Command::Unset {
            names: vec!["PORT".into()],
        },
    ))
    .unwrap();
    match dispatch(&cli(
        root,
        Command::Get {
            name: "PORT".into(),
        },
    )) {
        Err(CliError::Runtime(CoreError::VariableNotFound(name))) => assert_eq!(name, "PORT"),
        other => panic!("expected VariableNotFound, got {other:?}"),
    }
}

#[test]
fn commit_requires_message_then_log_and_prefix_show_work() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["A=1".into()],
        },
    ))
    .unwrap();

    // Missing -m is a usage error (exit 1).
    let err = dispatch(&cli(
        root,
        Command::Commit {
            message: None,
            author: None,
        },
    ))
    .unwrap_err();
    assert!(matches!(err, CliError::Usage(ref text) if text.contains("-m")));
    assert_eq!(err.exit_code(), 1);

    // Default author is "unknown"; the log shows short id + message +
    // author.
    let committed = commit_ok(root, "first", None);
    let log = dispatch(&cli(root, Command::Log { limit: None })).unwrap();
    assert!(log.contains("first"), "log: {log}");
    assert!(log.contains("[unknown]"), "log: {log}");

    // show accepts a unique prefix (hex part only).
    let hex = committed.as_str().strip_prefix("cmt_").unwrap();
    let shown = dispatch(&cli(
        root,
        Command::Show {
            prefix: hex[..12].into(),
        },
    ))
    .unwrap();
    assert!(shown.contains("message: first"), "show: {shown}");
    assert!(shown.contains("A"), "show lists entry A: {shown}");

    // Bad prefixes are usage errors; ambiguous ones list candidates.
    let err = dispatch(&cli(
        root,
        Command::Show {
            prefix: "zzzzzz".into(),
        },
    ))
    .unwrap_err();
    assert!(matches!(err, CliError::Usage(ref text) if text.contains("no commit matches")));
    let _ = dispatch(&cli(
        root,
        Command::Show {
            prefix: String::new(),
        },
    ));

    // Second commit enables a two-commit diff by prefixes.
    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["B=2".into()],
        },
    ))
    .unwrap();
    let second = commit_ok(root, "second", Some("user:alice"));
    let diff = dispatch(&cli(
        root,
        Command::Diff {
            a: Some(hex[..4].into()),
            b: Some(second.as_str()[4..8].to_owned()),
        },
    ))
    .unwrap();
    assert!(diff.contains('B'), "commit diff must mention B: {diff}");

    // Staged diff with no arguments.
    dispatch(&cli(
        root,
        Command::Unset {
            names: vec!["A".into()],
        },
    ))
    .unwrap();
    let staged = dispatch(&cli(root, Command::Diff { a: None, b: None })).unwrap();
    assert!(staged.contains("- config A"), "staged diff: {staged}");

    // Exactly one commit id to diff is rejected.
    let err = dispatch(&cli(
        root,
        Command::Diff {
            a: Some(hex[..6].into()),
            b: None,
        },
    ))
    .unwrap_err();
    assert!(
        matches!(err, CliError::Usage(ref text) if text.contains("exactly two")),
        "got: {err:?}"
    );
}

#[test]
fn import_bom_duplicates_and_missing_file_paths() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    // UTF-8 BOM before the first key, plus an in-file duplicate whose
    // last value wins and is reported once.
    let env_file = root.join("bom.env");
    std::fs::write(&env_file, "\u{feff}FIRST=1\nSECOND=x\nSECOND=y\n").unwrap();
    let out = dispatch(&cli(
        root,
        Command::Import {
            file: env_file.clone(),
        },
    ))
    .unwrap();
    assert!(
        out.contains("imported 2 config value(s)") && out.contains("added: FIRST, SECOND"),
        "got: {out}"
    );
    assert_eq!(
        dispatch(&cli(
            root,
            Command::Get {
                name: "FIRST".into()
            }
        ))
        .unwrap(),
        "1"
    );
    assert_eq!(
        dispatch(&cli(
            root,
            Command::Get {
                name: "SECOND".into()
            }
        ))
        .unwrap(),
        "y"
    );

    // Read failures keep the filename so the operator knows which input
    // was missing.
    let missing = root.join("missing.env");
    let err = dispatch(&cli(
        root,
        Command::Import {
            file: missing.clone(),
        },
    ))
    .unwrap_err();
    assert!(
        err.to_string().contains("cannot read")
            && err
                .to_string()
                .contains(missing.display().to_string().as_str()),
        "error must carry the path, got: {err}"
    );
    assert_eq!(err.exit_code(), 1);
}

#[test]
fn import_file_classification_output() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    let env_file = root.join("fixture.env");
    std::fs::write(
        &env_file,
        "# deployment settings\n\
         PORT=8080\n\
         QUOTED=\"hello world\"\n\
         SINGLE='single value'\n\
         GITHUB_TOKEN=tokens-are-not-stored\n\
         DATABASE_URL=postgres://localhost/app\n\
         BAD NAME=oops\n",
    )
    .unwrap();

    let out = dispatch(&cli(
        root,
        Command::Import {
            file: env_file.clone(),
        },
    ))
    .unwrap();

    assert!(
        out.contains("imported 3 config value(s)"),
        "summary line missing: {out}"
    );
    assert!(out.contains("added: PORT, QUOTED, SINGLE"), "got: {out}");
    assert!(
        out.contains("needs secret (not stored): GITHUB_TOKEN, DATABASE_URL"),
        "secret routing missing: {out}"
    );
    assert!(
        out.contains("skipped invalid names: BAD NAME"),
        "got: {out}"
    );

    // Imported values resolve; secret names were never stored.
    assert_eq!(
        dispatch(&cli(
            root,
            Command::Get {
                name: "QUOTED".into()
            }
        ))
        .unwrap(),
        "hello world"
    );
    let err = dispatch(&cli(
        root,
        Command::Get {
            name: "GITHUB_TOKEN".into(),
        },
    ))
    .unwrap_err();
    assert!(matches!(
        err,
        CliError::Runtime(CoreError::VariableNotFound(_))
    ));

    // Re-import skips what is already bound.
    let again = dispatch(&cli(
        root,
        Command::Import {
            file: env_file.clone(),
        },
    ))
    .unwrap();
    assert!(
        again.contains("skipped already bound: PORT, QUOTED, SINGLE"),
        "second pass: {again}"
    );
}

#[test]
fn unsupported_groups_return_not_implemented_with_exit_two() {
    let dir = tempfile::tempdir().unwrap();
    let stubs = [
        ("doctor", Command::Doctor(StubArgs { args: Vec::new() })),
        ("merge", Command::Merge(StubArgs { args: Vec::new() })),
        ("rollback", Command::Rollback(StubArgs { args: Vec::new() })),
        (
            "promote",
            Command::Promote(StubArgs {
                args: vec!["main".into(), "production".into()],
            }),
        ),
        ("run", Command::Run(StubArgs { args: Vec::new() })),
        ("broker", Command::Broker(StubArgs { args: Vec::new() })),
        ("pack", Command::Pack(StubArgs { args: Vec::new() })),
        ("mcp", Command::Mcp(StubArgs { args: Vec::new() })),
        (
            "audit",
            Command::Audit(StubArgs {
                args: vec!["list".into()],
            }),
        ),
        ("remote", Command::Remote(StubArgs { args: Vec::new() })),
        ("login", Command::Login(StubArgs { args: Vec::new() })),
        (
            "workspace",
            Command::Workspace(StubArgs { args: Vec::new() }),
        ),
        ("push", Command::Push(StubArgs { args: Vec::new() })),
        ("pull", Command::Pull(StubArgs { args: Vec::new() })),
        ("sync", Command::Sync(StubArgs { args: Vec::new() })),
    ];
    for (group, command) in stubs {
        // Stubs work anywhere — they never touch the filesystem, so run
        // them against an uninitialized directory on purpose.
        let err = dispatch(&cli(dir.path(), command)).unwrap_err();
        assert!(
            matches!(&err, CliError::NotImplemented(name) if *name == group),
            "`{group}` must map to NotImplemented(\"{group}\"), got {err:?}"
        );
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains(group));
    }
}

#[test]
fn exit_code_mapping_covers_every_error_class() {
    assert_eq!(CliError::Usage("bad invocation".into()).exit_code(), 1);
    assert_eq!(
        CliError::Runtime(CoreError::VariableNotFound("V".into())).exit_code(),
        1
    );
    assert_eq!(CliError::NotImplemented("doctor").exit_code(), 2);
    assert_eq!(
        CliError::NotARepository(PathBuf::from("/tmp/project")).exit_code(),
        3
    );
}

#[test]
fn add_restore_branch_env_agent_policy_flows() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["DB_HOST=db.internal".into()],
        },
    ))
    .unwrap();

    // add confirms by name...
    let out = dispatch(&cli(
        root,
        Command::Add {
            name: Some("DB_HOST".into()),
            all: false,
        },
    ))
    .unwrap();
    assert_eq!(out, "added DB_HOST");

    // ...and --all confirms everything staged (and errors when nothing is
    // known).
    let out = dispatch(&cli(
        root,
        Command::Add {
            name: None,
            all: true,
        },
    ))
    .unwrap();
    assert_eq!(out, "added DB_HOST");

    let err = dispatch(&cli(
        root,
        Command::Add {
            name: Some("UNKNOWN_VAR".into()),
            all: false,
        },
    ))
    .unwrap_err();
    assert!(matches!(
        err,
        CliError::Runtime(CoreError::VariableNotFound(_))
    ));

    // NAME and --all together is a usage error.
    let err = dispatch(&cli(
        root,
        Command::Add {
            name: Some("DB_HOST".into()),
            all: true,
        },
    ))
    .unwrap_err();
    assert!(
        matches!(err, CliError::Usage(ref text) if text.contains("not both")),
        "got: {err:?}"
    );

    // restore drops staged intent and reports the outcome per name.
    let out = dispatch(&cli(
        root,
        Command::Restore {
            names: vec!["DB_HOST".into(), "NEVER_STAGED".into()],
        },
    ))
    .unwrap();
    assert!(out.contains("restored DB_HOST"));
    assert!(out.contains("nothing staged for NEVER_STAGED"));

    // Branch create/list/checkout round trip through status. The restore
    // above emptied staging, so stage a fresh variable before the base
    // commit.
    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["BASE=1".into()],
        },
    ))
    .unwrap();
    commit_ok(root, "base", None);
    let out = dispatch(&cli(
        root,
        Command::Branch {
            name: Some("feature".into()),
        },
    ))
    .unwrap();
    assert_eq!(out, "created branch feature");
    let listing = dispatch(&cli(root, Command::Branch { name: None })).unwrap();
    assert!(
        listing.contains("feature") && listing.contains("main"),
        "{listing}"
    );
    let switched = dispatch(&cli(
        root,
        Command::Checkout {
            name: "feature".into(),
        },
    ))
    .unwrap();
    assert_eq!(switched, "switched to branch feature");

    // Environments: create → protect → list → inspect.
    let err = dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::Create {
                name: "development".into(),
            },
        },
    ));
    assert!(err.is_ok());
    let out = dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::Protect {
                name: "development".into(),
                unprotect: false,
            },
        },
    ))
    .unwrap();
    assert_eq!(out, "development is now protected");
    let listing = dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::List,
        },
    ))
    .unwrap();
    assert!(
        listing.contains("development") && listing.contains("yes"),
        "{listing}"
    );
    let inspect = dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::Inspect {
                name: "development".into(),
            },
        },
    ))
    .unwrap();
    assert!(inspect.contains("environment: development"), "{inspect}");
    assert!(inspect.contains("protected:   yes"), "{inspect}");
    let err = dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::Inspect {
                name: "ghost".into(),
            },
        },
    ))
    .unwrap_err();
    assert!(matches!(
        err,
        CliError::Runtime(CoreError::EnvironmentNotFound(_))
    ));

    // Agents: create → list → inspect → disable.
    let out = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Create {
                name: "ci-bot".into(),
            },
        },
    ))
    .unwrap();
    assert!(out.contains("created agent ci-bot (agent_ci-bot)"), "{out}");
    let listing = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::List,
        },
    ))
    .unwrap();
    assert!(
        listing.contains("ci-bot") && listing.contains("enabled"),
        "{listing}"
    );
    let inspect = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Inspect {
                name: "ci-bot".into(),
            },
        },
    ))
    .unwrap();
    assert!(
        inspect.contains("agent_ci-bot") && inspect.contains("(none)"),
        "{inspect}"
    );
    let out = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Disable {
                name: "ci-bot".into(),
            },
        },
    ))
    .unwrap();
    assert_eq!(out, "disabled agent ci-bot");
    let listing = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::List,
        },
    ))
    .unwrap();
    assert!(listing.contains("disabled"), "{listing}");

    // Policies: validate/list on an empty store print friendly notices.
    let out = dispatch(&cli(
        root,
        Command::Policy {
            command: PolicyCommand::Validate,
        },
    ))
    .unwrap();
    assert_eq!(out, "no policies found");
    let out = dispatch(&cli(
        root,
        Command::Policy {
            command: PolicyCommand::List,
        },
    ))
    .unwrap();
    assert_eq!(out, "no policies found");
}

/// Commits with `-m` (author optional) and returns the new commit id
/// parsed back from the rendered output.
fn commit_ok(root: &Path, message: &str, author: Option<&str>) -> CommitId {
    let out = dispatch(&cli(
        root,
        Command::Commit {
            message: Some(message.to_owned()),
            author: author.map(str::to_owned),
        },
    ))
    .unwrap_or_else(|err| panic!("commit `{message}` failed: {err}"));
    let id = out.strip_prefix("committed ").expect("commit prints id");
    vaultx_types::CommitId::parse(id).unwrap()
}

#[test]
fn secret_destroy_requires_explicit_yes_flag() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    let err = dispatch(&cli(
        root,
        Command::Secret {
            command: SecretCommand::Destroy {
                name: "FOO".into(),
                yes: false,
                env: None,
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("--yes")),
        "got: {err:?}"
    );
    // Usage-class failure, not the exit-2 "planned" bucket.
    assert_eq!(err.exit_code(), 1);
}

#[test]
fn secret_set_rejects_inconsistent_broker_flags() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    // --brokered without --injection is a usage error before any prompt.
    let err = dispatch(&cli(
        root,
        Command::Secret {
            command: SecretCommand::Set {
                name: "TOKEN".into(),
                stdin: Some("-".into()),
                brokered: true,
                injection: None,
                provider: None,
                env: None,
                message: None,
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("--brokered requires --injection"))
    );

    // --provider without --brokered is refused too.
    let err = dispatch(&cli(
        root,
        Command::Secret {
            command: SecretCommand::Set {
                name: "PLAIN".into(),
                stdin: Some("-".into()),
                brokered: false,
                injection: None,
                provider: Some("github".into()),
                env: None,
                message: None,
            },
        },
    ))
    .unwrap_err();
    assert!(matches!(&err, CliError::Usage(text) if text.contains("require --brokered")));
}

#[test]
fn secret_positional_must_be_the_stdin_marker() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    let err = dispatch(&cli(
        root,
        Command::Secret {
            command: SecretCommand::Set {
                name: "FOO".into(),
                // Plaintext arguments are never accepted.
                stdin: Some("hunter2".into()),
                brokered: false,
                injection: None,
                provider: None,
                env: None,
                message: None,
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("only `-`")),
        "got: {err:?}"
    );
}

#[test]
fn secret_metadata_unknown_name_is_a_runtime_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    match dispatch(&cli(
        root,
        Command::Secret {
            command: SecretCommand::Metadata {
                name: "MISSING".into(),
                env: None,
            },
        },
    )) {
        Err(CliError::Runtime(CoreError::SecretNotFound(name))) => assert_eq!(name, "MISSING"),
        other => panic!("expected SecretNotFound, got {other:?}"),
    }
}

#[test]
fn secret_metadata_never_shows_a_value_for_existing_secrets() {
    // Drives set via the service layer (stdin is a process concern; the
    // end-to-end stdin path is covered by tests/secret_cli.rs).
    use vaultx_core::{BrokeredBinding, SecretString, VaultxServices};
    use vaultx_types::model::{InjectionTemplateId, VariableKind};
    use vaultx_types::CredentialRef;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let services = VaultxServices::init(root).expect("init");
    services
        .secrets()
        .set_secret(
            "GITHUB_TOKEN",
            &SecretString::copy_from("canary-hunter2"),
            VariableKind::Brokered,
            "development",
            Some(BrokeredBinding {
                credential_ref: CredentialRef::parse("github-token").unwrap(),
                injection: InjectionTemplateId::GithubBearer,
                provider_hint: Some(vaultx_types::ProviderName::parse("github").unwrap()),
            }),
        )
        .expect("set");

    let out = dispatch(&cli(
        root,
        Command::Secret {
            command: SecretCommand::Metadata {
                name: "GITHUB_TOKEN".into(),
                env: None,
            },
        },
    ))
    .unwrap();
    assert!(out.contains("state:       active"), "{out}");
    assert!(out.contains("kind:        brokered"), "{out}");
    assert!(out.contains("github-token@github-bearer (github)"), "{out}");
    assert!(out.contains("revisions:   1"), "{out}");
    assert!(out.contains("fingerprint:"), "{out}");
    assert!(!out.contains("canary-hunter2"), "plaintext leaked:\n{out}");
}
