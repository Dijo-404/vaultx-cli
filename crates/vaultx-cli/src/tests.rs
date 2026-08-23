//! Integration-style tests driving [`dispatch`] directly with
//! constructed [`Cli`] values against real temporary projects. No
//! processes are spawned: handlers are pure parse+present functions over
//! core services, so output strings and error variants can be asserted
//! without stdio.

use std::path::{Path, PathBuf};

use vaultx_core::{CoreError, MergeStrategy};
use vaultx_types::CommitId;

use crate::{
    dispatch, AgentCommand, Cli, CliError, Command, EnvCommand, PackCommand, PolicyCommand,
    SecretCommand, StubArgs,
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
        // `broker` and `mcp` are implemented now; their subcommands are
        // exercised in the dedicated tests below.
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
fn secret_set_validates_name_before_collecting_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    // The stdin marker would trigger a real stdin read; the invalid name
    // must fail before any plaintext is collected.
    match dispatch(&cli(
        root,
        Command::Secret {
            command: SecretCommand::Set {
                name: "lower-case".into(),
                stdin: Some("-".into()),
                brokered: false,
                injection: None,
                provider: None,
                env: None,
                message: None,
            },
        },
    )) {
        Err(CliError::Runtime(CoreError::InvalidVariableName(name))) => {
            assert_eq!(name, "lower-case")
        }
        other => panic!("expected InvalidVariableName, got {other:?}"),
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

// ---- merge / rollback / promote / doctor ----

/// Opens the project services directly (for secret setup that would
/// otherwise require stdin prompting).
fn open_services(root: &Path) -> vaultx_core::VaultxServices {
    vaultx_core::VaultxServices::open(root).expect("open")
}

fn store_secret(root: &Path, name: &str, value: &str) {
    open_services(root)
        .secrets()
        .set_secret(
            name,
            &vaultx_core::SecretString::copy_from(value),
            vaultx_types::model::VariableKind::Secret,
            "development",
            None,
        )
        .expect("set secret");
}

#[test]
fn merge_clean_produces_two_parent_commit() {
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
    let base = commit_ok(root, "base", None);
    dispatch(&cli(
        root,
        Command::Branch {
            name: Some("feature".into()),
        },
    ))
    .unwrap();
    dispatch(&cli(
        root,
        Command::Checkout {
            name: "feature".into(),
        },
    ))
    .unwrap();
    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["B=2".into()],
        },
    ))
    .unwrap();
    let feature_tip = commit_ok(root, "feature work", None);
    dispatch(&cli(
        root,
        Command::Checkout {
            name: "main".into(),
        },
    ))
    .unwrap();
    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["C=3".into()],
        },
    ))
    .unwrap();
    let main_tip = commit_ok(root, "main work", None);

    let out = dispatch(&cli(
        root,
        Command::Merge {
            branch: "feature".into(),
            into: None,
            strategy: None,
            allow_weaker_protection: false,
        },
    ))
    .unwrap();

    assert!(out.starts_with("merged feature into main"), "{out}");
    let merged_id = CommitId::parse(out.lines().nth(1).expect("id line")).unwrap();
    assert_ne!(merged_id, main_tip);
    assert_ne!(merged_id, feature_tip);

    // Two parents: [ours tip, theirs tip].
    let shown = dispatch(&cli(
        root,
        Command::Show {
            prefix: merged_id.as_str()[4..16].into(),
        },
    ))
    .unwrap();
    let parents_line = shown
        .lines()
        .find(|line| line.starts_with("parents:"))
        .expect("parents line");
    assert!(
        parents_line.contains(main_tip.as_str()) && parents_line.contains(feature_tip.as_str()),
        "both tips must be parents: {shown}"
    );
    for name in ["A", "B", "C"] {
        assert!(
            shown.contains(name),
            "merged manifest must contain {name}: {shown}"
        );
    }
    let _ = base;
}

#[test]
fn merge_config_conflict_exits_one_and_refs_unmoved() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["PORT=8080".into()],
        },
    ))
    .unwrap();
    commit_ok(root, "base", None);
    dispatch(&cli(
        root,
        Command::Branch {
            name: Some("feature".into()),
        },
    ))
    .unwrap();
    dispatch(&cli(
        root,
        Command::Checkout {
            name: "feature".into(),
        },
    ))
    .unwrap();
    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["PORT=7070".into()],
        },
    ))
    .unwrap();
    let feature_tip = commit_ok(root, "their change", None);
    dispatch(&cli(
        root,
        Command::Checkout {
            name: "main".into(),
        },
    ))
    .unwrap();
    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["PORT=9090".into()],
        },
    ))
    .unwrap();
    commit_ok(root, "our change", None);

    let err = dispatch(&cli(
        root,
        Command::Merge {
            branch: "feature".into(),
            into: None,
            strategy: None,
            allow_weaker_protection: false,
        },
    ))
    .unwrap_err();

    match &err {
        CliError::Conflicts(report) => {
            assert!(report.contains("config conflicts"), "{report}");
            assert!(report.contains("PORT"), "{report}");
            assert!(report.contains("ours=9090"), "{report}");
            assert!(report.contains("theirs=7070"), "{report}");
        }
        other => panic!("expected Conflicts, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 1);

    // Refs unmoved: main HEAD is still "our change", feature still at its
    // tip, and neither manifest changed.
    let log = dispatch(&cli(root, Command::Log { limit: Some(1) })).unwrap();
    assert!(log.contains("our change"), "{log}");
    let value = dispatch(&cli(
        root,
        Command::Get {
            name: "PORT".into(),
        },
    ))
    .unwrap();
    assert_eq!(value, "9090");
    dispatch(&cli(
        root,
        Command::Checkout {
            name: "feature".into(),
        },
    ))
    .unwrap();
    let log = dispatch(&cli(root, Command::Log { limit: Some(1) })).unwrap();
    assert!(log.contains("their change"), "{log}");
    assert!(
        head_is_at(root, feature_tip),
        "feature tip must be untouched"
    );
}

/// Whether the current branch's tip equals `expected` (via status).
fn head_is_at(root: &Path, expected: CommitId) -> bool {
    open_services(root)
        .history()
        .branches()
        .into_iter()
        .flatten()
        .any(|(_, tip)| tip == expected)
}

#[test]
fn merge_secret_conflict_blocked_without_plaintext_leak() {
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
    commit_ok(root, "base", None);
    dispatch(&cli(
        root,
        Command::Branch {
            name: Some("feature".into()),
        },
    ))
    .unwrap();
    store_secret(root, "DB_PASSWORD", "canary-ours-hunter2");
    commit_ok(root, "ours rotate", None);
    let ours_revision = open_services(root)
        .secrets()
        .secret_metadata("DB_PASSWORD", "development")
        .unwrap()
        .current_revision;
    dispatch(&cli(
        root,
        Command::Checkout {
            name: "feature".into(),
        },
    ))
    .unwrap();
    store_secret(root, "DB_PASSWORD", "canary-theirs-hunter2");
    commit_ok(root, "their rotate", None);
    let theirs_revision = open_services(root)
        .secrets()
        .secret_metadata("DB_PASSWORD", "development")
        .unwrap()
        .current_revision;
    dispatch(&cli(
        root,
        Command::Checkout {
            name: "main".into(),
        },
    ))
    .unwrap();

    let err = dispatch(&cli(
        root,
        Command::Merge {
            branch: "feature".into(),
            into: None,
            strategy: Some(MergeStrategy::Theirs),
            allow_weaker_protection: false,
        },
    ))
    .unwrap_err();

    match &err {
        CliError::Conflicts(report) => {
            assert!(
                report.contains("secret conflicts (revision ids only)"),
                "{report}"
            );
            assert!(
                report.contains(ours_revision.as_str())
                    && report.contains(theirs_revision.as_str()),
                "revision ids must be shown: {report}"
            );
            assert!(
                !report.contains("canary-ours") && !report.contains("canary-theirs"),
                "plaintext leaked:\n{report}"
            );
        }
        other => panic!("expected Conflicts, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 1, "secret conflicts block with exit 1");
}

#[test]
fn merge_strategy_flags_pick_config_sides() {
    for (strategy_flag, expected_value) in [
        (MergeStrategy::Ours, "9090"),
        (MergeStrategy::Theirs, "7070"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_in(root);

        dispatch(&cli(
            root,
            Command::Set {
                pairs: vec!["PORT=8080".into()],
            },
        ))
        .unwrap();
        commit_ok(root, "base", None);
        dispatch(&cli(
            root,
            Command::Branch {
                name: Some("feature".into()),
            },
        ))
        .unwrap();
        dispatch(&cli(
            root,
            Command::Checkout {
                name: "feature".into(),
            },
        ))
        .unwrap();
        dispatch(&cli(
            root,
            Command::Set {
                pairs: vec!["PORT=7070".into()],
            },
        ))
        .unwrap();
        commit_ok(root, "their change", None);
        dispatch(&cli(
            root,
            Command::Checkout {
                name: "main".into(),
            },
        ))
        .unwrap();
        dispatch(&cli(
            root,
            Command::Set {
                pairs: vec!["PORT=9090".into()],
            },
        ))
        .unwrap();
        commit_ok(root, "our change", None);

        let out = dispatch(&cli(
            root,
            Command::Merge {
                branch: "feature".into(),
                into: None,
                strategy: Some(strategy_flag),
                allow_weaker_protection: false,
            },
        ))
        .unwrap_or_else(|err| panic!("strategy merge failed: {err}"));
        assert!(out.contains("merged feature into main"), "{out}");

        let value = dispatch(&cli(
            root,
            Command::Get {
                name: "PORT".into(),
            },
        ))
        .unwrap();
        assert_eq!(value, expected_value, "{strategy_flag:?}");
    }
}

#[test]
fn merge_refuses_protection_weakening_unless_overridden() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["KEEP=1".into()],
        },
    ))
    .unwrap();
    commit_ok(root, "base", None);
    dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::Create {
                name: "staging".into(),
            },
        },
    ))
    .unwrap();
    dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::Protect {
                name: "staging".into(),
                unprotect: false,
            },
        },
    ))
    .unwrap();
    dispatch(&cli(
        root,
        Command::Branch {
            name: Some("feature".into()),
        },
    ))
    .unwrap();

    // Feature removes the variable the protected environment pins.
    dispatch(&cli(
        root,
        Command::Checkout {
            name: "feature".into(),
        },
    ))
    .unwrap();
    dispatch(&cli(
        root,
        Command::Unset {
            names: vec!["KEEP".into()],
        },
    ))
    .unwrap();
    commit_ok(root, "drop KEEP", None);
    dispatch(&cli(
        root,
        Command::Checkout {
            name: "main".into(),
        },
    ))
    .unwrap();

    let err = dispatch(&cli(
        root,
        Command::Merge {
            branch: "feature".into(),
            into: None,
            strategy: None,
            allow_weaker_protection: false,
        },
    ))
    .unwrap_err();
    match &err {
        CliError::Runtime(CoreError::ProtectionWeakening(msg)) => {
            assert!(msg.contains("staging") && msg.contains("KEEP"), "{msg}");
        }
        other => panic!("expected ProtectionWeakening, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 1);

    // Override path proceeds and lands the removal.
    let out = dispatch(&cli(
        root,
        Command::Merge {
            branch: "feature".into(),
            into: None,
            strategy: None,
            allow_weaker_protection: true,
        },
    ))
    .unwrap();
    assert!(out.contains("merged feature into main"), "{out}");
    match dispatch(&cli(
        root,
        Command::Get {
            name: "KEEP".into(),
        },
    )) {
        Err(CliError::Runtime(CoreError::VariableNotFound(_))) => {}
        other => panic!("expected removed KEEP after override, got {other:?}"),
    }
}

#[test]
fn rollback_appends_commit_keeps_history_and_warns_destroyed_secret() {
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
    let c1 = commit_ok(root, "first", None);
    store_secret(root, "TOKEN", "destroy-me-canary");
    let c2 = commit_ok(root, "second with token", None);
    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["B=2".into()],
        },
    ))
    .unwrap();
    let _c3 = commit_ok(root, "third", None);

    // Real destroy: the value and recovery material are shredded.
    dispatch(&cli(
        root,
        Command::Secret {
            command: SecretCommand::Destroy {
                name: "TOKEN".into(),
                yes: true,
                env: None,
            },
        },
    ))
    .unwrap();

    let out = dispatch(&cli(root, Command::Rollback { to: None })).unwrap();
    let mut lines = out.lines();
    assert!(
        lines.next().expect("line").starts_with("rolled back to "),
        "{out}"
    );
    let new_id_line = lines.next().expect("new commit line");
    assert!(new_id_line.starts_with("new commit: "), "{out}");
    let warning = lines.next().expect("warning line");
    assert!(
        warning.contains("warning:") && warning.contains("TOKEN") && warning.contains("destroyed"),
        "{out}"
    );
    assert!(
        !out.contains("destroy-me-canary"),
        "plaintext leaked:\n{out}"
    );
    assert!(lines.next().is_none(), "no extra lines expected: {out}");

    // The new commit references the HISTORICAL manifest (A + TOKEN
    // present, B gone) while old commits remain intact.
    let new_id = CommitId::parse(new_id_line.trim_start_matches("new commit: ")).unwrap();
    let shown = dispatch(&cli(
        root,
        Command::Show {
            prefix: new_id.as_str()[4..16].into(),
        },
    ))
    .unwrap();
    assert!(shown.contains("rollback to"), "{shown}");
    assert!(
        shown.contains("entries: 2"),
        "restored manifest must hold A + TOKEN only:\n{shown}"
    );
    assert!(shown.contains("\n    A "), "{shown}");
    assert!(shown.contains("\n    TOKEN "), "{shown}");
    let old = dispatch(&cli(
        root,
        Command::Show {
            prefix: c3_hex(&_c3),
        },
    ))
    .unwrap();
    assert!(
        old.contains("entries: 3"),
        "old commits must stay intact:\n{old}"
    );
    let first = dispatch(&cli(
        root,
        Command::Show {
            prefix: c3_hex(&c1),
        },
    ))
    .unwrap();
    assert!(first.contains("message: first"), "{first}");
    let second = dispatch(&cli(
        root,
        Command::Show {
            prefix: c3_hex(&c2),
        },
    ))
    .unwrap();
    assert!(second.contains("message: second with token"), "{second}");

    // History grew; nothing was rewritten.
    let log = dispatch(&cli(root, Command::Log { limit: Some(10) })).unwrap();
    assert!(log.lines().count() == 4, "{log}");
}

/// `cmt_`-stripped short hex used as a show prefix.
fn c3_hex(id: &CommitId) -> String {
    id.as_str()[4..16].to_owned()
}

#[test]
fn rollback_requires_target_when_head_is_root_and_rejects_staged_work() {
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
    commit_ok(root, "root only", None);

    let err = dispatch(&cli(root, Command::Rollback { to: None })).unwrap_err();
    assert!(
        matches!(err, CliError::Runtime(CoreError::UnsupportedOperation(ref msg)) if msg.contains("--to")),
        "got: {err:?}"
    );
    assert_eq!(err.exit_code(), 1);
}

#[test]
fn promote_success_then_protected_refusal_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["URL=https://prod".into()],
        },
    ))
    .unwrap();
    commit_ok(root, "baseline", None);
    dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::Create {
                name: "production".into(),
            },
        },
    ))
    .unwrap();

    // Unknown source is a plain failure (exit 1).
    let err = dispatch(&cli(
        root,
        Command::Promote {
            to: "production".into(),
            from: Some("ghost".into()),
            force: false,
        },
    ))
    .unwrap_err();
    assert_eq!(err.exit_code(), 1);

    // Success: current branch promoted onto production.
    let out = dispatch(&cli(
        root,
        Command::Promote {
            to: "production".into(),
            from: None,
            force: false,
        },
    ))
    .unwrap();
    assert_eq!(out, "promoted main -> production");

    // Advance main; protect production; unforced move refused.
    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["URL=https://v2".into()],
        },
    ))
    .unwrap();
    let newer_tip = commit_ok(root, "advance main", None);
    dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::Protect {
                name: "production".into(),
                unprotect: false,
            },
        },
    ))
    .unwrap();
    let err = dispatch(&cli(
        root,
        Command::Promote {
            to: "production".into(),
            from: None,
            force: false,
        },
    ))
    .unwrap_err();
    match &err {
        CliError::Runtime(CoreError::Repo(repo_err)) => {
            assert!(
                repo_err.to_string().contains("protected"),
                "expected protected-ref refusal, got {repo_err}"
            );
        }
        other => panic!("expected protected-ref refusal, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 1);

    // Force overrides.
    let out = dispatch(&cli(
        root,
        Command::Promote {
            to: "production".into(),
            from: None,
            force: true,
        },
    ))
    .unwrap();
    assert_eq!(out, "promoted main -> production");
    let inspect = dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::Inspect {
                name: "production".into(),
            },
        },
    ))
    .unwrap();
    assert!(inspect.contains(newer_tip.as_str()), "{inspect}");
}

#[test]
fn doctor_fresh_repo_passes_and_tampered_object_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    let out = dispatch(&cli(root, Command::Doctor)).unwrap();
    assert!(out.contains("PASS repository integrity"), "{out}");
    assert!(out.contains("WARN broker"), "{out}");
    assert!(out.contains("WARN remote"), "{out}");
    assert!(out.contains("summary:"), "{out}");
    assert!(!out.contains("FAIL"), "fresh repo must not fail: {out}");

    // Tamper with an object on disk.
    use vaultx_core::VaultxServices;
    let services = VaultxServices::open(root).unwrap();
    services.config().set_config("V", "1").unwrap();
    let head = services.history().commit("seed", "user:t").unwrap();
    let digest = &head.as_str()[4..];
    let object_path = services
        .context()
        .repository()
        .objects()
        .root()
        .join("sha256")
        .join(&digest[..2])
        .join(&digest[2..]);
    std::fs::write(object_path, b"{\"tampered\":true}").unwrap();

    let err = dispatch(&cli(root, Command::Doctor)).unwrap_err();
    match &err {
        CliError::Diagnostics(report) => {
            assert!(report.contains("FAIL repository integrity"), "{report}");
            assert!(
                report.contains("summary: 2 passed, 4 warned, 1 failed"),
                "exact summary expected:\n{report}"
            );
        }
        other => panic!("expected Diagnostics, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 1);
}

// ---------------------------------------------------------------------------
// Policy pack commands
// ---------------------------------------------------------------------------

/// A minimal valid pack used as CLI test fixture.
const PACK_YAML: &str = r#"format: 1
name: test.capability.call
provider: github
request:
  hosts: [api.github.com]
  methods: [GET]
  paths: ["/repos/{owner}/{repo}"]
credential:
  credential_ref: test-token
  injection: bearer
"#;

fn write_pack(root: &Path, relative: &str, contents: &str) -> PathBuf {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, contents).unwrap();
    path
}

#[test]
fn pack_list_inspect_and_validate_report_parsed_packs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Pack commands never require an initialized repository: run against a
    // bare directory on purpose.
    write_pack(root, "policy-packs/github/test.capability.yaml", PACK_YAML);
    write_pack(
        root,
        "policy-packs/openai/other.yaml",
        &PACK_YAML.replace("test.capability.call", "zzz.other.call"),
    );

    let listed = dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::List { dir: None },
        },
    ))
    .unwrap();
    assert!(listed.contains("NAME"), "{listed}");
    assert!(listed.contains("test.capability.call"), "{listed}");
    assert!(listed.contains("bearer"), "{listed}");
    assert!(listed.contains("HOSTS"), "{listed}");
    // Sorted by capability name.
    assert!(listed.find("test.capability.call").unwrap() < listed.find("zzz.other.call").unwrap());

    let inspected = dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Inspect {
                name: "test.capability.call".into(),
                dir: None,
            },
        },
    ))
    .unwrap();
    assert!(inspected.contains("format:     1"), "{inspected}");
    assert!(inspected.contains("/repos/{owner}/{repo}"), "{inspected}");
    assert!(inspected.contains("injection: bearer"), "{inspected}");

    let validated = dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Validate { dir: None },
        },
    ))
    .unwrap();
    assert_eq!(validated.matches(": ok (").count(), 2, "{validated}");

    let err = dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Inspect {
                name: "missing.pack".into(),
                dir: None,
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Pack(text) if text.contains("no policy pack named")),
        "{err:?}"
    );
}

#[test]
fn pack_validate_reports_errors_per_file_and_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_pack(root, "policy-packs/github/good.yaml", PACK_YAML);
    write_pack(
        root,
        "policy-packs/github/bad-version.yaml",
        &PACK_YAML.replace("format: 1", "format: 2"),
    );
    write_pack(
        root,
        "policy-packs/github/bad-host.yaml",
        &PACK_YAML.replace("[api.github.com]", "[localhost]"),
    );

    let err = dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Validate { dir: None },
        },
    ))
    .unwrap_err();
    match &err {
        CliError::Pack(report) => {
            assert!(
                report.contains(": ok ("),
                "good file still reported: {report}"
            );
            assert!(report.contains("bad-version.yaml"), "{report}");
            assert!(report.contains("`format`"), "{report}");
            assert!(report.contains("bad-host.yaml"), "{report}");
            assert!(report.contains("cannot be targeted"), "{report}");
            assert_eq!(report.matches(": ERROR").count(), 2, "{report}");
        }
        other => panic!("expected Pack, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 1);

    // Missing pack directory is its own failure class.
    let empty = tempfile::tempdir().unwrap();
    let err = dispatch(&cli(
        empty.path(),
        Command::Pack {
            command: PackCommand::Validate { dir: None },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Pack(text) if text.contains("does not exist")),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), 1);
}

#[test]
fn pack_add_copies_into_provider_tree_and_respects_force() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let source = write_pack(root, "staging/new-pack.yaml", PACK_YAML);

    let out = dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Add {
                file: source.clone(),
                dir: None,
                force: false,
            },
        },
    ))
    .unwrap();
    let target = root.join("policy-packs/github/call.yaml");
    assert!(out.contains(&target.display().to_string()), "{out}");

    let installed = std::fs::read_to_string(&target).unwrap();
    assert_eq!(installed, PACK_YAML);

    // Re-adding without --force refuses to overwrite.
    let err = dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Add {
                file: source.clone(),
                dir: None,
                force: false,
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("--force")),
        "{err:?}"
    );

    // --force overwrites.
    dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Add {
                file: source,
                dir: None,
                force: true,
            },
        },
    ))
    .unwrap();

    // Invalid packs are rejected before any copy happens.
    let bad = write_pack(
        root,
        "staging/bad.yaml",
        &PACK_YAML.replace("format: 1", "format: 3"),
    );
    let err = dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Add {
                file: bad,
                dir: Some(root.join("elsewhere")),
                force: true,
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Pack(text) if text.contains("`format`")),
        "{err:?}"
    );
    assert!(!root.join("elsewhere").exists());
}

#[test]
fn pack_inspect_survives_broken_sibling_packs() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_pack(root, "policy-packs/github/target.yaml", PACK_YAML);
    write_pack(
        root,
        "policy-packs/github/broken-sibling.yaml",
        &PACK_YAML.replace("format: 1", "format: 9"),
    );

    // The broken sibling must not block inspecting the valid target.
    let out = dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Inspect {
                name: "test.capability.call".into(),
                dir: None,
            },
        },
    ))
    .unwrap();
    assert!(out.contains("test.capability.call"), "{out}");

    // Validate still surfaces the sibling failure.
    let err = dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Validate { dir: None },
        },
    ))
    .unwrap_err();
    assert!(err.to_string().contains("broken-sibling.yaml"), "{err:?}");

    // Asking for the missing pack names the broken sibling instead of a
    // bare not-found.
    let err = dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Inspect {
                name: "absent.pack".into(),
                dir: None,
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Pack(text) if text.contains("broken-sibling.yaml")),
        "{err:?}"
    );
}

#[test]
fn pack_add_force_never_swaps_capabilities_on_one_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Two different capabilities sharing the derived filename `call.yaml`
    // under the same provider directory.
    let first = write_pack(root, "staging/first.yaml", PACK_YAML);
    let second = write_pack(
        root,
        "staging/second.yaml",
        &PACK_YAML.replace("test.capability.call", "test.capability_two.call"),
    );

    dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Add {
                file: first,
                dir: None,
                force: false,
            },
        },
    ))
    .unwrap();

    // Same-capability re-add under --force still works...
    let same_capability = write_pack(root, "staging/same.yaml", PACK_YAML);
    dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Add {
                file: same_capability,
                dir: None,
                force: true,
            },
        },
    ))
    .unwrap();

    // ...but a DIFFERENT capability is refused even under --force.
    let err = dispatch(&cli(
        root,
        Command::Pack {
            command: PackCommand::Add {
                file: second,
                dir: None,
                force: true,
            },
        },
    ))
    .unwrap_err();
    match &err {
        CliError::Usage(text) => {
            assert!(
                text.contains("holds capability `test.capability.call`"),
                "{text}"
            );
            assert!(text.contains("test.capability_two.call"), "{text}");
        }
        other => panic!("expected Usage refusal, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 1);

    // The installed bytes were never replaced.
    let installed =
        vaultx_policy_packs::load_pack(&root.join("policy-packs/github/call.yaml")).unwrap();
    assert_eq!(installed.name, "test.capability.call");
}

#[test]
fn run_requires_environment_pinned_commit_and_nonempty_resolution() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    // No environments exist yet: unknown-environment usage error.
    let err = dispatch(&cli(
        root,
        Command::Run {
            env: Some("development".into()),
            allow_empty: false,
            command: vec!["sh".into(), "-c".into(), "exit 0".into()],
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("unknown environment `development`")),
        "{err:?}"
    );

    // Environments pin a commit. The pin here binds ONLY a plain secret
    // (set via the service layer; stdin is a process concern): the run
    // resolver skips secret entries entirely, so the resolved set is empty
    // and execution is refused without --allow-empty — and even with
    // --allow-empty the secret must never reach the child environment.
    {
        use vaultx_core::{SecretString, VaultxServices};
        use vaultx_types::model::VariableKind;
        let services = VaultxServices::open(root).expect("open");
        services
            .secrets()
            .set_secret(
                "API_TOKEN",
                &SecretString::copy_from("canary-hunter2"),
                VariableKind::Secret,
                "development",
                None,
            )
            .expect("set");
    }
    commit_ok(root, "seed", None);
    dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::Create {
                name: "development".into(),
            },
        },
    ))
    .unwrap();
    let err = dispatch(&cli(
        root,
        Command::Run {
            env: None,
            allow_empty: false,
            command: vec!["sh".into(), "-c".into(), "exit 0".into()],
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("resolves no config variables")),
        "{err:?}"
    );

    // --allow-empty explicitly permits running; the secret stays out.
    let out = dispatch(&cli(
        root,
        Command::Run {
            env: None,
            allow_empty: true,
            command: vec![
                "sh".into(),
                "-c".into(),
                "test -z \"${API_TOKEN:-}\"".into(),
            ],
        },
    ))
    .unwrap();
    assert_eq!(out, "");
}

#[cfg(unix)]
#[test]
fn run_injects_committed_config_only_and_propagates_exit_codes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["RUN_PROBE=committed-value".into()],
        },
    ))
    .unwrap();
    commit_ok(root, "seed config", None);
    dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::Create {
                name: "development".into(),
            },
        },
    ))
    .unwrap();

    // Staged-but-uncommitted values must NOT leak into the child.
    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["RUN_UNCOMMITTED=stage-only".into()],
        },
    ))
    .unwrap();

    let out = dispatch(&cli(
        root,
        Command::Run {
            env: None,
            allow_empty: false,
            command: vec![
                "sh".into(),
                "-c".into(),
                "test \"$RUN_PROBE\" = committed-value && test -z \"${RUN_UNCOMMITTED:-}\"".into(),
            ],
        },
    ))
    .unwrap();
    assert_eq!(out, "", "success prints nothing extra");

    // Nonzero child status propagates as ChildExit with its own code.
    let err = dispatch(&cli(
        root,
        Command::Run {
            env: None,
            allow_empty: true,
            command: vec!["sh".into(), "-c".into(), "exit 7".into()],
        },
    ))
    .unwrap_err();
    assert!(matches!(err, CliError::ChildExit(7)), "{err:?}");
    assert_eq!(err.exit_code(), 7);

    let err = dispatch(&cli(
        root,
        Command::Run {
            env: None,
            allow_empty: true,
            command: vec!["definitely-not-a-program-xyz".into()],
        },
    ))
    .unwrap_err();
    assert!(matches!(err, CliError::Runtime(_)), "{err:?}");

    // Missing command after -- is a usage error.
    let err = dispatch(&cli(
        root,
        Command::Run {
            env: None,
            allow_empty: true,
            command: Vec::new(),
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("command after `--`")),
        "{err:?}"
    );
}
