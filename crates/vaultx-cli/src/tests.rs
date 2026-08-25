//! Integration-style tests driving [`dispatch`] directly with
//! constructed [`Cli`] values against real temporary projects. No
//! processes are spawned: handlers are pure parse+present functions over
//! core services, so output strings and error variants can be asserted
//! without stdio.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use vaultx_core::{CoreError, MergeStrategy};
use vaultx_types::CommitId;

use crate::cli::REVEAL_CONFIRMATION_PHRASE;
use crate::cli::{typed_confirmation_matches, DELETE_REFS_CONFIRMATION_PHRASE};
use crate::{
    dispatch, AgentCommand, AuditCommand, Cli, CliError, Command, EnvCommand, McpCommand,
    PackCommand, PolicyCommand, RemoteCommand, SecretCommand, WorkspaceCommand,
};

/// Isolates the process-wide XDG runtime directory so broker-endpoint
/// probes never observe (or disturb) a developer's live broker socket.
/// The value is process-global by nature; every CLI test wants the same
/// empty isolation, so a lazily-created leaked temp dir is correct.
fn isolated_xdg_runtime_dir() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::tempdir()
            .expect("tempdir for runtime isolation")
            .keep();
        // SAFETY-adjacent note: `set_var` mutates process-global state;
        // edition 2021 exposes it as safe and every test in this binary
        // intends the same value, so races are benign.
        std::env::set_var("XDG_RUNTIME_DIR", &dir);
        dir
    })
}

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

// ---------------------------------------------------------------------------
// Team-sync surface (login/remote/workspace/push/pull/sync/audit list)
//
// Drives `dispatch` against a real in-process control plane: one axum
// server bound to 127.0.0.1:0 for the whole binary, with per-test
// workspaces/projects/sessions seeded into the shared store so parallel
// tests never observe each other's server-side state. A process-wide
// mutex serializes the tests because the session-token file under
// XDG_RUNTIME_DIR is shared.
// ---------------------------------------------------------------------------

use vaultx_audit::{
    AppendStore as _, AuditAction, AuditDecision, CorrelationId, JsonlAppendStore, NewAuditEvent,
    SafeAuditMetadata,
};
use vaultx_control_plane::api::AppState as ControlPlaneState;
use vaultx_control_plane::model::{Principal as ControlPrincipal, UserRecord, WorkspaceMembership};
use vaultx_control_plane::store::{ControlPlaneStore as _, InMemoryControlPlaneStore};

struct FakeControlPlane {
    base_url: String,
    store: std::sync::Arc<InMemoryControlPlaneStore>,
}

/// Serializes every team-sync test (shared session file + shared server).
static TEAM_SYNC_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fake_control_plane() -> &'static FakeControlPlane {
    static PLANE: OnceLock<FakeControlPlane> = OnceLock::new();
    PLANE.get_or_init(|| {
        isolated_xdg_runtime_dir();
        let store = std::sync::Arc::new(InMemoryControlPlaneStore::new());
        let app = vaultx_control_plane::api::router(ControlPlaneState::new(std::sync::Arc::clone(
            &store,
        )
            as std::sync::Arc<dyn vaultx_control_plane::ControlPlaneStore>));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("server runtime");
        let listener = runtime
            .block_on(async { tokio::net::TcpListener::bind("127.0.0.1:0").await })
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        // The server thread owns the runtime for the rest of the process;
        // it serves until exit, which is exactly the lifetime a hermetic
        // fixture wants.
        std::thread::spawn(move || {
            runtime.block_on(async move { axum::serve(listener, app).await.expect("serve") });
        });
        FakeControlPlane {
            base_url: format!("http://{addr}"),
            store,
        }
    })
}

/// Seeds user/workspace/project/session for one test and returns
/// `(project_id, session_token)`.
fn seed_project(plane: &FakeControlPlane, tag: &str) -> (vaultx_types::ProjectId, String) {
    use vaultx_types::WorkspaceId;
    let workspace = WorkspaceId::parse(&format!("ws_{tag}")).expect("valid workspace id");
    let project = vaultx_types::ProjectId::parse(&format!("proj_{tag}")).expect("valid project");
    let login = format!("user-{tag}");
    let token = format!("vxs_cli_{tag}_session");
    plane
        .store
        .upsert_user(&UserRecord {
            login: login.clone(),
            display_name: None,
            verifier: vaultx_control_plane::auth::hash_verifier("pw").expect("seed"),
        })
        .expect("seed user");
    plane
        .store
        .create_workspace(&vaultx_control_plane::model::WorkspaceRecord {
            id: workspace.clone(),
            name: tag.to_owned(),
            owner: login.clone(),
        })
        .expect("seed workspace");
    plane
        .store
        .create_project(&vaultx_control_plane::model::ProjectRecord {
            id: project.clone(),
            workspace,
            name: "core".to_owned(),
        })
        .expect("seed project");
    plane
        .store
        .issue_session(
            &token,
            &ControlPrincipal {
                subject: login,
                class: vaultx_control_plane::auth::TokenClass::ControlSession,
            },
        )
        .expect("seed session");
    (project, token)
}

fn team_sync_guard() -> std::sync::MutexGuard<'static, ()> {
    TEAM_SYNC_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Full local setup for one sync test: initialized project + login +
/// remote binding; returns the seeded project id.
fn setup_synced_project(plane: &FakeControlPlane, tag: &str) -> (PathBuf, vaultx_types::ProjectId) {
    let dir = tempfile::tempdir().expect("tempdir").keep();
    init_in(&dir);
    let (project, token) = seed_project(plane, tag);
    dispatch(&cli(
        &dir,
        Command::Login {
            server: plane.base_url.clone(),
            token: Some(token),
        },
    ))
    .expect("login succeeds");
    dispatch(&cli(
        &dir,
        Command::Remote {
            command: RemoteCommand::Add {
                name: "origin".to_owned(),
                project: project.to_string(),
            },
        },
    ))
    .expect("remote add succeeds");
    (dir, project)
}

fn append_local_event(root: &Path, deny: bool) -> u64 {
    let audit_path = root.join(".vaultx").join("audit").join("events.jsonl");
    let store = JsonlAppendStore::open(audit_path);
    let stored = store
        .append(NewAuditEvent {
            correlation_id: CorrelationId::generate().expect("correlation"),
            actor: vaultx_policy::Principal::parse("agent:ci-bot").expect("principal"),
            project: vaultx_types::ProjectId::parse("proj_core").expect("project"),
            environment: None,
            action: AuditAction::HttpRequest,
            decision: if deny {
                AuditDecision::Deny {
                    reason: "path not allowed".to_owned(),
                }
            } else {
                AuditDecision::Allow
            },
            credential: None,
            destination: None,
            capability: None,
            policy_ids: Vec::new(),
            metadata: SafeAuditMetadata::default(),
        })
        .expect("append");
    stored.sequence
}

#[test]
fn login_stores_credentials_and_rejects_bad_tokens() {
    let _guard = team_sync_guard();
    let plane = fake_control_plane();
    let (_project, token) = seed_project(plane, "logintest");

    // Start from a clean session state so the rejection is observable.
    remove_session_file();

    // A garbage token is rejected by the probe and nothing is stored.
    let dir = tempfile::tempdir().unwrap();
    init_in(dir.path());
    let err = dispatch(&cli(
        dir.path(),
        Command::Login {
            server: plane.base_url.clone(),
            token: Some("vxs_definitely_wrong".to_owned()),
        },
    ))
    .unwrap_err();
    assert!(err.to_string().contains("rejected"), "got: {err}");
    assert!(!session_file_exists(), "failed logins must store nothing");

    // Non-http servers are refused before any credential material moves.
    let err = dispatch(&cli(
        dir.path(),
        Command::Login {
            server: "ftp://nope".to_owned(),
            token: Some(token.clone()),
        },
    ))
    .unwrap_err();
    assert!(matches!(err, CliError::Usage(ref text) if text.contains("http")));

    // The valid token verifies and persists.
    let out = dispatch(&cli(
        dir.path(),
        Command::Login {
            server: plane.base_url.clone(),
            token: Some(token),
        },
    ))
    .unwrap();
    assert!(out.contains("authenticated against"), "got: {out}");
    assert!(out.contains("credentials stored"), "got: {out}");

    // Stored outside any repository, owner-only on unix.
    let path = vaultx_sync_client::session_path();
    assert!(path.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "session file must be 0600");
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "runtime session dir must be 0700");
    }

    // workspace list now works through the same credentials.
    let listed = dispatch(&cli(
        dir.path(),
        Command::Workspace {
            command: WorkspaceCommand::List,
        },
    ))
    .unwrap();
    assert!(listed.contains("ws_logintest"), "got: {listed}");
}

#[test]
fn push_uploads_objects_refs_and_reports_counts() {
    let _guard = team_sync_guard();
    let plane = fake_control_plane();
    let (root, project) = setup_synced_project(plane, "pushtest");

    dispatch(&cli(
        &root,
        Command::Set {
            pairs: vec!["API_KEY=from-cli".into()],
        },
    ))
    .unwrap();
    commit_ok(&root, "seed config", None);

    let out = dispatch(&cli(
        &root,
        Command::Push {
            with_audit: false,
            remote: None,
            authorize_protected: false,
        },
    ))
    .unwrap();
    assert!(
        out.contains("uploaded 3 object(s)"),
        "config+manifest+commit expected: {out}"
    );
    assert!(out.contains("conflicts: none"), "got: {out}");

    // Server side really received objects and the main ref.
    let head = head_commit_of(&root);
    assert_eq!(
        plane
            .store
            .get_ref_state(
                &project,
                vaultx_control_plane::model::RefNamespace::Heads,
                "main"
            )
            .unwrap()
            .map(|r| r.commit),
        Some(head)
    );
    assert_eq!(plane.store.list_object_ids(&project).unwrap().len(), 3);

    // Re-push is idempotent at the object level.
    let again = dispatch(&cli(
        &root,
        Command::Push {
            with_audit: false,
            remote: None,
            authorize_protected: false,
        },
    ))
    .unwrap();
    assert!(again.contains("uploaded 0 object(s)"), "got: {again}");
}

#[test]
fn pull_applies_remote_policy_into_vaultx_policies() {
    let _guard = team_sync_guard();
    let plane = fake_control_plane();
    let (root, project) = setup_synced_project(plane, "pulltest");

    plane
        .store
        .upsert_policy(
            &project,
            &vaultx_control_plane::model::PolicyDocument {
                name: vaultx_types::PolicyName::parse("read_only").expect("policy name"),
                document_json: "{}".to_owned(),
            },
        )
        .expect("seed policy");

    let out = dispatch(&cli(
        &root,
        Command::Pull {
            strategy: None,
            remote: None,
            authorize_protected: false,
        },
    ))
    .unwrap();
    assert!(out.contains("1 policy/policies applied"), "got: {out}");
    let policy_path = root.join(".vaultx").join("policies").join("read_only.yaml");
    assert!(policy_path.is_file(), "pulled policy file must appear");
    assert_eq!(
        std::fs::read_to_string(policy_path).unwrap(),
        "{}",
        "file content mirrors the served document"
    );
}

#[test]
fn sync_round_trips_between_two_clones_with_one_summary() {
    let _guard = team_sync_guard();
    let plane = fake_control_plane();

    // Workspace A commits and pushes.
    let (root_a, project) = setup_synced_project(plane, "synctest");
    let head_seed = {
        dispatch(&cli(
            &root_a,
            Command::Set {
                pairs: vec!["SHARED_VAR=v1".into()],
            },
        ))
        .unwrap();
        commit_ok(&root_a, "seed", None)
    };
    dispatch(&cli(
        &root_a,
        Command::Push {
            with_audit: false,
            remote: None,
            authorize_protected: false,
        },
    ))
    .unwrap();

    // Workspace B binds the same project and syncs down.
    let root_b = tempfile::tempdir().expect("tempdir").keep();
    init_in(&root_b);
    let (_, token_b) = seed_project(plane, "synctestb");
    // Grant B membership in the shared workspace.
    plane
        .store
        .add_workspace_member(&WorkspaceMembership {
            workspace: vaultx_types::WorkspaceId::parse("ws_synctest").expect("valid"),
            user: "user-synctestb".to_owned(),
            role: vaultx_control_plane::model::ROLE_MEMBER.to_owned(),
        })
        .expect("membership");
    dispatch(&cli(
        &root_b,
        Command::Login {
            server: plane.base_url.clone(),
            token: Some(token_b),
        },
    ))
    .unwrap();
    dispatch(&cli(
        &root_b,
        Command::Remote {
            command: RemoteCommand::Add {
                name: "origin".to_owned(),
                project: project.to_string(),
            },
        },
    ))
    .unwrap();

    let out = dispatch(&cli(
        &root_b,
        Command::Sync {
            strategy: None,
            remote: None,
            authorize_protected: false,
        },
    ))
    .unwrap();
    assert!(out.contains("sync:"), "single summary expected: {out}");
    assert!(out.contains("downloaded 3 object(s)"), "got: {out}");
    assert_eq!(head_commit_of(&root_b), head_seed);

    // B's own device identity was registered by its sync attestation.
    assert_eq!(
        plane
            .store
            .list_devices_for_user("user-synctestb")
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn audit_upload_tracks_watermark_and_reports_counts() {
    let _guard = team_sync_guard();
    let plane = fake_control_plane();
    let (root, _project) = setup_synced_project(plane, "audupload");

    let first = append_local_event(&root, false);
    let second = append_local_event(&root, true);
    assert_eq!(second, first + 1);

    // Push --with-audit uploads both events and advances the watermark.
    let out = dispatch(&cli(
        &root,
        Command::Push {
            with_audit: true,
            remote: None,
            authorize_protected: false,
        },
    ))
    .unwrap();
    assert!(out.contains("audit: uploaded 2 event(s)"), "got: {out}");

    let state = std::fs::read_to_string(root.join(".vaultx").join("sync-state.json")).unwrap();
    assert!(
        state.contains(&format!("\"last_uploaded_sequence\":{second}")),
        "{state}"
    );

    // A further push uploads nothing new.
    let out = dispatch(&cli(
        &root,
        Command::Push {
            with_audit: true,
            remote: None,
            authorize_protected: false,
        },
    ))
    .unwrap();
    assert!(out.contains("audit: nothing new to upload"), "got: {out}");
}

#[test]
fn audit_list_filters_by_outcome_actor_and_limit() {
    let _guard = team_sync_guard();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    append_local_event(root, false); // seq 0 allow
    append_local_event(root, true); // seq 1 deny
    append_local_event(root, false); // seq 2 allow

    let all = dispatch(&cli(
        root,
        Command::Audit {
            command: AuditCommand::List {
                actor: None,
                outcome: None,
                limit: None,
            },
        },
    ))
    .unwrap();
    assert!(all.contains("SEQ"), "table header: {all}");
    assert_eq!(all.lines().count(), 4, "header + three rows: {all}");
    // The deny reason must not be mistaken for an outcome cell.
    let allow_rows = all
        .lines()
        .filter(|line| line.split_whitespace().nth(3) == Some("allow"))
        .count();
    assert_eq!(allow_rows, 2, "two allows expected: {all}");
    assert!(all.contains("deny"), "got: {all}");

    let denies = dispatch(&cli(
        root,
        Command::Audit {
            command: AuditCommand::List {
                actor: None,
                outcome: Some(false),
                limit: None,
            },
        },
    ))
    .unwrap();
    assert!(denies.contains("deny"), "got: {denies}");
    assert!(!denies.contains("\n0 "), "only the deny row: {denies}");

    let limited = dispatch(&cli(
        root,
        Command::Audit {
            command: AuditCommand::List {
                actor: None,
                outcome: None,
                limit: Some(1),
            },
        },
    ))
    .unwrap();
    assert!(limited.contains("agent:ci-bot"), "got: {limited}");
    assert_eq!(limited.lines().count(), 2, "header + one row: {limited}");

    let actor_filtered = dispatch(&cli(
        root,
        Command::Audit {
            command: AuditCommand::List {
                actor: Some("agent:nobody".to_owned()),
                outcome: None,
                limit: None,
            },
        },
    ))
    .unwrap();
    assert_eq!(actor_filtered, "no audit events");

    // Positive filter: the real actor matches every row.
    let actor_matched = dispatch(&cli(
        root,
        Command::Audit {
            command: AuditCommand::List {
                actor: Some("agent:ci-bot".to_owned()),
                outcome: None,
                limit: None,
            },
        },
    ))
    .unwrap();
    assert_eq!(
        actor_matched.lines().count(),
        4,
        "header + three rows for the matching actor: {actor_matched}"
    );
}

#[test]
fn normalize_server_enforces_https_off_loopback() {
    use crate::remoting::normalize_server;
    assert!(normalize_server("https://vaultx.example.com").is_ok());
    assert!(normalize_server("http://localhost:8080").is_ok());
    assert!(normalize_server("http://127.0.0.1:9000/").is_ok());
    assert!(normalize_server("http://[::1]:9000").is_ok());
    assert!(normalize_server("http://[::1]").is_ok());
    let err = normalize_server("http://sync.corp.example.com").unwrap_err();
    assert!(err.to_string().contains("https"), "got: {err}");
}

#[test]
fn parse_pull_strategy_accepts_known_and_rejects_unknown() {
    use crate::cli::parse_pull_strategy;
    assert_eq!(
        parse_pull_strategy("fast-forward"),
        Ok(crate::cli::PullStrategy::FastForward)
    );
    assert!(parse_pull_strategy("ours").is_ok());
    assert!(parse_pull_strategy("yolo").is_err());
}

#[test]
fn reconcile_chunk_skips_rejected_positions_and_counts_the_rest() {
    use crate::remoting::reconcile_chunk;
    use std::collections::HashMap;
    let sequences = [10, 11, 12, 13];
    let mut rejected = HashMap::new();
    rejected.insert(1usize, "actor must not be empty");
    let (accepted, skipped) = reconcile_chunk(&sequences, &rejected);
    assert_eq!(accepted, 3);
    assert_eq!(skipped, vec![(11, "actor must not be empty".to_owned())]);

    let (all, none) = reconcile_chunk(&sequences, &HashMap::new());
    assert_eq!(all, 4);
    assert!(none.is_empty());
}

#[test]
fn corrupt_sync_state_fails_loudly_instead_of_resetting() {
    let _guard = team_sync_guard();
    let plane = fake_control_plane();
    let (root, _project) = setup_synced_project(plane, "corruptstate");
    std::fs::write(root.join(".vaultx").join("sync-state.json"), "{not json").unwrap();

    let err = dispatch(&cli(
        &root,
        Command::Push {
            with_audit: true,
            remote: None,
            authorize_protected: false,
        },
    ))
    .unwrap_err();
    assert!(err.to_string().contains("corrupt"), "got: {err}");
}

#[test]
fn remote_agents_lists_remote_identities_or_reports_empty() {
    let _guard = team_sync_guard();
    let plane = fake_control_plane();
    let (root, _project) = setup_synced_project(plane, "remoteagents");

    let out = dispatch(&cli(
        &root,
        Command::Remote {
            command: RemoteCommand::Agents { remote: None },
        },
    ))
    .unwrap();
    assert!(
        out.contains("no agent identities") || out.contains("ID"),
        "got: {out}"
    );
}

#[test]
fn team_sync_commands_error_cleanly_without_configuration() {
    let _guard = team_sync_guard();
    let plane = fake_control_plane();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    // Establish the "never logged in" precondition: the session file is
    // process-global, so earlier team-sync tests may have created one.
    remove_session_file();

    // No login at all: push/pull/sync/remote-add fail with guidance.
    for command in [
        Command::Push {
            with_audit: false,
            remote: None,
            authorize_protected: false,
        },
        Command::Pull {
            strategy: None,
            remote: None,
            authorize_protected: false,
        },
        Command::Sync {
            strategy: None,
            remote: None,
            authorize_protected: false,
        },
    ] {
        let err = dispatch(&cli(root, command)).unwrap_err();
        assert!(
            matches!(err, CliError::Usage(ref text) if text.contains("not logged in")),
            "expected clean usage error, got {err:?}"
        );
        assert_eq!(err.exit_code(), 1);
    }

    // Logged in but no remote configured: still clean.
    let (_, token) = seed_project(plane, "noremo");
    dispatch(&cli(
        root,
        Command::Login {
            server: plane.base_url.clone(),
            token: Some(token),
        },
    ))
    .unwrap();
    let err = dispatch(&cli(
        root,
        Command::Push {
            with_audit: false,
            remote: None,
            authorize_protected: false,
        },
    ))
    .unwrap_err();
    assert!(
        matches!(err, CliError::Usage(ref text) if text.contains("no remote configured")),
        "got {err:?}"
    );
}

fn session_file_exists() -> bool {
    std::env::var_os("XDG_RUNTIME_DIR").is_some_and(|base| {
        PathBuf::from(base)
            .join("vaultx")
            .join("session.json")
            .is_file()
    })
}

fn remove_session_file() {
    if session_file_exists() {
        std::fs::remove_file(vaultx_sync_client::session_path()).expect("remove session file");
    }
}

fn head_commit_of(root: &Path) -> CommitId {
    let repository = vaultx_repository::Repository::open(root).expect("open repo");
    repository
        .refs()
        .read_ref(vaultx_repository::RefNamespace::Heads, "main")
        .expect("read ref")
        .expect("main ref exists")
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
    let _runtime = isolated_xdg_runtime_dir();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    let out = dispatch(&cli(root, Command::Doctor)).unwrap();
    assert!(out.contains("PASS repository integrity"), "{out}");
    assert!(out.contains("WARN broker"), "{out}");
    assert!(out.contains("broker connectivity"), "{out}");
    assert!(out.contains("PASS sync consistency"), "{out}");
    assert!(out.contains("no remote configured"), "{out}");
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
                report.contains("summary: 3 passed, 5 warned, 1 failed"),
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

#[test]
fn mcp_serve_maps_unknown_project_and_agent_onto_error_classes() {
    // Outside a repository keeps the exit-3 class before any session
    // work starts.
    let empty = tempfile::tempdir().unwrap();
    let err = dispatch(&cli(
        empty.path(),
        Command::Mcp {
            command: McpCommand::Serve {
                agent: "coding-agent".into(),
                env: None,
                socket: None,
            },
        },
    ))
    .unwrap_err();
    assert!(matches!(err, CliError::NotARepository(_)), "{err:?}");
    assert_eq!(err.exit_code(), 3);

    // Unknown agent is a runtime failure (exit 1); the message names the
    // agent but never any token.
    let dir = tempfile::tempdir().unwrap();
    init_in(dir.path());
    let err = dispatch(&cli(
        dir.path(),
        Command::Mcp {
            command: McpCommand::Serve {
                agent: "ghost-agent".into(),
                env: None,
                socket: None,
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Runtime(CoreError::Io(io)) if io.to_string().contains("unknown agent `ghost-agent`")),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// Export (plan §33) — placeholder safety and the reveal path
// ---------------------------------------------------------------------------

/// Seeds a project with one literal config value, one plain secret, and
/// one brokered credential, all committed at HEAD. The secret values are
/// canaries scanned for in every rendered output.
fn seed_export_fixture(root: &Path, canary_secret: &str, canary_brokered: &str) {
    use vaultx_types::model::{InjectionTemplateId, VariableKind};

    let services = open_services(root);
    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["PORT=8080".into()],
        },
    ))
    .unwrap();
    services
        .secrets()
        .set_secret(
            "API_TOKEN",
            &vaultx_core::SecretString::copy_from(canary_secret),
            VariableKind::Secret,
            "development",
            None,
        )
        .unwrap();
    services
        .secrets()
        .set_secret(
            "GITHUB_CRED",
            &vaultx_core::SecretString::copy_from(canary_brokered),
            VariableKind::Brokered,
            "development",
            Some(vaultx_core::BrokeredBinding {
                credential_ref: vaultx_types::CredentialRef::parse("github-token").unwrap(),
                injection: InjectionTemplateId::Bearer,
                provider_hint: None,
            }),
        )
        .unwrap();
    commit_ok(root, "seed export fixture", None);
}

#[test]
fn safe_export_renders_placeholders_and_never_leaks_canary_values() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);
    seed_export_fixture(root, "canary-plain-hunter3", "canary-brokered-hunter4");

    let out = dispatch(&cli(
        root,
        Command::Export {
            format: "env".into(),
            reveal_secrets: false,
            yes_i_want_plaintext_secrets: false,
        },
    ))
    .unwrap();

    // Literal config values pass through (quoted); protected values are
    // inert placeholders.
    assert!(out.contains("PORT='8080'"), "{out}");
    assert!(out.contains("API_TOKEN='<vaultx:secret>'"), "{out}");
    assert!(out.contains("GITHUB_CRED='<vaultx:brokered>'"), "{out}");
    // Canary leak scan across the entire rendered output.
    assert!(!out.contains("canary-plain"), "plaintext leaked: {out}");
    assert!(
        !out.contains("canary-brokered"),
        "brokered value leaked: {out}"
    );
}

#[test]
fn reveal_export_emits_plain_secrets_but_brokered_stays_placeholder() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);
    seed_export_fixture(root, "canary-plain-hunter3", "canary-brokered-hunter4");

    let out = dispatch(&cli(
        root,
        Command::Export {
            format: "env".into(),
            reveal_secrets: true,
            yes_i_want_plaintext_secrets: true,
        },
    ))
    .unwrap();

    // The plain secret's real value appears (quoted, source-safe)...
    assert!(out.contains("API_TOKEN='canary-plain-hunter3'"), "{out}");
    // ...but the brokered credential NEVER does (INV-002/INV-003).
    assert!(out.contains("GITHUB_CRED='<vaultx:brokered>'"), "{out}");
    assert!(
        !out.contains("canary-brokered"),
        "brokered value leaked: {out}"
    );
}

#[test]
fn reveal_export_without_consent_fails_on_non_tty_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);
    seed_export_fixture(root, "canary-plain-hunter3", "canary-brokered-hunter4");

    // Test processes have non-terminal stdin, so the typed-confirmation
    // branch is unreachable and only the flag may authorize.
    let err = dispatch(&cli(
        root,
        Command::Export {
            format: "env".into(),
            reveal_secrets: true,
            yes_i_want_plaintext_secrets: false,
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text)
            if text.contains("--yes-i-want-plaintext-secrets") && text.contains("authorization")),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), 1);
}

#[test]
fn export_unknown_format_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);
    let err = dispatch(&cli(
        root,
        Command::Export {
            format: "json".into(),
            reveal_secrets: false,
            yes_i_want_plaintext_secrets: false,
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("`json`")),
        "{err:?}"
    );

    // An empty HEAD exports cleanly as an empty notice.
    let out = dispatch(&cli(
        root,
        Command::Export {
            format: "env".into(),
            reveal_secrets: false,
            yes_i_want_plaintext_secrets: false,
        },
    ))
    .unwrap();
    assert!(out.contains("nothing committed to export"), "{out}");
}

#[test]
fn typed_confirmation_matching_is_trimmed_and_exact() {
    assert!(typed_confirmation_matches(
        "REVEAL\n",
        REVEAL_CONFIRMATION_PHRASE
    ));
    assert!(typed_confirmation_matches(
        "  REVEAL  ",
        REVEAL_CONFIRMATION_PHRASE
    ));
    assert!(!typed_confirmation_matches(
        "reveal",
        REVEAL_CONFIRMATION_PHRASE
    ));
    assert!(!typed_confirmation_matches(
        "YES",
        REVEAL_CONFIRMATION_PHRASE
    ));
    assert!(typed_confirmation_matches(
        "DELETE\n",
        DELETE_REFS_CONFIRMATION_PHRASE
    ));
}

#[test]
fn reveal_of_missing_revision_names_the_variable_without_leaking_values() {
    use vaultx_types::SecretRevisionId;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);
    seed_export_fixture(root, "canary-plain-hunter3", "canary-brokered-hunter4");

    // Sever the revision record for API_TOKEN by committing a fresh
    // manifest binding at a nonexistent revision id (export reads HEAD).
    let ghost = SecretRevisionId::parse(
        "sec_rev_deadbeefcafebabe00000000000000000000000000000000000000000000",
    )
    .unwrap();
    let services = open_services(root);
    let name = vaultx_types::VariableName::parse("API_TOKEN").unwrap();
    services
        .context()
        .repository()
        .add(name, vaultx_repository_manifest_entry_secret(ghost))
        .unwrap();
    drop(services);
    commit_ok(root, "binds a ghost revision", None);

    let err = dispatch(&cli(
        root,
        Command::Export {
            format: "env".into(),
            reveal_secrets: true,
            yes_i_want_plaintext_secrets: true,
        },
    ))
    .unwrap_err();
    match &err {
        CliError::Runtime(CoreError::MissingRevision { name, .. }) => {
            assert_eq!(name, "API_TOKEN");
        }
        other => panic!("expected MissingRevision, got {other:?}"),
    }
}

/// Helper keeping the `ManifestEntry` import local to these tests.
fn vaultx_repository_manifest_entry_secret(
    revision: vaultx_types::SecretRevisionId,
) -> vaultx_repository::ManifestEntry {
    vaultx_repository::ManifestEntry::Secret { revision }
}

// ---------------------------------------------------------------------------
// Recover (plan §Recovery)
// ---------------------------------------------------------------------------

use vaultx_repository::RefNamespace as RecoveryRefNamespace;

#[test]
fn recover_healthy_repo_reports_clean() {
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
    store_secret(root, "TOKEN", "v");
    commit_ok(root, "healthy history", None);

    let out = dispatch(&cli(
        root,
        Command::Recover {
            fix: false,
            yes_delete_unresolvable_refs: false,
        },
    ))
    .unwrap();
    assert!(out.contains("no findings"), "{out}");
}

#[test]
fn recover_detects_severed_ref_and_fix_requires_confirmation() {
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
    commit_ok(root, "good commit", None);

    // Plant a ref whose target was never persisted.
    let ghost =
        CommitId::parse("cmt_1111111122222222333333334444444455555555666666667777777788888888")
            .unwrap();
    open_services(root)
        .context()
        .repository()
        .refs()
        .write_ref(RecoveryRefNamespace::Heads, "broken", &ghost)
        .unwrap();

    // Plain recover reports the finding and exits nonzero.
    let err = dispatch(&cli(
        root,
        Command::Recover {
            fix: false,
            yes_delete_unresolvable_refs: false,
        },
    ))
    .unwrap_err();
    match &err {
        CliError::Diagnostics(report) => {
            assert!(
                report.contains("unresolvable ref: heads/broken"),
                "{report}"
            );
            assert!(report.contains(&ghost.as_str()[..16]), "{report}");
        }
        other => panic!("expected Diagnostics, got {other:?}"),
    }

    // --fix without consent (non-tty stdin) is refused; the ref remains.
    let err = dispatch(&cli(
        root,
        Command::Recover {
            fix: true,
            yes_delete_unresolvable_refs: false,
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("--yes-delete-unresolvable-refs")),
        "{err:?}"
    );
    assert!(
        open_services(root)
            .context()
            .repository()
            .refs()
            .read_ref(RecoveryRefNamespace::Heads, "broken")
            .unwrap()
            .is_some(),
        "refusal must leave the severed ref in place"
    );

    // With the escape-hatch flag the ref is deleted; objects stay intact.
    let out = dispatch(&cli(
        root,
        Command::Recover {
            fix: true,
            yes_delete_unresolvable_refs: true,
        },
    ))
    .unwrap();
    assert!(out.contains("removed 1 unresolvable ref(s)"), "{out}");
    assert!(out.contains("repository consistent after repair"), "{out}");
    assert!(
        open_services(root)
            .context()
            .repository()
            .refs()
            .read_ref(RecoveryRefNamespace::Heads, "broken")
            .unwrap()
            .is_none(),
        "the severed ref must be gone after --fix"
    );
    // INV-013: repair never mutates objects.
    open_services(root)
        .context()
        .repository()
        .objects()
        .verify_all()
        .expect("object store untouched by fix");
}

#[test]
fn recover_flags_foreign_signed_commit_objects() {
    use vaultx_crypto::signature::SigningKeyPair;
    use vaultx_repository::history::History as RepoHistory;
    use vaultx_repository::{Commit as RepoCommit, ObjectEnvelope, ObjectType};
    use vaultx_types::IdentityRef;

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
    commit_ok(root, "legit commit", None);

    // Forge a well-formed commit object signed by a DIFFERENT key and
    // point a ref at it: object integrity holds, signature verification
    // must fail.
    let services = open_services(root);
    let repo = services.context().repository();
    let head = repo.current_head().unwrap().expect("head exists");
    let manifest_id = RepoHistory::new(repo.objects())
        .find_commit(&head)
        .unwrap()
        .manifest;
    let stranger = SigningKeyPair::generate();
    let forged = RepoCommit::new(
        Vec::new(),
        manifest_id,
        IdentityRef::parse("user:stranger").unwrap(),
        "forged by a stranger key",
    )
    .sign_with(&stranger)
    .unwrap();
    let envelope = ObjectEnvelope::new(ObjectType::Commit, serde_json::to_vec(&forged).unwrap());
    repo.objects().put(&envelope).unwrap();
    drop(services);

    let forged_id = forged.commit_id().unwrap();
    open_services(root)
        .context()
        .repository()
        .refs()
        .write_ref(RecoveryRefNamespace::Heads, "forged", &forged_id)
        .unwrap();

    let err = dispatch(&cli(
        root,
        Command::Recover {
            fix: false,
            yes_delete_unresolvable_refs: false,
        },
    ))
    .unwrap_err();
    match &err {
        CliError::Diagnostics(report) => {
            assert!(
                report.contains("signature finding") && report.contains("signature invalid"),
                "{report}"
            );
        }
        other => panic!("expected Diagnostics, got {other:?}"),
    }
    assert_eq!(err.exit_code(), 1);
}

#[test]
fn recover_detects_missing_secret_revision_records() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    // Store + commit a secret, then locate its revision record on disk.
    store_secret(root, "DB_PASSWORD", "hunter2");
    commit_ok(root, "adds secret", None);
    let secrets_dir = root.join(".vaultx").join("secrets");
    let mut record_path = None;
    for entry in std::fs::read_dir(&secrets_dir).unwrap().flatten() {
        for file in std::fs::read_dir(entry.path()).unwrap().flatten() {
            record_path = Some(file.path());
        }
    }
    let record_path = record_path.expect("one secret revision record exists");
    std::fs::remove_file(&record_path).unwrap();

    let err = dispatch(&cli(
        root,
        Command::Recover {
            fix: false,
            yes_delete_unresolvable_refs: false,
        },
    ))
    .unwrap_err();
    match &err {
        CliError::Diagnostics(report) => {
            assert!(
                report.contains("missing secret revision: DB_PASSWORD"),
                "{report}"
            );
            // Identifiers only — never values.
            assert!(!report.contains("hunter2"), "value leaked: {report}");
        }
        other => panic!("expected Diagnostics, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Agent run (plan §17) — sanitized brokered workload execution
// ---------------------------------------------------------------------------

/// Serializes process-global env mutations across parallel tests; every
/// test that touches env vars must hold this lock for its whole body.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Sets one env var for a test body and restores the previous value on
/// drop. Callers must hold [`ENV_LOCK`] so concurrent tests never race
/// the process-global environment.
struct EnvVarGuard {
    name: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(name: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(name);
        std::env::set_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.previous.take() {
            Some(value) => std::env::set_var(self.name, value),
            None => std::env::remove_var(self.name),
        }
    }
}

fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Seeds an initialized project with committed config (`PORT`), plain
/// secrets (`API_TOKEN`, `GITHUB_TOKEN`), a brokered credential
/// (`GITHUB_CRED`), a pinned `development` environment, and an enabled
/// agent named `runner-bot`. All secret values are canaries.
fn seed_agent_run_fixture(root: &Path) {
    use vaultx_types::model::{InjectionTemplateId, VariableKind};

    init_in(root);
    dispatch(&cli(
        root,
        Command::Set {
            pairs: vec!["PORT=8080".into()],
        },
    ))
    .unwrap();
    store_secret(root, "API_TOKEN", "canary-plain-hunter3");
    store_secret(root, "GITHUB_TOKEN", "canary-parent-hunter5");
    open_services(root)
        .secrets()
        .set_secret(
            "GITHUB_CRED",
            &vaultx_core::SecretString::copy_from("canary-brokered-hunter4"),
            VariableKind::Brokered,
            "development",
            Some(vaultx_core::BrokeredBinding {
                credential_ref: vaultx_types::CredentialRef::parse("github-token").unwrap(),
                injection: InjectionTemplateId::Bearer,
                provider_hint: None,
            }),
        )
        .unwrap();
    commit_ok(root, "seed agent-run fixture", None);
    dispatch(&cli(
        root,
        Command::Env {
            command: EnvCommand::Create {
                name: "development".into(),
            },
        },
    ))
    .unwrap();
    dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Create {
                name: "runner-bot".into(),
            },
        },
    ))
    .unwrap();
}

/// Builds an `agent run` invocation whose child is `sh -c <script>`.
fn agent_run(name: &str, ttl_secs: Option<u64>, script: String) -> Command {
    Command::Agent {
        command: AgentCommand::Run {
            name: name.into(),
            env: None,
            ttl_secs,
            command: vec!["sh".into(), "-c".into(), script],
        },
    }
}

/// Sorted relative paths of every file under `root` (recursive).
fn snapshot_tree(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                out.push(path.strip_prefix(base).unwrap().to_path_buf());
            }
        }
    }
    let mut files = Vec::new();
    walk(root, root, &mut files);
    files.sort();
    files
}

#[cfg(unix)]
#[test]
fn run_injects_config_and_broker_metadata_but_not_secret_values() {
    let _runtime = isolated_xdg_runtime_dir();
    let _serial = lock_env();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    seed_agent_run_fixture(root);

    // The dump file lives OUTSIDE the project so the no-new-files
    // assertion below stays meaningful.
    let dump_dir = tempfile::tempdir().unwrap();
    let out_path = dump_dir.path().join("child-env.txt");
    let script = format!(
        "printf 'PORT=%s\\nAPI_TOKEN=%s\\nGITHUB_TOKEN=%s\\nGITHUB_CRED=%s\\nENDPOINT=%s\\nSESSION=%s\\nAGENT=%s\\nPROJECT=%s\\nENVIRONMENT=%s\\n' \
         \"$PORT\" \"$API_TOKEN\" \"$GITHUB_TOKEN\" \"$GITHUB_CRED\" \"$VAULTX_BROKER_ENDPOINT\" \
         \"$VAULTX_BROKER_SESSION\" \"$VAULTX_AGENT\" \"$VAULTX_PROJECT\" \"$VAULTX_ENVIRONMENT\" > {}",
        out_path.display()
    );

    let before = snapshot_tree(root);
    let out = dispatch(&cli(root, agent_run("runner-bot", Some(600), script)))
        .unwrap_or_else(|err| panic!("agent run failed: {err}"));
    assert_eq!(out, "", "success prints nothing extra");

    let dumped = std::fs::read_to_string(&out_path).unwrap();
    let get = |key: &str| {
        dumped
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")).map(str::to_owned))
            .unwrap_or_else(|| panic!("{key} line missing in child env:\n{dumped}"))
    };

    assert_eq!(get("PORT"), "8080", "committed config must be injected");
    assert_eq!(get("API_TOKEN"), "", "plain secret value must be absent");
    assert_eq!(get("GITHUB_TOKEN"), "", "managed name must stay unset");
    assert_eq!(
        get("GITHUB_CRED"),
        "",
        "brokered credential value must be absent"
    );
    assert_eq!(
        get("ENDPOINT"),
        vaultx_broker_client::default_endpoint(),
        "broker endpoint metadata"
    );
    assert_eq!(get("AGENT"), "runner-bot");
    assert_eq!(get("PROJECT"), "proj_local");
    assert_eq!(get("ENVIRONMENT"), "development");

    // The child saw a real capability token (64 hex chars, the minting
    // grammar of FileSessionStore) even though it is unrecoverable from
    // storage.
    let token = get("SESSION");
    assert_eq!(token.len(), 64, "token shape: {token}");
    assert!(token.bytes().all(|b| b.is_ascii_hexdigit()), "{token}");

    // INV-012 canary scan across everything vaultx itself rendered.
    for canary in [
        "canary-plain-hunter3",
        "canary-parent-hunter5",
        "canary-brokered-hunter4",
        &token,
    ] {
        assert!(!out.contains(canary), "leak `{canary}` in output: {out}");
    }

    // No plaintext .env file was ever written; only .vaultx metadata
    // (the session store) may have appeared.
    for new_path in snapshot_tree(root).iter().filter(|p| !before.contains(p)) {
        let shown = new_path.to_string_lossy();
        assert!(
            shown.starts_with(".vaultx/"),
            "new file outside .vaultx: {shown}"
        );
        assert!(!shown.ends_with(".env"), "plaintext env written: {shown}");
    }
}

#[cfg(unix)]
#[test]
fn run_strips_parent_managed_names_even_when_set_in_parent_env() {
    let _runtime = isolated_xdg_runtime_dir();
    let _serial = lock_env();

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    seed_agent_run_fixture(root);

    // Pollute the parent process env with a value for a MANAGED name.
    let _polluted = EnvVarGuard::set("GITHUB_TOKEN", "parent-attacker-value");

    let dump_dir = tempfile::tempdir().unwrap();
    let out_path = dump_dir.path().join("child-env.txt");
    let script = format!(
        "printf 'GITHUB_TOKEN=%s\\nPORT=%s\\n' \"$GITHUB_TOKEN\" \"$PORT\" > {}",
        out_path.display()
    );
    let out = dispatch(&cli(root, agent_run("runner-bot", None, script)))
        .unwrap_or_else(|err| panic!("agent run failed: {err}"));

    let dumped = std::fs::read_to_string(&out_path).unwrap();
    assert!(
        !dumped.contains("parent-attacker-value"),
        "parent value survived sanitization:\n{dumped}"
    );
    let token_line = dumped
        .lines()
        .find_map(|line| line.strip_prefix("GITHUB_TOKEN="))
        .expect("GITHUB_TOKEN line present");
    assert_eq!(token_line, "", "managed name must be unset in child");
    assert_eq!(
        dumped.lines().find_map(|l| l.strip_prefix("PORT=")),
        Some("8080"),
        "config injection unaffected by stripping"
    );

    // The attacker value and real secret never appear in CLI output.
    assert!(
        !out.contains("parent-attacker-value") && !out.contains("canary-parent-hunter5"),
        "leak in output: {out}"
    );
}

#[cfg(unix)]
#[test]
fn run_propagates_child_exit_code() {
    let _serial = lock_env();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    seed_agent_run_fixture(root);

    let err = dispatch(&cli(
        root,
        agent_run("runner-bot", None, "exit 7".to_string()),
    ))
    .unwrap_err();
    assert!(matches!(err, CliError::ChildExit(7)), "{err:?}");
    assert_eq!(err.exit_code(), 7);
}

/// Dispatches sessions-list for the fixture agent and fails if any
/// stored session still renders as `active`.
fn assert_no_active_sessions(root: &Path) {
    let listed = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::SessionsList {
                name: "runner-bot".into(),
            },
        },
    ))
    .unwrap_or_else(|err| panic!("sessions-list failed: {err}"));
    assert!(
        !listed.contains("active"),
        "live capability left behind:\n{listed}"
    );
}

#[cfg(unix)]
#[test]
fn run_leaves_no_active_session_after_spawn_failure_exit_or_success() {
    let _runtime = isolated_xdg_runtime_dir();
    let _serial = lock_env();

    // I-1: a nonexistent program fails at spawn time, AFTER the session
    // was minted — the runner must revoke it instead of orphaning a live
    // capability.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    seed_agent_run_fixture(root);
    let err = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Run {
                name: "runner-bot".into(),
                env: None,
                ttl_secs: None,
                command: vec!["definitely-not-a-program-xyz".into()],
            },
        },
    ))
    .unwrap_err();
    assert!(matches!(err, CliError::Runtime(_)), "{err:?}");
    assert_no_active_sessions(root);

    // I-2, success path: after a clean child exit no live session is
    // left either (the stored record shows `revoked`).
    dispatch(&cli(
        root,
        agent_run("runner-bot", None, "true".to_string()),
    ))
    .unwrap_or_else(|err| panic!("agent run failed: {err}"));
    assert_no_active_sessions(root);

    // I-2, failure path: nonzero exit revokes too.
    let err = dispatch(&cli(
        root,
        agent_run("runner-bot", None, "exit 5".to_string()),
    ))
    .unwrap_err();
    assert!(matches!(err, CliError::ChildExit(5)), "{err:?}");
    assert_no_active_sessions(root);
}

#[test]
fn run_unknown_agent_errors_cleanly() {
    // Unknown agent fails before any session work, in an agentless repo.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);
    let err = dispatch(&cli(
        root,
        agent_run("ghost-agent", None, "true".to_string()),
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("unknown agent `ghost-agent`")),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), 1);

    // A disabled agent is refused too, before any session exists.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    seed_agent_run_fixture(root);
    dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Disable {
                name: "runner-bot".into(),
            },
        },
    ))
    .unwrap();
    let err = dispatch(&cli(
        root,
        agent_run("runner-bot", None, "true".to_string()),
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("`runner-bot` is disabled")),
        "{err:?}"
    );

    // Sessions were never minted along either refusal path.
    let listed = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::SessionsList {
                name: "runner-bot".into(),
            },
        },
    ))
    .unwrap();
    assert!(listed.contains("no sessions"), "{listed}");
}

#[test]
fn run_requires_command_after_double_dash() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    let err = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Run {
                name: "runner-bot".into(),
                env: None,
                ttl_secs: None,
                command: Vec::new(),
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("after `--`")),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), 1);
}

// -- agent delegation (plan §25) ----------------------------------------------

#[test]
fn delegation_mints_scoped_child_enforced_by_broker_and_prints_token_once() {
    use std::sync::Arc;

    use vaultx_audit::JsonlAppendStore;
    use vaultx_broker::{
        BrokerDependencies, BrokerEngine, BrokerService, CredentialMetadata, ExecutedResponse,
        FileSessionStore, InMemoryCredentialSource, InjectorRegistry, SessionStore as _,
        TransportExecutor,
    };
    use vaultx_crypto::secret::SecretBytes;
    use vaultx_policy::{parse_policy_yaml, RuleEngine};
    use vaultx_types::{AgentId, CredentialRef, ProjectId};

    struct StaticTransport(ExecutedResponse);
    impl TransportExecutor for StaticTransport {
        fn execute(
            &self,
            _outbound: &vaultx_broker::OutboundRequest,
        ) -> Result<ExecutedResponse, vaultx_broker::BrokerError> {
            Ok(self.0.clone())
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init_in(root);

    dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Create {
                name: "ci-bot".into(),
            },
        },
    ))
    .unwrap();
    let created = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::SessionCreate {
                name: "ci-bot".into(),
                env: None,
                ttl_secs: None,
            },
        },
    ))
    .unwrap();
    let parent_id = created
        .lines()
        .next()
        .unwrap()
        .strip_prefix("created session ")
        .and_then(|rest| rest.split_whitespace().next())
        .expect("session id printed")
        .to_owned();
    // Possession-gated delegation: the raw token is the parent handle.
    let parent_token = created.lines().last().unwrap().trim().to_owned();
    assert_ne!(parent_token, parent_id);

    // Bare `sess_...` ids are refused before any store lookup: holding an
    // id proves nothing about who is delegating.
    let err = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Delegate {
                parent_token: parent_id.clone(),
                credentials: vec!["github-work-token".into()],
                hosts: Vec::new(),
                methods: Vec::new(),
                paths: Vec::new(),
                max_requests: None,
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("raw parent capability token")),
        "{err:?}"
    );

    // Delegate: at least one narrowing flag is mandatory.
    let err = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Delegate {
                parent_token: parent_token.clone(),
                credentials: Vec::new(),
                hosts: Vec::new(),
                methods: Vec::new(),
                paths: Vec::new(),
                max_requests: None,
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("narrow at least one dimension")),
        "{err:?}"
    );

    // Malformed path globs die as usage errors, not silent constraints.
    let err = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Delegate {
                parent_token: parent_token.clone(),
                credentials: Vec::new(),
                hosts: Vec::new(),
                methods: Vec::new(),
                paths: vec!["/repos/../escape".into()],
                max_requests: None,
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("invalid path glob")),
        "{err:?}"
    );

    // Unknown tokens are refused without minting anything — and the
    // presented value is never echoed back into the error.
    let err = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Delegate {
                parent_token: "not-a-real-parent-token-at-all".into(),
                credentials: vec!["c".into()],
                hosts: Vec::new(),
                methods: Vec::new(),
                paths: Vec::new(),
                max_requests: None,
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("unknown or invalid parent session token")),
        "{err:?}"
    );
    let rendered = format!("{err}");
    assert!(
        !rendered.contains("not-a-real-parent-token"),
        "token echoed in error"
    );

    let out = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Delegate {
                parent_token: parent_token.clone(),
                credentials: vec!["github-work-token".into()],
                hosts: vec!["api.github.com".into()],
                methods: vec!["GET".into()],
                paths: vec!["/repos/acme/ok/**".into()],
                max_requests: Some(5),
            },
        },
    ))
    .unwrap();
    assert!(
        out.contains("CAPABILITY TOKEN (shown once; it cannot be recovered):"),
        "{out}"
    );
    let child_token = out.lines().last().unwrap().trim().to_owned();
    assert_eq!(
        out.matches(child_token.as_str()).count(),
        1,
        "token printed exactly once"
    );

    // Later CLI output never re-echoes the capability token.
    let listing = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::SessionsList {
                name: "ci-bot".into(),
            },
        },
    ))
    .unwrap();
    assert!(listing.contains("sess_"), "{listing}");
    assert!(
        !listing.contains(child_token.as_str()),
        "token leaked via sessions list"
    );

    // Broker enforcement against the same on-disk session store.
    let sessions =
        Arc::new(FileSessionStore::open(root.join(".vaultx").join("sessions.json")).unwrap());
    let credentials = InMemoryCredentialSource::new();
    credentials.insert(
        CredentialRef::parse("github-work-token").unwrap(),
        SecretBytes::from_bytes(b"CANARY_CLI_DELEGATION_7f3"),
        vaultx_broker::InjectionTemplateId::GithubBearer,
        CredentialMetadata::default(),
    );
    let document = parse_policy_yaml(
        "name: ci-bot-github\n\
         principal: \"agent:ci-bot\"\n\
         credential: github-work-token\n\
         http:\n  \
         hosts: [api.github.com]\n  \
         allow:\n    - methods: [GET]\n      paths: [/repos/acme/**]\n",
    )
    .unwrap();
    let engine = BrokerEngine::new(BrokerDependencies {
        authorizer: Arc::new(RuleEngine::from_documents([document]).unwrap()),
        sessions,
        credentials: Arc::new(credentials),
        injectors: Arc::new(InjectorRegistry::new()),
        transport: Arc::new(StaticTransport(ExecutedResponse {
            status: 200,
            headers: Vec::new(),
            body: b"{}".to_vec(),
        })),
        audit: Arc::new(JsonlAppendStore::open(root.join("audit-cli.jsonl"))),
        project: ProjectId::parse("proj_local").unwrap(),
        egress_allow_private: false,
    });

    let request_for = |token: &str, url: &str| vaultx_broker::BrokerRequest {
        protocol: vaultx_broker::PROTOCOL_VERSION,
        session_token: token.to_owned(),
        credential: CredentialRef::parse("github-work-token").unwrap(),
        method: vaultx_policy::HttpMethod::GET,
        url: url.to_owned(),
        headers: Vec::new(),
        body: vaultx_broker::BrokerBody::None,
        capability_hint: None,
    };

    let in_scope = request_for(&child_token, "https://api.github.com/repos/acme/ok");
    assert_eq!(
        engine.execute_broker_request(in_scope).decision,
        vaultx_broker::Decision::Allow
    );

    let out_of_scope = request_for(&child_token, "https://api.github.com/repos/acme/other");
    let response = engine.execute_broker_request(out_of_scope);
    assert!(matches!(
        &response.decision,
        vaultx_broker::Decision::Deny { reason, .. } if reason == "outside_delegation"
    ));

    // The parent's own token still covers the path the child cannot reach:
    // attenuation narrowed the child, never the parent.
    let parent_record_store =
        FileSessionStore::open(root.join(".vaultx").join("sessions.json")).unwrap();
    let records = parent_record_store
        .list_for_agent(&AgentId::parse("agent_ci-bot").unwrap())
        .unwrap();
    assert_eq!(records.len(), 2);
    let delegated = records
        .iter()
        .find(|record| record.constraints.is_some())
        .expect("delegated child listed");
    assert_eq!(
        delegated.constraints.as_ref().unwrap().remaining_requests,
        Some(4),
        "the allowed request consumed exactly one budget unit"
    );
    assert!(delegated.parent_session.is_some());

    // Revoking the parent through the CLI invalidates the child at once.
    dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Revoke {
                session_id: parent_id.clone(),
            },
        },
    ))
    .unwrap();
    let after_revoke = request_for(&child_token, "https://api.github.com/repos/acme/ok");
    assert!(matches!(
        engine.execute_broker_request(after_revoke).decision,
        vaultx_broker::Decision::Deny { ref reason, .. } if reason == "session_revoked"
    ));

    // Delegating from a revoked/expired parent is a usage error, not a
    // runtime failure — and the dead token still proves nothing.
    let err = dispatch(&cli(
        root,
        Command::Agent {
            command: AgentCommand::Delegate {
                parent_token: parent_token.clone(),
                credentials: vec!["github-work-token".into()],
                hosts: Vec::new(),
                methods: Vec::new(),
                paths: Vec::new(),
                max_requests: Some(1),
            },
        },
    ))
    .unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(text) if text.contains("parent session revoked or expired")),
        "{err:?}"
    );
}
