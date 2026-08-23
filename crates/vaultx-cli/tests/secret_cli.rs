//! End-to-end tests spawning the built `vaultx` binary, exercising the
//! stdin plaintext-input mode and exit-code contract for secret commands
//! (paths that cannot be driven through in-process [`dispatch`] because
//! they read the real standard input).

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

fn run(root: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vaultx"))
        .arg("--project")
        .arg(root)
        .args(args)
        .stdin(match stdin {
            Some(_) => Stdio::piped(),
            None => Stdio::null(),
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn vaultx");
    if let Some(payload) = stdin {
        child
            .stdin
            .take()
            .expect("stdin piped")
            .write_all(payload)
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait");
    Output {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

const CANARY: &str = "canary-hunter2-ZZ9plural";
const CANARY_ROTATED: &str = "rotated-canary-value";

#[test]
fn secret_set_via_stdin_then_metadata_rotate_and_destroy() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let init = run(root, &["init"], None);
    assert_eq!(init.code, 0, "init failed: {}", init.stderr);

    // `echo <secret> | vaultx -P tmp secret set FOO -`
    let set = run(
        root,
        &["secret", "set", "FOO", "-"],
        Some(CANARY.as_bytes()),
    );
    assert_eq!(set.code, 0, "set failed: {}{}", set.stdout, set.stderr);
    assert!(set.stdout.contains("set FOO"), "{}", set.stdout);
    assert!(!set.stdout.contains(CANARY), "plaintext echoed back");

    // Metadata shows Active without leaking the value.
    let meta = run(root, &["secret", "metadata", "FOO"], None);
    assert_eq!(meta.code, 0);
    assert!(
        meta.stdout.contains("state:       active"),
        "{}",
        meta.stdout
    );
    assert!(!meta.stdout.contains(CANARY));

    // Rotate through stdin; old revision becomes revoked.
    let rotate = run(
        root,
        &["secret", "rotate", "FOO", "-"],
        Some(CANARY_ROTATED.as_bytes()),
    );
    assert_eq!(
        rotate.code, 0,
        "rotate failed: {}{}",
        rotate.stdout, rotate.stderr
    );
    let meta = run(root, &["secret", "metadata", "FOO"], None);
    assert_eq!(meta.code, 0);
    assert!(meta.stdout.contains("revoked"), "{}", meta.stdout);
    assert!(meta.stdout.contains("active"), "{}", meta.stdout);
    assert!(meta.stdout.contains("revisions:   2"), "{}", meta.stdout);

    // Destroy refuses without --yes (usage class), succeeds with it.
    let refused = run(root, &["secret", "destroy", "FOO"], None);
    assert_eq!(refused.code, 1);
    assert!(refused.stderr.contains("--yes"), "{}", refused.stderr);

    let destroyed = run(root, &["secret", "destroy", "FOO", "--yes"], None);
    assert_eq!(destroyed.code, 0, "destroy failed: {}", destroyed.stderr);
    assert!(
        destroyed.stdout.contains("destroyed FOO"),
        "{}",
        destroyed.stdout
    );

    // Post-destroy metadata reports the destroyed state; no reveal path.
    let meta = run(root, &["secret", "metadata", "FOO"], None);
    assert_eq!(meta.code, 0);
    assert!(
        meta.stdout.contains("state:       destroyed"),
        "{}",
        meta.stdout
    );
}

#[test]
fn secret_set_stdin_rejects_empty_value_with_exit_one() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    run(root, &["init"], None);

    let empty = run(
        root,
        &["secret", "set", "EMPTY", "-"],
        Some(b"\n".as_slice()),
    );
    assert_eq!(empty.code, 1);
    assert!(
        empty.stderr.contains("must not be empty"),
        "{}",
        empty.stderr
    );

    // Unknown names on later operations surface as runtime errors too.
    let missing = run(root, &["secret", "metadata", "GHOST"], None);
    assert_eq!(missing.code, 1);
    assert!(
        missing.stderr.contains("no secret named `GHOST`"),
        "{}",
        missing.stderr
    );
}
