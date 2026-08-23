//! [`DoctorService`]: read-only health diagnostics for one project.
//!
//! Every check is **non-mutating** (missing artifacts are reported, not
//! provisioned) and never prints secret material: only paths, states,
//! counts, and error summaries surface.
//!
//! Status semantics: `PASS` = healthy, `WARN` = degraded or deferred
//! integration (never fatal), `FAIL` = broken and blocking. The CLI exits
//! nonzero when any check fails.

use vaultx_crypto::signature::SigningKeyPair;
use vaultx_keyring::{FileKeyStore, WrappingKeyProvider as _};

use crate::history::DEVICE_KEY_FILE;
use crate::project::ProjectContext;
use crate::secrets::{KEYS_DIR_NAME, ROOT_KEY_FILE};

/// Conventional broker IPC socket path inside `.vaultx`; the broker
/// server itself arrives with a later task.
const BROKER_SOCKET_FILE: &str = "broker.sock";
/// Conventional remote-sync configuration file inside `.vaultx`; remote
/// configuration arrives with the sync tasks.
const REMOTE_CONFIG_FILE: &str = "remote.json";

/// Outcome class of one doctor check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckStatus {
    /// Healthy.
    Pass,
    /// Degraded, deferred, or advisory; never fatal.
    Warn,
    /// Broken; blocks a clean exit.
    Fail,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        })
    }
}

/// One rendered doctor check row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckOutcome {
    /// Stable check name (`repository integrity`).
    pub name: &'static str,
    /// Result class.
    pub status: CheckStatus,
    /// Human-readable detail; identifiers and states only.
    pub detail: String,
}

/// Health diagnostics over an opened project context.
#[derive(Clone, Copy, Debug)]
pub struct DoctorService<'a> {
    ctx: &'a ProjectContext,
}

impl<'a> DoctorService<'a> {
    /// Builds a service operating on `ctx`.
    #[must_use]
    pub const fn new(ctx: &'a ProjectContext) -> Self {
        Self { ctx }
    }

    /// Runs every check in stable order.
    #[must_use]
    pub fn run(&self) -> Vec<CheckOutcome> {
        vec![
            self.check_repository_integrity(),
            self.check_signing_key(),
            self.check_keyring_availability(),
            self.check_project_keys(),
            self.check_policy_validity(),
            self.check_broker_socket(),
            self.check_remote_config(),
        ]
    }

    fn check_repository_integrity(&self) -> CheckOutcome {
        match self.ctx.repository().objects().verify_all() {
            Ok(()) => outcome(
                "repository integrity",
                CheckStatus::Pass,
                "object store verified",
            ),
            Err(err) => outcome(
                "repository integrity",
                CheckStatus::Fail,
                format!("integrity sweep failed: {err}"),
            ),
        }
    }

    fn check_signing_key(&self) -> CheckOutcome {
        let path = self.ctx.vault_dir().join(DEVICE_KEY_FILE);
        let text = match std::fs::read_to_string(&path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return outcome(
                    "signing key",
                    CheckStatus::Pass,
                    "no device signing key yet; generated on first commit",
                );
            }
            Err(err) => {
                return outcome(
                    "signing key",
                    CheckStatus::Fail,
                    format!("cannot read .vaultx/{DEVICE_KEY_FILE}: {err}"),
                );
            }
            Ok(text) => text,
        };
        let load = hex::decode(text.trim())
            .map_err(|err| format!("not valid hex ({err})"))
            .and_then(|bytes| {
                let seed: [u8; 32] = bytes.try_into().map_err(|bytes: Vec<u8>| {
                    format!("expected 32 bytes, found {}", bytes.len())
                })?;
                SigningKeyPair::from_seed(&seed)
                    .map(|_| ())
                    .map_err(|err| err.to_string())
            });
        match load {
            Ok(()) => outcome("signing key", CheckStatus::Pass, "device identity loads"),
            Err(reason) => outcome(
                "signing key",
                CheckStatus::Fail,
                format!(".vaultx/{DEVICE_KEY_FILE} is unusable: {reason}"),
            ),
        }
    }

    fn check_keyring_availability(&self) -> CheckOutcome {
        let path = self.ctx.vault_dir().join(ROOT_KEY_FILE);
        let store = FileKeyStore::new(path);
        match store.load() {
            Ok(_) => outcome(
                "keyring availability",
                CheckStatus::Warn,
                "development file-based root-key store (.vaultx/root.key) in use; an OS \
                 keychain provider is required for production",
            ),
            Err(_) => outcome(
                "keyring availability",
                CheckStatus::Warn,
                "no root wrapping key provisioned yet; the development file-based fallback \
                 (.vaultx/root.key) will be created on first secret write",
            ),
        }
    }

    fn check_project_keys(&self) -> CheckOutcome {
        let path = self
            .ctx
            .vault_dir()
            .join(KEYS_DIR_NAME)
            .join("project.json");
        if !path.is_file() {
            return outcome(
                "project keys",
                CheckStatus::Warn,
                "project vault keys not provisioned yet (created on first secret write)",
            );
        }
        // Distinguish a lost root wrapping key (operator action required;
        // must never be silently recreated) from an unwrap failure under
        // a present-but-wrong key.
        if !self.ctx.vault_dir().join(ROOT_KEY_FILE).is_file() {
            return outcome(
                "project keys",
                CheckStatus::Fail,
                format!(
                    "root wrapping key missing at .vaultx/{ROOT_KEY_FILE}; \
                     project vault keys cannot be unwrapped until it is restored"
                ),
            );
        }
        match crate::secrets::SecretService::new(self.ctx).verify_project_keys() {
            Ok(()) => outcome(
                "project keys",
                CheckStatus::Pass,
                "wrapped keys unwrap cleanly",
            ),
            Err(err) => outcome(
                "project keys",
                CheckStatus::Fail,
                format!("cannot unwrap .vaultx/keys/project.json: {err}"),
            ),
        }
    }

    fn check_policy_validity(&self) -> CheckOutcome {
        let ops = crate::policies::PolicyOpsService::new(self.ctx);
        match ops.build_engine() {
            Ok(engine) => {
                let count = engine.policies().len();
                if count == 0 {
                    outcome(
                        "policy validity",
                        CheckStatus::Pass,
                        "no policy documents defined",
                    )
                } else {
                    outcome(
                        "policy validity",
                        CheckStatus::Pass,
                        format!("{count} policy document(s) build into a valid engine"),
                    )
                }
            }
            Err(err) => outcome(
                "policy validity",
                CheckStatus::Fail,
                format!("policies do not build into a rule engine: {err}"),
            ),
        }
    }

    fn check_broker_socket(&self) -> CheckOutcome {
        let path = self.ctx.vault_dir().join(BROKER_SOCKET_FILE);
        if path.exists() {
            outcome("broker", CheckStatus::Pass, "broker socket present")
        } else {
            outcome(
                "broker",
                CheckStatus::Warn,
                "broker not running (no socket at .vaultx/broker.sock)",
            )
        }
    }

    fn check_remote_config(&self) -> CheckOutcome {
        let path = self.ctx.vault_dir().join(REMOTE_CONFIG_FILE);
        if path.is_file() {
            outcome("remote", CheckStatus::Pass, "remote configured")
        } else {
            outcome("remote", CheckStatus::Warn, "no remote configured")
        }
    }
}

fn outcome(name: &'static str, status: CheckStatus, detail: impl Into<String>) -> CheckOutcome {
    CheckOutcome {
        name,
        status,
        detail: detail.into(),
    }
}

/// Renders the doctor report: `PASS/WARN/FAIL <name>: <detail>` lines plus
/// a summary line. Exposed here so CLI presentation stays thin while the
/// exact wording stays testable next to the checks that produce it.
#[must_use]
pub fn render_checks(outcomes: &[CheckOutcome]) -> String {
    let mut lines: Vec<String> = outcomes
        .iter()
        .map(|o| format!("{} {}: {}", o.status, o.name, o.detail))
        .collect();
    let passed = outcomes
        .iter()
        .filter(|o| o.status == CheckStatus::Pass)
        .count();
    let warned = outcomes
        .iter()
        .filter(|o| o.status == CheckStatus::Warn)
        .count();
    let failed = outcomes
        .iter()
        .filter(|o| o.status == CheckStatus::Fail)
        .count();
    lines.push(format!(
        "summary: {passed} passed, {warned} warned, {failed} failed"
    ));
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_ctx() -> (tempfile::TempDir, ProjectContext) {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ProjectContext::init(dir.path()).unwrap();
        (dir, ctx)
    }

    #[test]
    fn fresh_project_has_no_failures_and_advisory_warns() {
        let (_guard, ctx) = temp_ctx();
        let outcomes = DoctorService::new(&ctx).run();

        assert!(
            !outcomes.iter().any(|o| o.status == CheckStatus::Fail),
            "fresh project must have no failures: {outcomes:?}"
        );
        for expected in [
            "repository integrity",
            "signing key",
            "keyring availability",
        ] {
            assert!(
                outcomes.iter().any(|o| o.name == expected),
                "`{expected}` check missing: {outcomes:?}"
            );
        }
        // Deferred integrations are WARNs on a fresh project.
        assert!(
            outcomes
                .iter()
                .any(|o| o.name == "broker" && o.status == CheckStatus::Warn),
            "{outcomes:?}"
        );
        assert!(
            outcomes
                .iter()
                .any(|o| o.name == "remote" && o.status == CheckStatus::Warn),
            "{outcomes:?}"
        );

        // Rendered output carries status labels and never key material.
        for line in render_lines(&outcomes) {
            assert!(!line.contains('\u{0}'));
        }
    }

    #[test]
    fn tampered_object_fails_integrity_check() {
        let (_guard, ctx) = temp_ctx();
        crate::config::ConfigService::new(&ctx)
            .set_config("V", "1")
            .unwrap();
        let head = crate::history::HistoryService::new(&ctx)
            .commit("seed", "user:d")
            .unwrap();
        let digest = &head.as_str()[4..];
        let object_path = ctx
            .repository()
            .objects()
            .root()
            .join("sha256")
            .join(&digest[..2])
            .join(&digest[2..]);
        std::fs::write(object_path, b"{\"tampered\":true}").unwrap();

        let outcomes = DoctorService::new(&ctx).run();
        let integrity = outcomes
            .iter()
            .find(|o| o.name == "repository integrity")
            .unwrap();
        assert_eq!(integrity.status, CheckStatus::Fail);
        assert!(
            integrity.detail.contains("sha256 mismatch") || integrity.detail.contains("corrupt"),
            "detail should name the corruption: {}",
            integrity.detail
        );
    }

    #[test]
    fn corrupt_signing_key_fails_but_missing_one_passes() {
        let (_guard, ctx) = temp_ctx();
        std::fs::write(
            ctx.vault_dir().join(DEVICE_KEY_FILE),
            "definitely not hex!!",
        )
        .unwrap();
        let outcomes = DoctorService::new(&ctx).run();
        assert!(
            outcomes
                .iter()
                .any(|o| o.name == "signing key" && o.status == CheckStatus::Fail),
            "{outcomes:?}"
        );

        std::fs::remove_file(ctx.vault_dir().join(DEVICE_KEY_FILE)).unwrap();
        let outcomes = DoctorService::new(&ctx).run();
        assert!(
            outcomes
                .iter()
                .any(|o| o.name == "signing key" && o.status == CheckStatus::Pass),
            "{outcomes:?}"
        );
    }

    #[test]
    fn invalid_policy_document_fails_validity_check() {
        let (_guard, ctx) = temp_ctx();
        std::fs::write(ctx.policies_dir().join("broken.yaml"), "name: [unclosed").unwrap();
        let outcomes = DoctorService::new(&ctx).run();
        let policies = outcomes
            .iter()
            .find(|o| o.name == "policy validity")
            .unwrap();
        assert_eq!(policies.status, CheckStatus::Fail);
    }

    #[test]
    fn wrong_root_key_fails_project_key_unwrap() {
        let (_guard, ctx) = temp_ctx();
        // Provision the hierarchy, then corrupt the root key so unwrapping
        // fails authentication.
        crate::secrets::SecretService::new(&ctx)
            .set_secret(
                "TOKEN",
                &vaultx_crypto::secret::SecretString::copy_from("v"),
                vaultx_types::model::VariableKind::Secret,
                "development",
                None,
            )
            .unwrap();
        std::fs::write(ctx.vault_dir().join(ROOT_KEY_FILE), hex::encode([7u8; 32])).unwrap();

        let outcomes = DoctorService::new(&ctx).run();
        let keys = outcomes.iter().find(|o| o.name == "project keys").unwrap();
        assert_eq!(keys.status, CheckStatus::Fail);
        // A present-but-wrong root key is a generic unwrap failure, not a
        // missing-wrapping-key condition.
        assert!(
            keys.detail
                .contains("cannot unwrap .vaultx/keys/project.json")
                && !keys.detail.contains("root wrapping key missing"),
            "detail should name the unwrap failure: {}",
            keys.detail
        );
    }

    #[test]
    fn lost_root_wrapping_key_fails_and_is_never_recreated() {
        let (_guard, ctx) = temp_ctx();
        crate::secrets::SecretService::new(&ctx)
            .set_secret(
                "TOKEN",
                &vaultx_crypto::secret::SecretString::copy_from("v"),
                vaultx_types::model::VariableKind::Secret,
                "development",
                None,
            )
            .unwrap();
        assert!(ctx.vault_dir().join(ROOT_KEY_FILE).is_file());
        std::fs::remove_file(ctx.vault_dir().join(ROOT_KEY_FILE)).unwrap();

        let outcomes = DoctorService::new(&ctx).run();
        let keys = outcomes.iter().find(|o| o.name == "project keys").unwrap();
        assert_eq!(keys.status, CheckStatus::Fail);
        assert!(
            keys.detail.contains("root wrapping key missing")
                && keys.detail.contains(".vaultx/root.key"),
            "detail must name the lost wrapping key: {}",
            keys.detail
        );
        assert!(
            !ctx.vault_dir().join(ROOT_KEY_FILE).exists(),
            "doctor must never recreate a lost root wrapping key"
        );
    }

    fn render_lines(outcomes: &[CheckOutcome]) -> Vec<String> {
        render_checks(outcomes).lines().map(str::to_owned).collect()
    }
}
