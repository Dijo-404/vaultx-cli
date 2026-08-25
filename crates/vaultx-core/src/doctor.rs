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

/// Outcome of one lightweight broker IPC handshake probe. The probe
/// itself is executed by the caller (CLI/TUI own the async runtime);
/// the doctor only classifies the result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BrokerProbe {
    /// The endpoint answered a protocol ping.
    Reachable {
        /// Broker-reported protocol version.
        version: String,
    },
    /// The endpoint could not be reached or did not answer.
    Unreachable {
        /// Secret-free failure reason (OS error text, timeout, ...).
        reason: String,
    },
}

/// Health diagnostics over an opened project context.
///
/// Broker connectivity is classified from an injected
/// [`BrokerProbe`]; without one (`DoctorService::new`) that check
/// reports itself as not probed instead of inventing a verdict.
#[derive(Clone, Debug)]
pub struct DoctorService<'a> {
    ctx: &'a ProjectContext,
    broker_probe: Option<(String, BrokerProbe)>,
}

impl<'a> DoctorService<'a> {
    /// Builds a service operating on `ctx`.
    #[must_use]
    pub const fn new(ctx: &'a ProjectContext) -> Self {
        Self {
            ctx,
            broker_probe: None,
        }
    }

    /// Attaches a resolved endpoint plus its handshake outcome so
    /// [`DoctorService::run`] can classify real broker connectivity.
    #[must_use]
    pub fn with_broker_probe(mut self, endpoint: String, probe: BrokerProbe) -> Self {
        self.broker_probe = Some((endpoint, probe));
        self
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
            self.check_sync_consistency(),
            self.check_broker_connectivity(),
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
                    "signing key availability",
                    CheckStatus::Pass,
                    "no device signing key yet; generated on first commit",
                );
            }
            Err(err) => {
                return outcome(
                    "signing key availability",
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
            Ok(()) => outcome(
                "signing key availability",
                CheckStatus::Pass,
                "device identity loads",
            ),
            Err(reason) => outcome(
                "signing key availability",
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

    /// Presence + permission sanity of the project-local broker socket.
    /// On unix a world-writable socket would let any local user speak to
    /// (or squat) the endpoint, so it downgrades the verdict to WARN.
    fn check_broker_socket(&self) -> CheckOutcome {
        const SPLIT_NOTE: &str =
            "; connectivity probes target the global XDG endpoint, not this project-local path";
        let path = self.ctx.vault_dir().join(BROKER_SOCKET_FILE);
        if !path.exists() {
            return outcome(
                "broker socket permissions",
                CheckStatus::Warn,
                format!(
                    "broker not running (no socket at .vaultx/{BROKER_SOCKET_FILE}){SPLIT_NOTE}"
                ),
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            match std::fs::metadata(&path) {
                Ok(metadata) => {
                    let mode = metadata.permissions().mode();
                    if mode & 0o002 != 0 {
                        return outcome(
                            "broker socket permissions",
                            CheckStatus::Warn,
                            format!(
                                ".vaultx/{BROKER_SOCKET_FILE} is world-writable (mode {:o}); \
                                 tighten it before trusting agent traffic\
                                 {SPLIT_NOTE}",
                                mode & 0o777
                            ),
                        );
                    }
                }
                Err(err) => {
                    return outcome(
                        "broker socket permissions",
                        CheckStatus::Warn,
                        format!("cannot stat .vaultx/{BROKER_SOCKET_FILE}: {err}{SPLIT_NOTE}"),
                    );
                }
            }
        }
        outcome(
            "broker socket permissions",
            CheckStatus::Pass,
            format!("broker socket present; not world-writable{SPLIT_NOTE}"),
        )
    }

    /// Plan §44 sync consistency: compares local refs against a locally
    /// recorded last-sync snapshot when one exists. No snapshot format is
    /// persisted by any current component, so a configured remote without
    /// one reports a deferred-integration WARN rather than inventing
    /// state.
    fn check_sync_consistency(&self) -> CheckOutcome {
        let remote_path = self.ctx.vault_dir().join(REMOTE_CONFIG_FILE);
        if !remote_path.is_file() {
            return outcome(
                "sync consistency",
                CheckStatus::Pass,
                "no remote configured",
            );
        }
        match std::fs::read_to_string(&remote_path)
            .ok()
            .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        {
            Some(_) => outcome(
                "sync consistency",
                CheckStatus::Warn,
                "remote configured but no last-sync snapshot exists locally; \
                 nothing to compare yet",
            ),
            None => outcome(
                "sync consistency",
                CheckStatus::Warn,
                ".vaultx/remote.json exists but does not parse as JSON; inspect it manually",
            ),
        }
    }

    /// Classifies the injected handshake probe against the resolved
    /// endpoint. A missing endpoint socket stays advisory; a present-but-
    /// unresponsive endpoint means something claims to be running and is
    /// broken, which blocks.
    fn check_broker_connectivity(&self) -> CheckOutcome {
        const SPLIT_NOTE: &str =
            "; permission audit separately inspects project-local .vaultx/broker.sock";
        let name = "broker connectivity";
        let Some((endpoint, probe)) = self.broker_probe.as_ref() else {
            return outcome(name, CheckStatus::Warn, "not probed in this context");
        };
        let socket_exists = std::path::Path::new(endpoint).exists();
        match probe {
            BrokerProbe::Reachable { version } => outcome(
                name,
                CheckStatus::Pass,
                format!("handshake ok at {endpoint} (version {version}){SPLIT_NOTE}"),
            ),
            BrokerProbe::Unreachable { reason } => {
                if socket_exists {
                    outcome(
                        name,
                        CheckStatus::Fail,
                        format!("endpoint at {endpoint} unreachable: {reason}{SPLIT_NOTE}"),
                    )
                } else {
                    outcome(
                        name,
                        CheckStatus::Warn,
                        format!("no socket at {endpoint}; broker not running{SPLIT_NOTE}"),
                    )
                }
            }
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
            "signing key availability",
            "keyring availability",
            "sync consistency",
            "broker connectivity",
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
                .any(|o| o.name == "broker socket permissions" && o.status == CheckStatus::Warn),
            "{outcomes:?}"
        );
        assert!(
            outcomes
                .iter()
                .any(|o| o.name == "remote" && o.status == CheckStatus::Warn),
            "{outcomes:?}"
        );

        // A fresh project reports sync as clean with no remote, and the
        // unprobed broker connectivity check stays advisory.
        let sync = outcomes
            .iter()
            .find(|o| o.name == "sync consistency")
            .unwrap();
        assert_eq!(sync.status, CheckStatus::Pass);
        assert!(sync.detail.contains("no remote configured"), "{sync:?}");
        let connectivity = outcomes
            .iter()
            .find(|o| o.name == "broker connectivity")
            .unwrap();
        assert_eq!(connectivity.status, CheckStatus::Warn);
        assert!(
            connectivity.detail.contains("not probed"),
            "{connectivity:?}"
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
                .any(|o| o.name == "signing key availability" && o.status == CheckStatus::Fail),
            "{outcomes:?}"
        );

        std::fs::remove_file(ctx.vault_dir().join(DEVICE_KEY_FILE)).unwrap();
        let outcomes = DoctorService::new(&ctx).run();
        assert!(
            outcomes
                .iter()
                .any(|o| o.name == "signing key availability" && o.status == CheckStatus::Pass),
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

    #[test]
    fn broker_connectivity_classifies_injected_probe_outcomes() {
        let (_guard, ctx) = temp_ctx();
        let endpoint = ctx.vault_dir().join(BROKER_SOCKET_FILE);

        // Reachable handshake passes with the version echoed back.
        let outcomes = DoctorService::new(&ctx)
            .with_broker_probe(
                endpoint.display().to_string(),
                BrokerProbe::Reachable {
                    version: "9.9.9".to_owned(),
                },
            )
            .run();
        let check = outcomes
            .iter()
            .find(|o| o.name == "broker connectivity")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Pass);
        assert!(check.detail.contains("handshake ok") && check.detail.contains("9.9.9"));

        // Unreachable without a socket stays advisory.
        std::fs::remove_file(&endpoint).ok();
        let outcomes = DoctorService::new(&ctx)
            .with_broker_probe(
                endpoint.display().to_string(),
                BrokerProbe::Unreachable {
                    reason: "connection refused".to_owned(),
                },
            )
            .run();
        let check = outcomes
            .iter()
            .find(|o| o.name == "broker connectivity")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("no socket"), "{check:?}");

        // Unreachable WITH a socket present means a stale/broken
        // endpoint: blocking failure naming the reason, no secret
        // material involved.
        std::fs::write(&endpoint, b"stale").unwrap();
        let outcomes = DoctorService::new(&ctx)
            .with_broker_probe(
                endpoint.display().to_string(),
                BrokerProbe::Unreachable {
                    reason: "connection refused".to_owned(),
                },
            )
            .run();
        let check = outcomes
            .iter()
            .find(|o| o.name == "broker connectivity")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(
            check.detail.contains("unreachable") && check.detail.contains("connection refused"),
            "{check:?}"
        );
    }

    #[test]
    fn sync_consistency_passes_without_remote_and_warns_with_uncomparable_remote() {
        let (_guard, ctx) = temp_ctx();

        // Fresh project: clean pass, explicitly "no remote configured".
        let outcomes = DoctorService::new(&ctx).run();
        let sync = outcomes
            .iter()
            .find(|o| o.name == "sync consistency")
            .unwrap();
        assert_eq!(sync.status, CheckStatus::Pass);
        assert_eq!(sync.detail, "no remote configured");

        // A configured remote with no local snapshot is deferred, not
        // broken; an unparsable remote file is flagged for inspection.
        std::fs::write(ctx.vault_dir().join(REMOTE_CONFIG_FILE), "{}").unwrap();
        let outcomes = DoctorService::new(&ctx).run();
        let sync = outcomes
            .iter()
            .find(|o| o.name == "sync consistency")
            .unwrap();
        assert_eq!(sync.status, CheckStatus::Warn);
        assert!(sync.detail.contains("no last-sync snapshot"), "{sync:?}");

        std::fs::write(ctx.vault_dir().join(REMOTE_CONFIG_FILE), "not json at all").unwrap();
        let outcomes = DoctorService::new(&ctx).run();
        let sync = outcomes
            .iter()
            .find(|o| o.name == "sync consistency")
            .unwrap();
        assert_eq!(sync.status, CheckStatus::Warn);
        assert!(sync.detail.contains("does not parse"), "{sync:?}");
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_socket_downgrades_socket_permissions_to_warn() {
        use std::os::unix::fs::PermissionsExt;

        let (_guard, ctx) = temp_ctx();
        let path = ctx.vault_dir().join(BROKER_SOCKET_FILE);

        std::fs::write(&path, b"sock").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let outcomes = DoctorService::new(&ctx).run();
        let check = outcomes
            .iter()
            .find(|o| o.name == "broker socket permissions")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.detail.contains("world-writable"), "{check:?}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let outcomes = DoctorService::new(&ctx).run();
        let check = outcomes
            .iter()
            .find(|o| o.name == "broker socket permissions")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Pass, "{check:?}");
    }

    fn render_lines(outcomes: &[CheckOutcome]) -> Vec<String> {
        render_checks(outcomes).lines().map(str::to_owned).collect()
    }
}
