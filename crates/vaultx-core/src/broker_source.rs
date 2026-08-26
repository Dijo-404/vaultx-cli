//! [`VaultCredentialSource`]: bridges the encrypted secret vault into the
//! broker's credential-resolution seam.
//!
//! Only secrets stored with `kind == Brokered` are resolvable — plain
//! `Secret` values can never be pulled through the outbound-request
//! pipeline (plan §18: the broker resolves *brokered credentials*, not
//! arbitrary vault entries). Resolution happens per request: plaintext is
//! decrypted inside this boundary and handed to injection as
//! zeroizing-on-drop bytes; nothing is cached.
//!
//! The CLI convention binds a brokered secret's logical credential ref to
//! its lowercased variable name, so lookups go name-first and then verify
//! that the stored binding matches the requested ref exactly.

use std::sync::Arc;

use vaultx_broker::credential::CredentialSource;
use vaultx_broker::error::BrokerError;
use vaultx_broker::inject::InjectionTemplateId;
use vaultx_crypto::secret::SecretBytes;
use vaultx_types::{CredentialRef, EnvironmentId};

use crate::error::{CoreError, CoreResult};
use crate::secrets::SecretService;
use crate::ProjectContext;

/// Resolves brokered credentials by decrypting on demand.
#[derive(Debug)]
pub struct VaultCredentialSource {
    ctx: Arc<ProjectContext>,
}

impl VaultCredentialSource {
    /// Wraps an opened project context. The context is shared (not
    /// owned) so the CLI/TUI keep using their own facade alongside.
    #[must_use]
    pub fn new(ctx: Arc<ProjectContext>) -> Self {
        Self { ctx }
    }

    /// Environment ids use the `env_<bare>` spelling everywhere; secret
    /// service lookups take the bare name.
    fn bare_env(environment: &EnvironmentId) -> &str {
        environment.as_str().trim_start_matches("env_")
    }

    fn lookup(
        &self,
        credential: &CredentialRef,
        environment: &EnvironmentId,
    ) -> Result<(String, crate::secrets::SecretMetadata), BrokerError> {
        let unknown = || BrokerError::UnknownCredential(credential.to_string());
        let secrets = SecretService::new(self.ctx.as_ref());
        for entry in secrets
            .list_secrets(Self::bare_env(environment))
            .map_err(|_| unknown())?
        {
            if entry.kind != vaultx_types::model::VariableKind::Brokered {
                continue;
            }
            let Ok(metadata) =
                secrets.secret_metadata(entry.name.as_str(), Self::bare_env(environment))
            else {
                continue;
            };
            if metadata.state != crate::secrets::SecretRevisionState::Active {
                continue;
            }
            let Some(binding) = metadata.brokered.as_ref() else {
                continue;
            };
            if binding.credential_ref == *credential {
                return Ok((entry.name.to_string(), metadata));
            }
        }
        Err(unknown())
    }
}

/// Maps the type-layer template id onto the broker seam's enum. Both are
/// kebab-case tagged; matching stays explicit so a new variant cannot
/// silently fall through.
fn to_broker_template(template: vaultx_types::model::InjectionTemplateId) -> InjectionTemplateId {
    match template {
        vaultx_types::model::InjectionTemplateId::Bearer => InjectionTemplateId::Bearer,
        vaultx_types::model::InjectionTemplateId::BasicPassword => {
            InjectionTemplateId::BasicPassword
        }
        vaultx_types::model::InjectionTemplateId::ApiKeyHeader => InjectionTemplateId::ApiKeyHeader,
        vaultx_types::model::InjectionTemplateId::GithubBearer => InjectionTemplateId::GithubBearer,
        vaultx_types::model::InjectionTemplateId::QueryParameter => {
            InjectionTemplateId::QueryParameter
        }
        vaultx_types::model::InjectionTemplateId::AwsSigv4 => InjectionTemplateId::AwsSigv4,
        vaultx_types::model::InjectionTemplateId::CustomStaticHeaderPlusSecret => {
            InjectionTemplateId::CustomStaticHeaderPlusSecret
        }
    }
}

impl CredentialSource for VaultCredentialSource {
    /// Bindings are scoped per environment: the same ref may use
    /// different templates in staging vs production, so selection MUST
    /// honor the session's environment rather than scanning globally.
    fn template_for_in_env(
        &self,
        credential: &CredentialRef,
        environment: &EnvironmentId,
    ) -> Result<InjectionTemplateId, BrokerError> {
        let (_, metadata) = self.lookup(credential, environment)?;
        metadata
            .brokered
            .map(|binding| to_broker_template(binding.injection))
            .ok_or_else(|| BrokerError::UnknownCredential(credential.to_string()))
    }

    /// Flat lookup retained for trait completeness; production paths go
    /// through [`Self::template_for_in_env`].
    fn template_for(&self, credential: &CredentialRef) -> Result<InjectionTemplateId, BrokerError> {
        // The resolution seam carries no environment context here, so the
        // binding is located through every registered environment (the
        // authoritative registry, not guessed spellings).
        let environments = crate::EnvironmentService::new(self.ctx.as_ref())
            .list_environments()
            .map_err(|_| BrokerError::UnknownCredential(credential.to_string()))?;
        for summary in environments {
            if let Ok(environment) = EnvironmentId::parse(&format!("env_{}", summary.name)) {
                if let Ok((_, metadata)) = self.lookup(credential, &environment) {
                    if let Some(binding) = metadata.brokered {
                        return Ok(to_broker_template(binding.injection));
                    }
                }
            }
        }
        Err(BrokerError::UnknownCredential(credential.to_string()))
    }

    fn resolve(
        &self,
        credential: &CredentialRef,
        environment: &EnvironmentId,
    ) -> Result<SecretBytes, BrokerError> {
        // The binding's logical ref (`github_token`) is not the vault
        // entry name (`GITHUB_TOKEN`); reveal must target the stored
        // name, never the requested ref.
        let (secret_name, _) = self.lookup(credential, environment)?;
        // Reveal happens only after the binding matched; any failure
        // collapses to the same unknown-credential denial so callers
        // cannot probe which step failed.
        let secrets = SecretService::new(self.ctx.as_ref());
        let plaintext = secrets
            .reveal_secret(&secret_name, Self::bare_env(environment))
            .map_err(|_| BrokerError::UnknownCredential(credential.to_string()))?;
        Ok(SecretBytes::from_bytes(plaintext.as_slice()))
    }
}

// ---------------------------------------------------------------------------
// Production engine assembly (used by `vaultx broker serve`)
// ---------------------------------------------------------------------------

use std::sync::Arc as StdArc;

use vaultx_audit::JsonlAppendStore;
use vaultx_broker::engine::{BrokerDependencies, BrokerEngine};
use vaultx_broker::http_transport::HttpTransport;
use vaultx_broker::session::FileSessionStore;
use vaultx_http::{CanonicalUrl, EgressGuard, RedirectAuthorizer, RedirectPolicy, SizeLimits};

/// Redirect gate for v1 serving: same origin only (host + port). The
/// original request was already authorized against policy, so a
/// same-origin hop stays inside its approval scope; every cross-origin
/// hop is refused outright and credentials therefore never leave the
/// approved origin (INV-006/007 by construction).
#[derive(Debug, Default)]
pub struct SameOriginRedirectAuthorizer;

impl RedirectAuthorizer for SameOriginRedirectAuthorizer {
    fn authorize_redirect(&self, original: &CanonicalUrl, next: &CanonicalUrl) -> bool {
        original.host() == next.host() && original.port_or_default() == next.port_or_default()
    }
}

/// Environment variable selecting the authorization backend for
/// [`build_production_engine`]: `native` (default, the deterministic rule
/// engine) or `cedar` (the Cedar-compiled policy set). Any other value —
/// including garbage or typos — fails closed at startup.
pub const POLICY_ENGINE_ENV: &str = "VAULTX_POLICY_ENGINE";

/// Selects the authorizer backend from an already-read mode string.
///
/// `None` and the empty string both mean the default (`native`), matching
/// [`std::env::var`]'s absent/unset distinction being irrelevant here.
fn authorizer_from_mode(
    ops: &crate::PolicyOpsService<'_>,
    mode: Option<&str>,
) -> CoreResult<StdArc<dyn vaultx_policy::Authorizer>> {
    match mode {
        None | Some("") | Some("native") => Ok(StdArc::new(ops.build_engine()?)),
        Some("cedar") => Ok(StdArc::new(ops.build_cedar_engine()?)),
        Some(other) => Err(CoreError::PolicyLoadFailed(format!(
            "unknown {POLICY_ENGINE_ENV} value `{other}`; \
             expected \"native\" or \"cedar\" (refusing to start fail-closed)"
        ))),
    }
}

/// Assembles a fully wired [`BrokerEngine`] over an opened project:
///
/// * authorizer — project policies via [`crate::PolicyOpsService`],
///   backend chosen by [`POLICY_ENGINE_ENV`] (`native` default, `cedar`
///   opt-in; unknown values refuse startup);
/// * sessions — persistent verifier-hash store at
///   `<project>/.vaultx/sessions.json` (`0600`);
/// * credentials — [`VaultCredentialSource`] decrypting brokered
///   secrets on demand;
/// * audit — hash-chained JSONL store on the project's audit path
///   (fail-closed: every outcome lands there);
/// * transport — hardened reqwest/rustls client with DNS pinning,
///   manual redirects (same-origin), and plan size limits.
///
/// # Errors
/// Propagates policy compilation and session-store open failures.
pub fn build_production_engine(ctx: &StdArc<ProjectContext>) -> CoreResult<BrokerEngine> {
    let ops = crate::PolicyOpsService::new(ctx.as_ref());
    let authorizer = authorizer_from_mode(&ops, std::env::var(POLICY_ENGINE_ENV).ok().as_deref())?;
    let sessions = FileSessionStore::open(ctx.vault_dir().join("sessions.json"))
        .map_err(|err| CoreError::Io(std::io::Error::other(err.to_string())))?;
    let transport = HttpTransport::new(
        EgressGuard::new(false),
        SizeLimits::default(),
        RedirectPolicy::new(5),
        StdArc::new(SameOriginRedirectAuthorizer),
        None,
    )
    .map_err(|err| CoreError::Io(std::io::Error::other(err.to_string())))?;

    Ok(BrokerEngine::new(BrokerDependencies {
        authorizer,
        sessions: StdArc::new(sessions),
        credentials: StdArc::new(VaultCredentialSource::new(StdArc::clone(ctx))),
        injectors: StdArc::new(vaultx_broker::InjectorRegistry::new()),
        transport: StdArc::new(transport),
        audit: StdArc::new(JsonlAppendStore::open(ctx.audit_path())),
        project: vaultx_types::ProjectId::parse("proj_local")
            .map_err(|_| CoreError::Io(std::io::Error::other("invalid local project id")))?,
        egress_allow_private: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::{BrokeredBinding, SecretService};
    use vaultx_crypto::secret::SecretString;
    use vaultx_types::model::{InjectionTemplateId as ModelTemplate, VariableKind};
    use vaultx_types::ProviderName;

    /// Mirrors the real CLI flow: `vaultx secret set GITHUB_TOKEN
    /// --brokered` stores the secret under the uppercase variable name
    /// while the binding's logical ref is the lowercase form. Resolution
    /// through [`VaultCredentialSource`] must decrypt the stored name,
    /// not re-derive a vault entry from the ref (regression for the E2E
    /// `credential_unavailable` denial).
    #[test]
    fn resolves_brokered_secret_by_binding_ref_not_entry_name() {
        let project_dir = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let ctx = Arc::new(ProjectContext::init(project_dir.path()).unwrap());
        let secrets = SecretService::new(ctx.as_ref());
        drop(store_dir);
        secrets
            .set_secret(
                "GITHUB_TOKEN",
                &SecretString::copy_from("cli-flow-canary"),
                VariableKind::Brokered,
                "development",
                Some(BrokeredBinding {
                    credential_ref: CredentialRef::parse("github_token").unwrap(),
                    injection: ModelTemplate::GithubBearer,
                    provider_hint: Some(ProviderName::parse("github").unwrap()),
                }),
            )
            .unwrap();

        let source = VaultCredentialSource::new(Arc::clone(&ctx));
        let credential = CredentialRef::parse("github_token").unwrap();
        let environment = EnvironmentId::parse("env_development").unwrap();

        let template = source
            .template_for_in_env(&credential, &environment)
            .unwrap();
        assert_eq!(template, InjectionTemplateId::GithubBearer);

        let resolved = source.resolve(&credential, &environment).unwrap();
        assert_eq!(resolved.expose(|b| b.to_vec()), b"cli-flow-canary");
    }

    /// A valid document whose glob (`/a/*/b`) has no exact Cedar encoding:
    /// the native engine accepts it, Cedar mode refuses startup.
    const WILDCARD_YAML: &str = r#"
name: mid-wildcard
principal: agent:wild
credential: wild-token
http:
  hosts: [api.wild.com]
  allow:
    - methods: [GET]
      paths: [/a/*/b]
"#;

    fn temp_ctx_with_wildcard_policy() -> (tempfile::TempDir, Arc<ProjectContext>) {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Arc::new(ProjectContext::init(dir.path()).unwrap());
        crate::PolicyOpsService::new(ctx.as_ref())
            .save_policy_yaml("mid-wildcard", WILDCARD_YAML)
            .unwrap();
        (dir, ctx)
    }

    #[test]
    fn engine_mode_default_and_native_accept_wildcard_documents() {
        let (_guard, ctx) = temp_ctx_with_wildcard_policy();
        let ops = crate::PolicyOpsService::new(ctx.as_ref());
        for mode in [None, Some(""), Some("native")] {
            assert!(
                authorizer_from_mode(&ops, mode).is_ok(),
                "mode {mode:?} must accept the native-only document"
            );
        }
    }

    #[test]
    fn engine_mode_cedar_refuses_untranslatable_glob_at_startup() {
        let (_guard, ctx) = temp_ctx_with_wildcard_policy();
        let ops = crate::PolicyOpsService::new(ctx.as_ref());
        let msg = match authorizer_from_mode(&ops, Some("cedar")) {
            Err(CoreError::PolicyLoadFailed(msg)) => msg,
            Ok(_) => panic!("cedar mode must refuse the wildcard document"),
            Err(other) => panic!("unexpected error: {other}"),
        };
        assert!(
            msg.contains("/a/*/b") && msg.contains("mid-wildcard"),
            "{msg}"
        );
    }

    #[test]
    fn engine_mode_unknown_value_fails_closed() {
        let (_guard, ctx) = temp_ctx_with_wildcard_policy();
        let ops = crate::PolicyOpsService::new(ctx.as_ref());
        for mode in ["CEDAR", "Native", "bogus", "cedar "] {
            match authorizer_from_mode(&ops, Some(mode)) {
                Err(CoreError::PolicyLoadFailed(msg)) => {
                    assert!(msg.contains(POLICY_ENGINE_ENV), "{mode}: {msg}");
                }
                Ok(_) => panic!("{mode} must fail closed"),
                Err(other) => panic!("{mode}: unexpected error {other}"),
            }
        }
    }

    /// The real startup path reads the env var; serialized behind a mutex
    /// because env-var mutations are process-global.
    #[test]
    fn build_production_engine_honors_env_selection() {
        static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();
        let (_guard_dir, ctx) = temp_ctx_with_wildcard_policy();

        std::env::remove_var(POLICY_ENGINE_ENV);
        assert!(build_production_engine(&ctx).is_ok(), "default is native");

        std::env::set_var(POLICY_ENGINE_ENV, "cedar");
        assert!(
            build_production_engine(&ctx).is_err(),
            "cedar mode must refuse the wildcard document"
        );

        std::env::set_var(POLICY_ENGINE_ENV, "bogus");
        assert!(build_production_engine(&ctx).is_err());

        std::env::remove_var(POLICY_ENGINE_ENV);
    }
}
