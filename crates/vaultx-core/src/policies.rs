//! [`PolicyOpsService`]: policy YAML persistence, engine construction,
//! validation, and dry-run authorization checks.
//!
//! Policy documents are human-editable YAML files under
//! `.vaultx/policies/<name>.yaml`. Parsing and semantic validation are
//! delegated to [`vaultx_policy`]; this service only adds file management
//! plus the convenience wrappers the CLI/TUI need.
//!
//! # Deferred: broker wiring
//!
//! [`PolicyOpsService::build_engine`] produces a ready-to-use
//! [`RuleEngine`], but binding it to the broker (which consumes engines
//! through the `Authorizer` seam) is part of the IPC/server tasks.

use std::collections::BTreeMap;

use vaultx_policy::{
    load_policy_file, parse_policy_yaml, Action, AuthorizationContext, AuthorizationDecision,
    AuthorizationRequest, Authorizer, HttpMethod, Principal, RuleEngine,
};
use vaultx_types::{CredentialRef, EnvironmentId, PolicyName};

use crate::error::CoreError;
use crate::error::CoreResult;
use crate::project::ProjectContext;

/// Policy operations over `.vaultx/policies`.
#[derive(Clone, Copy, Debug)]
pub struct PolicyOpsService<'a> {
    ctx: &'a ProjectContext,
}

impl<'a> PolicyOpsService<'a> {
    /// Builds a service operating on `ctx`.
    #[must_use]
    pub const fn new(ctx: &'a ProjectContext) -> Self {
        Self { ctx }
    }

    fn policy_path(&self, name: &PolicyName) -> std::path::PathBuf {
        self.ctx
            .policies_dir()
            .join(format!("{}.yaml", name.as_str()))
    }

    /// Parses + validates `yaml_text` and persists it as
    /// `<policies>/<name>.yaml`.
    ///
    /// The document's own `name` field must equal `expected_name`; this
    /// keeps the file name authoritative and prevents silent shadowing of
    /// differently-named documents.
    ///
    /// # Errors
    /// * [`CoreError::PolicyLoadFailed`] for YAML parse/validation errors
    ///   and for name mismatches.
    /// * Propagates filesystem failures.
    pub fn save_policy_yaml(&self, expected_name: &str, yaml_text: &str) -> CoreResult<()> {
        let parsed_name = PolicyName::parse(expected_name)?;
        let document = parse_policy_yaml(yaml_text)
            .map_err(|err| CoreError::PolicyLoadFailed(err.to_string()))?;
        if document.name != parsed_name {
            return Err(CoreError::PolicyLoadFailed(format!(
                "document declares name `{}` but `{expected_name}` was requested",
                document.name
            )));
        }
        let path = self.policy_path(&parsed_name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, yaml_text)?;
        Ok(())
    }

    /// Loads and validates every policy document under
    /// `.vaultx/policies`, sorted by file name. Files without a
    /// `.yaml`/`.yml` extension are ignored.
    ///
    /// # Errors
    /// * [`CoreError::PolicyLoadFailed`] when any policy file fails to
    ///   parse or validate.
    pub fn load_policies(&self) -> CoreResult<Vec<vaultx_policy::PolicyDocument>> {
        let mut documents = Vec::new();
        for result in self.load_policies_reported() {
            documents.push(result.map_err(CoreError::PolicyLoadFailed)?);
        }
        Ok(documents)
    }

    fn sorted_policy_files(&self) -> CoreResult<Vec<std::path::PathBuf>> {
        let dir = self.ctx.policies_dir();
        if !dir.is_dir() {
            return Ok(Vec::new());
        }
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)?
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("yaml") | Some("yml")
                )
            })
            .collect();
        files.sort();
        Ok(files)
    }

    fn load_policies_reported(&self) -> Vec<Result<vaultx_policy::PolicyDocument, String>> {
        match self.sorted_policy_files() {
            Err(err) => vec![Err(err.to_string())],
            Ok(files) => files
                .iter()
                .map(|path| {
                    let display = path.display().to_string();
                    load_policy_file(path).map_err(|err| format!("{display}: {err}"))
                })
                .collect(),
        }
    }

    /// Builds a [`RuleEngine`] from all stored policies.
    ///
    /// # Errors
    /// * [`CoreError::PolicyLoadFailed`] for load failures, invalid
    ///   documents, or duplicate policy names across files.
    pub fn build_engine(&self) -> CoreResult<RuleEngine> {
        let documents = self.load_policies()?;
        RuleEngine::from_documents(documents)
            .map_err(|err| CoreError::PolicyLoadFailed(err.to_string()))
    }

    /// Per-file validation summary: `Ok(name)` per valid document,
    /// `Err(reason)` per invalid one.
    ///
    /// # Errors
    /// * Propagates directory-listing failures.
    pub fn validate_all(&self) -> CoreResult<Vec<Result<PolicyName, String>>> {
        Ok(self
            .load_policies_reported()
            .into_iter()
            .map(|result| result.map(|doc| doc.name))
            .collect())
    }

    /// Convenience wrapper running one authorization check against an
    /// engine without assembling an [`AuthorizationRequest`] by hand.
    ///
    /// `environment` takes a **bare** environment name (`development`)
    /// prefixed internally; pass `None` when the environment is unknown.
    ///
    /// # Errors
    /// * Propagates identifier-validation failures for principal,
    ///   credential, or environment.
    #[allow(clippy::too_many_arguments)]
    pub fn test_policy(
        &self,
        engine: &RuleEngine,
        principal: &str,
        credential: &str,
        host: &str,
        method: HttpMethod,
        path: &str,
        environment: Option<&str>,
        body_len_bytes: u64,
    ) -> CoreResult<AuthorizationDecision> {
        let environment = environment
            .map(|bare| EnvironmentId::parse(&format!("env_{bare}")))
            .transpose()?;
        let request = AuthorizationRequest {
            principal: Principal::parse(principal)?,
            action: Action::HttpRequest,
            resource: CredentialRef::parse(credential)?,
            context: AuthorizationContext {
                host: host.to_owned(),
                method,
                path: path.to_owned(),
                query: BTreeMap::new(),
                body_len_bytes,
                environment,
            },
        };
        Ok(engine.authorize(&request))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaultx_policy::DenyReason;

    const VALID_YAML: &str = r#"
name: coding-agent-github
principal: agent:coding-agent
credential: github-work-token
environment:
  allow: [env_development]
http:
  hosts: [api.github.com]
  allow:
    - methods: [GET]
      paths: [/repos/acme/backend/**]
request:
  max_body_bytes: 262144
"#;

    fn temp_ctx() -> (tempfile::TempDir, ProjectContext) {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ProjectContext::init(dir.path()).unwrap();
        (dir, ctx)
    }

    #[test]
    fn save_load_build_engine_and_test_policy_cycle() {
        let (_guard, ctx) = temp_ctx();
        let ops = PolicyOpsService::new(&ctx);

        ops.save_policy_yaml("coding-agent-github", VALID_YAML)
            .unwrap();

        // Name mismatch is refused before anything is written.
        assert!(matches!(
            ops.save_policy_yaml("different-name", VALID_YAML),
            Err(CoreError::PolicyLoadFailed(msg)) if msg.contains("different-name")
        ));

        // Invalid YAML is refused.
        assert!(matches!(
            ops.save_policy_yaml("broken", "name: [unclosed"),
            Err(CoreError::PolicyLoadFailed(_))
        ));
        // Semantically invalid (no allow rules) is refused too.
        assert!(ops
            .save_policy_yaml(
                "no-allow",
                "name: no-allow\nprincipal: agent:a\ncredential: c\nhttp:\n  hosts: [api.example.com]\n"
            )
            .is_err());

        // Exactly one file landed.
        assert_eq!(ops.sorted_policy_files().unwrap().len(), 1);

        let docs = ops.load_policies().unwrap();
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].name.as_str(), "coding-agent-github");

        let engine = ops.build_engine().unwrap();
        assert_eq!(engine.policies().len(), 1);

        let decision = ops
            .test_policy(
                &engine,
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::GET,
                "/repos/acme/backend/issues",
                Some("development"),
                0,
            )
            .unwrap();
        assert!(
            matches!(&decision, AuthorizationDecision::Allow { .. }),
            "expected allow, got {decision:?}"
        );

        // Wrong host -> no matching allow.
        let denied = ops
            .test_policy(
                &engine,
                "agent:coding-agent",
                "github-work-token",
                "evil.example.com",
                HttpMethod::GET,
                "/repos/acme/backend/issues",
                Some("development"),
                0,
            )
            .unwrap();
        assert!(matches!(denied, AuthorizationDecision::Deny { .. }));

        // Unknown environment -> denied by the allowlist gate.
        let env_denied = ops
            .test_policy(
                &engine,
                "agent:coding-agent",
                "github-work-token",
                "api.github.com",
                HttpMethod::GET,
                "/repos/acme/backend/issues",
                Some("production"),
                0,
            )
            .unwrap();
        assert!(matches!(
            env_denied,
            AuthorizationDecision::Deny {
                reason: DenyReason::EnvironmentDenied,
                ..
            }
        ));

        // Invalid principals surface as typed errors, not denies.
        assert!(ops
            .test_policy(
                &engine,
                "user:alice",
                "github-work-token",
                "api.github.com",
                HttpMethod::GET,
                "/x",
                None,
                0,
            )
            .is_err());

        let report = ops.validate_all().unwrap();
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].as_ref().unwrap().as_str(), "coding-agent-github");
    }

    #[test]
    fn validate_all_reports_each_bad_document_and_engine_recovers() {
        let (_guard, ctx) = temp_ctx();
        let ops = PolicyOpsService::new(&ctx);

        // The saved name must match the document's declared name.
        ops.save_policy_yaml("coding-agent-github", VALID_YAML)
            .unwrap();

        // Drop in a broken file directly to exercise the summary path.
        let broken_path = ctx.policies_dir().join("bad-policy.yaml");
        std::fs::write(&broken_path, "name: [unclosed").unwrap();

        let report = ops.validate_all().unwrap();
        assert_eq!(report.len(), 2);
        assert!(report.iter().any(Result::is_ok));
        assert!(report.iter().any(Result::is_err));

        // build_engine refuses while any document is invalid...
        assert!(matches!(
            ops.build_engine(),
            Err(CoreError::PolicyLoadFailed(_))
        ));

        // ...and recovers once the offender is removed.
        std::fs::remove_file(&broken_path).unwrap();
        assert_eq!(ops.build_engine().unwrap().policies().len(), 1);

        // Duplicate names across two files also refuse engine building.
        let dup_path = ctx.policies_dir().join("good-copy.yml");
        std::fs::write(&dup_path, VALID_YAML).unwrap();
        assert!(matches!(
            ops.build_engine(),
            Err(CoreError::PolicyLoadFailed(msg)) if msg.contains("duplicate"),
        ));
    }
}
