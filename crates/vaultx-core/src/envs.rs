//! [`EnvironmentService`]: deployable environment refs with protection
//! metadata, promotion, and local audit events.
//!
//! # Naming
//!
//! Plan references use bare environment names (`development`, `staging`,
//! `production`) while [`EnvironmentId`] requires the `env_` prefix.
//! Services accept **bare** names and map to the prefixed id internally;
//! refs live at `refs/environments/<bare-name>`.
//!
//! # Promotion
//!
//! [`EnvironmentService::promote`] copies a source ref (branch or another
//! environment) onto a target environment ref, honoring protection rules:
//! moving an existing protected ref requires `force = true`. Every
//! successful promotion appends an [`AuditAction::ConfigCommitted`] event
//! to the project's local JSONL audit store.

use vaultx_audit::store::AppendStore as _;
use vaultx_audit::{
    AuditAction, AuditDecision, CorrelationId, JsonlAppendStore, NewAuditEvent, SafeAuditMetadata,
};
use vaultx_policy::Principal;
use vaultx_repository::{EnvironmentProtection, RefNamespace};
use vaultx_types::{CommitId, EnvironmentId, ProjectId};

use crate::error::{CoreError, CoreResult};
use crate::project::ProjectContext;

/// Actor recorded on service-emitted audit events: the interactive local
/// operator session (not an agent).
const LOCAL_ACTOR: &str = "session:vaultx-cli";
/// Placeholder project id for single-project local repositories. A real
/// workspace/project registry arrives with the sync tasks.
const LOCAL_PROJECT_ID: &str = "proj_local";

/// One row of [`EnvironmentService::list_environments`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentSummary {
    /// Bare environment name (`development`).
    pub name: String,
    /// Whether the env ref refuses unforced moves/deletes.
    pub protected: bool,
    /// Commit the env ref currently points at.
    pub commit: Option<CommitId>,
}

/// Environment operations: create / protect / promote / list.
#[derive(Clone, Copy, Debug)]
pub struct EnvironmentService<'a> {
    ctx: &'a ProjectContext,
}

impl<'a> EnvironmentService<'a> {
    /// Builds a service operating on `ctx`.
    #[must_use]
    pub const fn new(ctx: &'a ProjectContext) -> Self {
        Self { ctx }
    }

    fn environment_id(&self, bare_name: &str) -> CoreResult<EnvironmentId> {
        Ok(EnvironmentId::parse(&format!("env_{bare_name}"))?)
    }

    fn require_environment(&self, bare_name: &str) -> CoreResult<CommitId> {
        self.ctx
            .repository()
            .refs()
            .read_ref(RefNamespace::Environments, bare_name)?
            .ok_or_else(|| CoreError::EnvironmentNotFound(bare_name.to_owned()))
    }

    /// Creates an environment ref pointing at the current head commit with
    /// an explicit unprotected sidecar.
    ///
    /// # Errors
    /// * [`TypeError`](vaultx_types::TypeError) when `bare_name` cannot
    ///   form a valid `env_`-prefixed [`EnvironmentId`].
    /// * [`CoreError::AlreadyExists`] when the environment exists.
    /// * [`CoreError::UnsupportedOperation`] before the first commit (no
    ///   head to pin).
    pub fn create_environment(&self, bare_name: &str) -> CoreResult<EnvironmentId> {
        let env_id = self.environment_id(bare_name)?;
        let refs = self.ctx.repository().refs();
        if refs
            .read_ref(RefNamespace::Environments, bare_name)?
            .is_some()
        {
            return Err(CoreError::AlreadyExists(format!(
                "environment `{bare_name}`"
            )));
        }
        let head = self.ctx.repository().current_head()?.ok_or_else(|| {
            CoreError::UnsupportedOperation(
                "cannot create an environment before the first commit".to_owned(),
            )
        })?;
        refs.write_env_ref(bare_name, &head, false)?;
        refs.write_env_protection(bare_name, &EnvironmentProtection::default())?;
        Ok(env_id)
    }

    /// Sets the protection sidecar of an existing environment.
    ///
    /// # Errors
    /// * [`CoreError::EnvironmentNotFound`] for unknown environments.
    pub fn protect_environment(&self, bare_name: &str, protected: bool) -> CoreResult<()> {
        self.require_environment(bare_name)?;
        self.ctx
            .repository()
            .refs()
            .write_env_protection(bare_name, &EnvironmentProtection { protected })?;
        Ok(())
    }

    /// Moves the target environment ref onto the source ref's commit.
    ///
    /// The source resolves against branch refs first, then environment
    /// refs, so both `promote main production` and chained environment
    /// promotions work. Moving an existing **protected** target requires
    /// `force`.
    ///
    /// On success a [`AuditAction::ConfigCommitted`] audit event is
    /// appended locally.
    ///
    /// # Errors
    /// * Unknown sources surface as ref-not-found repository errors.
    /// * [`CoreError::EnvironmentNotFound`] for unknown targets.
    /// * [`CoreError::Repo::ProtectedRef`] when the target is protected
    ///   and `force` is false.
    /// * Propagates ref-write and audit-store failures.
    pub fn promote(&self, from_ref: &str, to_env: &str, force: bool) -> CoreResult<()> {
        let refs = self.ctx.repository().refs();
        let source = match refs.read_ref(RefNamespace::Heads, from_ref)? {
            Some(commit) => Some(commit),
            None => refs.read_ref(RefNamespace::Environments, from_ref)?,
        }
        .ok_or_else(|| {
            CoreError::Repo(vaultx_repository::RepoError::RefNotFound(
                from_ref.to_owned(),
            ))
        })?;

        // Promotion targets declared environments only; creating them is
        // the explicit `create_environment` step.
        self.require_environment(to_env)?;

        refs.write_env_ref(to_env, &source, force)?;
        self.record_promotion(from_ref, to_env)?;
        Ok(())
    }

    fn record_promotion(&self, from_ref: &str, to_env: &str) -> CoreResult<()> {
        let event = NewAuditEvent {
            correlation_id: CorrelationId::generate()?,
            actor: Principal::parse(LOCAL_ACTOR)?,
            project: ProjectId::parse(LOCAL_PROJECT_ID)?,
            environment: Some(self.environment_id(to_env)?),
            action: AuditAction::ConfigCommitted,
            decision: AuditDecision::Allow,
            credential: None,
            destination: None,
            capability: None,
            policy_ids: Vec::new(),
            metadata: SafeAuditMetadata::from_pairs([
                ("operation", "promote"),
                ("from", from_ref),
                ("to", to_env),
            ])?,
        };
        JsonlAppendStore::open(self.ctx.audit_path()).append(event)?;
        Ok(())
    }

    /// Lists all environments sorted by name with their protection state
    /// and pinned commit.
    ///
    /// # Errors
    /// * Propagates ref-store failures.
    pub fn list_environments(&self) -> CoreResult<Vec<EnvironmentSummary>> {
        let refs = self.ctx.repository().refs();
        refs.list_refs(RefNamespace::Environments)?
            .into_iter()
            .map(|(name, commit)| {
                let protected = refs.read_env_protection(&name).map(|p| p.protected)?;
                Ok(EnvironmentSummary {
                    name,
                    protected,
                    commit: Some(commit),
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigService;
    use crate::history::HistoryService;

    fn temp_ctx() -> (tempfile::TempDir, ProjectContext) {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ProjectContext::init(dir.path()).unwrap();
        (dir, ctx)
    }

    #[test]
    fn create_protect_promote_flow_with_force_rules() {
        let (_guard, ctx) = temp_ctx();
        let config = ConfigService::new(&ctx);
        let history = HistoryService::new(&ctx);
        let envs = EnvironmentService::new(&ctx);

        config.set_config("A", "1").unwrap();
        history.commit("baseline", "user:e").unwrap();

        // Cannot promote before the environment exists...
        assert!(matches!(
            envs.promote("main", "production", false),
            Err(CoreError::EnvironmentNotFound(_))
        ));
        // ...or create one without a head? (head exists now).
        let dev = envs.create_environment("development").unwrap();
        assert_eq!(dev.as_str(), "env_development");

        // Duplicate creation is refused.
        assert!(matches!(
            envs.create_environment("development"),
            Err(CoreError::AlreadyExists(_))
        ));
        // Invalid names fail typed-id validation.
        assert!(matches!(
            envs.create_environment("Bad Env"),
            Err(CoreError::Id(_))
        ));
        assert!(matches!(
            envs.protect_environment("ghost", true),
            Err(CoreError::EnvironmentNotFound(_))
        ));

        let listed = envs.list_environments().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "development");
        assert!(!listed[0].protected);

        // Promote main -> development (unprotected, no force needed).
        envs.promote("main", "development", false).unwrap();

        // Protect, advance main, then verify the force rule.
        envs.protect_environment("development", true).unwrap();
        config.set_config("B", "2").unwrap();
        history.commit("second", "user:e").unwrap();

        assert!(matches!(
            envs.promote("main", "development", false),
            Err(CoreError::Repo(vaultx_repository::RepoError::ProtectedRef(
                _
            )))
        ));

        let listed = envs.list_environments().unwrap();
        assert_eq!(listed[0].name, "development");
        assert!(listed[0].protected);

        envs.promote("main", "development", true).unwrap();
        let listed = envs.list_environments().unwrap();
        assert_eq!(listed[0].commit, ctx.repository().current_head().unwrap());

        // Chained environment promotion: development -> staging.
        envs.create_environment("staging").unwrap();
        envs.promote("development", "staging", false).unwrap();
        let names: Vec<String> = envs
            .list_environments()
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, vec!["development", "staging"]);

        // Unknown sources are refused loudly.
        assert!(matches!(
            envs.promote("missing-source", "staging", false),
            Err(CoreError::Repo(vaultx_repository::RepoError::RefNotFound(
                _
            )))
        ));
    }

    #[test]
    fn promotion_appends_auditable_events() {
        let (_guard, ctx) = temp_ctx();
        let config = ConfigService::new(&ctx);
        let history = HistoryService::new(&ctx);
        let envs = EnvironmentService::new(&ctx);

        config.set_config("A", "1").unwrap();
        history.commit("baseline", "user:e").unwrap();
        envs.create_environment("development").unwrap();
        envs.promote("main", "development", false).unwrap();

        let raw = std::fs::read_to_string(ctx.audit_path()).unwrap();
        assert!(
            raw.contains("\"operation\":\"promote\"")
                && raw.contains("\"from\":\"main\"")
                && raw.contains("\"to\":\"development\""),
            "audit log must record the promotion: {raw}"
        );
    }

    #[test]
    fn create_environment_requires_a_commit_first() {
        let (_guard, ctx) = temp_ctx();
        let envs = EnvironmentService::new(&ctx);
        assert!(matches!(
            envs.create_environment("development"),
            Err(CoreError::UnsupportedOperation(_))
        ));
    }
}
