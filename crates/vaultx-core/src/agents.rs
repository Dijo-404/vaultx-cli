//! [`AgentLifecycleService`]: local agent identity files under
//! `.vaultx/agents/<bare-name>.json`.
//!
//! # Naming
//!
//! Plan references use bare agent names while [`AgentId`] requires the
//! `agent_` prefix. Files store the bare name on disk; the JSON payload's
//! `name` field carries the full prefixed [`AgentId`].
//!
//! # Deferred: broker wiring
//!
//! v1 manages identities only: creation, enable/disable (revocation),
//! policy attachment, and inspection. Session issuance, token minting, and
//! broker-side enforcement of these identities arrive with the IPC/server
//! tasks; nothing here talks to the broker yet.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use vaultx_types::{AgentId, PolicyName};

use crate::error::{CoreError, CoreResult};
use crate::project::ProjectContext;

/// Directory under `.vaultx` holding agent identity files.
pub(crate) const AGENTS_DIR_NAME: &str = "agents";

/// On-disk representation of one agent identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentityFile {
    /// Full prefixed id (`agent_<bare>`).
    pub name: AgentId,
    /// Disabled agents are excluded from future sessions; there is no
    /// delete in v1 so history stays inspectable.
    pub enabled: bool,
    /// Policy names the agent is bound to.
    pub policy_names: Vec<PolicyName>,
    /// Monotonic creation counter within this project (1-based).
    pub created_sequence: u64,
}

/// One row of [`AgentLifecycleService::list_agents`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSummary {
    /// Bare agent name (`ci-bot`).
    pub name: String,
    /// Whether the agent may obtain sessions once broker wiring lands.
    pub enabled: bool,
}

/// Agent lifecycle operations over `.vaultx/agents`.
#[derive(Clone, Copy, Debug)]
pub struct AgentLifecycleService<'a> {
    ctx: &'a ProjectContext,
}

impl<'a> AgentLifecycleService<'a> {
    /// Builds a service operating on `ctx`.
    #[must_use]
    pub const fn new(ctx: &'a ProjectContext) -> Self {
        Self { ctx }
    }

    fn agents_dir(&self) -> PathBuf {
        self.ctx.vault_dir().join(AGENTS_DIR_NAME)
    }

    fn validate_bare_name(&self, bare_name: &str) -> CoreResult<AgentId> {
        Ok(AgentId::parse(&format!("agent_{bare_name}"))?)
    }

    fn agent_path(&self, bare_name: &str) -> CoreResult<PathBuf> {
        self.validate_bare_name(bare_name)?;
        Ok(self.agents_dir().join(format!("{bare_name}.json")))
    }

    fn load_file(&self, bare_name: &str) -> CoreResult<AgentIdentityFile> {
        let path = self.agent_path(bare_name)?;
        if !path.is_file() {
            return Err(CoreError::AgentNotFound(bare_name.to_owned()));
        }
        let raw = std::fs::read_to_string(&path)?;
        let file = serde_json::from_str::<AgentIdentityFile>(&raw)?;
        // Defense against hand-edited files whose `name` disagrees with
        // the file name.
        let expected = self.validate_bare_name(bare_name)?;
        if file.name != expected {
            return Err(CoreError::UnsupportedOperation(format!(
                "agent file `{bare_name}` declares mismatched id `{}`",
                file.name
            )));
        }
        Ok(file)
    }

    fn save_file(&self, bare_name: &str, file: &AgentIdentityFile) -> CoreResult<()> {
        let path = self.agent_path(bare_name)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_vec_pretty(file)?)?;
        Ok(())
    }

    fn count_agent_files(&self) -> u64 {
        std::fs::read_dir(self.agents_dir())
            .map(|entries| {
                entries
                    .filter_map(std::result::Result::ok)
                    .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
                    .count() as u64
            })
            .unwrap_or(0)
    }

    /// Registers a new **enabled** agent with an empty policy set.
    ///
    /// # Errors
    /// * [`TypeError`](vaultx_types::TypeError) when the bare name cannot
    ///   form a valid `agent_`-prefixed [`AgentId`].
    /// * [`CoreError::AlreadyExists`] when an identity file exists.
    pub fn create_agent(&self, bare_name: &str) -> CoreResult<AgentId> {
        let full_id = self.validate_bare_name(bare_name)?;
        let path = self.agents_dir().join(format!("{bare_name}.json"));
        if path.exists() {
            return Err(CoreError::AlreadyExists(format!("agent `{bare_name}`")));
        }
        let sequence = self.count_agent_files() + 1;
        self.save_file(
            bare_name,
            &AgentIdentityFile {
                name: full_id.clone(),
                enabled: true,
                policy_names: Vec::new(),
                created_sequence: sequence,
            },
        )?;
        Ok(full_id)
    }

    /// Enables a previously disabled agent.
    ///
    /// # Errors
    /// * [`CoreError::AgentNotFound`] for unknown agents.
    pub fn enable(&self, bare_name: &str) -> CoreResult<()> {
        self.set_enabled(bare_name, true)
    }

    /// Disables an agent. This is v1 revocation: no session machinery
    /// exists yet, so revocation simply flips the flag and persists it.
    ///
    /// # Errors
    /// * [`CoreError::AgentNotFound`] for unknown agents.
    pub fn disable(&self, bare_name: &str) -> CoreResult<()> {
        self.set_enabled(bare_name, false)
    }

    fn set_enabled(&self, bare_name: &str, enabled: bool) -> CoreResult<()> {
        let mut file = self.load_file(bare_name)?;
        file.enabled = enabled;
        self.save_file(bare_name, &file)
    }

    /// Attaches a policy to an agent (idempotent per policy name).
    ///
    /// # Errors
    /// * [`CoreError::AgentNotFound`] for unknown agents.
    /// * [`TypeError`](vaultx_types::TypeError) for invalid policy names.
    pub fn attach_policy(&self, bare_name: &str, policy_name: &str) -> CoreResult<()> {
        let parsed = PolicyName::parse(policy_name)?;
        let mut file = self.load_file(bare_name)?;
        if !file.policy_names.contains(&parsed) {
            file.policy_names.push(parsed);
            self.save_file(bare_name, &file)?;
        }
        Ok(())
    }

    /// Lists all agents sorted by bare name.
    ///
    /// # Errors
    /// * Propagates read/decode failures ([`CoreError::Json`] for corrupt
    ///   identity files).
    pub fn list_agents(&self) -> CoreResult<Vec<AgentSummary>> {
        let mut agents = Vec::new();
        let dir = self.agents_dir();
        if !dir.is_dir() {
            return Ok(agents);
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path)?;
            let file = serde_json::from_str::<AgentIdentityFile>(&raw)?;
            let bare = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_owned();
            agents.push(AgentSummary {
                name: bare,
                enabled: file.enabled,
            });
        }
        agents.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(agents)
    }

    /// Full detail of one agent.
    ///
    /// # Errors
    /// * [`CoreError::AgentNotFound`] for unknown agents.
    pub fn inspect(&self, bare_name: &str) -> CoreResult<AgentIdentityFile> {
        self.load_file(bare_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::ProjectContext;

    #[test]
    fn agent_lifecycle_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ProjectContext::init(dir.path()).unwrap();
        let agents = AgentLifecycleService::new(&ctx);

        let full = agents.create_agent("ci-bot").unwrap();
        assert_eq!(full.as_str(), "agent_ci-bot");
        assert!(matches!(
            agents.create_agent("ci-bot"),
            Err(CoreError::AlreadyExists(_))
        ));
        assert!(matches!(
            agents.create_agent("Bad Name!"),
            Err(CoreError::Id(_))
        ));

        agents.attach_policy("ci-bot", "read_only").unwrap();
        agents.attach_policy("ci-bot", "deploy_helper").unwrap();
        // Idempotent re-attach keeps a single entry.
        agents.attach_policy("ci-bot", "read_only").unwrap();

        let detail = agents.inspect("ci-bot").unwrap();
        assert!(detail.enabled);
        assert_eq!(detail.created_sequence, 1);
        assert_eq!(
            detail
                .policy_names
                .iter()
                .map(PolicyName::as_str)
                .collect::<Vec<_>>(),
            vec!["read_only", "deploy_helper"]
        );

        agents.disable("ci-bot").unwrap();
        assert!(!agents.inspect("ci-bot").unwrap().enabled);
        assert!(agents.enable("ghost").is_err());
        assert!(matches!(
            agents.inspect("ghost"),
            Err(CoreError::AgentNotFound(_))
        ));

        // Second agent gets the next sequence number.
        agents.create_agent("sync-daemon").unwrap();
        assert_eq!(agents.inspect("sync-daemon").unwrap().created_sequence, 2);

        let listed = agents.list_agents().unwrap();
        assert_eq!(
            listed.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
            vec!["ci-bot", "sync-daemon"]
        );
        assert!(!listed[0].enabled);

        // Persistence across reopen.
        drop(ctx);
        let reopened = ProjectContext::open(dir.path()).unwrap();
        let detail = AgentLifecycleService::new(&reopened)
            .inspect("ci-bot")
            .unwrap();
        assert!(!detail.enabled);
        assert_eq!(detail.policy_names.len(), 2);
        assert_eq!(detail.name.as_str(), "agent_ci-bot");

        // A hand-edited file with mismatched inner id is refused.
        let tampered_path = reopened.vault_dir().join("agents").join("sync-daemon.json");
        let mut tampered = serde_json::from_str::<AgentIdentityFile>(
            &std::fs::read_to_string(&tampered_path).unwrap(),
        )
        .unwrap();
        tampered.name = AgentId::parse("agent_something_else").unwrap();
        std::fs::write(
            &tampered_path,
            serde_json::to_vec_pretty(&tampered).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            AgentLifecycleService::new(&reopened).inspect("sync-daemon"),
            Err(CoreError::UnsupportedOperation(_))
        ));
    }
}
