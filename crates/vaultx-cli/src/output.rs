//! Presentation helpers rendering `vaultx-core` service results as
//! plain text.
//!
//! Rules (task §output):
//!
//! * nothing here prints secret material — core services only ever
//!   surface identifiers, config values, and metadata;
//! * diffs are rendered straight from [`DiffEntry`]'s `Display`;
//! * tables use space-padded aligned columns with the last column left
//!   unpadded;
//! * commit ids appear in short form (`cmt_` + first 12 hex chars) for
//!   listings, full form where uniqueness matters.

use std::path::Path;

use vaultx_core::{
    AgentIdentityFile, AgentSummary, CommitDetail, CommitSummary, DiffEntry, EntrySummary,
    EnvironmentSummary, ImportReport, MergeConflictSet, RollbackReport, SecretMetadata,
    StatusReport,
};
use vaultx_policy_packs::PolicyPack;
use vaultx_types::model::{InjectionTemplateId, VariableKind};
use vaultx_types::CommitId;

/// Number of hex characters kept in short commit ids.
const SHORT_HEX_LEN: usize = 12;

/// Renders a commit id as `cmt_<first 12 hex chars>`.
///
/// Ids shorter than the canonical hex length (defensive) keep whatever
/// they have.
#[must_use]
pub fn short_commit_id(id: &CommitId) -> String {
    let text = id.as_str();
    let hex = text.strip_prefix(CommitId::PREFIX).unwrap_or(text);
    let keep = hex.len().min(SHORT_HEX_LEN);
    format!("{}{}", CommitId::PREFIX, &hex[..keep])
}

/// Renders headers plus rows as aligned columns.
///
/// Every row must carry exactly one cell per header; the final column is
/// not padded so values never gain trailing spaces. An empty `rows`
/// yields just the header line; callers usually pre-check for empty
/// input to print friendlier notices instead.
#[must_use]
pub fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    debug_assert!(rows.iter().all(|row| row.len() == headers.len()));
    let mut widths: Vec<usize> = headers
        .iter()
        .map(|header| header.chars().count())
        .collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }
    let mut lines = vec![padded_line(
        &headers
            .iter()
            .map(|header| (*header).to_owned())
            .collect::<Vec<_>>(),
        &widths,
    )];
    lines.extend(rows.iter().map(|row| padded_line(row, &widths)));
    lines.join("\n")
}

/// Joins cells into one line, padding every cell but the last to its
/// column width.
fn padded_line(cells: &[String], widths: &[usize]) -> String {
    let last = cells.len().saturating_sub(1);
    cells
        .iter()
        .enumerate()
        .map(|(index, cell)| {
            if index == last {
                cell.clone()
            } else {
                format!("{:<width$}", cell, width = widths[index])
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Renders the `vaultx status` report: branch, head, staged table.
#[must_use]
pub fn render_status(report: &StatusReport) -> String {
    let branch = report
        .branch
        .clone()
        .unwrap_or_else(|| "(detached)".to_owned());
    let head = report
        .head_commit
        .as_ref()
        .map_or_else(|| "(none)".to_owned(), ToString::to_string);
    let mut lines = vec![format!("branch: {branch}"), format!("head:   {head}")];
    if report.staged_changes.is_empty() {
        lines.push("staged: (none)".to_owned());
    } else {
        lines.push(format!("staged: {} change(s)", report.staged_changes.len()));
        let rows: Vec<Vec<String>> = report
            .staged_changes
            .iter()
            .map(|(name, kind)| vec![format!("  {name}"), kind.to_string()])
            .collect();
        lines.push(render_table(&["  NAME", "CHANGE"], &rows));
    }
    lines.join("\n")
}

/// Renders the committed-config listing (`vaultx list`).
///
/// Rows arrive pre-shaped as NAME/KIND/VALUE triples; an empty set
/// prints a friendly notice because the HEAD manifest legitimately
/// starts out empty.
#[must_use]
pub fn render_config_list(rows: &[Vec<String>]) -> String {
    if rows.is_empty() {
        return "no config variables committed".to_owned();
    }
    render_table(&["NAME", "KIND", "VALUE"], rows)
}

/// Renders an import summary: what was stored, what needs secrets, and
/// what was skipped (already bound or invalid). Secret *values* never
/// reach this layer; only names are reported.
#[must_use]
pub fn render_import_report(file: &Path, report: &ImportReport) -> String {
    let mut lines = vec![format!(
        "imported {} config value(s) from {}",
        report.added_config.len(),
        file.display()
    )];
    if !report.added_config.is_empty() {
        lines.push(format!("added: {}", report.added_config.join(", ")));
    }
    if !report.needs_secret.is_empty() {
        lines.push(format!(
            "needs secret (not stored): {}",
            report.needs_secret.join(", ")
        ));
    }
    if !report.skipped_existing.is_empty() {
        lines.push(format!(
            "skipped already bound: {}",
            report.skipped_existing.join(", ")
        ));
    }
    if !report.skipped_invalid.is_empty() {
        lines.push(format!(
            "skipped invalid names: {}",
            report.skipped_invalid.join(", ")
        ));
    }
    lines.join("\n")
}

/// Renders history entries newest-first:
/// `<short-id> <message> [<author>]`.
#[must_use]
pub fn render_log(entries: &[CommitSummary]) -> String {
    if entries.is_empty() {
        return "no commits yet".to_owned();
    }
    entries
        .iter()
        .map(|entry| {
            format!(
                "{} {} [{}]",
                short_commit_id(&entry.id),
                entry.message,
                entry.author
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders one commit's detail block including its captured entries.
#[must_use]
pub fn render_commit_detail(detail: &CommitDetail) -> String {
    let parents = if detail.parents.is_empty() {
        "(none)".to_owned()
    } else {
        detail
            .parents
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut lines = vec![
        format!("commit:  {}", detail.id),
        format!("author:  {}", detail.author),
        format!("parents: {parents}"),
        format!("message: {}", detail.message),
        String::new(),
    ];
    if detail.entries.is_empty() {
        lines.push("entries: (none)".to_owned());
    } else {
        lines.push(format!("entries: {}", detail.entries.len()));
        lines.push(render_entries_table(&detail.entries));
    }
    lines.join("\n")
}

/// Renders manifest entries as an indented NAME/KIND/REFERENCE table.
fn render_entries_table(entries: &[EntrySummary]) -> String {
    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|entry| {
            vec![
                format!("  {}", entry.name),
                entry.kind.to_owned(),
                entry.reference.clone(),
            ]
        })
        .collect();
    indent(render_table(&["  NAME", "KIND", "REFERENCE"], &rows))
}

/// Renders a metadata diff using [`DiffEntry`]'s own `Display`.
#[must_use]
pub fn render_diff(diff: &[DiffEntry]) -> String {
    if diff.is_empty() {
        return "no differences".to_owned();
    }
    diff.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders branches as NAME/TIP columns with short tips.
#[must_use]
pub fn render_branches(branches: &[(String, CommitId)]) -> String {
    if branches.is_empty() {
        return "no branches".to_owned();
    }
    let rows: Vec<Vec<String>> = branches
        .iter()
        .map(|(name, tip)| vec![name.clone(), short_commit_id(tip)])
        .collect();
    render_table(&["NAME", "TIP"], &rows)
}

/// Renders environments as NAME/PROTECTED/COMMIT columns.
#[must_use]
pub fn render_environments(environments: &[EnvironmentSummary]) -> String {
    if environments.is_empty() {
        return "no environments created".to_owned();
    }
    let rows: Vec<Vec<String>> = environments
        .iter()
        .map(|env| {
            vec![
                env.name.clone(),
                yes_no(env.protected).to_owned(),
                env.commit
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), short_commit_id),
            ]
        })
        .collect();
    render_table(&["NAME", "PROTECTED", "COMMIT"], &rows)
}

/// Renders `vaultx env inspect`: protection state, pinned commit, and
/// the captured manifest entries.
#[must_use]
pub fn render_env_inspect(
    name: &str,
    protected: bool,
    commit: &CommitId,
    entries: &[EntrySummary],
) -> String {
    let mut lines = vec![
        format!("environment: {name}"),
        format!("protected:   {}", yes_no(protected)),
        format!("commit:      {commit}"),
    ];
    if entries.is_empty() {
        lines.push("entries:     (none)".to_owned());
    } else {
        lines.push(format!("entries:     {}", entries.len()));
        lines.push(render_entries_table(entries));
    }
    lines.join("\n")
}

/// Renders agents as NAME/STATUS columns.
#[must_use]
pub fn render_agents(agents: &[AgentSummary]) -> String {
    if agents.is_empty() {
        return "no agents registered".to_owned();
    }
    let rows: Vec<Vec<String>> = agents
        .iter()
        .map(|agent| {
            vec![
                agent.name.clone(),
                if agent.enabled { "enabled" } else { "disabled" }.to_owned(),
            ]
        })
        .collect();
    render_table(&["NAME", "STATUS"], &rows)
}

/// Renders one agent identity file's fields (policies as a comma list).
#[must_use]
pub fn render_agent_detail(agent: &AgentIdentityFile) -> String {
    let policies = if agent.policy_names.is_empty() {
        "(none)".to_owned()
    } else {
        agent
            .policy_names
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    [
        format!("agent:    {}", agent.name),
        format!("enabled:  {}", yes_no(agent.enabled)),
        format!("policies: {policies}"),
        format!("sequence: {}", agent.created_sequence),
    ]
    .join("\n")
}

/// Renders per-policy validation outcomes: `OK <name>` or the failure
/// reason verbatim from the loader.
#[must_use]
pub fn render_policy_validation(results: Vec<Result<String, String>>) -> String {
    if results.is_empty() {
        return "no policies found".to_owned();
    }
    results
        .into_iter()
        .map(|result| match result {
            Ok(name) => format!("OK {name}"),
            Err(reason) => format!("ERROR {reason}"),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders `vaultx secret metadata`: identity, state, binding, keyed
/// fingerprint, and revision history. Never renders the secret value.
#[must_use]
pub fn render_secret_metadata(meta: &SecretMetadata) -> String {
    let binding = meta.brokered.as_ref().map_or_else(
        || "-".to_owned(),
        |b| {
            let provider = b
                .provider_hint
                .as_ref()
                .map_or_else(String::new, |p| format!(" ({p})"));
            format!(
                "{}@{}{}",
                b.credential_ref,
                injection_label(b.injection),
                provider
            )
        },
    );
    let mut lines = vec![
        format!("secret:      {}", meta.name),
        format!("id:          {}", meta.secret_id),
        format!("environment: {}", meta.environment),
        format!("state:       {}", meta.state),
        format!("kind:        {}", kind_label(meta.kind)),
        format!("binding:     {binding}"),
        // Keyed + non-invertible: fingerprints are safe to display.
        format!("fingerprint: {}", meta.fingerprint_hex),
        format!("created:     {}", meta.created_at),
    ];
    if meta.history.is_empty() {
        lines.push("revisions:   (none)".to_owned());
    } else {
        lines.push(format!("revisions:   {}", meta.history.len()));
        let rows: Vec<Vec<String>> = meta
            .history
            .iter()
            .map(|revision| {
                vec![
                    format!("  {}", revision.id),
                    revision.state.to_string(),
                    revision.created_at.to_string(),
                ]
            })
            .collect();
        lines.push(render_table(&["  REVISION", "STATE", "CREATED"], &rows));
    }
    lines.join("\n")
}

/// Renders a refused merge as grouped conflict blocks. Config values are
/// shown; secret conflicts carry revision ids only — never values.
#[must_use]
pub fn render_merge_conflicts(set: &MergeConflictSet) -> String {
    let mut lines = vec![format!("merge blocked by {} conflict(s)", set.len())];
    if !set.configs.is_empty() {
        lines.push("config conflicts (values shown):".to_owned());
        for conflict in &set.configs {
            lines.push(format!(
                "  {}: ours={} theirs={}",
                conflict.name, conflict.ours_value, conflict.theirs_value
            ));
        }
    }
    if !set.secrets.is_empty() {
        lines.push("secret conflicts (revision ids only):".to_owned());
        for conflict in &set.secrets {
            lines.push(format!(
                "  {}: ours={} theirs={}",
                conflict.name, conflict.ours_revision, conflict.theirs_revision
            ));
        }
    }
    if !set.policies.is_empty() {
        lines.push("policy conflicts:".to_owned());
        for name in &set.policies {
            lines.push(format!("  {name}"));
        }
    }
    lines.push("nothing was written; resolve the conflicts and retry".to_owned());
    lines.join("\n")
}

/// Renders a completed rollback: restored target, new commit id, and any
/// destroyed-secret warnings.
#[must_use]
pub fn render_rollback(report: &RollbackReport) -> String {
    let mut lines = vec![
        format!("rolled back to {}", short_commit_id(&report.target)),
        format!("new commit: {}", report.commit_id),
    ];
    for warning in &report.warnings {
        lines.push(format!("warning: {warning}"));
    }
    lines.join("\n")
}

/// Kebab-case label for an injection template (matches its serde form).
pub(crate) fn injection_label(template: InjectionTemplateId) -> &'static str {
    match template {
        InjectionTemplateId::Bearer => "bearer",
        InjectionTemplateId::BasicPassword => "basic-password",
        InjectionTemplateId::ApiKeyHeader => "api-key-header",
        InjectionTemplateId::GithubBearer => "github-bearer",
        InjectionTemplateId::QueryParameter => "query-parameter",
        InjectionTemplateId::AwsSigv4 => "aws-sigv4",
        InjectionTemplateId::CustomStaticHeaderPlusSecret => "custom-static-header-plus-secret",
    }
}

/// Lowercase label for a variable kind (matches the serde form).
fn kind_label(kind: VariableKind) -> &'static str {
    match kind {
        VariableKind::Config => "config",
        VariableKind::Secret => "secret",
        VariableKind::Brokered => "brokered",
        VariableKind::Dynamic => "dynamic",
    }
}

/// `"yes"` / `"no"` helper for boolean columns.
fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

/// Renders the full parsed form of one policy pack for
/// `vaultx pack inspect`. Only identifiers, hostnames, patterns, and
/// limits appear — never secret material.
#[must_use]
pub fn render_pack_inspect(pack: &PolicyPack) -> String {
    let mut lines = vec![
        format!("format:     {}", pack.format),
        format!("name:       {}", pack.name),
        format!("provider:   {}", pack.provider.as_str()),
        "request:".to_owned(),
    ];
    lines.push(format!("  hosts:    {}", pack.request.hosts.join(", ")));
    let methods: Vec<&str> = pack
        .request
        .methods
        .iter()
        .map(|method| method.as_str())
        .collect();
    lines.push(format!("  methods:  {}", methods.join(", ")));
    for path in &pack.request.paths {
        lines.push(format!("  path:     {path}"));
    }
    match &pack.request.query_allowlist {
        Some(keys) if !keys.is_empty() => {
            lines.push(format!("  query:    {}", keys.join(", ")));
        }
        _ => lines.push("  query:    (unconstrained)".to_owned()),
    }
    if let Some(variables) = &pack.request.variables {
        if !variables.is_empty() {
            let rendered = variables
                .iter()
                .map(|(name, kind)| format!("{name}: {kind}"))
                .collect::<Vec<_>>()
                .join(", ");
            lines.push(format!("  vars:     {rendered}"));
        }
    }
    lines.push("credential:".to_owned());
    lines.push(format!(
        "  ref:      {}",
        pack.credential.credential_ref.as_str()
    ));
    lines.push(format!(
        "  injection: {}",
        injection_label(pack.credential.injection)
    ));
    if pack.constraints.max_body_bytes.is_some() || pack.constraints.content_types.is_some() {
        lines.push("constraints:".to_owned());
        if let Some(max) = pack.constraints.max_body_bytes {
            lines.push(format!("  max_body_bytes: {max}"));
        }
        if let Some(types) = &pack.constraints.content_types {
            lines.push(format!("  content_types: {}", types.join(", ")));
        }
    }
    match &pack.response {
        Some(response) => {
            lines.push("response:".to_owned());
            if let Some(max) = response.max_body_bytes {
                lines.push(format!("  max_body_bytes: {max}"));
            }
            if !response.redact_headers.is_empty() {
                lines.push(format!(
                    "  redact_headers: {}",
                    response.redact_headers.join(", ")
                ));
            }
            if !response.redact_fields.is_empty() {
                lines.push(format!(
                    "  redact_fields: {}",
                    response.redact_fields.join(", ")
                ));
            }
        }
        None => lines.push("response: (none)".to_owned()),
    }
    lines.join("\n")
}

/// Prefixes every line of a nested block with two spaces.
fn indent(block: String) -> String {
    block
        .lines()
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n")
}
