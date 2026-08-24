//! Secret-value masking and the diff-redaction guarantee (plan §15/§38).
//!
//! Every line a TUI diff view renders is produced by [`redact_diff`] or
//! [`policy_delta`]. Both functions are constructed to emit **metadata
//! only** — variable names, revision ids, object ids, host/path/method
//! tokens — because none of their inputs can carry plaintext secret
//! material ([`DiffEntry`] is metadata-only by construction, and
//! [`PolicyDocument`] holds no secret fields). The rendering layer never
//! receives a value it would have to scrub after the fact.

use vaultx_core::DiffEntry;
use vaultx_policy::{HttpMethod, MethodPathRule, PolicyDocument};

/// Replacement shown in place of every secret/brokered value.
pub const MASK: &str = "••••";

/// Marker appended to brokered credential logical names in agent views.
///
/// Brokered credentials are represented as non-revealable: their logical
/// name may be displayed, but there is deliberately no reveal action and
/// no code path that could render brokered material.
pub const NON_REVEALABLE: &str = "[non-revealable]";

/// One rendered, already-redacted diff line. `marker` is `'+'`, `'-'`,
/// `'~'`, or `' '` (context/header).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedLine {
    /// Git-style change marker.
    pub marker: char,
    /// Metadata-only line body.
    pub text: String,
}

impl RedactedLine {
    fn context(text: impl Into<String>) -> Self {
        Self {
            marker: ' ',
            text: text.into(),
        }
    }

    fn new(marker: char, text: impl Into<String>) -> Self {
        Self {
            marker,
            text: text.into(),
        }
    }
}

/// Returns the display replacement for one entry reference.
///
/// Secret and brokered entries are always masked; config/dynamic
/// references are plain metadata ids and render verbatim.
#[must_use]
pub fn mask_reference(kind: &str, reference: &str) -> String {
    match kind {
        "secret" | "brokered" => MASK.to_owned(),
        _ => reference.to_owned(),
    }
}

/// Renders a manifest diff as git-style lines that provably contain no
/// secret content (plan §38 diff example: revision deltas only).
#[must_use]
pub fn redact_diff(entries: &[DiffEntry]) -> Vec<RedactedLine> {
    let mut out = Vec::new();
    for entry in entries {
        match entry {
            DiffEntry::ConfigAdded { name, value } => {
                out.push(RedactedLine::new('+', format!("config {name} = {value}")));
            }
            DiffEntry::ConfigRemoved { name } => {
                out.push(RedactedLine::new('-', format!("config {name}")));
            }
            DiffEntry::ConfigChanged { name, old, new } => {
                out.push(RedactedLine::context(name.as_str()));
                out.push(RedactedLine::new('-', format!("config {old}")));
                out.push(RedactedLine::new('+', format!("config {new}")));
            }
            DiffEntry::SecretAdded { name, revision } => {
                out.push(RedactedLine::new(
                    '+',
                    format!("secret {name} @ {revision}"),
                ));
            }
            DiffEntry::SecretRemoved { name, revision } => {
                out.push(RedactedLine::new(
                    '-',
                    format!("secret {name} (was @ {revision})"),
                ));
            }
            DiffEntry::SecretRevisionChanged {
                name,
                old_revision,
                new_revision,
            } => {
                out.push(RedactedLine::context(name.as_str()));
                out.push(RedactedLine::new('-', format!("revision {old_revision}")));
                out.push(RedactedLine::new('+', format!("revision {new_revision}")));
            }
            DiffEntry::CredentialAdded { name, binding } => {
                out.push(RedactedLine::new(
                    '+',
                    format!(
                        "brokered {name} = {}@{}",
                        binding.credential, binding.revision
                    ),
                ));
            }
            DiffEntry::CredentialRemoved { name, binding } => {
                out.push(RedactedLine::new(
                    '-',
                    format!(
                        "brokered {name} (was {}@{})",
                        binding.credential, binding.revision
                    ),
                ));
            }
            DiffEntry::CredentialBindingChanged {
                name,
                old_binding,
                new_binding,
            } => {
                out.push(RedactedLine::context(name.as_str()));
                out.push(RedactedLine::new(
                    '-',
                    format!(
                        "brokered {}@{}",
                        old_binding.credential, old_binding.revision
                    ),
                ));
                out.push(RedactedLine::new(
                    '+',
                    format!(
                        "brokered {}@{}",
                        new_binding.credential, new_binding.revision
                    ),
                ));
            }
            DiffEntry::DynamicAdded { name, provider } => {
                out.push(RedactedLine::new(
                    '+',
                    format!("dynamic {name} via {provider}"),
                ));
            }
            DiffEntry::DynamicRemoved { name, provider } => {
                out.push(RedactedLine::new(
                    '-',
                    format!("dynamic {name} (was via {provider})"),
                ));
            }
            DiffEntry::DynamicProviderChanged {
                name,
                old_provider,
                new_provider,
            } => {
                out.push(RedactedLine::context(name.as_str()));
                out.push(RedactedLine::new('-', format!("dynamic {old_provider}")));
                out.push(RedactedLine::new('+', format!("dynamic {new_provider}")));
            }
            DiffEntry::VariableKindChanged {
                name,
                old_kind,
                new_kind,
            } => {
                out.push(RedactedLine::new(
                    '~',
                    format!("kind {name} : {old_kind:?} -> {new_kind:?}"),
                ));
            }
            // Policy entries whose documents cannot be resolved degrade to
            // object-id metadata; `policy_delta` replaces them when both
            // documents are available.
            DiffEntry::PolicyAdded {
                name,
                policy_object,
            } => {
                out.push(RedactedLine::new(
                    '+',
                    format!("policy {name} = {policy_object}"),
                ));
            }
            DiffEntry::PolicyRemoved {
                name,
                policy_object,
            } => {
                out.push(RedactedLine::new(
                    '-',
                    format!("policy {name} (was {policy_object})"),
                ));
            }
            DiffEntry::PolicyChanged {
                name,
                old_policy_object,
                new_policy_object,
            } => {
                out.push(RedactedLine::context(name.as_str()));
                out.push(RedactedLine::new(
                    '-',
                    format!("policy {old_policy_object}"),
                ));
                out.push(RedactedLine::new(
                    '+',
                    format!("policy {new_policy_object}"),
                ));
            }
        }
    }
    out
}

fn rule_lines(rules: &[MethodPathRule], deny: bool) -> Vec<(String, String)> {
    let tag = if deny { "(deny) " } else { "" };
    rules
        .iter()
        .flat_map(|rule| {
            rule.methods.iter().flat_map(move |method| {
                rule.paths
                    .iter()
                    .map(move |path| (format!("{tag}{}", method_token(*method)), path.clone()))
            })
        })
        .collect()
}

fn method_token(method: HttpMethod) -> &'static str {
    method.as_str()
}

/// Renders host/path/method deltas between two policy documents (plan
/// §38 policy-diff example). Output is deterministic and metadata-only:
/// host additions/removals first, then removed and added allow/deny rules.
#[must_use]
pub fn policy_delta(old: &PolicyDocument, new: &PolicyDocument) -> Vec<RedactedLine> {
    let mut out = Vec::new();

    for host in &old.http.hosts {
        if !new.http.hosts.contains(host) {
            out.push(RedactedLine::new('-', format!("host {host}")));
        }
    }
    for host in &new.http.hosts {
        if !old.http.hosts.contains(host) {
            out.push(RedactedLine::new('+', format!("host {host}")));
        }
    }

    let mut removed = rule_lines(&old.http.deny, true);
    removed.extend(rule_lines(&old.http.allow, false));
    let mut added = rule_lines(&new.http.deny, true);
    added.extend(rule_lines(&new.http.allow, false));
    removed.sort();
    added.sort();

    for (method, path) in &removed {
        if !added.contains(&(method.clone(), path.clone())) {
            out.push(RedactedLine::new('-', format!("{method} {path}")));
        }
    }
    for (method, path) in &added {
        if !removed.contains(&(method.clone(), path.clone())) {
            out.push(RedactedLine::new('+', format!("{method} {path}")));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaultx_types::{SecretRevisionId, VariableName};

    const CANARY: &str = "hunter2-plaintext-canary";

    fn revision(raw: &str) -> SecretRevisionId {
        SecretRevisionId::parse(raw).expect("valid revision id")
    }

    #[test]
    fn secret_and_brokered_references_are_always_masked() {
        assert_eq!(mask_reference("secret", CANARY), MASK);
        assert_eq!(mask_reference("brokered", CANARY), MASK);
        assert_eq!(
            mask_reference("config", "obj_manifest_main"),
            "obj_manifest_main"
        );
    }

    #[test]
    fn redact_diff_emits_revision_metadata_without_plaintext() {
        let name = VariableName::parse("STRIPE_KEY").unwrap();
        let entries = vec![
            DiffEntry::SecretAdded {
                name: name.clone(),
                revision: revision("sec_rev_000001"),
            },
            DiffEntry::SecretRevisionChanged {
                name,
                old_revision: revision("sec_rev_000001"),
                new_revision: revision("sec_rev_000002"),
            },
        ];
        let rendered: String = redact_diff(&entries)
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n");

        assert!(rendered.contains("STRIPE_KEY"));
        assert!(rendered.contains("@ sec_rev_000001"));
        assert!(rendered.contains("revision sec_rev_000002"));
        assert!(!rendered.contains(CANARY));
    }

    #[test]
    fn policy_delta_lists_host_and_rule_changes_only() {
        use vaultx_policy::{
            validate_policy, EnvironmentRules, HttpRules, PolicyDocument, Principal,
            RequestConstraints, ResponseConstraints,
        };
        use vaultx_types::{CredentialRef, PolicyName};

        fn document(hosts: &[&str], allow_paths: &[&str]) -> PolicyDocument {
            let document = PolicyDocument {
                name: PolicyName::parse("stripe").unwrap(),
                principal: Principal::parse("agent:bot").unwrap(),
                credential: CredentialRef::parse("deploy_token-1").unwrap(),
                environment: EnvironmentRules::default(),
                http: HttpRules {
                    hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
                    allow: allow_paths
                        .iter()
                        .map(|p| MethodPathRule {
                            methods: vec![HttpMethod::GET],
                            paths: vec![(*p).to_owned()],
                        })
                        .collect(),
                    deny: Vec::new(),
                },
                request: RequestConstraints::default(),
                response: ResponseConstraints::default(),
            };
            validate_policy(&document).expect("valid document");
            document
        }

        let old = document(&["api.example.com"], &["/v1/charges", "/v1/customers"]);
        let new = document(&["api.example.com", "files.example.com"], &["/v1/charges"]);

        let rendered: String = policy_delta(&old, &new)
            .into_iter()
            .map(|line| format!("{}{}", line.marker, line.text))
            .collect();

        assert!(rendered.contains("+host files.example.com"));
        assert!(rendered.contains("-GET /v1/customers"));
        assert!(!rendered.contains("+GET /v1/customers"));
        assert!(!rendered.contains(CANARY));
    }
}
