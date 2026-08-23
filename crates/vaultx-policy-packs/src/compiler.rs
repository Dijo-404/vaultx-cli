//! Pack compiler: lowers a validated [`PolicyPack`] into the generic
//! broker constraint set ([`CompiledPack`]) and its
//! [`vaultx_policy::PolicyDocument`] projection.
//!
//! Compilation is where broker invariants are *preserved* rather than
//! merely checked:
//!
//! * path placeholders compile to single-segment `*` wildcards so the
//!   output patterns are directly consumable by the rule engine's
//!   matcher;
//! * `set-cookie` is force-appended to the response redaction list and
//!   the credential-bearing header pair is force-added to the request
//!   deny list — packs can add restrictions but never remove defaults;
//! * limits have already been capped at validation time, so compiled
//!   values can never exceed the global ceilings.

use vaultx_policy::{
    EnvironmentRules, HttpMethod, HttpRules, MethodPathRule, PolicyDocument, Principal,
    RequestConstraints, ResponseConstraints,
};
use vaultx_types::model::InjectionTemplateId;
use vaultx_types::{CredentialRef, PolicyName, ProviderName};

use crate::error::PackError;
use crate::schema::{PolicyPack, FORCED_REDACT_HEADER};

/// Prefix applied when deriving a [`PolicyName`] from a capability name;
/// keeps pack-derived policies distinguishable from hand-authored ones.
const POLICY_NAME_PREFIX: &str = "pack-";

/// Credential-bearing headers every pack-derived policy denies on the
/// request path, mirroring hand-authored policy documents. The broker's
/// transport-level sensitive-header filter stays authoritative; this is
/// defense in depth at the policy layer.
const FORCED_REQUEST_DENY_HEADERS: [&str; 2] = ["authorization", "proxy-authorization"];

/// The generic broker constraint set produced from one pack.
///
/// Everything here is expressed in primitives the broker already
/// understands; `query_allowlist`, `content_type_allowlist`, and the
/// response field keys have no policy-document counterpart and are
/// consumed by the transport/response-sanitizer layers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledPack {
    /// Original dotted capability name.
    pub capability: String,
    /// Policy name derived for engine integration (see
    /// [`CompiledPack::policy_name_for`]).
    pub policy_name: PolicyName,
    /// Credential provider of the source pack.
    pub provider: ProviderName,
    /// Exact hostnames (lowercase).
    pub hosts: Vec<String>,
    /// HTTP methods allowed by the capability.
    pub methods: Vec<HttpMethod>,
    /// Path templates as written in the pack (placeholders intact).
    pub path_templates: Vec<String>,
    /// Matcher-grammar patterns (`{name}` → `*`) consumable by the rule
    /// engine.
    pub path_patterns: Vec<String>,
    /// Query parameter keys the capability may send (empty =
    /// unconstrained).
    pub query_allowlist: Vec<String>,
    /// Logical credential ID bound to this capability.
    pub credential_ref: CredentialRef,
    /// Injection template selected by the pack.
    pub injection: InjectionTemplateId,
    /// Request body cap (already ≤ 256 KiB).
    pub max_request_body_bytes: Option<u64>,
    /// Allowed media types, lowercased (empty = unconstrained).
    pub content_type_allowlist: Vec<String>,
    /// Request headers denied at the policy layer; always contains
    /// `authorization` and `proxy-authorization`.
    pub deny_request_headers: Vec<String>,
    /// Response body cap (already ≤ 1 MiB).
    pub max_response_body_bytes: Option<u64>,
    /// Response headers redacted before delivery; always contains
    /// `set-cookie`.
    pub redact_response_headers: Vec<String>,
    /// Exact JSON object keys redacted from response bodies.
    pub redact_response_fields: Vec<String>,
}

impl CompiledPack {
    /// Derives the deterministic [`PolicyName`] for a capability name:
    /// `pack-` prefix plus dots replaced with underscores.
    ///
    /// The derivation is *not* injective: two capability names differing
    /// only in their dot/underscore layout (`a.b` and `a_b`) derive to
    /// the same policy name. [`crate::load_pack_dir`] therefore rejects
    /// such collisions up front with
    /// [`PackError::AmbiguousCapabilityName`] instead of letting them
    /// surface later as confusing duplicate-policy failures during
    /// engine construction.
    ///
    /// # Errors
    /// Returns [`PackError::InvalidField`] if the derived value somehow
    /// fails [`PolicyName`] validation; unreachable for names accepted by
    /// pack validation (charset subset, bounded length), kept so the
    /// function is total over public input.
    pub fn policy_name_for(capability: &str) -> Result<PolicyName, PackError> {
        let derived = format!("{POLICY_NAME_PREFIX}{}", capability.replace('.', "_"));
        PolicyName::parse(&derived).map_err(|_| PackError::InvalidField {
            field: "name".to_owned(),
            reason: format!("`{capability}` does not map onto a valid policy name"),
        })
    }

    /// Projects the compiled constraints onto a
    /// [`vaultx_policy::PolicyDocument`] bound to `principal`, ready for
    /// [`vaultx_policy::RuleEngine`] construction.
    ///
    /// Constraints without a document counterpart (query allowlist,
    /// content types, response field redaction) stay on
    /// [`CompiledPack`] for the broker layers that enforce them.
    #[must_use]
    pub fn to_policy_document(&self, principal: &Principal) -> PolicyDocument {
        PolicyDocument {
            name: self.policy_name.clone(),
            principal: principal.clone(),
            credential: self.credential_ref.clone(),
            environment: EnvironmentRules::default(),
            http: HttpRules {
                hosts: self.hosts.clone(),
                allow: vec![MethodPathRule {
                    methods: self.methods.clone(),
                    paths: self.path_patterns.clone(),
                }],
                deny: vec![],
            },
            request: RequestConstraints {
                max_body_bytes: self.max_request_body_bytes,
                deny_headers: self.deny_request_headers.clone(),
            },
            response: ResponseConstraints {
                max_body_bytes: self.max_response_body_bytes,
                redact_headers: self.redact_response_headers.clone(),
            },
        }
    }
}

/// Compiles a validated pack into generic broker constraints.
///
/// # Errors
/// Re-runs every pack invariant first so hand-constructed packs get the
/// same typed rejections as parsed ones; compilation never weakens an
/// invalid pack into a valid-looking output.
pub fn compile(pack: &PolicyPack) -> Result<CompiledPack, PackError> {
    pack.validate()?;

    let mut redact_headers = pack
        .response
        .as_ref()
        .map(|rules| rules.redact_headers.clone())
        .unwrap_or_default();
    if !redact_headers.iter().any(|h| h == FORCED_REDACT_HEADER) {
        redact_headers.push(FORCED_REDACT_HEADER.to_owned());
    }

    Ok(CompiledPack {
        capability: pack.name.clone(),
        policy_name: CompiledPack::policy_name_for(&pack.name)?,
        provider: pack.provider.clone(),
        hosts: pack.request.hosts.clone(),
        methods: pack.request.methods.clone(),
        path_templates: pack.request.paths.clone(),
        path_patterns: pack
            .request
            .paths
            .iter()
            .map(|path| compile_path_pattern(path))
            .collect(),
        query_allowlist: pack.request.query_allowlist.clone().unwrap_or_default(),
        credential_ref: pack.credential.credential_ref.clone(),
        injection: pack.credential.injection,
        max_request_body_bytes: pack.constraints.max_body_bytes,
        content_type_allowlist: pack
            .constraints
            .content_types
            .iter()
            .flatten()
            .map(|media_type| media_type.to_ascii_lowercase())
            .collect(),
        deny_request_headers: FORCED_REQUEST_DENY_HEADERS
            .iter()
            .map(|header| (*header).to_owned())
            .collect(),
        max_response_body_bytes: pack.response.as_ref().and_then(|r| r.max_body_bytes),
        redact_response_fields: pack
            .response
            .as_ref()
            .map(|rules| rules.redact_fields.clone())
            .unwrap_or_default(),
        redact_response_headers: redact_headers,
    })
}

/// Rewrites `{placeholder}` segments into the matcher's single-segment
/// wildcard while leaving literals (including a trailing `/**`)
/// untouched.
fn compile_path_pattern(template: &str) -> String {
    template
        .split('/')
        .map(|segment| {
            if segment.starts_with('{') && segment.ends_with('}') && segment.len() >= 2 {
                "*"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    const PACK_YAML: &str = r#"
format: 1
name: test.capability.call
provider: github
request:
  hosts: [api.github.com]
  methods: [GET, POST]
  paths: ["/repos/{owner}/{repo}", "/repos/{owner}/{repo}/pulls"]
credential:
  credential_ref: github-work-token
  injection: github-bearer
constraints:
  max_body_bytes: 65536
response:
  max_body_bytes: 262144
  redact_headers: [x-request-id]
"#;

    fn pack() -> PolicyPack {
        crate::parse_pack_yaml(PACK_YAML).expect("pack parses")
    }

    #[test]
    fn compiles_placeholders_to_matcher_wildcards_and_keeps_templates() {
        let compiled = compile(&pack()).unwrap();
        assert_eq!(
            compiled.path_templates,
            vec![
                "/repos/{owner}/{repo}".to_owned(),
                "/repos/{owner}/{repo}/pulls".to_owned()
            ]
        );
        assert_eq!(
            compiled.path_patterns,
            vec!["/repos/*/*".to_owned(), "/repos/*/*/pulls".to_owned()]
        );
    }

    #[test]
    fn set_cookie_is_always_redacted_even_without_response_rules() {
        let with_rules = compile(&pack()).unwrap();
        assert!(with_rules
            .redact_response_headers
            .iter()
            .any(|header| header == FORCED_REDACT_HEADER));
        assert_eq!(
            with_rules
                .redact_response_headers
                .iter()
                .filter(|header| **header == FORCED_REDACT_HEADER)
                .count(),
            1,
            "forced entry is not duplicated when declared"
        );

        let mut bare = pack();
        bare.response = None;
        let compiled = compile(&bare).unwrap();
        assert_eq!(
            compiled.redact_response_headers,
            vec![FORCED_REDACT_HEADER.to_owned()]
        );
        assert_eq!(compiled.max_response_body_bytes, None);
    }

    #[test]
    fn revalidates_hand_built_packs_before_compiling() {
        let mut bad = pack();
        bad.format = 7;
        let err = compile(&bad).unwrap_err();
        assert!(err.to_string().contains("`format`"), "{err}");

        let mut private_host = pack();
        private_host.request.hosts = vec!["localhost".to_owned()];
        assert!(matches!(
            compile(&private_host),
            Err(PackError::ForbiddenHost { .. })
        ));
    }

    #[test]
    fn policy_names_derive_deterministically_with_prefix() {
        assert_eq!(
            CompiledPack::policy_name_for("github.pull_request.create")
                .unwrap()
                .as_str(),
            "pack-github_pull_request_create"
        );
        assert_eq!(
            CompiledPack::policy_name_for("a_b_c").unwrap().as_str(),
            "pack-a_b_c"
        );
        // Deterministic across repeated calls.
        assert_eq!(
            CompiledPack::policy_name_for("a.b").unwrap(),
            CompiledPack::policy_name_for("a.b").unwrap()
        );
    }

    #[test]
    fn mixed_dot_underscore_capability_names_collide_at_load_time() {
        // Per-name compilation stays total: a single pack cannot know
        // whether its derived name is contested.
        assert!(CompiledPack::policy_name_for("a.b").is_ok());
        assert!(CompiledPack::policy_name_for("a_b").is_ok());

        // Two capabilities differing only in dot/underscore layout derive
        // to the same policy name; directory loading rejects the collision
        // up front instead of deferring to engine construction.
        let dir = tempfile::tempdir().unwrap();
        for (file, name) in [
            ("one.yaml", "test.capability.x"),
            ("nested/two.yaml", "test_capability.x"),
        ] {
            let path = dir.path().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, PACK_YAML.replace("test.capability.call", name)).unwrap();
        }
        let err = crate::load_pack_dir(dir.path()).unwrap_err();
        assert!(
            matches!(&err, PackError::AmbiguousCapabilityName(name) if name == "test.capability.x"),
            "{err}"
        );
    }

    #[test]
    fn request_deny_headers_baseline_is_always_present_in_documents() {
        let compiled = compile(&pack()).unwrap();
        assert_eq!(
            compiled.deny_request_headers,
            vec!["authorization".to_owned(), "proxy-authorization".to_owned()]
        );
        let principal =
            vaultx_policy::Principal::parse("agent:baseline-check").expect("principal parses");
        let document = compiled.to_policy_document(&principal);
        assert_eq!(
            document.request.deny_headers,
            vec!["authorization".to_owned(), "proxy-authorization".to_owned()]
        );
    }

    #[test]
    fn content_types_are_lowercased_at_compile_time() {
        let yaml = PACK_YAML.replace(
            "constraints:\n  max_body_bytes: 65536",
            "constraints:\n  max_body_bytes: 65536\n  content_types: [Application/JSON]",
        );
        let pack = crate::parse_pack_yaml(&yaml).unwrap();
        let compiled = compile(&pack).unwrap();
        assert_eq!(compiled.content_type_allowlist, vec!["application/json"]);
    }

    #[test]
    fn query_allowlist_defaults_to_empty_when_absent() {
        let compiled = compile(&pack()).unwrap();
        assert!(compiled.query_allowlist.is_empty());

        let yaml = PACK_YAML.replace(
            "request:\n  hosts:",
            "request:\n  query_allowlist: [page]\n  hosts:",
        );
        let pack = crate::parse_pack_yaml(&yaml).unwrap();
        assert_eq!(compile(&pack).unwrap().query_allowlist, vec!["page"]);
    }
}
