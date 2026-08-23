//! Declarative policy packs: typed YAML capability descriptions compiled
//! into the generic broker constraint set.
//!
//! A [`PolicyPack`] says *what a capability may do* (hosts, methods, path
//! templates, credential binding, size/type limits). The compiler turns
//! it into a [`CompiledPack`] whose
//! [`to_policy_document`][CompiledPack::to_policy_document] projection is
//! directly consumable by [`vaultx_policy::RuleEngine`], so packs inherit
//! the existing default-deny, deny-first authorization semantics without
//! any new evaluation path.
//!
//! # Invariant preservation
//!
//! Packs can only narrow broker behavior:
//!
//! * `format: 1` is mandatory; unknown fields are rejected everywhere;
//! * `aws-sigv4` injection is rejected until the broker implements it;
//! * sensitive hop/auth headers cannot be smuggled in as "required"
//!   headers — no such schema field exists and unknown fields fail;
//! * response `set-cookie` redaction is forced at compile time;
//! * body-size limits are capped at the global 256 KiB / 1 MiB ceilings;
//! * hosts must be public registrable names: no IPs, ports, wildcards,
//!   loopback/private suffixes, or cloud metadata endpoints.

mod compiler;
mod error;
mod loader;
mod schema;

pub use compiler::{compile, CompiledPack};
pub use error::PackError;
pub use loader::{load_pack, load_pack_dir, pack_files, parse_pack_yaml};
pub use schema::{
    PackConstraints, PackCredentialBinding, PackRequestTemplate, PackResponseRules, PolicyPack,
    FORCED_REDACT_HEADER, MAX_REQUEST_BODY_BYTES_CAP, MAX_RESPONSE_BODY_BYTES_CAP,
    PACK_FORMAT_VERSION,
};

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use vaultx_policy::{
        Action, AuthorizationContext, AuthorizationDecision, AuthorizationRequest, Authorizer,
        DenyReason, HttpMethod, Principal, RuleEngine,
    };

    use crate::PolicyPack;

    /// Workspace-rooted example tree (`<root>/policy-packs`).
    fn example_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policy-packs")
    }

    fn example_paths() -> Vec<std::path::PathBuf> {
        let paths = crate::pack_files(&example_root()).expect("example tree walks");
        assert!(!paths.is_empty(), "example packs are missing");
        paths
    }

    #[test]
    fn every_example_pack_parses_compiles_and_round_trips() {
        for path in example_paths() {
            let pack =
                crate::load_pack(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
            crate::compile(&pack).unwrap_or_else(|err| panic!("compile {}: {err}", path.display()));

            let serialized = serde_yaml::to_string(&pack).expect("serialize");
            let reparsed: PolicyPack = serde_yaml::from_str(&serialized)
                .unwrap_or_else(|err| panic!("re-parse {}: {err}", path.display()));
            assert_eq!(reparsed, pack, "{} round trip", path.display());
        }
    }

    #[test]
    fn example_packs_compile_into_working_rule_engines() {
        /// (method, request path, expected decision)
        type Case = (HttpMethod, &'static str, bool);
        // (capability name, cases)
        let expectations: &[(&str, &[Case])] = &[
            (
                "github.pull_request.create",
                &[
                    (HttpMethod::POST, "/repos/acme/web/pulls", true),
                    (HttpMethod::GET, "/repos/acme/web/pulls", false),
                    (HttpMethod::DELETE, "/repos/acme/web/pulls", false),
                    (HttpMethod::POST, "/repos/acme/web/issues", false),
                ],
            ),
            (
                "github.repository.read",
                &[
                    (HttpMethod::GET, "/repos/acme/web", true),
                    (HttpMethod::GET, "/repos/acme/web/pulls/7", true),
                    (HttpMethod::POST, "/repos/acme/web", false),
                    (HttpMethod::GET, "/orgs/acme", false),
                ],
            ),
            (
                "openai.responses.create",
                &[
                    (HttpMethod::POST, "/v1/responses", true),
                    (HttpMethod::GET, "/v1/responses", false),
                    (HttpMethod::POST, "/v1/chat", false),
                ],
            ),
            (
                "stripe.customer.read",
                &[
                    (HttpMethod::GET, "/v1/customers/cus_123", true),
                    (HttpMethod::PUT, "/v1/customers/cus_123", false),
                    (HttpMethod::GET, "/v1/charges", false),
                ],
            ),
            (
                "generic.example-api.invoke",
                &[
                    (HttpMethod::GET, "/api/tenant-one/widgets", true),
                    (HttpMethod::POST, "/api/tenant-one/widgets", true),
                    (HttpMethod::GET, "/api/tenant-two/widgets/list", true),
                    (HttpMethod::DELETE, "/api/tenant-one/widgets", false),
                    (HttpMethod::GET, "/admin/tenant-one/widgets", false),
                ],
            ),
        ];

        for path in example_paths() {
            let pack = crate::load_pack(&path).unwrap();
            let compiled = crate::compile(&pack).unwrap();
            let principal = Principal::parse("agent:pack-test").expect("principal parses");
            let document = compiled.to_policy_document(&principal);
            let engine = RuleEngine::from_documents([document]).unwrap();

            let cases = expectations
                .iter()
                .find(|(name, _)| *name == compiled.capability)
                .map(|(_, cases)| cases)
                .unwrap_or_else(|| {
                    panic!(
                        "no engine expectations registered for {}",
                        compiled.capability
                    )
                });

            for (method, req_path, should_allow) in *cases {
                let ctx = AuthorizationContext {
                    host: compiled.hosts[0].clone(),
                    method: *method,
                    path: (*req_path).to_owned(),
                    query: BTreeMap::new(),
                    body_len_bytes: 0,
                    environment: None,
                };
                let request = AuthorizationRequest {
                    principal: principal.clone(),
                    action: Action::HttpRequest,
                    resource: compiled.credential_ref.clone(),
                    context: ctx,
                };
                let decision = engine.authorize(&request);
                if *should_allow {
                    assert!(
                        matches!(decision, AuthorizationDecision::Allow { .. }),
                        "{}: {method} {req_path} must allow, got {decision:?}",
                        compiled.capability
                    );
                } else {
                    assert!(
                        matches!(
                            decision,
                            AuthorizationDecision::Deny {
                                reason: DenyReason::NoMatchingAllow,
                                ..
                            }
                        ),
                        "{}: {method} {req_path} must deny, got {decision:?}",
                        compiled.capability
                    );
                }
            }

            // A different host always denies even for allowed shapes.
            let mut foreign = AuthorizationContext {
                host: "evil.example.com".to_owned(),
                method: compiled.methods[0],
                path: "/anything".to_owned(),
                query: BTreeMap::new(),
                body_len_bytes: 0,
                environment: None,
            };
            foreign.path = compiled.path_patterns[0].replace('*', "acme");
            let request = AuthorizationRequest {
                principal: principal.clone(),
                action: Action::HttpRequest,
                resource: compiled.credential_ref.clone(),
                context: foreign,
            };
            assert!(matches!(
                engine.authorize(&request),
                AuthorizationDecision::Deny {
                    reason: DenyReason::NoMatchingAllow,
                    ..
                }
            ));
        }
    }
}
