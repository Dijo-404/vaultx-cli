//! Plan §25 / §43 P3: delegation monotonicity property.
//!
//! For any parent constraint set and any child derived from it — either a
//! strict subset (the CLI's narrowing flags) or an *arbitrary* requested
//! set run through the intersection algebra ([`SessionConstraints::narrow`],
//! as the store applies on every delegation) — any request denied under
//! the parent constraints is denied under the child constraints, and any
//! request the child allows the parent would have allowed too:
//!
//! ```text
//! child effective authority ⊆ parent effective authority
//! ```

use std::collections::BTreeSet;

use proptest::prelude::*;
use vaultx_broker::SessionConstraints;

const CREDENTIALS: [&str; 3] = ["cred-a", "cred-b", "cred-c"];
const ENVIRONMENTS: [&str; 2] = ["env_dev", "env_prod"];
const HOSTS: [&str; 2] = ["a.test", "b.test"];
const METHODS: [&str; 2] = ["GET", "POST"];
const PATHS: [&str; 5] = ["/x", "/x/y", "/x/y/z", "/a", "/a/b"];
/// Valid glob patterns for path constraints. Identical strings and
/// prefix-nested globs exercise [`SessionConstraints::narrow`]'s
/// subsumption filter in both directions.
const PATTERNS: [&str; 6] = ["/x/**", "/x/*", "/x/y/**", "/a/**", "/a/b", "/x"];

#[derive(Clone, Copy, Debug)]
struct Request {
    credential: usize,
    environment: usize,
    host: usize,
    method: usize,
    path: usize,
}

fn request_strategy() -> impl Strategy<Value = Request> {
    (
        0..CREDENTIALS.len(),
        0..ENVIRONMENTS.len(),
        0..HOSTS.len(),
        0..METHODS.len(),
        0..PATHS.len(),
    )
        .prop_map(|(credential, environment, host, method, path)| Request {
            credential,
            environment,
            host,
            method,
            path,
        })
}

/// One boolean per universe element: kept or dropped.
fn mask(len: usize) -> impl Strategy<Value = Vec<bool>> {
    proptest::collection::vec(any::<bool>(), len)
}

/// `None` when nothing is selected (unrestricted), else the selected set.
fn optional_set(universe: &[&str], keep: &[bool]) -> Option<BTreeSet<String>> {
    let selected: BTreeSet<String> = universe
        .iter()
        .zip(keep)
        .filter(|(_, flag)| **flag)
        .map(|(item, _)| (*item).to_owned())
        .collect();
    if selected.is_empty() {
        None
    } else {
        Some(selected)
    }
}

/// Parent/child set pair where the child keeps only elements the parent
/// kept *and* its own extra mask allows. When the parent collapses to
/// unrestricted (`None`) the child does too; otherwise the child stays
/// `Some`, possibly `Some(empty)` (= that dimension denies everything).
fn subset_pair(
    universe: &[&str],
    parent_mask: &[bool],
    extra: &[bool],
) -> (Option<BTreeSet<String>>, Option<BTreeSet<String>>) {
    let parent = optional_set(universe, parent_mask);
    let child_selected: BTreeSet<String> = universe
        .iter()
        .zip(parent_mask)
        .zip(extra)
        .filter(|((_, parent_keep), extra_keep)| **parent_keep && **extra_keep)
        .map(|((item, _), _)| (*item).to_owned())
        .collect();
    let child = if parent.is_none() {
        None
    } else {
        Some(child_selected)
    };
    (parent, child)
}

fn allows(constraints: &SessionConstraints, request: &Request) -> bool {
    constraints
        .check_request(
            CREDENTIALS[request.credential],
            ENVIRONMENTS[request.environment],
            HOSTS[request.host],
            METHODS[request.method],
            PATHS[request.path],
        )
        .is_ok()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// A child built by intersecting masks into its parent (what the CLI's
    /// repeatable narrowing flags produce) can never allow a request the
    /// parent denies.
    #[test]
    fn subset_child_never_allows_what_parent_denies(
        cred_parent in mask(CREDENTIALS.len()), cred_extra in mask(CREDENTIALS.len()),
        env_parent in mask(ENVIRONMENTS.len()), env_extra in mask(ENVIRONMENTS.len()),
        host_parent in mask(HOSTS.len()), host_extra in mask(HOSTS.len()),
        method_parent in mask(METHODS.len()), method_extra in mask(METHODS.len()),
        path_parent in mask(PATTERNS.len()), path_extra in mask(PATTERNS.len()),
        requests in proptest::collection::vec(request_strategy(), 1..16),
    ) {
        let (cred_p, cred_c) = subset_pair(&CREDENTIALS, &cred_parent, &cred_extra);
        let (env_p, env_c) = subset_pair(&ENVIRONMENTS, &env_parent, &env_extra);
        let (host_p, host_c) = subset_pair(&HOSTS, &host_parent, &host_extra);
        let (method_p, method_c) = subset_pair(&METHODS, &method_parent, &method_extra);
        // Path globs: the child keeps only patterns both masks select.
        let parent_patterns: Vec<String> = PATTERNS
            .iter()
            .zip(&path_parent)
            .filter(|(_, keep)| **keep)
            .map(|(pattern, _)| (*pattern).to_owned())
            .collect();
        let child_patterns: Vec<String> = PATTERNS
            .iter()
            .zip(&path_parent)
            .zip(&path_extra)
            .filter(|((_, parent_keep), extra_keep)| **parent_keep && **extra_keep)
            .map(|((pattern, _), _)| (*pattern).to_owned())
            .collect();
        let parent = SessionConstraints {
            credentials: cred_p,
            environments: env_p,
            hosts: host_p,
            methods: method_p,
            paths: Some(parent_patterns),
            remaining_requests: None,
        };
        let child = SessionConstraints {
            credentials: cred_c,
            environments: env_c,
            hosts: host_c,
            methods: method_c,
            paths: Some(child_patterns),
            remaining_requests: None,
        };

        for request in &requests {
            prop_assert!(
                allows(&parent, request) || !allows(&child, request),
                "child allowed a parent-denied request: {request:?}"
            );
            prop_assert!(
                !allows(&child, request) || allows(&parent, request),
                "parent denied a child-allowed request: {request:?}"
            );
        }
    }

    /// The store intersects whatever the delegating caller asks for with
    /// the parent's own constraints. Even for *arbitrary* (possibly
    /// broader) requests the intersection result must stay inside the
    /// parent's accepted-request language.
    #[test]
    fn intersected_child_of_arbitrary_request_is_monotonic(
        cred_parent in mask(CREDENTIALS.len()), cred_request in mask(CREDENTIALS.len()),
        env_parent in mask(ENVIRONMENTS.len()), env_request in mask(ENVIRONMENTS.len()),
        host_parent in mask(HOSTS.len()), host_request in mask(HOSTS.len()),
        method_parent in mask(METHODS.len()), method_request in mask(METHODS.len()),
        path_parent in mask(PATTERNS.len()), path_request in mask(PATTERNS.len()),
        requests in proptest::collection::vec(request_strategy(), 1..16),
    ) {
        let parent = SessionConstraints {
            credentials: optional_set(&CREDENTIALS, &cred_parent),
            environments: optional_set(&ENVIRONMENTS, &env_parent),
            hosts: optional_set(&HOSTS, &host_parent),
            methods: optional_set(&METHODS, &method_parent),
            paths: Some(
                PATTERNS
                    .iter()
                    .zip(&path_parent)
                    .filter(|(_, keep)| **keep)
                    .map(|(pattern, _)| (*pattern).to_owned())
                    .collect(),
            ),
            remaining_requests: None,
        };
        let requested = SessionConstraints {
            credentials: optional_set(&CREDENTIALS, &cred_request),
            environments: optional_set(&ENVIRONMENTS, &env_request),
            hosts: optional_set(&HOSTS, &host_request),
            methods: optional_set(&METHODS, &method_request),
            paths: Some(
                PATTERNS
                    .iter()
                    .zip(&path_request)
                    .filter(|(_, keep)| **keep)
                    .map(|(pattern, _)| (*pattern).to_owned())
                    .collect(),
            ),
            remaining_requests: None,
        };
        let child = parent.narrow(&requested);

        for request in &requests {
            prop_assert!(
                allows(&parent, request) || !allows(&child, request),
                "intersection let a request escape the parent: {request:?}"
            );
            prop_assert!(
                !allows(&child, request) || allows(&parent, request),
                "intersection result exceeds parent authority: {request:?}"
            );
        }
    }
}
