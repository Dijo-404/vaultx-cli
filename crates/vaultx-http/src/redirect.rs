//! Redirect evaluation: every hop is a *new destination*.
//!
//! # INV-006 / INV-007 linkage
//!
//! A redirect target is an independent authorization subject. The broker
//! transport must:
//!
//! * treat [`RedirectDecision::Follow`] as permission to **connect**, not
//!   permission to authenticate — credentials are re-injected onto the new
//!   request only when the [`RedirectAuthorizer`] approved that exact
//!   canonical target (INV-006: no credential forwarding to unapproved
//!   destinations);
//! * restart policy evaluation for the new target (INV-007: redirects
//!   never inherit the original request's authorization).
//!
//! This module performs only the mechanical checks (hop budget, scheme
//! continuity, canonicalization); destination approval is delegated so the
//! broker can consult its own policy engine and credential state.

use crate::canonical::CanonicalUrl;
use crate::error::HttpPolicyError;

/// Outcome of evaluating one redirect hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectDecision {
    /// The redirect may be followed toward this independently validated
    /// and authorized target. Carries credentials **only** if the same
    /// authorizer call approved them for this exact URL.
    Follow {
        /// The re-canonicalized next destination.
        new_target: CanonicalUrl,
    },
    /// The redirect is refused; the reason is diagnostic text safe for
    /// audit logs (it contains only URLs already seen by policy).
    Deny {
        /// Why the hop was refused.
        reason: String,
    },
}

/// Broker-supplied hook deciding whether a redirect destination may be
/// used — including whether credentials may travel there.
///
/// Implementations receive both endpoints in canonical form and must make
/// their decision against policy (host allowlists, credential scoping)
/// exactly as if the agent had requested `next` directly.
pub trait RedirectAuthorizer: Send + Sync {
    /// Returns `true` only when `next` is an authorized destination for a
    /// request that originated at `original`.
    fn authorize_redirect(&self, original: &CanonicalUrl, next: &CanonicalUrl) -> bool;
}

/// Mechanism-level redirect rules applied before delegation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectPolicy {
    max_hops: u8,
}

impl RedirectPolicy {
    /// Creates a policy allowing at most `max_hops` consecutive hops
    /// (`0` disables following entirely).
    #[must_use]
    pub const fn new(max_hops: u8) -> Self {
        Self { max_hops }
    }

    /// Evaluates a single `Location` header value.
    ///
    /// Order of checks:
    ///
    /// 1. `hop_count >= max_hops` → deny (the authorizer is never
    ///    consulted once the budget is spent);
    /// 2. resolve `location_value` against the current target per RFC 3986
    ///    relative-reference rules (`url::Url::join`);
    /// 3. re-canonicalize the result — it must remain `https`, userinfo-
    ///    free, and pass host grammar ([`CanonicalUrl::parse`]); any
    ///    failure (scheme downgrade to `http`, custom schemes, malformed
    ///    targets) becomes a deny;
    /// 4. delegate destination approval to `authorizer`; a refusal denies.
    ///
    /// Note `original` is the *current* request target (the URL whose
    /// response carried the `Location`), which serves as the resolution
    /// base; the resolved candidate is passed to the authorizer as `next`.
    #[must_use]
    pub fn evaluate(
        &self,
        original: &CanonicalUrl,
        location_value: &str,
        hop_count: u8,
        authorizer: &dyn RedirectAuthorizer,
    ) -> RedirectDecision {
        if hop_count >= self.max_hops {
            return RedirectDecision::Deny {
                reason: format!(
                    "redirect hop limit {} reached at hop {hop_count}",
                    self.max_hops
                ),
            };
        }

        let joined = match original.as_url().join(location_value) {
            Ok(joined) => joined,
            Err(err) => {
                return RedirectDecision::Deny {
                    reason: format!("unresolvable redirect location: {err}"),
                };
            }
        };

        let next = match CanonicalUrl::parse(joined.as_str()) {
            Ok(next) => next,
            Err(HttpPolicyError::UnsupportedScheme(scheme)) => {
                return RedirectDecision::Deny {
                    reason: format!("redirect downgrades or changes scheme to `{scheme}`"),
                };
            }
            Err(err) => {
                return RedirectDecision::Deny {
                    reason: format!("redirect target rejected by canonicalization: {err}"),
                };
            }
        };

        if authorizer.authorize_redirect(original, &next) {
            RedirectDecision::Follow { new_target: next }
        } else {
            RedirectDecision::Deny {
                reason: format!(
                    "redirect target `{}` not authorized",
                    next.as_url().as_str()
                ),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ApproveAll(AtomicUsize);
    impl RedirectAuthorizer for ApproveAll {
        fn authorize_redirect(&self, _: &CanonicalUrl, _: &CanonicalUrl) -> bool {
            self.0.fetch_add(1, Ordering::SeqCst);
            true
        }
    }

    struct DenyAll;
    impl RedirectAuthorizer for DenyAll {
        fn authorize_redirect(&self, _: &CanonicalUrl, _: &CanonicalUrl) -> bool {
            false
        }
    }

    /// Approves only same-host targets, mirroring a typical broker rule.
    struct SameHostOnly;
    impl RedirectAuthorizer for SameHostOnly {
        fn authorize_redirect(&self, original: &CanonicalUrl, next: &CanonicalUrl) -> bool {
            original.host() == next.host() && original.port_or_default() == next.port_or_default()
        }
    }

    fn origin(raw: &str) -> CanonicalUrl {
        CanonicalUrl::parse(raw).expect("valid canonical url")
    }

    #[test]
    fn relative_locations_resolve_against_current_target() {
        let current = origin("https://api.example.com/v1/a/b");
        let authz = ApproveAll(AtomicUsize::new(0));
        let policy = RedirectPolicy::new(5);

        let decision = policy.evaluate(&current, "../c?x=1", 0, &authz);
        assert_eq!(
            decision,
            RedirectDecision::Follow {
                new_target: origin("https://api.example.com/v1/c?x=1")
            }
        );

        // Root-relative form resolves from the authority root.
        let decision = policy.evaluate(&current, "/other/path", 1, &authz);
        assert_eq!(
            decision,
            RedirectDecision::Follow {
                new_target: origin("https://api.example.com/other/path")
            }
        );
        assert_eq!(authz.0.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn absolute_and_protocol_relative_targets_are_canonicalized() {
        let current = origin("https://a.example/x");
        let authz = ApproveAll(AtomicUsize::new(0));
        let policy = RedirectPolicy::new(3);

        let decision = policy.evaluate(&current, "https://b.example/y#frag", 0, &authz);
        assert_eq!(
            decision,
            RedirectDecision::Follow {
                new_target: origin("https://b.example/y") // fragment stripped
            }
        );

        let decision = policy.evaluate(&current, "//b.example/z", 0, &authz);
        assert_eq!(
            decision,
            RedirectDecision::Follow {
                new_target: origin("https://b.example/z")
            }
        );
    }

    #[test]
    fn cross_origin_follows_only_with_authorizer_approval() {
        let current = origin("https://a.example/x");
        let policy = RedirectPolicy::new(3);

        // Same-host-only broker rule: cross-origin denied even though the
        // mechanism checks all passed.
        let decision = policy.evaluate(&current, "https://evil.example/steal", 0, &SameHostOnly);
        match decision {
            RedirectDecision::Deny { reason } => assert!(reason.contains("not authorized")),
            other => panic!("expected deny, got {other:?}"),
        }

        // A broker rule that explicitly allows the partner domain follows.
        struct AllowPartner;
        impl RedirectAuthorizer for AllowPartner {
            fn authorize_redirect(&self, _: &CanonicalUrl, next: &CanonicalUrl) -> bool {
                next.host() == "partner.example"
            }
        }
        let decision = policy.evaluate(&current, "https://partner.example/api", 0, &AllowPartner);
        assert!(matches!(decision, RedirectDecision::Follow { .. }));
    }

    #[test]
    fn denial_when_authorizer_refuses() {
        let current = origin("https://a.example/x");
        let decision = RedirectPolicy::new(3).evaluate(&current, "/y", 0, &DenyAll);
        match decision {
            RedirectDecision::Deny { reason } => assert!(reason.contains("not authorized")),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn hop_limit_denies_without_consulting_authorizer() {
        let current = origin("https://a.example/x");
        let authz = ApproveAll(AtomicUsize::new(0));

        // Budget of 2: hop_count 0 and 1 follow, hop_count 2 denies.
        let policy = RedirectPolicy::new(2);
        assert!(policy.evaluate(&current, "/1", 0, &authz).follows());
        assert!(policy.evaluate(&current, "/2", 1, &authz).follows());
        let decision = policy.evaluate(&current, "/3", 2, &authz);
        match decision {
            RedirectDecision::Deny { reason } => assert!(reason.contains("hop limit")),
            other => panic!("expected deny, got {other:?}"),
        }

        // Zero-hop policies refuse immediately, before any I/O could start.
        let decision = RedirectPolicy::new(0).evaluate(&current, "/x", 0, &authz);
        assert!(matches!(decision, RedirectDecision::Deny { .. }));
        assert_eq!(authz.0.load(Ordering::SeqCst), 2); // never called on denial paths
    }

    #[test]
    fn scheme_downgrades_and_changes_are_denied() {
        let current = origin("https://a.example/x");
        let authz = ApproveAll(AtomicUsize::new(0));
        let policy = RedirectPolicy::new(5);

        let decision = policy.evaluate(&current, "http://a.example/y", 0, &authz);
        match decision {
            RedirectDecision::Deny { reason } => assert!(reason.contains("`http`")),
            other => panic!("expected deny, got {other:?}"),
        }

        let decision = policy.evaluate(&current, "ftp://a.example/y", 0, &authz);
        assert!(matches!(decision, RedirectDecision::Deny { .. }));

        let decision = policy.evaluate(&current, "file:///etc/passwd", 0, &authz);
        assert!(matches!(decision, RedirectDecision::Deny { .. }));
        assert_eq!(authz.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn hostile_redirect_targets_are_rejected_by_canonicalization() {
        let current = origin("https://a.example/x");
        let authz = ApproveAll(AtomicUsize::new(0));
        let policy = RedirectPolicy::new(5);

        // Userinfo smuggling via redirect.
        let decision = policy.evaluate(&current, "https://user:pass@a.example/", 0, &authz);
        assert!(matches!(decision, RedirectDecision::Deny { .. }));

        // Unresolvable garbage location.
        let decision = policy.evaluate(&current, "http://", 0, &authz);
        assert!(matches!(decision, RedirectDecision::Deny { .. }));

        assert_eq!(authz.0.load(Ordering::SeqCst), 0);
    }

    impl RedirectDecision {
        fn follows(&self) -> bool {
            matches!(self, Self::Follow { .. })
        }
    }
}
