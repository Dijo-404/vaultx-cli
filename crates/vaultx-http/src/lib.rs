//! Hardened outbound HTTP policy engine — the *pure logic* layer of the
//! vaultx egress path.
//!
//! # Scope and security posture (plan §5, §20)
//!
//! This crate owns every request-policy decision the broker transport
//! will need: URL canonicalization, DNS/IP egress policy, redirect
//! handling, header filtering, body size ceilings, and response
//! sanitization. It contains **no network I/O** — there is no client,
//! no TLS stack, no resolver here; those arrive with the broker
//! transport and must consume this crate's decisions.
//!
//! **This crate must not know how to retrieve secret plaintext.** It has
//! no dependency on `vaultx-crypto`, never receives credential material,
//! and its error types cannot echo secrets. Credential *injection* is a
//! broker concern gated by the [`redirect::RedirectAuthorizer`] seam.
//!
//! # Canonicalization contract
//!
//! Authorization and transport share one canonical destination:
//! [`canonical::CanonicalUrl`]. Callers parse once and pass the value
//! onward; re-parsing raw strings after validation is forbidden because
//! normalization drift between policy and wire form is a deny-evasion
//! vector. See the `canonical` module for the exact rules.
//!
//! # DNS rebinding contract
//!
//! Resolution is bound to the validated connection target:
//!
//! 1. canonicalize (`CanonicalUrl::parse`);
//! 2. literal IPs are decided immediately ([`netpolicy::EgressGuard::check_host`]);
//! 3. hostnames resolve **after** validation and every resolved address
//!    is re-checked ([`netpolicy::EgressGuard::recheck_resolved`]) before
//!    connecting.
//!
//! Metadata-service endpoints are denied unconditionally, even in
//! allow-private deployments.
//!
//! # Redirects
//!
//! Every hop is a new destination requiring independent authorization;
//! credentials travel only to targets the broker's
//! [`redirect::RedirectAuthorizer`] approved for that exact URL.

mod canonical;
mod error;
mod headers;
mod limits;
mod netpolicy;
mod redirect;
mod sanitize;

pub use canonical::CanonicalUrl;
pub use error::HttpPolicyError;
pub use headers::{filter_request_headers, validate_header_pair, SENSITIVE_REQUEST_HEADERS};
pub use limits::SizeLimits;
pub use netpolicy::{classify_ip, is_egress_allowed, Classification, EgressGuard};
pub use redirect::{RedirectAuthorizer, RedirectDecision, RedirectPolicy};
pub use sanitize::{enforce_content_type, redact_headers, redact_json_fields};
