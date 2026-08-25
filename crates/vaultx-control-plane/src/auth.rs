//! Bearer-token minting, classification, and route authorization.
//!
//! Token classes are disjoint by construction: the class is encoded in the
//! token prefix, so an agent session token can never be mistaken for a
//! control-plane session even before the store is consulted. This is the
//! mechanism behind the plan §39 note that administrative APIs must not
//! share a reachable surface with agent session tokens.

use sha2::{Digest, Sha256};

use crate::error::ControlPlaneError;
use crate::model::Principal;

/// Salt length (bytes) for in-memory credential verifiers.
const VERIFIER_SALT_LEN: usize = 16;

/// Computes the hex digest of `password` under a binary salt.
fn password_digest(salt: &[u8], password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

/// Derives the stored credential verifier for `password`: a per-user
/// random salt plus salted SHA-256 digest (`sha256$<salt-hex>$<digest-hex>`).
///
/// This is the milestone's in-memory stopgap only. Production PostgreSQL
/// backends MUST store argon2/bcrypt verifiers instead (see
/// [`crate::store::InMemoryControlPlaneStore`]).
///
/// # Errors
/// [`ControlPlaneError::Storage`] when the OS randomness source fails.
pub fn hash_verifier(password: &str) -> Result<String, ControlPlaneError> {
    let mut salt = [0u8; VERIFIER_SALT_LEN];
    getrandom::getrandom(&mut salt)
        .map_err(|_| ControlPlaneError::Storage("verifier entropy unavailable".to_owned()))?;
    Ok(format!(
        "sha256${}${}",
        hex::encode(salt),
        password_digest(&salt, password)
    ))
}

/// Checks `password` against a verifier produced by [`hash_verifier`].
/// Verifiers in any other format never match.
#[must_use]
pub fn verify_verifier(password: &str, stored: &str) -> bool {
    let Some(("sha256", rest)) = stored.split_once('$') else {
        return false;
    };
    let Some((salt_hex, expected_hex)) = rest.split_once('$') else {
        return false;
    };
    let Ok(salt) = hex::decode(salt_hex) else {
        return false;
    };
    if salt.len() != VERIFIER_SALT_LEN {
        return false;
    }
    password_digest(&salt, password) == expected_hex
}

/// Stable workload principal id derived from an OIDC exchange assertion:
/// neither the assertion nor any derived secret is ever stored or logged
/// verbatim. Shared by the session handler and tests so allowlist entries
/// and minted subjects cannot drift apart.
#[must_use]
pub fn oidc_exchange_subject(provider: &str, assertion: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(assertion.as_bytes());
    format!("oidc:{provider}:{:.16}", hex::encode(hasher.finalize()))
}

/// Disjoint bearer-token families.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenClass {
    /// Team identity: full administrative surface (plan §29).
    ControlSession,
    /// Federated/OIDC-exchanged workload identity; data-plane sync only.
    WorkloadExchange,
    /// Broker-style agent session, subordinate to a human/workload/project
    /// context plus a stored policy binding. Rejected on all
    /// control-plane routes.
    Agent,
}

impl TokenClass {
    /// Wire name used in session responses and audit details.
    #[must_use]
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::ControlSession => "control_session",
            Self::WorkloadExchange => "workload_exchange",
            Self::Agent => "agent",
        }
    }

    /// Token prefix for this class.
    fn prefix(self) -> &'static str {
        match self {
            Self::ControlSession => "vxs_",
            Self::WorkloadExchange => "vxw_",
            Self::Agent => "vxa_",
        }
    }

    /// Class encoded by `token`'s prefix, or `None` for unknown shapes.
    #[must_use]
    pub fn of_token(token: &str) -> Option<Self> {
        [Self::ControlSession, Self::WorkloadExchange, Self::Agent]
            .into_iter()
            .find(|class| token.starts_with(class.prefix()))
    }
}

/// Mints a fresh opaque bearer token of `class`.
///
/// # Errors
/// [`ControlPlaneError::Storage`] when the OS randomness source fails.
pub fn mint_token(class: TokenClass) -> Result<String, ControlPlaneError> {
    let mut bytes = [0u8; 24];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| ControlPlaneError::Storage("token entropy unavailable".to_owned()))?;
    Ok(format!("{}{}", class.prefix(), hex::encode(bytes)))
}

/// Extracts a bearer token from `Authorization` header values.
#[must_use]
pub fn bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let rest = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let trimmed = rest.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Resolves the principal presenting `headers`, requiring its token class
/// to be one of `allowed`.
///
/// # Errors
/// * [`ControlPlaneError::Unauthorized`] for absent/unknown/invalid tokens.
/// * [`ControlPlaneError::Forbidden`] when the class is recognized but not
///   permitted on this route (e.g. an agent token on an admin route).
pub fn authorize(
    store: &dyn crate::store::ControlPlaneStore,
    headers: &axum::http::HeaderMap,
    allowed: &[TokenClass],
) -> Result<Principal, ControlPlaneError> {
    let token = bearer_token(headers).ok_or(ControlPlaneError::Unauthorized)?;
    let class = TokenClass::of_token(&token).ok_or(ControlPlaneError::Unauthorized)?;
    if !allowed.contains(&class) {
        return Err(ControlPlaneError::Forbidden);
    }
    let principal = store
        .resolve_token(&token)?
        .ok_or(ControlPlaneError::Unauthorized)?;
    debug_assert_eq!(principal.class, class, "stored class must match prefix");
    Ok(principal)
}

/// Classes accepted on administrative/management routes.
pub const ADMIN_CLASSES: &[TokenClass] = &[TokenClass::ControlSession];

/// Classes accepted on data-plane sync routes (team sessions plus
/// OIDC-exchanged workload tokens).
pub const SYNC_CLASSES: &[TokenClass] = &[TokenClass::ControlSession, TokenClass::WorkloadExchange];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_tokens_carry_their_class_prefix() {
        let token = mint_token(TokenClass::ControlSession).expect("mint");
        assert_eq!(
            TokenClass::of_token(&token),
            Some(TokenClass::ControlSession)
        );
        assert!(token.starts_with("vxs_"));
        assert_ne!(
            mint_token(TokenClass::Agent).unwrap(),
            mint_token(TokenClass::Agent).unwrap()
        );
    }

    #[test]
    fn unknown_or_foreign_prefixes_do_not_classify() {
        assert_eq!(
            TokenClass::of_token("vxa_deadbeef"),
            Some(TokenClass::Agent)
        );
        assert_eq!(TokenClass::of_token("vxq_nope"), None);
        assert_eq!(TokenClass::of_token("vxs"), None);
        assert_eq!(TokenClass::of_token(""), None);
    }

    #[test]
    fn admin_and_sync_class_sets_are_disjoint_on_agent() {
        assert!(!ADMIN_CLASSES.contains(&TokenClass::Agent));
        assert!(!SYNC_CLASSES.contains(&TokenClass::Agent));
        assert!(SYNC_CLASSES.contains(&TokenClass::WorkloadExchange));
    }

    #[test]
    fn bearer_extraction_is_case_tolerant_and_trimmed() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("bearer  vxs_abc "),
        );
        assert_eq!(bearer_token(&headers).as_deref(), Some("vxs_abc"));

        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn verifiers_are_salted_per_user_and_never_reversible() {
        let a = hash_verifier("hunter2").expect("hash");
        let b = hash_verifier("hunter2").expect("hash");
        assert_ne!(a, b, "each derivation uses a fresh random salt");
        assert!(verify_verifier("hunter2", &a));
        assert!(!verify_verifier("wrong", &a));
        // Legacy plaintext or malformed verifiers must never match.
        assert!(!verify_verifier("hunter2", "hunter2"));
        assert!(!verify_verifier("", "$"));
        // Subjects are deterministic per (provider, assertion) pair.
        assert_eq!(
            oidc_exchange_subject("github-actions", "tok"),
            oidc_exchange_subject("github-actions", "tok")
        );
        assert_ne!(
            oidc_exchange_subject("github-actions", "tok"),
            oidc_exchange_subject("gitlab-ci", "tok")
        );
    }
}
