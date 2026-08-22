//! Path and host matching primitives used by policy rules.
//!
//! Path patterns are segment-oriented:
//!
//! * patterns must start with `/`;
//! * empty segments are rejected (`//`, trailing `/`, bare `/`) — use `/**`
//!   for the root;
//! * `**` is only allowed as the trailing segment and matches zero or more
//!   remaining segments;
//! * `*` matches exactly one non-empty segment;
//! * all other segments match literally (paths are case-sensitive);
//! * `..` segments are rejected at validation time so a pattern can never
//!   escape its prefix.

use crate::error::PolicyError;

/// Validates a request-path pattern.
///
/// # Errors
/// Returns [`PolicyError::InvalidPattern`] when the pattern is empty, does
/// not start with `/`, contains an empty segment (`//`, a trailing `/`, or
/// the degenerate bare `/`), contains a `..` segment, or uses `**` anywhere
/// other than the final segment. Root-only access is expressed with `/**`.
pub fn validate_pattern(pattern: &str) -> Result<(), PolicyError> {
    let reject = || PolicyError::InvalidPattern(pattern.to_owned());
    if pattern.is_empty() || !pattern.starts_with('/') {
        return Err(reject());
    }
    let segments: Vec<&str> = split_segments(pattern).collect();
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            return Err(reject());
        }
        if *segment == ".." {
            return Err(reject());
        }
        if *segment == "**" && index + 1 != segments.len() {
            return Err(reject());
        }
    }
    Ok(())
}

/// Returns true when `path` matches `pattern`.
///
/// Patterns that fail [`validate_pattern`] never match. Matching is
/// case-sensitive and segment-based, so `/repos/*/issues` matches
/// `/repos/acme/issues` but not `/repos/acme/web/issues`, while
/// `/repos/acme/**` matches both `/repos/acme` and any deeper path.
#[must_use]
pub fn path_matches(pattern: &str, path: &str) -> bool {
    if validate_pattern(pattern).is_err() {
        return false;
    }
    let pattern_segments: Vec<&str> = split_segments(pattern).collect();
    let path_segments: Vec<&str> = split_segments(path).collect();
    match_segments(&pattern_segments, &path_segments)
}

fn match_segments(pattern: &[&str], path: &[&str]) -> bool {
    match pattern.split_first() {
        // Every pattern segment consumed: the paths match only when the
        // request path is fully consumed too.
        None => path.is_empty(),
        Some((segment, rest)) if *segment == "**" => {
            // validate_pattern guarantees this is the final pattern
            // segment; it matches zero or more remaining path segments.
            debug_assert!(rest.is_empty());
            true
        }
        Some((segment, rest)) => match path.split_first() {
            Some((head, tail)) if segment_matches(segment, head) => match_segments(rest, tail),
            _ => false,
        },
    }
}

fn segment_matches(pattern_segment: &str, path_segment: &str) -> bool {
    if pattern_segment == "*" {
        return !path_segment.is_empty();
    }
    pattern_segment == path_segment
}

fn split_segments(value: &str) -> impl Iterator<Item = &str> + '_ {
    value.strip_prefix('/').unwrap_or(value).split('/')
}

/// Returns true when `host` equals one of the entries in `host_list`.
///
/// Comparison is exact after both sides are lowercased, so hosts are
/// case-insensitive but never matched by suffix or wildcard.
#[must_use]
pub fn host_matches(host_list: &[String], host: &str) -> bool {
    let normalized = host.to_ascii_lowercase();
    host_list
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(&normalized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_star_matches_remaining_segments_including_zero() {
        assert!(path_matches("/repos/acme/**", "/repos/acme/backend/pulls"));
        assert!(path_matches("/repos/acme/**", "/repos/acme"));
        assert!(!path_matches("/repos/acme/**", "/repos"));
        assert!(!path_matches("/repos/acme/**", "/other/acme/backend"));
        assert!(path_matches("/**", "/anything/at/all"));
        assert!(path_matches("/repos/**", "/repos/"));
    }

    #[test]
    fn single_star_matches_exactly_one_non_empty_segment() {
        assert!(path_matches("/repos/*/issues", "/repos/acme/issues"));
        assert!(!path_matches("/repos/*/issues", "/repos/acme/web/issues"));
        assert!(!path_matches("/repos/*/issues", "/repos/issues"));
        assert!(!path_matches("/repos/*", "/repos/"));
        assert!(path_matches("/repos/*", "/repos/x"));
    }

    #[test]
    fn exact_patterns_match_only_identical_paths() {
        assert!(path_matches(
            "/repos/acme/backend/pulls",
            "/repos/acme/backend/pulls"
        ));
        assert!(!path_matches(
            "/repos/acme/backend/pulls",
            "/repos/acme/backend/pulls/"
        ));
        assert!(!path_matches("/repos", "/repo"));
    }

    #[test]
    fn no_match_across_different_prefixes() {
        assert!(!path_matches("/api/**", "/v2/api/resource"));
        assert!(!path_matches("/repos/**", "/issues/list"));
    }

    #[test]
    fn matching_is_case_sensitive() {
        assert!(path_matches("/Repos/Acme", "/Repos/Acme"));
        assert!(!path_matches("/repos/acme", "/REPOS/acme"));
        assert!(!path_matches("/repos/acme/issues", "/repos/acme/Issues"));
    }

    #[test]
    fn invalid_patterns_never_match() {
        assert!(!path_matches("", "/repos"));
        assert!(!path_matches("repos/**", "/repos"));
        assert!(!path_matches("/repos/../**", "/repos"));
        assert!(!path_matches("/a/**/b", "/a/b"));
    }

    #[test]
    fn validate_pattern_rejects_malformed_input() {
        for bad in [
            "",
            "repos/acme",
            "/repos/../escape",
            "/a/../../b",
            "/repos/**/issues",
            "/**/tail",
            "/a//b",
            "/a/",
            "///",
            "/",
        ] {
            assert!(
                matches!(validate_pattern(bad), Err(PolicyError::InvalidPattern(_))),
                "{bad}"
            );
        }
        for good in ["/repos/acme/backend/pulls", "/**", "/single"] {
            assert!(validate_pattern(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn host_matching_is_exact_after_lowercase_normalization() {
        let hosts = vec!["api.github.com".to_owned()];
        assert!(host_matches(&hosts, "api.github.com"));
        assert!(host_matches(&hosts, "API.GitHub.Com"));
        assert!(!host_matches(&hosts, "evil-api.github.com"));
        assert!(!host_matches(&hosts, "github.com"));
        assert!(!host_matches(&hosts, ""));
        assert!(!host_matches(&[], "api.github.com"));
    }

    #[test]
    fn root_path_edge_cases() {
        // Bare "/" is no longer a valid pattern; root access is expressed
        // with the zero-or-more wildcard.
        assert!(validate_pattern("/").is_err());
        assert!(path_matches("/**", "/"));
        assert!(!path_matches("/*", "/"));
        // The matcher itself stays literal: trailing-slash paths are
        // rejected upstream by AuthorizationContext::validate, not here.
        assert!(path_matches("/a/**", "/a/"));
    }
}
