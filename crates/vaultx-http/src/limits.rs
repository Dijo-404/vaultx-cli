//! Request/response body size ceilings.
//!
//! Size enforcement happens *before* buffering (transport streams through
//! a counting reader that aborts at the ceiling); this module owns the
//! policy decision so broker transport and tests share one source of
//! truth.

use crate::error::HttpPolicyError;

/// Byte ceilings for proxied bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeLimits {
    /// Largest request body accepted, in bytes.
    pub max_request_body_bytes: u64,
    /// Largest response body retained, in bytes.
    pub max_response_body_bytes: u64,
}

impl Default for SizeLimits {
    /// Defaults: 256 KiB requests, 1 MiB responses.
    fn default() -> Self {
        Self {
            max_request_body_bytes: 256 * 1024,
            max_response_body_bytes: 1024 * 1024,
        }
    }
}

impl SizeLimits {
    /// Creates explicit limits; prefer [`SizeLimits::default`] unless the
    /// deployment has audited reasons to deviate.
    #[must_use]
    pub const fn new(max_request_body_bytes: u64, max_response_body_bytes: u64) -> Self {
        Self {
            max_request_body_bytes,
            max_response_body_bytes,
        }
    }

    /// Checks an observed request body size against the ceiling.
    ///
    /// # Errors
    /// [`HttpPolicyError::BodyTooLarge`] when `len` exceeds
    /// `max_request_body_bytes`.
    pub const fn check_request(&self, len: u64) -> Result<(), HttpPolicyError> {
        if len > self.max_request_body_bytes {
            return Err(HttpPolicyError::BodyTooLarge {
                limit: len,
                max: self.max_request_body_bytes,
            });
        }
        Ok(())
    }

    /// Checks an observed response body size against the ceiling.
    ///
    /// # Errors
    /// [`HttpPolicyError::ResponseTooLarge`] when `len` exceeds
    /// `max_response_body_bytes`.
    pub const fn check_response(&self, len: u64) -> Result<(), HttpPolicyError> {
        if len > self.max_response_body_bytes {
            return Err(HttpPolicyError::ResponseTooLarge {
                limit: len,
                max: self.max_response_body_bytes,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_256kib_and_1mib() {
        let limits = SizeLimits::default();
        assert_eq!(limits.max_request_body_bytes, 262_144);
        assert_eq!(limits.max_response_body_bytes, 1_048_576);
    }

    #[test]
    fn boundary_sizes_pass_and_exceeding_fails() {
        let limits = SizeLimits::new(100, 200);

        // Exactly at the limit passes on both sides.
        assert!(limits.check_request(100).is_ok());
        assert!(limits.check_response(200).is_ok());
        assert!(limits.check_request(0).is_ok());

        // One byte over fails with precise numbers in the error.
        let err = limits.check_request(101).unwrap_err();
        assert!(matches!(
            err,
            HttpPolicyError::BodyTooLarge {
                limit: 101,
                max: 100
            }
        ));
        let err = limits.check_response(201).unwrap_err();
        assert!(matches!(
            err,
            HttpPolicyError::ResponseTooLarge {
                limit: 201,
                max: 200
            }
        ));

        // Independent ceilings do not leak into each other.
        assert!(limits.check_response(50).is_ok());
        assert!(limits.check_request(150).is_err());
    }
}
