//! Secret-safe wrapper types.
//!
//! Rules enforced by this module:
//! - plaintext lives inside [`zeroize::Zeroizing`] so it is scrubbed on drop;
//! - [`Debug`] never reveals content (it writes `"<redacted>"`), so a canary
//!   value can never leak through logging;
//! - per PLAN §8 there is intentionally **no** `Display` implementation, and
//!   no `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash`, `Serialize`, or
//!   `Deserialize` — secret values do not silently render, duplicate, or
//!   cross serialization boundaries;
//! - the only way to read plaintext is through [`SecretBytes::expose`] or
//!   [`SecretString::expose_str`], whose closures are narrowly scoped.

use std::fmt;
use zeroize::Zeroizing;

/// Owned heap-allocated secret bytes that are zeroized on drop and redacted
/// from debug output.
///
/// The type deliberately implements neither `Clone`, `Display`, nor any
/// comparison or serialization traits: moving is the only way to transfer
/// ownership, and plaintext can only be observed via [`SecretBytes::expose`].
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Wraps an existing `Vec<u8>`. The buffer is adopted as-is and will be
    /// zeroized when the returned value drops.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Copies `bytes` into a new secret buffer.
    ///
    /// Note: the caller is responsible for zeroizing the source if it was
    /// itself secret material; prefer [`SecretBytes::from_vec`] when the data
    /// is already owned.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }

    /// Creates an empty secret buffer.
    pub fn empty() -> Self {
        Self(Zeroizing::new(Vec::new()))
    }

    /// Runs `f` with access to the plaintext bytes. This is the only way to
    /// read the contents of a [`SecretBytes`].
    pub fn expose<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.0)
    }

    /// Number of plaintext bytes held.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when no plaintext bytes are held.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted>")
    }
}

/// Owned heap-allocated secret string that is zeroized on drop and redacted
/// from debug output.
///
/// Same rules as [`SecretBytes`]: no `Display`, `Clone`, comparison, or
/// serialization impls; plaintext only reachable via
/// [`SecretString::expose_str`].
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Wraps an existing `String`, which will be zeroized on drop.
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Copies `value` into a new secret string.
    ///
    /// The caller remains responsible for the source buffer if it contained
    /// secret material.
    pub fn copy_from(value: &str) -> Self {
        Self::new(value.to_owned())
    }

    /// Runs `f` with access to the plaintext string. This is the only way to
    /// read the contents of a [`SecretString`].
    pub fn expose_str<R>(&self, f: impl FnOnce(&str) -> R) -> R {
        f(self.0.as_str())
    }

    /// Length of the plaintext in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` when the plaintext string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY: &str = "CANARY_SECRET_123";

    #[test]
    fn debug_of_secret_bytes_is_redacted() {
        let secret = SecretBytes::from_bytes(CANARY.as_bytes());
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "<redacted>");
        assert!(!rendered.contains(CANARY));
    }

    #[test]
    fn debug_of_secret_bytes_from_vec_is_redacted() {
        let secret = SecretBytes::from_vec(CANARY.as_bytes().to_vec());
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "<redacted>");
        assert!(!rendered.contains(CANARY));
    }

    #[test]
    fn debug_of_secret_string_is_redacted() {
        let secret = SecretString::copy_from(CANARY);
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "<redacted>");
        assert!(!rendered.contains(CANARY));
    }

    #[test]
    fn expose_returns_plaintext_bytes() {
        let secret = SecretBytes::from_bytes(b"plaintext-value");
        let observed = secret.expose(|bytes| bytes.to_vec());
        assert_eq!(observed, b"plaintext-value".to_vec());
    }

    #[test]
    fn expose_str_returns_plaintext_str() {
        let secret = SecretString::copy_from("hunter2");
        let observed = secret.expose_str(|s| s.to_owned());
        assert_eq!(observed, "hunter2");
    }

    #[test]
    fn length_accessors_do_not_reveal_content() {
        let empty = SecretBytes::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.expose(|b| b.to_vec()), Vec::<u8>::new());

        let filled = SecretBytes::from_bytes(b"12345");
        assert!(!filled.is_empty());
        assert_eq!(filled.len(), 5);

        let empty_str = SecretString::copy_from("");
        assert!(empty_str.is_empty());
        assert_eq!(empty_str.len(), 0);

        let filled_str = SecretString::copy_from("12345");
        assert!(!filled_str.is_empty());
        assert_eq!(filled_str.len(), 5);
    }

    #[test]
    fn expose_can_transform_without_leaking_via_return_value_choice() {
        // The closure decides what escapes; here only a derived, non-secret
        // fact leaves the scope.
        let secret = SecretBytes::from_bytes(b"top-secret");
        let is_ascii = secret.expose(|b| b.is_ascii());
        assert!(is_ascii);
    }
}
