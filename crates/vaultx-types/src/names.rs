//! Human-facing name and reference newtypes shared across the vaultx
//! workspace. Like the typed identifiers, these validate on construction
//! and on deserialization.

use crate::error::TypeError;
use crate::ids::define_string_newtype;
use crate::ids::is_valid_id_content;

define_string_newtype!(
    /// Name of a variable inside an environment definition: uppercase
    /// `A-Z`, digits, `_`; must start with a letter or `_`; max 128 chars.
    VariableName
);
define_string_newtype!(
    /// Name of a credential provider: lowercase alphanumeric and `-`,
    /// max 64 chars.
    ProviderName
);
define_string_newtype!(
    /// Name of a policy: lowercase alphanumeric with `-` and `_`,
    /// max 128 chars.
    PolicyName
);
define_string_newtype!(
    /// Reference to a git branch (`heads/<name>` form is not enforced
    /// here): non-empty, no leading/trailing slash, max 255 chars.
    BranchRef
);
define_string_newtype!(
    /// Reference to a principal identity: non-empty, max 255 chars.
    IdentityRef
);

impl VariableName {
    pub const MAX_LEN: usize = 128;

    pub fn parse(value: &str) -> Result<Self, TypeError> {
        if value.is_empty() {
            return Err(TypeError::Empty);
        }
        let mut chars = value.chars();
        let starts_valid = matches!(chars.next(), Some(c) if c.is_ascii_uppercase() || c == '_');
        if !starts_valid {
            return Err(TypeError::InvalidCharacters);
        }
        if !chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            return Err(TypeError::InvalidCharacters);
        }
        let len = value.chars().count();
        if len > Self::MAX_LEN {
            return Err(TypeError::TooLong { max: Self::MAX_LEN });
        }
        Ok(Self(value.to_owned()))
    }
}

impl ProviderName {
    pub const MAX_LEN: usize = 64;

    pub fn parse(value: &str) -> Result<Self, TypeError> {
        if value.is_empty() {
            return Err(TypeError::Empty);
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(TypeError::InvalidCharacters);
        }
        let len = value.chars().count();
        if len > Self::MAX_LEN {
            return Err(TypeError::TooLong { max: Self::MAX_LEN });
        }
        Ok(Self(value.to_owned()))
    }
}

impl PolicyName {
    pub const MAX_LEN: usize = 128;

    pub fn parse(value: &str) -> Result<Self, TypeError> {
        if !is_valid_id_content(value) {
            if value.is_empty() {
                return Err(TypeError::Empty);
            }
            return Err(TypeError::InvalidCharacters);
        }
        let len = value.chars().count();
        if len > Self::MAX_LEN {
            return Err(TypeError::TooLong { max: Self::MAX_LEN });
        }
        Ok(Self(value.to_owned()))
    }
}

impl BranchRef {
    pub const MAX_LEN: usize = 255;

    pub fn parse(value: &str) -> Result<Self, TypeError> {
        if value.is_empty() {
            return Err(TypeError::Empty);
        }
        if value.starts_with('/') || value.ends_with('/') {
            return Err(TypeError::InvalidCharacters);
        }
        let len = value.chars().count();
        if len > Self::MAX_LEN {
            return Err(TypeError::TooLong { max: Self::MAX_LEN });
        }
        Ok(Self(value.to_owned()))
    }
}

impl IdentityRef {
    pub const MAX_LEN: usize = 255;

    pub fn parse(value: &str) -> Result<Self, TypeError> {
        if value.is_empty() {
            return Err(TypeError::Empty);
        }
        let len = value.chars().count();
        if len > Self::MAX_LEN {
            return Err(TypeError::TooLong { max: Self::MAX_LEN });
        }
        Ok(Self(value.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_name_validation() {
        for valid in ["API_KEY", "_SECRET_TOKEN", "X", "UPPER_123", "A_B_C"] {
            assert!(VariableName::parse(valid).is_ok(), "{valid}");
        }
        assert_eq!(VariableName::parse(""), Err(TypeError::Empty));
        assert_eq!(
            VariableName::parse("1UPPER"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            VariableName::parse("lower"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            VariableName::parse("HAS SPACE"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            VariableName::parse("HAS-DASH"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            VariableName::parse(&"A".repeat(129)),
            Err(TypeError::TooLong { max: 128 })
        );
        assert!(VariableName::parse(&"A".repeat(128)).is_ok());
    }

    #[test]
    fn provider_name_validation() {
        for valid in ["github", "vaultx-broker", "aws"] {
            assert!(ProviderName::parse(valid).is_ok(), "{valid}");
        }
        assert_eq!(ProviderName::parse(""), Err(TypeError::Empty));
        assert_eq!(
            ProviderName::parse("GitHub"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            ProviderName::parse("under_score"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            ProviderName::parse(&"a".repeat(65)),
            Err(TypeError::TooLong { max: 64 })
        );
        assert!(ProviderName::parse(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn policy_name_validation() {
        assert!(PolicyName::parse("least-privilege_readonly").is_ok());
        assert_eq!(PolicyName::parse(""), Err(TypeError::Empty));
        assert_eq!(
            PolicyName::parse("Least-Privilege"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            PolicyName::parse(&"a".repeat(129)),
            Err(TypeError::TooLong { max: 128 })
        );
    }

    #[test]
    fn branch_ref_validation() {
        for valid in ["main", "feature/foo", "release/v1.2"] {
            assert!(BranchRef::parse(valid).is_ok(), "{valid}");
        }
        assert_eq!(BranchRef::parse(""), Err(TypeError::Empty));
        assert_eq!(
            BranchRef::parse("/leading"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            BranchRef::parse("trailing/"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            BranchRef::parse(&format!("feature/{}", "b".repeat(248))),
            Err(TypeError::TooLong { max: 255 })
        );
        assert!(BranchRef::parse(&format!("feature/{}", "b".repeat(247))).is_ok());
    }

    #[test]
    fn identity_ref_validation() {
        assert!(IdentityRef::parse("user:alice").is_ok());
        assert_eq!(IdentityRef::parse(""), Err(TypeError::Empty));
        assert_eq!(
            IdentityRef::parse(&"i".repeat(256)),
            Err(TypeError::TooLong { max: 255 })
        );
        assert!(IdentityRef::parse(&"i".repeat(255)).is_ok());
    }

    #[test]
    fn names_round_trip_through_json() {
        fn assert_round_trip<T>(value: T, json: &str)
        where
            T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
        {
            let encoded = serde_json::to_string(&value).unwrap();
            assert_eq!(encoded, json);
            let decoded: T = serde_json::from_str(json).unwrap();
            assert_eq!(decoded, value);
        }

        assert_round_trip(
            VariableName::parse("DB_PASSWORD").unwrap(),
            "\"DB_PASSWORD\"",
        );
        assert_round_trip(
            ProviderName::parse("vaultx-broker").unwrap(),
            "\"vaultx-broker\"",
        );
        assert_round_trip(PolicyName::parse("read_only").unwrap(), "\"read_only\"");
        assert_round_trip(BranchRef::parse("feature/foo").unwrap(), "\"feature/foo\"");
        assert_round_trip(IdentityRef::parse("user:alice").unwrap(), "\"user:alice\"");
    }

    #[test]
    fn deserialization_rejects_invalid_names() {
        assert!(serde_json::from_str::<VariableName>("\"lower\"").is_err());
        assert!(serde_json::from_str::<ProviderName>("\"GitHub\"").is_err());
        assert!(serde_json::from_str::<BranchRef>("\"/leading\"").is_err());
    }
}
