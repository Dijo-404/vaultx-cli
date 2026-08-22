//! Strongly typed identifier newtypes shared across the vaultx workspace.
//!
//! Every identifier validates its canonical form on construction and on
//! deserialization so security-sensitive IDs never degrade into
//! interchangeable raw strings.

use crate::error::TypeError;

pub(crate) const MAX_ID_CONTENT_LEN: usize = 64;

/// All registered prefixed-ID families, longest first so that more
/// specific prefixes win discrimination (`sec_rev_` before `sec_`).
#[rustfmt::skip]
pub(crate) const ID_PREFIXES: [&str; 11] = [
    "sec_rev_",
    "ws_", "proj_", "env_", "cmt_", "obj_",
    "sec_", "pol_", "agent_", "sess_", "aud_",
];

pub(crate) fn is_valid_id_content(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// True when `value` begins with a registered prefix more specific than
/// `own`, meaning the value belongs to another identifier family.
pub(crate) fn claimed_by_longer_registered_prefix(value: &str, own: &str) -> bool {
    ID_PREFIXES
        .iter()
        .any(|p| p.len() > own.len() && value.starts_with(*p))
}

/// True when the content after an ID prefix itself looks like another
/// identifier (nested-family embedding).
pub(crate) fn content_starts_with_registered_prefix(content: &str) -> bool {
    ID_PREFIXES.iter().any(|p| content.starts_with(*p))
}

macro_rules! define_string_newtype {
    ($(#[$doc:meta])+ $name:ident) => {
        $(#[$doc])+
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, ::serde::Serialize)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::de::Deserializer<'de>,
            {
                struct ValueVisitor;

                impl<'de> ::serde::de::Visitor<'de> for ValueVisitor {
                    type Value = $name;

                    fn expecting(
                        &self,
                        formatter: &mut ::std::fmt::Formatter<'_>,
                    ) -> ::std::fmt::Result {
                        formatter.write_str(concat!("a valid ", stringify!($name)))
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: ::serde::de::Error,
                    {
                        $name::parse(value).map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(ValueVisitor)
            }
        }
    };
}

macro_rules! define_conversion_traits {
    ($name:ident) => {
        impl ::std::str::FromStr for $name {
            type Err = TypeError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        impl ::std::convert::TryFrom<&str> for $name {
            type Error = TypeError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }

        impl ::std::convert::TryFrom<String> for $name {
            type Error = TypeError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(&value)?;
                Ok(Self(value))
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

macro_rules! define_prefixed_id {
    ($(#[$doc:meta])+ $name:ident, $prefix:literal) => {
        define_string_newtype!($(#[$doc])+ $name);

        impl $name {
            pub const PREFIX: &'static str = $prefix;
            pub const MAX_CONTENT_LEN: usize = crate::ids::MAX_ID_CONTENT_LEN;

            pub fn parse(value: &str) -> Result<Self, TypeError> {
                if value.is_empty() {
                    return Err(TypeError::Empty);
                }
                let Some(content) = value.strip_prefix($prefix) else {
                    return Err(TypeError::InvalidPrefix {
                        expected: $prefix.to_owned(),
                    });
                };
                if content.is_empty() {
                    return Err(TypeError::Empty);
                }
                if !crate::ids::is_valid_id_content(content)
                    || crate::ids::claimed_by_longer_registered_prefix(value, $prefix)
                    || crate::ids::content_starts_with_registered_prefix(content)
                {
                    return Err(TypeError::InvalidCharacters);
                }
                let len = content.chars().count();
                if len > Self::MAX_CONTENT_LEN {
                    return Err(TypeError::TooLong {
                        max: Self::MAX_CONTENT_LEN,
                    });
                }
                Ok(Self(value.to_owned()))
            }
        }

        define_conversion_traits!($name);
    };
}

macro_rules! define_plain_id {
    ($(#[$doc:meta])+ $name:ident, $max:literal) => {
        define_string_newtype!($(#[$doc])+ $name);

        impl $name {
            pub const MAX_CONTENT_LEN: usize = $max;

            pub fn parse(value: &str) -> Result<Self, TypeError> {
                if value.is_empty() {
                    return Err(TypeError::Empty);
                }
                if !crate::ids::is_valid_id_content(value) {
                    return Err(TypeError::InvalidCharacters);
                }
                let len = value.chars().count();
                if len > Self::MAX_CONTENT_LEN {
                    return Err(TypeError::TooLong {
                        max: Self::MAX_CONTENT_LEN,
                    });
                }
                Ok(Self(value.to_owned()))
            }
        }

        define_conversion_traits!($name);
    };
}

pub(crate) use define_string_newtype;

define_prefixed_id!(
    /// Identifier of a workspace.
    WorkspaceId,
    "ws_"
);
define_prefixed_id!(
    /// Identifier of a project scoped to a workspace.
    ProjectId,
    "proj_"
);
define_prefixed_id!(
    /// Identifier of a deployable environment.
    EnvironmentId,
    "env_"
);
define_prefixed_id!(
    /// Identifier of a repository commit tracked by sync.
    CommitId,
    "cmt_"
);
define_prefixed_id!(
    /// Identifier of a manifest object in the object store.
    ObjectId,
    "obj_"
);
define_prefixed_id!(
    /// Identifier of a secret entry.
    SecretId,
    "sec_"
);
define_prefixed_id!(
    /// Identifier of a specific secret revision.
    SecretRevisionId,
    "sec_rev_"
);
define_plain_id!(
    /// Logical reference to a brokered credential.
    CredentialRef,
    128
);
define_prefixed_id!(
    /// Identifier of a policy.
    PolicyId,
    "pol_"
);
define_prefixed_id!(
    /// Identifier of an agent registration.
    AgentId,
    "agent_"
);
define_prefixed_id!(
    /// Identifier of an agent session.
    SessionId,
    "sess_"
);
define_prefixed_id!(
    /// Identifier of an audit event.
    AuditEventId,
    "aud_"
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn assert_round_trip<T>(value: T, json: &str)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let encoded = serde_json::to_string(&value).unwrap();
        assert_eq!(encoded, json);
        let decoded: T = serde_json::from_str(json).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn parse_accepts_valid_ids() {
        for (parsed, expected) in [
            (
                WorkspaceId::parse("ws_alpha-01").map(|id| id.to_string()),
                "ws_alpha-01",
            ),
            (
                ProjectId::parse("proj_core").map(|id| id.to_string()),
                "proj_core",
            ),
            (
                EnvironmentId::parse("env_prod").map(|id| id.to_string()),
                "env_prod",
            ),
            (
                CommitId::parse("cmt_9f8e7d").map(|id| id.to_string()),
                "cmt_9f8e7d",
            ),
            (
                ObjectId::parse("obj_manifest_main").map(|id| id.to_string()),
                "obj_manifest_main",
            ),
            (
                SecretId::parse("sec_db_password").map(|id| id.to_string()),
                "sec_db_password",
            ),
            (
                SecretRevisionId::parse("sec_rev_000042").map(|id| id.to_string()),
                "sec_rev_000042",
            ),
            (
                CredentialRef::parse("deploy_token-1").map(|id| id.to_string()),
                "deploy_token-1",
            ),
            (
                PolicyId::parse("pol_least_privilege").map(|id| id.to_string()),
                "pol_least_privilege",
            ),
            (
                AgentId::parse("agent_sync_daemon").map(|id| id.to_string()),
                "agent_sync_daemon",
            ),
            (
                SessionId::parse("sess_a1b2c3").map(|id| id.to_string()),
                "sess_a1b2c3",
            ),
            (
                AuditEventId::parse("aud_evt_77").map(|id| id.to_string()),
                "aud_evt_77",
            ),
        ] {
            assert_eq!(parsed.unwrap(), expected);
        }
    }

    #[test]
    fn rejects_wrong_prefix() {
        assert_eq!(
            ProjectId::parse("ws_alpha"),
            Err(TypeError::InvalidPrefix {
                expected: "proj_".to_owned()
            })
        );
        assert_eq!(
            SecretRevisionId::parse("sec_only"),
            Err(TypeError::InvalidPrefix {
                expected: "sec_rev_".to_owned()
            })
        );
        assert_eq!(
            AuditEventId::parse("sess_a1b2c3"),
            Err(TypeError::InvalidPrefix {
                expected: "aud_".to_owned()
            })
        );
    }

    #[test]
    fn rejects_empty_values() {
        assert_eq!(WorkspaceId::parse(""), Err(TypeError::Empty));
        assert_eq!(WorkspaceId::parse("ws_"), Err(TypeError::Empty));
        assert_eq!(CredentialRef::parse(""), Err(TypeError::Empty));
    }

    #[test]
    fn rejects_invalid_characters() {
        assert_eq!(
            WorkspaceId::parse("ws_Alpha!"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            WorkspaceId::parse("ws_has space"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            CredentialRef::parse("Bad Name"),
            Err(TypeError::InvalidCharacters)
        );
    }

    #[test]
    fn rejects_overlong_ids() {
        assert_eq!(
            WorkspaceId::parse(&format!("ws_{}", "a".repeat(65))),
            Err(TypeError::TooLong { max: 64 })
        );
        assert!(WorkspaceId::parse(&format!("ws_{}", "a".repeat(64))).is_ok());
        assert_eq!(
            CredentialRef::parse(&"a".repeat(129)),
            Err(TypeError::TooLong { max: 128 })
        );
        assert!(CredentialRef::parse(&"a".repeat(128)).is_ok());
    }

    #[test]
    fn rejects_nested_identifier_families() {
        assert_eq!(
            SecretId::parse("sec_rev_x"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            WorkspaceId::parse("ws_ws_a"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            SecretRevisionId::parse("sec_rev_sec_a"),
            Err(TypeError::InvalidCharacters)
        );
        assert!(SecretId::parse("sec_db_password").is_ok());
        assert!(SecretRevisionId::parse("sec_rev_000042").is_ok());
    }

    #[test]
    fn id_conversion_traits_delegate_to_parse() {
        assert!(WorkspaceId::from_str("ws_ok").is_ok());
        assert!(WorkspaceId::try_from("ws_ok").is_ok());
        assert!(WorkspaceId::try_from(String::from("ws_ok")).is_ok());
        assert!(matches!(
            WorkspaceId::try_from("nope"),
            Err(TypeError::InvalidPrefix { .. })
        ));
        let moved: String = CredentialRef::try_from(String::from("deploy_token-1"))
            .unwrap()
            .into();
        assert_eq!(moved, "deploy_token-1");
        let copied: String = WorkspaceId::parse("ws_ok").unwrap().into();
        assert_eq!(copied, "ws_ok");
    }

    #[test]
    fn exposes_max_content_lengths() {
        for (actual, expected) in [
            (WorkspaceId::MAX_CONTENT_LEN, 64),
            (ProjectId::MAX_CONTENT_LEN, 64),
            (EnvironmentId::MAX_CONTENT_LEN, 64),
            (CommitId::MAX_CONTENT_LEN, 64),
            (ObjectId::MAX_CONTENT_LEN, 64),
            (SecretId::MAX_CONTENT_LEN, 64),
            (SecretRevisionId::MAX_CONTENT_LEN, 64),
            (CredentialRef::MAX_CONTENT_LEN, 128),
            (PolicyId::MAX_CONTENT_LEN, 64),
            (AgentId::MAX_CONTENT_LEN, 64),
            (SessionId::MAX_CONTENT_LEN, 64),
            (AuditEventId::MAX_CONTENT_LEN, 64),
        ] {
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn rejects_unicode_in_id_content() {
        assert_eq!(
            WorkspaceId::parse("ws_café"),
            Err(TypeError::InvalidCharacters)
        );
        assert_eq!(
            CredentialRef::parse("déploy_token"),
            Err(TypeError::InvalidCharacters)
        );
    }

    #[test]
    fn ids_round_trip_through_json() {
        assert_round_trip(
            WorkspaceId::parse("ws_alpha-01").unwrap(),
            "\"ws_alpha-01\"",
        );
        assert_round_trip(ProjectId::parse("proj_core").unwrap(), "\"proj_core\"");
        assert_round_trip(EnvironmentId::parse("env_prod").unwrap(), "\"env_prod\"");
        assert_round_trip(CommitId::parse("cmt_9f8e7d").unwrap(), "\"cmt_9f8e7d\"");
        assert_round_trip(
            ObjectId::parse("obj_manifest_main").unwrap(),
            "\"obj_manifest_main\"",
        );
        assert_round_trip(
            SecretId::parse("sec_db_password").unwrap(),
            "\"sec_db_password\"",
        );
        assert_round_trip(
            SecretRevisionId::parse("sec_rev_000042").unwrap(),
            "\"sec_rev_000042\"",
        );
        assert_round_trip(
            CredentialRef::parse("deploy_token-1").unwrap(),
            "\"deploy_token-1\"",
        );
        assert_round_trip(
            PolicyId::parse("pol_least_privilege").unwrap(),
            "\"pol_least_privilege\"",
        );
        assert_round_trip(
            AgentId::parse("agent_sync_daemon").unwrap(),
            "\"agent_sync_daemon\"",
        );
        assert_round_trip(SessionId::parse("sess_a1b2c3").unwrap(), "\"sess_a1b2c3\"");
        assert_round_trip(AuditEventId::parse("aud_evt_77").unwrap(), "\"aud_evt_77\"");
    }

    #[test]
    fn deserialization_rejects_invalid_values() {
        assert!(serde_json::from_str::<WorkspaceId>("\"oops\"").is_err());
        assert!(serde_json::from_str::<WorkspaceId>("\"ws_\"").is_err());
        assert!(serde_json::from_str::<WorkspaceId>("\"\"").is_err());
        assert!(serde_json::from_str::<CredentialRef>("\"Bad Name\"").is_err());
    }
}
