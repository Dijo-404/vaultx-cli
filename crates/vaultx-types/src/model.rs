//! Small cross-crate DTOs shared by the vaultx workspace.

use crate::ids::{CredentialRef, EnvironmentId, ObjectId, SecretRevisionId};
use crate::names::{ProviderName, VariableName};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VariableKind {
    Config,
    Secret,
    Brokered,
    Dynamic,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InjectionTemplateId {
    Bearer,
    BasicPassword,
    ApiKeyHeader,
    GithubBearer,
    QueryParameter,
    AwsSigv4,
    CustomStaticHeaderPlusSecret,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VariableSource {
    Manifest { object: ObjectId },
    Inline,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VariableDefinition {
    pub name: VariableName,
    pub kind: VariableKind,
    pub environment: EnvironmentId,
    pub source: VariableSource,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BrokeredCredential {
    pub id: CredentialRef,
    pub secret_revision: SecretRevisionId,
    pub injection: InjectionTemplateId,
    pub provider_hint: Option<ProviderName>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn injection_templates_serialize_to_kebab_case() {
        for (template, expected) in [
            (InjectionTemplateId::Bearer, "\"bearer\""),
            (InjectionTemplateId::BasicPassword, "\"basic-password\""),
            (InjectionTemplateId::ApiKeyHeader, "\"api-key-header\""),
            (InjectionTemplateId::GithubBearer, "\"github-bearer\""),
            (InjectionTemplateId::QueryParameter, "\"query-parameter\""),
            (InjectionTemplateId::AwsSigv4, "\"aws-sigv4\""),
            (
                InjectionTemplateId::CustomStaticHeaderPlusSecret,
                "\"custom-static-header-plus-secret\"",
            ),
        ] {
            let encoded = serde_json::to_string(&template).unwrap();
            assert_eq!(encoded, expected);
            let back: InjectionTemplateId = serde_json::from_str(expected).unwrap();
            assert_eq!(back, template);
        }
    }

    #[test]
    fn variable_kind_round_trips() {
        for (kind, expected) in [
            (VariableKind::Config, "\"config\""),
            (VariableKind::Secret, "\"secret\""),
            (VariableKind::Brokered, "\"brokered\""),
            (VariableKind::Dynamic, "\"dynamic\""),
        ] {
            assert_round_trip(kind, expected);
        }
    }

    #[test]
    fn variable_source_round_trips() {
        assert_round_trip(
            VariableSource::Manifest {
                object: ObjectId::parse("obj_manifest").unwrap(),
            },
            "{\"manifest\":{\"object\":\"obj_manifest\"}}",
        );
        assert_round_trip(VariableSource::Inline, "\"inline\"");
    }

    #[test]
    fn variable_definition_round_trips() {
        let definition = VariableDefinition {
            name: VariableName::parse("DB_PASSWORD").unwrap(),
            kind: VariableKind::Secret,
            environment: EnvironmentId::parse("env_prod").unwrap(),
            source: VariableSource::Manifest {
                object: ObjectId::parse("obj_manifest").unwrap(),
            },
        };
        assert_round_trip(
            definition,
            "{\"name\":\"DB_PASSWORD\",\"kind\":\"secret\",\"environment\":\"env_prod\",\"source\":{\"manifest\":{\"object\":\"obj_manifest\"}}}",
        );
    }

    #[test]
    fn brokered_credential_round_trips_with_and_without_provider_hint() {
        let with_hint = BrokeredCredential {
            id: CredentialRef::parse("aws-deploy-key").unwrap(),
            secret_revision: SecretRevisionId::parse("sec_rev_7").unwrap(),
            injection: InjectionTemplateId::AwsSigv4,
            provider_hint: Some(ProviderName::parse("aws").unwrap()),
        };
        assert_round_trip(
            with_hint,
            "{\"id\":\"aws-deploy-key\",\"secret_revision\":\"sec_rev_7\",\"injection\":\"aws-sigv4\",\"provider_hint\":\"aws\"}",
        );
        assert_round_trip(
            BrokeredCredential {
                id: CredentialRef::parse("github-token").unwrap(),
                secret_revision: SecretRevisionId::parse("sec_rev_9").unwrap(),
                injection: InjectionTemplateId::Bearer,
                provider_hint: None,
            },
            "{\"id\":\"github-token\",\"secret_revision\":\"sec_rev_9\",\"injection\":\"bearer\",\"provider_hint\":null}",
        );
    }
}
