//! Broker protocol types (plan §19).
//!
//! [`BrokerRequest`] is what an agent presents; [`BrokerResponse`] is
//! what the broker returns. The wire contract:
//!
//! * `capability_hint` is informational/ergonomic only — authorization is
//!   always performed against the actual canonical request plus policy
//!   context (the engine never reads the hint);
//! * response headers are sanitized before delivery;
//! * denied responses never include secret-bearing diagnostics.
//!
//! Serialization exists so these values can cross the future IPC layer
//! unchanged and so tests can pin the exact shapes.

use getrandom::getrandom;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use vaultx_policy::HttpMethod;
use vaultx_types::CredentialRef;

use crate::error::BrokerError;

/// The single protocol version implemented by this broker (plan §19:
/// "versioned structured protocol").
pub const PROTOCOL_VERSION: u16 = 1;

const REQUEST_ID_PREFIX: &str = "req_";
/// Random bytes behind a generated request id (rendered as 32 hex chars).
const REQUEST_ID_BYTES: usize = 16;

fn random_hex(bytes: usize) -> Result<String, BrokerError> {
    let mut buffer = vec![0u8; bytes];
    getrandom(&mut buffer).map_err(|e| BrokerError::Entropy(e.to_string()))?;
    Ok(hex::encode(buffer))
}

fn is_lowercase_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

// ---------------------------------------------------------------------------
// RequestId
// ---------------------------------------------------------------------------

/// Correlation identifier returned with every broker response
/// (`req_` + 32 lowercase hex characters), freshly generated per request.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct RequestId(String);

impl RequestId {
    /// Prefix of every well-formed request id.
    pub const PREFIX: &'static str = REQUEST_ID_PREFIX;

    /// Generates a fresh random request id.
    ///
    /// # Errors
    /// Returns [`BrokerError::Entropy`] when secure randomness is
    /// unavailable.
    pub fn generate() -> Result<Self, BrokerError> {
        Self::from_random_hex(&random_hex(REQUEST_ID_BYTES)?)
    }

    /// Deterministic last-resort id used only when secure entropy is
    /// unavailable at generation time. Recognizable by its all-zero hex
    /// tail; never produced while entropy works.
    pub(crate) fn deterministic_fallback() -> Self {
        Self(format!(
            "{REQUEST_ID_PREFIX}{}",
            "0".repeat(REQUEST_ID_BYTES * 2)
        ))
    }

    fn from_random_hex(hex: &str) -> Result<Self, BrokerError> {
        let id = format!("{REQUEST_ID_PREFIX}{hex}");
        if Self::is_well_formed(&id) {
            Ok(Self(id))
        } else {
            // Unreachable for generator output; guards against silent
            // drift if the constants above change.
            Err(BrokerError::Entropy(
                "generated request id failed validation".to_owned(),
            ))
        }
    }

    /// True when `value` matches the canonical request-id grammar.
    fn is_well_formed(value: &str) -> bool {
        match value.strip_prefix(Self::PREFIX) {
            Some(content) => content.len() == REQUEST_ID_BYTES * 2 && is_lowercase_hex(content),
            None => false,
        }
    }

    /// Returns the canonical string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for RequestId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RequestId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if Self::is_well_formed(&raw) {
            Ok(Self(raw))
        } else {
            Err(D::Error::custom(
                "request id must be `req_` followed by 32 lowercase hex characters",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// BrokerBody
// ---------------------------------------------------------------------------

/// Request or passthrough body of a brokered exchange.
///
/// Tagged serialization keeps round trips unambiguous: byte payloads and
/// structured JSON cannot be confused during deserialization.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BrokerBody {
    /// No body.
    #[default]
    None,
    /// Raw bytes (any content type).
    Bytes {
        /// Payload bytes.
        data: Vec<u8>,
    },
    /// Structured JSON payload, passed through verbatim to transport.
    Json {
        /// JSON value.
        value: serde_json::Value,
    },
}

impl BrokerBody {
    /// Wire length of this body in bytes, used for policy body-size
    /// constraints. JSON bodies are measured by their serialized form.
    #[must_use]
    pub fn wire_len_bytes(&self) -> u64 {
        match self {
            Self::None => 0,
            Self::Bytes { data } => data.len() as u64,
            Self::Json { value } => serde_json::to_vec(value)
                .map(|bytes| bytes.len() as u64)
                .unwrap_or_default(),
        }
    }
}

// ---------------------------------------------------------------------------
// BrokerRequest / BrokerResponse / Decision
// ---------------------------------------------------------------------------

/// A brokered outbound HTTP request as presented by an agent (plan §19).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct BrokerRequest {
    /// Protocol version; must equal [`PROTOCOL_VERSION`].
    pub protocol: u16,
    /// Raw bearer token presented by the caller. Consumed only by session
    /// validation inside the broker; never logged, echoed, or stored in
    /// plaintext.
    pub session_token: String,
    /// Logical credential reference — the agent chooses *what* to use,
    /// never how material is injected (plan §21).
    pub credential: CredentialRef,
    /// HTTP method of the outbound request.
    pub method: HttpMethod,
    /// Raw destination URL as typed by the agent; canonicalized by the
    /// engine before any decision.
    pub url: String,
    /// Caller-supplied headers as-presented. Sensitive headers are
    /// stripped by the engine (INV-004); injection owns auth headers.
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: BrokerBody,
    /// Informational capability name. Never consulted for authorization.
    pub capability_hint: Option<String>,
    /// Caller-supplied correlation identifier (plan §30 replay
    /// protection). When present it must match the request-id grammar and
    /// becomes both the echoed response id and the replay-cache key: any
    /// repeat of the same (session, id) pair inside the cache window is
    /// denied `replay_detected`. When absent the broker mints a fresh
    /// random id per execution, which is unique by construction and
    /// therefore not replay-trackable.
    #[serde(default)]
    pub request_id: Option<RequestId>,
}

impl std::fmt::Debug for BrokerRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manual implementation: the bearer token and body bytes are
        // redacted so an accidental `{:?}` log line cannot become the
        // exfiltration path for caller credentials.
        f.debug_struct("BrokerRequest")
            .field("protocol", &self.protocol)
            .field("session_token", &"<redacted>")
            .field("credential", &self.credential.as_str())
            .field("method", &self.method.as_str())
            .field("url", &self.url)
            .field("headers", &self.headers)
            .field("body_wire_len_bytes", &self.body.wire_len_bytes())
            .field("capability_hint", &self.capability_hint)
            .field(
                "request_id",
                &self.request_id.as_ref().map(RequestId::as_str),
            )
            .finish()
    }
}

/// Authorization outcome carried on a broker response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// The request was allowed end-to-end.
    Allow,
    /// The request was refused at some pipeline stage.
    Deny {
        /// Static denial category (never secret-bearing diagnostics).
        reason: String,
        /// Policy responsible for the denial, when attributed.
        policy: Option<String>,
    },
}

/// Broker reply (plan §19). Headers and body are sanitized by the engine
/// before this value is constructed; denied responses carry no body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BrokerResponse {
    /// Per-request correlation identifier.
    pub request_id: RequestId,
    /// Upstream HTTP status code (403 for denials produced by the broker
    /// itself).
    pub status: u16,
    /// Sanitized upstream response headers.
    pub headers: Vec<(String, String)>,
    /// Sanitized upstream response body.
    pub body: Vec<u8>,
    /// End-to-end outcome.
    pub decision: Decision,
}

impl BrokerResponse {
    /// Builds a denial response: HTTP 403, empty headers/body, no
    /// secret-bearing diagnostics.
    #[must_use]
    pub fn denied(
        request_id: RequestId,
        reason: impl Into<String>,
        policy: Option<String>,
    ) -> Self {
        Self {
            request_id,
            status: 403,
            headers: Vec::new(),
            body: Vec::new(),
            decision: Decision::Deny {
                reason: reason.into(),
                policy,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> BrokerRequest {
        BrokerRequest {
            protocol: PROTOCOL_VERSION,
            session_token: "0123456789abcdef0123456789abcdef".to_owned(),
            credential: CredentialRef::parse("github-work-token").unwrap(),
            method: HttpMethod::POST,
            url: "https://api.github.com/repos/acme/backend/pulls".to_owned(),
            headers: vec![("accept".to_owned(), "application/json".to_owned())],
            body: BrokerBody::Json {
                value: serde_json::json!({"title": "Fix auth bug"}),
            },
            capability_hint: Some("github.pull_request.create".to_owned()),
            request_id: Some(RequestId::generate().unwrap()),
        }
    }

    #[test]
    fn request_round_trips_through_json() {
        let request = sample_request();
        let encoded = serde_json::to_string(&request).unwrap();
        let decoded: BrokerRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, request);

        // The tagged body keeps its variant across the boundary.
        assert!(matches!(decoded.body, BrokerBody::Json { .. }));
    }

    #[test]
    fn requests_without_request_id_still_decode() {
        // Wire compatibility: pre-§30 producers omit the field entirely.
        let legacy = serde_json::to_string(&BrokerRequest {
            protocol: PROTOCOL_VERSION,
            session_token: "0123456789abcdef0123456789abcdef".to_owned(),
            credential: CredentialRef::parse("github-work-token").unwrap(),
            method: HttpMethod::GET,
            url: "https://api.github.com/x".to_owned(),
            headers: Vec::new(),
            body: BrokerBody::None,
            capability_hint: None,
            request_id: None,
        })
        .unwrap();
        // Strip the emitted `request_id` key to simulate a legacy line.
        let without: serde_json::Value = serde_json::from_str(&legacy).unwrap();
        let mut stripped = without.clone();
        stripped
            .as_object_mut()
            .unwrap()
            .remove("request_id")
            .expect("field present");
        let decoded: BrokerRequest = serde_json::from_value(stripped).unwrap();
        assert_eq!(decoded.request_id, None);
        assert_eq!(decoded.credential.as_str(), "github-work-token");
    }

    #[test]
    fn malformed_caller_request_ids_are_rejected_at_decode() {
        let mut value = serde_json::to_value(sample_request()).unwrap();
        for bad in ["nope", "req_zz", "req_0123456789ABCDEF0123456789abcdef"] {
            value["request_id"] = serde_json::Value::String(bad.to_owned());
            assert!(
                serde_json::from_value::<BrokerRequest>(value.clone()).is_err(),
                "{bad} must be rejected"
            );
        }
    }

    #[test]
    fn body_variants_round_trip_without_confusion() {
        let none_json = serde_json::to_string(&BrokerBody::None).unwrap();
        assert_eq!(none_json, r#"{"type":"none"}"#);
        let decoded_none: BrokerBody = serde_json::from_str(&none_json).unwrap();
        assert_eq!(decoded_none, BrokerBody::None);

        let bytes = BrokerBody::Bytes {
            data: vec![1, 2, 3, 255],
        };
        let bytes_json = serde_json::to_string(&bytes).unwrap();
        let decoded_bytes: BrokerBody = serde_json::from_str(&bytes_json).unwrap();
        assert_eq!(decoded_bytes, bytes);

        let json = BrokerBody::Json {
            value: serde_json::json!({"k": [1, true, null]}),
        };
        let decoded_json: BrokerBody =
            serde_json::from_str(&serde_json::to_string(&json).unwrap()).unwrap();
        assert_eq!(decoded_json, json);

        // A bare array must NOT deserialize into the Bytes variant.
        let ambiguous: Result<BrokerBody, _> = serde_json::from_str("[1,2,3]");
        assert!(ambiguous.is_err());
    }

    #[test]
    fn wire_len_matches_serialized_shapes() {
        assert_eq!(BrokerBody::None.wire_len_bytes(), 0);
        assert_eq!(BrokerBody::Bytes { data: vec![0u8; 7] }.wire_len_bytes(), 7);
        let json = BrokerBody::Json {
            value: serde_json::json!({"a":1}),
        };
        let expected = serde_json::to_vec(json_value(&json)).unwrap().len() as u64;
        assert_eq!(json.wire_len_bytes(), expected);
    }

    fn json_value(body: &BrokerBody) -> &serde_json::Value {
        let BrokerBody::Json { value } = body else {
            panic!("expected json body");
        };
        value
    }

    #[test]
    fn generated_request_ids_are_wellformed_and_unique() {
        let first = RequestId::generate().unwrap();
        let second = RequestId::generate().unwrap();
        for id in [&first, &second] {
            assert!(id.as_str().starts_with(RequestId::PREFIX));
            assert_eq!(id.as_str().len(), "req_".len() + 32);
            assert!(
                id.as_str()["req_".len()..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "{} must be lowercase hex",
                id.as_str()
            );
        }
        assert_ne!(first, second);
    }

    #[test]
    fn deserialization_rejects_malformed_request_ids() {
        for bad in [
            "\"nope\"",
            "\"req_\"",
            "\"req_zzz\"",
            "\"REQ_0123456789abcdef0123456789abcdef\"",
            "\"req_0123456789ABCDEF0123456789abcdef\"",
            "\"req_0123456789abcdef0123456789abcde\"", // too short
            "\"req_0123456789abcdef0123456789abcdef00\"", // too long
        ] {
            assert!(
                serde_json::from_str::<RequestId>(bad).is_err(),
                "{bad} should be rejected"
            );
        }
        let good = serde_json::to_string(&RequestId::generate().unwrap()).unwrap();
        assert!(serde_json::from_str::<RequestId>(&good).is_ok());
    }

    #[test]
    fn allow_response_round_trips_through_json() {
        let response = BrokerResponse {
            request_id: RequestId::generate().unwrap(),
            status: 201,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: br#"{"ok":true}"#.to_vec(),
            decision: Decision::Allow,
        };
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(encoded.contains(r#""decision":"allow""#));
        let decoded: BrokerResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn denied_response_helper_produces_403_empty_deny() {
        let request_id = RequestId::generate().unwrap();
        let response = BrokerResponse::denied(
            request_id.clone(),
            "path_not_allowed",
            Some("coding-agent-github".to_owned()),
        );
        assert_eq!(response.request_id, request_id);
        assert_eq!(response.status, 403);
        assert!(response.headers.is_empty());
        assert!(response.body.is_empty());
        assert_eq!(
            response.decision,
            Decision::Deny {
                reason: "path_not_allowed".to_owned(),
                policy: Some("coding-agent-github".to_owned()),
            }
        );

        let encoded = serde_json::to_string(&response).unwrap();
        let decoded: BrokerResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn debug_output_redacts_session_token_and_body() {
        const CANARY_TOKEN: &str = "CANARY_SESSION_TOKEN_9f8";
        let mut request = sample_request();
        request.session_token = CANARY_TOKEN.to_owned();
        request.body = BrokerBody::Bytes {
            data: b"CANARY_BODY_BYTES".to_vec(),
        };
        let debugged = format!("{request:?}");
        assert!(!debugged.contains(CANARY_TOKEN));
        assert!(!debugged.contains("CANARY_BODY_BYTES"));
        assert!(debugged.contains("<redacted>"));
        // PartialEq/serialization are unaffected by the Debug override.
        assert_eq!(request, request.clone());
        assert!(serde_json::to_string(&request)
            .unwrap()
            .contains(CANARY_TOKEN));
    }

    #[test]
    fn protocol_version_constant_is_one() {
        assert_eq!(PROTOCOL_VERSION, 1);
        assert_eq!(sample_request().protocol, PROTOCOL_VERSION);
    }
}
