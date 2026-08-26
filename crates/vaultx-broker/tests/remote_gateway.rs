//! Plan §30 remote/isolated broker gateway end-to-end tests.
//!
//! Exercises the real network path: a full [`BrokerEngine`] pipeline
//! (session auth → policy → credential resolution → injection →
//! sanitized response) served through rustls TLS on `127.0.0.1:0`, with
//! an rcgen-generated CA, server certificate, and client workload
//! identity. The local Unix-socket path is covered unchanged by the
//! unit tests in `ipc.rs`; these tests prove the TLS gateway serves the
//! *same* protocol over the *same* engine.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use vaultx_audit::JsonlAppendStore;
use vaultx_broker::BrokerError;
use vaultx_broker::{
    BrokerDependencies, BrokerEndpoint, BrokerEngine, BrokerRequest, BrokerResponse, BrokerServer,
    CredentialMetadata, ExecutedResponse, InMemoryCredentialSource, InMemorySessionStore,
    InjectionTemplateId, InjectorRegistry, OutboundRequest, RequestId, ServerConfig,
    SessionStore as _, TransportExecutor,
};
use vaultx_broker_client::{BrokerClient, ClientError, RemoteEndpoint};
use vaultx_crypto::secret::SecretBytes;
use vaultx_policy::{parse_policy_yaml, HttpMethod, RuleEngine};
use vaultx_types::{AgentId, CredentialRef, EnvironmentId, ProjectId};

const SECRET_CANARY: &str = "CANARY_GATEWAY_SECRET_9f8";
/// Upstream body carrying a `ghp_`-shaped token the engine must scrub.
const RESPONSE_TOKEN: &str = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ab";
const FIXTURE_AGENT_ID: &str = "agent_coding";

// ---------------------------------------------------------------------------
// Test certificates (rcgen): one CA, a server leaf, a client identity.
// ---------------------------------------------------------------------------

struct TestCerts {
    _dir: tempfile::TempDir,
    server_cert: PathBuf,
    server_key: PathBuf,
    ca: PathBuf,
    client_cert: PathBuf,
    client_key: PathBuf,
}

impl TestCerts {
    fn client_identity(&self) -> (Option<PathBuf>, Option<PathBuf>) {
        (
            Some(self.client_cert.clone()),
            Some(self.client_key.clone()),
        )
    }

    fn remote_endpoint(&self, addr: String, with_identity: bool) -> RemoteEndpoint {
        let (cert_pem, key_pem) = if with_identity {
            self.client_identity()
        } else {
            (None, None)
        };
        RemoteEndpoint {
            addr,
            ca_pem: self.ca.clone(),
            cert_pem,
            key_pem,
        }
    }
}

fn write_private(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write pem");
}

/// Generates a small PKI (rcgen's default validity window avoids clock
/// skew flakes) and writes every component as PEM.
fn generate_test_certs() -> TestCerts {
    let dir = tempfile::tempdir().expect("cert tempdir");

    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "VaultX Gateway Test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

    let server_key = rcgen::KeyPair::generate().expect("server key");
    // `CertificateParams::new` accepts IP literals as SANs directly.
    let server_params =
        rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .expect("server sans");
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("server cert");
    let server_cert_pem = server_cert.pem();
    let server_key_pem = server_key.serialize_pem();

    let client_key = rcgen::KeyPair::generate().expect("client key");
    let mut client_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params.is_ca = rcgen::IsCa::ExplicitNoCa;
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "vaultx-agent-workload");
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("client cert");
    let client_cert_pem = client_cert.pem();
    let client_key_pem = client_key.serialize_pem();

    let ca_pem = ca_cert.pem();

    let paths = TestCerts {
        server_cert: dir.path().join("server-cert.pem"),
        server_key: dir.path().join("server-key.pem"),
        ca: dir.path().join("ca.pem"),
        client_cert: dir.path().join("client-cert.pem"),
        client_key: dir.path().join("client-key.pem"),
        _dir: dir,
    };
    write_private(&paths.server_cert, &server_cert_pem);
    write_private(&paths.server_key, &server_key_pem);
    write_private(&paths.ca, &ca_pem);
    write_private(&paths.client_cert, &client_cert_pem);
    write_private(&paths.client_key, &client_key_pem);
    paths
}

// ---------------------------------------------------------------------------
// Engine fixture (mirrors the happy-path transport pattern of engine.rs)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CapturingTransport {
    captured: Arc<Mutex<Vec<OutboundRequest>>>,
}

impl CapturingTransport {
    fn last_auth_header(&self) -> Option<(String, String)> {
        self.captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .last()
            .map(|outbound| {
                outbound
                    .headers
                    .iter()
                    .find(|(name, _)| name == "authorization")
                    .cloned()
                    .expect("injected authorization header")
            })
    }
}

impl TransportExecutor for CapturingTransport {
    fn execute(&self, outbound: &OutboundRequest) -> Result<ExecutedResponse, BrokerError> {
        self.captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(outbound.clone());
        Ok(ExecutedResponse {
            status: 200,
            headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            body: format!(r#"{{"echo":"{RESPONSE_TOKEN}","ok":true}}"#).into_bytes(),
        })
    }
}

struct Fixture {
    engine: BrokerEngine,
    raw_token: String,
    transport: CapturingTransport,
    audit_dir: tempfile::TempDir,
}

fn build_fixture() -> Fixture {
    let audit_dir = tempfile::tempdir().expect("audit dir");
    let audit = Arc::new(JsonlAppendStore::open(audit_dir.path().join("audit.jsonl")));
    let sessions = Arc::new(InMemorySessionStore::new());
    let credentials = Arc::new(InMemoryCredentialSource::new());
    let transport = CapturingTransport {
        captured: Arc::new(Mutex::new(Vec::new())),
    };

    credentials.insert(
        CredentialRef::parse("github-work-token").unwrap(),
        SecretBytes::from_bytes(SECRET_CANARY.as_bytes()),
        InjectionTemplateId::GithubBearer,
        CredentialMetadata::default(),
    );
    let (_, raw_token) = sessions
        .create(
            &AgentId::parse(FIXTURE_AGENT_ID).unwrap(),
            &EnvironmentId::parse("env_development").unwrap(),
        )
        .expect("session created");

    let principal = format!(
        "agent:{}",
        FIXTURE_AGENT_ID
            .strip_prefix("agent_")
            .unwrap_or(FIXTURE_AGENT_ID)
    );
    let yaml = format!(
        "name: coding-agent-github\n\
         principal: \"{principal}\"\n\
         credential: github-work-token\n\
         http:\n  \
         hosts: [api.github.com]\n  \
         allow:\n    - methods: [GET]\n      paths: [/repos/acme/backend/**]\n"
    );
    let authorizer = RuleEngine::from_documents([parse_policy_yaml(&yaml).expect("valid policy")])
        .expect("fixture policies compile");

    let engine = BrokerEngine::new(BrokerDependencies {
        authorizer: Arc::new(authorizer),
        sessions,
        credentials,
        injectors: Arc::new(InjectorRegistry::new()),
        transport: Arc::new(transport.clone()),
        audit,
        project: ProjectId::parse("proj_gateway").unwrap(),
        egress_allow_private: false,
    });

    Fixture {
        engine,
        raw_token,
        transport,
        audit_dir,
    }
}

fn broker_request(token: &str, url: &str, request_id: Option<RequestId>) -> BrokerRequest {
    BrokerRequest {
        protocol: vaultx_broker::PROTOCOL_VERSION,
        session_token: token.to_owned(),
        credential: CredentialRef::parse("github-work-token").unwrap(),
        method: HttpMethod::GET,
        url: url.to_owned(),
        headers: Vec::new(),
        body: vaultx_broker::BrokerBody::None,
        capability_hint: None,
        request_id,
    }
}

// ---------------------------------------------------------------------------
// Gateway harness: binds one engine behind a real TLS listener.
// ---------------------------------------------------------------------------

struct Gateway {
    addr: SocketAddr,
    handle: tokio::task::JoinHandle<()>,
}

/// Test-visible handles into the engine behind the gateway.
struct GatewayFixture {
    raw_token: String,
    transport: CapturingTransport,
}

async fn spawn_gateway(certs: &TestCerts, require_client_cert: bool) -> (Gateway, GatewayFixture) {
    let Fixture {
        engine,
        raw_token,
        transport,
        audit_dir,
    } = build_fixture();
    let client_ca_pem = require_client_cert.then(|| certs.ca.clone());
    let server = BrokerServer::bind_remote(
        Arc::new(engine),
        "gateway-test",
        ServerConfig {
            socket_path: None,
            max_connections: 16,
            endpoint: Some(BrokerEndpoint::RemoteTls {
                bind: "127.0.0.1:0".parse().unwrap(),
                cert_pem: certs.server_cert.clone(),
                key_pem: certs.server_key.clone(),
                client_ca_pem,
            }),
        },
    )
    .await
    .expect("bind remote gateway");
    let addr = server.remote_addr().expect("bound tcp address");
    let handle = tokio::spawn(async move {
        // Keep the audit sink's directory alive as long as the gateway
        // serves so every pipeline outcome stays auditable.
        let _keep_alive = audit_dir;
        let _ = server.serve().await;
    });
    (
        Gateway { addr, handle },
        GatewayFixture {
            raw_token,
            transport,
        },
    )
}

impl Gateway {
    async fn connect(&self, certs: &TestCerts, with_identity: bool) -> BrokerClient {
        let endpoint = certs.remote_endpoint(self.addr.to_string(), with_identity);
        BrokerClient::connect_remote(&endpoint)
            .await
            .expect("gateway connect")
    }

    fn stop(self) {
        self.handle.abort();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn end_to_end_brokered_request_over_mutual_tls() {
    let certs = generate_test_certs();
    let (gateway, fixture) = spawn_gateway(&certs, true).await;

    let mut client = gateway.connect(&certs, true).await;
    let version = client.ping().await.expect("pong");
    assert_eq!(version, env!("CARGO_PKG_VERSION"));

    let request_id = RequestId::generate().unwrap();
    let request = broker_request(
        &fixture.raw_token,
        "https://api.github.com/repos/acme/backend/issues",
        Some(request_id.clone()),
    );
    let response = client.request(request).await.expect("brokered response");

    assert_eq!(response.request_id, request_id, "caller id echoed");
    assert_eq!(
        response.decision,
        vaultx_broker::Decision::Allow,
        "seeded policy allows GET /repos/acme/backend/**"
    );
    assert_eq!(response.status, 200);

    // INV-002/003 over the wire: no credential plaintext anywhere in the
    // serialized envelope or the decoded payload; the upstream token
    // shape is scrubbed before delivery.
    let wire = serde_json::to_string(&response).expect("serialize");
    assert!(!wire.contains(SECRET_CANARY), "{wire}");
    assert!(!wire.contains(RESPONSE_TOKEN), "{wire}");
    let body_text = String::from_utf8(response.body.clone()).expect("utf-8 body");
    assert!(!body_text.contains(SECRET_CANARY));
    assert!(
        !body_text.contains(RESPONSE_TOKEN),
        "upstream token shape scrubbed"
    );
    assert!(body_text.contains("[redacted]"), "scrubbed body delivered");

    // Injection happened inside broker scope on the outbound side only.
    assert_eq!(
        fixture.transport.last_auth_header(),
        Some(("authorization".to_owned(), format!("token {SECRET_CANARY}")))
    );

    gateway.stop();
}

#[tokio::test]
async fn gateway_refuses_clients_without_certificate_before_any_protocol_byte() {
    let certs = generate_test_certs();
    let (gateway, _fixture) = spawn_gateway(&certs, true).await;

    let endpoint = certs.remote_endpoint(gateway.addr.to_string(), false);
    // TLS 1.3 may surface the server's certificate_required alert just
    // after the client-side handshake future resolves, so the refusal is
    // observed on the first exchange. Either way: no pong is ever
    // produced, i.e. no protocol byte is processed by either side.
    let outcome = async {
        let mut client = BrokerClient::connect_remote(&endpoint).await?;
        client.ping().await
    }
    .await;

    match outcome {
        Err(ClientError::TlsHandshakeFailed(_))
        | Err(ClientError::ConnectionFailed { .. })
        | Err(ClientError::Io(_)) => {}
        Err(ClientError::Timeout) => panic!("refusal must not hang"),
        Err(other) => panic!("unexpected error class: {other:?}"),
        Ok(_) => panic!("certificate-less client must not reach the protocol"),
    }

    // A certificate-bearing peer still works afterwards: the refusal is
    // per-handshake, never a wedge.
    let mut ok_client = gateway.connect(&certs, true).await;
    ok_client.ping().await.expect("pong after refusal");
    gateway.stop();
}

#[tokio::test]
async fn replayed_request_id_denied_over_tls_fresh_id_allowed() {
    let certs = generate_test_certs();
    let (gateway, fixture) = spawn_gateway(&certs, true).await;
    let mut client = gateway.connect(&certs, true).await;

    let replay_id = RequestId::generate().unwrap();
    let url = "https://api.github.com/repos/acme/backend/issues";

    let first = client
        .request(broker_request(
            &fixture.raw_token,
            url,
            Some(replay_id.clone()),
        ))
        .await
        .expect("first exchange");
    assert_eq!(first.decision, vaultx_broker::Decision::Allow);

    let replay = client
        .request(broker_request(&fixture.raw_token, url, Some(replay_id)))
        .await
        .expect("replay answered on the wire");
    match replay.decision {
        vaultx_broker::Decision::Deny { reason, .. } => {
            assert_eq!(reason, vaultx_broker::REPLAY_DETECTED_REASON)
        }
        other => panic!("replay must be denied, got {other:?}"),
    }

    let fresh = RequestId::generate().unwrap();
    let third = client
        .request(broker_request(&fixture.raw_token, url, Some(fresh)))
        .await
        .expect("fresh id proceeds");
    assert_eq!(third.decision, vaultx_broker::Decision::Allow);

    gateway.stop();
}

#[tokio::test]
async fn server_only_tls_serves_certless_clients() {
    // Without --client-ca the gateway is plain server-TLS: identity rests
    // entirely on session tokens, exactly like the local socket.
    let certs = generate_test_certs();
    let (gateway, fixture) = spawn_gateway(&certs, false).await;
    let mut client = gateway.connect(&certs, false).await;

    let pong = client.ping().await.expect("pong without client cert");
    assert_eq!(pong, env!("CARGO_PKG_VERSION"));

    let allow = client
        .request(broker_request(
            &fixture.raw_token,
            "https://api.github.com/repos/acme/backend/issues",
            None,
        ))
        .await
        .expect("brokered response");
    assert_eq!(allow.decision, vaultx_broker::Decision::Allow);
    gateway.stop();
}

#[tokio::test]
async fn unauthorized_destination_is_denied_through_the_wire() {
    let certs = generate_test_certs();
    let (gateway, fixture) = spawn_gateway(&certs, true).await;
    let mut client = gateway.connect(&certs, true).await;

    let denied = client
        .request(broker_request(
            &fixture.raw_token,
            "https://evil.example.com/repos/acme/backend/issues",
            None,
        ))
        .await
        .expect("deny answered");
    match denied.decision {
        vaultx_broker::Decision::Deny { reason, .. } => {
            assert_eq!(reason, "no_matching_allow")
        }
        other => panic!("foreign host must be denied, got {other:?}"),
    }
    assert!(
        fixture.transport.last_auth_header().is_none(),
        "denied requests never reach transport"
    );
    gateway.stop();
}

// Keep the BrokerResponse import meaningful even if assertions above are
// reshaped: the wire scan covers the full serialization of every variant.
#[test]
fn response_envelope_has_no_secret_shaped_field_names() {
    let response = BrokerResponse::denied(RequestId::generate().unwrap(), "nope", None);
    let wire = serde_json::to_string(&response).expect("serialize");
    for banned in ["secret", "plaintext", "credential_value", "reveal"] {
        assert!(!wire.contains(banned), "{wire}");
    }
}
