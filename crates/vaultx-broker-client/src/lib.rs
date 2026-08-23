//! Typed client for the vaultx broker IPC endpoint (plan §18/§19).
//!
//! One JSON line out, one JSON line in, with a hard timeout so agents
//! never hang on a wedged broker. Errors are secret-blind: connection and
//! protocol failures carry only failure classes.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vaultx_broker::request::PROTOCOL_VERSION;
use vaultx_broker::{BrokerRequest, BrokerResponse, ClientLine, ServerLine, MAX_LINE_BYTES};

/// Default per-request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Client-side failures. Messages never echo request content.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The endpoint could not be reached.
    #[error("cannot connect to broker at {path}: {source}")]
    ConnectionFailed {
        /// Endpoint that was dialed.
        path: String,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
    /// The exchange did not complete inside the timeout.
    #[error("broker request timed out")]
    Timeout,
    /// The broker answered with an unparseable or unexpected line.
    #[error("broker protocol violation: {0}")]
    ProtocolViolation(String),
    /// Underlying I/O failed mid-exchange.
    #[error("broker i/o failure: {0}")]
    Io(String),
}

/// Connection to one broker IPC endpoint.
pub struct BrokerClient {
    stream: IpcStream,
}

#[cfg(unix)]
type IpcStream = tokio::net::UnixStream;

#[cfg(windows)]
enum IpcStream {
    Placeholder,
}

impl BrokerClient {
    /// Connects to the broker endpoint at `path`.
    ///
    /// # Errors
    /// [`ClientError::ConnectionFailed`] when dialing fails; on Windows
    /// builds, a typed violation (named-pipe support pending).
    pub async fn connect(path: impl AsRef<std::path::Path>) -> Result<Self, ClientError> {
        #[cfg(unix)]
        {
            let stream = tokio::net::UnixStream::connect(path.as_ref())
                .await
                .map_err(|err| ClientError::ConnectionFailed {
                    path: path.as_ref().display().to_string(),
                    source: err,
                })?;
            Ok(Self { stream })
        }
        #[cfg(windows)]
        {
            let _ = path;
            Err(ClientError::ProtocolViolation(
                "windows named-pipe endpoints are not supported yet".to_owned(),
            ))
        }
    }

    /// Sends the control ping and waits for the pong.
    ///
    /// # Errors
    /// See [`ClientError`].
    pub async fn ping(&mut self) -> Result<String, ClientError> {
        match self.exchange(&ClientLine::Ping, DEFAULT_TIMEOUT).await? {
            ServerLine::Pong { version, .. } => Ok(version),
            ServerLine::Response(_) | ServerLine::ProtocolViolation { .. } => Err(
                ClientError::ProtocolViolation("expected pong for ping".to_owned()),
            ),
        }
    }

    /// Sends one brokered request and returns the broker's response.
    ///
    /// # Errors
    /// See [`ClientError`].
    pub async fn request(&mut self, request: BrokerRequest) -> Result<BrokerResponse, ClientError> {
        match self
            .exchange(&ClientLine::Request(request), DEFAULT_TIMEOUT)
            .await?
        {
            ServerLine::Response(response) => Ok(response),
            ServerLine::Pong { .. } => Err(ClientError::ProtocolViolation(
                "expected request response, got pong".to_owned(),
            )),
            ServerLine::ProtocolViolation { error } => Err(ClientError::ProtocolViolation(error)),
        }
    }

    async fn exchange(
        &mut self,
        line: &ClientLine,
        timeout: Duration,
    ) -> Result<ServerLine, ClientError> {
        let fut = self.raw_exchange(line);
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ClientError::Timeout)?
    }

    async fn raw_exchange(&mut self, line: &ClientLine) -> Result<ServerLine, ClientError> {
        let mut encoded = serde_json::to_vec(line)
            .map_err(|err| ClientError::Io(format!("encode failure: {err}")))?;
        encoded.push(b'\n');
        self.stream
            .write_all(&encoded)
            .await
            .map_err(|err| ClientError::Io(format!("send failure: {err}")))?;
        self.stream
            .flush()
            .await
            .map_err(|err| ClientError::Io(format!("send failure: {err}")))?;

        let mut buf = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        loop {
            let read = self
                .stream
                .read(&mut byte)
                .await
                .map_err(|err| ClientError::Io(format!("receive failure: {err}")))?;
            if read == 0 {
                return Err(ClientError::Io(
                    "connection closed before response".to_owned(),
                ));
            }
            match byte[0] {
                b'\n' => break,
                b'\r' => {}
                other => {
                    buf.push(other);
                    if buf.len() > MAX_LINE_BYTES {
                        return Err(ClientError::ProtocolViolation(
                            "response exceeds maximum permitted size".to_owned(),
                        ));
                    }
                }
            }
        }
        serde_json::from_slice::<ServerLine>(&buf)
            .map_err(|err| ClientError::ProtocolViolation(err.to_string()))
    }
}

/// Convenience: protocol constant re-exported for callers building raw
/// request lines.
#[must_use]
pub const fn protocol_version() -> u16 {
    PROTOCOL_VERSION
}

/// Default broker IPC endpoint used by every client-facing surface
/// (`vaultx` CLI, MCP tools): `$XDG_RUNTIME_DIR/vaultx/local/broker.sock`
/// with a uid-scoped `/tmp` fallback (unix), or the platform pipe name
/// (windows).
///
/// Wraps [`vaultx_broker::ipc::default_socket_path`] so clients and the
/// broker always agree on the bind location.
#[must_use]
pub fn default_endpoint() -> String {
    #[cfg(unix)]
    {
        vaultx_broker::ipc::default_socket_path("local")
            .to_string_lossy()
            .into_owned()
    }
    #[cfg(windows)]
    {
        r"\\.\pipe\vaultx-local".to_owned()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use vaultx_broker::request::{BrokerBody, Decision, RequestId, PROTOCOL_VERSION};
    use vaultx_broker::{BrokerServer, EngineHandle, ServerConfig};
    use vaultx_policy::HttpMethod;
    use vaultx_types::CredentialRef;

    struct MockEngine;

    impl EngineHandle for MockEngine {
        fn execute(&self, request: BrokerRequest) -> BrokerResponse {
            let allowed = request.method == HttpMethod::GET
                && request.url.starts_with("https://api.github.com/");
            let request_id = RequestId::generate().unwrap();
            if allowed {
                BrokerResponse {
                    request_id,
                    status: 200,
                    headers: vec![],
                    body: b"ok".to_vec(),
                    decision: Decision::Allow,
                }
            } else {
                BrokerResponse::denied(request_id, "no_matching_allow", None)
            }
        }
    }

    fn broker_request(url: &str) -> BrokerRequest {
        BrokerRequest {
            protocol: PROTOCOL_VERSION,
            session_token: "0123456789abcdef0123456789abcdef".to_owned(),
            credential: CredentialRef::parse("github-work-token").unwrap(),
            method: HttpMethod::GET,
            url: url.to_owned(),
            headers: Vec::new(),
            body: BrokerBody::None,
            capability_hint: None,
        }
    }

    async fn spawn() -> (std::path::PathBuf, tokio::task::JoinHandle<()>) {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("broker.sock");
        let server = BrokerServer::<MockEngine>::bind(
            StdArc::new(MockEngine),
            "proj-test",
            ServerConfig {
                socket_path: Some(path.clone()),
                max_connections: 0,
            },
        )
        .expect("bind");
        let bound = server.path().to_path_buf();
        // Keep the tempdir alive for the whole test by leaking its guard.
        std::mem::forget(dir);
        let handle = tokio::spawn(async move {
            let _ = server.serve().await;
        });
        for _ in 0..100 {
            if bound.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        (bound, handle)
    }

    #[tokio::test]
    async fn ping_and_request_round_trip_through_client() {
        let (bound, handle) = spawn().await;
        let mut client = BrokerClient::connect(&bound).await.expect("connect");

        let version = client.ping().await.expect("pong");
        assert_eq!(version, env!("CARGO_PKG_VERSION"));

        let allow = client
            .request(broker_request("https://api.github.com/x"))
            .await
            .expect("allow");
        assert_eq!(allow.decision, Decision::Allow);

        let deny = client
            .request(broker_request("https://other.example/y"))
            .await
            .expect("deny");
        assert!(matches!(
            deny.decision,
            Decision::Deny { ref reason, .. } if reason == "no_matching_allow"
        ));
        drop(client);
        handle.abort();
    }

    #[tokio::test]
    async fn timeout_fires_when_server_never_answers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("silent.sock");
        let listener = tokio::net::UnixListener::bind(&path).expect("bind silent endpoint");
        // Accept but never reply; hold the peer open until the timeout.
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_secs(60)).await;
                drop(stream);
            }
        });

        let mut client = BrokerClient::connect(&path).await.expect("connect");
        let err = client
            .exchange(&ClientLine::Ping, Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::Timeout), "{err:?}");
    }

    #[tokio::test]
    async fn connection_refused_surfaces_connection_failed() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.sock");
        let err = match BrokerClient::connect(&missing).await {
            Err(err) => err,
            Ok(_) => panic!("connect to missing endpoint must fail"),
        };
        assert!(
            matches!(err, ClientError::ConnectionFailed { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn protocol_version_is_one() {
        assert_eq!(protocol_version(), 1);
        assert_eq!(PROTOCOL_VERSION, 1);
    }
}
