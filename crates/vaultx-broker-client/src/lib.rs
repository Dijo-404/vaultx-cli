//! Typed client for the vaultx broker IPC endpoint (plan §18/§19) and
//! its remote TLS gateway (plan §30).
//!
//! One JSON line out, one JSON line in, with a hard timeout so agents
//! never hang on a wedged broker. Errors are secret-blind: connection,
//! TLS, and protocol failures carry only failure classes.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    /// The remote gateway's TLS handshake failed: untrusted server
    /// certificate, rejected client identity, or protocol mismatch.
    /// There is deliberately no insecure-retry mode.
    #[error("broker TLS handshake failed: {0}")]
    TlsHandshakeFailed(String),
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

/// Dial parameters for a remote broker gateway (plan §30). The CA bundle
/// is **required**: the gateway identity is always verified against
/// operator-supplied roots — no certificate-validation bypass exists.
#[derive(Clone, Debug)]
pub struct RemoteEndpoint {
    /// `HOST:PORT` of the gateway.
    pub addr: String,
    /// PEM bundle of trusted CA certificates for the gateway's chain.
    pub ca_pem: PathBuf,
    /// Optional client certificate (PEM) for gateways requiring mutual
    /// TLS workload identity.
    pub cert_pem: Option<PathBuf>,
    /// Private key matching [`Self::cert_pem`] (PEM).
    pub key_pem: Option<PathBuf>,
}

/// Connection to one broker IPC endpoint.
pub struct BrokerClient {
    stream: IpcStream,
}

/// The byte stream under one connection: a local Unix socket or a
/// TLS-protected TCP session to the remote gateway. Boxed so the enum
/// stays small across await points.
enum IpcStream {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
}

impl AsyncRead for IpcStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(unix)]
            Self::Unix(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for IpcStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            #[cfg(unix)]
            Self::Unix(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(unix)]
            Self::Unix(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            #[cfg(unix)]
            Self::Unix(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => std::pin::Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
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
            Ok(Self {
                stream: IpcStream::Unix(stream),
            })
        }
        #[cfg(windows)]
        {
            let _ = path;
            Err(ClientError::ProtocolViolation(
                "windows named-pipe endpoints are not supported yet".to_owned(),
            ))
        }
    }

    /// Connects to a remote TLS gateway (plan §30): rustls with the
    /// caller-supplied root store, optional client-certificate identity
    /// for mutually authenticated deployments. Certificate validation is
    /// unconditional — an unverifiable gateway is refused, never
    /// downgraded.
    ///
    /// # Errors
    /// [`ClientError::ConnectionFailed`] on TCP failure,
    /// [`ClientError::TlsHandshakeFailed`] when the handshake or any
    /// certificate check fails, and typed violations elsewhere.
    pub async fn connect_remote(endpoint: &RemoteEndpoint) -> Result<Self, ClientError> {
        // rustls 0.23 requires an explicit process-level crypto provider;
        // installing is idempotent (same pattern as the broker crate).
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

        let ca_file = std::fs::File::open(&endpoint.ca_pem).map_err(|err| {
            ClientError::Io(format!(
                "cannot open CA bundle {}: {err}",
                endpoint.ca_pem.display()
            ))
        })?;
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        let ca_certs = rustls_pemfile::certs(&mut std::io::BufReader::new(ca_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| ClientError::Io(format!("cannot parse CA bundle: {err}")))?;
        if ca_certs.is_empty() {
            return Err(ClientError::Io(
                "CA bundle contains no certificates".to_owned(),
            ));
        }
        for cert in ca_certs {
            roots.add(cert).map_err(|err| {
                ClientError::Io(format!("CA bundle rejected by trust store: {err}"))
            })?;
        }

        let builder = tokio_rustls::rustls::ClientConfig::builder();
        let config =
            if let (Some(cert_pem), Some(key_pem)) = (&endpoint.cert_pem, &endpoint.key_pem) {
                let cert_file = std::fs::File::open(cert_pem)
                    .map_err(|err| ClientError::Io(format!("cannot open client cert: {err}")))?;
                let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|err| ClientError::Io(format!("cannot parse client cert: {err}")))?;
                if certs.is_empty() {
                    return Err(ClientError::Io(
                        "client cert file contains no certificates".to_owned(),
                    ));
                }
                let key_file = std::fs::File::open(key_pem)
                    .map_err(|err| ClientError::Io(format!("cannot open client key: {err}")))?;
                let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))
                    .map_err(|err| ClientError::Io(format!("cannot parse client key: {err}")))?
                    .ok_or_else(|| {
                        ClientError::Io("client key file contains no private key".to_owned())
                    })?;
                builder
                    .with_root_certificates(roots)
                    .with_client_auth_cert(certs, key)
                    .map_err(|err| ClientError::Io(format!("client identity rejected: {err}")))?
            } else {
                builder.with_root_certificates(roots).with_no_client_auth()
            };

        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        let tcp = tokio::net::TcpStream::connect(endpoint.addr.as_str())
            .await
            .map_err(|err| ClientError::ConnectionFailed {
                path: endpoint.addr.clone(),
                source: err,
            })?;
        // Server-name selection: IP literals stay literal; anything else
        // is treated as a DNS name for certificate matching.
        let host = endpoint.addr.split(':').next().unwrap_or(&endpoint.addr);
        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|_| {
                ClientError::TlsHandshakeFailed(format!("invalid server name `{host}`"))
            })?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|err| ClientError::TlsHandshakeFailed(err.to_string()))?;
        Ok(Self {
            stream: IpcStream::Tls(Box::new(tls)),
        })
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
            request_id: None,
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
                endpoint: None,
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
