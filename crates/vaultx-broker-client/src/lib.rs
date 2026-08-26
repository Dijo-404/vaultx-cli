//! Typed client for the vaultx broker IPC endpoint (plan §18/§19) and
//! its remote TLS gateway (plan §30).
//!
//! One JSON line out, one JSON line in, with a hard timeout so agents
//! never hang on a wedged broker. Errors are secret-blind: connection,
//! TLS, and protocol failures carry only failure classes.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
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
    /// The endpoint string is malformed: missing port, invalid port, or
    /// a bracketed IPv6 literal that is not exactly `[HOST]:PORT`.
    #[error("invalid broker endpoint `{endpoint}`: {reason}")]
    InvalidEndpoint {
        /// The offending endpoint string.
        endpoint: String,
        /// What was wrong with it.
        reason: String,
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

/// Dial parameters for a remote broker gateway (plan §30). The CA bundle
/// is **required**: the gateway identity is always verified against
/// operator-supplied roots — no certificate-validation bypass exists.
#[derive(Clone, Debug)]
pub struct RemoteEndpoint {
    /// `HOST:PORT` of the gateway. IPv6 literals use bracket form,
    /// `[::1]:8443`.
    pub addr: String,
    /// PEM bundle of trusted CA certificates for the gateway's chain.
    pub ca_pem: PathBuf,
    /// Optional client certificate (PEM) for gateways requiring mutual
    /// TLS workload identity.
    pub cert_pem: Option<PathBuf>,
    /// Private key matching [`Self::cert_pem`] (PEM).
    pub key_pem: Option<PathBuf>,
}

/// A parsed remote endpoint: either a fully-formed socket address (IP
/// literal with port, including bracketed IPv6) or a host/port pair
/// needing resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
enum DialTarget {
    Literal(std::net::SocketAddr),
    HostPort { host: String, port: u16 },
}

impl DialTarget {
    /// The TLS server name to verify the gateway certificate against.
    fn server_name(
        &self,
    ) -> Result<tokio_rustls::rustls::pki_types::ServerName<'static>, ClientError> {
        match self {
            // IP literals stay literals: webpki matches them against IP
            // SANs without any DNS involvement.
            Self::Literal(addr) => Ok(tokio_rustls::rustls::pki_types::ServerName::IpAddress(
                addr.ip().into(),
            )),
            Self::HostPort { host, .. } => {
                tokio_rustls::rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| {
                    ClientError::InvalidEndpoint {
                        endpoint: host.clone(),
                        reason: "not a valid DNS hostname".to_owned(),
                    }
                })
            }
        }
    }
}

fn invalid_endpoint(raw: &str, reason: &str) -> ClientError {
    ClientError::InvalidEndpoint {
        endpoint: raw.to_owned(),
        reason: reason.to_owned(),
    }
}

/// Parses `HOST:PORT` (or a full socket address) into a [`DialTarget`].
fn parse_endpoint(raw: &str) -> Result<DialTarget, ClientError> {
    if let Ok(addr) = raw.parse::<std::net::SocketAddr>() {
        return Ok(DialTarget::Literal(addr));
    }
    let Some((host, port_raw)) = raw.rsplit_once(':') else {
        return Err(invalid_endpoint(raw, "a port is required (HOST:PORT)"));
    };
    if host.contains(':') || host.contains('[') || host.contains(']') {
        // Bare IPv6 literals ("::1", "fe80::1") land here too: their tail
        // after the final colon is not a port either.
        return Err(invalid_endpoint(
            raw,
            "IPv6 literals need bracket form [HOST]:PORT",
        ));
    }
    if host.is_empty() {
        return Err(invalid_endpoint(raw, "empty host"));
    }
    let Ok(port) = port_raw.parse::<u16>() else {
        return Err(invalid_endpoint(raw, "port must be a number in 0..=65535"));
    };
    Ok(DialTarget::HostPort {
        host: host.to_owned(),
        port,
    })
}

/// Connection to one broker IPC endpoint.
///
/// The stream is split once into persistent halves: the read half sits
/// behind a [`tokio::io::BufReader`] for the connection's lifetime, so
/// response bytes buffered past the current line's `\n` survive between
/// exchanges instead of being dropped with a per-call reader.
pub struct BrokerClient {
    writer: tokio::io::WriteHalf<IpcStream>,
    reader: tokio::io::BufReader<tokio::io::ReadHalf<IpcStream>>,
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
            Ok(Self::new(IpcStream::Unix(stream)))
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

        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        // PemObject replaces the unmaintained rustls-pemfile crate.
        let ca_certs = {
            use tokio_rustls::rustls::pki_types::pem::PemObject;
            tokio_rustls::rustls::pki_types::CertificateDer::pem_file_iter(&endpoint.ca_pem)
                .map_err(|err| ClientError::Io(format!("cannot read CA bundle: {err}")))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|err| ClientError::Io(format!("cannot parse CA bundle: {err}")))?
        };
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
                use tokio_rustls::rustls::pki_types::pem::PemObject;
                use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
                let certs = CertificateDer::pem_file_iter(cert_pem)
                    .map_err(|err| ClientError::Io(format!("cannot parse client cert: {err}")))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|err| ClientError::Io(format!("cannot parse client cert: {err}")))?;
                if certs.is_empty() {
                    return Err(ClientError::Io(
                        "client cert file contains no certificates".to_owned(),
                    ));
                }
                let key = PrivateKeyDer::from_pem_file(key_pem)
                    .map_err(|err| ClientError::Io(format!("cannot parse client key: {err}")))?;
                builder
                    .with_root_certificates(roots)
                    .with_client_auth_cert(certs, key)
                    .map_err(|err| ClientError::Io(format!("client identity rejected: {err}")))?
            } else {
                builder.with_root_certificates(roots).with_no_client_auth()
            };

        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        // Endpoint parsing: full `SocketAddr` syntax first (this is what
        // makes `[::1]:8443` work), then an explicit `HOST:PORT` split
        // that rejects bare IPv6 literals and missing/invalid ports
        // instead of guessing.
        let target = parse_endpoint(&endpoint.addr)?;
        let tcp = match &target {
            DialTarget::Literal(addr) => tokio::net::TcpStream::connect(addr).await,
            DialTarget::HostPort { host, port } => {
                tokio::net::TcpStream::connect((host.as_str(), *port)).await
            }
        }
        .map_err(|err| ClientError::ConnectionFailed {
            path: endpoint.addr.clone(),
            source: err,
        })?;
        // Server-name selection: IP literals become [`ServerName::IpAddress`]
        // (no reverse-DNS guessing); anything else must be a valid DNS
        // name for certificate matching.
        let server_name = target.server_name()?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|err| ClientError::TlsHandshakeFailed(err.to_string()))?;
        Ok(Self::new(IpcStream::Tls(Box::new(tls))))
    }

    /// Splits the transport into persistent read/write halves with one
    /// long-lived buffered reader (see [`Self`]'s type docs).
    fn new(stream: IpcStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            writer,
            reader: tokio::io::BufReader::with_capacity(8192, reader),
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
        use tokio::io::AsyncBufReadExt as _;

        let mut encoded = serde_json::to_vec(line)
            .map_err(|err| ClientError::Io(format!("encode failure: {err}")))?;
        encoded.push(b'\n');
        self.writer
            .write_all(&encoded)
            .await
            .map_err(|err| ClientError::Io(format!("send failure: {err}")))?;
        self.writer
            .flush()
            .await
            .map_err(|err| ClientError::Io(format!("send failure: {err}")))?;

        // Bounded buffered read off the persistent reader, mirroring the
        // server's [`read_line_capped`]: the cap counts CR-stripped
        // content and trips as soon as it is exceeded; EOF before a
        // newline is a connection failure.
        let mut raw = Vec::with_capacity(512);
        loop {
            let available = self
                .reader
                .fill_buf()
                .await
                .map_err(|err| ClientError::Io(format!("receive failure: {err}")))?;
            if available.is_empty() {
                return Err(if raw.is_empty() {
                    ClientError::Io("connection closed before response".to_owned())
                } else {
                    ClientError::Io("connection closed mid-response".to_owned())
                });
            }
            let chunk_len = available.len();
            match available.iter().position(|byte| *byte == b'\n') {
                Some(end) => {
                    append_non_cr(&mut raw, &available[..end]);
                    // Bytes after `\n` stay buffered for the next exchange.
                    self.reader.consume(end + 1);
                    break;
                }
                None => {
                    append_non_cr(&mut raw, available);
                    self.reader.consume(chunk_len);
                }
            }
            if raw.len() > MAX_LINE_BYTES {
                return Err(ClientError::ProtocolViolation(
                    "response exceeds maximum permitted size".to_owned(),
                ));
            }
        }
        if raw.len() > MAX_LINE_BYTES {
            return Err(ClientError::ProtocolViolation(
                "response exceeds maximum permitted size".to_owned(),
            ));
        }
        serde_json::from_slice::<ServerLine>(&raw)
            .map_err(|err| ClientError::ProtocolViolation(err.to_string()))
    }
}

/// Appends `bytes` minus carriage returns, matching the broker's line
/// reader so both ends agree on framing.
fn append_non_cr(raw: &mut Vec<u8>, bytes: &[u8]) {
    raw.reserve(bytes.len());
    for &byte in bytes {
        if byte != b'\r' {
            raw.push(byte);
        }
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

    // -- endpoint parsing (plan §30 client surface) --------------------------

    #[test]
    fn endpoint_parsing_covers_ipv6_literals_hosts_and_errors() {
        use std::net::Ipv6Addr;

        let bracketed = parse_endpoint("[::1]:8443").expect("bracketed ipv6");
        assert_eq!(
            bracketed,
            DialTarget::Literal(std::net::SocketAddr::from((Ipv6Addr::LOCALHOST, 8443)))
        );
        // IP literals map to ServerName::IpAddress, not DNS.
        assert!(matches!(
            bracketed.server_name(),
            Ok(tokio_rustls::rustls::pki_types::ServerName::IpAddress(_))
        ));

        let host = parse_endpoint("gateway.example.com:443").expect("dns host");
        assert_eq!(
            host,
            DialTarget::HostPort {
                host: "gateway.example.com".to_owned(),
                port: 443
            }
        );
        assert!(matches!(
            host.server_name(),
            Ok(tokio_rustls::rustls::pki_types::ServerName::DnsName(_))
        ));

        for (raw, reason_fragment) in [
            ("127.0.0.1", "a port is required"),
            ("::1", "IPv6 literals need bracket form"),
            ("[::1]", "IPv6 literals need bracket form"),
            ("host:notaport", "port must be a number"),
            ("host:99999", "port must be a number"),
            (":8443", "empty host"),
        ] {
            let err = parse_endpoint(raw).expect_err(raw);
            match &err {
                ClientError::InvalidEndpoint { endpoint, reason } => {
                    assert_eq!(endpoint, raw);
                    assert!(reason.contains(reason_fragment), "{reason}");
                }
                other => panic!("expected InvalidEndpoint for {raw}, got {other:?}"),
            }
            // The Display message carries both facts.
            let rendered = err.to_string();
            assert!(rendered.contains(raw), "{rendered}");
            assert!(rendered.contains(reason_fragment), "{rendered}");
        }
    }

    /// Connects over TLS to an `[::1]:port` gateway when the host has
    /// IPv6 loopback; skips silently otherwise.
    #[tokio::test]
    async fn ipv6_loopback_endpoint_connects_when_available() {
        let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await else {
            return;
        };

        // Mini-PKI: a real CA plus a signed server leaf (webpki rejects a
        // CA-constrained certificate presented as an end entity).
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

        let key = rcgen::KeyPair::generate().expect("server key");
        let params = rcgen::CertificateParams::new(vec!["localhost".to_owned(), "::1".to_owned()])
            .expect("params");
        let cert = params.signed_by(&key, &ca_cert, &ca_key).expect("cert");

        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().to_owned()],
                tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
            )
            .expect("server config");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = std::sync::Arc::new(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(
            server_config,
        )));

        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    use tokio::io::AsyncWriteExt as _;
                    // One canned pong line, then close.
                    let pong = format!(
                        "{{\"ok\":true,\"version\":\"{}\"}}\n",
                        env!("CARGO_PKG_VERSION")
                    );
                    let _ = tls.write_all(pong.as_bytes()).await;
                    let _ = tls.flush().await;
                    let _ = tls.shutdown().await;
                }
            }
        });

        // Write the CA + leaf to a temp file so connect_remote can load it.
        let dir = tempfile::tempdir().expect("tmp");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca_cert.pem()).expect("ca pem");

        let endpoint = RemoteEndpoint {
            addr: format!("[::1]:{port}"),
            ca_pem: ca_path,
            cert_pem: None,
            key_pem: None,
        };
        let mut client = BrokerClient::connect_remote(&endpoint)
            .await
            .expect("connect via bracketed ipv6 literal");
        let version = client.ping().await.expect("pong");
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }
}
