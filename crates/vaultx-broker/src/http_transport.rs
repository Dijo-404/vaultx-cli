//! Real outbound transport: reqwest over rustls with DNS pinning and
//! manual redirect authorization (plan §20).
//!
//! # Rebinding contract implementation
//!
//! For every hop (initial destination *and* each redirect target):
//!
//! 1. the canonical host is resolved through the configured
//!    [`DnsResolver`];
//! 2. every resolved address passes
//!    [`EgressGuard::recheck_resolved`] — metadata endpoints never
//!    connect even with private destinations enabled;
//! 3. the connection is **pinned** to a validated address via a fresh
//!    reqwest client built with `resolve(host, validated_addr)`, so the
//!    policy-approved destination and the wire destination coincide;
//! 4. redirects are followed manually (`Policy::none()` on reqwest):
//!    each `Location` goes through [`RedirectPolicy::evaluate`], whose
//!    authorizer approval is required before the next hop is dialed.
//!    Credentials ride along **only** on independently approved hops,
//!    satisfying INV-006/007 by construction (unauthorized targets are
//!    never contacted at all).
//!
//! # Performance note
//!
//! One reqwest client is built per attempt because TLS/SNI-correct IP
//! pinning in reqwest is a client-builder property. Latency cost is a
//! fresh TLS handshake per request; correctness outranks throughput for
//! a local security broker. Connection reuse may arrive with hyper-level
//! pooling later.
//!
//! # Blocking model
//!
//! [`HttpTransport`] owns a private current-thread tokio runtime and
//! implements the synchronous [`TransportExecutor`] seam on top of it,
//! so callers may invoke `execute` from any non-async thread (including
//! `spawn_blocking` workers, which is how the IPC server drives it).

use std::net::IpAddr;
use std::sync::Arc;

use vaultx_http::{
    CanonicalUrl, EgressGuard, RedirectAuthorizer, RedirectDecision, RedirectPolicy, SizeLimits,
};

use crate::error::BrokerError;
use crate::inject::OutboundRequest;
use crate::request::BrokerBody;
use crate::transport::{ExecutedResponse, TransportExecutor};

/// Status codes treated as redirects by the manual follow loop.
fn is_redirect(status: u16) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

/// Injectable DNS boundary. Production uses the OS resolver; tests pin
/// hosts to loopback so no packet leaves the machine.
pub trait DnsResolver: Send + Sync {
    /// Resolves `host:port` to candidate addresses.
    ///
    /// # Errors
    /// Resolution failures surface as `std::io::Error`.
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>>;
}

/// OS-resolver implementation.
#[derive(Debug, Default)]
pub struct SystemResolver;

impl DnsResolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<IpAddr>> {
        use std::net::ToSocketAddrs as _;
        Ok((host, port)
            .to_socket_addrs()?
            .map(|sock| sock.ip())
            .collect())
    }
}

/// Hardened outbound executor (plan §20 "hardened HTTP client").
pub struct HttpTransport {
    egress: EgressGuard,
    limits: SizeLimits,
    redirects: RedirectPolicy,
    redirect_authorizer: Arc<dyn RedirectAuthorizer>,
    resolver: Arc<dyn DnsResolver>,
    /// Deliberately never dropped: engine handles can outlive orderly
    /// teardown paths and land inside async workers, where dropping a
    /// runtime panics. A broker process keeps exactly one transport for
    /// its whole life, so leaking it costs nothing and removes the
    /// failure class entirely.
    runtime: std::mem::ManuallyDrop<tokio::runtime::Runtime>,
    /// Test-only relaxation of certificate verification; never set by
    /// production constructors.
    insecure_certs: bool,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("limits", &self.limits)
            .field("max_redirect_hops", &self.redirects)
            .finish_non_exhaustive()
    }
}

impl HttpTransport {
    /// Assembles a transport. Call inside a tokio context is **not**
    /// required; the transport owns its runtime.
    pub fn new(
        egress: EgressGuard,
        limits: SizeLimits,
        redirects: RedirectPolicy,
        redirect_authorizer: Arc<dyn RedirectAuthorizer>,
        resolver: Option<Arc<dyn DnsResolver>>,
    ) -> Result<Self, BrokerError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| {
                BrokerError::TransportFailure(format!("cannot start transport runtime: {err}"))
            })?;
        Ok(Self {
            runtime: std::mem::ManuallyDrop::new(runtime),
            egress,
            limits,
            redirects,
            redirect_authorizer,
            resolver: resolver.unwrap_or_else(|| Arc::new(SystemResolver)),
            insecure_certs: false,
        })
    }

    /// Test-only: skips upstream certificate verification so loopback
    /// TLS stubs with self-signed certs can terminate connections.
    #[doc(hidden)]
    #[must_use]
    pub fn allow_invalid_certs_for_tests(mut self) -> Self {
        self.insecure_certs = true;
        self
    }

    /// Validates every address the resolver produced for one hop and
    /// returns them; empty resolution is fatal here (the guard alone
    /// passes empty vacuously by contract).
    fn validate_resolution(&self, canonical: &CanonicalUrl) -> Result<Vec<IpAddr>, BrokerError> {
        let host = canonical.host();
        let port = canonical.port_or_default();
        let ips = self.resolver.resolve(host, port).map_err(|err| {
            BrokerError::TransportFailure(format!("destination resolution failed: {err}"))
        })?;
        if ips.is_empty() {
            return Err(BrokerError::TransportFailure(
                "destination resolved to no addresses".to_owned(),
            ));
        }
        self.egress.recheck_resolved(&ips).map_err(|err| {
            BrokerError::DestinationDenied(format!("resolved destination refused: {err}"))
        })?;
        Ok(ips)
    }

    /// Builds a one-shot client pinned to `addr`, SNI/TLS still keyed on
    /// the hostname.
    fn pinned_client(
        &self,
        canonical: &CanonicalUrl,
        addr: IpAddr,
    ) -> Result<reqwest::Client, BrokerError> {
        let host = canonical.host();
        let port = canonical.port_or_default();
        // reqwest keys DNS overrides on the bare hostname; the pinned
        // SocketAddr supplies the validated port.
        let key = host.to_owned();
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .resolve(&key, std::net::SocketAddr::new(addr, port))
            .use_rustls_tls()
            .no_proxy()
            // Bounded failure: a silent peer must never park a
            // spawn_blocking thread indefinitely.
            .connect_timeout(std::time::Duration::from_secs(10))
            .read_timeout(std::time::Duration::from_secs(30))
            .timeout(std::time::Duration::from_secs(60));
        if self.insecure_certs {
            builder = builder.danger_accept_invalid_certs(true);
        }
        builder
            .build()
            .map_err(|err| BrokerError::TransportFailure(format!("client build failed: {err}")))
    }

    /// Sends one exchange to `canonical`, trying each validated address
    /// in order.
    async fn send_once(
        &self,
        canonical: CanonicalUrl,
        method: vaultx_policy::HttpMethod,
        headers: Vec<(String, String)>,
        body: BrokerBody,
    ) -> Result<reqwest::Response, BrokerError> {
        let ips = self.validate_resolution(&canonical)?;
        let mut last_err: Option<BrokerError> = None;
        for ip in ips {
            let client = self.pinned_client(&canonical, ip)?;
            match self
                .dispatch(&client, &canonical, method, &headers, &body)
                .await
            {
                Ok(response) => return Ok(response),
                Err(err) => last_err = Some(err),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            BrokerError::TransportFailure("no validated address accepted the connection".to_owned())
        }))
    }

    /// Maps the authorized outbound shape onto reqwest and awaits the
    /// response head.
    async fn dispatch(
        &self,
        client: &reqwest::Client,
        canonical: &CanonicalUrl,
        method: vaultx_policy::HttpMethod,
        headers: &[(String, String)],
        body: &BrokerBody,
    ) -> Result<reqwest::Response, BrokerError> {
        let req_method = reqwest::Method::from_bytes(method.as_str().as_bytes())
            .map_err(|_| BrokerError::TransportFailure("unsupported method".to_owned()))?;
        let mut builder = client.request(req_method, canonical.as_url().as_str());
        for (name, value) in headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let payload: Option<Vec<u8>> = match body {
            BrokerBody::None => None,
            BrokerBody::Bytes { data } => Some(data.clone()),
            BrokerBody::Json { value } => Some(
                serde_json::to_vec(value)
                    .map_err(|err| BrokerError::InjectionError(format!("json body: {err}")))?,
            ),
        };
        if let Some(bytes) = &payload {
            if self.limits.check_request(bytes.len() as u64).is_err() {
                return Err(BrokerError::TransportFailure(
                    "request body exceeds permitted size".to_owned(),
                ));
            }
            builder = builder.body(bytes.clone());
        }
        builder.send().await.map_err(|err| {
            // Only the failure class survives: lower-level reqwest/hyper
            // chains can embed full URLs (query strings included), which
            // must never reach audit or diagnostics (INV-012).
            let class = if err.is_connect() {
                "connect"
            } else if err.is_timeout() {
                "timeout"
            } else if err.is_body() || err.is_decode() {
                "exchange"
            } else {
                "request"
            };
            BrokerError::TransportFailure(format!("exchange failed: {class}"))
        })
    }

    /// Reads the response body under the size ceiling.
    async fn read_capped(&self, response: &mut reqwest::Response) -> Result<Vec<u8>, BrokerError> {
        let cap = usize::try_from(self.limits.max_response_body_bytes).unwrap_or(usize::MAX);
        let mut out: Vec<u8> = Vec::with_capacity(cap.min(8192));
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| BrokerError::TransportFailure(format!("response read failed: {err}")))?
        {
            if out.len() + chunk.len() > cap {
                return Err(BrokerError::ResponseTooLarge);
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Runs the manual redirect-aware loop for one outbound request.
    async fn run(&self, outbound: OutboundRequest) -> Result<ExecutedResponse, BrokerError> {
        // Anchor for the redirect authorizer: always the INITIAL target,
        // never the previous hop, so chain approvals stay tied to what
        // the agent asked for (INV-007).
        let initial = outbound.canonical_url.clone();
        let mut canonical = outbound.canonical_url.clone();
        let mut method = outbound.method;
        let mut body = outbound.body.clone();
        let mut hop: u8 = 0;
        loop {
            let mut response = self
                .send_once(
                    canonical.clone(),
                    method,
                    outbound.headers.clone(),
                    body.clone(),
                )
                .await?;
            let status = response.status().as_u16();
            if !is_redirect(status) {
                let headers: Vec<(String, String)> = response
                    .headers()
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_ascii_lowercase(),
                            value.to_str().unwrap_or("").to_owned(),
                        )
                    })
                    .collect();
                let payload = self.read_capped(&mut response).await?;
                return Ok(ExecutedResponse {
                    status,
                    headers,
                    body: payload,
                });
            }

            // A redirect status without Location cannot be followed;
            // surface it as the final response rather than failing the
            // whole exchange.
            let Some(location_value) = response.headers().get(reqwest::header::LOCATION) else {
                let headers: Vec<(String, String)> = response
                    .headers()
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_ascii_lowercase(),
                            value.to_str().unwrap_or("").to_owned(),
                        )
                    })
                    .collect();
                let payload = self.read_capped(&mut response).await?;
                return Ok(ExecutedResponse {
                    status,
                    headers,
                    body: payload,
                });
            };
            let location = location_value.to_str().map_err(|_| {
                BrokerError::TransportFailure("redirect location is not valid text".to_owned())
            })?;
            // Contract: `original` is the INITIAL request target, not
            // the previous hop, so chained approvals stay anchored to
            // what the agent asked for.
            match self.redirects.evaluate(
                &initial,
                location,
                hop,
                self.redirect_authorizer.as_ref(),
            ) {
                RedirectDecision::Follow { new_target } => {
                    // 303 (and the de-facto behavior of 301/302) rewrite
                    // the verb to GET and drop the body; 307/308 keep both.
                    if status == 303 || status == 301 || status == 302 {
                        method = vaultx_policy::HttpMethod::GET;
                        body = BrokerBody::None;
                    }
                    canonical = new_target;
                    hop += 1;
                }
                RedirectDecision::Deny { reason } => {
                    // Reason strings quote only URLs policy already saw.
                    return Err(BrokerError::DestinationDenied(reason));
                }
            }
        }
    }
}

impl TransportExecutor for HttpTransport {
    fn execute(&self, outbound: &OutboundRequest) -> Result<ExecutedResponse, BrokerError> {
        self.runtime.block_on(self.run(outbound.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::BrokerBody;
    use std::collections::VecDeque;
    use std::net::{SocketAddr, TcpListener};
    use std::sync::{Arc, Mutex};

    const FAKE_HOST: &str = "api.transport-test.invalid";

    fn url(port: u16, path: &str) -> String {
        format!("https://{FAKE_HOST}:{port}{path}")
    }

    /// Loopback TLS stub speaking hand-rolled HTTPS responses; records
    /// each request path so redirect behavior is observable. Presents a
    /// self-signed certificate for `FAKE_HOST`; transports under test
    /// enable `allow_invalid_certs_for_tests`.
    struct StubServer {
        addr: SocketAddr,
        seen_paths: Arc<Mutex<Vec<String>>>,
        responses: Arc<Mutex<VecDeque<String>>>,
    }

    impl StubServer {
        fn start(responses: Vec<String>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
            let addr = listener.local_addr().expect("addr");
            let seen_paths = Arc::new(Mutex::new(Vec::new()));
            let queue: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(responses.into()));

            // Runtime-local TLS assets. rustls 0.23 requires an explicit
            // process-level crypto provider; installing is idempotent.
            let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
            let cert = rcgen::generate_simple_self_signed(vec![FAKE_HOST.to_owned()])
                .expect("self-signed cert");
            let cert_der = cert.cert.der().to_owned();
            let key_der = cert.key_pair.serialize_der();
            let mut server_config = tokio_rustls::rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert_der],
                    tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
                )
                .expect("tls server config");
            server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

            let paths = Arc::clone(&seen_paths);
            let worker_queue = Arc::clone(&queue);
            std::thread::spawn(move || {
                let queue = worker_queue;
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("stub runtime");
                runtime.block_on(async move {
                    listener
                        .set_nonblocking(true)
                        .expect("nonblocking listener");
                    let listener =
                        tokio::net::TcpListener::from_std(listener).expect("async listener");
                    loop {
                        let Ok((stream, _)) = listener.accept().await else {
                            break;
                        };
                        let response = queue
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .pop_front();
                        let Ok(mut tls_stream) = acceptor.accept(stream).await else {
                            continue;
                        };
                        if let Some(head) = read_head(&mut tls_stream).await {
                            let path = head.split_whitespace().nth(1).unwrap_or("?").to_owned();
                            paths
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(path);
                        }
                        match response {
                            Some(text) => {
                                if write_response(tls_stream, &text).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                });
            });
            Self {
                addr,
                seen_paths,
                responses: Arc::clone(&queue),
            }
        }

        fn paths(&self) -> Vec<String> {
            self.seen_paths
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    type StubStream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;

    /// Reads one request (head + declared body) before the stub answers.
    async fn read_head(stream: &mut StubStream) -> Option<String> {
        use tokio::io::AsyncReadExt as _;
        let mut buf = [0u8; 4096];
        let mut head = Vec::new();
        // Read until the blank line terminates the request head.
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            head.extend_from_slice(&buf[..n]);
        }
        let pos = head.windows(4).position(|w| w == b"\r\n\r\n")?;
        let text = String::from_utf8_lossy(&head[..pos]).into_owned();
        let declared: usize = text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().ok())?
            })
            .unwrap_or(0);
        // Drain a declared body so keep-alive framing stays sane.
        let mut remaining = declared.saturating_sub(head.len() - pos - 4);
        while remaining > 0 {
            let n = stream.read(&mut buf).await.ok()?;
            if n == 0 {
                break;
            }
            remaining -= n.min(remaining);
        }
        Some(text)
    }

    /// Writes a full raw HTTP/1.1 response and half-closes.
    async fn write_response(mut stream: StubStream, text: &str) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        stream.write_all(text.as_bytes()).await?;
        stream.flush().await?;
        stream.shutdown().await?;
        Ok(())
    }

    /// Resolver pinning `FAKE_HOST` at the stub's loopback address; any
    /// other host resolves to a *private* address so rebinding-style
    /// payloads are caught by the egress re-check.
    struct PinResolver {
        ok_ip: IpAddr,
    }

    impl DnsResolver for PinResolver {
        fn resolve(&self, host: &str, _port: u16) -> std::io::Result<Vec<IpAddr>> {
            if host == FAKE_HOST {
                Ok(vec![self.ok_ip])
            } else {
                Ok(vec!["10.9.8.7".parse().expect("private ip")])
            }
        }
    }

    struct ApproveSameOrigin;
    impl RedirectAuthorizer for ApproveSameOrigin {
        fn authorize_redirect(&self, original: &CanonicalUrl, next: &CanonicalUrl) -> bool {
            original.host() == next.host() && original.port_or_default() == next.port_or_default()
        }
    }

    struct DenyAll;
    impl RedirectAuthorizer for DenyAll {
        fn authorize_redirect(&self, _: &CanonicalUrl, _: &CanonicalUrl) -> bool {
            false
        }
    }

    fn outbound(addr: SocketAddr, path: &str) -> OutboundRequest {
        OutboundRequest {
            canonical_url: CanonicalUrl::parse(&url(addr.port(), path)).expect("canonical"),
            method: vaultx_policy::HttpMethod::GET,
            headers: vec![("authorization".to_owned(), "Bearer CANARY".to_owned())],
            body: BrokerBody::None,
        }
    }

    fn transport(stub: &StubServer, authorizer: Arc<dyn RedirectAuthorizer>) -> HttpTransport {
        HttpTransport::new(
            // Loopback destinations are legitimate inside tests; metadata
            // endpoints stay hard-denied regardless of this flag.
            EgressGuard::new(true),
            SizeLimits::default(),
            RedirectPolicy::new(5),
            authorizer,
            Some(Arc::new(PinResolver {
                ok_ip: stub.addr.ip(),
            })),
        )
        .expect("transport")
        .allow_invalid_certs_for_tests()
    }

    #[test]
    fn passthrough_returns_status_headers_and_body() {
        let stub = StubServer::start(vec![format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nset-cookie: sid=x; HttpOnly\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
        )]);
        let transport = transport(&stub, Arc::new(ApproveSameOrigin));
        let executed = transport.execute(&outbound(stub.addr, "/one")).expect("ok");
        assert_eq!(executed.status, 200);
        assert!(executed
            .headers
            .iter()
            .any(|(n, v)| n == "content-type" && v == "application/json"));
        assert_eq!(executed.body, b"hello");
        assert_eq!(stub.paths(), vec!["/one".to_owned()]);
    }

    #[test]
    fn same_origin_redirect_follows_and_reauthorizes() {
        let stub = StubServer::start(vec![
            "HTTP/1.1 302 Found\r\nlocation: /two\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                .to_owned(),
            "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok".to_owned(),
        ]);
        let transport = transport(&stub, Arc::new(ApproveSameOrigin));
        let executed = transport.execute(&outbound(stub.addr, "/one")).expect("ok");
        assert_eq!(executed.status, 200);
        assert_eq!(executed.body, b"ok");
        assert_eq!(stub.paths(), vec!["/one".to_owned(), "/two".to_owned()]);
    }

    #[test]
    fn cross_host_redirect_refused_without_contacting_target() {
        let stub = StubServer::start(vec![
            "HTTP/1.1 302 Found\r\nlocation: /steal\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                .to_owned(),
        ]);
        let transport = transport(&stub, Arc::new(DenyAll));
        let err = transport.execute(&outbound(stub.addr, "/one")).unwrap_err();
        assert!(
            matches!(&err, BrokerError::DestinationDenied(reason) if reason.contains("not authorized")),
            "{err:?}"
        );
        // Only the first hop was ever dialed.
        assert_eq!(stub.paths(), vec!["/one".to_owned()]);
    }

    #[test]
    fn redirect_downgrade_to_http_is_denied_by_canonicalization() {
        let stub = StubServer::start(vec![]);
        stub.responses
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push_back(format!(
                "HTTP/1.1 302 Found\r\nlocation: http://{FAKE_HOST}:{}/downgrade\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                stub.addr.port()
            ));
        let transport = transport(&stub, Arc::new(ApproveSameOrigin));
        let err = transport.execute(&outbound(stub.addr, "/one")).unwrap_err();
        assert!(matches!(err, BrokerError::DestinationDenied(_)), "{err:?}");
        assert_eq!(stub.paths(), vec!["/one".to_owned()]);
    }

    #[test]
    fn resolved_private_address_blocks_connection_before_dialing() {
        // The canonical host claims our fake public-ish name, but the
        // injected resolver returns loopback for it — the exact rebinding
        // payload shape.
        struct RebindingResolver;
        impl DnsResolver for RebindingResolver {
            fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<IpAddr>> {
                Ok(vec!["127.0.0.1".parse().expect("loopback")])
            }
        }
        let transport = HttpTransport::new(
            EgressGuard::new(false),
            SizeLimits::default(),
            RedirectPolicy::new(5),
            Arc::new(DenyAll),
            Some(Arc::new(RebindingResolver)),
        )
        .expect("transport");
        // Nothing is listening anywhere; the guard must refuse first.
        let target = outbound(SocketAddr::from(([127, 0, 0, 1], 9)), "/x");
        let err = transport.execute(&target).unwrap_err();
        assert!(
            matches!(&err, BrokerError::DestinationDenied(reason) if reason.contains("loopback")),
            "{err:?}"
        );
    }

    #[test]
    fn response_over_ceiling_aborts_with_response_too_large() {
        // Announce nothing; stream far more than the 1 MiB ceiling then
        // close. The transport must abort mid-read.
        let oversized_body =
            "x".repeat(SizeLimits::default().max_response_body_bytes as usize + 16);
        let stub = StubServer::start(vec![format!(
            "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n{oversized_body}",
        )]);
        let transport = transport(&stub, Arc::new(DenyAll));
        let err = transport.execute(&outbound(stub.addr, "/big")).unwrap_err();
        assert!(matches!(err, BrokerError::ResponseTooLarge), "{err:?}");
    }

    #[test]
    fn request_over_ceiling_never_leaves_the_process() {
        let stub = StubServer::start(vec!["HTTP/1.1 200 OK\r\n\r\n".to_owned()]);
        let transport = transport(&stub, Arc::new(DenyAll));
        let mut target = outbound(stub.addr, "/post");
        target.method = vaultx_policy::HttpMethod::POST;
        target.body = BrokerBody::Bytes {
            data: vec![0u8; SizeLimits::default().max_request_body_bytes as usize + 1],
        };
        let err = transport.execute(&target).unwrap_err();
        assert!(matches!(
            err,
            BrokerError::ResponseTooLarge | BrokerError::TransportFailure(_)
        ));
        // The size check happens pre-dial: no request reached the stub.
        assert!(stub.paths().is_empty());
    }
}
