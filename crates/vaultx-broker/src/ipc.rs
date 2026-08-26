//! Local IPC transport for the broker process (plan §18 "Local endpoint",
//! §19 wire protocol) plus the remote TLS gateway (plan §30).
//!
//! One JSON line in → one JSON line out, over a Unix domain socket (or a
//! Windows named pipe), or over mutually-authenticated TLS on a TCP
//! listener for isolated deployments. The envelope types distinguish the
//! control channel ([`ClientLine::Ping`]) from brokered requests
//! ([`BrokerRequest`] reused verbatim as the request-line shape) and keep
//! responses tagged so protocol violations are reported instead of
//! crashing the server.
//!
//! # Trust boundary
//!
//! The socket directory is created `0700` and the socket file `0600`, so
//! on conventional systems only the owning user can connect. The server
//! performs **no** per-peer authentication beyond that file-system
//! boundary; session bearer tokens remain the per-request proof of agent
//! identity.
//!
//! # Remote/isolated gateway (plan §30 strict mode)
//!
//! [`BrokerEndpoint::RemoteTls`] serves the *same wire protocol* through
//! a rustls TLS listener so agents can reach a broker whose host holds
//! vault keys the agent machine does not:
//!
//! * **Workload identity** — when `client_ca_pem` is configured the
//!   handshake *requires* a client certificate signed by that CA;
//!   connections failing certificate verification never deliver a single
//!   protocol byte. The verified client cert is the workload identity;
//!   session tokens remain the per-request agent proof underneath it.
//! * **Replay protection** — enforced inside the engine pipeline for
//!   every transport (`replay_detected`, see `engine::REPLAY_TTL`).
//! * **Egress policy** — unchanged: the authorizer owns destination
//!   decisions exactly as locally (referenced, not rebuilt here).
//! * **No secret-returning API** — INV-002 by construction: the protocol
//!   surface is exactly [`ClientLine`] (ping | request) and [`ServerLine`]
//!   (pong | violation | response). There is no reveal, decrypt-at-rest,
//!   or administrative route anywhere in either enum, and no way to name
//!   one; the administrative reveal path exists only in the local CLI
//!   secret command, which shares no code path with this wire protocol.
//!   A serialization-scan regression test pins the response invariant.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

#[cfg(unix)]
use tokio::net::UnixListener;

use crate::error::BrokerError;
use crate::request::{BrokerRequest, BrokerResponse};

/// Maximum accepted line length (2 MiB): generous enough for the largest
/// permitted brokered payload, small enough that a hostile peer cannot
/// exhaust memory with one line.
pub const MAX_LINE_BYTES: usize = 2 * 1024 * 1024;

/// Default maximum concurrently served connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 16;

/// Upper bound on one TLS handshake (plan §30): a silent or
/// handshake-happy peer cannot pin an accept slot indefinitely. Timed-out
/// handshakes are dropped without any protocol byte being processed.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-read idle bound inside a served connection: a peer that sends
/// nothing for this long has its connection — and its concurrency slot —
/// released. Idle closes are silent (no violation line): silence is a
/// liveness failure, not a protocol violation.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on draining in-flight exchanges after shutdown; anything still
/// running when it expires is aborted by the task set's drop.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Wire envelopes
// ---------------------------------------------------------------------------

/// A single line sent by a client to the broker.
#[derive(Clone, Debug, PartialEq)]
// The request variant legitimately dwarfs the ping variant: boxing the
// payload would add an allocation to every brokered line for no benefit.
#[allow(clippy::large_enum_variant)]
pub enum ClientLine {
    /// Control ping (`{"protocol":1,"op":"ping"}`).
    Ping,
    /// One brokered HTTP request (plan §19 request shape).
    Request(BrokerRequest),
}

impl<'de> Deserialize<'de> for ServerLine {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        if value.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            let version = value
                .get("version")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| serde::de::Error::custom("pong missing version"))?
                .to_owned();
            return Ok(Self::Pong { ok: true, version });
        }
        if value.get("request_id").is_some() && value.get("decision").is_some() {
            let response = BrokerResponse::deserialize(value).map_err(serde::de::Error::custom)?;
            return Ok(Self::Response(response));
        }
        if value.get("error").is_some() {
            let error = value
                .get("error")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| serde::de::Error::custom("violation missing message"))?
                .to_owned();
            return Ok(Self::ProtocolViolation { error });
        }
        Err(serde::de::Error::custom("unrecognized server line shape"))
    }
}

impl<'de> Deserialize<'de> for ClientLine {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        if value.get("op").and_then(serde_json::Value::as_str) == Some("ping") {
            let protocol = value.get("protocol").and_then(serde_json::Value::as_u64);
            if protocol != Some(u64::from(crate::request::PROTOCOL_VERSION)) {
                return Err(serde::de::Error::custom(
                    "unsupported ping protocol version",
                ));
            }
            return Ok(Self::Ping);
        }
        let req = BrokerRequest::deserialize(value).map_err(serde::de::Error::custom)?;
        Ok(Self::Request(req))
    }
}

impl Serialize for ClientLine {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        match self {
            Self::Ping => {
                let mut s = serializer.serialize_struct("Ping", 2)?;
                s.serialize_field("protocol", &crate::request::PROTOCOL_VERSION)?;
                s.serialize_field("op", "ping")?;
                s.end()
            }
            Self::Request(req) => req.serialize(serializer),
        }
    }
}

/// A single line sent by the broker to a client.
#[derive(Clone, Debug, PartialEq)]
pub enum ServerLine {
    /// Reply to [`ClientLine::Ping`].
    Pong {
        /// Always `true`.
        ok: bool,
        /// Broker crate version.
        version: String,
    },
    /// The line could not be understood; the connection closes after this
    /// response because framing may already be lost.
    ProtocolViolation {
        /// Static description of the violation class.
        error: String,
    },
    /// Outcome of one brokered request.
    Response(BrokerResponse),
}

impl Serialize for ServerLine {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct as _;
        match self {
            Self::Pong { ok: _, version } => {
                let mut s = serializer.serialize_struct("Pong", 2)?;
                s.serialize_field("ok", &true)?;
                s.serialize_field("version", version)?;
                s.end()
            }
            Self::ProtocolViolation { error } => {
                let mut s = serializer.serialize_struct("ProtocolViolation", 1)?;
                s.serialize_field("error", error)?;
                s.end()
            }
            Self::Response(response) => response.serialize(serializer),
        }
    }
}

// ---------------------------------------------------------------------------
// Socket path resolution (plan §18)
// ---------------------------------------------------------------------------

/// Resolves the default bind path for `endpoint_id`:
/// `$XDG_RUNTIME_DIR/vaultx/<id>/broker.sock`, falling back to a
/// **uid-scoped** `/tmp` directory when the runtime dir is unset.
///
/// The fallback is `/tmp/vaultx-<uid>/<id>/broker.sock`, never the bare
/// shared `/tmp`: a world-writable parent would let an attacker
/// pre-create the tree, own it (0700 on their own dir constrains
/// nothing), and swap or harvest the socket. Scoping by uid keeps the
/// parent attacker-inaccessible from the first mkdir.
#[cfg(unix)]
#[must_use]
pub fn default_socket_path(endpoint_id: &str) -> PathBuf {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir)
            .join("vaultx")
            .join(endpoint_id)
            .join("broker.sock"),
        _ => {
            let uid = unsafe { libc::getuid() };
            PathBuf::from("/tmp")
                .join(format!("vaultx-{uid}"))
                .join(endpoint_id)
                .join("broker.sock")
        }
    }
}

/// Sanitizes an endpoint segment: lowercase alphanumerics and `-`
/// survive; everything else collapses to `-`. Prevents path traversal
/// through user-supplied project ids.
#[must_use]
fn sanitize_endpoint_segment(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

/// Windows named-pipe name for a project (`\\.\pipe\vaultx-<project>`).
#[cfg(windows)]
#[must_use]
pub fn default_pipe_name(project_id: &str) -> String {
    format!(
        "\\\\.\\pipe\\vaultx-{}",
        sanitize_endpoint_segment(project_id)
    )
}

// ---------------------------------------------------------------------------
// Engine handle + server
// ---------------------------------------------------------------------------

/// Async façade over the synchronous pipeline, injected into the server so
/// tests can substitute mock engines without building real dependencies.
pub trait EngineHandle: Send + Sync + 'static {
    /// Executes one brokered request through the full pipeline.
    fn execute(&self, request: BrokerRequest) -> BrokerResponse;
}

impl<T> EngineHandle for T
where
    T: crate::BrokerService + Send + Sync + 'static,
{
    fn execute(&self, request: BrokerRequest) -> BrokerResponse {
        crate::BrokerService::execute_broker_request(self, request)
    }
}

/// Endpoint selection for a broker server (plan §18 local IPC vs §30
/// remote TLS gateway).
#[derive(Clone, Debug)]
pub enum BrokerEndpoint {
    /// Unix domain socket at `path` (or the platform pipe name).
    LocalSocket(PathBuf),
    /// Remote TLS gateway bound on `bind` (plan §30). `client_ca_pem`,
    /// when present, makes client certificates **required** during the
    /// handshake — that certificate check *is* the workload identity.
    RemoteTls {
        /// TCP address to bind (`127.0.0.1:0` picks an ephemeral port).
        bind: SocketAddr,
        /// Server certificate chain, PEM encoded.
        cert_pem: PathBuf,
        /// Server private key, PEM encoded (PKCS#8 or SEC1).
        key_pem: PathBuf,
        /// CA whose signatures client certificates must carry. `None`
        /// serves server-only TLS (no client-auth requirement).
        client_ca_pem: Option<PathBuf>,
    },
}

/// Configuration knobs for [`BrokerServer`].
#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    /// Endpoint override; `None` uses [`default_socket_path`] (or the
    /// platform pipe name). Ignored when [`Self::endpoint`] selects a
    /// remote gateway.
    pub socket_path: Option<PathBuf>,
    /// Maximum concurrent connections (`0` selects the default).
    pub max_connections: usize,
    /// Explicit endpoint selection. `None` keeps the legacy local-socket
    /// resolution driven by [`Self::socket_path`].
    pub endpoint: Option<BrokerEndpoint>,
}

impl ServerConfig {
    fn effective_connections(&self) -> usize {
        if self.max_connections == 0 {
            DEFAULT_MAX_CONNECTIONS
        } else {
            self.max_connections
        }
    }

    /// Resolves the local socket path: an explicit endpoint wins, then
    /// the legacy `socket_path` override, then the default resolution.
    fn local_socket_path(&self, fallback: PathBuf) -> PathBuf {
        match &self.endpoint {
            Some(BrokerEndpoint::LocalSocket(path)) => path.clone(),
            _ => self.socket_path.clone().unwrap_or(fallback),
        }
    }
}

/// A bound, serving broker endpoint.
///
/// Unix implementation binds the plan's socket path or the plan §30 TLS
/// listener; the Windows named pipe compiles but returns a typed failure
/// until its serving loop lands (the rest of the workspace stays
/// cross-platform compilable).
pub struct BrokerServer<E: EngineHandle> {
    engine: Arc<E>,
    config: ServerConfig,
    shutdown_tx: watch::Sender<bool>,
    path: PathBuf,
    /// True for [`BrokerEndpoint::RemoteTls`] servers; controls exit
    /// cleanup (TCP endpoints must not attempt socket unlinking).
    remote: bool,
    #[cfg(unix)]
    listener: Option<UnixListener>,
    /// Present only for [`BrokerEndpoint::RemoteTls`] servers: the bound
    /// TCP listener plus its prepared TLS acceptor.
    #[cfg(unix)]
    tls_listener: Option<(tokio::net::TcpListener, Arc<tokio_rustls::TlsAcceptor>)>,
}

impl<E: EngineHandle> BrokerServer<E> {
    /// Binds the local endpoint and prepares the server. Call
    /// [`Self::serve`] to run the accept loop (usually inside
    /// `tokio::spawn`).
    ///
    /// Unix: creates parent directories `0700`, refuses to displace a
    /// **live** broker (probe-connect first), removes a stale socket,
    /// binds, then tightens the socket file itself to `0600`.
    ///
    /// # Errors
    /// [`BrokerError::TransportFailure`] when the endpoint cannot be
    /// created/bound, when another live broker owns it, or when a remote
    /// endpoint was requested (use [`Self::bind_remote`]).
    pub fn bind(
        engine: Arc<E>,
        project_endpoint_id: &str,
        config: ServerConfig,
    ) -> Result<Self, BrokerError> {
        if matches!(config.endpoint, Some(BrokerEndpoint::RemoteTls { .. })) {
            return Err(BrokerError::TransportFailure(
                "remote TLS endpoints require BrokerServer::bind_remote".to_owned(),
            ));
        }
        #[cfg(unix)]
        {
            let sanitized = sanitize_endpoint_segment(project_endpoint_id);
            let path = config.local_socket_path(default_socket_path(&sanitized));
            if let Some(parent) = path.parent() {
                create_private_dir(parent)?;
            }
            // A leftover file means a previous broker died without
            // cleanup — unless one is still serving. Probe-connect
            // decides: success proves liveness and we refuse rather than
            // silently stealing the endpoint.
            if path.exists() && std::os::unix::net::UnixStream::connect(&path).is_ok() {
                return Err(BrokerError::TransportFailure(
                    "broker endpoint already in use".to_owned(),
                ));
            }
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path).map_err(|err| {
                BrokerError::TransportFailure(format!(
                    "cannot bind broker endpoint {}: {err}",
                    path.display()
                ))
            })?;
            restrict_path_permissions(&path)?;
            Ok(Self {
                engine,
                config,
                shutdown_tx: watch::channel(false).0,
                path,
                listener: Some(listener),
                remote: false,
                tls_listener: None,
            })
        }
        #[cfg(windows)]
        {
            let _ = project_endpoint_id;
            Err(BrokerError::TransportFailure(
                "windows named-pipe endpoints are not implemented yet".to_owned(),
            ))
        }
    }

    /// Binds the remote TLS gateway (plan §30): loads the server
    /// certificate/key via `rustls-pemfile` and builds a rustls
    /// [`tokio_rustls::TlsAcceptor`]. When `client_ca_pem` is configured
    /// the handshake requires a client certificate signed by that CA —
    /// rejection happens before any protocol byte is processed.
    ///
    /// # Errors
    /// [`BrokerError::TransportFailure`] when files cannot be read or
    /// parsed, when rustls rejects the material, or on Windows (named
    /// pipes and remote gateways are both pending there).
    ///
    /// Must run inside a tokio runtime (the TCP listener binds through
    /// the reactor).
    pub async fn bind_remote(
        engine: Arc<E>,
        _project_endpoint_id: &str,
        config: ServerConfig,
    ) -> Result<Self, BrokerError> {
        let Some(BrokerEndpoint::RemoteTls {
            bind,
            cert_pem,
            key_pem,
            client_ca_pem,
        }) = config.endpoint.clone()
        else {
            return Err(BrokerError::TransportFailure(
                "bind_remote requires a RemoteTls endpoint".to_owned(),
            ));
        };
        #[cfg(unix)]
        {
            // rustls 0.23 requires an explicit process-level crypto
            // provider; installing is idempotent (see http_transport).
            let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
            let tls_config =
                build_tls_server_config(&cert_pem, &key_pem, client_ca_pem.as_deref())?;
            let acceptor = Arc::new(tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)));
            let listener = tokio::net::TcpListener::bind(bind).await.map_err(|err| {
                BrokerError::TransportFailure(format!("cannot bind gateway address {bind}: {err}"))
            })?;
            let shown = listener.local_addr().map_err(|err| {
                BrokerError::TransportFailure(format!(
                    "cannot inspect bound gateway address {bind}: {err}"
                ))
            })?;
            Ok(Self {
                engine,
                config,
                shutdown_tx: watch::channel(false).0,
                path: PathBuf::from(format!("tcp://{shown}")),
                listener: None,
                remote: true,
                tls_listener: Some((listener, acceptor)),
            })
        }
        #[cfg(windows)]
        {
            let _ = (bind, cert_pem, key_pem, project_endpoint_id);
            Err(BrokerError::TransportFailure(
                "remote TLS endpoints are not implemented yet".to_owned(),
            ))
        }
    }

    /// The bound endpoint path (socket path, pipe name, or the remote
    /// gateway's `tcp://ADDR:PORT` display form).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The concrete bound TCP address of a remote gateway.
    #[must_use]
    #[cfg(unix)]
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.tls_listener
            .as_ref()
            .and_then(|(listener, _)| listener.local_addr().ok())
    }

    /// Signals graceful shutdown; the accept loop exits promptly and
    /// then **drains** in-flight connection tasks for up to
    /// [`DRAIN_TIMEOUT`] (5 s) before returning — an exchange already
    /// inside the engine pipeline gets to finish; anything still pending
    /// is aborted with the drain's expiry.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Clonable shutdown trigger usable after `serve` has consumed the
    /// server (the CLI's signal handler needs exactly this).
    #[must_use]
    pub fn shutdown_trigger(&self) -> Arc<dyn Fn() + Send + Sync> {
        let tx = self.shutdown_tx.clone();
        Arc::new(move || {
            let _ = tx.send(true);
        })
    }

    /// Runs the accept loop until shutdown is signalled. Local sockets
    /// are removed on exit; TCP listeners simply close.
    ///
    /// # Errors
    /// Fatal accept failures surface as [`BrokerError::TransportFailure`]
    /// (transient per-connection errors — resets/aborts — are tolerated);
    /// everything else is contained to its own task.
    #[cfg(unix)]
    pub async fn serve(mut self) -> Result<(), BrokerError> {
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        // A trigger fired before this subscribe must still stop us:
        // borrow_and_update surfaces already-set values that `changed()`
        // alone would miss.
        if *shutdown_rx.borrow_and_update() {
            return self.cleanup_on_exit();
        }
        let live = Arc::new(LiveConnections::default());
        let mut connections = tokio::task::JoinSet::new();
        if let Some((tcp_listener, acceptor)) = self.tls_listener.take() {
            return self
                .serve_remote(
                    tcp_listener,
                    acceptor,
                    live,
                    &mut shutdown_rx,
                    &mut connections,
                )
                .await;
        }
        let Some(listener) = self.listener.take() else {
            return Err(BrokerError::TransportFailure(
                "server already consumed".to_owned(),
            ));
        };
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                accepted = listener.accept() => {
                    let (stream, _addr) = match accepted {
                        Ok(pair) => pair,
                        Err(err) if is_transient_accept_error(err.kind()) => continue,
                        Err(err) => {
                            return Err(BrokerError::TransportFailure(
                                format!("accept failed: {err}")
                            ));
                        }
                    };
                    let Some(slot) = live.try_acquire(self.config.effective_connections())
                    else {
                        // Refuse off the accept path: an inline drain
                        // would let a silent peer wedge both accepts and
                        // shutdown. The spawned task bounds its wait.
                        connections.spawn(async move {
                            refuse_connection(stream).await;
                        });
                        continue;
                    };
                    let engine = Arc::clone(&self.engine);
                    let mut conn_shutdown = shutdown_rx.clone();
                    // A fresh receiver may have missed the shutdown send;
                    // check the current value up front.
                    if *conn_shutdown.borrow_and_update() {
                        drop(slot);
                        drop(stream);
                        continue;
                    }
                    // `slot` is an RAII guard: its Drop releases the
                    // count even when the connection task panics.
                    connections.spawn(async move {
                        serve_connection(stream, engine, &mut conn_shutdown).await;
                        drop(slot);
                    });
                }
            }
        }
        drop(listener);
        drain_connections(connections).await;
        self.cleanup_on_exit()
    }

    /// Remote gateway accept loop (plan §30). Same slot accounting and
    /// shutdown semantics as the local loop; each accepted TCP stream is
    /// wrapped in TLS first, bounded by [`HANDSHAKE_TIMEOUT`].
    /// Handshake failures — including a missing or untrusted client
    /// certificate when `client_ca_pem` enforces mutual auth — are
    /// contained to their own task and never deliver a protocol byte.
    #[cfg(unix)]
    async fn serve_remote(
        self,
        listener: tokio::net::TcpListener,
        acceptor: Arc<tokio_rustls::TlsAcceptor>,
        live: Arc<LiveConnections>,
        shutdown_rx: &mut watch::Receiver<bool>,
        connections: &mut tokio::task::JoinSet<()>,
    ) -> Result<(), BrokerError> {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                accepted = listener.accept() => {
                    let (stream, _peer) = match accepted {
                        Ok(pair) => pair,
                        Err(err) if is_transient_accept_error(err.kind()) => continue,
                        Err(err) => {
                            return Err(BrokerError::TransportFailure(
                                format!("accept failed: {err}")
                            ));
                        }
                    };
                    // Over-limit peers are dropped without a drain
                    // exchange: pre-TLS plaintext replies cannot reach a
                    // client that has not completed a handshake.
                    let Some(slot) = live.try_acquire(self.config.effective_connections())
                    else {
                        drop(stream);
                        continue;
                    };
                    let engine = Arc::clone(&self.engine);
                    let mut conn_shutdown = shutdown_rx.clone();
                    if *conn_shutdown.borrow_and_update() {
                        drop(slot);
                        drop(stream);
                        continue;
                    }
                    let acceptor = Arc::clone(&acceptor);
                    connections.spawn(async move {
                        // A refused or stalled handshake (bad/absent
                        // client cert, hostile hello, silent peer) is
                        // contained here: no protocol request was ever
                        // seen, nothing to audit.
                        if let Ok(Ok(tls_stream)) =
                            tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream))
                                .await
                        {
                            serve_connection(tls_stream, engine, &mut conn_shutdown).await;
                        }
                        drop(slot);
                    });
                }
            }
        }
        drop(listener);
        drain_connections(std::mem::take(connections)).await;
        self.cleanup_on_exit()
    }

    /// Removes the local socket file on exit (TCP endpoints need no
    /// cleanup).
    #[cfg(unix)]
    fn cleanup_on_exit(&self) -> Result<(), BrokerError> {
        if !self.remote {
            let _ = std::fs::remove_file(&self.path);
        }
        Ok(())
    }

    /// Windows placeholder accept loop.
    #[cfg(windows)]
    pub async fn serve(self) -> Result<(), BrokerError> {
        Err(BrokerError::TransportFailure(
            "windows named-pipe serving is not implemented yet".to_owned(),
        ))
    }
}

/// Tracks live connections with RAII slots so panics cannot leak the
/// count and permanently wedge the limit at zero capacity.
#[derive(Default)]
struct LiveConnections {
    count: AtomicUsize,
}

impl LiveConnections {
    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    /// Atomically claims a slot when under `limit`; `None` at the soft
    /// cap. The compare-and-swap closes the benign TOCTOU between
    /// counting and claiming.
    fn try_acquire(self: &Arc<Self>, limit: usize) -> Option<ConnectionSlot> {
        let mut current = self.count();
        loop {
            if current >= limit {
                return None;
            }
            match self.count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Some(ConnectionSlot {
                        owner: Arc::clone(self),
                    })
                }
                Err(actual) => current = actual,
            }
        }
    }
}

struct ConnectionSlot {
    owner: Arc<LiveConnections>,
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.owner.count.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Bounded refusal exchange for over-limit peers: drain one pending line
/// (so our reply is not destroyed by an RST), answer, and close — all off
/// the accept path, all under a short timeout so silent peers cost
/// nothing.
async fn refuse_connection(mut stream: tokio::net::UnixStream) {
    // One drained line only; persistence is irrelevant here, but the
    // buffered type is required by [`read_line_capped`].
    let mut buffered = tokio::io::BufReader::with_capacity(1024, &mut stream);
    let drain = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        read_line_capped(&mut buffered),
    );
    let _ = drain.await;
    let line = ServerLine::ProtocolViolation {
        error: "connection limit reached".to_owned(),
    };
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        write_line(&mut stream, &line),
    );
    let _ = reply.await;
}

/// True for accept-loop errors that describe the *dying peer* rather than
/// the listener: resets/aborts during connection setup, interrupted
/// syscalls, and timeouts. The loop logs nothing and keeps serving;
/// anything else is fatal and surfaces to the caller.
fn is_transient_accept_error(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::TimedOut
    )
}

/// Drains in-flight connection tasks after the accept loop stops:
/// bounded by [`DRAIN_TIMEOUT`], after which remaining tasks are aborted
/// (a [`tokio::task::JoinSet`] aborts everything left on drop).
#[cfg(unix)]
async fn drain_connections(mut tasks: tokio::task::JoinSet<()>) {
    let deadline = tokio::time::sleep(DRAIN_TIMEOUT);
    tokio::pin!(deadline);
    while !tasks.is_empty() {
        tokio::select! {
            _ = &mut deadline => break,
            joined = tasks.join_next() => {
                if joined.is_none() {
                    break;
                }
            }
        }
    }
}

/// Creates `path` and every missing parent with `0700`.
#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<(), BrokerError> {
    std::fs::create_dir_all(path).map_err(|err| {
        BrokerError::TransportFailure(format!(
            "cannot create endpoint dir {}: {err}",
            path.display()
        ))
    })?;
    restrict_path_permissions(path)
}

/// Tightens `path` to owner-only permissions (`0700` / `0600` semantics:
/// the mode applied is `0700`; callers pass socket files too — the mask
/// keeps them owner-only either way).
#[cfg(unix)]
fn restrict_path_permissions(path: &Path) -> Result<(), BrokerError> {
    use std::os::unix::fs::PermissionsExt as _;
    // Socket files get 0600; directories 0700. Applying 0700 to a socket
    // would grant search bits that are meaningless on sockets, so pick by
    // kind.
    let mode = if path.is_dir() { 0o700 } else { 0o600 };
    let mut perms = std::fs::metadata(path)
        .map_err(|err| {
            BrokerError::TransportFailure(format!("cannot stat {}: {err}", path.display()))
        })?
        .permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms).map_err(|err| {
        BrokerError::TransportFailure(format!("cannot chmod {}: {err}", path.display()))
    })
}

/// Reads one newline-terminated JSON line with the hard length cap.
///
/// `reader` must be a **persistent** [`tokio::io::BufReader`] owned by
/// the connection loop: bytes buffered past this line's `\n` (pipelined
/// frames arriving in one segment) stay in its internal buffer and are
/// served by the next call. A per-call reader would silently drop them.
///
/// The cap is enforced during accumulation against CR-stripped content —
/// identical to the original byte loop: a line whose content exceeds
/// [`MAX_LINE_BYTES`] is a violation as soon as it happens, terminator
/// or not, so a hostile peer cannot park unbounded data in memory.
///
/// Returns `Ok(None)` on clean EOF before any byte of a new line; EOF
/// mid-line stays an error.
#[cfg(unix)]
async fn read_line_capped(
    reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
) -> Result<Option<Vec<u8>>, BrokerError> {
    use tokio::io::AsyncBufReadExt as _;

    let mut raw = Vec::with_capacity(512);
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|err| BrokerError::TransportFailure(format!("read failure: {err}")))?;
        if available.is_empty() {
            return if raw.is_empty() {
                Ok(None)
            } else {
                Err(BrokerError::TransportFailure(
                    "connection closed mid-line".to_owned(),
                ))
            };
        }
        let chunk_len = available.len();
        match available.iter().position(|byte| *byte == b'\n') {
            Some(end) => {
                append_non_cr(&mut raw, &available[..end]);
                // Bytes after `\n` remain buffered for the next call.
                reader.consume(end + 1);
                if raw.len() > MAX_LINE_BYTES {
                    return Err(BrokerError::TransportFailure(
                        "line exceeds maximum permitted size".to_owned(),
                    ));
                }
                return Ok(Some(raw));
            }
            None => {
                append_non_cr(&mut raw, available);
                reader.consume(chunk_len);
                if raw.len() > MAX_LINE_BYTES {
                    return Err(BrokerError::TransportFailure(
                        "line exceeds maximum permitted size".to_owned(),
                    ));
                }
            }
        }
    }
}

/// Appends `bytes` minus carriage returns — matching the original byte
/// loop, which dropped `\r` wherever it appeared.
fn append_non_cr(raw: &mut Vec<u8>, bytes: &[u8]) {
    raw.reserve(bytes.len());
    for &byte in bytes {
        if byte != b'\r' {
            raw.push(byte);
        }
    }
}

/// Serializes and writes one response line followed by `\n`.
async fn write_line(
    writer: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    line: &ServerLine,
) -> Result<(), BrokerError> {
    let mut encoded =
        serde_json::to_vec(line).map_err(|err| BrokerError::Serialization(err.to_string()))?;
    encoded.push(b'\n');
    writer
        .write_all(&encoded)
        .await
        .map_err(|err| BrokerError::TransportFailure(format!("write failure: {err}")))?;
    writer
        .flush()
        .await
        .map_err(|err| BrokerError::TransportFailure(format!("write failure: {err}")))?;
    Ok(())
}

/// Loads a rustls server configuration from PEM material. When
/// `client_ca_pem` is set, client authentication becomes **mandatory**
/// with the CA as sole trust anchor — that verified certificate is the
/// remote agent's workload identity (plan §30).
#[cfg(unix)]
fn build_tls_server_config(
    cert_pem: &Path,
    key_pem: &Path,
    client_ca_pem: Option<&Path>,
) -> Result<rustls::ServerConfig, BrokerError> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    fn read_certs(label: &str, path: &Path) -> Result<Vec<CertificateDer<'static>>, BrokerError> {
        // PemObject replaces the unmaintained rustls-pemfile crate.
        CertificateDer::pem_file_iter(path)
            .map_err(|err| {
                BrokerError::TransportFailure(format!(
                    "cannot read certificate file {label}: {err}"
                ))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                BrokerError::TransportFailure(format!(
                    "cannot parse certificates in {label}: {err}"
                ))
            })
    }

    let certs = read_certs("server certificate", cert_pem)?;
    if certs.is_empty() {
        return Err(BrokerError::TransportFailure(
            "server certificate file contains no certificates".to_owned(),
        ));
    }
    let key = PrivateKeyDer::from_pem_file(key_pem)
        .map_err(|err| BrokerError::TransportFailure(format!("cannot parse server key: {err}")))?;

    let builder = rustls::ServerConfig::builder();
    let config = match client_ca_pem {
        Some(ca_path) => {
            let ca_certs = read_certs("client CA", ca_path)?;
            if ca_certs.is_empty() {
                return Err(BrokerError::TransportFailure(
                    "client CA file contains no certificates".to_owned(),
                ));
            }
            let mut roots = rustls::RootCertStore::empty();
            for cert in ca_certs {
                roots.add(cert).map_err(|err| {
                    BrokerError::TransportFailure(format!("cannot trust client CA: {err}"))
                })?;
            }
            // Mandatory client authentication: handshakes without a
            // certificate chain this CA signed are rejected outright.
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|err| {
                    BrokerError::TransportFailure(format!(
                        "client certificate verifier rejected: {err}"
                    ))
                })?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
        }
        None => builder.with_no_client_auth().with_single_cert(certs, key),
    };
    config
        .map_err(|err| BrokerError::TransportFailure(format!("tls configuration rejected: {err}")))
}

/// Serves one connection: request/response pairs until EOF, shutdown, a
/// fatal framing violation, or the [`IDLE_TIMEOUT`] read bound. Engine
/// execution runs on the blocking pool so the synchronous pipeline never
/// stalls the async reactor. Generic over the byte stream so Unix sockets
/// and TLS-wrapped TCP share one handler.
#[cfg(unix)]
async fn serve_connection<E: EngineHandle, S>(
    stream: S,
    engine: Arc<E>,
    shutdown: &mut watch::Receiver<bool>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader_half, mut writer) = tokio::io::split(stream);
    // ONE persistent reader for the whole connection: frames buffered
    // past the current line's `\n` survive across loop iterations, so
    // pipelined lines arriving in a single segment are all served.
    let mut reader = tokio::io::BufReader::with_capacity(8192, reader_half);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            line = tokio::time::timeout(IDLE_TIMEOUT, read_line_capped(&mut reader)) => {
                match line {
                    Ok(Ok(Some(bytes))) => {
                        if !handle_line_bytes(&engine, bytes, &mut writer).await {
                            break;
                        }
                    }
                    // Idle close is silent by design: a silent peer will
                    // never read a diagnostic anyway.
                    Ok(Ok(None)) => break,
                    Ok(Err(err)) => {
                        let violation = ServerLine::ProtocolViolation {
                            error: err.to_string(),
                        };
                        let _ = write_line(&mut writer, &violation).await;
                        break;
                    }
                    Err(_elapsed) => break,
                }
            }
        }
    }
    let _ = writer.shutdown().await;
}

/// Parses and dispatches one client line. Returns `false` when the
/// connection must close.
#[cfg(unix)]
async fn handle_line_bytes<E: EngineHandle, W>(
    engine: &Arc<E>,
    bytes: Vec<u8>,
    writer: &mut W,
) -> bool
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let parsed: Result<ClientLine, _> = serde_json::from_slice(&bytes);
    match parsed {
        Ok(ClientLine::Ping) => {
            let pong = ServerLine::Pong {
                ok: true,
                version: env!("CARGO_PKG_VERSION").to_owned(),
            };
            matches!(write_line(writer, &pong).await, Ok(()))
        }
        Ok(ClientLine::Request(request)) => {
            // Session validation, authorization, injection, sanitization,
            // and audit all happen inside the engine pipeline so every
            // outcome — including denials — lands in the audit chain.
            let engine = Arc::clone(engine);
            let outcome = tokio::task::spawn_blocking(move || engine.execute(request)).await;
            let line = match outcome {
                Ok(response) => ServerLine::Response(response),
                Err(join_err) => ServerLine::ProtocolViolation {
                    error: format!("internal execution failure: {join_err}"),
                },
            };
            matches!(write_line(writer, &line).await, Ok(()))
        }
        Err(_) => {
            let violation = ServerLine::ProtocolViolation {
                error: "unrecognized request line".to_owned(),
            };
            let _ = write_line(writer, &violation).await;
            false
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::request::{BrokerBody, Decision, RequestId, PROTOCOL_VERSION};
    use std::sync::Arc as StdArc;
    use tokio::io::AsyncReadExt as _;
    use vaultx_policy::HttpMethod;
    use vaultx_types::CredentialRef;

    /// Minimal real engine wired like the engine tests' standard fixture.
    struct MockEngine;

    impl EngineHandle for MockEngine {
        fn execute(&self, request: BrokerRequest) -> BrokerResponse {
            // Deny everything except a GET to the fixture host; enough
            // to exercise both pipeline outcomes through the wire.
            let allowed = request.method == HttpMethod::GET
                && request.url.starts_with("https://api.github.com/");
            let request_id = RequestId::generate().unwrap();
            if allowed {
                BrokerResponse {
                    request_id,
                    status: 200,
                    headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
                    body: b"ok".to_vec(),
                    decision: Decision::Allow,
                }
            } else {
                BrokerResponse::denied(request_id, "no_matching_allow", None)
            }
        }
    }

    fn sample_token() -> String {
        "0123456789abcdef0123456789abcdef".to_owned()
    }

    fn broker_request(url: &str) -> BrokerRequest {
        BrokerRequest {
            protocol: PROTOCOL_VERSION,
            session_token: sample_token(),
            credential: CredentialRef::parse("github-work-token").unwrap(),
            method: HttpMethod::GET,
            url: url.to_owned(),
            headers: Vec::new(),
            body: BrokerBody::None,
            capability_hint: None,
            request_id: None,
        }
    }

    async fn spawn_server(
        dir: &Path,
        max_connections: usize,
    ) -> (tokio::task::JoinHandle<Result<(), BrokerError>>, PathBuf) {
        let path = dir.join("nested").join("broker.sock");
        let server = BrokerServer::<MockEngine>::bind(
            StdArc::new(MockEngine),
            "proj-test",
            ServerConfig {
                socket_path: Some(path.clone()),
                max_connections,
                endpoint: None,
            },
        )
        .expect("bind");
        let bound = server.path().to_path_buf();
        let handle = tokio::spawn(async move { server.serve().await });
        for _ in 0..100 {
            if bound.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        (handle, bound)
    }

    /// Writes one line and reads one newline-framed reply. The overall
    /// deadline is generous (5 s) so CI load slows nothing into flake
    /// territory; the framing means we return the instant the reply is
    /// complete rather than sleeping and hoping.
    async fn exchange_line(bound: &Path, line: &[u8]) -> String {
        let mut stream = tokio::net::UnixStream::connect(bound).await.unwrap();
        stream.write_all(line).await.unwrap();
        read_framed_reply(&mut stream).await
    }

    /// Reads bytes until the first `\n` or the deadline; returns the raw
    /// line text (newline stripped).
    async fn read_framed_reply(stream: &mut tokio::net::UnixStream) -> String {
        let mut byte = [0u8; 1];
        let mut buf = Vec::new();
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut byte))
                .await
            {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(_)) => {
                    if byte[0] == b'\n' {
                        break;
                    }
                    if byte[0] != b'\r' {
                        buf.push(byte[0]);
                    }
                }
                Ok(Err(_)) => break,
            }
        }
        String::from_utf8(buf).unwrap()
    }

    #[tokio::test]
    async fn request_round_trip_allow_and_deny_over_socket() {
        let dir = tempfile::tempdir().expect("tmp");
        let (_handle, bound) = spawn_server(dir.path(), 16).await;

        let request = serde_json::to_string(&broker_request("https://api.github.com/x"))
            .expect("encode")
            .into_bytes();
        let mut line = request;
        line.push(b'\n');
        let reply = exchange_line(&bound, &line).await;
        assert!(reply.contains("\"decision\":\"allow\""), "{reply}");
        assert!(reply.contains("\"status\":200"), "{reply}");

        let denied_request = serde_json::to_string(&broker_request("https://other.example/y"))
            .expect("encode")
            .into_bytes();
        let mut denied_line = denied_request;
        denied_line.push(b'\n');
        let reply = exchange_line(&bound, &denied_line).await;
        // `Decision` is externally tagged: deny replies nest the variant
        // object under the "deny" key.
        assert!(reply.contains("\"deny\""), "{reply}");
        assert!(reply.contains("no_matching_allow"), "{reply}");
    }

    #[tokio::test]
    async fn control_ping_answers_with_version_pong() {
        let dir = tempfile::tempdir().expect("tmp");
        let (_handle, bound) = spawn_server(dir.path(), 16).await;
        let reply = exchange_line(&bound, b"{\"protocol\":1,\"op\":\"ping\"}\n").await;
        assert!(reply.contains("\"ok\":true"), "{reply}");
    }

    #[tokio::test]
    async fn two_pipelined_lines_in_a_single_write_are_both_served() {
        // Legal under the line-framed protocol: one TCP/UDS segment
        // carrying two complete frames. The persistent per-connection
        // reader must serve both — a per-call reader loses the bytes
        // buffered past the first `\n` and the second line vanishes.
        let dir = tempfile::tempdir().expect("tmp");
        let (_handle, bound) = spawn_server(dir.path(), 16).await;
        let mut stream = tokio::net::UnixStream::connect(&bound).await.unwrap();

        let mut segment =
            serde_json::to_string(&broker_request("https://api.github.com/x")).unwrap();
        segment.push('\n');
        segment.push_str("{\"protocol\":1,\"op\":\"ping\"}\n");
        stream.write_all(segment.as_bytes()).await.unwrap();

        let first = read_framed_reply(&mut stream).await;
        assert!(first.contains("\"decision\":\"allow\""), "{first}");
        let second = read_framed_reply(&mut stream).await;
        assert!(second.contains("\"ok\":true"), "{second}");
    }

    #[tokio::test]
    async fn three_pipelined_pings_all_answered() {
        let dir = tempfile::tempdir().expect("tmp");
        let (_handle, bound) = spawn_server(dir.path(), 16).await;
        let mut stream = tokio::net::UnixStream::connect(&bound).await.unwrap();
        let segment: &[u8] = b"{\"protocol\":1,\"op\":\"ping\"}\n\
             {\"protocol\":1,\"op\":\"ping\"}\n\
             {\"protocol\":1,\"op\":\"ping\"}\n";
        stream.write_all(segment).await.unwrap();
        for _ in 0..3 {
            let reply = read_framed_reply(&mut stream).await;
            assert!(reply.contains("\"ok\":true"), "{reply}");
        }
    }

    #[tokio::test]
    async fn malformed_line_gets_violation_then_connection_closes_cleanly() {
        let dir = tempfile::tempdir().expect("tmp");
        let (_handle, bound) = spawn_server(dir.path(), 16).await;
        let mut stream = tokio::net::UnixStream::connect(&bound).await.unwrap();
        stream.write_all(b"this is not json\n").await.unwrap();
        let text = read_framed_reply(&mut stream).await;
        assert!(text.contains("\"error\""), "{text}");
    }

    #[tokio::test]
    async fn oversized_line_is_refused_without_crashing_server() {
        let dir = tempfile::tempdir().expect("tmp");
        let (_handle, bound) = spawn_server(dir.path(), 16).await;
        let mut stream = tokio::net::UnixStream::connect(&bound).await.unwrap();
        let huge = vec![b'a'; MAX_LINE_BYTES + 1];
        stream.write_all(&huge).await.unwrap();

        let text = read_framed_reply(&mut stream).await;
        assert!(text.contains("exceeds maximum permitted size"), "{text}");

        // The server survives and still answers pings.
        let reply = exchange_line(&bound, b"{\"protocol\":1,\"op\":\"ping\"}\n").await;
        assert!(reply.contains("\"ok\":true"), "{reply}");
    }

    #[tokio::test]
    async fn connection_limit_refuses_extra_peers_politely() {
        let dir = tempfile::tempdir().expect("tmp");
        let (_handle, bound) = spawn_server(dir.path(), 1).await;

        // The holder occupies the single slot. Synchronize on a completed
        // exchange instead of a sleep so the slot is guaranteed live.
        let mut holder = tokio::net::UnixStream::connect(&bound).await.unwrap();
        holder
            .write_all(b"{\"protocol\":1,\"op\":\"ping\"}\n")
            .await
            .unwrap();
        let pong = read_framed_reply(&mut holder).await;
        assert!(pong.contains("\"ok\":true"), "{pong}");

        // Second peer is refused (drained + violation line) even though
        // it stays silent afterwards.
        let mut second = tokio::net::UnixStream::connect(&bound).await.unwrap();
        second
            .write_all(b"{\"protocol\":1,\"op\":\"ping\"}\n")
            .await
            .unwrap();
        let text = read_framed_reply(&mut second).await;
        assert!(text.contains("connection limit"), "{text}");
    }

    #[tokio::test]
    async fn socket_permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("perm.sock");
        {
            let server = BrokerServer::<MockEngine>::bind(
                StdArc::new(MockEngine),
                "proj-perm",
                ServerConfig {
                    socket_path: Some(path.clone()),
                    max_connections: 0,
                    endpoint: None,
                },
            )
            .expect("bind");
            let mode = std::fs::metadata(server.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            // Nested parent dirs are private too.
            let parent_mode = std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(parent_mode & 0o777, 0o700);
        }
    }

    #[tokio::test]
    async fn stale_socket_is_replaced_but_live_broker_is_respected() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("live.sock");
        // Stale regular file (not a socket): probe-connect fails, so a
        // fresh broker may replace it.
        std::fs::write(&path, b"junk").unwrap();
        assert!(BrokerServer::<MockEngine>::bind(
            StdArc::new(MockEngine),
            "proj-live",
            ServerConfig {
                socket_path: Some(path.clone()),
                max_connections: 0,
                endpoint: None,
            },
        )
        .is_ok());
        drop(std::fs::remove_file(&path));

        // A genuinely live listener owns its endpoint: bind must refuse
        // rather than steal it.
        let live = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let result = BrokerServer::<MockEngine>::bind(
            StdArc::new(MockEngine),
            "proj-live",
            ServerConfig {
                socket_path: Some(path.clone()),
                max_connections: 0,
                endpoint: None,
            },
        );
        drop(live);
        assert!(result.is_err(), "must not displace a live broker");
    }

    #[test]
    fn endpoint_segment_sanitizes_traversal_attempts() {
        let segment = sanitize_endpoint_segment("../../etc/passwd");
        assert!(!segment.contains(".."));
        assert_eq!(segment, "------etc-passwd");
    }
}
