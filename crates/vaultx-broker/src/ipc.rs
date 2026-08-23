//! Local IPC transport for the broker process (plan §18 "Local endpoint",
//! §19 wire protocol).
//!
//! One JSON line in → one JSON line out, over a Unix domain socket (or a
//! Windows named pipe). The envelope types distinguish the control
//! channel ([`ClientLine::Ping`]) from brokered requests
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

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

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

// ---------------------------------------------------------------------------
// Wire envelopes
// ---------------------------------------------------------------------------

/// A single line sent by a client to the broker.
#[derive(Clone, Debug, PartialEq)]
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

/// Configuration knobs for [`BrokerServer`].
#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    /// Endpoint override; `None` uses [`default_socket_path`] (or the
    /// platform pipe name).
    pub socket_path: Option<PathBuf>,
    /// Maximum concurrent connections (`0` selects the default).
    pub max_connections: usize,
}

impl ServerConfig {
    fn effective_connections(&self) -> usize {
        if self.max_connections == 0 {
            DEFAULT_MAX_CONNECTIONS
        } else {
            self.max_connections
        }
    }
}

/// A bound, serving broker endpoint.
///
/// Unix implementation binds the plan's socket path; the Windows named
/// pipe compiles but returns a typed failure until its serving loop
/// lands (the rest of the workspace stays cross-platform compilable).
pub struct BrokerServer<E: EngineHandle> {
    engine: Arc<E>,
    config: ServerConfig,
    shutdown_tx: watch::Sender<bool>,
    path: PathBuf,
    #[cfg(unix)]
    listener: Option<UnixListener>,
}

impl<E: EngineHandle> BrokerServer<E> {
    /// Binds the endpoint and prepares the server. Call [`Self::serve`]
    /// to run the accept loop (usually inside `tokio::spawn`).
    ///
    /// Unix: creates parent directories `0700`, refuses to displace a
    /// **live** broker (probe-connect first), removes a stale socket,
    /// binds, then tightens the socket file itself to `0600`.
    ///
    /// # Errors
    /// [`BrokerError::TransportFailure`] when the endpoint cannot be
    /// created/bound, or when another live broker owns it.
    pub fn bind(
        engine: Arc<E>,
        project_endpoint_id: &str,
        config: ServerConfig,
    ) -> Result<Self, BrokerError> {
        #[cfg(unix)]
        {
            let sanitized = sanitize_endpoint_segment(project_endpoint_id);
            let path = config
                .socket_path
                .clone()
                .unwrap_or_else(|| default_socket_path(&sanitized));
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
                BrokerError::TransportFailure(format!("cannot bind broker endpoint: {err}"))
            })?;
            restrict_path_permissions(&path)?;
            Ok(Self {
                engine,
                config,
                shutdown_tx: watch::channel(false).0,
                path,
                listener: Some(listener),
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

    /// The bound endpoint path (socket path or pipe name).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Signals graceful shutdown; the accept loop exits promptly while
    /// in-flight connection tasks complete naturally.
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

    /// Runs the accept loop until shutdown is signalled. On Unix the
    /// socket file is removed on exit.
    ///
    /// # Errors
    /// Fatal accept failures surface as [`BrokerError::TransportFailure`];
    /// per-connection errors are contained to their own task.
    #[cfg(unix)]
    pub async fn serve(mut self) -> Result<(), BrokerError> {
        let Some(listener) = self.listener.take() else {
            return Err(BrokerError::TransportFailure(
                "server already consumed".to_owned(),
            ));
        };
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        // A trigger fired before this subscribe must still stop us:
        // borrow_and_update surfaces already-set values that `changed()`
        // alone would miss.
        if *shutdown_rx.borrow_and_update() {
            drop(listener);
            let _ = std::fs::remove_file(&self.path);
            return Ok(());
        }
        let live = Arc::new(LiveConnections::default());
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => break,
                accepted = listener.accept() => {
                    let (stream, _addr) = match accepted {
                        Ok(pair) => pair,
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
                        let mut conn_shutdown = shutdown_rx.clone();
                        tokio::spawn(async move {
                            refuse_connection(stream, &mut conn_shutdown).await;
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
                    tokio::spawn(async move {
                        serve_connection(stream, engine, &mut conn_shutdown).await;
                        drop(slot);
                    });
                }
            }
        }
        drop(listener);
        let _ = std::fs::remove_file(&self.path);
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
async fn refuse_connection(
    mut stream: tokio::net::UnixStream,
    shutdown: &mut watch::Receiver<bool>,
) {
    let drain = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        read_line_capped(&mut stream),
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
    // Keep the receiver alive to end of scope: a dropped clone that never
    // observed a send would be harmless, but holding it documents intent.
    let _ = shutdown.borrow();
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
/// Returns `Ok(None)` on clean EOF before any byte of a new line.
#[cfg(unix)]
async fn read_line_capped(
    reader: &mut (impl tokio::io::AsyncReadExt + Unpin),
) -> Result<Option<Vec<u8>>, BrokerError> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let read = reader
            .read(&mut byte)
            .await
            .map_err(|err| BrokerError::TransportFailure(format!("read failure: {err}")))?;
        if read == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err(BrokerError::TransportFailure(
                    "connection closed mid-line".to_owned(),
                ))
            };
        }
        match byte[0] {
            b'\n' => return Ok(Some(std::mem::take(&mut buf))),
            b'\r' => {}
            other => {
                buf.push(other);
                if buf.len() > MAX_LINE_BYTES {
                    return Err(BrokerError::TransportFailure(
                        "line exceeds maximum permitted size".to_owned(),
                    ));
                }
            }
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

/// Serves one connection: request/response pairs until EOF, shutdown, or
/// fatal framing violation. Engine execution runs on the blocking pool so
/// the synchronous pipeline never stalls the async reactor.
#[cfg(unix)]
async fn serve_connection<E: EngineHandle>(
    stream: tokio::net::UnixStream,
    engine: Arc<E>,
    shutdown: &mut watch::Receiver<bool>,
) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = reader;
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            line = read_line_capped(&mut reader) => {
                match line {
                    Ok(Some(bytes)) => {
                        if !handle_line_bytes(&engine, bytes, &mut writer).await {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        let violation = ServerLine::ProtocolViolation {
                            error: err.to_string(),
                        };
                        let _ = write_line(&mut writer, &violation).await;
                        break;
                    }
                }
            }
        }
    }
    let _ = writer.shutdown().await;
}

/// Parses and dispatches one client line. Returns `false` when the
/// connection must close.
#[cfg(unix)]
async fn handle_line_bytes<E: EngineHandle>(
    engine: &Arc<E>,
    bytes: Vec<u8>,
    writer: &mut (impl tokio::io::AsyncWriteExt + Unpin),
) -> bool {
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
