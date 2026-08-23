//! Stdio JSON-RPC server lifecycle (plan §26).
//!
//! On startup the server opens the project, resolves the agent identity,
//! and mints a fresh broker session whose raw token is held in memory
//! only — it backs every `vaultx.http_request` /
//! `vaultx.capability_request` tool call and is never logged or echoed.

use std::path::PathBuf;

use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use vaultx_broker::SessionStore as _;
use vaultx_core::VaultxServices;
use vaultx_types::EnvironmentId;

use crate::jsonrpc::{
    error_line, parse_line, success_line, IncomingRequest, ParsedLine, INVALID_PARAMS,
    METHOD_NOT_FOUND, PARSE_ERROR,
};
use crate::tools::{
    call_tool, resolve_endpoint, tool_specs, ToolContext, ToolError, MCP_PROTOCOL_VERSION,
};

/// Upper bound on one inbound line; anything larger is refused rather
/// than processed.
const MAX_LINE_BYTES: usize = 4 * 1024 * 1024;

/// Configuration for [`serve`].
#[derive(Clone, Debug)]
pub struct ServeConfig {
    /// Project directory to operate on.
    pub project: PathBuf,
    /// Agent bare name owning the session.
    pub agent: String,
    /// Environment for the session (`development` when omitted).
    pub env: Option<String>,
    /// Broker endpoint override.
    pub socket: Option<PathBuf>,
}

/// Fatal server failures; messages are secret-blind.
#[derive(Debug, thiserror::Error)]
#[error("vaultx mcp: {0}")]
pub struct McpError(pub String);

fn startup_failure(message: impl std::fmt::Display) -> McpError {
    McpError(message.to_string())
}

/// Runs the server until stdin closes.
///
/// # Errors
/// Startup failures (unknown project/agent, session minting) and fatal
/// I/O errors surface as [`McpError`]. Per-line failures never stop the
/// loop; they are answered with JSON-RPC errors instead.
pub async fn serve(config: ServeConfig) -> Result<(), McpError> {
    let services = VaultxServices::open(&config.project).map_err(|err| startup_failure(&err))?;

    // Unknown or disabled agents must be caught before a session token
    // exists at all.
    let summary = services
        .agents()
        .list_agents()
        .map_err(startup_failure)?
        .into_iter()
        .find(|agent| agent.name == config.agent)
        .ok_or_else(|| startup_failure(format!("unknown agent `{}`", config.agent)))?;
    if !summary.enabled {
        return Err(startup_failure(format!(
            "agent `{}` is disabled",
            config.agent
        )));
    }
    let identity = services
        .agents()
        .inspect(&config.agent)
        .map_err(startup_failure)?;

    let store =
        vaultx_broker::FileSessionStore::open(services.context().vault_dir().join("sessions.json"))
            .map_err(startup_failure)?;
    let env_bare = config.env.as_deref().unwrap_or(crate::DEFAULT_ENV);
    let environment = EnvironmentId::parse(&format!("env_{env_bare}"))
        .map_err(|_| startup_failure("invalid environment name"))?;
    // The raw token lives only inside this call frame (and the context
    // below); it is never written anywhere.
    let (_session_id, token) = store
        .create_expiring(&identity.name, &environment, None)
        .map_err(startup_failure)?;

    let ctx = ToolContext {
        services: &services,
        endpoint: resolve_endpoint(config.socket.as_deref()),
        session_token: token,
        agent_name: config.agent.clone(),
    };

    let mut stdout = tokio::io::stdout();
    let mut stdin = BufReader::new(tokio::io::stdin());
    loop {
        let response = match read_line_bounded(&mut stdin).await {
            Ok(ReadOutcome::Eof) => return Ok(()),
            Ok(ReadOutcome::Oversize) => Some(error_line(
                &serde_json::Value::Null,
                PARSE_ERROR,
                "line too long",
            )),
            Ok(ReadOutcome::Line(line)) => handle_line(&ctx, &line).await,
            Err(err) => return Err(McpError(err.to_string())),
        };
        if let Some(response) = response {
            // A dead stdout pipe means the client is gone; nothing is
            // left to answer, so shut the session down cleanly.
            if write_response(&mut stdout, response).await.is_err() {
                return Ok(());
            }
        }
    }
}

/// Result of one bounded line read.
enum ReadOutcome {
    /// Clean end of input.
    Eof,
    /// One line whose terminating newline was consumed.
    Line(String),
    /// The line exceeded [`MAX_LINE_BYTES`] before any newline.
    Oversize,
}

/// Reads one newline-terminated line while enforcing [`MAX_LINE_BYTES`]
/// *during* accumulation: once the cap is reached without a newline,
/// buffering stops and the reader drains (without storing bytes) until
/// the next real newline, so oversized lines can never grow memory
/// unboundedly and following lines still parse.
async fn read_line_bounded<R>(reader: &mut R) -> std::io::Result<ReadOutcome>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    let mut oversize = false;
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(if oversize {
                ReadOutcome::Oversize
            } else if line.is_empty() {
                ReadOutcome::Eof
            } else {
                ReadOutcome::Line(String::from_utf8_lossy(&line).into_owned())
            });
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let take = match newline {
            Some(pos) => pos + 1,
            None => chunk.len(),
        };
        if !oversize && line.len() + take > MAX_LINE_BYTES {
            oversize = true;
            line.clear();
        }
        if !oversize {
            line.extend_from_slice(&chunk[..take]);
        }
        let terminated = newline.is_some();
        reader.consume(take);
        if terminated {
            return Ok(if oversize {
                ReadOutcome::Oversize
            } else {
                ReadOutcome::Line(String::from_utf8_lossy(&line).into_owned())
            });
        }
    }
}

async fn write_response(stdout: &mut tokio::io::Stdout, line: String) -> std::io::Result<()> {
    stdout.write_all(line.as_bytes()).await?;
    stdout.write_all(b"\n").await?;
    stdout.flush().await
}

/// Handles one inbound line, returning the response line to emit (or
/// `None` for notifications, blank input, and anything else that owes no
/// response). Crate-visible so protocol tests can drive it directly.
pub(crate) async fn handle_line(ctx: &ToolContext<'_>, line: &str) -> Option<String> {
    match parse_line(line) {
        ParsedLine::Blank => None,
        ParsedLine::Malformed => Some(error_line(
            &serde_json::Value::Null,
            PARSE_ERROR,
            "parse error",
        )),
        ParsedLine::Request(ref request) if request.is_notification() => None,
        ParsedLine::Request(request) => Some(handle_request(ctx, request).await),
    }
}

async fn handle_request(ctx: &ToolContext<'_>, request: IncomingRequest) -> String {
    let id = request.id.unwrap_or(serde_json::Value::Null);
    let outcome = match request.method.as_str() {
        "initialize" => Ok(serde_json::json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "vaultx", "version": env!("CARGO_PKG_VERSION")},
        })),
        "tools/list" => Ok(serde_json::json!({
            "tools": tool_specs()
                .iter()
                .map(crate::tools::ToolSpec::to_wire)
                .collect::<Vec<_>>(),
        })),
        "tools/call" => {
            let name = request
                .params
                .get("name")
                .and_then(serde_json::Value::as_str);
            let arguments = request
                .params
                .get("arguments")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            match name {
                Some(name) => call_tool(ctx, name, &arguments).await,
                None => Err(ToolError::new(
                    INVALID_PARAMS,
                    "missing string argument `name`",
                )),
            }
        }
        other => Err(ToolError::new(
            METHOD_NOT_FOUND,
            format!("unknown method `{other}`"),
        )),
    };
    match outcome {
        Ok(result) => success_line(&id, result),
        Err(err) => error_line(&id, err.code, &err.message),
    }
}
