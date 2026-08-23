//! The four `vaultx.*` MCP tools (plan §26) over the brokered pipeline.
//!
//! Every tool executes against a live [`ToolContext`]: an opened project
//! facade, the broker endpoint, and the server-held session token. The
//! token never appears in any output; responses carry only sanitized
//! summaries. Policy denials are *results* (a denial is a valid
//! outcome), while transport/service failures map onto JSON-RPC errors.

use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde_json::{json, Map, Value};
use vaultx_broker_client::BrokerClient;
use vaultx_core::VaultxServices;
use vaultx_policy::HttpMethod;
use vaultx_types::CredentialRef;

use crate::jsonrpc::{INVALID_PARAMS, TOOL_FAILURE, UNKNOWN_CAPABILITY};

/// Protocol version announced by `initialize`.
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// Everything a tool call needs. Held for the lifetime of one serve
/// session; the raw session token lives here in memory only.
pub struct ToolContext<'a> {
    /// Opened project services.
    pub services: &'a VaultxServices,
    /// Broker IPC endpoint used by request tools.
    pub endpoint: PathBuf,
    /// Raw capability token minted at startup; never logged or echoed.
    pub session_token: String,
    /// Agent bare name backing the session (principal matching).
    pub agent_name: String,
}

/// Tool-level failure carrying its JSON-RPC error code.
#[derive(Debug)]
pub struct ToolError {
    /// JSON-RPC error code.
    pub code: i64,
    /// Secret-blind message.
    pub message: String,
}

impl ToolError {
    pub(crate) fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn invalid_params(message: &str) -> ToolError {
    ToolError::new(INVALID_PARAMS, message)
}

/// One entry of `tools/list`.
#[derive(Clone, Debug)]
pub struct ToolSpec {
    /// Stable tool name (`vaultx.…`).
    pub name: &'static str,
    /// Human-facing description.
    pub description: &'static str,
    /// JSON Schema for the arguments object.
    pub input_schema: Value,
}

impl ToolSpec {
    /// Wire shape expected by MCP clients.
    #[must_use]
    pub fn to_wire(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        })
    }
}

/// All advertised tools, in stable order.
#[must_use]
pub fn tool_specs() -> Vec<ToolSpec> {
    let http_request = json!({
        "type": "object",
        "properties": {
            "credential": {"type": "string", "description": "Logical credential reference"},
            "method": {"type": "string", "description": "Outbound HTTP method"},
            "url": {"type": "string"},
            "headers": {"type": "object", "additionalProperties": {"type": "string"}},
            "body": {"type": "string"}
        },
        "required": ["credential", "method", "url"],
        "additionalProperties": false
    });
    vec![
        ToolSpec {
            name: "vaultx.list_capabilities",
            description: "List policy capabilities visible to this session",
            input_schema: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        },
        ToolSpec {
            name: "vaultx.config_get",
            description: "Read one non-sensitive config value committed to the project",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Config variable name"}
                },
                "required": ["name"],
                "additionalProperties": false
            }),
        },
        ToolSpec {
            name: "vaultx.http_request",
            description:
                "Perform a policy-authorized outbound HTTP request through the local broker",
            input_schema: http_request.clone(),
        },
        ToolSpec {
            name: "vaultx.capability_request",
            description:
                "Invoke an installed policy-pack capability through the same authorization path",
            input_schema: json!({
                "type": "object",
                "properties": {
                    "capability": {"type": "string", "description": "Pack capability name"},
                    "params": http_request
                },
                "required": ["capability", "params"],
                "additionalProperties": false
            }),
        },
    ]
}

/// Dispatches one `tools/call` invocation.
///
/// # Errors
/// Returns a [`ToolError`] whose code is safe to forward as the JSON-RPC
/// error code; messages are secret-blind by construction.
pub async fn call_tool(
    ctx: &ToolContext<'_>,
    name: &str,
    arguments: &Value,
) -> Result<Value, ToolError> {
    let arguments = ensure_object(arguments)?;
    match name {
        "vaultx.list_capabilities" => list_capabilities(ctx),
        "vaultx.config_get" => config_get(ctx, &arguments),
        "vaultx.http_request" => http_request_tool(ctx, &arguments, None).await,
        "vaultx.capability_request" => capability_request(ctx, &arguments).await,
        other => Err(invalid_params(&format!("unknown tool `{other}`"))),
    }
}

fn ensure_object(arguments: &Value) -> Result<Value, ToolError> {
    match arguments {
        Value::Null => Ok(json!({})),
        Value::Object(_) => Ok(arguments.clone()),
        _ => Err(invalid_params("arguments must be an object")),
    }
}

fn arg_string<'a>(args: &'a Value, key: &str) -> Result<&'a str, ToolError> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_params(&format!("missing string argument `{key}`")))
}

/// Policies whose principal matches `agent:<bare-name>` are the
/// capabilities visible to this session.
fn list_capabilities(ctx: &ToolContext<'_>) -> Result<Value, ToolError> {
    let principal = format!("agent:{}", ctx.agent_name);
    let documents = ctx
        .services
        .policies()
        .load_policies()
        .map_err(|_| ToolError::new(TOOL_FAILURE, "policy load failed"))?;
    let capabilities: Vec<Value> = documents
        .iter()
        .filter(|doc| doc.principal.as_str() == principal)
        .map(|doc| json!({"name": doc.name.as_str()}))
        .collect();
    Ok(json!({ "capabilities": capabilities }))
}

fn config_get(ctx: &ToolContext<'_>, args: &Value) -> Result<Value, ToolError> {
    let name = arg_string(args, "name")?;
    // Failures stay generic so values (and near-miss names) never leak.
    ctx.services
        .config()
        .get_config(name)
        .map(|value| json!({ "value": value }))
        .map_err(|_| ToolError::new(TOOL_FAILURE, "config lookup failed"))
}

fn parse_http_method(raw: &str) -> Result<HttpMethod, ToolError> {
    match raw.to_ascii_uppercase().as_str() {
        "GET" => Ok(HttpMethod::GET),
        "POST" => Ok(HttpMethod::POST),
        "PUT" => Ok(HttpMethod::PUT),
        "PATCH" => Ok(HttpMethod::PATCH),
        "DELETE" => Ok(HttpMethod::DELETE),
        "HEAD" => Ok(HttpMethod::HEAD),
        "OPTIONS" => Ok(HttpMethod::OPTIONS),
        other => Err(invalid_params(&format!(
            "`{other}` is not a supported HTTP method"
        ))),
    }
}

fn header_pairs(args: &Value) -> Result<Vec<(String, String)>, ToolError> {
    let Some(Value::Object(map)) = args.get("headers") else {
        return Ok(Vec::new());
    };
    let mut pairs = Vec::with_capacity(map.len());
    for (name, value) in map {
        let Some(value) = value.as_str() else {
            return Err(invalid_params("header values must be strings"));
        };
        pairs.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    Ok(pairs)
}

async fn send_via_broker(
    ctx: &ToolContext<'_>,
    args: &Value,
    capability_hint: Option<&str>,
) -> Result<Value, ToolError> {
    let credential_raw = arg_string(args, "credential")?;
    let credential = CredentialRef::parse(credential_raw)
        .map_err(|_| invalid_params("invalid credential ref"))?;
    let method = parse_http_method(arg_string(args, "method")?)?;
    let url = arg_string(args, "url")?;
    let headers = header_pairs(args)?;
    let body = match args.get("body") {
        None | Some(Value::Null) => vaultx_broker::BrokerBody::None,
        Some(Value::String(text)) => vaultx_broker::BrokerBody::Bytes {
            data: text.as_bytes().to_vec(),
        },
        Some(_) => return Err(invalid_params("body must be a string")),
    };

    let request = vaultx_broker::BrokerRequest {
        protocol: vaultx_broker::PROTOCOL_VERSION,
        // Crosses the wire once inside the broker envelope only.
        session_token: ctx.session_token.clone(),
        credential,
        method,
        url: url.to_owned(),
        headers,
        body,
        capability_hint: capability_hint.map(str::to_owned),
    };

    let mut client = BrokerClient::connect(&ctx.endpoint)
        .await
        .map_err(broker_failure)?;
    let response = client.request(request).await.map_err(broker_failure)?;

    match response.decision {
        vaultx_broker::Decision::Allow => {
            let mut header_map = Map::with_capacity(response.headers.len());
            let mut content_type = None;
            for (name, value) in response.headers {
                if name.eq_ignore_ascii_case("content-type") && content_type.is_none() {
                    content_type.get_or_insert(value.clone());
                }
                header_map.insert(name, Value::String(value));
            }
            Ok(json!({
                "status": response.status,
                "headers": header_map,
                "body_b64":
                    base64::engine::general_purpose::STANDARD.encode(response.body),
                "content_type": content_type,
                "decision": "allow",
            }))
        }
        // A denial is a valid outcome, not an RPC failure.
        vaultx_broker::Decision::Deny { reason, policy } => Ok(json!({
            "decision": "deny",
            "reason": reason,
            "policy": policy,
        })),
    }
}

fn broker_failure(err: vaultx_broker_client::ClientError) -> ToolError {
    // ClientError strings are secret-blind (path/class diagnostics).
    ToolError::new(TOOL_FAILURE, err.to_string())
}

async fn http_request_tool(
    ctx: &ToolContext<'_>,
    args: &Value,
    capability_hint: Option<&str>,
) -> Result<Value, ToolError> {
    send_via_broker(ctx, args, capability_hint).await
}

/// Resolves `<capability>` against pack-derived policies named
/// `pack-<capability with '.' replaced by '_'>`; unknown capabilities are
/// refused before any network activity.
async fn capability_request(ctx: &ToolContext<'_>, args: &Value) -> Result<Value, ToolError> {
    let capability = arg_string(args, "capability")?;
    let expected_policy = format!("pack-{}", capability.replace('.', "_"));
    let documents = ctx
        .services
        .policies()
        .load_policies()
        .map_err(|_| ToolError::new(TOOL_FAILURE, "policy load failed"))?;
    if !documents
        .iter()
        .any(|doc| doc.name.as_str() == expected_policy)
    {
        return Err(ToolError::new(
            UNKNOWN_CAPABILITY,
            format!("unknown capability `{capability}`"),
        ));
    }
    let params = args
        .get("params")
        .ok_or_else(|| invalid_params("missing object argument `params`"))?;
    send_via_broker(ctx, &ensure_object(params)?, Some(capability)).await
}

/// Broker endpoint selection mirroring the CLI's default rules: explicit
/// override first, else `$XDG_RUNTIME_DIR/vaultx/local/broker.sock`
/// (unix) or the platform pipe name.
#[must_use]
pub fn resolve_endpoint(socket: Option<&Path>) -> PathBuf {
    match socket {
        Some(path) => path.to_path_buf(),
        None => default_socket_path(),
    }
}

#[cfg(unix)]
fn default_socket_path() -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let uid = unsafe { libc::getuid() };
            PathBuf::from("/tmp").join(format!("vaultx-{uid}"))
        });
    base.join("vaultx").join("local").join("broker.sock")
}

#[cfg(windows)]
fn default_socket_path() -> PathBuf {
    PathBuf::from(r"\\.\pipe\vaultx-local")
}
