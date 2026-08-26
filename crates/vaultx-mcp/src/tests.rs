//! Protocol and tool-level tests: framing, tool shapes, config reads,
//! and brokered request paths against a spawned in-test mock broker.

use std::sync::Arc as StdArc;

use base64::Engine as _;
use serde_json::{json, Value};

use crate::jsonrpc::PARSE_ERROR;
use crate::server::handle_line;
use crate::tools::{call_tool, resolve_endpoint, ToolContext};
use vaultx_broker::{
    BrokerRequest, BrokerResponse, BrokerServer, Decision, EngineHandle, RequestId, ServerConfig,
};
use vaultx_core::{SecretString, VaultxServices};
use vaultx_policy::HttpMethod;
use vaultx_types::VariableKind;

struct MockEngine {
    allow_paths: &'static str,
}

impl EngineHandle for MockEngine {
    fn execute(&self, request: BrokerRequest) -> BrokerResponse {
        let request_id = RequestId::generate().unwrap();
        let allowed = request.method == HttpMethod::GET
            && request.url.starts_with("https://api.github.com/")
            && request.url.contains(self.allow_paths);
        if allowed {
            BrokerResponse {
                request_id,
                status: 200,
                headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                body: b"{\"ok\":true}".to_vec(),
                decision: Decision::Allow,
            }
        } else {
            BrokerResponse::denied(request_id, "no_matching_allow", Some("deny-all".to_owned()))
        }
    }
}

/// Spawns a mock broker on a tempdir socket; the tempdir guard is leaked
/// so the socket outlives the test body.
async fn spawn_mock_broker() -> std::path::PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broker.sock");
    let server = BrokerServer::<MockEngine>::bind(
        StdArc::new(MockEngine {
            allow_paths: "/test",
        }),
        "proj-mcp-test",
        ServerConfig {
            socket_path: Some(path.clone()),
            max_connections: 0,
            endpoint: None,
        },
    )
    .unwrap();
    let bound = server.path().to_path_buf();
    std::mem::forget(dir);
    tokio::spawn(async move {
        let _ = server.serve().await;
    });
    for _ in 0..100 {
        if bound.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    bound
}

fn ctx<'a>(services: &'a VaultxServices, endpoint: &std::path::Path) -> ToolContext<'a> {
    ToolContext {
        services,
        endpoint: endpoint.to_path_buf(),
        session_token: "0123456789abcdef0123456789abcdef".to_owned(),
        agent_name: "coding-agent".to_owned(),
    }
}

async fn rpc(ctx: &ToolContext<'_>, line: String) -> Value {
    let response = handle_line(ctx, &line).await.expect("response emitted");
    serde_json::from_str(&response).expect("valid response JSON")
}

#[tokio::test]
async fn initialize_and_tools_list_have_contract_shape() {
    let services = VaultxServices::init(tempdir_root().path()).unwrap();
    let context = ctx(&services, &resolve_endpoint(None));

    let init = rpc(
        &context,
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}).to_string(),
    )
    .await;
    assert_eq!(init["id"], 1);
    assert_eq!(init["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(init["result"]["capabilities"]["tools"], json!({}));
    assert_eq!(init["result"]["serverInfo"]["name"], "vaultx");
    assert_eq!(
        init["result"]["serverInfo"]["version"],
        env!("CARGO_PKG_VERSION")
    );

    let listed = rpc(
        &context,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}).to_string(),
    )
    .await;
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 4);
    for tool in tools {
        assert!(tool["name"].as_str().unwrap().starts_with("vaultx."));
        assert!(!tool["description"].as_str().unwrap().is_empty());
        assert_eq!(tool["inputSchema"]["type"], "object");
    }
}

#[tokio::test]
async fn unknown_method_parse_error_and_notification_framing() {
    let services = VaultxServices::init(tempdir_root().path()).unwrap();
    let context = ctx(&services, &resolve_endpoint(None));

    let err = rpc(
        &context,
        json!({"jsonrpc":"2.0","id":9,"method":"no/such/method"}).to_string(),
    )
    .await;
    assert_eq!(err["error"]["code"], -32601);
    assert!(err["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unknown method"));

    // Malformed JSON: parse error with null id.
    let err =
        serde_json::from_str::<Value>(&handle_line(&context, "{not json").await.unwrap()).unwrap();
    assert_eq!(err["error"]["code"], PARSE_ERROR);
    assert_eq!(err["id"], Value::Null);

    // Notifications produce no output at all.
    let notification = json!({"jsonrpc":"2.0","method":"notifications/initialized"}).to_string();
    assert!(handle_line(&context, &notification).await.is_none());
}

fn tempdir_root() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

#[tokio::test]
async fn config_get_returns_committed_or_staged_value_and_safe_failure() {
    let dir = tempdir_root();
    let root = dir.path();
    let services = VaultxServices::init(root).unwrap();
    services
        .config()
        .set_config("DB_HOST", "db.internal")
        .unwrap();
    let context = ctx(&services, &resolve_endpoint(None));

    let ok = call_tool(&context, "vaultx.config_get", &json!({"name": "DB_HOST"}))
        .await
        .unwrap();
    assert_eq!(ok["value"], "db.internal");

    // Unknown variable: -32000 with a message that carries neither the
    // name nor any value.
    let err = call_tool(
        &context,
        "vaultx.config_get",
        &json!({"name": "MISSING_VAR"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, -32000);
    assert_eq!(err.message, "config lookup failed");

    // Unknown tool names are invalid params.
    let err = call_tool(&context, "vaultx.nothing", &json!({}))
        .await
        .unwrap_err();
    assert_eq!(err.code, -32602);
}

#[tokio::test]
async fn http_request_allow_and_deny_flow_through_spawned_broker() {
    let dir = tempdir_root();
    let services = VaultxServices::init(dir.path()).unwrap();
    let endpoint = spawn_mock_broker().await;
    let context = ctx(&services, &endpoint);

    let ok = call_tool(
        &context,
        "vaultx.http_request",
        &json!({
            "credential": "github-work-token",
            "method": "GET",
            "url": "https://api.github.com/test/thing",
            "headers": {"Accept": "application/json"}
        }),
    )
    .await
    .unwrap();
    assert_eq!(ok["decision"], "allow");
    assert_eq!(ok["status"], 200);
    assert_eq!(ok["content_type"], "application/json");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(ok["body_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, b"{\"ok\":true}");

    let denied = call_tool(
        &context,
        "vaultx.http_request",
        &json!({
            "credential": "github-work-token",
            "method": "GET",
            "url": "https://evil.example/test"
        }),
    )
    .await
    .unwrap();
    assert_eq!(denied["decision"], "deny");
    assert_eq!(denied["reason"], "no_matching_allow");
    assert_eq!(denied["policy"], "deny-all");

    // Transport failure (nothing listening): -32000.
    let missing = tempfile::tempdir().unwrap();
    let dead = ctx(&services, &missing.path().join("none.sock"));
    let err = call_tool(
        &dead,
        "vaultx.http_request",
        &json!({
            "credential": "c",
            "method": "GET",
            "url": "https://api.github.com/test"
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, -32000);
}

#[tokio::test]
async fn capability_request_requires_installed_pack_policy() {
    let dir = tempdir_root();
    let root = dir.path();
    let services = VaultxServices::init(root).unwrap();

    let context = ctx(&services, &resolve_endpoint(None));
    let err = call_tool(
        &context,
        "vaultx.capability_request",
        &json!({
            "capability": "test.cap.call",
            "params": {
                "credential": "github-work-token",
                "method": "GET",
                "url": "https://api.github.com/test"
            }
        }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, -32001);
    assert!(err.message.contains("unknown capability"), "{err:?}");

    // Install the pack-derived policy the naming convention expects:
    // pack-<capability with '.' replaced by '_'>.
    let yaml = "\
name: pack-test_cap_call
principal: agent:coding-agent
credential: github-work-token
environment:
  allow: [env_development]
http:
  hosts: [api.github.com]
  allow:
    - methods: [GET]
      paths: [/test/**]
request:
  max_body_bytes: 262144
";
    services
        .policies()
        .save_policy_yaml("pack-test_cap_call", yaml)
        .unwrap();

    // list_capabilities now surfaces it for this agent's principal.
    let capabilities = call_tool(&context, "vaultx.list_capabilities", &json!({}))
        .await
        .unwrap();
    assert_eq!(
        capabilities["capabilities"],
        json!([{"name": "pack-test_cap_call"}])
    );

    // And the capability forwards through the broker like http_request.
    let endpoint = spawn_mock_broker().await;
    let context = ctx(&services, &endpoint);
    let ok = call_tool(
        &context,
        "vaultx.capability_request",
        &json!({
            "capability": "test.cap.call",
            "params": {
                "credential": "github-work-token",
                "method": "GET",
                "url": "https://api.github.com/test/run"
            }
        }),
    )
    .await
    .unwrap();
    assert_eq!(ok["decision"], "allow");
}

#[tokio::test]
async fn list_capabilities_filters_by_agent_principal() {
    let dir = tempdir_root();
    let root = dir.path();
    let services = VaultxServices::init(root).unwrap();

    let mine = "\
name: agent-mine
principal: agent:me
credential: c-one
http:
  hosts: [a.example.com]
  allow:
    - methods: [GET]
      paths: [/**]
";
    let theirs = "\
name: agent-other
principal: agent:someone-else
credential: c-two
http:
  hosts: [b.example.com]
  allow:
    - methods: [GET]
      paths: [/**]
";
    services
        .policies()
        .save_policy_yaml("agent-mine", mine)
        .unwrap();
    services
        .policies()
        .save_policy_yaml("agent-other", theirs)
        .unwrap();

    let mut context = ctx(&services, &resolve_endpoint(None));
    context.agent_name = "me".to_owned();
    let capabilities = call_tool(&context, "vaultx.list_capabilities", &json!({}))
        .await
        .unwrap();
    assert_eq!(
        capabilities["capabilities"],
        json!([{"name": "agent-mine"}])
    );
}

#[tokio::test]
async fn secrets_never_surface_through_any_tool_result() {
    let dir = tempdir_root();
    let root = dir.path();
    let services = VaultxServices::init(root).unwrap();
    services
        .secrets()
        .set_secret(
            "GITHUB_TOKEN",
            &SecretString::copy_from("canary-hunter2"),
            VariableKind::Secret,
            "development",
            None,
        )
        .unwrap();
    services.config().set_config("SAFE", "plain-value").unwrap();
    let context = ctx(&services, &resolve_endpoint(None));

    let ok = call_tool(&context, "vaultx.config_get", &json!({"name": "SAFE"}))
        .await
        .unwrap();
    let rendered = ok.to_string();
    assert!(!rendered.contains("canary-hunter2"));

    // Asking for the secret by name through config_get must fail with
    // the exact generic message — never a value, never a near-miss hint.
    let err = call_tool(
        &context,
        "vaultx.config_get",
        &json!({"name": "GITHUB_TOKEN"}),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, -32000);
    assert_eq!(err.message, "config lookup failed");

    // And no response body anywhere on the wire carries the canary VALUE.
    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
               "params":{"name":"vaultx.config_get","arguments":{"name":"GITHUB_TOKEN"}}}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
               "params":{"name":"vaultx.config_get","arguments":{"name":"SAFE"}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call",
               "params":{"name":"vaultx.list_capabilities"}}),
        json!({"jsonrpc":"2.0","id":5,"method":"no/such/method"}),
    ] {
        if let Some(response) = handle_line(&context, &request.to_string()).await {
            assert!(
                !response.contains("canary-hunter2"),
                "secret value surfaced in response: {response}"
            );
        }
    }

    // Blank lines stay silent even in this flow (framing regression).
    assert!(handle_line(&context, "").await.is_none());
    assert!(handle_line(&context, "   ").await.is_none());
}
