//! MCP server lifecycle, agent session binding, and structured broker
//! tools (plan §26). Must not expose brokered secret plaintext.
//!
//! The server speaks line-delimited JSON-RPC 2.0 over stdin/stdout:
//! [`serve`] mints one broker session for `--agent` (token held in
//! memory only), answers `initialize`, `tools/list`, and `tools/call`,
//! and routes the four `vaultx.*` tools through the brokered pipeline so
//! no tool ever sees credential material.
//!
//! Layout: [`jsonrpc`] holds framing, [`tools`] the tool surface, and
//! this module the serve loop.

pub mod jsonrpc;
pub mod server;
pub mod tools;

/// Bare environment used for sessions when none is given.
pub const DEFAULT_ENV: &str = "development";

pub use jsonrpc::IncomingRequest;
pub use server::{serve, McpError, ServeConfig};
pub use tools::{
    call_tool, resolve_endpoint, tool_specs, ToolContext, ToolError, MCP_PROTOCOL_VERSION,
};

#[cfg(test)]
mod tests;
