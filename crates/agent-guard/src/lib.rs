//! InnerWarden Agent Guard, AI agent protection module.
//!
//! Detects AI agents/tools/runtimes on the host and screens their activity:
//! - Command/argument/response scanning for prompt injection, credential
//!   leaks, dangerous commands, and ATR rule matches (pattern/regex over the
//!   serialized payload). Exposed live via `/api/agent/check-command`.
//! - An inline **MCP inspecting proxy** ([`mcp_proxy`]): a stdio
//!   man-in-the-middle that wraps a real MCP server, parses each JSON-RPC
//!   message, and inspects `tools/call` arguments + `tools/list` / tool
//!   results. Modes: advisory (alert only, default), guard (block a disallowed
//!   `tools/call` with a denial), kill (block + terminate the server). Run it
//!   with `innerwarden agent proxy -- <server> [args]`.
//! - Session tracking (rate limiting, sensitive-file access, exfil chains).
//! - Process discovery via `/proc` scanning + MCP config-file discovery.
//!
//! The `check-command` API is advisory ("snitch"). The MCP proxy is advisory by
//! default but can enforce inline (guard/kill) when an operator opts in.
//!
//! Recognized agents/tools/runtimes (see [`signatures`]): Claude Code, Cursor,
//! Aider, Goose, OpenClaw, Codex CLI, Gemini CLI, Cline, Ollama, and more.

pub mod agents;
pub mod agents_ops;
pub mod asi;
pub mod benchmark;
pub mod breaker;
pub mod deobfuscate;
pub mod detect;
pub mod file_update;
pub mod hook;
pub mod mcp;
pub mod mcp_proxy;
pub mod mcp_wire;
pub mod mcp_wire_toml;
pub mod redact;
pub mod registry;
pub mod render;
pub mod rules;
pub mod session;
mod shell;
pub mod signatures;
pub mod threats;
