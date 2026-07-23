//! InnerWarden agent-guard MCP inspecting proxy.
//!
//! A stdio man-in-the-middle that sits between an AI agent's MCP client and a
//! real MCP server, inspecting `tools/call` arguments and `tools/list` /
//! tool-result payloads for threats while passing all other traffic through
//! untouched. The decision logic is pure and synchronous (this module tree);
//! the async transport that pumps bytes is a thin layer added separately.
//!
//! Design posture: the default mode is advisory, a transparent pipe that only
//! alerts, so wiring this module in changes no existing behavior. Blocking
//! (guard / kill) is strictly opt-in.
//!
//! MCP over stdio is newline-delimited JSON-RPC 2.0: exactly one JSON object
//! per line (batching was removed in spec revision 2025-06-18). Pass-through
//! messages are forwarded as their original raw bytes and never re-serialized,
//! which is the only way to guarantee byte-fidelity; the typed envelope here
//! exists purely to route and inspect a message.

pub mod enforce;
pub mod jsonrpc;
pub mod router;
pub mod taint;
pub mod transport;
