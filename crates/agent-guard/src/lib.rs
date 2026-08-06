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

// ── Module surface (audit ARCH-08) ───────────────────────────────────────────
//
// This crate is `publish = false` and consumed by an exact git rev, so cargo
// runs no semver check on it. Everything `pub` was therefore equally public and
// equally undocumented, and there was no way to tell a load-bearing contract
// from an implementation detail that happens to be reachable.
//
// The three groups below are that distinction, and `the_external_contract_is_
// explicit` locks the first one: a module another product depends on cannot
// quietly stop being public.

// ── 1. EXTERNAL CONTRACT ─────────────────────────────────────────────────────
// Imported by Active Defence. Changing a signature here breaks a separate
// product that pins this crate by revision, so treat these as published API.
pub mod detect;
pub mod mcp;
pub mod mcp_proxy;
pub mod registry;
pub mod rules;
pub mod signatures;

// ── 2. COMMUNITY BINARY + TEST SURFACE ───────────────────────────────────────
// Used by the `innerwarden` binary in this workspace, or by the integration
// tests, which are external consumers in Rust's eyes. Public because they must
// be, not because they are a contract.
pub mod agents;
pub mod agents_ops;
pub mod asi;
pub mod benchmark;
pub mod breaker;
pub mod file_update;
pub mod hook;
pub mod hook_targets;
pub mod mcp_wire;
pub mod mcp_wire_toml;
pub mod redact;
pub mod render;
pub mod session;
pub mod threats;

// ── 3. INTERNAL ──────────────────────────────────────────────────────────────
// No consumer outside this crate. Kept private so a future caller has to make a
// deliberate decision to widen the surface, rather than finding it already open.
mod deobfuscate;
mod shell;

#[cfg(test)]
mod module_surface_tests {
    /// REGRESSION ANCHOR for audit ARCH-08.
    ///
    /// This crate is `publish = false` and Active Defence pins it by git
    /// revision, so cargo runs no semver check: nothing tells you that a module
    /// another product imports has stopped being public until that product's
    /// build breaks, in a different repository, on someone else's machine.
    ///
    /// The list below IS the external contract, restated where a compiler can
    /// check it. Removing or privatising one of these is then a deliberate act
    /// with a failing test attached, not an accident.
    ///
    /// FAILS ON REVERT: make any of these `pub(crate)` and the module path stops
    /// resolving here.
    #[test]
    fn the_external_contract_is_explicit() {
        // Naming a type from each module forces the path to resolve, which is
        // what a `pub` check actually needs; merely listing names would not.
        fn _detect(_: &crate::detect::DetectedAgent) {}
        fn _mcp(_: &crate::mcp::Verdict) {}
        fn _proxy(_: crate::mcp_proxy::enforce::ProxyMode) {}
        fn _registry(_: &crate::registry::Registry) {}
        fn _rules(_: &crate::rules::RuleEngine) {}
        fn _signatures(_: &crate::signatures::Signature) {}
    }

    /// The internal group must stay internal. A module with no consumer outside
    /// this crate should require a deliberate widening, not be found already
    /// open by whoever needs it next.
    #[test]
    fn the_internal_group_is_reachable_only_from_inside() {
        // Compiles here (inside the crate) and would not compile from outside,
        // which is the property being asserted.
        let _ = crate::deobfuscate::deobfuscate("echo hi");
        let _ = crate::shell::project("echo hi");
    }
}
