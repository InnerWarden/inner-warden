# Changelog

All notable changes to InnerWarden are documented here. This project
follows semantic versioning.

## 1.0.7 - 2026-07-29

### Fixed

- **MCP response inspection no longer fails open.** The proxy scanned only
  `content[].type=="text"` blocks of a `tools/call` result, so a result carrying
  its payload anywhere else produced an empty string and passed as clean —
  silently bypassing indirect-prompt-injection detection. `structuredContent`
  (structured tool output, part of the current protocol revision) took exactly
  that path. The scan now covers text blocks, `structuredContent`, and any
  unrecognised non-empty result shape, bounded to 64 KiB and truncated on a char
  boundary. Deliberately shape-agnostic, so a new result field cannot reopen the
  same blind spot.

### Added

- **Guard events sink for a co-located host agent.** On a blocked or
  would-block decision (command or MCP tool call), the guard appends one compact
  JSON line to `guard-events.jsonl` next to the graph, so an InnerWarden host
  agent running on the same machine can ingest the guard's findings. Block-only,
  best-effort, and already redacted — a passing command adds no extra I/O, and a
  failure here can never alter a verdict or the hook exit code.

## 1.0.0 - 2026-07-23

First public InnerWarden release: the free, cross-OS guardrail for AI agents. Runs
on Linux, macOS, and Windows.

### Added

- Command screening: analyzes an AI agent's shell command before it runs and
  returns a verdict (allow, review, or deny).
- Tool-call screening: inspects MCP and tool calls and returns the same verdict.
- MCP proxy: a man-in-the-middle in front of an MCP server that inspects every
  JSON-RPC message and can refuse a disallowed tool call inline, keeping stdout
  pure MCP traffic.
- AI Jail: run an agent in a constrained profile so a screened-and-denied action
  is stopped rather than only flagged.
- Agent discovery: finds AI agents and agent tooling on the machine.
- Local dashboard: a read-only view on loopback at `http://127.0.0.1:8787` that
  never leaves the machine.
- Notifications: surfaces verdicts and events through configured channels.
- Claude Code integration via a PreToolUse hook, plus MCP-client support for
  Cursor, Codex, and other MCP clients.
