# InnerWarden

An open-source runtime guardrail for AI agents. InnerWarden screens what an AI
agent tries to do (shell commands and MCP/tool calls) before those actions run,
and returns a clear verdict: allow, review, or deny.

Binary: `innerwarden`. Linux and macOS are first-class; Windows is supported on
a best-effort, experimental basis. It runs right where a developer runs an AI
coding agent.

## The problem

AI agents no longer just suggest, they act. They run shell commands, call tools,
and reach out over MCP. When an agent is hijacked (prompt injection, tool
poisoning, a compromised skill), the agent's own process is the wrong place to
enforce safety: the thing you would ask to hold the line is the thing that has
already been turned. You need a guardrail that sits beside the agent and
inspects its intended actions independently, before they happen.

InnerWarden is that guardrail. It is advisory by default: it flags a dangerous
action and returns a verdict, and the enforcing forms (the MCP proxy and the
Claude Code hook) can refuse an action before it reaches its target.

## Quick install

macOS and Linux:

```sh
curl -fsSL https://innerwarden.com/free | sh
```

Windows (PowerShell):

```powershell
irm https://innerwarden.com/free.exe -OutFile innerwarden.exe
```

With Rust / cargo (any platform):

```sh
cargo install --git https://github.com/InnerWarden/inner-warden innerwarden
```

No account. The guard itself sends nothing off the machine. The `curl | sh`
installer sends one anonymous, opt-out install ping (version + OS + CPU arch
only — no IP, no host data; set `INNERWARDEN_NO_TELEMETRY=1` to disable). A
`cargo install` or from-source build sends nothing at all.

## What it does

- Screens shell commands and MCP/tool calls before they run, and returns a
  verdict: `allow`, `review`, or `deny` (advisory by default).
- Runs an MCP proxy: a man-in-the-middle in front of an MCP server that inspects
  every JSON-RPC message and can refuse a disallowed tool call inline. stdout
  stays pure MCP traffic, alerts go to stderr.
- AI Jail: run an agent in a constrained profile so a screened-and-denied action
  is stopped rather than merely flagged.
- Agent discovery: finds AI agents and agent tooling on the machine so you can
  see what is running and wire the guardrail into it.
- Local dashboard: a read-only view on loopback at `http://127.0.0.1:8787`. It
  never leaves the machine.
- Notifications: surfaces verdicts and events through your configured channels.

The verdict is JSON: a recommendation (`allow` / `review` / `deny`), a risk
score, matched signals, and a short explanation.

## Supported agents

Claude Code (via a PreToolUse hook installed by the guard), plus Cursor and
Codex (and any other MCP client) through the MCP proxy. Any agent with a
pre-execution wrapper can gate on the exit code: `innerwarden` exits non-zero on
a deny.

## Build from source

Requires a stable Rust toolchain.

```sh
cargo build --release
```

The binary is produced at `target/release/innerwarden`.

## Contributing

Contributions are welcome under Apache-2.0. See `CONTRIBUTING.md` for how to
build, test, and submit changes.

## License

Apache-2.0. See `LICENSE`.

InnerWarden also offers a commercial host-enforcement layer for Linux production
fleets (kernel-level enforcement, host telemetry, autonomous response). See
[innerwarden.com](https://innerwarden.com). It is a separate product; this
repository is the open-source guardrail and stands on its own.
