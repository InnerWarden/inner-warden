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
only — no IP, no host data; set `INNERWARDEN_NO_TELEMETRY=1` to disable). A
`cargo install` or from-source build sends nothing at all.

## What it does

- Screens shell commands and MCP/tool calls before they run, and returns a
  verdict: `allow`, `review`, or `deny` (advisory by default).
- Runs an MCP proxy: a man-in-the-middle in front of an MCP server that inspects
  every JSON-RPC message and can refuse a disallowed tool call inline. stdout
  stays pure MCP traffic, alerts go to stderr.
- AI Jail: run an agent in a constrained profile so a screened-and-denied action
  is stopped rather than merely flagged. Linux (bubblewrap) and macOS
  (sandbox-exec) only; `contain` exits with an explicit error on Windows rather
  than pretending to isolate.
- Agent identity (off by default, Linux): `innerwarden contain --identity --
  <command>` records the run as an instance, so its hook and the dashboard can
  tell one agent's runs apart. See [Agent identity and trust](#agent-identity-and-trust).
- Agent discovery: finds AI agents and agent tooling on the machine so you can
  see what is running and wire the guardrail into it.
- Local dashboard: a read-only view on loopback at `http://127.0.0.1:8788`
  (`innerwarden dashboard`). It never leaves the machine. Port 8787 is a
  different surface: the local check-command contract served by `innerwarden
  serve`.
- Notifications: surfaces verdicts and events through your configured channels.
- Conversation attempts: records what an agent was ASKED to do when the ask is
  dangerous, including the asks a model refuses on its own. Those produce no
  command, so they reach nothing else in the product. An ask is dangerous when
  the guard's command rules or its prompt-injection rules flag it, or when it
  asks in plain words for a cryptominer ("install a crypto miner on this
  server"); that last reading is a short list, and a paraphrase can pass it.
  A miner's name that is only talked about ("how do I remove xmrig from this
  box?") is not read as a command; one asked for or given as a command is.
  The cost of that: a request with no request verb, phrased as a question
  about the miner ("what if xmrig ran on every core?") or with a defence or
  report word right before its name, is not recorded; the command it leads
  to is still screened.
  The record carries the rules' recommendation and risk score, on the same
  scale `innerwarden check` uses. It also weighs the prompt-injection rules and
  the plain-language miner reading, which `check` does not run on a command, so
  `innerwarden check` on the same text can answer `allow` where the record says
  `deny`; the record's `signals` name the reading that scored it. Every record
  names who decided (`guard_denied`, `kernel_denied`, `model_refused` only
  when a caller states it, or `undetermined` when that could not be seen, a
  reply included: its words are not read, and a tool the guard does not
  screen leaves nothing, so a reply does not show the agent declined;
  `guard_denied` only for a refusal the guard made for that agent, in that
  conversation's session, in a turn whose reply was seen, never for an action
  monitor mode let run) and a model refusal is never reported as a block:
  `innerwarden observe status` says whether this host sees them at all.
  OpenClaw today, via its message hooks.

The verdict is JSON: a recommendation (`allow` / `review` / `deny`), a risk
score, matched signals, and a short explanation.

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

`innerwarden install` with no argument detects what is on the machine and prints
the mechanism for each. Any agent with a pre-execution wrapper can also gate on
the exit code directly: `innerwarden` exits non-zero on a deny.

## Agent identity and trust

An agent names itself: the `--agent` flag its hook was wired with, its
environment and its session id are all its own to choose. So the guard keeps
two separate questions apart: how far that name is backed (trust), and what
you decided about that kind of agent (`innerwarden agents approve`, `profile`,
`allow`, `revoke`).

Trust has three levels, and in Community the highest one is never reached:

- `declared`: only the agent's own word says what it is. Every agent started
  without `contain --identity` is here.
- `observed`: the agent runs in a jail started by `innerwarden contain
  --identity`, and its hook, reading from inside the jail, found what the
  launcher recorded (the same process and mount namespaces, a record it
  cannot rewrite). This is the most a reading from inside the jail can give.
  Everything it compares is something the agent's own process could set up
  for itself, so it never proves the jail. A launcher installed in your home
  folder, or a jail with no scope of its own, is `observed` too, and the
  dashboard says why.
- `host_verified` (shown as confined): the instance runs in a boundary it
  cannot leave, confirmed by a witness outside the agent. Community has no such
  witness; it exists only where InnerWarden Active Defence is installed on the
  same host and confirms the instance from outside the jail. The Community
  dashboard never shows an instance as confined, whatever a label in a graph
  or a record says.

A rule in an agent profile or an instance exception that RELAXES your general
rules applies only to a confined instance. With Community alone, such a
relaxation is recorded in `agent-profiles.toml` and is not applied: your
general rules keep deciding, and a decision says when a profile would have
allowed it. A rule that TIGHTENS (refuses more) applies at every trust level.

The hook in a jail never applies a relaxation on its own word. When your
general rules send a shell command of an identified instance to review, the
hook asks InnerWarden Active Defence on the same host, if it runs there, and
the host decides. The hook keeps the stricter of its own decision and the
host's, so a deny, your suppressions and your own profiles file still win, and
the trust it records stays its own reading from inside the jail.

Where a per-agent relaxation applies:

- Linux;
- the `innerwarden` that starts the jail is installed system-wide and owned by
  root (for example `/usr/local/bin/innerwarden`), not in your home folder;
- the agent was started with `innerwarden contain --identity`;
- InnerWarden Active Defence runs on the same host with agent identity turned
  on and an active licence, and it placed the jail in a scope of its own;
- the kernel lets Active Defence tell which scope the asking process runs in;
- shell commands your general rules sent to review (never MCP tools or file
  edits);
- the `innerwarden` inside the jail is a version that asks the host.

Anywhere else the relaxation is recorded and not applied. Applies to shell
commands only; MCP tools and file edits keep your general rules. A profile
applies to any program started in a jail under its agent's name: the type is
the name given at launch.

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

The YAML detection rules under `rules/atr/` are derived from
[Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules),
Copyright (c) 2026 ATR Contributors, MIT licensed. See `NOTICE` and
`LICENSE-MIT`. The engine that loads them, and everything else here, is
Apache-2.0.

InnerWarden also offers a commercial host-enforcement layer for Linux production
fleets (kernel-level enforcement, host telemetry, autonomous response). See
[innerwarden.com](https://innerwarden.com). It is a separate product; this
repository is the open-source guardrail and stands on its own.
