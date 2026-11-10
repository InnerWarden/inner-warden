# What InnerWarden does, in detail

The short version is in the [README](../README.md). This page holds the full
list, with every limit.

- Screens shell commands and MCP/tool calls before they run, and returns a
  verdict: `allow`, `review`, or `deny` (advisory by default).
- Runs an MCP proxy: a man-in-the-middle in front of an MCP server that inspects
  every JSON-RPC message and can refuse a disallowed tool call inline. stdout
  stays pure MCP traffic, alerts go to stderr.
- AI Jail: run an agent in a constrained profile so a screened-and-denied action
  is stopped rather than merely flagged. Linux (bubblewrap) and macOS
  (sandbox-exec) only; `contain` exits with an explicit error on Windows rather
  than pretending to isolate. On Linux, where the host takes it, every jail
  starts its programs under a seccomp filter that refuses `TIOCSTI` and
  `TIOCLINUX`, the terminal commands that push input into your terminal, and
  new btrfs or bcachefs subvolumes and snapshots.
- Agent identity (off by default, Linux): `innerwarden contain --identity --
  <command>` records the run as an instance, so its hook and the dashboard can
  tell one agent's runs apart. See [Agent identity and trust](agent-identity.md).
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
  reply included: its words are not read, and a call the guard let run (or
  did not see) leaves nothing, so a reply does not show the agent declined;
  `guard_denied` only for a refusal the guard made for that agent, in that
  conversation's session, in a turn whose reply was seen, never for an action
  monitor mode let run) and a model refusal is never reported as a block:
  `innerwarden observe status` says whether this host sees them at all.
  OpenClaw today, via its message hooks; `kernel_denied` only where
  InnerWarden Pro's Execution Gate, in enforce for that agent, refused a
  program during a call of that conversation, as Pro recorded it.

The verdict is JSON: a recommendation (`allow` / `review` / `deny`), a risk
score, matched signals, and a short explanation.

## The guard and its own switches

An agent that could turn its guard off would not be guarded. Under an
enforcing hook (`innerwarden enforce`), the guard refuses an agent the
following, and says they are the person's to run, from their own terminal.

- The guard's own loosening commands: allow, mute, monitor and dry-run, the
  agent decisions (approve, profile, allow, revoke), disconnecting an agent,
  connecting or installing one in monitor, uninstalling, and starting a jail
  (which rewrites the agent's hook). A read, help, a connect that keeps
  enforcing and `contain --dry-run` stay open.
- The commands of InnerWarden Pro's tools that disarm one of its guards or
  widen what it lets through.
- A write to what carries the guard: the agent settings that load its hook,
  the guard's configuration and the guard's program. That holds through a
  file tool and from the shell: a redirection, `tee`, `cp`, `mv`, `rm`, `ln`,
  `install`, `sed -i`, `dd`, a download saved over it, a `chmod` that closes
  it to its owner. Removing, moving or locking an agent's own settings folder
  counts, because the settings go with it.
- The same command however the line spells it: behind `sudo`, `env`, a lock
  or a scheduling wrapper, as the argument of a shell or of `ssh`, in a
  variable or a value the line builds, under a pattern that can match the
  guard's name, or as text piped into a shell or an interpreter.
- A line that names the guard and holds a part the guard cannot read. It is
  refused, not guessed at, and the refusal says how to write the line so that
  it can be read.

The CLI is a second check. Run inside an AI agent's shell, where the hook does
not see the call (a script the agent wrote), `innerwarden` refuses its own
loosening commands.

### Where this ends

The guard reads the text of one command, before it runs. It does not see:

- A name or a command that never appears in the text, because it is decoded
  or put together only when the line runs.
- What an earlier command prepared: a script, or a copy of a program under
  another name.
- A write whose target the text does not spell: one found by a pattern or a
  search, made from inside an editor or by code handed to an interpreter, or
  carried in an archive or a patch.
- Anything in monitor mode, which records and refuses nothing.

An agent's hook lets a call run unless the guard answers with a refusal. A
guard that takes too long answers with one (ten seconds, under an enforcing
hook). A guard whose program is gone or cannot start answers nothing, and the
call runs: that is why a write to the guard's program is refused above.

Some ordinary lines are refused by the same rules, and the refusal says so: a
program run from a variable on a line that also names the guard, an agent
that copies a new `innerwarden` binary into place, or one that writes a
project's `.mcp.json` or removes a project's `.claude` folder from the shell.
Those are yours to run.

These are the limits of a guard that reads text. InnerWarden Pro works below
the text, at the host (Linux): armed for an agent, its Execution Gate decides
in the kernel which programs that agent's processes may start, whatever the
command line says. It is off until you arm it.

