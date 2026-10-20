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
  than pretending to isolate. On Linux, where the host takes it, every jail
  starts its programs under a seccomp filter that refuses `TIOCSTI` and
  `TIOCLINUX`, the terminal commands that push input into your terminal, and
  new btrfs or bcachefs subvolumes and snapshots.
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
host's, so a deny and your own profiles file still win, and the trust it
records stays its own reading from inside the jail. A review the hook would
block on its line is still asked about, because the host may relax it; the
host lets nothing of it run that the hook does not keep. When the host
refuses a command on its own (it will not start a program in it), the hook
says: "Active Defence on this host will not start a program in this command."
and records the block as the host's.

A profile in the system file (`/etc/innerwarden/agent-profiles.toml`,
`schema_version = 2`) can ask for more: with `ask_host = "every_command"`
the hook asks the host about every shell command of that type's identified
instances, confined or not, that it does not refuse itself, including the
ones your general rules allow. A command they allow, your suppressions
included, is made stricter only by a refusal of the host's own: the host's
reading of your general rules does not override your suppressions. A command
the hook refuses is never asked about. It costs a request to the host on
every command, bounded like the others. Only the system file says
`ask_host`; the user's file never does, and a file of schema 1 that says it
is refused. Every program that reads the system file must read schema 2
before you write one: an older `innerwarden` refuses a file of schema 2, and
so does an older Active Defence on the host, which reads the same file.
Update both first.

A profile of schema 2, in either file, can also say when its jail starts and
what of the home it hides, under `[profile.<type>.jail]`:

- `start = "only_when_admitted"`: `contain --identity` starts the agent only
  once Active Defence on the host has admitted the jail. Otherwise it says
  "Active Defence on this host did not admit this jail, and its profile
  starts it only when admitted.", says what to check and which file asks for
  it, and exits 2 with nothing started. Inside the jail the command starts
  through `innerwarden contain-gate`, which will not start it without the
  record of that admission, so a launcher stopped while it waits (a Ctrl-C,
  killed) starts nothing either. On macOS such a profile never starts.
- `hide_home = [".cache/git/credential"]`: home paths the jail covers with an
  empty mount on Linux, or denies on macOS. A link on the way is followed and
  the place it leads to is hidden. A path that leads outside the home, or
  that would cover the project, the guard, a read-only path or the agent's
  own settings, stops the launch; a home folder the jail writes that is
  itself a link (`~/.cache` on another disk) counts as the home where it
  leads. On Linux a path that is not there yet, in a folder the jail writes,
  is made empty (mode 0700) first, so what a program makes there later stays
  hidden too. Each folder the jail writes between such a path and your home
  is pinned as below, so no program in the jail renames it away from the
  path's cover.

The user's file can only tighten these: the stricter `start` and every hidden
path of both files hold. When Active Defence sends a note about the jail (for
example, whether kernel protection is in effect for the session), it prints
it as `innerwarden contain: <note>`.

Every Linux jail keeps the host's name resolution working: where
`/etc/resolv.conf` is a link into `/run`, the file it leads to is shown
read-only in the jail, and nothing else of the host's `/run`. Where that file
sits in a folder of resolver data alone (resolvconf), the folder is shown, so
the jail follows the host when the network changes. Elsewhere
(systemd-resolved, NetworkManager) a jail keeps the resolver file it started
with until the agent is restarted.

On macOS every jail keeps in place the folders above what it hides: the
project, `~/.config` (which holds InnerWarden's own folder) and each folder
between the project and a `--deny-read` path cannot be renamed, removed or
replaced by a link from inside the jail, so nothing it hides is shown at
another name. The jail still writes in them; only the folder itself cannot be
changed (its mode or times). Where `~/.config` is not there yet,
`innerwarden contain` makes it first, empty and 0700; a dry run makes
nothing.

Where a place the jail hides is a link, the jail hides the place it leads
to: `~/.ssh`, `~/.gnupg` or `~/.aws` kept as a link into a folder the jail
shows (`~/.ssh` a link to `.config/ssh`), a link inside one of them
(`~/.ssh/config` a link into `~/.config/dotfiles`, as GNU stow and chezmoi
make one per file), a `--deny-read` path of the project, or InnerWarden's own
folder. Every link on the way is followed. On Linux that place is covered
wherever a folder the jail shows holds it, and each folder the jail writes
between the cover and your home is a mount point of its own, so a program in
the jail can neither read the place nor rename it away from the name your
link uses; a dotdir's place that is not there yet is made first, empty and
0700, so nothing the agent writes there reaches it (a `--deny-read` path that
is not there is not hidden). On macOS it is denied, read and write, also
outside your home, and each folder above it that the jail may write, the
project included, is closed to renaming and removal (the jail still writes in
it). The launcher looks for the links inside those dotdirs as far as 100000
entries and 32 folders deep, and says where it stops short. A link never
moves a mask or a deny onto what the jail needs: the guard, the agent's
settings or a file in them, the project, a read-only path, the system's
folders. Nor does a `--deny-read` link in the project, which the agent can
change, move one onto what the jail runs on: on Linux a place outside your
home, on macOS a place of the system outside the project. Each such place is
left as it is, and `innerwarden contain` says so, with what to do (on Linux
only where the jail shows that place: elsewhere it is not in the jail at
all). A dotdir that leads into the project is hidden there, and said. A link
stops the launch only here: a hidden dotdir, a link inside one, InnerWarden's
own folder or, in an identified Linux jail, the launcher's records folder,
whose way goes through a link in a folder the jail writes (`~/.aws` a link to
`~/.cache/aws-link`, itself a link) is refused, since no mount or deny pins a
link and a program in the jail could replace it on the host (replace that
link with what it leads to); on Linux, InnerWarden's own folder kept as a
link is refused for the same reason (replace it with the folder it leads
to), and so is a link inside a hidden dotdir that leads to nothing yet where
the jail shows that place (make it, or remove the link); and a project,
worktree or profile path over the place InnerWarden's folder leads to is
refused, as is a worktree or profile path over the place a hidden dotdir
leads to. A profile's `hide_home` path keeps its own rule, above: one that
leads outside the home stops the launch.

An identified Linux jail keeps Claude Code's own state in the `~/.claude` it
already shares with you. The jail's home is an empty folder of its own, so
Claude Code's settings file, `~/.claude.json`, used to be gone at every launch
(and Claude Code said, from the second launch on, that it was missing). In the
jail it now leads to `~/.claude/.claude.json`, so what Claude Code saves there,
an MCP server you add or its first-run answers, is still there at the next
launch. Your own `~/.claude.json` is not shown in the jail, and the jail's
Claude Code never uses it. Nor are the copies Claude Code keeps of it in
`~/.claude/backups`: each identified jail has an empty `~/.claude/backups` of
its own, and the copies made there are gone when the jail ends. The first
identified launch starts Claude Code with a new file of the jail's own, so it
may ask its first-run questions once. (Where your own `~/.claude.json` is a
link, or a hard link, to a file in `~/.claude`, that file is shared with the
jail like the rest of the folder, and the jail makes no link to it. Where you
point Claude Code at `~/.claude` with `CLAUDE_CONFIG_DIR`,
`~/.claude/.claude.json` is the file it uses, in the jail and out of it.)
Claude Code is process 2 in every jail and lists each running session by its
process id, so each identified jail also has an empty `~/.claude/sessions` of
its own: two jails at once do not write the same session file, and none sees
the sessions running outside it. Both folders are covered at every place the
jail shows them, a `~/.claude` that is a link into `~/.config` and a project
that is `~/.claude` included. All of this is for Claude Code's own folder at
`~/.claude`, where it is unless `CLAUDE_CONFIG_DIR` names another: the jail
leaves another folder as it is, and jails at once share the session list in
it.

Claude Code keeps its file in the jail's own home, as before, where a hidden
home path covers `~/.claude/.claude.json`, where a read-only path of the
profile shows it, `~/.claude` or `~/.claude.json`, where that place is a link
or anything other than a file, or where your own `~/.claude.json` is that file
or leads into `~/.claude` or to nothing. Where one of the two folders cannot be the jail's
own (a link is there, the project is inside it, or it could not be made), the
jail shows the host's, and `innerwarden contain` says so. Limit: two jails at
once share the one settings file, and Claude Code's lock on it is each jail's
own, so a change one jail saves at the same moment as another can be lost (a
save is never left half written). Every jail, with `--identity` or without,
shares `~/.claude` with you, so what a program in any jail writes to
`~/.claude/.claude.json` is what the next identified Claude Code loads, as
with `~/.claude/settings.json`: an MCP server listed there starts with it,
outside `innerwarden proxy` unless the entry runs through it, and a project
marked trusted there skips Claude Code's trust question. A jail started
without `--identity` is
unchanged: Claude Code's settings file is still gone at every launch there,
and two such jails at once still share `~/.claude/sessions` and see the
host's. On macOS the jail lets Claude Code use your own `~/.claude.json`, as
before.

Where a per-agent relaxation applies:

- Linux;
- the `innerwarden` that starts the jail is installed system-wide and owned by
  root (for example `/usr/local/bin/innerwarden`), not in your home folder;
- the agent was started with `innerwarden contain --identity`;
- InnerWarden Active Defence runs on the same host with agent identity turned
  on and an active licence, and it placed the jail in a scope of its own;
- Active Defence can tell which jail the asking process belongs to;
- shell commands your general rules sent to review (never MCP tools or file
  edits);
- the `innerwarden` inside the jail is a version that asks the host.

Anywhere else the relaxation is recorded and not applied. Applies to shell
commands only; MCP tools and file edits keep your general rules. A profile
applies to any program started in a jail under its agent's name: the type is
the name given at launch.

An identified jail starts its programs under a seccomp filter, in the style of
Flatpak: no new user namespaces, no joining other namespaces, no new btrfs or
bcachefs subvolumes or snapshots, and no `TIOCSTI` or `TIOCLINUX`, the
terminal commands that push input into your terminal. Its
programs run with no capability, also when `contain` itself runs as root.
Programs that need their own user namespace (Chromium's sandbox, rootless
containers, an agent's own bubblewrap sandbox) do not work inside it; turn the
agent's own sandbox off inside `innerwarden contain`. A 32-bit program (i386
or x32 on x86_64, arm on aarch64) is ended at its first call in an identified
jail. A jail started without `--identity` gets only the terminal rule and the
subvolume rule, and applies them to 32-bit programs too, which run in it as
before. Every jail refuses new subvolumes and snapshots because a snapshot of
the project would show the files the jail hides in it (`.env`, `secrets/`,
each `--deny-read` path).

Where the host cannot start a jail with the filter (a kernel without seccomp
filters, a binary run under another architecture's emulation, a build for an
architecture other than x86_64 or aarch64), the jail runs without it and
`contain` says so when it starts, naming the keystrokes and the snapshots its
programs can then make. An identified jail whose host takes only the plain
jail's filter gets that one, and `contain` says user namespaces stay open,
joining other namespaces too, and that a 32-bit program runs in it; the
terminal rule and the subvolume rule still hold.

Limits: the filter covers those commands only. It refuses only new
subvolumes and snapshots: a snapshot made before the jail started, in a folder
the jail shows, still holds the files the jail hides (`.env`, `secrets/`, each
`--deny-read` path), and a program in the jail can read them there. Keep such
snapshots out of the project and out of the folders the jail shows. The jail
shares the host's network, so a program in it can still reach any abstract unix socket,
a desktop's X server among them, and through X type into another window. On
a kernel older than 4.8, a program in the jail that traces another can change
a call after the filter has seen it: there an identified jail does not close
user namespaces, and `contain` says the filter is weaker. This is not
yet proven on RHEL 9 or Rocky 9.

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
