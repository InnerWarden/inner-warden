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
  new btrfs or bcachefs subvolumes and snapshots. Exported variables whose
  name says they hold a credential (`OPENAI_API_KEY`, names ending in
  `_API_KEY`, `_TOKEN`, `_SECRET`, `_PASSWORD` and the like) are taken out of
  the jailed command's environment, and `--pass-env NAME` hands one in. It
  goes by the name: a secret under another name still reaches the jail.
- Agent identity (off by default, Linux): `innerwarden contain --identity --
  <command>` records the run as an instance, so its hook and the dashboard can
  tell one agent's runs apart. See [Agent identity and trust](agent-identity.md).
- Agent discovery: finds AI agents and agent tooling on the machine so you can
  see what is running and wire the guardrail into it.
- `innerwarden demo`: sends a few known risky calls (a download piped to a
  shell, a read of an SSH key, a write of agent settings, a home wipe inside
  `bash -c`, an MCP call) through the guard path each connected agent really
  uses, and shows what was refused. Nothing is run; each call is recorded and
  marked as a demo.
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

### Where decisions are recorded

On its own, InnerWarden keeps its record in the home of the account that runs
it: `~/.config/innerwarden/graph.json`, with the refusals also appended to
`guard-events.jsonl` beside it. `IW_GRAPH_FILE` moves it anywhere you say.

When InnerWarden Pro is installed on the same machine, its installer writes
`/etc/innerwarden/guard.toml`, which names a shared record in
`/var/lib/innerwarden/guard/` (`drwxrws--- innerwarden:innerwarden`). Pro
reads the refusals from there. Only accounts in the `innerwarden` group may
write it, and the installer adds the operator.

An AI agent that runs as its own Linux account is not in that group unless you
add it. Such an account still has every call screened, and its decisions are
kept in its own home instead (`~/.config/innerwarden`, the folder `0700` and
the files `0600`). That is a failure of the record's integrity: Pro does not
see those refusals, and the account, so the agent running as it, can edit or
delete them. The same happens when the shared directory is writable but the
graph or `guard-events.jsonl` in it is a file the account may not open.
`innerwarden status`, run as that account, says so in one line; the hook
says nothing about it on each call. Do not add the agent's account to the
`innerwarden` group: that group reads every member's decisions and
InnerWarden's own state. Give the account a folder of its own instead, on
the InnerWarden Pro install:

    sudo innerwarden-ctl agent-user add <agent-account>

That makes `/var/lib/innerwarden-agents/<agent-account>/`
(`<agent-account>:innerwarden 2750`, which only that account writes and Pro
reads) and adds an `[accounts."<agent-account>"]` entry to
`/etc/innerwarden/guard.toml`. The CLI, run as that account, then records
there, `0640`, and `IW_GRAPH_FILE` cannot move that record elsewhere.
The account is read from its uid, never from the environment.
`innerwarden status` says where decisions are recorded and whether Pro
reads them there. The first `innerwarden status` after the change says once
that the decisions of the meantime are still in the home, and how to read
them.

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
  widen what it lets through, and a `bpftool` write to Pro's kernel maps
  named by path or by name (one named by a numeric id is held for review).
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
- Starting another agent with the hook that screens it switched off or moved
  away, so the child would run every tool call unscreened: Claude Code
  started with `--bare`, `--safe-mode` or `--restricted`, with setting
  sources that leave out the user's, or with settings that switch hooks off
  or empty the events the guard's hook sits under; Codex CLI with `--disable
  hooks` or a `-c` override of its hooks; Hermes Agent with `--safe-mode` or
  `--ignore-user-config`; or any of them, Gemini CLI included, with a
  variable it reads that moves the folder its hook is in or switches its
  hooks off (`HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `HERMES_HOME`,
  `GEMINI_CLI_HOME`, `CLAUDE_CODE_SIMPLE` and the others they read). `HOME`
  set to the home folder the shell itself puts in, and `CLAUDE_CONFIG_DIR` set
  to the folder Claude Code already uses, move nothing and run; another
  folder for Claude Code is refused in words that say how to install the
  hook there. A tool
  call is judged by every command line it carries (a command string, an argv
  list, `args`, its environment as an object or a list, text typed into a
  terminal or handed to a shell). Each line goes through the person's allows
  and every other layer on its own, and the strictest outcome stands.
- A shell or process tool call the hook can only read in part. One that
  holds a command, its arguments or its environment in a shape that cannot
  be read as words (arguments as one string, a list inside an argument list,
  a value that is no text) is refused as a call the hook cannot read. So is a
  shell tool call with no command string that holds a field the hook does not
  read: anything but the command in another shape, its arguments, its
  environment, a timeout, a description or running in the background. A
  folder the call names for its command (`cwd`) is such a field: the hook
  judges a line where the agent runs, not there. A line of a call that holds
  such a field, or a variable no shell can name, is judged also as moved
  first (to that folder, where it names one) when it holds a substitution,
  and the entries of a `commands` list are judged also as one line.

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
- A writing command (`cp`, `mv`, `tee` and the like) that the line runs from
  inside a function it defines, a `case` arm or a command substitution. A
  redirection is read in those places; the commands are read where they
  stand as a command of the line.
- Anything in monitor mode, which records and refuses nothing.

The rule on a child agent reads these forms, not every form a shell allows.
It reads a variable set in front of the agent or for the rest of the line
(an assignment, `export` and its kin, `read`, `mapfile`, `getopts`,
`printf -v`, `let`, arithmetic, a loop's name, a `${NAME:=value}` default, a
reference); the launchers it knows (`env`, `sudo`, `doas`, `nohup`,
`setsid`, `time`, `timeout`, `nice`, `ionice`, `chrt`, `taskset`, `strace`,
`ltrace`, `chronic`, `unbuffer`, `caffeinate`, `flock`, `systemd-run`,
`coproc`, `xargs`, `npx` and its kin, `node`, `bun` and `deno` running the
agent's package); a command line handed to another program (a shell's
command string or its input, `eval`, `trap`, `watch`, `tmux`, `screen`,
`at`, `su`, `runuser`, `sg`, `script`, `find -exec`, GNU `parallel`,
`cmd /c`, PowerShell's `-Command`, `npx -c`, `npm exec -c` and pnpm's shell
mode), and what a line run by `eval` sets for the rest of the line; the setters
of a C shell, fish, PowerShell and Windows `cmd`; and a tool call's command
in the shapes above. It does not see:

- An agent named by something the line only holds as a value: a variable,
  an array, a function, an alias, words split by `IFS` or set by `set --`,
  or a glob or another expansion where the program stands.
- A file the line writes and then runs, sources or hands over as settings,
  or a value set in one call and used in a later call of the same shell.
- A copy or a link of the agent's program under another name.
- An agent started from code handed to an interpreter (`python -c`,
  `node -e`), or by PowerShell's `-EncodedCommand`.
- An agent started as another user, whose settings and hook are that
  user's own.
- The options of GNU `parallel` and `tmux` it does not know, and the
  arguments `parallel` reads from files.
- What `xargs` or a shell reads on its input from a file or another
  program; only text the line itself shows is read. That holds where the
  line spells out the program whose output is read, as a process
  substitution does: what that program prints is input, not text the line
  shows.
- Forms of the shell, of the programs above and of package runners that
  are not listed here.
- Text a tool call hands to a program that is not a shell, which is that
  program's input. The hook refuses that text only in a shell tool call
  with no command string.
- A field of a tool call that is none of the shapes above, such as an
  environment under a name the guard does not read. The hook refuses one
  only in a shell tool call with no command string; beside a command
  string, or in the call of a tool that is not a shell, it judges the lines
  it reads and lets the field pass unread. In the MCP proxy, a part of a
  tool call it cannot read as words gets the checks any tool's arguments
  get, which can depend on the tool; the hook refuses such a call.

Text typed into a terminal or a REPL is read as a shell line, which is what
it is only when a shell reads it.

In the MCP proxy and in a line handed to a shell, the guard also does not see:

- An order aimed at the model in a tool result when other words stand
  between it and the action it asks for. An override order followed by an
  action is held however it is quoted or fenced; one padded with filler
  before the action can pass.
- The input a shell tool call hands a shell past its first 64 KiB. The call
  is held for review and the rest is not read.
- What `xargs` or `find -exec` acts on, beyond what the line spells out. A
  removal `find` hands its finds to is judged by the folder `find` starts
  from, and a recursive removal fed by `xargs` is refused from a listing of a
  protected place and held for review from input the guard cannot read; any
  other command they run is judged from the literal words of the line, not
  from the names a search finds when it runs.
- A `-c` variable whose value is set at run time. Such a line is held for
  review, not judged by the value it will hold.

An agent's hook lets a call run unless the guard answers with a refusal. A
guard that takes too long answers with one, under an enforcing hook: after
ten seconds of screening (time spent waiting for a CPU is not counted on
Linux) or 25 seconds on the clock, 20 more with a second opinion from a model
configured. A tool call longer than 1 MiB is not read and is refused the same
way. `innerwarden install` writes a 50 second `timeout` on the Claude Code
hook line, so the guard's own refusal comes before Claude Code stops waiting;
a call Claude Code stops waiting for runs. On macOS and Linux,
an enforcing Claude Code hook line ends in a short shell tail, and an
enforcing Codex CLI or Gemini CLI line runs the guard inside a small `/bin/sh`
script (Codex starts the line with the login shell, which may not read that
tail), so a guard whose program is gone or dies refuses the call too. Hermes
Agent gets the same from its own `fail_closed: true`. In monitor, on Windows,
and for an agent whose hook line has no such tail, a guard that cannot start
answers nothing and the call runs: that is why a write to the guard's program
is refused above. Gemini CLI refuses a call on any hook exit but 0 and 1, so
its monitor line is a script too, which ends every other way with 1.

The same tail and script mean a program removed by the package manager (`npm
uninstall -g`, `apt remove`) before `innerwarden uninstall` leaves every tool
call of an enforcing agent refused, and the agent cannot mend it. Run
`innerwarden uninstall` first; the refusal names the settings files to edit
by hand if it is too late.

Some ordinary lines are refused by the same rules, and the refusal says so: a
program run from a variable on a line that also names the guard, an agent
that copies a new `innerwarden` binary into place, or one that writes a
project's `.mcp.json` or removes a project's `.claude` folder from the shell.
So is a child agent given `HOME` or `CLAUDE_CONFIG_DIR` in a form the shell
does not expand to the home folder: a `$HOME` or `~` in quotes or after a
backslash, a `~` in a word `env` or `sudo` is handed (zsh passes it on as
written), and any value in settings JSON. A variable set by arithmetic or by
PowerShell anywhere on a line counts for the whole line. In the MCP proxy, a
tool call in a shape other than a command string (an argv list, `args`, a
second key) keeps the file checks on its arguments, so a private key's path
among them (`ssh -i ~/.ssh/id_ed25519` given with `args`) is refused there. Those
are yours to run.

These are the limits of a guard that reads text. InnerWarden Pro works below
the text, at the host (Linux): armed for an agent, its Execution Gate decides
in the kernel which programs that agent's processes may start, whatever the
command line says. It is off until you arm it.

