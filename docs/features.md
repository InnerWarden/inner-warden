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
kept in its own home instead, so Pro does not see its refusals.
`innerwarden status`, run as that account, says so in one line; the hook
says nothing about it on each call. To let Pro see them, add the agent's
account to the group, then start the agent again from a new login so the
group applies:

    sudo usermod -aG innerwarden <agent-account>

The account can then write the shared record, the same as the operator, and
so it can also change what others recorded there. A folder of its own that
only that account writes would avoid that, but Pro does not read one today.

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
- Starting another agent with the hook that screens it switched off or moved
  away, so the child would run every tool call unscreened: Claude Code
  started with `--bare`, `--safe-mode` or `--restricted`, with setting
  sources that leave out the user's, with settings that switch hooks off or
  empty the events the guard's hook sits under, or with a variable it reads
  that moves the folder its hook is in or switches its hooks off (`HOME`,
  `CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_SIMPLE` and the others it reads). `HOME`
  set to the home folder the shell itself puts in, and `CLAUDE_CONFIG_DIR` set
  to the folder Claude Code already uses, move nothing and run; another
  folder is refused in words that say how to install the hook there. A tool
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

An agent's hook lets a call run unless the guard answers with a refusal. A
guard that takes too long answers with one (ten seconds, thirty with a second
opinion from a model configured, under an enforcing hook). A guard whose
program is gone or cannot start answers nothing, and the
call runs: that is why a write to the guard's program is refused above.

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

