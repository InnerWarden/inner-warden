# Changelog

All notable changes to InnerWarden are documented here. This project
follows semantic versioning.

## Unreleased

### Upgrade notes: what to do

- **An agent can no longer install a package whose name is one letter off a
  popular one.** `pip install reqeusts` or `npm install expresss` run by an
  agent is now held for review and blocked under the default policy; run by
  you with `innerwarden check` it is `review`, never `deny`. If a package you
  really use is held, install it yourself, or allow it for the agent.
- **`innerwarden status` counts only what your agents sent.** A check you ran
  by hand (and every drill or verify run) is no longer counted as proof that
  your agent's commands reach the guard, so an install whose agent has not
  run a command since it was wired now says so instead of reading as on and
  screening.

### Added

- **Look-alike package names are caught on install.** An install through
  pip, pipx, uv, poetry, pipenv, npm, yarn, pnpm or bun that names a package
  one edit away (a letter added, dropped, changed, or two swapped) from a
  popular PyPI or npm package, and is not itself a known package, is flagged
  `package_typosquat` and named with the package it imitates. This is how
  typosquatted packages, and package names an AI agent made up, get
  installed. Real packages that sit one letter from each other (scipy and
  scapy, react and preact) are known and pass. Names shorter than five
  letters are never compared. The list ships in the repository
  (`crates/agent-guard/data/popular-packages.txt`).
- **Library users: a connected agent's registry row keeps its systemd unit.**
  `Registry::connect` records the system service the process runs in, read
  only from the cgroup the kernel reports for it, so the row survives a
  service restart that changes the pid. `ConnectedAgent`, `PersistedAgent`
  and `AgentSummary` gain `systemd_unit`; `connect_with_facts_and_unit` is
  new. Registry files written by an earlier version load unchanged, and a row
  without a unit is written without the key.

### Changed

- **`innerwarden --version` names the paid release too.** With Active
  Defence installed it adds, on stderr, that `innerwarden-ctl --version`
  gives the host stack's release. stdout stays one line.
- **`upgrade` names what is still running the old binary correctly.** Its
  closing advice called whatever answered on 127.0.0.1:8787 "the dashboard".
  It now names the Community dashboard on 8788 and an `innerwarden serve` on
  8787 each by its own answer, and says nothing about anything else.

### Fixed

- **A download run in two steps is caught.** `f=$(curl -s URL) && echo "$f"
  > /tmp/r.sh && sh /tmp/r.sh` was allowed, and so were the same steps with
  `wget`, `printf`, `tee`, here-strings, heredocs, `cat >`, a copy of the
  file, or `chmod +x` and `./r.sh`. A value fetched into a shell variable is
  now followed into the file it is written to, and running that file is
  screened like any other downloaded script (review, and blocked for an
  agent; denied when the fetch has no TLS, a bare IP, a paste host or a
  decoder). Feeding the variable to a shell's input (`sh <<<"$f"`) is denied.
  Writing a fetched value to a file nobody runs (`echo "$f" > data.json`)
  stays allowed.
- **Sourcing a downloaded file with `.` is seen.** `curl -o r.sh URL && .
  ./r.sh` was allowed while `source ./r.sh` was caught.
- **An MCP wrapper whose proxy binary is gone is not reported as guarded.**
  The agent list, the dashboard and `status` judged an MCP agent's wrapper by
  its text, so a config pointing at a removed or moved `innerwarden` read
  "guarded" while every one of its servers failed to start. It now says the
  proxy program does not exist and offers `innerwarden agents connect <name>`
  in the mode the wrappers had. Nothing is unwrapped.

### Project

- The benchmark gate holds the new cases: 153 attacks caught, every one
  blocked for an agent, and 0 of 98 ordinary commands flagged.
- The release job fails when the `guard-vX.Y.Z` source tag is missing or
  names a different commit than the one it built.
- A test pins that the `.deb` and `.rpm` ship `/usr/bin/innerwarden` and no
  `iw` shortcut (`iw` is the Linux wireless tool's name).
- The coverage job reads its configuration again (the engine name is
  case-sensitive, so the 75% floor and the excludes were silently ignored)
  and fails if the configuration is ever rejected.
- Every dashboard journey test runs at a fixed clock, so the suite no longer
  breaks when the calendar moves past its fixtures.
- The CLI's tests are no longer answered by an `innerwarden-ctl` installed on
  the machine running them.

## 1.5.2 - 2026-10-07

### Upgrade notes: what to do

- **OpenClaw message hook: install it again, this once.**
  `innerwarden observe install`, then restart the OpenClaw gateway. The hook
  an earlier version wrote keeps running after an upgrade, and with it
  Control UI chats are recorded only after 15 minutes and without the agent's
  name. The install now also adds the reply plugin (below), and grants it the
  conversation access OpenClaw requires before a plugin can read a turn; it
  says so, and leaves alone an entry you turned off and your `plugins.allow`,
  `plugins.deny` and `plugins.enabled`. From this version on, `upgrade` brings
  the hook and the plugin up to the new version's itself (`observe refresh`).
  `innerwarden observe status` and the dashboard's Messages card say when
  either is an earlier version's, or is not what InnerWarden wrote.
- **A copy installed from the `.deb` or `.rpm` is upgraded with the package.**
  `innerwarden upgrade` refuses it and exits 2, so an unattended
  `sudo innerwarden upgrade` on such a host now fails. Use the command it
  prints (it fetches the package and its checksum into a private directory,
  checks it, then installs it), or `--yes` to replace the file anyway.
  `upgrade --check` reports on every kind of install.
- **`innerwarden uninstall` on a packaged copy** removes the hooks, the
  configuration and the `iw` / `iw-guard` shortcuts, leaves the binary to
  `sudo apt remove innerwarden` or `sudo dnf remove innerwarden`, and exits 1
  with "partly removed" until that is done.
- **`innerwarden uninstall` removes only the installer's copy.** A binary
  the installer did not lay down (installed with `cargo install`, with Scoop,
  or a copy another program keeps for itself) is now left where it is, with
  the command that removes it where there is one, and the run exits 1 with
  "partly removed". After uninstalling a cargo or Scoop copy, finish with
  `cargo uninstall innerwarden` or `scoop uninstall innerwarden`.
- **Reconnect MCP agents to have them named.** `innerwarden agents connect`
  now writes `--label` and `--agent` into each MCP wrapper, so its decisions
  are recorded under the session `mcp:<agent>` instead of `mcp:innerwarden`.
  Run it again for wrappers an earlier version wrote; history recorded before
  that stays under the old session.

### Changed

- **A Control UI ask is recorded with how the turn ended.** OpenClaw reports
  no reply from its Control UI chat to hooks, so an ask made there was
  recorded after two minutes with the outcome not seen. `observe install`
  now adds an OpenClaw plugin, `innerwarden-replies`, that reads the end of
  each Control UI turn a person started (OpenClaw's typed `agent_end` hook)
  and reports only its shape, a tool call, a reply, or neither, to the new
  `innerwarden observe ended`. That closes the ask whose message started the
  turn, and no other: a turn that replied with no tool call is recorded as
  `undetermined` with `decider_basis: replied_without_tool_call` (the agent
  ran nothing; the plugin never reads the words, so whether it declined is
  not seen); one that called a tool is `undetermined`, `tool_call_in_turn`,
  because a tool the guard does not screen leaves nothing in its record, and
  a reply after it does not show the agent declined; one that ended with
  nothing said is `undetermined`, `turn_ended_without_reply`. A heartbeat or
  cron turn never closes an ask. A turn holding a message in a shape the
  plugin does not know is not reported, unless a tool call it recognises
  makes it `tool_call_in_turn`, and the ask is recorded as not seen. Where
  the plugin runs, the message hook's two-minute timer leaves an ask to the
  end of its turn (at most 15 minutes), so a long turn is not recorded as
  "this chat does not report your agent's reply", and what the guard
  recorded late in it is in the record. The plugin reads Control UI turns
  only.
  The gateway logs the plugin as one it cannot verify, because it was not
  installed through `openclaw plugins install`.
- **A reply is no longer read as the model declining.** `observe reply`
  recorded a reply with nothing the guard screens in its window as
  `model_refused`, and the dashboard said "Your agent declined on its own".
  The reply's words are never read, and a tool the guard does not screen
  (OpenClaw's own exec) leaves nothing in its record, so an ask the agent
  carried out with such a tool, or answered by doing what was asked in
  words, read the same. Such a reply is now `undetermined`, with
  `decider_basis: no_screened_execution_recorded_in_window`, and the
  dashboard says the agent replied and nothing the guard screens ran, under
  the outcome "Answered". Records an earlier version wrote that way read the
  same. `model_refused` is written only when a caller states it
  (`observe reply --decider`).
- **`upgrade` refreshes what `observe install` wrote.** After the binary is
  replaced, the new binary's `innerwarden observe refresh` replaces the
  message hook's and the reply plugin's files with the new version's where
  they are exactly what an earlier release wrote. A file somebody changed is
  left as it is and named, nothing that was not installed is added, and the
  gateway is never restarted: the upgrade says to restart it.
- **The MCP proxy ends with its session.** When the client closes, the proxy
  relays the server's last output for 3 s, then stops the server: SIGTERM to
  its whole process group, SIGKILL 1 s later, so a server started through
  `npx`, `uvx` or `sh -c` is stopped with its launcher.
- **The MCP loop breaker holds one call for one window.** An identical tool
  call made more than 3 times within 60 s is refused (guard) or flagged
  (advisory), that call only, and the refusal says when it is accepted again.
  The cost ceiling is gone. Library users: `innerwarden_agent_guard::breaker`'s
  `BreakerConfig` and `Breaker::record` changed.
- **Conversation records claim less, and say why.** `guard_denied` is recorded
  only for an observed reply and an enforce-mode refusal on a line naming the
  agent that was asked and the session the ask arrived in. A refusal of the
  same agent in another conversation, or under the MCP proxy's own session
  (how OpenClaw is guarded), is recorded as `undetermined` with
  `decider_basis: guard_block_recorded_in_window`; it used to stamp whatever
  ask was waiting `guard_denied`, `enforced: true`. A monitor-mode
  `would_block` in the window is recorded as `undetermined` with
  `decider_basis: flagged_action_ran_in_window`, never as a refusal or as the
  model declining. `guard.attempt` gains `agent` and
  the bases `next_message_before_reply`, `channel_reports_no_reply`,
  `pending_limit_reached`, `pending_state_unavailable` and
  `flagged_action_ran_in_window`; `guard.blocked` gains `agent`.
- **A guard event file that cannot be written is an outage.** A link, a second
  name, something that is not a plain file, or a file this account cannot
  append to, at `guard-events.jsonl` or `record-health.json`, is reported by
  `innerwarden graph` and the dashboard with the fix, instead of dropping lines
  silently.

### Fixed

- **`uninstall` no longer deletes a copy it did not install.** It decided
  from npm, the `.deb`/`.rpm` database and whether the file could be deleted,
  and as root every file can be, so `sudo innerwarden uninstall` run from a
  copy another program keeps for itself deleted it. The binary is now removed
  only when it is the installer's: named `innerwarden`, `iw` or `iw-guard`,
  and either in the installer's directory for this account (`~/.local/bin`,
  or `%LOCALAPPDATA%\Programs\InnerWarden` on Windows) or with an `iw` or
  `iw-guard` beside it that links to it or is a copy of it. Anything else is
  kept and named, and the hooks and configuration are still removed.
- **`uninstall --dry-run` writes nothing.** The preview found out whether the
  binary could be deleted by creating and deleting a file beside it. Both the
  preview and the run now read that from the file system's own permission
  check, without writing.
- **`upgrade` refreshes the installer's `iw` and `iw-guard` copies.** Where
  the shell installer cannot make a link it copies the binary instead, and on
  Linux and macOS `upgrade` replaced only `innerwarden`, so `iw` went on
  running the build first installed, and `uninstall` then kept both copies as
  another program's. A copy is now replaced with the binary when it is this
  build or any earlier one (recognised by the release key every build since
  1.1.0 carries, without running it), and `uninstall` removes such a copy. A
  link is left a link, and a file that is not InnerWarden is not touched.
- **`upgrade` never writes through a link at its staging name.** The new
  binary is staged beside the old one, and a link planted under that name, in
  a directory another account can write, made `sudo innerwarden upgrade` write
  the release (and its first check, an empty file) over whatever the link
  pointed at. Whatever is at the staging name is now removed first and the
  file is created afresh.
- **Removing one agent's hook no longer prints `rm <path>`.** `innerwarden
  uninstall <agent>` ended by handing out a bare `rm` of whatever copy was
  running, an npm or package copy included. It now points at the full
  `innerwarden uninstall`, which decides whether the binary is its to remove.
- **A question about a miner is not an attack attempt.** The command rules
  refuse a miner binary wherever its name appears, so a message such as "how
  do I remove xmrig from this box?" was recorded as a conversation attempt,
  deny 40. A name that is only talked about is now taken out before the rules
  read the message: a plain word the sentence acts on right before it
  ("remove xmrig", "kill the xmrig process", "we found minerd") or asks about
  in the clause that holds it ("how do I remove xmrig", "is xmrig running"),
  and `t-rex` unless the message is about mining. A message that asks for
  anything, gives the miner as a command (`nohup xmrig`, `xmrig -o ...`), or
  has a defence word only elsewhere in the sentence ("configure xmrig and
  monitor the hashrate") is read as before. What is no longer recorded: a
  request with no request verb, phrased as a question about the miner ("what
  if xmrig ran on every core?") or with a defence or report word right
  before its name ("now that we found xmrig, keep it going"). The command
  such an ask leads to is still screened: a miner in a command an agent runs
  is still refused.
- **A held lock no longer holds back the hook's verdict.** The hook records
  each decision before it answers, and one of the locks that write takes was
  waited for with no time limit, so any account able to open that lock (the
  guarded agent's own included) could keep the hook from answering at all.
  Every lock the record takes is now waited for at most 100 ms: the verdict is
  returned as normal, and the skipped record is reported as a recording
  outage, `graph_lock_timeout`. Agent configuration writes give up after 2 s
  and say which lock was held, and so does the agent-policy lock
  (`~/.config/innerwarden/agents.lock`) after 5 s: `enforce`, `dry-run`,
  `agents connect` and `disconnect`, `setup`, `upgrade`'s rewiring and the
  dashboard's auto-connect all take it first, and a holder that never let go
  kept each of them waiting for good. `innerwarden observe` gives up after 1 s, and
  an ask it could not hold is recorded at once with its outcome unknown.
- **One large tool result no longer clears what the MCP proxy remembers.**
  The proxy keeps the long values of each tool result so that a later call
  carrying one is flagged (`AG-TAINT`). A single large result, such as an
  image read or a file of many short words, used to push out every value kept
  before it. The newest results are now kept whole; each older one keeps a
  sample of up to 4 KiB, its network destinations (URLs, e-mail addresses,
  `host:port`) first, then the rest drawn by a key chosen per proxy; a value
  over 256 bytes is kept by its start, which still matches a call that
  carries all of it. The store stays bounded, at about 1.1 MiB per proxy.
  What a result's author still decides is how much of their own result
  competes for its share: once the store is full, the next maximal result
  the agent reads cuts a result to its share, and a page padded with other
  destinations keeps only some of them. A value is found by its hash, so a
  session that lists thousands of names under one directory no longer slows
  every message the proxy relays; the search of one call is bounded, and a
  call whose arguments cannot be checked in that bound is refused
  (`AG-TAINT`) rather than passed unchecked.
- **Each MCP proxy uses about half the memory.** A proxy compiled every rule
  in the shipped corpus as it started, about 47 MB before it had screened a
  message, half of it rules for model prompts that a proxy never applies.
  Each rule is now compiled the first time something it applies to is
  screened, before that first verdict is given: a proxy starts at about 6 MB
  and, once tool calls and results have passed through it, holds about 25 MB
  where it held about 52 MB (Linux x86_64). The verdicts are unchanged.
- **The MCP proxy no longer refuses every `write_file`.** ATR-2026-040 matched
  the tool's name, so in guard mode (the proxy's default) every write through
  a filesystem server was refused, an ordinary one inside its allowed
  directories included, while the same server's `edit_file` and `move_file`
  were not checked at all. The rule no longer looks at the name. A tool call
  that may change a file granting privilege or a login, holding code that
  runs as root, or carrying the guard itself, is refused instead
  (`AG-PRIV-WRITE`), whichever tool makes it and however the path is spelled
  (`/etc//sudoers`, `/tmp/../etc/cron.d/x`, `/private/etc/...`, `file://`):
  the sudo, doas and polkit rules, PAM, accounts and groups, SSH keys and
  server settings, root's home, the dynamic linker's preload list, system
  cron jobs and logrotate, boot services and systemd's defaults, the login
  scripts every account runs (`/etc/profile`, `/etc/profile.d`,
  `/etc/bash.bashrc`, `/etc/environment`, ...), network dispatcher scripts,
  udev and kernel module rules, kernel settings (`/etc/sysctl.d`), the
  package manager's hooks and install scripts, the system's programs and
  libraries, and the guard's own wiring: the agent settings that carry its
  hook (`.claude/settings.json`), every MCP configuration it wraps
  (`.claude.json`, a project's `.mcp.json`, `.cursor/mcp.json`,
  `.codex/config.toml`, `.gemini/settings.json`, `openclaw.json`), the
  OpenClaw hook and plugin `observe install` lays down, and its own
  configuration (`~/.config/innerwarden`, `/etc/innerwarden`,
  `/var/lib/innerwarden`). Only a path where the call writes (an argument
  such as `path`, `source`, `destination`, `file`) is judged against every
  one of these; a single path anywhere else (an argv entry, an unusual
  argument name) is judged against all but the system's programs, and a
  sentence, a search query or a command line is not taken for a target. The
  filesystem server's read-only tools, and any tool its server declares
  read-only (`readOnlyHint`), may name these files. What is left open: a
  write tool whose target argument has an unusual name is not held to the
  system's programs; a relative path (and `~/`) is held only to what is the
  same in every directory (`.ssh`, the agent settings), so `etc/sudoers.d/x`
  sent to a server working in `/` is not judged; Windows paths are not
  judged; links are not followed; and the configuration of another program
  that runs as root (a web server's, a container runtime's) is left to the
  other rules.
- **`innerwarden agents` and `status` report the mode each MCP proxy runs in.**
  The mode was guessed by searching the agent's configuration for the words
  `advisory`, `warn`, `guard` and `kill` anywhere in it, so a log level or a
  server's own argument could decide it, and a wrapper set to
  `--mode=advisory` beside any other `"guard"` was listed as enforce while it
  only recorded. Each wrapper's arguments are now read the way the proxy reads
  them, the way the dashboard already did, and a flag's value is never taken
  for the mode (`--label --mode=guard` is a label). A wrapper whose last
  option before `--` is a flag waiting for its value is listed as not guarded:
  the proxy takes that `--` as the value and runs the options written after
  it. A wrapper whose proxy refuses one of its words (`--verbose`) exits
  before its server starts, and is listed as not guarded. Only a command
  named `innerwarden`, `iw` or `iw-guard` is taken for the guard: any name
  that began with `innerwarden` counted, so a script under such a name was
  listed as the guard in enforce mode while it ran the server unscreened.
  Such a server is now listed as not guarded, and connecting the agent wraps
  it in the real proxy. The configuration is read, not the binary: a program
  written under one of the guard's own names is still taken for it. A
  generic MCP client now shows the mode of its own configuration: it showed
  none, and one kept in `~/.claude/` showed Claude Code's.
- **A loop-breaker finding names the risks a loop is.** `AG-ASI09-BREAKER`
  carried no OWASP Agentic class, so its case read "OWASP Agentic: none",
  and its id points at ASI09, human-agent trust exploitation, which a loop is
  not. It now names ASI02 (tool misuse and exploitation) and ASI08
  (cascading failures) in its record and on its case. The id is unchanged,
  so an alert rule written against it keeps matching.

## 1.5.1 - 2026-09-30

### Fixed

- **A hook whose binary is gone is no longer "on".** `status`, `agents` and the
  dashboard now say so, name the missing path and the `innerwarden install`
  that fixes it. A week-old record no longer proves commands reach the guard,
  and auto-connect logs a change once, not every minute.
- **Auto-connect never writes a hook naming a binary that is gone.** After an
  in-place upgrade on Linux, or once a build is cleaned, the dashboard's
  background setup could point a hook at a path that no longer runs. It now
  writes nothing and says once that the dashboard needs a restart.

## 1.5.0 - 2026-09-30

### Added

- **A dashboard you can read at a glance.** `innerwarden dashboard` now opens
  on five pages in the same design as the full product: Overview (what your
  agents did, messages sent to your agent, and what this machine does not
  watch), Protection (what Community covers here, with what it refused for
  you since the guard's log began), Cases, Agents and Tokens.
- **Cases.** Every command or tool call the guard flagged is a case with three
  answers: what happened, what InnerWarden did (seen, decided, enforced,
  verified), and what you can do, as the exact `innerwarden` command. Runs of
  one reason fold into one line; filters and links live in the address.
- **An honest path to Active Defence.** At most one offer per page, tied to
  the case on screen, dismissible, never a lock or a blur. Where Active
  Defence is installed, the offer is one line saying so.

### Changed

- **Destroying the host's audit trail is HIGH**, not MEDIUM, and a denied
  secret read is no longer MEDIUM.
- **Counts say what they count.** One timestamp format, one count per
  session on every screen, and a partial read says "at least N".

### Fixed

- **rustls 0.23.45** closes RUSTSEC-2026-0285.
- **The vendored ATR rules carry their MIT notice.**

## 1.4.9 - 2026-09-08

### Fixed

- **Windows: `innerwarden upgrade` now replaces the running binary.** It
  renamed the new file over the running `innerwarden.exe`, which Windows
  refuses (`Access is denied`), and then advised `sudo innerwarden upgrade`.
  The running image is now parked beside itself, the new one lands in its
  place, and the installer's `iw.exe` / `iw-guard.exe` copies are refreshed
  too. The advice on Windows names the real causes: another InnerWarden
  process, or a folder that needs an elevated PowerShell.

## 1.4.8 - 2026-09-08

### Fixed

- **The hook no longer lets a tool call it cannot read pass in silence.** Fed an
  empty stdin, non-JSON, or a shell tool call with no command string, the hook
  exited 0 and said nothing, so a payload shape it did not understand (an agent
  update, an encoding problem) would have let every command run unscreened. In
  enforce it now refuses such a call (exit 2, reason on stderr); in monitor it
  says the call was not screened (exit 1). Well-formed calls for tools that
  carry no command (Read, Edit) still pass untouched.

## 1.4.7 - 2026-09-08

### Fixed

- **Windows: the binary now starts on a stock machine.** `innerwarden.exe`
  imported `vcruntime140.dll`, which a fresh Windows without the Visual C++
  redistributable does not have; the installer said "Done" and the first
  command died with `STATUS_DLL_NOT_FOUND`. The C runtime is now linked in
  (`+crt-static`) and the release build fails if the exe still imports it.
- **Windows: the install command names `www.innerwarden.com`.** Windows
  PowerShell 5.1 does not follow the apex's 308 redirect; PowerShell 7 does,
  which is why the runners never saw it.

## 1.4.6 - 2026-09-08

Two things a new user meets in the first hour on a stock Ubuntu 24.04 host,
found by installing the way the site says to and running each command in
`--help`.

### Fixed

- **`innerwarden contain` on Ubuntu 24.04.** The jail died with
  `bwrap: setting up uid map: Permission denied`. The kernel there restricts
  unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns`)
  and the image ships no AppArmor profile for `bwrap`. `contain` now checks
  both before building the jail and, when it cannot, prints the profile that
  grants `bwrap` a user namespace and the `apparmor_parser` line to load it,
  then runs nothing. The sysctl stays as it was.
- **`innerwarden upgrade` on an up-to-date host** fetched the published
  binary, replaced identical bytes and reported "Upgrade complete". It now
  reads the manifest first and stops with "Already on the latest build", as
  `upgrade --check` already did. `--yes` still replaces the file.

## 1.4.5 - 2026-08-30

We ran the product the way a bank's security team would: 764 realistic commands,
built as nine independent batches and deliberately mixed. 310 that must be
refused, 357 that must run, 97 judgement calls. The benign half is the larger one
on purpose, because a guard that blocks real work gets switched off in week two.

                       before    after
    attacks blocked     48.7%    75.2%
    attacks caught      51.0%    78.7%
    ordinary work       96.6%    98.6%
    hard false positives    7        0

### Added

- **The guard now has a memory.** A value that arrives in a tool result and
  reappears as an argument later is the attack a stateless screener cannot see,
  because the second command is not wrong; its origin is. A `PostToolUse` hook
  carries results in, the session remembers what they contained for 30 minutes,
  and a command carrying one is held for review with the value and the source
  tool named. It never lowers a verdict: a command already refused stays refused.

  `innerwarden upgrade` now reconciles the hooks it wrote, so an existing
  install gets the observation half rather than a build that has the defence and
  a configuration that never invokes it.

- Detection for seven families that previously scored zero: cloud control-plane
  actions (audit trail, threat detection, IAM grants, public buckets, key
  deletion), data destruction, anti-forensics, persistence installs, Kubernetes
  escapes, untrusted software sources, and local credential stores and kernel
  hardening knobs. Every family ships its ordinary neighbours as pinned
  negatives, so `terraform plan`, `kubectl get`, `crontab -l`, `chmod 755` and
  `journalctl -u` stay untouched.

- Certificate verification being switched off is now visible: `--trusted-host`,
  `GIT_SSL_NO_VERIFY`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `curl -k` and the rest.

### Fixed

- **An agent could switch its own guard off.** A wildcard force-allow,
  `dry-run`, `mute`, and deleting or rewriting the hook configuration all
  returned `allow` at risk 0, while the loud routes were already refused.
  Confirmed by effect: with a wildcard allow in place the hook returned exit 0
  for a command it refuses a second earlier. Every quiet route now denies, and
  reading the configuration still does not.

- Twelve false positives, collapsing into four rules. `eval "$(...)"` alone was
  four of them and fires on `kubectl completion`, `direnv hook` and
  `ssh-agent -s`. Also IMDSv2's token handshake, which is the hardened path AWS
  tells people to use; `shred` of a runtime token, where refusing teaches people
  to leave it on disk; `/etc/ssl/certs/*.pem`, which is public by definition;
  and `.env.example`, which is a committed template.

### Performance

- The hook is a one-shot process, so every tool call pays to compile whatever
  regexes it touches. A literal gate now decides each family before a single
  regex is built, and normalization is lazy. Measured over 40 invocations
  against 1.4.4: **5.45s to 4.00s**, with detection unchanged.

## 1.4.4 - 2026-08-30

The dashboard opened with five counters and left the arithmetic to the reader,
and the graph behind it was quietly losing most of what it recorded.

### Fixed

- **The graph dropped 88% of the record.** `drop_oldest` selects the oldest
  nodes, a session anchor is always older than every command under it, so the
  first prune to reach the anchor removed it and `retain` then removed every
  `ran` edge that pointed at it. The commands were still stored and nothing
  could reach them. Pruning now keeps session anchors, `cases_page` recovers
  commands whose edge is gone by their `cmd:{session}:` prefix, and a session
  whose anchor was pruned is rebuilt from the ids that survive.

  Measured on one real store before and after: activity total 1,951 to 15,707,
  sessions 4 to 6, and the needs-review filter 6 to 136. Nothing new was
  recorded; that is all record that was already on disk and unreachable.

- **The screen did not answer the question people open it with.** A new
  headline computes the conclusion instead of printing counters: whether
  anything needs the reader, and what to do about it. Monitor mode is reported
  as the choice it is rather than as a failure, because calling it a fault
  pushes people to enforce before they are ready.

- **Evidence moved behind a switch instead of shouting.** "Configured, not
  verified", "Authority unknown", "Partial evidence" and the rest were each
  true and together read as a product that does not know what it is doing. They
  now live behind **Show technical detail**, off by default and persisted. The
  line that is not crossed: a good state may hide its provenance, a bad one may
  never hide its existence. Queued work, failures and hosts needing attention
  stay visible in both registers, and there is a test that refuses "Protected"
  while anything is queued.

- **A session was headlined by its own UUID.** The list read as four
  indistinguishable hex strings, one of which was the session the reader was
  sitting in. The heading is now the time range the run covers; the id stays on
  the card for correlating with a log.

- Hidden technical markup is not mounted rather than hidden with CSS, and
  nothing extra is fetched for the technical register, so the switch costs
  nothing while it is off.

## 1.4.3 - 2026-08-24

Three things the product said that were not true, all found by walking a real
install on a clean machine. None of them let an attack through; all three cost a
new user their first ten minutes, which for a security tool is worse.

### Fixed

- `innerwarden uninstall` said "removed" over a machine it had half-uninstalled.
  Without root against an npm install it destroyed the hook, the config
  directory and the API key first, then failed to unlink the binary, then
  printed a success line and exited 0. The next `innerwarden` call answered
  "linux-x64 IS supported, but its binary is not installed", so the product
  reported itself broken one command after reporting success.

  The remedy it offered was wrong twice: `rm <path>` needs exactly the root the
  run had just proven it did not have, and on an npm copy it is the move this
  crate already documents as wrong, because npm owns the `innerwarden` and `iw`
  launchers too. `upgrade` has consulted `managed_by` before acting since 1.4.0;
  `uninstall` never did.

  It now decides before it destroys. An npm-managed copy is left to
  `npm uninstall -g innerwarden`, which removes the binary, both launchers and
  npm's record of them. A direct install that cannot be written to says so up
  front, while the machine is still intact. Anything left behind is reported as
  left behind and exits non-zero. `--dry-run` previews the same decision, rather
  than listing a path the real run must not touch.

- The npm launcher's recovery instruction was the command that fails. When the
  platform binary is missing it is read at the exact moment the reader has
  nothing working, and it said `npm uninstall -g innerwarden && npm install -g
  innerwarden`. On a distro-packaged Node, npm's global prefix is
  `/usr/local/lib/node_modules` and root-owned, so on Linux that exits EACCES.
  It now leads with the installer that needs no root, per platform, and still
  offers npm with the sudo requirement stated.

  The test covering that message asserted it contained
  `npm install -g innerwarden`, which is a substring of the very command being
  handed out. It passed before the fix and would have passed after it, either
  way. It has been replaced rather than added to.

- `innerwarden -v` answered "unknown command `-v`" and then printed the whole
  help. `--version`, `-V` and `version` all worked; the one short form people
  actually type was the one missing, and the failure path buried its own reason
  under 61 lines of usage that wrap to 88 on an 80-column terminal. `-v` now
  answers, and an unrecognised token gets its reason plus a pointer to `--help`
  instead of the manual. `--help` itself is unchanged.

## 1.4.2 - 2026-08-24

Setting up Telegram alerts is now something the wizard does, rather than
something it asks you to go and do elsewhere.

### Fixed

- The setup wizard lost the answer to its own question. Answering **yes** to
  "Get notified when a command is flagged?" led to a channel picker where
  pressing ENTER selected nothing, and the wizard accepted the empty result,
  printed a note that read like an optional aside, and moved on. Nothing was
  written to disk. Someone who asked to be notified was not notified and was
  never told.

  Telegram now starts ticked, so ENTER alone does the obvious thing. An empty
  selection is explained once (SPACE toggles) and asked again. If nothing is
  chosen the wizard says **alerts are OFF** instead of implying success, and the
  same applies when a channel is picked but left blank. Both recovery lines now
  name the Telegram flags rather than suggesting a Slack webhook regardless of
  what was asked for.

### Added

- The wizard fetches your Telegram chat id instead of demanding it. It used to
  say "then get your chat id" and offer no way to get one, so finishing meant
  leaving the wizard to call the Telegram API and read JSON by hand. It now asks
  `getUpdates` and reports the id it found. A bot nobody has messaged yet has no
  chat to reply to, which is the normal state seconds after @BotFather hands over
  a token, so that case is explained and retried rather than reported as a
  failure. A rejected token says it was rejected. Typing the id by hand stays
  available throughout: an automatic step that can fail must not become the only
  way through.

## 1.4.1 - 2026-08-24

Three places the product asserted one thing and behaved otherwise. None let an
attack through; all three cost a new user time or trust, which is worse for a
security tool than a missing feature.

### Fixed

- `innerwarden notify --slack-webhook <url> --test` tested the wrong channel. It
  planned the test against the configuration from BEFORE the write, so on a
  fresh config it sent nothing and said nothing, and on a host that already had
  a channel it tested the OLD one and printed a success line for a channel it
  had never contacted. Setting a channel and testing it in one command is the
  obvious thing to do, `--help` suggests it, and the setup wizard does it.

  The test covering this was named `..._fires_the_just_set_channel` and asserted
  that the channel already in the file fired, not the one just set. The name
  promised the fix and the assertion pinned the bug.

- `innerwarden status` always reported the local dashboard as not running. Two
  constants were both called `DEFAULT_BIND`, in different modules, with
  different ports, and the status probe used the `serve` one to look for a
  dashboard that binds the other. The first command written for beginners was
  wrong about the second thing it says.

- `innerwarden uninstall` left every non-Claude agent calling a binary that no
  longer existed. It removed the Claude Code hook only, while Cursor, Codex and
  Gemini are wired by writing this binary's absolute path into their MCP config,
  and then it deleted the binary. `innerwarden agents disconnect`, the command
  that would have fixed it, went with it. Uninstall now unwires every agent
  first, through the same entry point `agents disconnect --all` uses.

- The npm launcher told supported platforms they were unsupported. After an
  uninstall (or an install with `--ignore-scripts`) the launcher survives
  without its binary and reported "no prebuilt binary for linux-x64" one line
  before listing linux and x64 as supported. It now distinguishes a missing
  binary on a published platform from a platform that has no build, and names
  the reinstall.

## 1.4.0 - 2026-08-23

The first ten minutes. A new user could install this, follow what it printed,
and end up unprotected without an error anywhere.

A minor rather than a patch because `upgrade` gained exit codes and the bare
`innerwarden` command prints something different on a machine with no config.

### Fixed

- `cat ~/.aws/credentials` was a review, not a deny, while `cat deploy.pem` was
  a deny. The hard list was keyed on file EXTENSION rather than on what the file
  holds, and a `.pem` is frequently a public certificate. The credential file is
  now scored as one; `~/.aws/config` beside it stays a review, because region
  and output settings are read legitimately and denying them was never the
  intent.

- `innerwarden allow --help` wrote the literal string `--help` into the
  guardrail's own bypass list and printed success. `check "--help"` then returned
  ALLOW with `[suppressed: allow --help]`. `mute --help` was worse: it lands in
  mute categories, and a muted category suppresses every rule in it against every
  command. `setup --help` ran the wizard.

  Help is now answered before dispatch for all 24 subcommands. `check` keeps
  screening: its argument IS the command being examined, so `--help` counts as
  help only when it is the sole non-output-flag argument, and
  `check rm -rf / --help` still denies.

- `agents connect` said nothing about restarting. The hook is read only at agent
  startup, so a user returned to a running session believing it was screened when
  it was not. Every sibling path already said it. Silent false protection is
  worse than an error.

- `status` was dispatched and appeared nowhere in `--help`, and it hardcoded the
  guard mode as unknown while the data it needed was already in hand. The result
  was that there was NO configuration in which `status` reported everything as
  fine: the command written for beginners could never tell one they were done.
  It now appears in help, reads the mode, probes the dashboard, and distinguishes
  "nothing recorded yet" from "the record could not be read".

- A fresh install reported itself broken. A directory that did not exist yet was
  treated as unwritable, so `innerwarden graph` on a new machine printed
  "InnerWarden has not recorded for 0 seconds (actions lost,
  graph_directory_unwritable)" and the dashboard served the same. A fresh box is
  not a broken one.

- `upgrade --check` fetched a checksum, discarded it, and told you to upgrade
  whatever the answer was, including when already current. It now reads the
  published manifest and says which it is.

- `upgrade` silently fought npm. A binary under a user-owned npm prefix upgraded
  with no warning and the next `npm install -g` reverted it, with no message from
  either tool. The site itself recommends that prefix. It now refuses unless
  forced.

- `uninstall` removed the Claude hook and left every other agent's MCP wiring
  pointing at a deleted binary.

### Changed

- A bare `innerwarden` on a machine with no configuration prints six lines saying
  nothing is wired yet, with the two commands to run, instead of 24 subcommands
  with `setup` on line one. `innerwarden --help` is unchanged.

- `upgrade` exits 2 when it refuses an npm-managed copy, and `upgrade --check`
  exits 1 when it cannot determine the published version.

### Internal

- `ureq` 2 to 3. The migration mattered rather than the version: ureq 3 moved
  timeouts off the request builder onto the agent, so the obvious port silently
  leaves every network probe unbounded, and its error enum went from two
  variants to ten, so an exhaustive match keeps compiling while losing cases.
  Both are now asked as questions (`is_an_answer`, `status_of`) in one place.

- CI now refuses an em dash on any line a change adds. The paid repo's version of
  that gate had been green since it was written without ever running: a shallow
  checkout has no `origin/master`, and its missing-base branch exited 0. This one
  fetches the base and refuses if it cannot.

- Coverage is measured with a floor derived from a measurement rather than
  chosen, browser journeys run instead of being counted, and the updater and
  release verifier are exercised rather than having their own source read back.

## 1.3.7 - 2026-08-21

Posture reporting. The dashboard could describe a control as working when
nothing had confirmed it, and a fresh install could read as a fault.

### Fixed

- The headline no longer counts an unconfirmed control as working (#108).
- A layer's sentence can no longer contradict the badge above it (#107); the
  pill, the row and the gap list now tell one story (#106).
- The API validator stopped discarding the layer disposition (#105).

### Added

- Posture says what needs an operator and what is simply fine, so a fresh
  install is not reported as a problem (#104).

## 1.3.6 - 2026-08-20

### Fixed

- `uninstall --dry-run` uninstalled instead of previewing (#101).
- The agent view shows which mode the guard is in, and `--help` documents
  dry-run (#100).

## 1.3.5 - 2026-08-20

### Fixed

- `status` no longer blames a config file that was never read (#97).
- `upgrade` names the command that actually upgrades this install, which
  differs by install channel (#96).

### Changed

- One tag now moves every install channel, instead of each being cut by hand
  (#95).

## 1.3.4 - 2026-08-20

### Fixed

- A fresh install is no longer reported as a broken one (#93).
- Absence of a signature is not absence of an agent (#89).
- An empty substitution no longer hides the command behind it (#86).
- The guard stopped reading data as if it were a command, and now names the
  safe way out (#85).

### Added

- One command that says whether this install is actually protecting you (#90).

### Changed

- CI: a mutation sweep that finishes and that fails when it should (#87); the
  apt lock no longer makes every Linux run a coin flip (#91); a retry loop no
  longer outlives the step it runs inside (#92).

## 1.3.3 - 2026-08-16

Two screening fixes, both found by running the shipped build against real
work rather than against the test corpus. Each was verified by reverting the
fix and watching the new test fail.

### Fixed

- **The tamper rule no longer crosses command boundaries.**
  `check_security_tamper` tested the removal verb and the InnerWarden path
  against the whole command string independently, so the two never had to be
  related to each other. Any ordinary cleanup step that shared a line with a
  read of our own config was denied at score 60 — a rename of an unrelated
  file beside a `grep` of `agent.toml`, a `sqlite3` query beside a removal
  under a temp directory. In none of them does the removal verb name an
  InnerWarden path, yet all were reported as *"disabling or tampering with
  security monitoring"*.

  That is the worst direction for a false positive to point. It lands on the
  person doing support, during an incident, and it teaches them that the
  tamper verdict is noise — the one verdict that has to keep its credibility.

  `destructive_rm_root` already refused to cross command boundaries for
  exactly this reason, and the tamper rule now uses the same segmentation:
  the verb and the path must belong to one command. Genuine self-tamper
  (removing or moving our own binary, config or state) still denies, whatever
  else shares the line.

- **Credential hunting is flagged, not just credential reading.** A command
  that goes looking for secrets across a broad root now scores, where
  previously only a read of an already-known secret path did.

## 1.3.2 - 2026-08-13

No behaviour change for users. This release carries build-supply-chain and
test-corpus hygiene, plus the CI repairs that make the nightly deep checks
mean something again.

### Security

- **postcss forced past GHSA-fxqj-rqcc-2cmp.** A version at or below 8.5.22
  reads arbitrary `.map` files from an attacker-controlled `sourceMappingURL`
  when `from` is unset. It is a development dependency of the dashboard build
  and never reaches the shipped binary, so this is hygiene rather than an
  exposure, but the lock now resolves to 8.5.26 through an `overrides` entry.
  The built bundle is byte-identical.
- **The Google API key fixture in the ATR corpus is now unmistakably a
  fixture.** It lived in the `true_positives` block of the rule that detects
  leaked API keys, next to other synthetic examples, and had an open GitHub
  secret-scanning alert against it since 2026-07-23. It still matches the
  rule's own pattern, so the rule keeps being tested.

### Fixed

- **The nightly undefined-behaviour check finishes again.** The `miri` job had
  no time budget, so it ran to GitHub's six-hour platform cap and was killed
  every night from 2026-08-06 to 2026-08-12, reporting "cancelled" — which
  reads as harmless. Nothing was checked for UB for a week and nothing said so.
  Three tests build 20k-node graphs to prove a byte budget, which an
  interpreter cannot do cheaply; they are skipped under miri, and a check now
  fails when a cap-scale test is added without that skip. miri also carries an
  explicit timeout, so a future hang fails visibly. Running it for real found
  no undefined behaviour.
- **The nightly mutation run reports again.** `cargo-mutants` hit its own job
  timeout, which killed the report upload with it, so every night produced
  nothing. It now stops itself inside the job budget and ships a partial report
  that says it is partial.

## 1.1.0 - 2026-08-06

### Security

- **The updater no longer runs a script it downloads.** `innerwarden upgrade`
  fetched an installer over the network and piped it to a shell, so an upgrade
  trusted whatever that endpoint served that day and no signature was ever
  checked. It now downloads the release asset for the running platform, verifies
  its SHA-256 and its Ed25519 signature against a public key compiled into the
  binary doing the upgrading, and swaps it in with an atomic rename beside the
  target. Either check failing means nothing is written.
- **Packaging verifies the bytes before it packages them.** The npm and
  `.deb`/`.rpm` build paths downloaded the release binaries and wrapped them
  unchecked, so a compromised release host reached users through three channels
  at once. Both paths now verify SHA-256 and Ed25519 for all six targets before
  the bytes enter a package, and treat a missing sidecar as an error rather than
  a skipped check.
- **A local model can no longer soften a rules verdict.** The optional LLM second
  opinion could downgrade a rules `deny` to `allow`. The effective verdict is now
  the stricter of the two, the command under review is delimited as untrusted
  input in the prompt, and the response records which layer decided.
- **Publishing is gated on green CI for the exact commit.** A tag on a commit
  whose tests were failing used to publish anyway, with npm provenance attesting
  it.

### Added

- **Guards the agent you actually run, not just Claude Code.** `install` used to
  refuse every other agent with "only 'claude-code' is supported today", which on
  a host running anything else read as "InnerWarden cannot protect this". Every
  known agent now resolves to a mechanism and a command that works: a PreToolUse
  hook where one exists, automatic MCP wiring through `innerwarden agents
  connect <agent>` where it does not, and `innerwarden contain` for agents with
  no cooperative surface at all. Claude Code, Cursor, Codex, Gemini CLI and
  OpenClaw wire automatically; wiring is reversible with `agents disconnect`.
- **OpenClaw support.** Its MCP servers live under a nested `mcp.servers` table
  that the config editor could not find, so an OpenClaw install looked unguardable.
  Sibling keys and unrelated settings are preserved, and a config that is not
  strict JSON is refused rather than rewritten.
- **Per-session behaviour in the command hook.** Call rate and repeated access to
  sensitive paths are now tracked across the one-shot hook invocations that make
  up a session, so a pattern that only exists across commands is visible to the
  verdict.
- **`innerwarden host <command>`.** Four verbs exist in both this guardrail and
  the paid Active Defence host layer. They run here, say so when the host layer
  also has one, and `host` reaches that version explicitly instead of it being
  silently shadowed.
- **A recording-health surface.** `innerwarden graph` and
  `/api/guard/record-health` report when the local record has stopped recording
  and for how long, rather than a dashboard quietly showing older and older data.

### Fixed

- **Recording stopped once the graph passed 16 MiB, and said so only on stderr.**
  The store was verified against the size limit meant for agent configuration
  files, and the verification read runs before the prune that would have brought
  it back under, so an install that crossed the limit never recorded again. The
  store now has its own ceiling, prune enforces a byte budget and not just a node
  count, and command ids no longer collide after a prune (which silently
  overwrote surviving history). The outage is now reported where a human looks.
- **A quoted heredoc body is text, not code.** Writing a document that quoted a
  dangerous command, in a pull request body or an incident postmortem, was blocked
  as though the command were being run. Unquoted delimiters, real substitutions,
  and pipes into an interpreter are still read as code.
- **The dashboard tells the truth about what it knows.** It no longer reports a
  setup state it never determined, no longer tells a paid host it recorded
  nothing, distinguishes "unavailable" from "empty" and says which failure it
  was, and serves the agent and token-intelligence views in both editions.
- **Suppression changes are recorded.** `allow` and `mute` changed what the guard
  blocks and left no trace.
- **The hook stopped compiling rules that cannot match.** The ATR corpus was
  compiled in full on every tool call, including the 62 pattern-tier rules that
  declare a surface the shell path never presents. Filtering before compilation
  took the hook from 208 ms to 73 ms.

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
