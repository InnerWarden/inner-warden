# What InnerWarden does, in detail

The short version is in the [README](../README.md). This page holds the full
list, with every limit.

- Screens shell commands and MCP/tool calls before they run, and returns a
  verdict: `allow`, `review`, or `deny`. `innerwarden check` only reports
  it; the hook `innerwarden install` writes refuses, in the default
  posture of a new install, only the high-certainty class (see
  [The posture](#the-posture-what-an-enforcing-hook-refuses)), every `deny`
  with `--strict`, every `review` too with `--block-review`, and nothing
  with `--monitor`; the MCP proxy starts in `guard`, which refuses a
  disallowed call.
- Runs an MCP proxy: a man-in-the-middle in front of an MCP server that inspects
  every JSON-RPC message and can refuse a disallowed tool call inline. stdout
  stays pure MCP traffic, alerts go to stderr. It pins each tool's
  definition the first time a server lists it, and in `guard` and `kill`
  holds a tool whose definition changes, one that may be a rename, and,
  once the server has pins, one it never listed before, until you run
  `innerwarden mcp approve`. From the release after 1.6.15, in `guard` and
  `kill` it also refuses a resource read whose location names a credential (`internal://credentials`,
  `config://auth_tokens`) or is a secret store by its scheme (`vault://`,
  `env://`, `kv://`, `keyring://`, `keychain://`, `ssm://`, `secret://`,
  `secrets://`, `secretsmanager://`, `creds://`, `credentials://`, the cloud
  stores `aws-sm://`, `azure-keyvault://`, `gcp-secret://`,
  `secret-manager://`, and any scheme with `vault`, `secret` or `keyring`
  as a word of it, such as `x-vault://`; any location in it), also when the
  name is written in fullwidth letters: reading it is your call, as reading a
  credentials file in the shell is. A document, a source file, a count or a setting about a
  credential (`docs://credentials-guide`, `file:///repo/src/auth/token.rs`,
  `stats://tokens`) and a file in a folder that names one are read with an
  alert. In `advisory` and `warn` every one of these is alerted and passes,
  and so is every one in 1.6.15, in any mode.
- From the release after 1.6.15, MCP servers reached by URL go through the
  same proxy as local ones. `innerwarden agents connect` rewrites a JSON
  client's remote entry (`url`, Gemini CLI's `httpUrl`, `serverUrl`; a
  `type` of `http`, `sse` or `streamable-http`) into
  `innerwarden proxy --mode guard -- <address>`, and the proxy talks HTTP(S)
  to the server: Streamable HTTP, falling back to the older HTTP with SSE when
  the server answers the first POST with 400, 404 or 405 (or from the start
  for `"type": "sse"`). The calls get every check a local server's get
  (pinned definitions, effect and provenance, secrets in answers, the
  posture). The proxy opens no port and serves no TLS of its own: the client
  reaches it through a pipe, and it reaches the server with the system's
  certificates. The entry's headers travel in the wrapper's `env`
  (`INNERWARDEN_MCP_HEADER_1`, ...), redirects are not followed, no proxy from
  the environment (`HTTP_PROXY`) is used, an error names only the server's
  host, and an SSE
  endpoint on another origin is refused. `agents disconnect` writes the entry
  back with its address, key, type and headers. Limits: the proxy cannot sign
  in for the client, so an entry with `oauth`, `auth` or
  `authProviderType` is left as it was (and counted as not screened), and a
  server that asks for a sign-in the client would have done (HTTP 401) gets an
  error that says to put its token in the entry's headers; Codex's TOML and
  Goose's YAML remote servers are not carried yet.
- From the release after 1.6.15, a tool call whose tool's name says it
  deletes, moves or writes (`delete_directory`, `move_file`, `write_file`,
  `fs.rmdir`, ...) is refused in `guard`, `strict` and `kill`
  (`AG-PROTECTED-TARGET`) when the path it names, as a whole argument, is the
  root, a folder of the operating system (`/etc`, `/usr` above
  `/usr/local/<dir>`, `/bin`, `/lib*`, `/boot`, `/System`,
  `C:\Windows`, at any depth), a top folder of the system tree or one level
  into it (`/var`, `/var/lib`, `/opt/app`, `/mnt/backup`, `/Volumes/disk`),
  a whole home (`~`, `/home/u`, `/Users/u`, `/root`) or a store of keys
  (`.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.pki`,
  `.password-store`, `.config/gcloud`, `.local/share/keyrings`,
  `Library/Keychains`). `advisory` and `warn` record it. Before,
  `delete_directory {"path": "/etc"}` matched only a rule that does not refuse.
  A relative path is not judged, and deeper paths (`/var/www/site/x`,
  `/usr/local/bin/tool`, `/tmp/x`) are ordinary work.
- The MCP proxy's default posture (`guard`, from the release after 1.6.15): a
  rule that matches a tool call by the tool's name or by its argument names
  alone (ATR-2026-098 on every `send_money` and every `"recipient":`,
  ATR-2026-040 on every `delete_file`, ATR-2026-012 on an `admin_` prefix)
  forwards the call with a warning and a record instead of refusing it. Such a
  rule refused the person's own payment, message or delete as it refused an
  injected one (25 of 339 calls AgentDojo's users asked for). The call stays
  refused when a value it carries, of any length (a file id too), was said
  by a server this session as a whole word, or the session was not read
  whole; when a value it carries matches the rule too; when a value is or is
  under the root, a top-level system folder (`/etc/passwd`), a folder of the
  guard's, a home itself or a dot entry at the top of a home
  (`~/.ssh/authorized_keys`), read after `..` is taken out (`/private` is a
  system folder; a relative path that climbs above where it starts counts); when a value
  is written like a shell line or a link (`|`, `;`, `&&`, a backquote,
  `$(`, `${`, a URL); when the call runs a command line; and when anything else
  refuses it (a secret read, a privileged write, a tool held since its
  definition changed, a shell line judged `deny`, the loop breaker). A
  value not said by any server proves nothing about where it came from,
  which is why the call is warned about and recorded, not passed in silence.
  `--mode kill` keeps every refusal of before; the agent-guard library also
  has a `strict` mode that does, which the `innerwarden proxy` command does
  not take yet.
- AI Jail: run an agent in a constrained profile so a screened-and-denied action
  is stopped rather than merely flagged. Linux (bubblewrap) and macOS
  (sandbox-exec) only; `contain` exits with an explicit error on Windows rather
  than pretending to isolate. On Linux, where the host takes it, every jail
  starts its programs under a seccomp filter that refuses `TIOCSTI` and
  `TIOCLINUX`, the terminal commands that push input into your terminal, and
  new btrfs or bcachefs subvolumes and snapshots. The jailed command gets
  only the variables a shell needs (`PATH`, `HOME`, `USER`, `LOGNAME`,
  `SHELL`, `LANG`, `LC_*`, `TERM`, `TZ`, `TMPDIR`, `COLORTERM` and the proxy
  settings `HTTP_PROXY`, `HTTPS_PROXY`, `FTP_PROXY`, `ALL_PROXY` and
  `NO_PROXY`, in capitals or lowercase); `--pass-env NAME` hands in any other, and `contain` names every
  variable it kept out, never a value.
  `--agent openclaw` (Linux) jails OpenClaw instead of Claude Code: the jail
  shows `~/.openclaw` writable (sessions, databases, workspace) and, read-only
  over it, every place OpenClaw 2026.9.7's documentation says it loads code
  or instructions from at its next start, where the jail shows it writable:
  its config `openclaw.json`, its `.env`, its plugins (`extensions`), managed
  hooks (`hooks`), managed skills (`skills`) and old cron store (`cron`); in
  each workspace (`~/.openclaw/workspace`, `workspace-<id>`, the ones the
  config names) its plugins (`.openclaw`), hooks (`hooks`) and skills
  (`skills`, `.agents`); each agent's `agents/<id>/agent/workshop-skills`;
  and the config's `plugins.load.paths`, `hooks.internal.load.extraDirs` and
  `skills.load.extraDirs`. Each is a mount point of its own, so a program in
  the jail can neither change, remove nor rename it, nor turn the guard plugin
  off or plant a plugin, a hook or a skill for the next start. The launcher
  makes each one that is not there (empty, owner only), and refuses to start
  where one is a link or is reached through one, where a load path the config
  names is not there, where the config uses `$include` (its files sit in the
  writable folder) or is not plain JSON. A settings change, or a config
  migration the gateway would write at its start, is refused inside the jail.
  What OpenClaw keeps in its state database (sessions, scheduled jobs) stays
  writable: the gateway needs it, so a job the jailed agent schedules through
  OpenClaw itself still runs at the next start. Automatic updates are off in the jail
  (`OPENCLAW_NO_AUTO_UPDATE=1`). It starts only with the guard plugin wired
  (`innerwarden agents connect openclaw`), keeps the plugin's mode
  (`innerwarden enforce` and `monitor` set it, never a `contain` flag), and
  refuses `--pass-env` of any `OPENCLAW_*` variable (and the older
  `CLAWDBOT_*`, `CLAWD_*` and `MOLTBOT_*`) and a command with OpenClaw's
  `--profile` or `--dev`, which move its state. `~/.ssh`, `~/.aws` and `~/.docker` stay out, as in
  every jail, and so do docker's and an ssh agent's sockets (no `/var`, an
  empty `/run` and `/tmp`). Not on macOS in this version.
  The hook inside the jail keeps its record of decisions in the project, in
  `<project>/.innerwarden/graph.json`. On Linux that folder is read-only
  inside the jail: the hook hands each decision, and each line it keeps
  beside the record (a suppression or rule changed, an agent's decision),
  over a socket to `contain`, which runs outside the jail and writes it. A
  program in the jail cannot change or remove a decision already written,
  and `IW_GRAPH_FILE` does not send the hook's decisions or those lines
  anywhere else. The socket's folder is in `$XDG_RUNTIME_DIR`, else in
  `$TMPDIR`; one inside a folder the jail can write is refused. A program
  in the jail can still add records of its own through that socket: the
  record says what the jail reported, not what the host saw. `contain`
  writes its own instance id and project name on each one, never a host
  decision the jail names, and marks every decision and line it writes for
  the jail `reported_by: jail`: the hook's and a program's cannot be told
  apart. It writes at most 512 at once and 64 a second after that, and that
  rate is shared: a program in the jail that sends decisions of its own can
  spend it, and the hook's next decision is then not written (counted, and
  said on the hook's stderr). It holds at most 64 MiB of reports being read
  at once. What it does not write (a report turned away with too many
  connections waiting and not sent again, a connection that sends no report
  within 2 seconds, over that rate, a write that failed) is counted in the
  record's health, which `innerwarden graph --stats` and the dashboard
  show, and in one `guard.jail_record_lost` line when the jail ends. That
  count holds what reached `contain`. A report that never reached it (the
  socket's queue full for the hook's whole wait, or the connect not done in
  that time) is not in it: it is said on the hook's stderr only. The hook
  waits at most 3 seconds for its record to be taken; a record not taken
  never changes the hook's verdict or its exit code (a refusal still exits
  2). The hook takes the jail's record channel only where the launcher's
  mount is there: a folder of that name made inside the jail is not it,
  and the hook then records as outside a jail. `contain` opens the channel
  only in a jail whose seccomp filter keeps user namespaces closed, a jail
  without `--identity` included: with them open a program there could
  mount a socket of its own where the hook hands its decisions. Every
  Linux jail therefore runs under the identified filter where the host
  takes it (Linux 4.8 or later, bubblewrap able to hand it in): no new user
  namespace, no joining one, and no call through another ABI (a 32-bit
  program does not run), so a nested sandbox (bubblewrap, rootless Podman)
  does not start inside the jail. Where the host does not take it, the
  record channel is not opened. The record's size cap
  still pushes its oldest decisions out. An entry at `.innerwarden` that is
  not a folder of the launching account is moved aside first. Where the
  folder or the socket cannot be had, or the jail's user namespaces cannot
  be closed, `contain --identity` refuses to start; a jail without
  `--identity` runs with the record writable and says so.
  On macOS the sandbox gives no such folder. The guard refuses a shell
  command or a file tool that writes, moves or removes the project's
  `.innerwarden` only when the name is written literally (`.innerwarden`,
  `../.innerwarden`, an absolute path to it). These still pass: a glob
  (`rm -rf .inner*`, `mv .[i]nnerwarden x`), a link made to the folder
  (`ln -s .innerwarden r && rm r/graph.json`), removing the project around
  it (`cd .. && rm -rf proj`, `rm -rf "$PWD"`), and a program run there
  (for example `python3 -c` code that opens the file). On macOS the record
  is not tamper-proof.
  On Linux `contain` also tells each refusal it writes for a jail beside
  your own record (the `guard-events.jsonl` next to the graph
  `innerwarden graph` reads, usually in `~/.config/innerwarden`), as a
  `guard.blocked` line marked `reported_by: jail`. The jail hides that
  folder, so on a host with InnerWarden Community alone a refusal inside
  the jail was in the project's record only, which nothing on the host
  reads. Only refusals are told, and only where the record channel is open.
  That line is the jail's word: its command is cut to 1024 characters and
  its session to 128, each control character a space, and its
  recommendation is `deny`, `review`, `allow` or empty. The host's record
  takes at most 32 of one jail's refusals at once and one a second after
  that; the rest are counted and told as one `guard.jail_blocks_not_told`
  line when the jail ends (the project's record still holds every one). A
  program in the jail can add refusals of its own there too, within that
  rate.
  The launcher's records of its instances
  (`$XDG_STATE_HOME/innerwarden/instances`, else
  `~/.local/state/innerwarden/instances`), which the dashboard and the
  host's agents read, are out of every jail's writing: hidden in a jail
  with `--identity`, read-only in one without (made first where they are
  not there yet, and the folders above them in `~/.local` held in place).
  Before a jail without `--identity` starts, `contain` checks that folder:
  one another account owns or others may write is moved aside whole
  (`instances.set-aside-...`) and made again, and every entry in it that is
  not one `contain` writes (an instance's record that parses and names its
  own id and your account, the project path beside it, or a temporary file
  of a launch writing now) is moved to such a folder beside it, and said. A
  record that is well formed but was not written by `contain` cannot be
  told from one that was, and is kept. On macOS the sandbox denies writing
  them and keeps the folders above them in place; reading them stays
  allowed.
  Claude Code's state in a jail. No jail shows your `~/.claude` writable.
  That folder carries the settings that wire the guard's hook, and before,
  a program in a jail could take the hook out, turn hooks off with a
  `settings.local.json` of its own, or swap a link there for a file, for
  every run after. Now each project has a folder of the launcher's,
  `$XDG_STATE_HOME/innerwarden/jail-claude/<project name>-<hash of its
  path>` (else under `~/.local/state`), made 0700 by `contain`. On Linux
  that folder is the jail's `~/.claude` (your `~/.claude` is covered with
  an empty folder, as named and where it leads, and the jail's
  `~/.claude.json` is a link into it); on macOS the jail starts Claude Code
  with `CLAUDE_CONFIG_DIR` naming it, and the sandbox lets the jail write
  there and denies writing your `~/.claude`, your `~/.claude.json`, and
  the CLI the guard's hook runs with the folder it is in (a CLI in a folder
  the jail must write, the home, the project or the temporary folder,
  refuses the start). Before each run `contain` puts in it read-only copies
  of your `~/.claude/settings.json` and `~/.claude/settings.local.json`
  (an empty one where you have none, so a program in the jail cannot make
  one), and on Linux shows your `CLAUDE.md`, agents, commands, skills,
  plugins, output styles, Claude Code's local install and each file a hook
  there runs from `~/.claude`, read-only from yours, and copies your
  Claude Code login (`.credentials.json`) in, so the jail's Claude Code is
  logged in and what it refreshes stays the jail's. Claude Code saves what
  it keeps (sessions, projects, `.claude.json`) in that folder, never in
  yours, and each jail covers `~/.claude/sessions` and `~/.claude/backups`
  with empty folders of its own, so two jails at once do not write the same
  session file. Two jails on the same project share that project's folder,
  as two Claude Code runs on the host share yours. The folder starts empty:
  the first run in a project asks what Claude Code asks on a new account.
  Before each run `contain` cuts its `.claude.json` to Claude Code's own
  state and preferences (start counts, theme, onboarding, the account it
  shows, and per project its history and last session's counts): MCP
  servers, the project's MCP servers turned on or off, allowed tools, the
  trust of a folder, approved keys and a bypass of permissions are never
  carried from one run to the next, so every run asks again to trust the
  folder. A file that is not JSON, or a link, is removed, and what a
  program in an earlier jail put there as a link at a name `contain`
  writes is removed without being followed.
  What a jail writes in its own `~/.claude` at a name your folder does not
  have (a `CLAUDE.md`, `skills`, the script a hook of yours names) is
  removed before the next run on the project, so no jail loads what an
  earlier one left there.
  The project's own Claude Code folder (`.claude`) and MCP servers file
  (`.mcp.json`) are read-only in the jail where they are there (on macOS
  the sandbox denies writing them): Claude Code on this machine loads them
  when it opens the project, so a jail could otherwise turn hooks off,
  turn every project server on or add a server there for you. So what you
  allow with "always allow" inside a jail is not saved in the project's
  `.claude/settings.local.json` and is asked again next run. Where they
  are not there, `contain` keeps that they were not for the run, and one a
  jail makes during it that sets hooks, `disableAllHooks`, permissions in
  bypass mode, `enableAllProjectMcpServers` or MCP servers (or that does
  not read as JSON) is said as the jail ends, `contain` exits 3 (the
  command's own failure status is kept), and it refuses each next start on
  the project, naming the file. Remove it, or what it sets, to start again,
  or, if you read it and want it, accept it from your own terminal with
  `innerwarden contain --accept-project-files --project <dir>` (refused in
  an agent's shell, and the guard refuses it to an agent). A file you make
  in the project between two runs is yours and refuses nothing for being
  new; the start reads it as it reads your settings. A launch that stopped
  before its jail ended (killed, the machine off) cannot say what its jail
  made, so what it found absent and is there now refuses the next start
  the same way; one that runs in the same project at the same time does
  too, until it ends (a pid used again by another program is told apart by
  when that program started). These notes sit beside the jail's own Claude
  Code folders in `~/.local/state/innerwarden/jail-claude`, out of every
  jail's reach; outside the jail, the guard holds that folder as it holds
  its own configuration (a write, `rm`, `mv`, `ln`, a mode or owner change,
  interpreter code, the file tools), and a note that cannot be read refuses
  the start instead of counting as none.
  On macOS a jail writes only its own project's folder of the launcher's,
  never another project's.
  A jail does not start where Claude Code's settings may turn the guard's
  hook off or cannot be read: your `~/.claude/settings.json` and
  `~/.claude/settings.local.json` and the project's
  `.claude/settings.json` and `.claude/settings.local.json`, each a link,
  anything but a file, over 4 MiB, not JSON (a comment in it included), not
  a JSON object, with `disableAllHooks` set to anything but `false`, or
  with hooks in a form other than Claude Code's; and the project's where it
  sets `PreToolUse` hooks with none of InnerWarden's in effect for `Bash`
  in them, or where the project's `.claude` or `.mcp.json` is a link, or
  its `.mcp.json` does not read as a JSON object. `contain`
  says which file and why, exits 2 and changes nothing. Hooks on other
  events, and `PreToolUse` hooks beside the guard's, start as before. The
  project's own settings files stay writable in the project, as the rest of
  the project is, and Claude Code keeps saving there what you allow.
  Limit: the settings are read and copied as the jail starts. A change a
  program in the jail makes to the project's settings during a run holds
  back the next start, not the run it is made in (the guard's part of that
  is separate work), and a change you make to yours during a run reaches
  the jail at its next start.
  Where you hand `CLAUDE_CONFIG_DIR` in (`--pass-env CLAUDE_CONFIG_DIR`),
  the folder it names is taken as your `~/.claude`: `contain` checks the
  settings there, arms the guard's hook there, gives the jail copies of
  them and covers that folder, and in the jail the variable names the
  jail's own folder (on Linux and on macOS). A value that is not a full
  path (relative, or with a `..` in it) refuses the start, and so does a
  folder the jail could not guard: `/`, your home or a folder above it, the
  project or a folder in it, a folder the jail writes (`~/.local`,
  `~/.cache`, `~/.cargo`, `~/.rustup`, `~/.npm`, or `~/.config` itself; a
  folder in `~/.config` such as `~/.config/claude` is covered in place), a
  folder that is not there, a link or a file. `contain --setup` checks the
  same before it arms anything. Not handed in, the variable stays out of
  the jail and `~/.claude` is your folder, as before.
  Limit: a second Claude Code an agent starts in the jail with another
  `CLAUDE_CONFIG_DIR` reads the settings in that folder, not the jail's
  copies, so it may run without the guard's hook; the guard refuses such a
  command where it sees it.
  Limit: how Claude Code behaves with the login copied into a jail when it
  refreshes it there (whether your own login on the host stays valid), and
  with `CLAUDE_CONFIG_DIR` on macOS (where it keeps the login in the
  keychain), is not measured yet.
  The guard's hook in a jail runs a copy of the CLI only root can replace:
  the launcher itself where it is one, else root's copy at
  `/usr/local/bin/innerwarden` or `/usr/bin/innerwarden` (said as the jail
  starts). A copy in your home (`~/.local/bin/innerwarden`) is one a
  program in the jail can replace, and on Linux InnerWarden Pro's
  Execution Gate in enforce refuses it there; the hook's wiring then holds
  every call. With no copy of root's, the hook runs the launcher and the
  start says so. The
  hook's wiring is the same for your agent outside the jail. A launcher
  under `/usr` is shown as `/usr` is, not bound on its own, so an upgrade
  that replaces it reaches a jail that is running.
- Agent identity (off by default, Linux): `innerwarden contain --identity --
  <command>` records the run as an instance, so its hook and the dashboard can
  tell one agent's runs apart. See [Agent identity and trust](agent-identity.md).
- Agent discovery: finds AI agents and agent tooling on the machine so you can
  see what is running and wire the guardrail into it.
- `innerwarden demo`: sends four known risky calls (a download piped to a
  shell, a read of an SSH key, a write of agent settings, a home wipe inside
  `bash -c`) through the guard path each connected agent really uses: its hook,
  or, for an agent behind the MCP proxy, the same four as MCP calls through the
  proxy's rules. It shows what was refused. Nothing is run; each call a hook
  judged is recorded and marked as a demo.
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

### The posture: what an enforcing hook refuses

Operator decision of 2026-11-21: the text rules are triage, not the boundary.
An enforcing hook line with no mode flag runs in the posture kept in
`~/.config/innerwarden/posture`:

- `guard`, the default posture, written by the first `agents connect`,
  `install` or `setup` on a home with no wiring yet. A shell call is refused
  only when the strict policy below refuses it AND one of its signals is in
  the high-certainty class:
  - a hard-class secret read (`sensitive_credential_read` at the hard
    score: SSH and GPG keys, `.aws/credentials`, `.netrc`, `.pgpass`, the gh
    and cargo logins, `/etc/shadow`; a path you declared protected,
    `protected_secret_read`; a secrets file read from outside the project,
    `credential_read_outside_project`);
  - destruction of the system or of a home (`destructive_command`, and the
    pattern findings "rm -rf of root" and "dd raw-device overwrite");
  - an act that takes the guard down (`guard_self_disable`,
    `security_tooling_tamper`, Cursor's hooks file losing the guard);
  - a reverse shell (`reverse_shell`);
  - download and run (`download_and_execute`, `download_chmod_execute`,
    `dynamic_code_execution`, `download_run_in_text_argument`,
    `fetch_exec_unparsed`, `fetch_exec_unanalyzable`, and the pattern
    findings "pipe to shell" and the PowerShell download cradles).

  Every other refusal, and every review, runs: the record keeps it as
  `would_block` on an enforcing line, an alert goes out as for a monitor
  would-block, and the agent shows one line (`systemMessage` for Claude
  Code, Codex and Gemini CLI; `permission: "allow"` with the words for
  Cursor; stderr, exit 0, for Hermes and any other agent).
- `strict`, or no file, or a file that holds anything else: every `deny`
  is refused and a `review` is answered as the table below says. This is
  the enforce of every release before the posture existed, so a home wired
  before it keeps it after an upgrade, and taking the file away only
  hardens the guard.

`agents connect --strict` and `install --strict` write `strict`;
`--guard` writes `guard` and, since it lowers what the hook refuses, is
refused in an agent's shell and by the guard when an agent runs it. With no
flag a posture already chosen stays. The file is in the guard's own folder,
which an agent cannot write (the file rules and the shell rules refuse it).

What the posture does not change: a call the hook cannot read (too long,
unreadable, past its deadline) is refused in both; a write of a file tool
to a privileged file is refused in both; a `--block-review` line refuses
every review and a `--monitor` line refuses nothing, whatever the file
says; where per-agent profiles are in force the call is held to them as
strict holds it; the MCP proxy and the OpenClaw plugin keep their own modes.

Measured with the release safety suite on 2026-11-21
(`cargo test -p innerwarden-agent-guard --test release_eval_posture -- --nocapture`;
a benign case is refused when the posture stops it):

| corpus | attacks stopped for an agent: strict | default posture | benign refused: strict | default posture |
|---|---|---|---|---|
| proof | 244/246 | 217/246 | 13/160 | 13/160 |
| attack-2026-11 | 320/377 | 179/377 | 0/138 | 0/138 |
| real | 4/5 | 4/5 | 21/31 | 16/31 |
| external-2026-11 (MCP, the proxy's) | 15/68 | 15/68 | 19/166 | 19/166 |
| own-work | 0/0 | 0/0 | 15/49 | 13/49 |

The attacks the default posture lets run with a warning are mostly
privileged containers and host sockets (108 of attack-2026-11), writes to
`~/.ssh/config` and shell startup files, credential searches, near-miss
package names and `eval` of a download; the suite prints each one.

### What an agent's hook does with each verdict

The hook answers each agent in the words that agent reads. In the strict
posture (the enforce of earlier versions; see above for the default
posture):

| Agent | `allow` | `review` | `deny` |
|---|---|---|---|
| Claude Code | runs | asks you (`permissionDecision: "ask"`, with the guard's reason) | refused |
| Gemini CLI | runs | refused, with the reason | refused |
| Hermes Agent | runs | asks you through its approval gate (`action: "approve"`); refused when nobody is there to approve | refused |
| Codex CLI | runs | runs, and Codex shows you a warning with the reason (`systemMessage`) | refused |
| Cursor | runs (`permission: "allow"`) | a shell command or an MCP call asks you (`permission: "ask"`, with the reason); a file read is refused, with the reason | refused (exit 2 and `permission: "deny"`, with the reason) |
| Antigravity CLI | runs (`decision: "allow"`) | asks you (`decision: "force_ask"`, with the reason) | refused (`decision: "deny"`, with the reason, exit 0) |
| any other agent | runs | refused, with the reason | refused |

Codex CLI has no way for a hook to ask the person: it reads an `ask` as
unsupported and runs the call. Refusing every review there would also refuse
ordinary work (a program named by a variable, a value an earlier tool
returned), so on Codex a review runs: Codex shows you the warning, but it
does not wait for you. Use `--block-review` to refuse reviews there.

Gemini CLI reads `decision: "ask"`, but in 0.68.0 that ask is not sure to
reach a person: a tool with no confirmation to show runs at once, and the
non-interactive path was not followed. So on Gemini a review is refused with
the reason, as a deny is. The same holds for any agent this table does not
list: an answer it may not read would let the review run unseen.

The Antigravity CLI reads a JSON `decision` on stdout. What it does with a
hook that exits with another code than 0, times out or prints no decision
is not in its hooks documentation, and the Gemini API's own agent hooks run
the tool then. So the guard answers every Antigravity call with a decision
and exit 0, a refusal included; the deadline, a fault and an internal error
answer with a deny on stdout too; and in enforce mode the hook line (Linux
and macOS) prints a deny itself when the innerwarden program is missing,
cannot start or is killed. A review is `force_ask`, which asks even where
an earlier "Always Allow" would skip `ask`; what Antigravity does with it
when nobody is there to ask (`agy -p`) was not measured.

Cursor blocks a call whose hook says nothing on stdout, so every call the
guard lets through is answered `allow` in JSON. Its `beforeReadFile` takes
allow or deny only, so a read rated review cannot be asked about and is
refused with the reason.

Cursor has no hook before a file edit, so its agent can edit
`~/.cursor/hooks.json` itself and turn the guard off: a shell command that
rewrites or removes that file is refused, an edit is not screened. What is
seen afterwards:

- an edit that takes out some of the guard's entries, or turns `failClosed`
  off: every Cursor call the guard still sees is refused, with the reason,
  until `innerwarden agents connect cursor` puts them back;
- an edit that keeps the entries and points them at another program: the
  guard no longer runs, so nothing is refused; `innerwarden status`,
  `agents` and the dashboard say that Cursor's hook runs another program;
- an edit that takes every entry out: the guard no longer runs either;
  `status`, `agents` and the dashboard say the hooks are not in the file.

In the last two cases Cursor's calls run unscreened until the hooks are
connected again. Community does not stop the edit itself.

Hermes Agent's approval gate (v0.23.1, `request_tool_approval`) asks the
person in a chat or through its gateway and refuses when nobody can answer.
It lets the call run without asking when you set Hermes to approve on its
own: yolo, `approvals.mode: off`, or `approvals.cron_mode` /
`approvals.single_query_mode` set to approve.

A review that carries a signal no agent should act on unasked (fetch and
execute, an obfuscated command, a persistence entry, a near-miss package
name) is refused like a deny, on every agent. `--block-review` refuses every
review. Monitor mode (`--monitor`) never refuses: every verdict runs, is
recorded, and nothing is asked.

What each agent does with the answer is read from its own source (Claude
Code's hooks reference, Gemini CLI 0.68.0, Hermes Agent v0.23.1, Codex CLI
0.167.2, Cursor's hooks documentation as published on 2026-11-20, the
Antigravity CLI's hooks documentation as published on 2026-11-21) and held by tests that feed each agent's payload through the line
`agents connect` writes; it was not measured in a running chat of each agent.

### Where decisions are recorded

On its own, InnerWarden keeps its record in the home of the account that runs
it: `~/.config/innerwarden/graph.json`, with the refusals also appended to
`guard-events.jsonl` beside it. `IW_GRAPH_FILE` moves it anywhere you say.
A call the MCP proxy refuses is written to the guard's own record too (the
one `innerwarden status` reads in your own terminal: the shared record where
InnerWarden Pro names one, else the one in your account's home, found from
the account database by uid and never from `HOME`),
graph and `guard-events.jsonl` line, whatever the proxy's environment says:
whoever starts the proxy can move its record, but not hide a refusal from
you, and neither can an empty, missing or redirected `HOME`. On Windows, where
no account database is read, the copy goes only to a shared record. What
`IW_GRAPH_FILE` still moves is everything else the proxy records
(every allowed call, and what advisory and warn only record).
`INNERWARDEN_AGENT_URL=off` turns off only the report of each refusal to an
InnerWarden Pro agent on the same machine (`POST /api/agent/proxy-block`);
the refusal is still recorded, and Pro still reads the `guard.blocked` line
from the shared record where it is installed.

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

What it refuses is the action, not the name. A line that stops, kills,
disarms, removes, moves over or rewrites the guard, its files and settings,
or an agent's settings is refused. A line that only names them as data is
held for review instead (a warning under the default posture): a search
pattern (`grep`, `rg`, `git grep`), a message (`-m`, `--body`,
`--title`, a commit message read from a here-document or a here-string), a
folder of a repository or a worktree whose name holds the guard's, and
Python, Node, Ruby or Perl code whose strings name the guard but which runs
nothing, signals nothing and changes only files of the project. A slot is
read as data only when its text is literal and what the command prints goes
nowhere that runs it; a line whose deny rests on anything else (a secret
read, a download run) keeps it.

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
  `--ignore-user-config`; or any of them, Gemini CLI and the Cursor CLI
  (`cursor-agent`, whose MCP wiring the guard writes) included, with a
  variable it reads that moves the folder its hook or wiring is in or
  switches its hooks off (`HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`,
  `HERMES_HOME`, `GEMINI_CLI_HOME`, `CURSOR_CONFIG_DIR`,
  `CLAUDE_CODE_SIMPLE` and the others they read), also when the line builds
  the variable's name at run time (`export CLAUDE_${X:-CONFIG}_DIR=...`). `HOME`
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
- An order in a tool result that neither speaks to the assistant nor is
  framed as the system, one written as code or data, one spread over more
  than five sentences, or one in a language other than English, Portuguese
  and Spanish. Where an order is read by its shape (the assistant called
  and a tool action ordered, or three classes of words within five
  sentences, one of them speaking to the assistant or framing), a payment,
  message, share, delete or booking carrying a value said in it is refused;
  a short value (`"34"`, `"Fred"`) is not looked for. In a session not
  read whole (an answer past the scan limit), a payment carrying a value
  not found in what was kept is refused, and any other acting call gets an
  alert only.
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
- A file written in an earlier call and run in this one. Each call is judged
  as its own line: `echo '...' > a.sh` in one call and `sh a.sh` in the next
  are two lines, and the second runs a file the guard does not read, as any
  file already on disk is. Within one line, a file the line writes and then
  runs (by name, by path, through `$SHELL`, `exec`, `env -S`, `xargs` or
  `find -exec` handing it over, or on a shell's stdin) is read as the code it
  holds when the line shows the text; when it does not (a program's output, a
  copy, `dd`, `sed -i`, `perl -pi`, `gawk -i inplace`, `truncate`, a
  variable, an archive unpacked, a patch or a `git checkout` on a line that
  also writes the file), the line is held for review. A file of
  assignments only, of values the line writes out or of the environment's
  own paths, is read as those assignments; when the line loads it in its
  own shell (`. ./env.sh`, `source`), they are judged as if written where
  it is loaded, so a harmful use of them later on the line gets the verdict
  of the same line typed out. A loaded file that sets a variable the guard
  reads in its own way (the home, the search path, `IFS`, `PS4`,
  `SHELLOPTS`, a setting that loads code) is held for review (`echo
  "export PATH=$PATH:$HOME/bin" > env.sh && . ./env.sh`), whether it
  assigns it, exports it, reads it (`read`, `mapfile`, `printf -v`), loops
  over it or unsets it. A use later on
  the line of a variable the loaded file sets can be held for review where
  the same line typed out is allowed (`. ./env.sh && rm -rf $X`): stricter,
  never looser. A value the line itself gives a name (`X=/`, `export`,
  `declare`, `local`, `readonly`, `typeset`, a value set in front of the
  command, a loop over one word, a loaded file's assignments) is read into
  every look the line gets, the target of a removal and the program word
  among them: `X=/; rm -rf $X` and `P=rm; $P -rf /` get the verdict of
  `rm -rf /`. `xargs` and `find -exec` are read one file at a time up
  to 64 files; past that the line is refused as read past its budget.
  `find -exec` with a pattern is matched only against the files the line
  writes by a redirect or `tee`.

The MCP proxy does not fix an MCP server that is itself vulnerable. A flaw in
the server's own logic happens inside the server, where the proxy does not
look: a forged token the server accepts (a JWT whose role it does not check),
a record of another person it hands back (an IDOR), or a path that escapes a
folder inside the server's own code. The proxy sees the call and the answer:
it refuses a call by what the call says, masks the secrets it knows by their
shape in the answer, and holds an answer that carries orders for the model in
`guard` and `kill`. A secret it does not know by shape, or data that is not
a secret (a salary, an address), reaches the model as the server sent it.

Under an enforcing hook, a line with a part the guard cannot read (a
substitution, a variable the line does not set to text it writes out) is
held for review where that part names the program, is code a shell or an
interpreter runs, is the target of a write, sets what later programs load,
or is an argument of a program not known to only read or print. A plain
variable a known program takes only as data does not hold the line. A line
the shell grammar cannot parse at all keeps the reading it had.

An agent's hook lets a call run unless the guard answers with a refusal. A
guard that takes too long answers with one, under an enforcing hook: after
ten seconds of screening (time spent waiting for a CPU is not counted on
Linux) or 25 seconds on the clock, 20 more with a second opinion from a model
configured. A tool call longer than 1 MiB is not read and is refused the same
way; a tool result past it (PostToolUse) already ran and is recorded from
its first 1 MiB. `innerwarden install` writes a 50 second `timeout` on the Claude Code
hook line, so the guard's own refusal comes before Claude Code stops waiting;
a call Claude Code stops waiting for runs. On macOS and Linux,
an enforcing Claude Code hook line ends in a short shell tail, and an
enforcing Codex CLI or Gemini CLI line runs the guard inside a small `/bin/sh`
script (Codex starts the line with the login shell, which may not read that
tail), so a guard whose program is gone or dies refuses the call too. Hermes
Agent gets the same from its own `fail_closed: true`, and Cursor from the
same script and its own `failClosed: true`. In monitor, on Windows,
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

Also not seen today, and not promised for any date:

- Code handed to a runner in forms the guard does not read. For `tcsh`,
  `at`, awk's `system()`, `make -f -` and `busybox`, some forms where the
  line writes the text and hands it over are read; other forms of the same
  runners pass.
- The writes that follow an `exec > file` (or `exec 3> file`): every later
  command of the line writes that file without a redirect of its own, and
  the guard does not count those writes.
- A script that Python, Node or Ruby code writes and the same line then runs.
  The guard does not read what the code put in the file.
- Some ways of stopping the guard: a `pkill` pattern that matches the
  guard's command line only on another program's part (the agent's id, the
  MCP server) or only on the shell a fail-closed hook script runs after the
  guard ends (`exit 2`, `case $s in`), which any script holds, is left to
  the other checks; process ids of the guard handed to a `kill` on a later
  line, or by a program the line does not show, are not followed. A
  restart of a service of the guard (`systemctl restart`) runs, as ordinary
  maintenance, while a restart asked of systemd over D-Bus is refused. The
  Cursor CLI's own flags are not read.
- A path that steps back with `..` after a symbolic link. The MCP proxy
  reads a path where a call writes by its text, with `.` and `..` taken
  out, without looking at the disk: the proxy may not run on the server's
  host, and the disk can change before the server opens the path. So
  `/srv/app/link/../sudoers` is read as `/srv/app/sudoers`, while a server
  whose `link` points into `/etc` writes `/etc/sudoers`.
- A tool its MCP server declares read-only (`readOnlyHint: true`). The
  proxy believes the declaration for the provenance table, a booking tool
  too, so a value a server said in such a call raises no alert. A tool whose
  name says it writes (`write_file`) is still held to the privileged files.
- A flaw in an MCP server's own logic. The proxy sees the calls, not what the
  server does with them: a forged token the server accepts, or a parameter
  that returns another user's record, looks like any other call. What is
  left is the proxy's outbound filter, which masks the secrets it knows in
  the answer.
- A name of the guard built at run time inside inline code (`'inner' +
  'warden'`, a path joined from pieces, a name read from the environment
  or from a file) or inside a file the code then reads. Code that runs a
  program, signals a process, reaches the home or the environment, or
  writes outside the project is never taken for a mention, but a name it
  only assembles is not read. The operating system's own permissions and
  InnerWarden Pro's kernel layer cover that case.
- Everything the hook decides, from `innerwarden check`. `check` judges one
  line on its own. The hook also knows the agent's session (an argument that
  came out of an earlier tool result) and the place the call reads, so some
  verdicts depend on what a folder holds when the call is made, such as a
  read of the home. A download piped to a shell is refused by `check`
  when it is fetched over `http://` and held for review over `https://`,
  which an installer also looks like; the hook refuses it for an agent. Read `check` as a preview, not as the hook's verdict.

These are the limits of a guard that reads text. InnerWarden Pro works below
the text, at the host (Linux): armed for an agent, its Execution Gate decides
in the kernel which programs that agent's processes may start, whatever the
command line says. It is off until you arm it.

