# Changelog

All notable changes to InnerWarden are documented here. This project
follows semantic versioning.

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
