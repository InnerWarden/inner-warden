# Changelog

All notable changes to InnerWarden are documented here. This project
follows semantic versioning.

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
