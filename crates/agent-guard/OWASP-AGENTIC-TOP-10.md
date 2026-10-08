# InnerWarden × OWASP Top 10 for Agentic Applications 2026

An **independent** mapping of InnerWarden's controls to the **OWASP Top 10 for
Agentic Applications 2026 (ASI01–ASI10)**, published by the OWASP GenAI Security
Project on 2025-12-09. The mapping is *derived from the code that runs*
([`src/asi.rs`](src/asi.rs)); the guard-layer controls are proven by
[`tests/owasp_asi.rs`](tests/owasp_asi.rs).

> **InnerWarden is not endorsed or certified by OWASP.** This is an independent
> mapping to the published framework.
> Framework: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>

## What this is, and is not

InnerWarden Community Edition is a **per-user runtime guardrail**. Commands routed
through its hooks and proxies are screened before execution; `check-command`
itself returns an advisory recommendation. InnerWarden Active Defence adds the
host layer. On Linux, its opt-in Execution Gate can refuse execution-critical
calls **in the kernel** once it is armed, a jailbroken agent cannot argue with
an `-EPERM`.

That makes it strong on the runtime-observable risks (unexpected execution,
rogue-agent host actions, tool misuse) and only **partial or supporting** on the
risks that are architectural rather than runtime, supply-chain provenance,
persistent-memory poisoning, inter-agent message authentication, human
over-trust. The table below says so per row rather than claiming "10/10".

## Coverage matrix

| ASI | Official title (2026) | InnerWarden control | Honest coverage |
|---|---|---|---|
| **ASI01** | Agent Goal Hijack | Prompt-injection detection (27 patterns + ATR `prompt-injection`/`agent-manipulation`/`cjk-social-engineering`) on commands and MCP content routed through the guardrail. In the benchmark, injected user input is `deny`; an instruction injected into a tool result is surfaced as a `review` alert, not blocked | **Detect / advise** |
| **ASI02** | Tool Misuse & Exploitation | `check-command` returns `deny` for the dangerous-command patterns marked blocking and `review` (not blocked for an agent) for the rest (`dangerous_command`); a poisoned tool description (ATR `tool-poisoning`/`skill-compromise`) is `deny` in the benchmark; the MCP proxy's loop breaker refuses (guard) or flags (advisory) an identical tool call made more than 3 times within 60 s, that call only and only while it repeats, and its reason says when the same call is accepted again (the finding names ASI02 and ASI08, so its record and its case show those classes; it keeps its historical id, `AG-ASI09-BREAKER`, which recorded decisions already carry, though a loop is not ASI09); the armed Active Defence Execution Gate can enforce the execution side on Linux | **Detect + breaker; conditional Linux kernel enforcement** |
| **ASI03** | Identity & Privilege Abuse | Community: reading a credential store (`sensitive_credential_read`, an operator-declared `protected_secret_read`) or overwriting one (`sensitive_file_overwrite`) is `deny` in the benchmark; searching the filesystem for credentials (`credential_hunt`) is `review`; loosening permissions on a system path is flagged (`insecure_permissions`); and the MCP proxy refuses (guard) or flags (advisory) `AG-PRIV-WRITE` (a tool call that may write a file granting privilege, such as the sudo rules or PAM, code that runs as root, or the agent settings that carry the guard). Active Defence adds privilege-provenance signals (`untrusted_root_exec`/`setns_owner`). It does **not** manage the agent's own identity, tokens or delegation | **Partial / supporting** |
| **ASI04** | Agentic Supply Chain Vulnerabilities | No SBOM/AIBOM, provenance, signature, version-pinning or registry validation. Community surfaces an install (pip, pipx, uv, poetry, pipenv, npm, yarn, pnpm, bun), a fetch-and-run (npx, npm exec, pnpm dlx, yarn dlx, bunx, uvx, uv tool run, pipx run) or a download (pip download, pip wheel) whose package name is one edit from a popular PyPI or npm package and is not itself on the shipped list (`package_typosquat`: review, blocked for an agent), and can detect a payload attempt; an armed Active Defence Execution Gate can block its execution on Linux | **Look-alike name screening and conditional runtime impact mitigation, not supply-chain validation** |
| **ASI05** | Unexpected Code Execution | Community, as measured on the shipped benchmark corpus ([`benchmarks/SCOREBOARD.md`](benchmarks/SCOREBOARD.md)): a download piped to a shell, or saved to a file and then run (curl, wget, BSD fetch, aria2c, axel, lwp-download, or a Python, Node, Perl, Ruby or PHP one-liner that fetches and writes the file), over TLS from a named host is `review` and blocked for an agent under the default policy, because it is the shape of a vendor installer; it is `deny` when the fetch has no TLS, a bare public IP, a paste or short-link host, or a decoder, or when the fetched bytes reach an interpreter as code by another route than a plain pipe or file (process or command substitution, `eval`, a here-string, a nested `bash -c` or `system()`). Reverse shells are `deny`. An obfuscated payload is `review` and blocked for an agent, and `deny` alongside other evidence. A temp-dir executable on its own (`/tmp/x`, or `./x` after `cd` into a temp directory) is `review` and NOT blocked for an agent; it adds to other evidence. A command the shell grammar cannot parse that names both a fetch and a way to run code is `review`, blocked for an agent (`fetch_exec_unparsed`). An armed Active Defence Execution Gate can refuse unauthorized scripts and binaries on Linux | **Direct detection (deny or agent-blocked review); conditional Linux kernel enforcement** |
| **ASI06** | Memory & Context Poisoning | No detection of persistent-memory / RAG / context-store poisoning. Per-pod attribution can scope an investigation but does not contain the workload; ATR `data-poisoning` is a weak signal | **Limited / indirect** |
| **ASI07** | Insecure Inter-Agent Communication | Does not authenticate or verify inter-agent messages. Active Defence can attribute container events to pods and tenants, but it does not provide inter-agent isolation | **Visibility only, not isolation** |
| **ASI08** | Cascading Failures | Circuit breaker + rate limits limit tool loops; Active Defence adds watchdog and containment, and its Linux Execution Gate has an explicit `disarm` kill-switch when armed | **Supporting mitigators** |
| **ASI09** | Human-Agent Trust Exploitation | Approval routing is coverage **only** when it carries independent evidence + a risk summary + explicit confirmation + an audit trail (Explained Alerts). A bare Telegram/Slack "approve?" is not | **Partial, only with independent evidence** |
| **ASI10** | Rogue Agents | Community, as measured on the shipped benchmark corpus (destruction, reverse shells, persistence) and the guard's tests (tampering, miners): system destruction (root wipes, disk overwrite, fork bomb), security-tooling tampering, cryptominers and reverse shells are `deny`; a scheduled task or service installed to run again (`crontab`, `systemctl enable`) is `review` and blocked for an agent, and `deny` alongside other evidence (an SSH key or reverse shell written to persist); a write to a shell profile (`.bashrc`, `.profile`) on its own is recorded but `allow`. An armed Active Defence Execution Gate can contain unauthorized execution on Linux | **Direct detection (deny or agent-blocked review; shell-profile writes recorded only); conditional Linux kernel enforcement** |

**Not an ASI, but shipped:** a secret/PII redaction transform scrubs tokens,
keys, `password=`, SSNs and card numbers from tool output before it enters the
agent's context. The 2026 framework has no "sensitive information disclosure"
class, so this is listed as an **additional data-protection control**, not an
ASI claim.

## The reason chain

Every guard verdict maps to its ASI class, so a deny reports *which* agentic risk
it touched. `POST /api/agent/check-command` returns `asi_ids` (e.g.
`["ASI05"]` for a reverse shell) alongside the verdict, so a security team sees
it in the framework they evaluate against. A signal with no honest ASI home
returns none rather than being force-fitted.
