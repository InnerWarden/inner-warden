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
| **ASI01** | Agent Goal Hijack | Prompt-injection detection (24 patterns + ATR `prompt-injection`/`agent-manipulation`/`cjk-social-engineering`) on commands and MCP content routed through the guardrail | **Detect / advise** |
| **ASI02** | Tool Misuse & Exploitation | `check-command` returns a deny recommendation for dangerous tool calls (`dangerous_command`, ATR `tool-poisoning`/`skill-compromise`); a per-session circuit breaker limits loop amplification / excessive execution; the armed Active Defence Execution Gate can enforce the execution side on Linux | **Detect + breaker; conditional Linux kernel enforcement** |
| **ASI03** | Identity & Privilege Abuse | Detection signals only, `credential_access`, `insecure_permissions`, privilege-provenance (`untrusted_root_exec`/`setns_owner`, spec 070). It does **not** manage the agent's own identity, tokens or delegation | **Partial / supporting** |
| **ASI04** | Agentic Supply Chain Vulnerabilities | No SBOM/AIBOM, provenance, signature, version-pinning or registry validation. Community can detect a payload attempt; an armed Active Defence Execution Gate can block its execution on Linux | **Conditional runtime impact mitigation, not supply-chain validation** |
| **ASI05** | Unexpected Code Execution | Community returns deny recommendations for download-and-execute, temp-dir executables, obfuscated payloads and reverse shells; an armed Active Defence Execution Gate can refuse unauthorized scripts and binaries on Linux | **Direct detection; conditional Linux kernel enforcement** |
| **ASI06** | Memory & Context Poisoning | No detection of persistent-memory / RAG / context-store poisoning. Per-pod attribution can scope an investigation but does not contain the workload; ATR `data-poisoning` is a weak signal | **Limited / indirect** |
| **ASI07** | Insecure Inter-Agent Communication | Does not authenticate or verify inter-agent messages. Active Defence can attribute container events to pods and tenants, but it does not provide inter-agent isolation | **Visibility only, not isolation** |
| **ASI08** | Cascading Failures | Circuit breaker + rate limits limit tool loops; Active Defence adds watchdog and containment, and its Linux Execution Gate has an explicit `disarm` kill-switch when armed | **Supporting mitigators** |
| **ASI09** | Human-Agent Trust Exploitation | Approval routing is coverage **only** when it carries independent evidence + a risk summary + explicit confirmation + an audit trail (Explained Alerts). A bare Telegram/Slack "approve?" is not | **Partial, only with independent evidence** |
| **ASI10** | Rogue Agents | Community detects dangerous host actions and returns deny recommendations; an armed Active Defence Execution Gate can contain unauthorized execution on Linux | **Direct detection; conditional Linux kernel enforcement** |

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
