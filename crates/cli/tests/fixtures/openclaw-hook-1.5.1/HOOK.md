---
name: innerwarden-attempts
description: "Record a dangerous ask that reached the agent in conversation, and who ended it"
metadata:
  {
    "openclaw":
      {
        "emoji": "🛡",
        "events": ["message:received", "message:sent"],
        "install": [{ "id": "innerwarden", "kind": "managed", "label": "innerwarden observe install" }],
      },
  }
---

# InnerWarden conversation attempts

Sends the inbound message text and the outbound reply notice to
`innerwarden observe`, which scores the ask with the free guard's own rule
engine and, when it is dangerous, appends one `guard.attempt` record to
`guard-events.jsonl`.

## Why this exists

The guard screens what an agent tries to RUN. An attacker who asks an agent to
mine crypto and is refused by the model produces no tool call, so nothing
reaches the guard and nothing is recorded. This hook is the observation of that
case, and only the observation.

## What it is NOT

It is not enforcement. It cannot stop a message, and OpenClaw's internal hooks
cannot cancel one: strings pushed to `event.messages` are ignored for every
`message:*` event. A record written through this hook is evidence that the
model declined, never evidence that InnerWarden blocked anything, which is why
every record names its decider and carries `enforced: false` unless a control
actually refused the action.

## What it records

- the ask, redacted through the guard's redaction path and bounded
- who decided: `model_refused`, `guard_denied`, `kernel_denied` or `undetermined`
- what that conclusion rests on (`decider_basis`)
- the timestamp and the channel the message arrived on

## Requirements

The `innerwarden` binary. `innerwarden observe install` writes its absolute
path into `bin.json` next to this file; `IW_GUARD_BIN` overrides it.
