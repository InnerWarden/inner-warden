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
`innerwarden observe`, which scores the ask with the free guard's own rules
(the command rules, the prompt-injection rules, and a short plain-language
list for a cryptominer request) and, when it is dangerous, appends one
`guard.attempt` record to `guard-events.jsonl`.

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
- the rules' recommendation and risk score, and the signals that fired
- who decided: `model_refused`, `guard_denied`, `kernel_denied` or `undetermined`
- what that conclusion rests on (`decider_basis`)
- the timestamp, the channel the message arrived on, and the agent (`openclaw`)

`model_refused` is only ever concluded from a reply that was observed, with
nothing in that turn saying otherwise. `guard_denied` needs the same observed
reply and a refusal the guard made in enforce mode, recorded after the ask, on
a line that names this agent (`openclaw`). An ask that ends any other way is
recorded as `undetermined`, with the reason:

- the same conversation sent another dangerous message before any reply
  (`next_message_before_reply`); both asks are recorded
- no reply arrived within 15 minutes (`no_reply_observed_within_ttl`)
- the channel never reports the reply (`channel_reports_no_reply`, below)
- monitor mode let an action the guard flagged run in the same turn
  (`flagged_action_ran_in_window`). This outranks every other reason: it is
  the one that says the attack may have worked
- the guard refused an action in the same turn, but the record cannot rest on
  it (`guard_block_recorded_in_window`): no reply was observed, or the refusal
  names no agent. The refusal is a record of its own either way

The guard's event file can be appended to by the agent's own account, so a line
there never settles an ask that nothing answered, and a line stamped after the
ask was recorded, or naming another agent, is not read at all.

## The Control UI chat (webchat)

OpenClaw fires `message:received` for a Control UI message, but streams the
reply back over the gateway connection and fires no `message:sent` for it, and
no other hook event marks the end of a webchat turn. So a dangerous webchat ask
is held for two minutes, long enough for what the guard records in the same
turn to be seen, and then recorded as `undetermined`, with
`channel_reports_no_reply` or what the guard recorded in that turn as its
basis. It never says the model declined there, because nothing here saw the
reply, and it never says the guard stopped it either. If the
gateway restarts inside those two minutes, the ask is recorded once it has
waited 15 minutes, by the next message this hook sees.

## Requirements

The `innerwarden` binary. `innerwarden observe install` writes its absolute
path into `bin.json` next to this file; `IW_GUARD_BIN` overrides it.
