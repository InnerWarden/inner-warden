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
`guard.attempt` record to `guard-events.jsonl`. A miner's name that is only
talked about ("how do I remove xmrig from this box?") is not read as a
command; one that is asked for, or given as a command, is.

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
a line that names this agent (`openclaw`) and this conversation's session. The
MCP proxy that guards OpenClaw records its decisions under its own session,
never a chat's, so a refusal it makes in the same turn is recorded as
`guard_block_recorded_in_window` below: one gateway holds many chats at once,
and the time alone does not say which chat the refusal belonged to. An ask
that ends any other way is recorded as `undetermined`, with the reason:

- the same conversation sent another dangerous message before any reply
  (`next_message_before_reply`); both asks are recorded
- no reply arrived within 15 minutes (`no_reply_observed_within_ttl`)
- the channel never reports the reply (`channel_reports_no_reply`, below)
- on the Control UI chat (below), the turn that answered it called a tool
  (`tool_call_in_turn`): whatever the agent said after that, it acted, so its
  reply does not show it declined; or the turn ended with nothing said,
  failed or was stopped (`turn_ended_without_reply`)
- monitor mode let an action the guard flagged run in the same turn
  (`flagged_action_ran_in_window`). This outranks every other reason: it is
  the one that says the attack may have worked
- the guard refused an action in the same turn, but the record cannot rest on
  it (`guard_block_recorded_in_window`): no reply was observed, or the refusal
  names no agent, or another session. The refusal is a record of its own
  either way

The guard's event file can be appended to by the agent's own account, so a line
there never settles an ask that nothing answered, and a line stamped after the
ask was recorded, or naming another agent, is not read at all.

## The Control UI chat (webchat)

OpenClaw fires `message:received` for a Control UI message, but streams the
reply back over the gateway connection and fires no `message:sent` for it, and
no internal hook event marks the end of a webchat turn. OpenClaw's typed
plugin hook `agent_end` does, so `innerwarden observe install` also installs a
small plugin, `innerwarden-replies` (in `~/.openclaw/extensions/`), that reads
how each Control UI turn a person started ended: a tool call, a reply, or
neither. It hands that one word, with the turn's id, to
`innerwarden observe ended`, which closes the ask whose message started that
turn, and no other. No conversation text leaves the gateway through it.
OpenClaw lets a plugin read a turn only with conversation access, so the
install grants it (`plugins.entries.innerwarden-replies.hooks.allowConversationAccess`)
and says so; an entry you turned off stays off, and your `plugins.allow`,
`plugins.deny` and `plugins.enabled` are reported, never edited. The gateway
logs it as a plugin it cannot verify, because it was not installed through
`openclaw plugins install`; `openclaw plugins inspect innerwarden-replies`
shows it. A heartbeat or cron turn never closes an ask.

A reply with no tool call in the turn is settled like any other reply. Where
the plugin does not run, or its report cannot be matched to the ask, a
dangerous webchat ask is held for two minutes, long enough for what the guard
records in the same turn to be seen, and then recorded as `undetermined`, with
`channel_reports_no_reply` or what the guard recorded in that turn as its
basis. It never says the model declined there, because nothing here saw the
reply, and it never says the guard stopped it either. If the gateway restarts
inside those two minutes, the ask is recorded once it has waited 15 minutes,
by the next message this hook sees.

## After an upgrade

`innerwarden upgrade` runs the new binary's `innerwarden observe refresh`,
which replaces this hook's files and the plugin's with the new version's where
they are exactly what an earlier release wrote. A file somebody changed is
left as it is and named. It installs nothing that was not installed and never
restarts the gateway: restart it to load the new files.

## Requirements

The `innerwarden` binary. `innerwarden observe install` writes its absolute
path into `bin.json` next to this file and next to the plugin's;
`IW_GUARD_BIN` overrides it.
