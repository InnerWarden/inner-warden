# What the person asked: the prompt record

The MCP proxy sees a tool call and the values in it. It cannot tell, from the
call alone, a value the person typed ("send the report to ana@example.com")
from the same value written by a model that read it in a web page or a file.
The prompt record gives it the person's own words, per agent session, so it
can ask one question: does this value appear in what the person asked?

This page says what is kept, where, for how long, and how to delete it.

## Which agents

| Agent | Event that carries the prompt | Wired by `innerwarden install` | Can the proxy match the session? |
|---|---|---|---|
| Claude Code | `UserPromptSubmit` | yes | yes: Claude Code sets `CLAUDE_CODE_SESSION_ID` in the processes it starts |
| Codex CLI | not wired | no | no: no session id handed to MCP servers is known |
| Gemini CLI | not wired | no | no: no session id handed to MCP servers is known |
| Hermes Agent | not wired | no | no: no session id handed to MCP servers is known |
| Cursor | not wired | no | no: no session id handed to MCP servers is known |

Only Claude Code is wired. For the other agents a record could never be read
for the call it was meant for, because the proxy has no session id to match it
with, so the answer would always be "unknown". Their prompts are not kept.

That Claude Code hands `CLAUDE_CODE_SESSION_ID` to an MCP server it starts was
read in the environment of the processes it starts, not measured on a running
MCP server.

## What is kept

- The prompt the person submitted, after masking: obvious secrets (provider
  tokens, private keys, passwords in URLs, `password=` and similar values,
  authorization headers) are replaced with `[REDACTED]` by the same masking the
  guard's record uses, before anything is written. A secret that masking does
  not recognise is kept as typed.
- The session id, and the agent the hook line names.
- When each prompt was kept.

Nothing else: not the conversation, not the model's answers, not tool results.

## Where

One file per session in `~/.config/innerwarden/prompts/`. The file name is a
hash of the session id. The folder is created with mode 0700 and each file with
mode 0600; a file is written in one rename. The guard already refuses an agent's
own writes under `~/.config/innerwarden`. A folder that is a symbolic link is
never written through.

## Limits

| Limit | Value |
|---|---|
| How long a prompt is kept and read | 24 hours |
| Most of one prompt kept | its first 16,384 characters |
| Most kept per session | 65,536 characters; the oldest prompts go first |
| Most sessions kept | 64; the least recently written go first |
| A prompt longer than 1 MiB as the hook reads it | not kept |

A prompt past 24 hours is never read, and it is dropped the next time its
session is written. A session file with nothing left is removed the next time
any session is written.

## The answer

`innerwarden_agent_guard::user_prompt::user_asked_for(session, value)` answers:

- `Yes`: the value appears in a prompt of this session (case and runs of
  blanks are ignored).
- `No`: the session has prompts in the record, and none holds the value.
- `Unknown(reason)`: no session id, no record for the session, a record of
  another session, a value shorter than 4 characters, a value that is a secret
  (kept masked, so never found), or a record that could not be read.

`user_asked_for_in_this_session(value)` reads the session from
`CLAUDE_CODE_SESSION_ID`. What the proxy does with the answer is its own
policy; the record only keeps the words and reads them.

## The hook never stops a prompt

Claude Code drops the person's prompt when a `UserPromptSubmit` hook exits 2,
and adds what it prints on exit 0 to the conversation. So the line is written
in monitor and without the fail-closed script the tool hooks use, and the hook
ends with 0 and prints nothing whatever happens to the record. If the guard's
program is gone, the line ends with 127, which Claude Code shows as an error
while the prompt goes on.

## How to delete it

```sh
rm -rf ~/.config/innerwarden/prompts
```

The guard refuses this to an agent; it is the person's to run. To stop keeping
prompts, take the innerwarden entry out of `hooks.UserPromptSubmit` in
`~/.claude/settings.json`. `innerwarden uninstall` takes it out with the other
hooks; it does not delete the folder.
