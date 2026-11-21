# What the person asked: the prompt record

The MCP proxy sees a tool call and the values in it. It cannot tell, from the
call alone, a value the person typed ("send the report to ana@example.com")
from the same value written by a model that read it in a web page or a file.
The prompt record gives it the person's own words, per agent session, so it
can ask one question: does this value appear in what the person asked?

This page says what the answer is for, what is kept, where, for how long, and
how to delete it.

## Information, never a pass

The answer never lets a refused call through. An agent with a shell on the
person's account can write a record of its own: it runs `innerwarden hook`
with a `UserPromptSubmit` payload it made up, and the record then says the
person asked for whatever the agent wrote. The rule that stops an agent
running the guard's own hook reads the command's text, so a copy of the
program or a variable gets past it. A test shows the forgery
(`an_agent_with_a_shell_can_forge_a_record`).

So the record is information only: what it can do is say that a value in a
call is not in what the person asked (an alert). It lowers nothing, and it
will not until the record has a writer the agent cannot imitate.

## Which agents

| Agent | Session id its prompt hook gets | Session id its MCP servers get | Channel | How it was found |
|---|---|---|---|---|
| Claude Code | `session_id` in the `UserPromptSubmit` payload | `CLAUDE_CODE_SESSION_ID` in the environment | on | read in the environment of the processes it starts |
| Codex CLI | `session_id` in the `UserPromptSubmit` payload (the thread id) | none: a stdio server gets a fixed list (`HOME`, `LOGNAME`, `PATH`, `SHELL`, `USER`, `LANG`, `LC_ALL`, `TERM`, `TMPDIR`, `TZ`) plus its own `env` | off | Codex's source (`codex-rs/hooks`, `codex-rs/rmcp-client`); not measured on a running Codex |
| Gemini CLI | `session_id` in the hook payload | none found | off | Gemini CLI's source (`packages/core`); not measured on a running Gemini CLI |
| Hermes Agent | `session_id` in the `pre_llm_call` payload | none: a stdio server gets `PATH`, `HOME`, `USER`, `LANG`, `LC_ALL`, `TERM`, `SHELL`, `TMPDIR`, `HERMES_HOME` plus its own `env` | off | Hermes v0.23.1 source (`tools/mcp_tool_config.py`); not measured on a running Hermes |
| Cursor | not measured | not measured | off | not measured: closed source, no Cursor at hand |

"Not measured on a running agent": starting one of these agents from an
agent session, with a hook and an MCP server that only record what they get,
is refused by the guard (an agent starting another agent with its hook moved
away), rightly. What the table says comes from the agents' own source.

The channel is on only where both columns hold the same id. For the other
agents a record could never be read for the call it was meant for, because the
proxy has no session id to match it with, so the answer would always be
"unknown": their prompts are not kept, and `innerwarden status` says, under
each of them, that the prompt channel is off and why. An agent turns on the
day it hands its MCP servers the id its prompt hook gets, and it is measured.

That Claude Code hands `CLAUDE_CODE_SESSION_ID` to an MCP server it starts was
read in the environment of the processes it starts, not measured on a running
MCP server.

## What is kept

- What the person submitted, up to the limits below (its first 16,384
  characters, 65,536 per session): text the person pasted into the prompt
  counts as theirs, wherever it came from (a web page, an email, a file).
  When a limit takes words off, the record says so, and a value not found is
  then "unknown", never "no" (see [The answer](#the-answer)). Each prompt is
  masked first: obvious secrets (provider
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
own writes under `~/.config/innerwarden`, and it refuses an agent's reads of
the prompts folder: a file tool (Read, Grep) pointed into it, and a shell line
that reads a file in it (`cat`, `head`, `tar`, an interpreter's `open`), or
hands a reading program the whole `~/.config/innerwarden` folder or a glob
inside it (`cp -r ~/.config/innerwarden x`, `cat ~/.config/innerwarden/*/*`;
the refusal names the whole folder, which holds the LLM key too).
The rule reads the command's text: a name relative to a `cd` into the folder
(`cd ~/.config/innerwarden && cat prompts/x.json`) and a glob in the folder's
own name (`cat ~/.config/inner*/prompts/*`) are not recognised (measured with
`innerwarden check`). Listing the folder (`ls`) is allowed: the file names
are hashes. A folder that is a symbolic link is never written through.

## Limits

| Limit | Value |
|---|---|
| How long a prompt is kept and read | 24 hours |
| Most of one prompt kept | its first 16,384 characters |
| Most kept per session | 65,536 characters; the oldest prompts go first |
| Most sessions kept | 64; the least recently written go first |
| A prompt longer than 1 MiB as the hook reads it | not kept; its session is marked as having lost words |

Two hook runs of one session at once do not write over each other: a record
is read, changed and written back with the update lock the guard uses for
its own record held from the read to the write, so no run reads what another
is about to replace. The write is tried again, up to 8 times, waiting up to
1 s for the lock each time, when the lock stays held or a writer that does not
take it changed the file in between. A
prompt that still cannot be written is not kept: an empty mark beside the
record (`.<name>.json.lost`) says the session lost a prompt, and a value not
found answers "unknown", never "no". A mark with no record beside it goes after
24 hours and counts toward the 64 sessions kept. Each record has its lock file beside it
(`.<name>.json.innerwarden.lock`), removed with the record.

A prompt past 24 hours is never read. It is deleted:

- when its session is written (the next prompt) or read (the proxy asks about
  that session); a session file left with nothing is removed then;
- with every other expired session file, when any session is written, and
  when the proxy reads, at most once a minute.

Nothing runs on a timer: with no prompt and no read after it, an expired file
stays on disk, unread, until the next one. A read deletes only when the file
still holds what it read, so a prompt written at the same moment is not lost.

## The answer

`innerwarden_agent_guard::user_prompt::user_asked_for(session, value)` answers:

- `Yes`: the value appears whole in a prompt of this session (case and runs
  of blanks are ignored). Whole means no letter, digit or one of `@._-+/:%~=#&`
  right before or after it: `ana@example.com` is not found in
  `ana@example.com.au` nor in `joana@example.com`, and `issue 4512` is not
  found in `issue 45123`. A mark that ends a sentence after it
  (`ana@example.com.`) is not part of it.
- `No`: the session has prompts in the record, none holds the value, and the
  session lost no words: no prompt was cut to 16,384 characters, dropped for
  the 65,536 per session or past its day, or left unkept past the hook's
  1 MiB cap.
- `Unknown(reason)`: no session id, no record for the session, a record of
  another session, a value shorter than 4 characters, a value that is a secret
  (kept masked, so never found), a record that could not be read, or a value
  not found in a session that lost words (any of the cuts above): it may
  have been in what is gone.

`user_asked_for_in_this_session(value)` reads the session from
`CLAUDE_CODE_SESSION_ID` in the proxy's environment. Any process between
Claude Code and the proxy can change that variable: a wrong id reads another
session's words or none (only reads; nothing is written from it). Together
with the forgery above, this is why the answer is information and never a
pass.

## The hook never drops a prompt

Claude Code drops the person's prompt when a `UserPromptSubmit` hook exits 2,
shows an error for any other end but 0, and adds what a hook prints on exit 0
to the conversation. The line is the guard alone, without the fail-closed
script the tool hooks use, and it ends with `--prompt`. With that last word
the guard knows, before it reads anything, that it runs on a prompt, and every
end of the run is 0 with nothing printed: the prompt kept or not, stdin it
cannot read, text that is not JSON, a prompt past the 1 MiB cap, a panic, the
deadline, a fault. Only a payload whose event is `UserPromptSubmit` and that
names no tool is kept as a prompt. Any other JSON on that line (a tool call of
any shape, a prompt event that names a tool) goes to the screening every line
gives a call, and is refused or allowed as there.

A prompt the person submitted never ends a run with 2, on any line: on a line
without the flag it is not kept and goes on. One case is left: on a line
without the flag, a prompt longer than 1 MiB whose event name comes after the
first 1 MiB cannot be told from a tool call, and is refused as one; Claude
Code's prompt line carries the flag, where such a head is read as a prompt.

The flag counts only as the line's last word, and the line is in order only
under `UserPromptSubmit`. The same line under a tool event screens nothing:
`innerwarden status` does not count it as a hook of ours that screens, and
`innerwarden install` replaces it. Its run still ends with 0 on stdin it
cannot read, text that is not JSON, the deadline or a panic, which is why
status says that event is not screened when every line of ours under it is
the prompt line; any JSON on it that is not a prompt naming no tool is
screened and refused as on any other line. Writing such a line takes an edit
of the agent's settings, which the guard refuses to the agent (measured with `innerwarden check`: `jq` into a temp file and `mv`, `sed -i`, `python3` and `jq | sponge` on the `PreToolUse` of `~/.claude/settings.json` are each `deny`). Cursor's wiring has no prompt
line, and the flag is ignored on a line that names Cursor.

The one end the guard cannot answer for: if its program is gone, the shell
ends the line with 127, which Claude Code shows as an error while the prompt
goes on.

## How to delete it

```sh
rm -rf ~/.config/innerwarden/prompts
```

The guard refuses this to an agent; it is the person's to run. To stop keeping
prompts, take the innerwarden entry out of `hooks.UserPromptSubmit` in
`~/.claude/settings.json`. `innerwarden uninstall` takes it out with the other
hooks; it does not delete the folder.
