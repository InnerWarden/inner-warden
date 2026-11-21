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

- The prompt the person submitted, as submitted: text the person pasted into
  it counts as theirs, wherever it came from (a web page, an email, a file).
  It is masked first: obvious secrets (provider
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
inside it (`cp -r ~/.config/innerwarden x`, `cat ~/.config/innerwarden/*/*`).
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
| A prompt longer than 1 MiB as the hook reads it | not kept |

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
- `No`: the session has prompts in the record, and none holds the value.
- `Unknown(reason)`: no session id, no record for the session, a record of
  another session, a value shorter than 4 characters, a value that is a secret
  (kept masked, so never found), or a record that could not be read.

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
script the tool hooks use, and it ends with `--prompt`. With that word the
guard knows, before it reads anything, that it runs on a prompt, and every end
of the run is 0 with nothing printed: the prompt kept or not, stdin it cannot
read, text that is not a payload, a payload past the 1 MiB cap, a panic, the
deadline, a fault. A tool call that arrives on that line is screened as on any
other.

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
