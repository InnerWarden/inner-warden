//! What the guard reads from Cursor's hooks and what it answers.
//!
//! `agents connect cursor` lists one entry under three of the events Cursor
//! runs from `~/.cursor/hooks.json` ([`crate::agent_hooks::CURSOR`]):
//!
//! ```json
//! {
//!   "version": 1,
//!   "hooks": {
//!     "beforeShellExecution": [{"command": "...", "timeout": 60, "failClosed": true}],
//!     "beforeMCPExecution":   [{"command": "...", "timeout": 60, "failClosed": true}],
//!     "beforeReadFile":       [{"command": "...", "timeout": 60, "failClosed": true}]
//!   }
//! }
//! ```
//!
//! Read in Cursor's hooks documentation (cursor.com/docs/agent/hooks, read
//! on 2026-11-20; it names no Cursor version), not measured on a running
//! Cursor:
//!
//! - Cursor sends the call as JSON on stdin, in snake_case: the fields every
//!   event carries (`conversation_id`, `generation_id`, `hook_event_name`,
//!   `cursor_version`, `workspace_roots`, ...) and the event's own:
//!   `command` and `cwd` for a shell command; `tool_name`, `tool_input` (a
//!   JSON string), `mcp_server_name` and `url` or `command` for an MCP call;
//!   `file_path`, `content` and `attachments` for a read.
//! - On exit 0 it reads `permission` from stdout: `allow`, `deny` or `ask`
//!   for a shell command or an MCP call, `allow` or `deny` for a read, with
//!   `user_message` and `agent_message`. Invalid JSON there blocks the call.
//!   Exit 2 blocks it too. Any other exit runs it, unless the entry carries
//!   `failClosed: true`, which blocks on a crash, a timeout, a non-zero exit
//!   or no output.
//! - Hooks from every place run (enterprise, team, project, user), and the
//!   strictest answer wins: `deny` over `ask` over `allow`.
//!
//! So the guard answers every call it lets through with `{"permission":
//! "allow"}`, never with nothing, and a refusal with exit 2 and the reason in
//! the JSON as well.

use serde_json::{json, Value};

/// The agent's id in the listing and on the hook line.
pub const AGENT: &str = "cursor";

/// The event before the agent runs a shell command.
pub const SHELL_EVENT: &str = "beforeShellExecution";

/// The event before the agent calls a tool of an MCP server.
pub const MCP_EVENT: &str = "beforeMCPExecution";

/// The key of the call [`read`] builds that keeps the `url` of the server a
/// Cursor MCP call goes to, when Cursor reaches it by URL.
pub const MCP_SERVER_URL_KEY: &str = "mcp_server_url";

/// Where the hook's call carries that Cursor sent no server name.
pub const MCP_SERVER_UNNAMED_KEY: &str = "mcp_server_unnamed";

/// Where the hook's call carries the command line Cursor gave for the
/// server (a server it runs, not one it reaches by URL).
pub const MCP_SERVER_COMMAND_KEY: &str = "mcp_server_command";

/// Where the hook's call carries Cursor's `workspace_roots`: each may hold
/// a `.cursor/mcp.json` Cursor reads over the user's.
pub const MCP_WORKSPACE_ROOTS_KEY: &str = "mcp_workspace_roots";

/// The event before the agent reads a file.
pub const READ_EVENT: &str = "beforeReadFile";

/// Which of the events a call came on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Shell,
    Mcp,
    Read,
}

impl Event {
    /// Whether Cursor takes `permission: "ask"` for this event. A read takes
    /// `allow` or `deny` only: an `ask` there does not match its schema,
    /// and Cursor blocks it without asking anyone.
    pub fn can_ask(self) -> bool {
        matches!(self, Self::Shell | Self::Mcp)
    }
}

/// A Cursor hook payload, read.
#[derive(Debug, Clone, PartialEq)]
pub enum CursorCall {
    /// The call in the shape the guard reads every agent's in
    /// (`tool_name`, `tool_input`, `cwd`, `session_id`), and its event.
    Call(Event, Value),
    /// A payload already in the shape every agent's hook carries
    /// (`tool_name` and `tool_input`), as Cursor's `preToolUse` sends: judged
    /// as it is. Its event is not one of the three, so a review of it is not
    /// asked about.
    Canonical,
    /// An event the guard is not wired for, with no tool call in it:
    /// nothing to permit or refuse.
    Other,
    /// Not readable as a call of the events the guard is wired for.
    Unreadable(&'static str),
}

/// A non-blank string field of `value`.
fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
}

/// PURE: read a Cursor hook payload as the call the guard judges.
///
/// A shell command is Claude Code's `Bash` call, in its `cwd`. A read is
/// its `Read` call of `file_path`; the file's `content`, which Cursor
/// sends along, is not kept. An MCP call is the tool `mcp__<server>__<tool>`
/// with its arguments, as Claude Code names an MCP tool. A call with no
/// folder of its own is judged in the first workspace root.
pub fn read(payload: &str) -> CursorCall {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return CursorCall::Unreadable("not JSON");
    };
    if !value.is_object() {
        return CursorCall::Unreadable("not a JSON object");
    }
    let root = value
        .get("workspace_roots")
        .and_then(Value::as_array)
        .and_then(|roots| roots.iter().find_map(Value::as_str))
        .filter(|root| !root.trim().is_empty());
    let cwd = text(&value, "cwd").or(root);
    let session = text(&value, "conversation_id");
    let call = |tool: String, input: Value| {
        let mut call = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": tool,
            "tool_input": input,
        });
        if let Some(cwd) = cwd {
            call["cwd"] = json!(cwd);
        }
        if let Some(session) = session {
            call["session_id"] = json!(session);
        }
        call
    };
    match value.get("hook_event_name").and_then(Value::as_str) {
        Some(SHELL_EVENT) => match text(&value, "command") {
            Some(command) => CursorCall::Call(
                Event::Shell,
                call("Bash".to_string(), json!({ "command": command })),
            ),
            None => CursorCall::Unreadable("a Cursor shell call with no command"),
        },
        Some(READ_EVENT) => match text(&value, "file_path") {
            Some(path) => CursorCall::Call(
                Event::Read,
                call("Read".to_string(), json!({ "file_path": path })),
            ),
            None => CursorCall::Unreadable("a Cursor file read with no file path"),
        },
        Some(MCP_EVENT) => {
            let Some(tool) = text(&value, "tool_name") else {
                return CursorCall::Unreadable("a Cursor MCP call with no tool name");
            };
            let input = match value.get("tool_input") {
                None | Some(Value::Null) => json!({}),
                Some(Value::String(raw)) if raw.trim().is_empty() => json!({}),
                Some(Value::String(raw)) => match serde_json::from_str::<Value>(raw) {
                    Ok(parsed @ Value::Object(_)) => parsed,
                    _ => {
                        return CursorCall::Unreadable(
                            "a Cursor MCP call whose tool_input is not a JSON object",
                        )
                    }
                },
                Some(parsed @ Value::Object(_)) => parsed.clone(),
                Some(_) => {
                    return CursorCall::Unreadable(
                        "a Cursor MCP call whose tool_input is not a JSON object",
                    )
                }
            };
            // No server name is carried as a flag, not as a name: a server
            // the configuration calls `unknown` is not this call's server.
            let named = text(&value, "mcp_server_name").filter(|name| !name.trim().is_empty());
            let server = named.unwrap_or("unknown");
            let mut call = call(format!("mcp__{server}__{tool}"), input);
            if named.is_none() {
                call[MCP_SERVER_UNNAMED_KEY] = json!(true);
            }
            // The command line of a server Cursor runs: a call is left to the
            // proxy only when this is the guard's proxy too.
            if let Some(command) = text(&value, "command") {
                call[MCP_SERVER_COMMAND_KEY] = json!(command);
            }
            if let Some(roots) = value
                .get("workspace_roots")
                .filter(|roots| roots.is_array())
            {
                call[MCP_WORKSPACE_ROOTS_KEY] = roots.clone();
            }
            // The address of a server Cursor reaches by URL, never one the
            // proxy carries (a wrapper is a local command): the hook judges
            // such a call as one to a remote server (`crate::mcp_unproxied`).
            if let Some(url) = text(&value, "url") {
                call[MCP_SERVER_URL_KEY] = json!(url);
            }
            CursorCall::Call(Event::Mcp, call)
        }
        _ if value.get("tool_name").and_then(Value::as_str).is_some() => CursorCall::Canonical,
        Some(_) => CursorCall::Other,
        None => CursorCall::Unreadable("a Cursor payload with no hook_event_name"),
    }
}

/// How much of a Cursor payload the hook reads in all, the `content` it
/// throws away included. Past it the call is not read, and is refused in
/// enforce, as any call the hook cannot read is. A `beforeReadFile` carries
/// the whole file it is about; 64 MiB covers the files an agent reads, and
/// keeps what one call can make the hook read (it reads it all, at disk and
/// pipe speed, before it answers) well inside the 60 s Cursor gives the hook,
/// past which an entry with `failClosed: true` refuses the call.
pub const MAX_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024;

/// A Cursor payload as the hook read it: the call with the file's `content`
/// left out (`Whole`), or the head of one whose other fields are longer
/// than the hook keeps (`TooLong`).
#[derive(Debug, PartialEq, Eq)]
pub enum Payload {
    Whole(Vec<u8>),
    TooLong(Vec<u8>),
}

/// The grammar of a JSON string, checked one byte at a time over a value the
/// reader does not keep, so that one it throws away is still one
/// `serde_json` would have read: no byte below 0x20, only the escapes JSON
/// has, four hex digits after `\u`, surrogates in pairs, and UTF-8 that is
/// well formed (no overlong form, no surrogate, nothing past U+10FFFF).
#[derive(Debug, Default)]
struct StringCheck {
    escape: Escape,
    /// Continuation bytes the UTF-8 sequence still needs, and the range the
    /// next one must fall in.
    need: u8,
    low: u8,
    high: u8,
    /// A `\uD800`-`\uDBFF` escape that waits for its low half.
    lead_surrogate: bool,
    /// Something in the string is not JSON.
    broken: bool,
}

#[derive(Debug, Default)]
enum Escape {
    #[default]
    None,
    Backslash,
    Hex {
        left: u8,
        code: u16,
    },
}

impl StringCheck {
    /// Take the next byte of the string's body. True when it is the quote
    /// that ends the string.
    fn step(&mut self, byte: u8) -> bool {
        if self.need > 0 {
            if (self.low..=self.high).contains(&byte) {
                self.need -= 1;
                self.low = 0x80;
                self.high = 0xBF;
                return false;
            }
            // A sequence cut short: the byte is read on its own below.
            self.broken = true;
            self.need = 0;
        }
        match self.escape {
            Escape::None => {}
            Escape::Backslash => {
                self.escape = Escape::None;
                match byte {
                    b'u' => {
                        self.escape = Escape::Hex { left: 4, code: 0 };
                        return false;
                    }
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                        self.broken |= std::mem::take(&mut self.lead_surrogate);
                        return false;
                    }
                    _ => {
                        self.broken = true;
                        return false;
                    }
                }
            }
            Escape::Hex { left, code } => match (byte as char).to_digit(16) {
                Some(digit) => {
                    let code = code * 16 + digit as u16;
                    if left > 1 {
                        self.escape = Escape::Hex {
                            left: left - 1,
                            code,
                        };
                        return false;
                    }
                    self.escape = Escape::None;
                    let lead = std::mem::take(&mut self.lead_surrogate);
                    match code {
                        0xD800..=0xDBFF => {
                            self.broken |= lead;
                            self.lead_surrogate = true;
                        }
                        0xDC00..=0xDFFF => self.broken |= !lead,
                        _ => self.broken |= lead,
                    }
                    return false;
                }
                None => {
                    // Fewer than four digits: the byte is read on its own.
                    self.broken = true;
                    self.escape = Escape::None;
                }
            },
        }
        // A lead surrogate is followed by the `\u` of its low half, and by
        // nothing else.
        if self.lead_surrogate && byte != b'\\' {
            self.broken = true;
            self.lead_surrogate = false;
        }
        match byte {
            b'"' => return true,
            b'\\' => self.escape = Escape::Backslash,
            0x00..=0x1F => self.broken = true,
            0x80..=0xFF => {
                let (need, low, high) = match byte {
                    0xC2..=0xDF => (1, 0x80, 0xBF),
                    0xE0 => (2, 0xA0, 0xBF),
                    0xE1..=0xEC | 0xEE..=0xEF => (2, 0x80, 0xBF),
                    0xED => (2, 0x80, 0x9F),
                    0xF0 => (3, 0x90, 0xBF),
                    0xF1..=0xF3 => (3, 0x80, 0xBF),
                    0xF4 => (3, 0x80, 0x8F),
                    _ => {
                        self.broken = true;
                        (0, 0x80, 0xBF)
                    }
                };
                self.need = need;
                self.low = low;
                self.high = high;
            }
            _ => {}
        }
        false
    }
}

/// One top-level `content` string the reader took out of the payload: where
/// its value was (just after the opening quote), its bytes for as long as
/// they fit beside what is kept, and whether it was valid JSON.
struct Dropped {
    at: usize,
    bytes: Vec<u8>,
    broken: bool,
}

/// Read a Cursor payload from `reader`, keeping at most `keep` bytes, with
/// the string value of the top-level `content` key (the text of the file a
/// `beforeReadFile` is about, which the guard never judges) read through and
/// thrown away as it streams, so a large file costs no memory and does not
/// count toward `keep`. What is kept is the payload with `"content": ""`.
///
/// Only a `beforeReadFile` loses its content. The value is held while it
/// fits within `keep` beside the rest, and once the whole payload is read
/// it goes back where it was for any other event: such a call is kept as it
/// came, or is `TooLong` when it does not fit.
///
/// A value that is thrown away is still checked as a JSON string
/// ([`StringCheck`]): a byte below 0x20, an escape JSON does not have, a
/// lone surrogate or broken UTF-8 in it leaves what is kept not JSON, as the
/// payload was, so the call stays unreadable. Nothing else is parsed here
/// beyond what finds that one value: the kept bytes are read as JSON
/// afterwards, and a payload that is not JSON (one cut short inside the
/// content too) stays unreadable. A `content` inside another object, or one
/// whose value is not a string, is kept as it is. Past `total` bytes in all,
/// the call is `TooLong`.
pub fn read_without_content(
    reader: impl std::io::Read,
    keep: usize,
    total: u64,
) -> std::io::Result<Payload> {
    use std::io::BufRead;
    let mut reader = std::io::BufReader::with_capacity(64 * 1024, reader);
    let mut out: Vec<u8> = Vec::new();
    let mut seen: u64 = 0;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut expect_key = false;
    let mut key: Option<Vec<u8>> = None;
    let mut key_is_content = false;
    let mut want_value = false;
    let mut skipping: Option<StringCheck> = None;
    let mut dropped: Vec<Dropped> = Vec::new();
    // Bytes of every dropped value still held, and whether one did not fit.
    let mut held = 0usize;
    let mut overflow = false;
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return Ok(put_back(out, dropped, overflow, keep));
        }
        let len = chunk.len();
        seen += len as u64;
        if seen > total {
            out.truncate(keep);
            return Ok(Payload::TooLong(out));
        }
        for &byte in chunk {
            if let Some(check) = skipping.as_mut() {
                let ended = check.step(byte);
                let value = dropped.last_mut().expect("a value being dropped");
                if ended {
                    value.broken = check.broken;
                    skipping = None;
                    out.push(b'"');
                } else if !overflow {
                    if out.len() + held + 1 > keep {
                        overflow = true;
                    } else {
                        value.bytes.push(byte);
                        held += 1;
                    }
                }
                continue;
            }
            if want_value {
                if byte.is_ascii_whitespace() {
                    out.push(byte);
                    continue;
                }
                want_value = false;
                if byte == b'"' {
                    out.push(b'"');
                    skipping = Some(StringCheck::default());
                    dropped.push(Dropped {
                        at: out.len(),
                        bytes: Vec::new(),
                        broken: false,
                    });
                    continue;
                }
            }
            out.push(byte);
            if in_string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = false;
                    if let Some(name) = key.take() {
                        key_is_content = name == b"content";
                    }
                    continue;
                }
                if let Some(name) = key.as_mut() {
                    name.push(byte);
                }
            } else {
                match byte {
                    b'"' => {
                        in_string = true;
                        if depth == 1 && expect_key {
                            key = Some(Vec::new());
                            expect_key = false;
                        }
                    }
                    b'{' | b'[' => {
                        depth += 1;
                        if byte == b'{' && depth == 1 {
                            expect_key = true;
                        }
                    }
                    b'}' | b']' => depth = depth.saturating_sub(1),
                    b',' if depth == 1 => expect_key = true,
                    b':' if depth == 1 => {
                        want_value = std::mem::take(&mut key_is_content);
                    }
                    _ => {}
                }
            }
            if out.len() > keep {
                out.truncate(keep);
                return Ok(Payload::TooLong(out));
            }
        }
        reader.consume(len);
    }
}

/// The payload once it is all read: a `beforeReadFile` keeps its content
/// out (a value that was not a JSON string leaves a control byte in its
/// place, so the call stays unreadable); any other event, or a payload that
/// names none, gets each dropped value back where it was. A payload that is
/// not JSON without its content is kept as it is: it cannot be read either
/// way.
fn put_back(mut out: Vec<u8>, dropped: Vec<Dropped>, overflow: bool, keep: usize) -> Payload {
    if dropped.is_empty() {
        return Payload::Whole(out);
    }
    // What is kept is not JSON (cut short, broken outside the content): the
    // call is unreadable whatever its content held, and stays so as it is.
    let Ok(value) = serde_json::from_slice::<Value>(&out) else {
        return Payload::Whole(out);
    };
    let event = value.get("hook_event_name").and_then(Value::as_str);
    if event == Some(READ_EVENT) {
        for value in dropped.iter().rev().filter(|value| value.broken) {
            out.insert(value.at, 0x01);
        }
        return Payload::Whole(out);
    }
    for value in dropped.into_iter().rev() {
        out.splice(value.at..value.at, value.bytes);
    }
    if overflow || out.len() > keep {
        out.truncate(keep);
        return Payload::TooLong(out);
    }
    Payload::Whole(out)
}

/// The answer that lets a call run.
pub fn allow() -> String {
    json!({ "permission": "allow" }).to_string()
}

/// The answer that lets a call run with a warning for the person and the
/// agent (the default posture's, `crate::posture::warning_line`).
pub fn allow_with_warning(message: &str) -> String {
    json!({
        "permission": "allow",
        "user_message": message,
        "agent_message": message,
    })
    .to_string()
}

/// The answer that asks the person, with the guard's words.
pub fn ask(message: &str) -> String {
    json!({
        "permission": "ask",
        "user_message": message,
        "agent_message": message,
    })
    .to_string()
}

/// The answer that refuses a call, with the guard's words.
pub fn deny(message: &str) -> String {
    json!({
        "permission": "deny",
        "user_message": message,
        "agent_message": message,
    })
    .to_string()
}

/// What the hook and the proxy screen between them, in the words that
/// follow "screened before they run: ".
pub fn screened() -> String {
    "shell commands (`beforeShellExecution`), the command lines and file paths in calls to \
     MCP tools (`beforeMCPExecution`, for every server, beside the proxy for those behind it), \
     and reads of secrets by the agent (`beforeReadFile`). Its file edits and other tools are \
     not screened."
        .to_string()
}

/// What a hook that is on still leaves out, and when Cursor stops running
/// it. Each line is one fact read in Cursor's documentation.
pub fn gaps() -> Vec<String> {
    vec![
        "Not screened: the agent's own file edits (Cursor has no hook before an edit, only \
         after it), Tab's reads and completions, and its other tools. An edit can change \
         ~/.cursor/hooks.json itself; a shell command that does is refused. While the file \
         still lists the guard under some of its events but not all (an entry taken out, \
         failClosed turned off), every Cursor call the guard still sees is refused until \
         `innerwarden agents connect cursor` puts it back. An edit that takes out every \
         entry at once is not seen: Cursor then starts no hook of ours."
            .to_string(),
        "A review asks you for a shell command or an MCP call (`permission: ask`). A read \
         cannot be asked about (`beforeReadFile` takes allow or deny only), so a read rated \
         review is refused with the reason."
            .to_string(),
        "Cursor also runs the hooks of a project's .cursor/hooks.json (in a workspace it \
         trusts) and of enterprise files. They run beside this one and cannot lift its \
         refusal: Cursor lets the strictest answer win. They are not read here."
            .to_string(),
        "In enforce mode the entry carries `failClosed: true`: a guard that is missing, cannot \
         start, is killed, times out or ends without its answer refuses the call. In monitor \
         mode it is false, and such a call runs."
            .to_string(),
        "The guard answers within 10 seconds (more only while it waits on a second opinion you \
         turned on) or refuses the call in enforce mode. Cursor gives the hook 60 seconds (the \
         entry's `timeout`)."
            .to_string(),
        "How Cursor starts the hook line was not measured. On Linux and macOS the enforcing \
         line starts /bin/sh itself, so it ends in exit 2 when the guard cannot answer, with \
         or without `failClosed`."
            .to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The payloads below are the fields Cursor's hooks documentation lists
    /// for each event, with the fields every event carries.
    fn common(event: &str) -> Value {
        json!({
            "conversation_id": "668320d2-2fd8-4888-b33c-2a466fec86e7",
            "generation_id": "490b90b7-a2ce-4c2c-bb76-cb77b125df2f",
            "model": "claude-sonnet",
            "hook_event_name": event,
            "cursor_version": "1.7.2",
            "workspace_roots": ["/home/dev/app"],
            "user_email": null,
            "transcript_path": null,
        })
    }

    fn with(event: &str, fields: Value) -> String {
        let mut payload = common(event);
        for (key, value) in fields.as_object().unwrap() {
            payload[key] = value.clone();
        }
        payload.to_string()
    }

    #[test]
    fn a_shell_command_is_a_bash_call_in_its_folder() {
        let payload = with(
            SHELL_EVENT,
            json!({"command": "git status", "cwd": "/home/dev/app/src", "sandbox": false}),
        );
        let CursorCall::Call(Event::Shell, call) = read(&payload) else {
            panic!("{:?}", read(&payload));
        };
        assert_eq!(call["tool_name"], "Bash");
        assert_eq!(call["tool_input"]["command"], "git status");
        assert_eq!(call["cwd"], "/home/dev/app/src");
        assert_eq!(call["session_id"], "668320d2-2fd8-4888-b33c-2a466fec86e7");
    }

    #[test]
    fn a_read_is_a_read_call_and_the_content_is_not_kept() {
        let payload = with(
            READ_EVENT,
            json!({"file_path": "/home/dev/.ssh/id_ed25519", "content": "PRIVATE", "attachments": []}),
        );
        let CursorCall::Call(Event::Read, call) = read(&payload) else {
            panic!("{:?}", read(&payload));
        };
        assert_eq!(call["tool_name"], "Read");
        assert_eq!(call["tool_input"]["file_path"], "/home/dev/.ssh/id_ed25519");
        assert_eq!(call["cwd"], "/home/dev/app", "judged in the first root");
        assert!(!call.to_string().contains("PRIVATE"), "{call}");
    }

    #[test]
    fn an_mcp_call_is_named_as_claude_code_names_one_with_its_arguments() {
        let payload = with(
            MCP_EVENT,
            json!({
                "tool_name": "run_command",
                "tool_input": "{\"command\":\"ls -la\"}",
                "mcp_server_name": "shell",
                "command": "npx shell-server",
            }),
        );
        let CursorCall::Call(Event::Mcp, call) = read(&payload) else {
            panic!("{:?}", read(&payload));
        };
        assert_eq!(call["tool_name"], "mcp__shell__run_command");
        assert_eq!(call["tool_input"]["command"], "ls -la");
        assert!(call.get(MCP_SERVER_URL_KEY).is_none(), "{call}");
    }

    /// A call to a server Cursor reaches by URL keeps the address, so the
    /// hook knows the server is remote, with or without its name.
    #[test]
    fn an_mcp_call_to_a_server_reached_by_url_keeps_the_address() {
        let payload = with(
            MCP_EVENT,
            json!({
                "tool_name": "get_file",
                "tool_input": "{\"path\":\"a.txt\"}",
                "url": "https://mcp.example/mcp",
            }),
        );
        let CursorCall::Call(Event::Mcp, call) = read(&payload) else {
            panic!("{:?}", read(&payload));
        };
        assert_eq!(call["tool_name"], "mcp__unknown__get_file");
        assert_eq!(call[MCP_SERVER_URL_KEY], "https://mcp.example/mcp");
    }

    /// No server name (absent or empty) is carried as a flag, never taken
    /// for a server called `unknown`; a server really called so is not
    /// flagged. The command line Cursor gives for the server is kept.
    #[test]
    fn an_mcp_call_with_no_server_name_is_flagged_and_its_command_kept() {
        for fields in [
            json!({"tool_name": "get_file", "tool_input": "{}"}),
            json!({"tool_name": "get_file", "tool_input": "{}", "mcp_server_name": " "}),
        ] {
            let payload = with(MCP_EVENT, fields);
            let CursorCall::Call(Event::Mcp, call) = read(&payload) else {
                panic!("{:?}", read(&payload));
            };
            assert_eq!(call["tool_name"], "mcp__unknown__get_file");
            assert_eq!(call[MCP_SERVER_UNNAMED_KEY], true, "{call}");
        }
        let payload = with(
            MCP_EVENT,
            json!({"tool_name": "get_file", "tool_input": "{}", "mcp_server_name": "unknown",
                   "command": "/usr/local/bin/innerwarden proxy -- npx fs"}),
        );
        let CursorCall::Call(Event::Mcp, call) = read(&payload) else {
            panic!("{:?}", read(&payload));
        };
        assert!(call.get(MCP_SERVER_UNNAMED_KEY).is_none(), "{call}");
        assert_eq!(
            call[MCP_SERVER_COMMAND_KEY],
            "/usr/local/bin/innerwarden proxy -- npx fs"
        );
    }

    #[test]
    fn a_call_that_cannot_be_read_is_said_so_and_another_event_is_nothing() {
        assert!(matches!(read("nope"), CursorCall::Unreadable(_)));
        assert!(matches!(read("[1]"), CursorCall::Unreadable(_)));
        assert!(matches!(
            read(&with(SHELL_EVENT, json!({"cwd": "/x"}))),
            CursorCall::Unreadable(_)
        ));
        assert!(matches!(
            read(&with(READ_EVENT, json!({"content": "x"}))),
            CursorCall::Unreadable(_)
        ));
        assert!(matches!(
            read(&with(
                MCP_EVENT,
                json!({"tool_name": "t", "tool_input": "not json"})
            )),
            CursorCall::Unreadable(_)
        ));
        assert!(matches!(
            read(&json!({"command": "ls"}).to_string()),
            CursorCall::Unreadable(_)
        ));
        assert_eq!(read(&with("afterFileEdit", json!({}))), CursorCall::Other);
        // A tool call in the shape every agent's hook carries is judged as it
        // is, never let through as an event the guard is not wired for.
        assert_eq!(
            read(&with(
                "preToolUse",
                json!({"tool_name": "Shell", "tool_input": {"command": "ls"}})
            )),
            CursorCall::Canonical
        );
        assert_eq!(
            read(
                &json!({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}})
                    .to_string()
            ),
            CursorCall::Canonical
        );
    }

    #[test]
    fn every_answer_is_one_line_of_json_with_a_permission() {
        for (answer, permission) in [
            (allow(), "allow"),
            (ask("flagged"), "ask"),
            (deny("refused"), "deny"),
        ] {
            assert!(!answer.contains('\n'));
            let value: Value = serde_json::from_str(&answer).unwrap();
            assert_eq!(value["permission"], permission);
        }
        let denied: Value = serde_json::from_str(&deny("why")).unwrap();
        assert_eq!(denied["user_message"], "why");
        assert_eq!(denied["agent_message"], "why");
    }

    fn kept(payload: &str, keep: usize) -> Payload {
        read_without_content(payload.as_bytes(), keep, MAX_PAYLOAD_BYTES).unwrap()
    }

    /// The content of a read is thrown away as it streams, escapes and all,
    /// and the rest of the call is kept as it came; a call that is not JSON
    /// stays one that is not JSON.
    #[test]
    fn a_reads_content_is_dropped_and_nothing_else() {
        let content = "x\\\" \\\\ \\u0041 }{,:\"content\":".repeat(1000);
        let payload = with(
            READ_EVENT,
            json!({"file_path": "/home/dev/app/big.txt", "content": content, "attachments": []}),
        );
        let Payload::Whole(bytes) = kept(&payload, 4096) else {
            panic!("the content counted toward the cap");
        };
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["content"], "");
        assert_eq!(value["file_path"], "/home/dev/app/big.txt");
        let mut expected: Value = serde_json::from_str(&payload).unwrap();
        expected["content"] = json!("");
        assert_eq!(value, expected);
        let CursorCall::Call(Event::Read, call) = read(std::str::from_utf8(&bytes).unwrap()) else {
            panic!();
        };
        assert_eq!(call["tool_input"]["file_path"], "/home/dev/app/big.txt");

        // A `content` that is not the top level's, or not a string, stays.
        let nested =
            r#"{"hook_event_name":"preToolUse","tool_input":{"content":"keep me"},"content":7}"#;
        assert_eq!(
            kept(nested, 4096),
            Payload::Whole(nested.as_bytes().to_vec())
        );

        // Cut short inside the content: what is kept is not JSON.
        let cut = &payload[..payload.len() / 2];
        let Payload::Whole(bytes) = kept(cut, 4096) else {
            panic!();
        };
        assert!(serde_json::from_slice::<Value>(&bytes).is_err());

        // The other fields still count toward the cap, and so does the whole.
        let long = with(
            READ_EVENT,
            json!({"file_path": "a".repeat(5000), "content": "x"}),
        );
        assert!(matches!(kept(&long, 4096), Payload::TooLong(_)));
        assert!(matches!(
            read_without_content(payload.as_bytes(), 4096, 100).unwrap(),
            Payload::TooLong(_)
        ));
    }

    fn kept_bytes(payload: &[u8], keep: usize) -> Payload {
        read_without_content(payload, keep, MAX_PAYLOAD_BYTES).unwrap()
    }

    /// A read whose content is `body`, the raw bytes of a JSON string's
    /// inside.
    fn read_with_raw_content(body: &[u8]) -> Vec<u8> {
        let mut payload =
            br#"{"hook_event_name":"beforeReadFile","file_path":"/a","content":""#.to_vec();
        payload.extend_from_slice(body);
        payload.extend_from_slice(br#"","attachments":[]}"#);
        payload
    }

    /// A content that is not a JSON string is thrown away all the same, but
    /// what is kept stays a call that cannot be read, as the payload was: a
    /// control byte, an escape JSON does not have, a short `\u`, a lone
    /// surrogate, broken UTF-8. A content that is a JSON string, however
    /// odd, leaves a call that reads.
    #[test]
    fn a_dropped_content_must_still_be_a_json_string() {
        let broken: &[&[u8]] = &[
            b"a\x01b",
            b"tab\there",
            b"\\q",
            b"\\u12",
            b"\\u12\"",
            b"\\ud800",
            b"\\ud800x",
            b"\\ud800\\n",
            b"\\ud800\\u0041",
            b"\\udc00",
            b"\xff",
            b"\xc0\x80",
            b"\xe0\x80\x80",
            b"\xed\xa0\x80",
            b"\xf4\x90\x80\x80",
            b"\xe2\x82",
            b"\xc3",
        ];
        for body in broken {
            let payload = read_with_raw_content(body);
            assert!(
                serde_json::from_slice::<Value>(&payload).is_err(),
                "{body:?} is not JSON"
            );
            let Payload::Whole(kept) = kept_bytes(&payload, 4096) else {
                panic!("{body:?}");
            };
            assert!(
                serde_json::from_slice::<Value>(&kept).is_err(),
                "{body:?}: {}",
                String::from_utf8_lossy(&kept)
            );
            assert!(
                !matches!(
                    std::str::from_utf8(&kept).map(read),
                    Ok(CursorCall::Call(..))
                ),
                "{body:?} must not read as a call"
            );
        }
        let fine: &[&[u8]] = &[
            "caf\u{e9} \u{1f600} \u{4e2d}".as_bytes(),
            b"\\ud83d\\ude00 \\u00e9 \\\" \\\\ \\/ \\b \\f \\n \\r \\t",
            b"\x7f",
            b"",
        ];
        for body in fine {
            let payload = read_with_raw_content(body);
            assert!(
                serde_json::from_slice::<Value>(&payload).is_ok(),
                "{body:?} is JSON"
            );
            let Payload::Whole(kept) = kept_bytes(&payload, 4096) else {
                panic!("{body:?}");
            };
            let value: Value = serde_json::from_slice(&kept).unwrap();
            assert_eq!(value["content"], "");
            assert_eq!(value["file_path"], "/a");
        }
    }

    /// Only a `beforeReadFile` loses its content, wherever its event name
    /// comes in the payload. Any other call keeps it as it came, and one
    /// whose content does not fit is `TooLong`, as before the content was
    /// ever dropped.
    #[test]
    fn only_a_read_loses_its_content() {
        let late =
            br#"{"content":"secret text","file_path":"/a","hook_event_name":"beforeReadFile"}"#;
        let Payload::Whole(late_kept) = kept_bytes(late, 4096) else {
            panic!();
        };
        assert_eq!(
            serde_json::from_slice::<Value>(&late_kept).unwrap()["content"],
            ""
        );

        for event in [SHELL_EVENT, MCP_EVENT, "beforeTabFileRead", "preToolUse"] {
            let payload =
                json!({"content": "keep \"me\" \u{e9}", "hook_event_name": event, "command": "ls"})
                    .to_string();
            assert_eq!(
                kept(&payload, 4096),
                Payload::Whole(payload.as_bytes().to_vec()),
                "{event}"
            );
            let big = json!({"hook_event_name": event, "content": "x".repeat(10_000)}).to_string();
            assert!(matches!(kept(&big, 4096), Payload::TooLong(_)), "{event}");
            // Two values, put back in their places.
            let two = format!(r#"{{"content":"one","hook_event_name":"{event}","content":"two"}}"#);
            assert_eq!(kept(&two, 4096), Payload::Whole(two.as_bytes().to_vec()));
        }
        // No event at all: kept as it came.
        let none = r#"{"content":"x","file_path":"/a"}"#;
        assert_eq!(kept(none, 4096), Payload::Whole(none.as_bytes().to_vec()));
        // A broken content in another event stays broken.
        let mut shell =
            br#"{"hook_event_name":"beforeShellExecution","command":"ls","content":"a"#.to_vec();
        shell.push(0x01);
        shell.extend_from_slice(br#""}"#);
        let Payload::Whole(shell_kept) = kept_bytes(&shell, 4096) else {
            panic!();
        };
        assert_eq!(shell_kept, shell);
    }

    #[test]
    fn the_hook_reads_at_most_64_mib_of_a_payload() {
        assert_eq!(MAX_PAYLOAD_BYTES, 64 * 1024 * 1024);
        let mut payload =
            br#"{"hook_event_name":"beforeReadFile","file_path":"/a","content":""#.to_vec();
        payload.resize(payload.len() + MAX_PAYLOAD_BYTES as usize, b'x');
        payload.extend_from_slice(br#""}"#);
        assert!(matches!(kept_bytes(&payload, 4096), Payload::TooLong(_)));
    }

    #[test]
    fn only_shell_and_mcp_calls_can_be_asked_about() {
        assert!(Event::Shell.can_ask());
        assert!(Event::Mcp.can_ask());
        assert!(!Event::Read.can_ask());
    }
}
