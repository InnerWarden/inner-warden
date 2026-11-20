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
            let server = text(&value, "mcp_server_name").unwrap_or("unknown");
            CursorCall::Call(Event::Mcp, call(format!("mcp__{server}__{tool}"), input))
        }
        _ if value.get("tool_name").and_then(Value::as_str).is_some() => CursorCall::Canonical,
        Some(_) => CursorCall::Other,
        None => CursorCall::Unreadable("a Cursor payload with no hook_event_name"),
    }
}

/// The answer that lets a call run.
pub fn allow() -> String {
    json!({ "permission": "allow" }).to_string()
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
         ~/.cursor/hooks.json itself and take the guard out; a shell command that does is \
         refused."
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

    #[test]
    fn only_shell_and_mcp_calls_can_be_asked_about() {
        assert!(Event::Shell.can_ask());
        assert!(Event::Mcp.can_ask());
        assert!(!Event::Read.can_ask());
    }
}
