//! What the guard reads from the Antigravity CLI's hooks and what it answers.
//!
//! The Antigravity CLI (`agy`) took the place of Gemini CLI for its free and
//! individual users on 2026-06-18. Its hooks are another contract from
//! Gemini CLI's, read in its hooks documentation (antigravity.google/docs/hooks,
//! read on 2026-11-21; it names no `agy` version), not measured on a running
//! `agy`, which needs a Google login:
//!
//! - The global file is `~/.gemini/config/hooks.json` (hooks in
//!   `~/.gemini/antigravity-cli/settings.json` are not loaded). The
//!   Antigravity App and IDE read the same file.
//! - Its top level maps a hook's NAME to its events. `agents connect
//!   antigravity` writes one name of its own, [`HOOK_NAME`], with one group
//!   under `PreToolUse`:
//!
//! ```json
//! {
//!   "innerwarden": {
//!     "PreToolUse": [
//!       {"hooks": [{"command": "...", "timeout": 60, "type": "command"}], "matcher": ""}
//!     ]
//!   }
//! }
//! ```
//!
//!   A matcher of `""` matches every tool, so every tool call reaches the
//!   guard.
//! - The call comes on stdin as JSON in camelCase: `toolCall.name`,
//!   `toolCall.args`, `stepIdx`, `conversationId`, `workspacePaths` and the
//!   rest of the common fields. Each tool carries its own argument names
//!   (`run_command`'s `CommandLine` and `Cwd`, `view_file`'s `AbsolutePath`).
//! - The answer is JSON on stdout: `decision` (`allow`, `auto_approve`,
//!   `deny`, `ask`, `force_ask`, `deny_unless_prior_grant`) and `reason`.
//!
//! What `agy` does with a hook that exits with another code than 0, times out
//! or prints something it cannot read is not in that documentation. The
//! Gemini API's own agent hooks treat all three as an approval
//! (ai.google.dev/gemini-api/docs/agent-hooks). So the guard does not lean
//! on its exit code here: every call it sees is answered with a JSON decision
//! on stdout and exit 0, a refusal included, and the enforcing hook line
//! prints a `deny` itself when the guard ends without one
//! ([`crate::hook::hook_command_shaped`]).

use serde_json::{json, Map, Value};

/// The agent's id in the listing and on the hook line.
pub const AGENT: &str = "antigravity";

/// The name the guard's hook is listed under in the hooks file.
pub const HOOK_NAME: &str = "innerwarden";

/// The event before the agent runs a tool.
pub const EVENT: &str = "PreToolUse";

/// The global hooks file, relative to the home directory.
pub const FILE: &str = ".gemini/config/hooks.json";

/// An Antigravity hook payload, read.
#[derive(Debug, Clone, PartialEq)]
pub enum AgyCall {
    /// The call in the shape the guard reads every agent's in (`tool_name`,
    /// `tool_input`, `cwd`, `session_id`).
    Call(Value),
    /// Not readable as a tool call.
    Unreadable(&'static str),
}

/// A non-blank string field of `value`.
fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
}

/// The glob of a search limited by `Includes` (a list, or one string): the
/// first that aims at secrets, else the first. A search whose glob aims at
/// secrets is judged as the hunt it is, so that one is the one kept.
fn include_glob(args: &Value) -> Option<String> {
    let globs: Vec<&str> = match args.get("Includes") {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    let globs: Vec<&str> = globs
        .into_iter()
        .filter(|glob| !glob.trim().is_empty())
        .collect();
    globs
        .iter()
        .find(|glob| crate::threats::glob_aims_at_secrets(glob))
        .or_else(|| globs.first())
        .map(|glob| glob.to_string())
}

/// PURE: read an Antigravity hook payload as the call the guard judges.
///
/// Each documented tool the guard screens becomes Claude Code's call of the
/// same kind: `run_command` is `Bash` in its `Cwd`, `view_file` is `Read`,
/// `write_to_file` is `Write`, `replace_file_content` is `Edit`,
/// `multi_replace_file_content` is `MultiEdit`, `grep_search` is `Grep` and
/// `find_by_name` is `Glob`. Any other tool keeps its own name and
/// arguments, and is judged as every agent's unknown tool is. A call with no
/// folder of its own is judged in the first workspace path.
///
/// A screened tool without the argument that names what it acts on is
/// unreadable, never let through as if it named nothing.
pub fn read(payload: &str) -> AgyCall {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return AgyCall::Unreadable("not JSON");
    };
    if !value.is_object() {
        return AgyCall::Unreadable("not a JSON object");
    }
    let Some(tool_call) = value.get("toolCall").filter(|call| call.is_object()) else {
        return AgyCall::Unreadable("an Antigravity call with no toolCall");
    };
    let Some(name) = text(tool_call, "name") else {
        return AgyCall::Unreadable("an Antigravity call with no tool name");
    };
    let args = match tool_call.get("args") {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(args @ Value::Object(_)) => args.clone(),
        Some(_) => return AgyCall::Unreadable("an Antigravity call whose args is not an object"),
    };
    let root = value
        .get("workspacePaths")
        .and_then(Value::as_array)
        .and_then(|roots| roots.iter().find_map(Value::as_str))
        .filter(|root| !root.trim().is_empty());
    let cwd = text(&args, "Cwd").or(root);
    let session = text(&value, "conversationId");
    let call = |tool: &str, input: Value| {
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
        AgyCall::Call(call)
    };
    let field = |key: &str| text(&args, key);
    let or_empty = |key: &str| args.get(key).and_then(Value::as_str).unwrap_or("");
    match name {
        "run_command" => match field("CommandLine") {
            Some(command) => call("Bash", json!({ "command": command })),
            None => AgyCall::Unreadable("an Antigravity run_command with no CommandLine"),
        },
        "view_file" => match field("AbsolutePath") {
            Some(path) => call("Read", json!({ "file_path": path })),
            None => AgyCall::Unreadable("an Antigravity view_file with no AbsolutePath"),
        },
        "write_to_file" => match field("TargetFile") {
            Some(path) => call(
                "Write",
                json!({ "file_path": path, "content": or_empty("CodeContent") }),
            ),
            None => AgyCall::Unreadable("an Antigravity write_to_file with no TargetFile"),
        },
        "replace_file_content" => match field("TargetFile") {
            Some(path) => call(
                "Edit",
                json!({
                    "file_path": path,
                    "old_string": or_empty("TargetContent"),
                    "new_string": or_empty("ReplacementContent"),
                }),
            ),
            None => AgyCall::Unreadable("an Antigravity replace_file_content with no TargetFile"),
        },
        "multi_replace_file_content" => match field("TargetFile") {
            Some(path) => call("MultiEdit", json!({ "file_path": path })),
            None => {
                AgyCall::Unreadable("an Antigravity multi_replace_file_content with no TargetFile")
            }
        },
        "grep_search" => match field("SearchPath") {
            Some(path) => {
                let mut input = json!({ "path": path, "pattern": or_empty("Query") });
                if let Some(glob) = include_glob(&args) {
                    input["glob"] = json!(glob);
                }
                call("Grep", input)
            }
            None => AgyCall::Unreadable("an Antigravity grep_search with no SearchPath"),
        },
        "find_by_name" => match field("SearchDirectory") {
            Some(path) => call(
                "Glob",
                json!({ "path": path, "pattern": or_empty("Pattern") }),
            ),
            None => AgyCall::Unreadable("an Antigravity find_by_name with no SearchDirectory"),
        },
        other => call(other, args.clone()),
    }
}

/// The answer that lets a call go on to `agy`'s own policy: `allow` hands it
/// to the next hook or the default policy and approves nothing by itself.
pub fn allow() -> String {
    json!({ "decision": "allow" }).to_string()
}

/// [`allow`] with the default posture's warning as its reason.
pub fn allow_with_warning(message: &str) -> String {
    json!({ "decision": "allow", "reason": message }).to_string()
}

/// The answer that asks the person, with the guard's words. `force_ask` and
/// not `ask`: `ask` honours an "Always Allow" the person gave before, which
/// would let a call the guard flagged run without asking.
pub fn ask(message: &str) -> String {
    json!({ "decision": "force_ask", "reason": message }).to_string()
}

/// The answer that refuses a call, with the guard's words.
pub fn deny(message: &str) -> String {
    json!({ "decision": "deny", "reason": message }).to_string()
}

/// What the hook screens, in the words that follow "screened before they
/// run: ".
pub fn screened() -> String {
    "shell commands (`run_command`), changes to privileged files through `write_to_file`, \
     `replace_file_content` and `multi_replace_file_content`, and reads of secrets through \
     `view_file`, `grep_search` and `find_by_name`. Its other tools reach the guard and are \
     judged as any agent's unknown tool; its MCP servers are not behind the proxy."
        .to_string()
}

/// What a hook that is on still leaves out. Each line is one fact read in
/// the Antigravity documentation, or says it was not measured.
pub fn gaps() -> Vec<String> {
    vec![
        "Not screened: its MCP servers. Where Antigravity CLI keeps them is not confirmed, so \
         the proxy is not wired, and the name an MCP call carries in the hook payload is not \
         documented."
            .to_string(),
        "Not measured: what Antigravity does when a hook exits with another code than 0, times \
         out or prints no decision. The guard answers every call it sees with a JSON decision \
         and exit 0, a refusal included, and in enforce mode the hook line prints a deny \
         itself when the guard ends without an answer (Linux and macOS). A hook Antigravity \
         stops at its own 60-second timeout is not covered."
            .to_string(),
        "Antigravity also runs the hooks of a project's .agents/hooks.json and of plugins. A \
         deny blocks the call at once; how it orders them otherwise is not documented, and \
         they are not read here."
            .to_string(),
        "~/.gemini/config/hooks.json is shared with the Antigravity App and IDE, which read \
         the same entry. An edit that takes the innerwarden entry out, or sets its `enabled` \
         to false, stops the guard without a word to it; `agents` and `status` show it."
            .to_string(),
        "A review asks you (`force_ask`). With no person to ask (`agy -p`) what Antigravity \
         does with it is not measured; connect with --block-review to refuse reviews instead."
            .to_string(),
    ]
}

/// Our member of the hooks file as `agents connect` writes it, one level
/// in: `"innerwarden": {...}`, pretty-printed with two spaces.
fn member_text(block: &Value) -> Option<String> {
    let whole = serde_json::to_string_pretty(&json!({ HOOK_NAME: block })).ok()?;
    let inner = whole.strip_prefix("{\n  ")?.strip_suffix("\n}")?;
    Some(inner.to_string())
}

/// PURE: the whole file `agents connect` writes where there was none.
pub fn fresh_file(block: &Value) -> Option<String> {
    Some(format!("{{\n  {}\n}}\n", member_text(block)?))
}

/// Where the text of a JSON object's last member ends (the byte after it,
/// before the blanks and the closing brace), and whether the object is
/// empty. `None` when `text` does not end with a closing brace.
fn object_end(text: &str) -> Option<(usize, bool)> {
    let close = text.trim_end().len().checked_sub(1)?;
    if text.as_bytes().get(close) != Some(&b'}') {
        return None;
    }
    let before = text[..close].trim_end();
    Some((before.len(), before.ends_with('{')))
}

/// Whether everything from `at` on is blanks, one closing brace and blanks.
fn only_the_close_after(text: &str, at: usize) -> bool {
    text[at..].trim() == "}"
}

/// PURE: `text` (a JSON object without our member) with our member added
/// as its last, every other byte as it was, so that [`splice_out`] gives
/// `text` back to the byte. `None` when `text` does not end like a JSON
/// object. The caller checks that the result reads as what it meant to
/// write.
pub fn splice_in(text: &str, block: &Value) -> Option<String> {
    let member = member_text(block)?;
    let (at, empty) = object_end(text)?;
    let added = if empty {
        format!("\n  {member}\n")
    } else {
        format!(",\n  {member}")
    };
    Some(format!("{}{added}{}", &text[..at], &text[at..]))
}

/// PURE: `text` with our member for `block`, as [`splice_in`] added it,
/// taken out to the byte. `None` when that exact text is not there once, as
/// the object's last member (the file was reformatted, or the member was
/// changed): the caller then writes the file whole.
pub fn splice_out(text: &str, block: &Value) -> Option<String> {
    let member = member_text(block)?;
    let after_others = format!(",\n  {member}");
    if text.matches(&after_others).count() == 1 {
        let start = text.find(&after_others)?;
        let end = start + after_others.len();
        if only_the_close_after(text, end) {
            return Some(format!("{}{}", &text[..start], &text[end..]));
        }
    }
    let alone = format!("\n  {member}\n");
    if text.matches(&alone).count() == 1 {
        let start = text.find(&alone)?;
        let end = start + alone.len();
        if text[..start].ends_with('{') && only_the_close_after(text, end) {
            return Some(format!("{}{}", &text[..start], &text[end..]));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The PreToolUse example of Antigravity's hooks documentation, as it
    /// stands there (antigravity.google/docs/hooks, read on 2026-11-21).
    const DOC_RUN_COMMAND: &str = r#"{
  "toolCall": {
    "name": "run_command",
    "args": {
      "CommandLine": "npm test",
      "Cwd": "/workspace/project",
      "WaitMsBeforeAsync": 5000
    }
  },
  "stepIdx": 19,
  "conversationId": "ec33ebf9-0cba-4100-8142-c61503f6c587",
  "workspacePaths": ["/workspace/project"],
  "transcriptPath": "~/.gemini/antigravity/brain/ec33ebf9-0cba-4100-8142-c61503f6c587/.system_generated/logs/transcript.jsonl",
  "artifactDirectoryPath": "~/.gemini/antigravity/brain/ec33ebf9-0cba-4100-8142-c61503f6c587",
  "modelName": "gemini-3.6-flash-medium"
}"#;

    /// A payload of the documented shape for `name` with `args`, run in a
    /// workspace and no `Cwd`.
    fn payload(name: &str, args: Value) -> String {
        json!({
            "toolCall": {"name": name, "args": args},
            "stepIdx": 3,
            "conversationId": "c-1",
            "workspacePaths": ["/work/app", "/work/other"],
            "modelName": "gemini-3.6-flash-medium",
        })
        .to_string()
    }

    fn call(payload: &str) -> Value {
        match read(payload) {
            AgyCall::Call(call) => call,
            other => panic!("not a call: {other:?}"),
        }
    }

    /// The documented example reads as Claude Code's `Bash` call, in the
    /// `Cwd` it names, with the conversation as its session.
    ///
    /// FAILS ON REVERT: read `command` instead of `CommandLine` and the
    /// call is unreadable.
    #[test]
    fn the_documented_run_command_is_a_bash_call_in_its_cwd() {
        assert_eq!(
            call(DOC_RUN_COMMAND),
            json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "npm test"},
                "cwd": "/workspace/project",
                "session_id": "ec33ebf9-0cba-4100-8142-c61503f6c587",
            })
        );
    }

    /// Each documented tool the guard screens becomes Claude Code's tool of
    /// the same kind, with the argument that names its target, and is judged
    /// in the first workspace path when it names no folder.
    #[test]
    fn each_screened_tool_reads_as_claude_codes_tool_of_the_same_kind() {
        let cases = [
            (
                payload(
                    "view_file",
                    json!({"AbsolutePath": "/home/dev/.ssh/id_ed25519"}),
                ),
                "Read",
                json!({"file_path": "/home/dev/.ssh/id_ed25519"}),
            ),
            (
                payload(
                    "write_to_file",
                    json!({"TargetFile": "/home/dev/.bashrc", "CodeContent": "x", "Overwrite": true}),
                ),
                "Write",
                json!({"file_path": "/home/dev/.bashrc", "content": "x"}),
            ),
            (
                payload(
                    "replace_file_content",
                    json!({"TargetFile": "/work/app/a.rs", "TargetContent": "a", "ReplacementContent": "b"}),
                ),
                "Edit",
                json!({"file_path": "/work/app/a.rs", "old_string": "a", "new_string": "b"}),
            ),
            (
                payload(
                    "multi_replace_file_content",
                    json!({"TargetFile": "/work/app/b.rs", "ReplacementChunks": []}),
                ),
                "MultiEdit",
                json!({"file_path": "/work/app/b.rs"}),
            ),
            (
                payload(
                    "grep_search",
                    json!({"SearchPath": "/home/dev", "Query": "password", "Includes": ["*.md", "*.pem"]}),
                ),
                "Grep",
                json!({"path": "/home/dev", "pattern": "password", "glob": "*.pem"}),
            ),
            (
                payload(
                    "find_by_name",
                    json!({"SearchDirectory": "/home/dev", "Pattern": "*.key"}),
                ),
                "Glob",
                json!({"path": "/home/dev", "pattern": "*.key"}),
            ),
        ];
        for (payload, tool, input) in cases {
            let call = call(&payload);
            assert_eq!(call["tool_name"], tool, "{payload}");
            assert_eq!(call["tool_input"], input, "{payload}");
            assert_eq!(call["cwd"], "/work/app", "{payload}");
            assert_eq!(call["session_id"], "c-1", "{payload}");
        }
    }

    /// A tool the guard does not translate keeps its name and arguments,
    /// and is judged as any agent's unknown tool.
    #[test]
    fn another_tool_keeps_its_name_and_arguments() {
        let call = call(&payload(
            "read_url_content",
            json!({"Url": "https://example.com"}),
        ));
        assert_eq!(call["tool_name"], "read_url_content");
        assert_eq!(call["tool_input"], json!({"Url": "https://example.com"}));
    }

    /// What cannot be read as a call is unreadable (refused in enforce),
    /// never a call that names nothing.
    ///
    /// FAILS ON REVERT: let a `run_command` with no `CommandLine` through
    /// as an empty `Bash` call.
    #[test]
    fn a_call_that_cannot_be_read_is_unreadable() {
        for payload in [
            "not json".to_string(),
            "[]".to_string(),
            json!({"conversationId": "c"}).to_string(),
            json!({"toolCall": {"args": {}}}).to_string(),
            json!({"toolCall": {"name": "run_command", "args": "npm test"}}).to_string(),
            payload("run_command", json!({"Cwd": "/work"})),
            payload("run_command", json!({"CommandLine": "   "})),
            payload("view_file", json!({})),
            payload("write_to_file", json!({"CodeContent": "x"})),
            payload("replace_file_content", json!({})),
            payload("multi_replace_file_content", json!({})),
            payload("grep_search", json!({"Query": "x"})),
            payload("find_by_name", json!({"Pattern": "*"})),
        ] {
            assert!(
                matches!(read(&payload), AgyCall::Unreadable(_)),
                "{payload}"
            );
        }
    }

    /// The answers are the documented `decision` values, with the guard's
    /// words in `reason`. A review is `force_ask`, which no earlier
    /// "Always Allow" skips.
    #[test]
    fn the_answers_are_the_documented_decisions() {
        let read = |answer: String| serde_json::from_str::<Value>(&answer).unwrap();
        assert_eq!(read(allow()), json!({"decision": "allow"}));
        assert_eq!(
            read(allow_with_warning("w")),
            json!({"decision": "allow", "reason": "w"})
        );
        assert_eq!(
            read(ask("q")),
            json!({"decision": "force_ask", "reason": "q"})
        );
        assert_eq!(
            read(deny("no")),
            json!({"decision": "deny", "reason": "no"})
        );
    }

    fn block() -> Value {
        json!({"PreToolUse": [{
            "hooks": [{"type": "command", "command": "\"/opt/iw/innerwarden\" hook --agent antigravity", "timeout": 60}],
            "matcher": "",
        }]})
    }

    /// Our member goes in as the file's last and comes out to the byte, in
    /// files written every way a person or a tool writes JSON; what went in
    /// reads as the file with our member added and nothing else changed.
    ///
    /// FAILS ON REVERT: write the comma after the member instead of before
    /// it, and the empty object no longer comes back as it was.
    #[test]
    fn our_member_goes_in_last_and_comes_out_to_the_byte() {
        let block = block();
        for text in [
            "{}",
            "{}\n",
            "{ }\n",
            "{\n}\n",
            "{\"a\":1}",
            "{\n  \"my-linter\": {\n    \"PostToolUse\": []\n  }\n}\n",
            "{\n    \"x\": [1, 2],\n    \"y\": {\"z\": null}\n}\n\n",
            "\n{\"a\": \"}\"}  \n",
        ] {
            let added = splice_in(text, &block).unwrap();
            let mut want: Value = serde_json::from_str(text).unwrap();
            want[HOOK_NAME] = block.clone();
            assert_eq!(
                serde_json::from_str::<Value>(&added).unwrap(),
                want,
                "{text:?}"
            );
            assert_eq!(splice_out(&added, &block).as_deref(), Some(text), "{added}");
        }
        let fresh = fresh_file(&block).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&fresh).unwrap(),
            json!({ HOOK_NAME: block.clone() })
        );
        assert_eq!(splice_in("{}\n", &block).as_deref(), Some(fresh.as_str()));
    }

    /// A member that is no longer the text `splice_in` wrote (another
    /// timeout, the file reformatted) is not taken out by text: the caller
    /// rewrites the file whole.
    #[test]
    fn a_member_that_changed_is_not_taken_out_by_text() {
        let block = block();
        let added = splice_in("{\"a\": 1}\n", &block).unwrap();
        let mut other = block.clone();
        other["PreToolUse"][0]["hooks"][0]["timeout"] = json!(30);
        assert_eq!(splice_out(&added, &other), None);
        let reformatted: Value = serde_json::from_str(&added).unwrap();
        assert_eq!(splice_out(&reformatted.to_string(), &block), None);
        assert_eq!(splice_in("not json", &block), None);
    }
}
