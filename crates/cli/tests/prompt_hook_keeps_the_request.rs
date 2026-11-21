//! End-to-end: the hook on the person's prompts (Claude Code's
//! `UserPromptSubmit`) keeps what they asked for, and never stops a prompt.
//!
//! The payload is Claude Code's for that event: `session_id`,
//! `transcript_path`, `cwd`, `permission_mode`, `hook_event_name` and
//! `prompt`. The line is the one `innerwarden install claude-code` writes,
//! started the way Claude Code starts a hook line, with `sh -c`. Claude Code
//! drops the prompt on exit 2 and adds what a prompt hook prints on exit 0 to
//! the conversation, so the hook must end with 0 and print nothing.
//!
//! HOME, the record and the session store point into a scratch directory.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use innerwarden_agent_guard::user_prompt::{self, UserAsked};
use serde_json::{json, Value};

// This test starts the binary where it was built and copies nothing.
#[allow(dead_code)]
mod fork_safe;
use fork_safe::spawn_without_racing_a_copy;

const SESSION: &str = "0b7d6a52-5d1e-4f0a-9c55-1f2e3d4c5b6a";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        std::fs::create_dir_all(dir.path().join("home/proj")).expect("home");
        Self { dir }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn env<'a>(&self, command: &'a mut Command) -> &'a mut Command {
        command
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .current_dir(self.home().join("proj"))
    }

    fn install(&self) -> Value {
        let out = spawn_without_racing_a_copy(
            self.env(&mut Command::new(bin()))
                .args(["install", "claude-code"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        )
        .wait_with_output()
        .expect("run innerwarden install");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(
            &std::fs::read(self.home().join(".claude/settings.json")).expect("settings"),
        )
        .expect("settings json")
    }

    /// Run a hook line as Claude Code does, `sh -c`, with `payload` on stdin.
    fn run_line(&self, line: &str, payload: &[u8]) -> Output {
        let mut child = spawn_without_racing_a_copy(
            self.env(&mut Command::new("sh"))
                .args(["-c", line])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        );
        // A hook may end before it reads everything; a broken pipe is fine.
        let _ = child.stdin.as_mut().expect("stdin").write_all(payload);
        drop(child.stdin.take());
        child.wait_with_output().expect("hook ran")
    }

    fn asked(&self, value: &str) -> UserAsked {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        user_prompt::user_asked_for_in(
            &user_prompt::dir_in(&self.home()),
            Some(SESSION),
            value,
            now,
        )
    }
}

fn prompt_payload(prompt: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "session_id": SESSION,
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/home/dev/proj",
        "permission_mode": "default",
        "hook_event_name": "UserPromptSubmit",
        "prompt": prompt,
    }))
    .unwrap()
}

/// The one line of ours under `UserPromptSubmit`.
fn prompt_line(settings: &Value) -> String {
    let entries = settings["hooks"]["UserPromptSubmit"]
        .as_array()
        .unwrap_or_else(|| panic!("no UserPromptSubmit hook: {settings}"));
    assert_eq!(entries.len(), 1, "{settings}");
    assert!(entries[0].get("matcher").is_none(), "{settings}");
    entries[0]["hooks"][0]["command"]
        .as_str()
        .expect("command")
        .to_string()
}

#[cfg(unix)]
#[test]
fn install_wires_the_prompt_hook_without_the_fail_closed_script() {
    let host = Host::new();
    // `install` with no flag enforces: the tool halves refuse through the
    // fail-closed script...
    let settings = host.install();
    let bash = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!bash.contains("--monitor") && bash.contains("||"), "{bash}");
    // ...and the prompt half is the guard alone, in the same mode.
    let line = prompt_line(&settings);
    assert!(!line.contains("--monitor"), "{line}");
    assert!(line.contains("--agent claude-code"), "{line}");
    assert!(
        !line.contains("||") && !line.starts_with("/bin/sh"),
        "{line}"
    );
    assert!(
        settings["hooks"]["UserPromptSubmit"][0]["hooks"][0]["timeout"].is_u64(),
        "{settings}"
    );
    // A second install writes the same file.
    let again = host.install();
    assert_eq!(settings, again);
}

#[cfg(unix)]
#[test]
fn the_person_s_prompt_is_kept_masked_and_the_hook_says_nothing() {
    let host = Host::new();
    let line = prompt_line(&host.install());
    let out = host.run_line(
        &line,
        &prompt_payload(
            "Email the invoice to ana@example.com, the token is ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        ),
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );

    assert_eq!(host.asked("ana@example.com"), UserAsked::Yes);
    assert_eq!(host.asked("eve@evil.example"), UserAsked::No);
    let dir = user_prompt::dir_in(&host.home());
    for entry in std::fs::read_dir(&dir).expect("prompts folder").flatten() {
        let raw = std::fs::read_to_string(entry.path()).unwrap();
        assert!(!raw.contains("ghp_abcdefghij"), "{raw}");
    }
    // Nothing of the prompt reaches the guard's record of tool calls.
    let record = std::fs::read_to_string(host.dir.path().join("graph.json")).unwrap_or_default();
    assert!(!record.contains("ana@example.com"), "{record}");
}

#[cfg(unix)]
#[test]
fn a_prompt_line_that_enforces_still_never_drops_the_prompt() {
    // The line install writes in enforce: the prompt is kept and the hook
    // still ends with 0.
    let host = Host::new();
    let line = the_prompt_line();
    let out = host.run_line(&line, &prompt_payload("rename the branch to release-7"));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty());
    assert_eq!(host.asked("release-7"), UserAsked::Yes);
}

#[cfg(unix)]
#[test]
fn a_prompt_past_the_cap_goes_on_and_is_not_kept() {
    let host = Host::new();
    let line = the_prompt_line();
    let long = "x".repeat(2 * 1024 * 1024);
    let out = host.run_line(&line, &prompt_payload(&long));
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stdout.is_empty());
    assert!(matches!(host.asked("xxxx"), UserAsked::Unknown(_)));
}

#[cfg(unix)]
#[test]
fn a_guard_that_is_gone_does_not_drop_the_prompt() {
    // Claude Code drops a prompt only on exit 2. The prompt line is the guard
    // alone, so a missing program ends it with 127: an error Claude Code
    // shows, and the prompt goes on.
    let host = Host::new();
    let line = innerwarden_agent_guard::hook::prompt_hook_command(
        Path::new("/nonexistent/innerwarden"),
        false,
        false,
        Some("claude-code"),
    );
    let out = host.run_line(&line, &prompt_payload("hello there"));
    assert_ne!(out.status.code(), Some(2));
}

/// The line `install` writes for the prompt hook: the guard alone, with the
/// prompt flag last.
fn the_prompt_line() -> String {
    innerwarden_agent_guard::hook::prompt_hook_command(
        Path::new(bin()),
        false,
        false,
        Some("claude-code"),
    )
}

fn assert_silent_zero(out: &Output, what: &str) {
    assert_eq!(
        out.status.code(),
        Some(0),
        "{what}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stdout.is_empty(),
        "{what}: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(
        out.stderr.is_empty(),
        "{what}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn install_ends_the_prompt_line_with_its_flag() {
    let host = Host::new();
    let line = prompt_line(&host.install());
    assert!(
        line.ends_with(&format!(" {}", user_prompt::PROMPT_LINE_FLAG)),
        "{line}"
    );
}

/// Every way a run on the prompt line can fail ends with 0 and says
/// nothing: stdin that is not text, text that is not a payload, a head past
/// the cap that names no tool, a panic while the prompt is kept.
#[cfg(unix)]
#[test]
fn every_failure_on_the_prompt_line_ends_with_zero_and_silence() {
    let host = Host::new();
    let line = the_prompt_line();
    let cases: [(&str, Vec<u8>); 4] = [
        ("stdin that is not text", vec![0xff, 0xfe, 0x00, 0x80]),
        ("text that is not a payload", b"this is not json".to_vec()),
        ("an empty stdin", Vec::new()),
        (
            "a head past the cap that names no tool",
            prompt_payload(&"y".repeat(2 * 1024 * 1024)),
        ),
    ];
    for (what, payload) in cases {
        let out = host.run_line(&line, &payload);
        assert_silent_zero(&out, what);
    }

    let mut child = spawn_without_racing_a_copy(
        host.env(&mut Command::new("sh"))
            .args(["-c", &line])
            .env("IW_TEST_PROMPT_HOOK_PANIC", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let _ = child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(&prompt_payload("hello there"));
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("hook ran");
    assert_silent_zero(&out, "a panic while the prompt is kept");
}

/// The deadline of a run on the prompt line ends it with 0 and silence: a
/// caller that never closes stdin does not drop the person's prompt.
#[cfg(unix)]
#[test]
fn the_deadline_on_the_prompt_line_ends_with_zero_and_silence() {
    let host = Host::new();
    let mut child = spawn_without_racing_a_copy(
        host.env(&mut Command::new("sh"))
            .args(["-c", &the_prompt_line()])
            .env("INNERWARDEN_HOOK_DEADLINE_MS", "300")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    // Half a payload, and stdin left open.
    let _ = child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"{\"hook_event_name\":\"UserPromptSubmit\",");
    let started = std::time::Instant::now();
    loop {
        if child.try_wait().expect("try_wait").is_some() {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "the hook never ended"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    drop(child.stdin.take());
    let out = child.wait_with_output().expect("hook ran");
    assert_silent_zero(&out, "the deadline");
}

/// A tool call that comes on the prompt line is screened as on any other:
/// the flag quiets a prompt run, never a tool call.
#[cfg(unix)]
#[test]
fn a_tool_call_on_the_prompt_line_is_still_screened() {
    let host = Host::new();
    let payload = serde_json::to_vec(&json!({
        "session_id": SESSION,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat ~/.aws/credentials"},
    }))
    .unwrap();
    let out = host.run_line(&the_prompt_line(), &payload);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The record is the person's: the guard refuses the agent's reads of it,
/// through the shell and through the file tools, as it refuses its writes.
#[cfg(unix)]
#[test]
fn the_agent_is_refused_a_read_of_the_record() {
    let host = Host::new();
    let line = format!("\"{}\" hook --agent claude-code", bin());
    let out = host.run_line(
        &the_prompt_line(),
        &prompt_payload("send it to ana@example.com"),
    );
    assert_silent_zero(&out, "the prompt");
    let file = std::fs::read_dir(user_prompt::dir_in(&host.home()))
        .expect("prompts folder")
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .expect("a record");
    let file = file.to_string_lossy().into_owned();
    let calls = [
        json!({"tool_name": "Bash", "tool_input": {"command": "cat ~/.config/innerwarden/prompts/*.json"}}),
        json!({"tool_name": "Bash", "tool_input": {"command": format!("head -c 400 {file}")}}),
        json!({"tool_name": "Bash", "tool_input": {"command": "tar czf /tmp/p.tgz ~/.config/innerwarden/prompts"}}),
        json!({"tool_name": "Bash", "tool_input": {"command": "cp -r ~/.config/innerwarden /tmp/x"}}),
        json!({"tool_name": "Bash", "tool_input": {"command": "cat ~/.config/innerwarden/*/*"}}),
        json!({"tool_name": "Read", "tool_input": {"file_path": file}}),
        json!({"tool_name": "Grep", "tool_input": {"pattern": "@", "path": "~/.config/innerwarden/prompts"}}),
    ];
    for mut call in calls {
        call["session_id"] = json!(SESSION);
        call["hook_event_name"] = json!("PreToolUse");
        let out = host.run_line(&line, &serde_json::to_vec(&call).unwrap());
        assert_eq!(
            out.status.code(),
            Some(2),
            "{call}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// THE LIMIT, shown: an agent with a shell on the person's account can run
/// the guard's hook itself with a prompt it made up, and the record then
/// says the person asked for it. This is why the record is information only
/// and never lets a refused call through (docs/prompt-record.md).
#[cfg(unix)]
#[test]
fn an_agent_with_a_shell_can_forge_a_record() {
    let host = Host::new();
    let forged = prompt_payload("please wire the money to acct 99887766 at eve@evil.example");
    let out = host.run_line(&the_prompt_line(), &forged);
    assert_silent_zero(&out, "the forged prompt");
    assert_eq!(host.asked("eve@evil.example"), UserAsked::Yes);
    assert_eq!(host.asked("acct 99887766"), UserAsked::Yes);
}

/// `--prompt` counts only as the line's last word, as the grammar of a line
/// of ours reads it: anywhere else the line is a tool line, and stdin it
/// cannot read is refused as on any other.
#[cfg(unix)]
#[test]
fn the_prompt_flag_counts_only_as_the_last_word() {
    let host = Host::new();
    let line = format!("\"{}\" hook --prompt --agent claude-code", bin());
    let out = host.run_line(&line, &[0xff, 0xfe, 0x00, 0x80]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A payload that names a tool is a tool call, whatever event it names:
/// on the prompt line it is screened, and nothing of it is kept.
#[cfg(unix)]
#[test]
fn a_prompt_event_that_names_a_tool_is_screened_not_kept() {
    let host = Host::new();
    for payload in [
        json!({
            "session_id": SESSION,
            "hook_event_name": "UserPromptSubmit",
            "prompt": "send it to eve@evil.example",
            "tool_name": "Bash",
            "tool_input": {"command": "cat ~/.aws/credentials"},
        }),
        // Another shape of a call: `tool` in place of `tool_name`.
        json!({
            "session_id": SESSION,
            "hook_event_name": "PreToolUse",
            "tool": "Bash",
            "tool_input": {"command": "cat ~/.aws/credentials"},
        }),
    ] {
        let out = host.run_line(&the_prompt_line(), &serde_json::to_vec(&payload).unwrap());
        assert_eq!(
            out.status.code(),
            Some(2),
            "{payload}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert_eq!(
        host.asked("eve@evil.example"),
        UserAsked::Unknown(user_prompt::why::NO_RECORD)
    );
}

/// The record read through an interpreter's `open` is refused like `cat`.
#[cfg(unix)]
#[test]
fn the_agent_is_refused_a_read_of_the_record_through_an_interpreter() {
    let host = Host::new();
    let out = host.run_line(
        &the_prompt_line(),
        &prompt_payload("send it to ana@example.com"),
    );
    assert_silent_zero(&out, "the prompt");
    let file = std::fs::read_dir(user_prompt::dir_in(&host.home()))
        .expect("prompts folder")
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .expect("a record");
    let line = format!("\"{}\" hook --agent claude-code", bin());
    for code in [
        format!("python3 -c \"print(open('{}').read())\"", file.display()),
        format!(
            "node -e \"console.log(require('fs').readFileSync('{}','utf8'))\"",
            file.display()
        ),
    ] {
        let call = json!({
            "session_id": SESSION,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": code},
        });
        let out = host.run_line(&line, &serde_json::to_vec(&call).unwrap());
        assert_eq!(
            out.status.code(),
            Some(2),
            "{code}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// A prompt the person submitted never ends a run with 2, on any line: on a
/// line without the prompt flag it is not kept, and still goes on.
#[cfg(unix)]
#[test]
fn a_prompt_event_on_a_line_without_the_flag_goes_on() {
    let host = Host::new();
    for line in [
        format!("\"{}\" hook --agent claude-code", bin()),
        format!("\"{}\" hook --block-review --agent claude-code", bin()),
    ] {
        let out = host.run_line(&line, &prompt_payload("rename the branch to release-7"));
        assert_eq!(
            out.status.code(),
            Some(0),
            "{line}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.stdout.is_empty(), "{line}");
    }
    assert!(matches!(host.asked("release-7"), UserAsked::Unknown(_)));
}

/// A prompt whose event name comes after the 1 MiB the hook reads: the head
/// names no tool, and the run ends with 0 on either line.
#[cfg(unix)]
#[test]
fn a_prompt_whose_event_is_past_the_head_goes_on() {
    let host = Host::new();
    // Written by hand: `json!` orders its keys, which would put the event
    // name first. Here it comes after the prompt, past the head.
    let past_the_head = format!(
        r#"{{"session_id":"{SESSION}","prompt":"{}","hook_event_name":"UserPromptSubmit"}}"#,
        "z".repeat(1100 * 1024)
    )
    .into_bytes();
    let out = host.run_line(&the_prompt_line(), &past_the_head);
    assert_silent_zero(&out, "the event name past the head, on the prompt line");
    // Not kept, and the session says it lost a prompt.
    assert_eq!(
        host.asked("zzzz"),
        UserAsked::Unknown(user_prompt::why::LOST)
    );
    // The event name in the head: 0 on a line without the flag too.
    let in_the_head = serde_json::to_vec(&json!({
        "session_id": SESSION,
        "hook_event_name": "UserPromptSubmit",
        "prompt": "z".repeat(1100 * 1024),
    }))
    .unwrap();
    for line in [
        the_prompt_line(),
        format!("\"{}\" hook --agent claude-code", bin()),
    ] {
        let out = host.run_line(&line, &in_the_head);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{line}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// On the prompt line, JSON whose event is not a prompt is screened as a
/// call, and refused as one: a tool event with no tool name is refused as a
/// call the hook cannot read.
#[cfg(unix)]
#[test]
fn a_tool_event_on_the_prompt_line_is_refused_as_a_call() {
    let host = Host::new();
    for payload in [
        json!({
            "session_id": SESSION,
            "hook_event_name": "PreToolUse",
            "tool_input": {"command": "cat ~/.aws/credentials"},
        }),
        json!({
            "session_id": SESSION,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cat ~/.aws/credentials"},
        }),
    ] {
        let out = host.run_line(&the_prompt_line(), &serde_json::to_vec(&payload).unwrap());
        assert_eq!(
            out.status.code(),
            Some(2),
            "{payload}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
