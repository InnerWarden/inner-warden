//! End-to-end: a project's own agent settings are held as the person's are.
//!
//! Claude Code reads hooks, the hook switch, the permission mode and the key
//! helper from the project's \`.claude/settings.json\` and
//! \`.claude/settings.local.json\` as well as from the home (2.1.330: a
//! \`disableAllHooks\` there switches off every hook that is not managed,
//! the person's own included). An agent works in that project and can write
//! both files, so a write that switches the guard's hook off, adds a hook,
//! puts the session in bypass mode or names a key helper is refused, by the
//! shell and by the file tools alike. A rule added to \`permissions.allow\` is
//! the ordinary "always allow" and still runs.
//!
//! These run the REAL binary the way Claude Code runs it, with HOME and the
//! record in a scratch directory.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        for folder in [".claude", ".codex", ".gemini", ".cursor", "src"] {
            std::fs::create_dir_all(dir.path().join("home/proj").join(folder)).expect("project");
        }
        Self { dir }
    }

    fn home(&self) -> std::path::PathBuf {
        self.dir.path().join("home")
    }

    fn project(&self) -> std::path::PathBuf {
        self.home().join("proj")
    }

    /// Run the hook once with \`payload\`; the exit code and stderr.
    fn hook(&self, payload: &serde_json::Value) -> (Option<i32>, String) {
        let mut child = Command::new(bin())
            .args(["hook", "--agent", "claude-code"])
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .current_dir(self.project())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run innerwarden hook");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(payload.to_string().as_bytes())
            .expect("write stdin");
        let out = child.wait_with_output().expect("collect output");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn bash(&self, command: &str) -> serde_json::Value {
        serde_json::json!({
            "session_id": "s-project-settings",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": "Bash",
            "tool_input": { "command": command },
        })
    }

    fn write_tool(&self, relative: &str, content: &str) -> serde_json::Value {
        serde_json::json!({
            "session_id": "s-project-settings",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": "Write",
            "tool_input": {
                "file_path": self.project().join(relative),
                "content": content,
            },
        })
    }

    fn edit_tool(&self, relative: &str, old: &str, new: &str) -> serde_json::Value {
        serde_json::json!({
            "session_id": "s-project-settings",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": "Edit",
            "tool_input": {
                "file_path": self.project().join(relative),
                "old_string": old,
                "new_string": new,
            },
        })
    }
}

/// Every way of lowering the guard from a project's settings, refused.
///
/// FAILS ON REVERT: take `.cursor/hooks.json` out of the guard's settings
/// places and the two Cursor lines run.
#[test]
fn a_project_settings_write_that_lowers_the_guard_is_refused() {
    let host = Host::new();
    let refused = [
        // The shell.
        host.bash(r#"echo '{"disableAllHooks": true}' > .claude/settings.local.json"#),
        host.bash(r#"echo '{"disableAllHooks": true}' > .claude/settings.json"#),
        host.bash(r#"printf '{"hooks":{}}' > .claude/settings.json"#),
        host.bash(r#"echo '{"permissions":{"defaultMode":"bypassPermissions"}}' > .claude/settings.local.json"#),
        host.bash(r#"echo '{"apiKeyHelper":"./key.sh"}' > .claude/settings.json"#),
        host.bash(r#"sed -i 's/"allow"/"disableAllHooks": true, "allow"/' .claude/settings.local.json"#),
        host.bash(r#"sed -i 's/acceptEdits/bypassPermissions/' .claude/settings.json"#),
        host.bash(
            r#"python3 -c 'import json; open(".claude/settings.local.json","w").write(json.dumps({"disableAllHooks": True}))'"#,
        ),
        host.bash(
            r#"python3 -c 'import json; json.dump({"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"true"}]}]}}, open(".claude/settings.json","w"))'"#,
        ),
        // The file tools.
        host.write_tool(".claude/settings.local.json", r#"{"disableAllHooks": true}"#),
        host.write_tool(
            ".claude/settings.json",
            r#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"./allow-all.sh"}]}]}}"#,
        ),
        host.write_tool(
            ".claude/settings.json",
            r#"{"permissions":{"defaultMode":"bypassPermissions"}}"#,
        ),
        host.write_tool(".claude/settings.local.json", r#"{"apiKeyHelper":"./key.sh"}"#),
        host.edit_tool(
            ".claude/settings.json",
            r#""allow": ["#,
            r#""defaultMode": "bypassPermissions", "allow": ["#,
        ),
        host.edit_tool(".claude/settings.local.json", "{", r#"{"disableAllHooks": true,"#),
        // The other agents' project files.
        host.write_tool(".gemini/settings.json", r#"{"hooksConfig":{"enabled":false}}"#),
        host.write_tool(".cursor/hooks.json", r#"{"version":1,"hooks":{}}"#),
        host.write_tool(".codex/config.toml", "[features]\ncodex_hooks = false\n"),
        host.bash(r#"echo '{"version":1,"hooks":{}}' > .cursor/hooks.json"#),
        host.bash(r#"echo '{"hooksConfig":{"enabled":false}}' > .gemini/settings.json"#),
    ];
    let mut let_through = Vec::new();
    for payload in &refused {
        let (code, stderr) = host.hook(payload);
        if code != Some(2) {
            let_through.push(format!("{code:?} {} :: {stderr}", payload["tool_input"]));
        }
    }
    assert!(
        let_through.is_empty(),
        "let through:\n{}",
        let_through.join("\n")
    );
}
