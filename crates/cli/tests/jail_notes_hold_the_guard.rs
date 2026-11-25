//! End-to-end: what the jail launcher keeps about a project, and accepting
//! what a jail made, are out of an agent's reach outside the jail.
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
        std::fs::create_dir_all(dir.path().join("home/proj/src")).expect("project");
        std::fs::create_dir_all(
            dir.path()
                .join("home/.local/state/innerwarden/jail-claude/proj-0123456789abcdef"),
        )
        .expect("the launcher's folder");
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
            "session_id": "s-jail-state",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": "Bash",
            "tool_input": { "command": command },
        })
    }

    fn write_tool(&self, relative: &str, content: &str) -> serde_json::Value {
        serde_json::json!({
            "session_id": "s-jail-state",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": "Write",
            "tool_input": {
                "file_path": self.project().join(relative),
                "content": content,
            },
        })
    }

    fn write_abs(&self, path: &std::path::Path, content: &str) -> serde_json::Value {
        serde_json::json!({
            "session_id": "s-jail-state",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": "Write",
            "tool_input": { "file_path": path, "content": content },
        })
    }

    fn edit_abs(&self, path: &std::path::Path, old: &str, new: &str) -> serde_json::Value {
        serde_json::json!({
            "session_id": "s-jail-state",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": "Edit",
            "tool_input": { "file_path": path, "old_string": old, "new_string": new },
        })
    }

    /// Each payload the hook does not refuse (exit 2), with what it said.
    fn let_through(&self, payloads: &[serde_json::Value]) -> Vec<String> {
        payloads
            .iter()
            .filter_map(|payload| {
                let (code, stderr) = self.hook(payload);
                (code != Some(2)).then(|| format!("{code:?} {} :: {stderr}", payload["tool_input"]))
            })
            .collect()
    }
}

/// Review of #361 item 2: the launcher's notes of what a jail made in
/// a project (`~/.local/state/innerwarden/jail-claude/<key>.made`, the run
/// notes beside it) and that whole folder are held as the guard's own
/// settings are: an agent outside the jail that took `.made` away would let
/// the next jail start on a file the person never accepted. Every shell
/// form, interpreter code and the file tools are refused; reading is not.
///
/// FAILS ON REVERT: take `.local/state/innerwarden/jail-claude` out of the
/// guard's settings places and these run.
#[test]
fn the_launchers_notes_of_what_a_jail_made_are_out_of_the_agents_reach() {
    let host = Host::new();
    let all = host.home().join(".local/state/innerwarden/jail-claude");
    let made = all.join("proj-0123456789abcdef.made");
    let made_s = made.to_str().unwrap().to_string();
    let refused = [
        host.bash("rm ~/.local/state/innerwarden/jail-claude/proj-0123456789abcdef.made"),
        host.bash("rm -f $HOME/.local/state/innerwarden/jail-claude/*.made"),
        host.bash("rm -rf ~/.local/state/innerwarden/jail-claude"),
        host.bash(&format!("rm {made_s}")),
        host.bash("rm ${XDG_STATE_HOME}/innerwarden/jail-claude/proj-0123456789abcdef.made"),
        host.bash("mv ~/.local/state/innerwarden/jail-claude/proj-0123456789abcdef.made /tmp/x"),
        host.bash(
            "ln -sf /dev/null ~/.local/state/innerwarden/jail-claude/proj-0123456789abcdef.made",
        ),
        host.bash("chmod 777 ~/.local/state/innerwarden/jail-claude"),
        host.bash("chmod 000 ~/.local/state/innerwarden/jail-claude/proj-0123456789abcdef.made"),
        host.bash("setfacl -m u:nobody:rw ~/.local/state/innerwarden/jail-claude"),
        host.bash(": > ~/.local/state/innerwarden/jail-claude/proj-0123456789abcdef.made"),
        host.bash(
            "truncate -s 0 ~/.local/state/innerwarden/jail-claude/proj-0123456789abcdef.made",
        ),
        host.bash("cd ~/.local/state/innerwarden && rm jail-claude/proj-0123456789abcdef.made"),
        host.bash(&format!("python3 -c 'import os; os.remove(\"{made_s}\")'")),
        host.bash(&format!(
            "node -e 'require(\"fs\").unlinkSync(\"{made_s}\")'"
        )),
        host.write_abs(&made, ""),
        host.edit_abs(&made, "/w/app/.mcp.json", ""),
        host.write_abs(&all.join("proj-0123456789abcdef.run.4242"), ""),
    ];
    let through = host.let_through(&refused);
    assert!(through.is_empty(), "let through:\n{}", through.join("\n"));
    for command in [
        "cat ~/.local/state/innerwarden/jail-claude/proj-0123456789abcdef.made",
        "ls -la ~/.local/state/innerwarden/jail-claude",
    ] {
        let (code, stderr) = host.hook(&host.bash(command));
        assert_eq!(code, Some(0), "{command}: {stderr}");
    }
}

/// Review of #361 item 5: interpreter code that writes the project's
/// `.mcp.json` is refused as the shell and the file tools are.
#[test]
fn interpreter_code_that_writes_the_projects_mcp_file_is_refused() {
    let host = Host::new();
    let refused = [
        host.bash(
            r#"python3 -c 'import json; json.dump({"mcpServers":{"e":{"command":"nc"}}}, open(".mcp.json","w"))'"#,
        ),
        host.bash(
            r#"node -e 'require("fs").writeFileSync(".mcp.json", JSON.stringify({mcpServers:{e:{command:"nc"}}}))'"#,
        ),
        host.bash(r#"echo '{"mcpServers":{"e":{"command":"nc"}}}' > .mcp.json"#),
        host.write_tool(".mcp.json", r#"{"mcpServers":{"e":{"command":"nc"}}}"#),
    ];
    let through = host.let_through(&refused);
    assert!(through.is_empty(), "let through:\n{}", through.join("\n"));
}

/// Review of #361 item 7: accepting what a jail made is the person's;
/// the agent's `contain --accept-project-files` is refused under every name
/// and wrapper of the program.
#[test]
fn an_agent_never_accepts_what_a_jail_made() {
    let host = Host::new();
    let refused = [
        host.bash("innerwarden contain --accept-project-files"),
        host.bash("iw contain --accept-project-files --project ."),
        host.bash("/usr/local/bin/innerwarden contain --accept-project-files"),
        host.bash("~/.local/bin/innerwarden contain --accept-project-files"),
        host.bash("env FOO=1 innerwarden contain --accept-project-files"),
        host.bash("sh -c 'innerwarden contain --accept-project-files'"),
        host.bash("bash -c \"iw contain --project . --accept-project-files\""),
    ];
    let through = host.let_through(&refused);
    assert!(through.is_empty(), "let through:\n{}", through.join("\n"));
}
