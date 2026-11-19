//! End-to-end: the hook never rewires an agent to a cargo build, nor to a
//! binary other than the one the hooks already run
//! (NEW-20261118-dev-build-rewired-real-claude-hooks).
//!
//! THE DEFECT: the first hook call of each version rewires the Claude Code
//! settings under HOME to the program that is running. A workspace test ran
//! `target/debug/innerwarden hook` with the developer's real HOME, and every
//! guard hook of that machine ended up naming the debug build, which the next
//! `cargo build` replaced with whatever the tree held.
//!
//! These run the REAL binary, which is itself a cargo build, against a
//! scratch home holding older wiring (the shell half only) that the hook
//! would otherwise bring up to date.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    /// A home whose Claude Code runs `program` as its guard, wired by an
    /// older version: the Bash hook only.
    fn wired_to(program: &str) -> Self {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        let claude = dir.path().join("home/.claude");
        std::fs::create_dir_all(&claude).expect("claude dir");
        let line = format!("\"{program}\" hook --agent claude-code");
        let settings = serde_json::json!({"hooks": {"PreToolUse": [{
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": line}]
        }]}});
        std::fs::write(
            claude.join("settings.json"),
            serde_json::to_string_pretty(&settings).unwrap(),
        )
        .expect("settings");
        Self { dir }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn settings(&self) -> String {
        std::fs::read_to_string(self.home().join(".claude/settings.json")).expect("settings")
    }

    /// One harmless Bash call, the way Claude Code sends it.
    fn hook(&self) -> Option<i32> {
        let payload = serde_json::json!({
            "session_id": "rewire-test",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        })
        .to_string();
        let mut child = Command::new(bin())
            .args(["hook", "--agent", "claude-code"])
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run innerwarden hook");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(payload.as_bytes())
            .expect("write stdin");
        child
            .wait_with_output()
            .expect("collect output")
            .status
            .code()
    }

    /// The stamp a rewire leaves beside the agent policy, anywhere in HOME.
    fn stamp(&self) -> Option<PathBuf> {
        fn find(dir: &Path) -> Option<PathBuf> {
            for entry in std::fs::read_dir(dir).ok()?.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Some(found) = find(&path) {
                        return Some(found);
                    }
                } else if path.file_name().is_some_and(|n| n == "rewired") {
                    return Some(path);
                }
            }
            None
        }
        find(&self.home())
    }
}

/// FAILS ON REVERT: drop `refuse_rewire_to` from `rewire_once_per_version`
/// and the settings name `target/debug/innerwarden` after this one call.
#[test]
fn a_cargo_build_never_takes_over_hooks_that_run_another_binary() {
    let host = Host::wired_to("/opt/innerwarden/innerwarden");
    let before = host.settings();
    assert_eq!(host.hook(), Some(0));
    let after = host.settings();
    assert_eq!(after, before, "the hook rewrote the settings");
    assert!(!after.contains(bin()), "{after}");
    assert_eq!(host.stamp(), None, "the hook wrote a rewire stamp");
}

/// The same build, already wired: still not rewired, because a cargo build
/// is replaced by the next `cargo build`, never an installed guard.
#[test]
fn a_cargo_build_never_rewires_even_its_own_wiring() {
    let host = Host::wired_to(bin());
    let before = host.settings();
    assert_eq!(host.hook(), Some(0));
    assert_eq!(host.settings(), before, "the hook rewrote the settings");
    assert_eq!(host.stamp(), None, "the hook wrote a rewire stamp");
}
