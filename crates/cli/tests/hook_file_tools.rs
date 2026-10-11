//! End-to-end: the PreToolUse hook on an agent's file tools.
//!
//! These run the REAL binary the way Claude Code runs it: a JSON payload on
//! stdin, the verdict in the exit code (2 refuses, 0 lets the call run). HOME,
//! the record and the session store point into a scratch directory, so a run
//! never reads or writes the developer's own state.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

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
        Self { dir }
    }

    fn home(&self) -> std::path::PathBuf {
        self.dir.path().join("home")
    }

    fn project(&self) -> std::path::PathBuf {
        self.home().join("proj")
    }

    /// Run the hook once with `payload`; the exit code and stderr.
    fn hook(&self, flags: &[&str], payload: &str) -> (Option<i32>, String) {
        let mut child = Command::new(bin())
            .arg("hook")
            .args(flags)
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
            .write_all(payload.as_bytes())
            .expect("write stdin");
        let out = child.wait_with_output().expect("collect output");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn edit_payload(&self, tool: &str, path: &str) -> String {
        let key = if tool == "NotebookEdit" {
            "notebook_path"
        } else {
            "file_path"
        };
        serde_json::json!({
            "session_id": "s-file-tools",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": tool,
            "tool_input": { key: path, "old_string": "a", "new_string": "b", "content": "x" },
        })
        .to_string()
    }
}

fn record(host: &Host) -> String {
    std::fs::read_to_string(host.dir.path().join("graph.json")).unwrap_or_default()
}

/// The row's proof: an agent's `Edit` of its own settings is refused, with
/// the reason and who may make the change.
///
/// FAILS ON REVERT: drop `screen_file_tool` from `cmd_hook` and the edit
/// exits 0 as a call with no command.
#[test]
fn an_edit_of_the_agents_settings_is_refused() {
    let host = Host::new();
    let settings = host.home().join(".claude/settings.json");
    let (code, stderr) = host.hook(
        &["--agent", "claude-code"],
        &host.edit_payload("Edit", &settings.to_string_lossy()),
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("blocked this file change"), "{stderr}");
    assert!(stderr.contains("the guard's own configuration"), "{stderr}");
    assert!(stderr.contains("make this change yourself"), "{stderr}");
    assert!(
        record(&host).contains("privileged_file_write"),
        "a refusal is recorded"
    );
}

/// Every file tool, and the other privileged places, by the same rule.
#[test]
fn every_file_tool_is_held_to_the_privileged_list() {
    let host = Host::new();
    for (tool, path) in [
        ("Write", host.home().join(".bashrc")),
        (
            "MultiEdit",
            host.home().join(".config/innerwarden/suppress.toml"),
        ),
        ("NotebookEdit", host.home().join(".ssh/authorized_keys")),
        ("Write", host.home().join(".config/systemd/user/x.service")),
        ("Edit", host.project().join(".claude/settings.local.json")),
    ] {
        let (code, stderr) = host.hook(&[], &host.edit_payload(tool, &path.to_string_lossy()));
        assert_eq!(code, Some(2), "{tool} {}: {stderr}", path.display());
    }
}

/// The row's guard: an ordinary project edit stays silent. Exit 0, nothing
/// on stderr, and nothing written to the record.
#[test]
fn a_project_edit_is_silent() {
    let host = Host::new();
    for (tool, path) in [
        ("Edit", host.project().join("src/main.rs")),
        ("Write", host.project().join("README.md")),
        ("MultiEdit", host.project().join(".npmrc")),
        ("NotebookEdit", host.project().join("analysis.ipynb")),
    ] {
        let (code, stderr) = host.hook(&[], &host.edit_payload(tool, &path.to_string_lossy()));
        assert_eq!(code, Some(0), "{tool} {}: {stderr}", path.display());
        assert!(stderr.is_empty(), "{tool}: {stderr}");
    }
    assert!(
        !record(&host).contains("main.rs"),
        "a project edit is not recorded"
    );
}

/// Monitor never blocks: the refusal is recorded as one it would have made.
#[test]
fn monitor_records_the_file_change_and_lets_it_run() {
    let host = Host::new();
    let settings = host.home().join(".claude/settings.json");
    let (code, stderr) = host.hook(
        &["--monitor"],
        &host.edit_payload("Edit", &settings.to_string_lossy()),
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert!(record(&host).contains("privileged_file_write"));
}

/// A file tool call that names no file is refused rather than let through
/// unscreened, as a shell call with no command is.
#[test]
fn a_file_tool_call_with_no_path_is_refused_in_enforce() {
    let host = Host::new();
    let payload = r#"{"tool_name":"Edit","tool_input":{"old_string":"a","new_string":"b"}}"#;
    assert_eq!(host.hook(&[], payload).0, Some(2));
    assert_eq!(host.hook(&["--monitor"], payload).0, Some(1));
}

/// The Bash path is unchanged by the file-tools path in front of it.
#[test]
fn a_shell_command_is_still_screened_as_before() {
    let host = Host::new();
    let bash = |command: &str| {
        serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}}).to_string()
    };
    assert_eq!(host.hook(&[], &bash("ls -la")).0, Some(0));
    assert_eq!(host.hook(&[], &bash("rm -rf ~")).0, Some(2));
}

fn percentile(sorted: &[u128], pct: usize) -> u128 {
    let at = (sorted.len() * pct).div_ceil(100).saturating_sub(1);
    sorted[at.min(sorted.len() - 1)]
}

/// Wall time of the hook process, p50 and p95 over `runs`, in microseconds.
fn measure(host: &Host, payload: &str, runs: usize) -> (u128, u128) {
    // One warm-up run, so the first page-in of the binary is not counted.
    let _ = host.hook(&[], payload);
    let mut times: Vec<u128> = (0..runs)
        .map(|_| {
            let start = Instant::now();
            let _ = host.hook(&[], payload);
            start.elapsed().as_micros()
        })
        .collect();
    times.sort_unstable();
    (percentile(&times, 50), percentile(&times, 95))
}

/// Not a budget: a measurement, printed for the change log. Run it on the
/// build box in release (`cargo test --release -p innerwarden --test
/// hook_file_tools -- --ignored --nocapture`).
#[test]
#[ignore]
fn measure_hook_latency() {
    let host = Host::new();
    let bash = serde_json::json!({
        "session_id": "s-latency",
        "hook_event_name": "PreToolUse",
        "cwd": host.project(),
        "tool_name": "Bash",
        "tool_input": {"command": "ls -la src"},
    })
    .to_string();
    let bash_names_verb = serde_json::json!({
        "session_id": "s-latency",
        "hook_event_name": "PreToolUse",
        "cwd": host.project(),
        "tool_name": "Bash",
        "tool_input": {"command": "grep -rn 'innerwarden mute' docs/ | head -5"},
    })
    .to_string();
    let edit_project = host.edit_payload(
        "Edit",
        &host.project().join("src/main.rs").to_string_lossy(),
    );
    let edit_settings = host.edit_payload(
        "Edit",
        &host.home().join(".claude/settings.json").to_string_lossy(),
    );
    for (name, payload) in [
        ("Bash ls -la", &bash),
        ("Bash grep naming a guard verb", &bash_names_verb),
        ("Edit project file", &edit_project),
        ("Edit ~/.claude/settings.json", &edit_settings),
    ] {
        let (p50, p95) = measure(&host, payload, 200);
        println!("hook latency {name}: p50 {p50} us, p95 {p95} us");
    }
}
