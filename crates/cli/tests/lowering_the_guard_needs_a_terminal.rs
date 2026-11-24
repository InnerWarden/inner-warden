//! Monitor (`dry-run`) lowers the guard that screens an agent. It is set by
//! a person at their own terminal, or by an operator's script that says so,
//! never by a caller that only lacks an agent's marker. And the agents whose
//! shells say so (Cursor, Goose) are read as agents.
//!
//! Every run uses a scratch home, so nothing touches a real configuration.

use std::path::Path;
use std::process::{Command, Output, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

const AGENT_SHELL_MARKERS: [&str; 9] = [
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CODEX_SANDBOX",
    "CODEX_SANDBOX_NETWORK_DISABLED",
    "GEMINI_CLI",
    "OPENCLAW_SHELL",
    "HERMES_AGENT",
    "CURSOR_AGENT",
    "GOOSE_TERMINAL",
];

/// A home whose Claude Code runs an enforcing hook.
fn enforced_home() -> tempfile::TempDir {
    let home = tempfile::TempDir::new().expect("scratch home");
    let claude = home.path().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    std::fs::write(
        claude.join("settings.json"),
        serde_json::json!({
            "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [
                { "type": "command", "command": "innerwarden hook --agent claude-code" }
            ] } ] }
        })
        .to_string(),
    )
    .unwrap();
    home
}

fn path_without_codex() -> std::ffi::OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept = std::env::split_paths(&path)
        .filter(|dir| !dir.join("codex").exists() && !dir.join("codex.exe").exists());
    std::env::join_paths(kept).expect("folders split from PATH join back")
}

fn command(home: &Path, marker: Option<&str>) -> Command {
    let mut command = Command::new(bin());
    command
        .env("HOME", home)
        .env("IW_GRAPH_FILE", home.join("graph.json"))
        .env("IW_NOTIFY_CONFIG", home.join("absent-notify.toml"))
        .env("INNERWARDEN_AGENT_URL", "off")
        .env("PATH", path_without_codex())
        .env_remove("CODEX_HOME")
        .stdin(Stdio::null());
    for name in AGENT_SHELL_MARKERS {
        command.env_remove(name);
    }
    if let Some(name) = marker {
        command.env(name, "1");
    }
    command
}

fn run(home: &Path, args: &[&str], marker: Option<&str>) -> Output {
    command(home, marker)
        .args(args)
        .output()
        .expect("run innerwarden")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn settings(home: &Path) -> String {
    std::fs::read_to_string(home.join(".claude/settings.json")).unwrap()
}

/// No terminal and no agent's marker: monitor is refused, and nothing is
/// written.
///
/// FAILS ON REVERT: take the `may_widen` check out of `cmd_mode` and the
/// hook is rewritten to record only.
#[test]
fn without_a_terminal_monitor_is_refused_even_with_no_marker() {
    for verb in ["dry-run", "monitor"] {
        let home = enforced_home();
        let before = settings(home.path());
        let out = run(home.path(), &[verb], None);
        assert_eq!(out.status.code(), Some(1), "{verb}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("refused, no terminal"),
            "{verb}: {}",
            stderr(&out)
        );
        assert_eq!(settings(home.path()), before, "{verb} wrote");
    }
}

/// An operator's script that says so is not refused, outside an agent's
/// shell; inside one it is, whatever it says.
#[test]
fn an_operators_script_sets_monitor_outside_an_agents_shell_only() {
    let home = enforced_home();
    let out = run(home.path(), &["dry-run", "--operator"], None);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        settings(home.path()).contains("--monitor"),
        "{}",
        settings(home.path())
    );

    let home = enforced_home();
    let before = settings(home.path());
    let out = run(home.path(), &["dry-run", "--operator"], Some("CLAUDECODE"));
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert_eq!(settings(home.path()), before);
}

/// Cursor's and Goose's shells are agents' shells: monitor is refused there
/// even for an operator's script.
///
/// FAILS ON REVERT: take `CURSOR_AGENT` or `GOOSE_TERMINAL` out of
/// `AGENT_SHELL_MARKERS` and the line runs.
#[test]
fn cursor_and_goose_shells_are_agents_shells() {
    for marker in ["CURSOR_AGENT", "GOOSE_TERMINAL"] {
        let home = enforced_home();
        let before = settings(home.path());
        let out = run(home.path(), &["dry-run", "--operator"], Some(marker));
        assert_eq!(out.status.code(), Some(1), "{marker}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("refused inside an AI agent's shell"),
            "{marker}: {}",
            stderr(&out)
        );
        assert_eq!(settings(home.path()), before, "{marker} wrote");
    }
}

/// The person at their own terminal sets monitor: run under a terminal
/// `script` gives it, with no agent's marker.
#[cfg(target_os = "linux")]
#[test]
fn the_person_at_a_terminal_sets_monitor() {
    if Command::new("script").arg("--version").output().is_err() {
        eprintln!("skipped: no `script` to give the run a terminal");
        return;
    }
    let home = enforced_home();
    let line = format!("{} dry-run", bin());
    let out = {
        let mut script = Command::new("script");
        script
            .args(["-qec", &line, "/dev/null"])
            .env("HOME", home.path())
            .env("IW_GRAPH_FILE", home.path().join("graph.json"))
            .env("IW_NOTIFY_CONFIG", home.path().join("absent-notify.toml"))
            .env("INNERWARDEN_AGENT_URL", "off")
            .env("PATH", path_without_codex())
            .env_remove("CODEX_HOME")
            .stdin(Stdio::null());
        for name in AGENT_SHELL_MARKERS {
            script.env_remove(name);
        }
        script.output().expect("run script")
    };
    let said = String::from_utf8_lossy(&out.stdout).into_owned() + &stderr(&out);
    assert!(!said.contains("refused"), "{said}");
    assert!(
        settings(home.path()).contains("--monitor"),
        "{said}\n{}",
        settings(home.path())
    );
}
