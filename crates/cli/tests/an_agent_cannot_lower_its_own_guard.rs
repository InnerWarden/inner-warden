//! Lowering the guard that screens an agent is the person's, never the
//! agent's: inside an AI agent's shell, `agents disconnect`, `agents connect
//! --monitor` and `contain` (which rewrites the agent's hook) refuse and write
//! nothing. The hook refuses the agent running them too (agent-guard); this
//! holds where the hook cannot see the call (a script the agent wrote).
//!
//! Every run here uses a scratch home, so nothing touches a real
//! configuration.

use std::path::Path;
use std::process::{Command, Output, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

const AGENT_SHELL_MARKERS: [&str; 7] = [
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CODEX_SANDBOX",
    "CODEX_SANDBOX_NETWORK_DISABLED",
    "GEMINI_CLI",
    "OPENCLAW_SHELL",
    "HERMES_AGENT",
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

/// The suite's PATH less every folder that holds a `codex`. `agents connect`
/// and a mode switch ask the Codex they find there to trust the hook they
/// wrote, and a test never starts the real one.
fn path_without_codex() -> std::ffi::OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept = std::env::split_paths(&path)
        .filter(|dir| !dir.join("codex").exists() && !dir.join("codex.exe").exists());
    std::env::join_paths(kept).expect("folders split from PATH join back")
}

fn run(home: &Path, args: &[&str], marker: Option<&str>) -> Output {
    let mut command = Command::new(bin());
    command
        .env("HOME", home)
        .env("IW_GRAPH_FILE", home.join("graph.json"))
        .env("INNERWARDEN_AGENT_URL", "off")
        // No real Codex: none on PATH to ask, no other folder for it to read.
        .env("PATH", path_without_codex())
        .env_remove("CODEX_HOME")
        .stdin(Stdio::null());
    for name in AGENT_SHELL_MARKERS {
        command.env_remove(name);
    }
    if let Some(name) = marker {
        command.env(name, "1");
    }
    command.args(args).output().expect("run innerwarden")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Live gate of Active Defence 0.17.4, G1. FAILS ON REVERT (no refusal in
/// the CLI): inside an agent's shell, disconnect took the hook off and
/// connect --monitor rewired it to record only.
#[test]
fn inside_an_agents_shell_wiring_that_lowers_the_guard_is_refused() {
    for marker in AGENT_SHELL_MARKERS {
        for args in [
            &["agents", "disconnect", "--all"][..],
            &["agents", "disconnect", "claude-code"],
            &["agents", "connect", "claude-code", "--monitor"],
            &["contain", "--", "true"],
            &["contain", "--setup"],
            // Review of 1.6.6, H1.
            &["install", "claude-code", "--monitor"],
            // Live gate of Active Defence 0.17.5, J1 and J2: the hook off,
            // or monitor, from a script the agent wrote as much as typed.
            &["uninstall", "claude-code"],
            &["uninstall"],
            &["uninstall", "--purge"],
            &["dry-run"],
            &["monitor"],
        ] {
            let home = enforced_home();
            let settings = home.path().join(".claude/settings.json");
            let before = std::fs::read(&settings).unwrap();
            let out = run(home.path(), args, Some(marker));
            assert_eq!(
                out.status.code(),
                Some(1),
                "{marker} {args:?}: {}",
                stderr(&out)
            );
            assert!(
                stderr(&out).contains("refused inside an AI agent's shell"),
                "{marker} {args:?}: {}",
                stderr(&out)
            );
            assert_eq!(
                std::fs::read(&settings).unwrap(),
                before,
                "{marker} {args:?} wrote"
            );
        }
    }
}

/// Inside a Hermes Agent `terminal` shell (`HERMES_AGENT=true`, which Hermes
/// v0.23.1 sets for every program it starts), taking Hermes's own hook off or
/// down to monitor is refused and its config is left as it was.
///
/// FAILS ON REVERT: take `HERMES_AGENT` out of `AGENT_SHELL_MARKERS` in
/// `suppress_io` and both run: the hook entry goes, or turns to monitor.
#[test]
fn inside_a_hermes_shell_its_hook_is_not_lowered() {
    let home = tempfile::TempDir::new().expect("scratch home");
    std::fs::create_dir_all(home.path().join(".hermes")).unwrap();
    let out = run(home.path(), &["agents", "connect", "hermes"], None);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let config = home.path().join(".hermes/config.yaml");
    let before = std::fs::read(&config).expect("connect wrote the hook");
    assert!(String::from_utf8_lossy(&before).contains("hook --agent hermes"));
    for args in [
        &["agents", "disconnect", "hermes"][..],
        &["agents", "connect", "hermes", "--monitor"],
    ] {
        let mut command = Command::new(bin());
        command
            .env("HOME", home.path())
            .env("IW_GRAPH_FILE", home.path().join("graph.json"))
            .env("INNERWARDEN_AGENT_URL", "off")
            .env("PATH", path_without_codex())
            .env_remove("CODEX_HOME")
            .stdin(Stdio::null());
        for name in AGENT_SHELL_MARKERS {
            command.env_remove(name);
        }
        let out = command
            .env("HERMES_AGENT", "true")
            .args(args)
            .output()
            .expect("run innerwarden");
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("refused inside an AI agent's shell"),
            "{args:?}: {}",
            stderr(&out)
        );
        assert_eq!(std::fs::read(&config).unwrap(), before, "{args:?} wrote");
    }
}

/// What lowers nothing stays open inside an agent's shell (a connect that
/// keeps enforcing, contain's own `--dry-run`), and the person, outside one,
/// is not refused by this rule.
#[test]
fn what_lowers_nothing_and_the_person_are_not_refused() {
    for args in [
        &["agents", "connect", "claude-code"][..],
        &["contain", "--dry-run", "--", "true"],
        &["install", "claude-code"],
        &["uninstall", "--dry-run"],
        &["enforce"],
    ] {
        let home = enforced_home();
        let out = run(home.path(), args, Some("CLAUDECODE"));
        assert!(
            !stderr(&out).contains("refused inside an AI agent's shell"),
            "{args:?}: {}",
            stderr(&out)
        );
    }
    let home = enforced_home();
    let out = run(home.path(), &["agents", "disconnect", "--all"], None);
    assert!(
        !stderr(&out).contains("refused inside an AI agent's shell"),
        "{}",
        stderr(&out)
    );
}

/// `contain --setup` only arms the hook: one it could not arm (settings
/// that are not JSON) fails and never says "armed". FAILS ON REVERT: it said
/// "hook armed" and exited 0 after "could not arm the in-jail hook".
#[test]
fn a_setup_that_could_not_arm_the_hook_fails() {
    let home = tempfile::TempDir::new().expect("scratch home");
    let claude = home.path().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    let settings = claude.join("settings.json");
    std::fs::write(&settings, "{ not json").unwrap();
    let out = run(home.path(), &["contain", "--setup", "--enforce"], None);
    let said = String::from_utf8_lossy(&out.stdout);
    assert_ne!(out.status.code(), Some(0), "{said}{}", stderr(&out));
    assert!(
        stderr(&out).contains("could not arm the in-jail hook"),
        "{}",
        stderr(&out)
    );
    assert!(!said.contains("armed"), "{said}");
    assert_eq!(std::fs::read_to_string(&settings).unwrap(), "{ not json");
}

/// Live gate of Active Defence 0.17.4, G2: a `contain` that asks for no mode
/// keeps the hook's (an enforcing one stays enforcing), and says it; one that
/// asks for monitor sets monitor. FAILS ON REVERT (the default monitor).
#[test]
fn a_jail_keeps_the_hooks_mode_unless_asked() {
    let home = enforced_home();
    let settings = home.path().join(".claude/settings.json");
    let out = run(home.path(), &["contain", "--setup"], None);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = std::fs::read_to_string(&settings).unwrap();
    assert!(
        text.contains("hook") && !text.contains("--monitor"),
        "{text}"
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("mode: enforce"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let out = run(home.path(), &["contain", "--setup", "--monitor"], None);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(std::fs::read_to_string(&settings)
        .unwrap()
        .contains("--monitor"));
}
