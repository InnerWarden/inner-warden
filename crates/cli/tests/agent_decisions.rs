//! End-to-end: `innerwarden agents approve|profile|allow|revoke`, run the way
//! a person runs them, and the hook that reads what they wrote. HOME, the
//! record and the launcher's directory point into a scratch directory; every
//! verb runs in a session of its own, with no terminal, so a confirmation
//! that needs one fails instead of waiting.
//!
//! None of these run on a machine that has a system profiles file
//! (`/etc/innerwarden/agent-profiles.toml`): it would be merged in.
#![cfg(unix)]

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SYSTEM_FILE: &str = "/etc/innerwarden/agent-profiles.toml";

/// The markers an AI agent's shell sets; a verb run with one is an agent's.
const AGENT_MARKERS: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_CODE_ENTRYPOINT",
    "CODEX_SANDBOX",
    "CODEX_SANDBOX_NETWORK_DISABLED",
    "GEMINI_CLI",
];

struct Host {
    dir: tempfile::TempDir,
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        std::fs::create_dir_all(dir.path().join("home/proj")).expect("project");
        Self { dir }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn profiles_path(&self) -> PathBuf {
        self.home().join(".config/innerwarden/agent-profiles.toml")
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_innerwarden"));
        command
            .args(args)
            .env("HOME", self.home())
            .env("USER", "maria")
            .env("XDG_STATE_HOME", self.dir.path().join("state"))
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .env_remove("IW_GUARD_SESSION")
            .env("INNERWARDEN_AGENT_URL", "off")
            .current_dir(self.home().join("proj"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for marker in AGENT_MARKERS {
            command.env_remove(marker);
        }
        // SAFETY: setsid is async-signal-safe and touches no memory: the
        // child leaves the terminal of the test run, so /dev/tty is not one.
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        command
    }

    fn run(&self, mut command: Command, stdin: &str) -> Run {
        let mut child = command.spawn().expect("run innerwarden");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        Run {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }

    fn agents(&self, args: &str) -> Run {
        let mut all = vec!["agents"];
        all.extend(args.split_whitespace());
        self.run(self.command(&all), "")
    }

    fn hook(&self, flags: &[&str], payload: &str) -> Run {
        let mut all = vec!["hook"];
        all.extend_from_slice(flags);
        self.run(self.command(&all), payload)
    }

    fn bash(&self, command: &str) -> String {
        serde_json::json!({
            "session_id": "s-decisions",
            "hook_event_name": "PreToolUse",
            "cwd": self.home().join("proj"),
            "tool_name": "Bash",
            "tool_input": { "command": command },
        })
        .to_string()
    }

    fn write_tool(&self) -> String {
        serde_json::json!({
            "session_id": "s-decisions",
            "hook_event_name": "PreToolUse",
            "cwd": self.home().join("proj"),
            "tool_name": "Write",
            "tool_input": { "file_path": self.home().join("proj/notes.md"), "content": "x" },
        })
        .to_string()
    }

    fn events(&self, kind: &str) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.dir.path().join("guard-events.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|line| line["kind"] == kind)
            .collect()
    }
}

fn system_file_present() -> bool {
    Path::new(SYSTEM_FILE).exists()
}

/// Approve, then revoke: the agent's next shell command and file change are
/// refused by its hook, an agent that gives another name is held to the
/// general rules, a monitoring hook only records, and everything decided
/// before the revocation stays in the file and in the event stream.
#[test]
fn a_revoked_agent_is_refused_by_its_hook_and_its_history_stays() {
    if system_file_present() {
        return;
    }
    let host = Host::new();
    let approved = host.agents("approve claude-code --owner ops --yes");
    assert_eq!(approved.code, Some(0), "{}", approved.stderr);
    assert_eq!(
        approved.stdout.trim(),
        "maria approved claude-code, owner ops, profile General rules."
    );
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(host.profiles_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "the user's file is the user's alone");
    }
    let ls = host.bash("ls");
    assert_eq!(host.hook(&["--agent", "claude-code"], &ls).code, Some(0));

    let revoked = host.agents("revoke claude-code --yes");
    assert_eq!(revoked.code, Some(0), "{}", revoked.stderr);
    assert!(revoked
        .stdout
        .contains("maria revoked claude-code. Its history stays."));
    assert!(
        revoked.stdout.contains("--system"),
        "the jail caveat is said: {}",
        revoked.stdout
    );

    let refused = host.hook(&["--agent", "claude-code"], &ls);
    assert_eq!(refused.code, Some(2), "{}", refused.stderr);
    assert!(
        refused.stderr.contains("this agent was revoked"),
        "{}",
        refused.stderr
    );
    let file = host.hook(&["--agent", "claude-code"], &host.write_tool());
    assert_eq!(file.code, Some(2), "{}", file.stderr);
    assert!(
        file.stderr.contains("this agent was revoked"),
        "{}",
        file.stderr
    );
    // Another name is the general rules, not a refusal; a monitoring hook
    // records and never acts.
    assert_eq!(host.hook(&["--agent", "cursor"], &ls).code, Some(0));
    assert_eq!(
        host.hook(&["--agent", "claude-code", "--monitor"], &ls)
            .code,
        Some(0)
    );

    let text = std::fs::read_to_string(host.profiles_path()).unwrap();
    for kept in [
        "lifecycle = \"revoked\"",
        "owner = \"ops\"",
        "approved_by = \"maria\"",
        "approved_at",
        "revoked_by = \"maria\"",
    ] {
        assert!(text.contains(kept), "{kept} in:\n{text}");
    }
    let decisions = host.events("guard.agent_decision");
    let actions: Vec<(&str, &str)> = decisions
        .iter()
        .map(|d| (d["action"].as_str().unwrap(), d["result"].as_str().unwrap()))
        .collect();
    assert_eq!(
        actions,
        [("agent_approve", "success"), ("agent_revoke", "success")]
    );
    assert!(decisions.iter().all(|d| d["by"] == "maria"));
    let blocked = host.events("guard.blocked");
    assert!(!blocked.is_empty(), "the refusals are recorded");

    let again = host.agents("revoke claude-code --yes --json");
    assert_eq!(again.code, Some(1));
    assert!(
        again.stderr.contains("refused (revoked)"),
        "{}",
        again.stderr
    );
    let answer: serde_json::Value = serde_json::from_str(again.stdout.trim()).unwrap();
    assert_eq!(answer["refused"], "revoked");
    assert_eq!(answer["success"], false);
    assert_eq!(
        host.events("guard.agent_decision").last().unwrap()["result"],
        "failure: revoked"
    );
}

/// A relaxation is never written into the user's file, a decision is not
/// taken without the person at a terminal, and an agent's shell does not
/// confirm one with `--yes`. Nothing is written in any of these.
#[test]
fn a_decision_without_the_person_at_a_terminal_changes_nothing() {
    if system_file_present() {
        return;
    }
    let host = Host::new();
    let allow = host.agents("allow claude-code --category bare_ip_fetch");
    assert_eq!(allow.code, Some(1));
    assert!(
        allow.stderr.contains("refused (needs_system_file)"),
        "{}",
        allow.stderr
    );
    let hard = host.agents("allow claude-code --category download_and_execute");
    assert_eq!(hard.code, Some(1));
    assert!(
        hard.stderr.contains("refused (hard_rule)"),
        "{}",
        hard.stderr
    );
    // No --yes and no terminal: exit 2.
    let unconfirmed = host.agents("approve claude-code");
    assert_eq!(unconfirmed.code, Some(2), "{}", unconfirmed.stderr);
    assert!(unconfirmed.stderr.contains("needs you at a terminal"));
    // An agent's shell: --yes is not the person's word.
    let mut agent = host.command(&["agents", "revoke", "claude-code", "--yes"]);
    agent.env("CLAUDECODE", "1");
    let from_agent = host.run(agent, "");
    assert_eq!(from_agent.code, Some(2), "{}", from_agent.stderr);
    assert!(!host.profiles_path().exists(), "nothing was written");
    // A tightening the person wrote and now takes back is a relaxation: it
    // asks for the agent's name at a terminal, and there is none.
    std::fs::create_dir_all(host.profiles_path().parent().unwrap()).unwrap();
    std::fs::write(
        host.profiles_path(),
        "schema_version = 1\n[profile.strict]\ndeny_categories = [\"bare_ip_fetch\"]\n[agent.claude-code]\nprofile = \"strict\"\n",
    )
    .unwrap();
    let before = std::fs::read(host.profiles_path()).unwrap();
    let back = host.agents("profile claude-code general --yes");
    assert_eq!(back.code, Some(2), "{}", back.stderr);
    assert_eq!(std::fs::read(host.profiles_path()).unwrap(), before);
    let tighter = host.agents("profile claude-code strict --yes");
    assert_eq!(
        tighter.code,
        Some(0),
        "the same profile again is no relaxation: {}",
        tighter.stderr
    );
}

/// The dashboard stays read-only: the decisions are verbs, not routes.
#[test]
fn an_unknown_flag_or_a_verb_out_of_place_is_not_a_decision() {
    let host = Host::new();
    let odd = host.agents("approve claude-code --force");
    assert_eq!(odd.code, Some(1));
    assert!(odd.stderr.contains("is not an option"), "{}", odd.stderr);
    assert!(!host.profiles_path().exists());
}
