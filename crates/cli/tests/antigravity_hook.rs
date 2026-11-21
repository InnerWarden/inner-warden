//! End-to-end: the Antigravity CLI's own hook payloads, through the hook line
//! `agents connect antigravity` writes, read back the way its hooks
//! documentation says it reads a hook's answer; and `agents connect` /
//! `disconnect` over a disposable HOME, which give back the hooks file they
//! found, to the byte.
//!
//! The payloads are the documented shape (antigravity.google/docs/hooks,
//! read on 2026-11-21): `toolCall.name`, `toolCall.args` in each tool's own
//! argument names, and the common fields. No Antigravity is started: it
//! needs a Google login. How it starts the hook line is not documented; it is
//! run here with `sh -c`.
//!
//! Unix only: the hook line is run through `/bin/sh`.
#![cfg(unix)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use innerwarden_agent_guard::agent_hooks::ANTIGRAVITY;
use serde_json::{json, Value};

fn bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_innerwarden"))
}

/// What Antigravity does with the call once it read the hook's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Refused,
    Runs,
    Asks,
}

/// Antigravity's hooks documentation, `PreToolUse` output: `decision` is
/// required; `deny` blocks at once, `ask` and `force_ask` ask the person,
/// `allow` and `auto_approve` let it go on. What it does with an exit other
/// than 0 or with no decision is not documented, so a run that ends that way
/// fails here instead of being read one way or the other.
fn agy_reads(code: Option<i32>, stdout: &str, what: &str) -> Call {
    assert_eq!(
        code,
        Some(0),
        "{what}: the hook must end with 0, its answer in JSON"
    );
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "{what}: exactly one answer on stdout: {stdout:?}"
    );
    let answer: Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|_| panic!("{what}: the answer is not JSON: {stdout:?}"));
    match answer["decision"].as_str() {
        Some("deny") => {
            assert!(
                answer["reason"]
                    .as_str()
                    .is_some_and(|r| !r.trim().is_empty()),
                "{what}: a refusal says why: {answer}"
            );
            Call::Refused
        }
        Some("ask" | "force_ask") => Call::Asks,
        Some("allow" | "auto_approve") => Call::Runs,
        other => panic!("{what}: not a documented decision: {other:?}"),
    }
}

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        std::fs::create_dir_all(dir.path().join("home/proj/src")).expect("project");
        std::fs::create_dir_all(dir.path().join("home/.ssh")).expect("ssh");
        std::fs::write(
            dir.path().join("home/.ssh/id_ed25519"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nnot a key\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .expect("a key");
        Self { dir }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn project(&self) -> PathBuf {
        self.home().join("proj")
    }

    /// A `PreToolUse` payload of the documented shape.
    fn payload(&self, tool: &str, args: Value) -> Value {
        json!({
            "toolCall": {"name": tool, "args": args},
            "stepIdx": 19,
            "conversationId": "ec33ebf9-0cba-4100-8142-c61503f6c587",
            "workspacePaths": [self.project()],
            "transcriptPath": self.home().join(".gemini/antigravity-cli/brain/ec33ebf9/.system_generated/logs/transcript.jsonl"),
            "artifactDirectoryPath": self.home().join(".gemini/antigravity-cli/brain/ec33ebf9"),
            "modelName": "gemini-3.6-flash-medium",
            "lastUserInput": "Fix the failing unit test",
        })
    }

    /// Run `line` with `sh -c` and `payload` on stdin, from the project.
    fn run(&self, line: &str, payload: &[u8]) -> (Option<i32>, String, String) {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(line)
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .env_remove("INNERWARDEN_HOOK_DEADLINE_MS")
            .current_dir(self.project())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the hook line");
        let mut stdin = child.stdin.take().expect("stdin");
        match stdin.write_all(payload) {
            Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => {
                panic!("write the payload: {error}")
            }
            _ => {}
        }
        drop(stdin);
        let out = child.wait_with_output().expect("wait for the hook");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn reads(&self, line: &str, payload: &Value, what: &str) -> Call {
        let (code, stdout, stderr) = self.run(line, payload.to_string().as_bytes());
        let call = agy_reads(code, &stdout, what);
        assert!(!stderr.contains("panicked"), "{what}: {stderr}");
        call
    }
}

/// The enforcing line: a line rated deny, a read of a private key, a write
/// to the agent's own settings and a call that cannot be read are refused
/// before they run, as a JSON `deny` with exit 0; ordinary work runs.
///
/// FAILS ON REVERT: take the `antigravity_answer` step out of `cmd_hook`,
/// and a refusal ends with exit 2 and no decision on stdout.
#[test]
fn enforce_refuses_with_a_json_deny_and_lets_ordinary_work_run() {
    let host = Host::new();
    let line = ANTIGRAVITY.command(bin(), false, false);
    let home = host.home();
    let shell = |command: &str| {
        host.payload(
            "run_command",
            json!({"CommandLine": command, "Cwd": host.project(), "WaitMsBeforeAsync": 5000}),
        )
    };
    assert_eq!(
        host.reads(&line, &shell("npm test"), "npm test"),
        Call::Runs
    );
    assert_eq!(host.reads(&line, &shell("ls -la src"), "ls"), Call::Runs);
    assert_eq!(
        host.reads(&line, &shell("rm -rf ~"), "rm -rf ~"),
        Call::Refused
    );

    let key = home.join(".ssh/id_ed25519");
    let read_key = host.payload("view_file", json!({"AbsolutePath": key}));
    assert_eq!(
        host.reads(&line, &read_key, "view_file of a key"),
        Call::Refused
    );
    let read_src = host.payload(
        "view_file",
        json!({"AbsolutePath": host.project().join("src/main.rs")}),
    );
    assert_eq!(
        host.reads(&line, &read_src, "view_file in the project"),
        Call::Runs
    );

    let settings = home.join(".claude/settings.json");
    let write_settings = host.payload(
        "write_to_file",
        json!({"TargetFile": settings, "CodeContent": "{}", "Overwrite": true}),
    );
    assert_eq!(
        host.reads(&line, &write_settings, "write_to_file of agent settings"),
        Call::Refused
    );
    let write_src = host.payload(
        "write_to_file",
        json!({"TargetFile": host.project().join("src/lib.rs"), "CodeContent": "fn x() {}"}),
    );
    assert_eq!(
        host.reads(&line, &write_src, "write_to_file in the project"),
        Call::Runs
    );

    for (raw, what) in [
        (b"not json".to_vec(), "not JSON"),
        (
            json!({"conversationId": "c"}).to_string().into_bytes(),
            "no toolCall",
        ),
        (
            host.payload("run_command", json!({"Cwd": host.project()}))
                .to_string()
                .into_bytes(),
            "run_command with no CommandLine",
        ),
    ] {
        let (code, stdout, _) = host.run(&line, &raw);
        assert_eq!(agy_reads(code, &stdout, what), Call::Refused, "{what}");
    }
}

/// The monitor line refuses nothing: a line rated deny and a call that
/// cannot be read both run, answered `allow` with exit 0.
#[test]
fn monitor_lets_every_call_run_with_an_allow() {
    let host = Host::new();
    let line = ANTIGRAVITY.command(bin(), false, true);
    let rm = host.payload("run_command", json!({"CommandLine": "rm -rf ~"}));
    assert_eq!(host.reads(&line, &rm, "rm -rf ~ in monitor"), Call::Runs);
    let (code, stdout, _) = host.run(&line, b"not json");
    assert_eq!(
        agy_reads(code, &stdout, "unreadable in monitor"),
        Call::Runs
    );
}

/// A review the guard asks about (the line the other agents' suites ask
/// on) asks the person with `force_ask`, which no earlier "Always Allow"
/// skips, and says why; with --block-review it is refused.
///
/// FAILS ON REVERT: drop `AskAntigravity` from `review_answer_for`, and the
/// review is refused instead of asked.
#[test]
fn a_review_asks_and_block_review_refuses_it() {
    let host = Host::new();
    let enforce = ANTIGRAVITY.command(bin(), false, false);
    let strict = ANTIGRAVITY.command(bin(), true, false);
    let review = host.payload(
        "run_command",
        json!({"CommandLine": "chmod 777 ./build.sh"}),
    );
    let (code, stdout, _) = host.run(&enforce, review.to_string().as_bytes());
    assert_eq!(agy_reads(code, &stdout, "a review"), Call::Asks, "{stdout}");
    let answer: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(answer["decision"], "force_ask");
    assert!(
        answer["reason"]
            .as_str()
            .is_some_and(|r| r.contains("world-writable permissions")),
        "the person is told why: {answer}"
    );
    assert_eq!(
        host.reads(&strict, &review, "a review with --block-review"),
        Call::Refused
    );
}

/// The guard is gone: the enforcing line answers with a deny of its own, as
/// JSON with exit 0, so Antigravity is not left to read an exit code.
///
/// FAILS ON REVERT: give Antigravity the plain fail-closed tail, which says
/// so on stderr with exit 2 and nothing on stdout.
#[test]
fn a_missing_guard_is_answered_with_a_deny() {
    let host = Host::new();
    let gone = host.dir.path().join("gone/innerwarden");
    let line = ANTIGRAVITY.command(&gone, false, false);
    let call = host.payload("run_command", json!({"CommandLine": "npm test"}));
    let (code, stdout, _) = host.run(&line, call.to_string().as_bytes());
    assert_eq!(agy_reads(code, &stdout, "a missing guard"), Call::Refused);
}

/// The suite's PATH less every folder that holds a `codex`.
fn path_without_codex() -> std::ffi::OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept = std::env::split_paths(&path)
        .filter(|dir| !dir.join("codex").exists() && !dir.join("codex.exe").exists());
    std::env::join_paths(kept).expect("folders split from PATH join back")
}

/// The binary with `args` over `home`, as the person runs it.
fn cli(home: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("PATH", path_without_codex())
        .env_remove("INNERWARDEN_CONFIG_DIR")
        .env_remove("CODEX_HOME");
    for marker in [
        "CLAUDECODE",
        "CLAUDE_CODE_ENTRYPOINT",
        "CODEX_SANDBOX",
        "CODEX_SANDBOX_NETWORK_DISABLED",
        "GEMINI_CLI",
        "OPENCLAW_SHELL",
        "CURSOR_AGENT",
        "CURSOR_TRACE_ID",
    ] {
        cmd.env_remove(marker);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run the binary")
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A hooks file as a person keeps it, with a hook of their own.
const THEIRS: &str = "{\n    \"my-linter\": {\n        \"PostToolUse\": [\n            {\"matcher\": \"write_to_file\", \"hooks\": [{\"command\": \"./lint.sh\"}]}\n        ]\n    }\n}\n";

/// `agents connect antigravity` writes the guard's entry beside the
/// person's hook, says it is on and what it screens, lists the agent as
/// guarded by its hook; a second connect writes nothing; `agents disconnect`
/// gives back the file it found, to the byte.
///
/// FAILS ON REVERT: take `ANTIGRAVITY` out of `agent_hooks::spec_for`, and
/// the connect finds no wiring for the agent.
#[test]
fn connect_and_disconnect_give_back_the_hooks_file_to_the_byte() {
    let dir = tempfile::TempDir::new().unwrap();
    let home = dir.path();
    std::fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    std::fs::write(home.join(".gemini/antigravity-cli/settings.json"), "{}\n").unwrap();
    std::fs::create_dir_all(home.join(".gemini/config")).unwrap();
    let hooks = home.join(".gemini/config/hooks.json");
    std::fs::write(&hooks, THEIRS).unwrap();

    let out = cli(home, &["agents", "connect", "antigravity"]);
    let text = said(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(
        text.contains("antigravity - connected (PreToolUse hook)"),
        "{text}"
    );
    assert!(
        text.contains("Screened before they run: shell commands (`run_command`)"),
        "{text}"
    );
    assert!(
        text.contains("not routed through the guard proxy"),
        "{text}"
    );
    let written = std::fs::read_to_string(&hooks).unwrap();
    let value: Value = serde_json::from_str(&written).unwrap();
    assert_eq!(
        value["my-linter"],
        serde_json::from_str::<Value>(THEIRS).unwrap()["my-linter"]
    );
    let entry = &value["innerwarden"]["PreToolUse"][0];
    assert_eq!(entry["matcher"], "");
    assert_eq!(entry["hooks"][0]["timeout"], 60);
    assert!(
        entry["hooks"][0]["command"]
            .as_str()
            .is_some_and(|c| c.contains("hook --agent antigravity") && c.contains("decision")),
        "{entry}"
    );

    let again = said(&cli(home, &["agents", "connect", "antigravity"]));
    assert!(again.contains("antigravity - already guarded"), "{again}");
    assert_eq!(std::fs::read_to_string(&hooks).unwrap(), written);

    let listed = said(&cli(home, &["agents"]));
    let row = listed
        .lines()
        .find(|line| line.trim_start().starts_with("antigravity"))
        .unwrap_or_else(|| panic!("no antigravity row: {listed}"));
    assert!(row.contains("guarded (hook, enforce)"), "{row}");

    let out = cli(home, &["agents", "disconnect", "antigravity"]);
    let text = said(&out);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("antigravity, disconnected"), "{text}");
    assert_eq!(std::fs::read_to_string(&hooks).unwrap(), THEIRS);
}

/// With no hooks file, connect creates it and disconnect removes it.
#[test]
fn a_hooks_file_connect_created_goes_with_the_disconnect() {
    let dir = tempfile::TempDir::new().unwrap();
    let home = dir.path();
    std::fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();
    std::fs::write(home.join(".gemini/antigravity-cli/settings.json"), "{}\n").unwrap();
    let hooks = home.join(".gemini/config/hooks.json");

    let out = cli(home, &["agents", "connect", "antigravity", "--monitor"]);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(hooks.is_file());
    let listed = said(&cli(home, &["agents"]));
    assert!(listed.contains("guarded (hook, monitor)"), "{listed}");
    let out = cli(home, &["agents", "disconnect", "antigravity"]);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(!hooks.exists());
}
