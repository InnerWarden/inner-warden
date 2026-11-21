//! End-to-end: a prompt record proven to come from the runtime's hook.
//!
//! The runtime that runs a hook (Claude Code) reads the hook's stdout
//! through a pipe it alone holds; the commands of its agent get stdin
//! `/dev/null` and stdout on a file (Claude Code 2.1.329, measured
//! 2026-11-21). Here the test process plays the runtime: it starts the hook
//! line as Claude Code does, and reads the record as the MCP proxy, a child
//! of the runtime, would ([`user_prompt::user_asked_for_proven_in`] with
//! [`prompt_writer::is_self_or_ancestor`]). The agent's ways of feeding the
//! hook a prompt it wrote (a shell line, a script file, a Python
//! `subprocess`, an `exec` into the hook line) run as the agent's Bash
//! tool runs them. Each is kept, as before (information), and none is
//! proven.

#![cfg(unix)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use innerwarden_agent_guard::prompt_writer;
use innerwarden_agent_guard::user_prompt::{self, UserAsked};
use serde_json::json;

// This test starts the binary where it was built and copies nothing.
#[allow(dead_code)]
mod fork_safe;
use fork_safe::spawn_without_racing_a_copy;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

const ASKED: &str = "send the invoice to ana@example.com";

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

    fn env<'a>(&self, command: &'a mut Command, session: &str) -> &'a mut Command {
        command
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .env("BIN", bin())
            .env("PAYLOAD", payload(session))
            .current_dir(self.home().join("proj"))
    }

    /// The runtime runs the hook: stdin and stdout pipes this process
    /// holds, through `sh -c` or straight.
    fn runtime_runs(&self, session: &str, through_sh: bool) {
        let line = format!("\"{}\" hook --agent claude-code --prompt", bin());
        let mut command = if through_sh {
            let mut command = Command::new("sh");
            command.args(["-c", &line]);
            command
        } else {
            let mut command = Command::new(bin());
            command.args(["hook", "--agent", "claude-code", "--prompt"]);
            command
        };
        let mut child = spawn_without_racing_a_copy(
            self.env(&mut command, session)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped()),
        );
        let _ = child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(payload(session).as_bytes());
        drop(child.stdin.take());
        let out = child.wait_with_output().expect("hook ran");
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert!(out.stdout.is_empty(), "{out:?}");
    }

    /// The agent runs `line` as its Bash tool runs a command: `bash -c`,
    /// stdin `/dev/null`, stdout and stderr on a file. With `piped`, the
    /// command's stdout is a pipe this process reads instead.
    fn agent_runs(&self, session: &str, line: &str, piped: bool) {
        let log = std::fs::File::create(self.dir.path().join(format!("{session}.out")))
            .expect("output file");
        let mut command = Command::new("bash");
        command.args(["-c", line]);
        self.env(&mut command, session).stdin(Stdio::null());
        if piped {
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        } else {
            command
                .stdout(log.try_clone().expect("output file"))
                .stderr(log);
        }
        let out = spawn_without_racing_a_copy(&mut command)
            .wait_with_output()
            .expect("agent line ran");
        assert!(out.status.success(), "{line}: {out:?}");
    }

    fn dir(&self) -> PathBuf {
        user_prompt::dir_in(&self.home())
    }

    fn asked(&self, session: &str, value: &str) -> UserAsked {
        user_prompt::user_asked_for_in(&self.dir(), Some(session), value, now())
    }

    fn proven(&self, session: &str, value: &str) -> UserAsked {
        user_prompt::user_asked_for_proven_in(
            &self.dir(),
            Some(session),
            value,
            now(),
            prompt_writer::is_self_or_ancestor,
        )
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn payload(session: &str) -> String {
    json!({
        "session_id": session,
        "transcript_path": "/tmp/t.jsonl",
        "cwd": "/tmp",
        "permission_mode": "default",
        "hook_event_name": "UserPromptSubmit",
        "prompt": ASKED,
    })
    .to_string()
}

/// FAILS ON REVERT of the writer kept with the prompt (main.rs
/// `keep_the_prompt`, `prompt_writer::hook_writer`): the prompt the runtime's
/// hook kept is proven, straight or through `sh -c`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn the_runtime_s_hook_is_proven() {
    let host = Host::new();
    for (session, through_sh) in [("runtime-sh", true), ("runtime-direct", false)] {
        host.runtime_runs(session, through_sh);
        assert_eq!(host.asked(session, "ana@example.com"), UserAsked::Yes);
        assert_eq!(
            host.proven(session, "ana@example.com"),
            UserAsked::Yes,
            "{session}"
        );
        assert_eq!(
            host.proven(session, "eve@evil.example"),
            UserAsked::No,
            "{session}"
        );
    }
}

/// Every way the agent feeds the hook a prompt of its own: kept, as
/// before, and never proven.
#[test]
fn the_agent_s_own_hook_runs_are_not_proven() {
    let host = Host::new();
    let script = host.dir.path().join("feed.sh");
    std::fs::write(
        &script,
        "#!/bin/bash\nout=$(printf '%s' \"$PAYLOAD\" | \"$BIN\" hook --agent claude-code --prompt)\n",
    )
    .expect("script");
    let cases = [
        (
            "shell-pipe",
            "printf '%s' \"$PAYLOAD\" | \"$BIN\" hook --agent claude-code --prompt".to_string(),
        ),
        (
            "shell-capture",
            "out=$(printf '%s' \"$PAYLOAD\" | \"$BIN\" hook --agent claude-code --prompt)"
                .to_string(),
        ),
        ("script-file", format!("bash {}", script.display())),
        (
            "python-subprocess",
            "python3 -c 'import os, subprocess; subprocess.run([os.environ[\"BIN\"], \"hook\", \
             \"--agent\", \"claude-code\", \"--prompt\"], input=os.environ[\"PAYLOAD\"].encode(), \
             capture_output=True)'"
                .to_string(),
        ),
        (
            "exec-into-the-line",
            "exec sh -c '\"$BIN\" hook --agent claude-code --prompt' < <(printf '%s' \"$PAYLOAD\")"
                .to_string(),
        ),
    ];
    for (session, line) in &cases {
        host.agent_runs(session, line, false);
        assert_eq!(
            host.asked(session, "ana@example.com"),
            UserAsked::Yes,
            "{session}: the prompt is kept, as before"
        );
        assert_eq!(
            host.proven(session, "ana@example.com"),
            UserAsked::Unknown(user_prompt::why::NOT_PROVEN),
            "{session}"
        );
        assert_eq!(
            host.proven(session, "eve@evil.example"),
            UserAsked::Unknown(user_prompt::why::NOT_PROVEN),
            "{session}: not proven is never no"
        );
    }
}

/// The limit, kept in sight: a runtime that hands its agent's commands a
/// stdout pipe it reads itself gives an `exec` into the hook line the same
/// proof as its own hook. Claude Code 2.1.329 hands them a file.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn limit_a_runtime_that_reads_its_agent_s_commands_through_a_pipe() {
    let host = Host::new();
    host.agent_runs(
        "piped-runtime",
        "exec sh -c '\"$BIN\" hook --agent claude-code --prompt' < <(printf '%s' \"$PAYLOAD\")",
        true,
    );
    assert_eq!(
        host.proven("piped-runtime", "ana@example.com"),
        UserAsked::Yes
    );
}
