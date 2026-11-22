//! What an ordinary MCP call of Codex costs in the hook, against a plain
//! shell call. A measurement, not a check (`--ignored`): run in a release
//! build, `cargo test --release -p innerwarden --test mcp_hook_call_cost --
//! --ignored --nocapture`, on this tree and on the one to compare.
//!
//! Drives the REAL binary over a disposable HOME, as Codex runs it.

#![cfg(unix)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

fn run(home: &std::path::Path, scratch: &std::path::Path, payload: &Value) -> Duration {
    let started = Instant::now();
    let mut child = Command::new(env!("CARGO_BIN_EXE_innerwarden"))
        .args(["hook", "--agent", "codex"])
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("IW_GRAPH_FILE", scratch.join("graph.json"))
        .env("IW_SESSION_FILE", scratch.join("sessions.json"))
        .env("IW_TEST_ACCOUNT_HOME", home)
        .env("IW_TEST_GUARD_CONFIG", scratch.join("no-guard.toml"))
        .env("INNERWARDEN_AGENT_URL", "off")
        .env_remove("INNERWARDEN_HOOK_DEADLINE_MS")
        .current_dir(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("run the hook");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    child.wait().unwrap();
    started.elapsed()
}

fn payload(home: &std::path::Path, tool: &str, input: Value) -> Value {
    json!({
        "session_id": "019a6c3e-0000-7000-8000-000000000197",
        "turn_id": "turn-1",
        "transcript_path": null,
        "cwd": home,
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.5-codex",
        "permission_mode": "default",
        "tool_name": tool,
        "tool_input": input,
        "tool_use_id": "call_1",
    })
}

fn median_and_p90(mut runs: Vec<Duration>) -> (Duration, Duration) {
    runs.sort();
    (runs[runs.len() / 2], runs[runs.len() * 9 / 10])
}

#[test]
#[ignore = "a measurement: run in release with --ignored --nocapture"]
fn an_ordinary_mcp_call_costs_about_what_a_shell_call_does() {
    let dir = tempfile::TempDir::new().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let shell = payload(&home, "Bash", json!({"command": "ls -la"}));
    let mcp = payload(
        &home,
        "mcp__linear__list_issues",
        json!({"query": "assignee:me state:open", "limit": 20}),
    );
    const RUNS: usize = 41;
    for _ in 0..3 {
        run(&home, dir.path(), &shell);
        run(&home, dir.path(), &mcp);
    }
    let mut shell_runs = Vec::new();
    let mut mcp_runs = Vec::new();
    for _ in 0..RUNS {
        shell_runs.push(run(&home, dir.path(), &shell));
        mcp_runs.push(run(&home, dir.path(), &mcp));
    }
    let (shell_median, shell_p90) = median_and_p90(shell_runs);
    let (mcp_median, mcp_p90) = median_and_p90(mcp_runs);
    eprintln!(
        "hook wall time over {RUNS} runs each: shell call median {:.2} ms p90 {:.2} ms; \
         clean MCP call median {:.2} ms p90 {:.2} ms",
        shell_median.as_secs_f64() * 1e3,
        shell_p90.as_secs_f64() * 1e3,
        mcp_median.as_secs_f64() * 1e3,
        mcp_p90.as_secs_f64() * 1e3,
    );
}
