//! NEW-20261102-free-mcp-proxy-env-hides-refusals: whoever controls the MCP
//! proxy's environment chooses where its record goes (`IW_GRAPH_FILE`) and
//! whether the local agent hears of a refusal (`INNERWARDEN_AGENT_URL=off`).
//! The refusals still held, and the operator never saw them. A refusal now
//! also reaches the guard's own record, the one `innerwarden status` reads.

#![cfg(unix)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// The proxy around `cat` (which echoes every forwarded line) in `mode`,
/// with its record moved off the home and the agent's report off; one line
/// in, then closed.
fn proxy(home: &Path, moved: &Path, mode: &str, line: &str) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_innerwarden"));
    command
        .args(["proxy", "--mode", mode, "--label", "e2e", "--", "cat"])
        .env("HOME", home)
        .env("IW_GRAPH_FILE", moved)
        .env("INNERWARDEN_AGENT_URL", "off")
        // Never this host's shared record, where InnerWarden Pro is installed.
        .env("IW_TEST_GUARD_CONFIG", home.join("no-guard.toml"))
        .env_remove("IW_GUARD_SESSION")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for marker in [
        "CLAUDECODE",
        "CLAUDE_CODE_ENTRYPOINT",
        "CODEX_SANDBOX",
        "GEMINI_CLI",
        "OPENCLAW_SHELL",
    ] {
        command.env_remove(marker);
    }
    let mut child = command.spawn().expect("run innerwarden proxy");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(line.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// A refused call (guard mode) is written where `IW_GRAPH_FILE` says and
/// in the guard's own record, the graph and the `guard.blocked` line beside it,
/// with `INNERWARDEN_AGENT_URL=off` too. A clean call, and one advisory mode
/// only records, stay where the environment sent them.
///
/// FAILS ON REVERT: drop the copy in `graph_io::record_mcp` and the home's
/// record is never written.
#[test]
fn a_refusal_reaches_the_guards_own_record_whatever_the_environment_says() {
    let dir = tempfile::TempDir::new().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(&home).unwrap();
    let moved = dir.path().join("elsewhere/graph.json");
    let own = home.join(".config/innerwarden");
    let secret = format!("sk-ant{}", "-FAKEfake1111fake2222fake3333value789");
    let denied = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "save", "arguments": {"token": secret}}
    })
    .to_string();
    let clean = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"weather","arguments":{"location":"NYC"}}}"#;

    proxy(&home, &moved, "guard", clean);
    assert!(read(&moved).contains("weather"), "{}", read(&moved));
    assert!(
        !own.join("graph.json").exists(),
        "a clean call stays where it was sent"
    );

    proxy(&home, &moved, "advisory", &denied);
    assert!(read(&moved).contains("save"));
    assert!(
        !own.join("graph.json").exists(),
        "a call advisory mode only records is no refusal"
    );

    proxy(&home, &moved, "guard", &denied);
    let graph = read(&own.join("graph.json"));
    assert!(graph.contains("save"), "{graph}");
    assert!(graph.contains("blocked"), "{graph}");
    assert!(!graph.contains("weather"), "{graph}");
    assert!(
        !graph.contains(&secret),
        "the raw argument reached the record"
    );
    let events = read(&own.join("guard-events.jsonl"));
    assert_eq!(events.lines().count(), 1, "{events}");
    assert!(
        events.contains("save") && !events.contains(&secret),
        "{events}"
    );
    // And where the environment sent it, as before.
    assert!(read(&moved).matches("blocked").count() >= 1);
}
