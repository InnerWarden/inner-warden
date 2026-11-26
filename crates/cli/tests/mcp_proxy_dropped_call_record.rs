//! A refused MCP call with no id is recorded as refused, never as allowed.
//!
//! In `guard`, `kill` and `strict` the proxy drops a refused `tools/call`
//! sent with no id (or `"id": null`): nothing can answer it, and it never
//! reaches the server. The narrative record wrote it as `allowed`, from the
//! days the proxy forwarded such a call, so the record said a call ran that
//! never did.
//!
//! Through the real binary: `innerwarden proxy` with `cat` as the server (a
//! line that reaches it comes back), a scratch home and record.
//!
//! FAILS ON REVERT of the `request_id` test taken out of
//! `graph_io::mcp_context`: the dropped call is recorded as `allowed`.

#![cfg(unix)]

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// What reached the client (and so the server: `cat` echoes every line),
/// and the record the proxy wrote.
fn proxy(mode: &str, call: &serde_json::Value) -> (String, serde_json::Value) {
    let dir = tempfile::TempDir::new().expect("scratch home");
    let graph = dir.path().join("graph.json");
    let mut child = Command::new(bin())
        .args(["proxy", "--mode", mode, "--label", "e2e", "--", "cat"])
        .env("HOME", dir.path())
        .env("IW_GRAPH_FILE", &graph)
        .env("IW_MCP_PINS", dir.path().join("mcp-pins.json"))
        .env("INNERWARDEN_AGENT_URL", "off")
        // The copy of a refusal into the guard's own record stays here.
        .env("IW_TEST_ACCOUNT_HOME", dir.path())
        .env("IW_TEST_GUARD_CONFIG", dir.path().join("no-guard.toml"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the proxy");
    writeln!(child.stdin.as_mut().expect("stdin"), "{call}").expect("write");
    drop(child.stdin.take());
    // Not its exit status: `kill` ends the server, and the proxy exits with
    // the server's status.
    let out = child.wait_with_output().expect("wait for the proxy");
    let record = std::fs::read_to_string(&graph).unwrap_or_else(|e| {
        panic!(
            "{mode}: no record ({e}): {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        serde_json::from_str(&record).expect("a JSON record"),
    )
}

/// The one call the record holds. A finding on what `cat` echoes back (the
/// call's own secret, in a mode that forwards it) is the server's, recorded
/// as `mcp server: ...`, not a call.
fn command(record: &serde_json::Value) -> serde_json::Value {
    let commands: Vec<&serde_json::Value> = record["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .filter(|node| {
            node["kind"] == "command"
                && !node["label"]
                    .as_str()
                    .is_some_and(|label| label.starts_with("mcp server: "))
        })
        .collect();
    assert_eq!(commands.len(), 1, "{record}");
    commands[0].clone()
}

#[test]
fn a_dropped_call_with_no_id_is_recorded_as_refused() {
    let secret = format!("sk-ant{}", "-FAKEfake1111fake2222fake3333value789");
    for id in [None, Some(serde_json::Value::Null)] {
        let mut call = serde_json::json!({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": "save", "arguments": {"token": secret}}
        });
        if let Some(id) = &id {
            call["id"] = id.clone();
        }
        for mode in ["guard", "kill", "strict"] {
            let (out, record) = proxy(mode, &call);
            assert!(
                !out.contains("tools/call"),
                "{mode} id {id:?}: the refused call reached the server: {out}"
            );
            let attrs = &command(&record)["attrs"];
            assert_eq!(attrs["recommendation"], "deny", "{mode} id {id:?}");
            assert_eq!(attrs["mode_at_decision"], "enforce", "{mode} id {id:?}");
            assert_eq!(attrs["outcome"], "blocked", "{mode} id {id:?}: {attrs}");
        }
        // A monitor mode forwards it: it would have been refused.
        let (out, record) = proxy("advisory", &call);
        assert!(out.contains("tools/call"), "{out}");
        assert_eq!(command(&record)["attrs"]["outcome"], "would_block");
    }
}
