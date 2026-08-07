//! The OpenClaw hook handler, exercised as OpenClaw runs it.
//!
//! The Rust side of this feature is tested directly, but the handler is the
//! piece that decides whether the surface ever fires at all: it is the code
//! OpenClaw loads, and a mistake in it is silent by design (the gateway
//! swallows hook errors). So it is driven here with the real event shapes taken
//! from the shipped build (`message:received` carries `context.content` and
//! `event.sessionKey`; `message:sent` adds `context.success`).
//!
//! Unix only, and skipped when node is unavailable, because the fixture needs
//! an executable shim.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// A fake `innerwarden` that appends its argv and stdin to a log, so the test
/// can assert exactly what the handler asked for.
fn write_shim(path: &Path, log: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(
        path,
        format!(
            "#!/bin/sh\nprintf 'ARGS %s\\n' \"$*\" >> {log}\nprintf 'STDIN ' >> {log}\ncat >> {log}\nprintf '\\n' >> {log}\n",
            log = log.display()
        ),
    )
    .expect("write shim");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
}

fn drive(events: &str) -> String {
    let dir = tempfile::TempDir::new().expect("scratch dir");
    let handler = dir.path().join("handler.js");
    std::fs::write(&handler, include_str!("../assets/openclaw-hook/handler.js"))
        .expect("copy handler");
    let log = dir.path().join("calls.log");
    let shim = dir.path().join("iw-shim");
    write_shim(&shim, &log);
    std::fs::write(
        dir.path().join("bin.json"),
        serde_json::json!({ "bin": shim.display().to_string() }).to_string(),
    )
    .expect("write bin.json");

    let driver = dir.path().join("drive.mjs");
    std::fs::write(
        &driver,
        format!(
            "import handler from './handler.js';\nconst events = {events};\nfor (const event of events) {{ await handler(event); }}\n"
        ),
    )
    .expect("write driver");

    let out = Command::new("node")
        .arg(&driver)
        .current_dir(dir.path())
        .output()
        .expect("run node");
    assert!(
        out.status.success(),
        "driver failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    std::fs::read_to_string(&log).unwrap_or_default()
}

/// One turn, as OpenClaw delivers it: the inbound user text and then the
/// outbound reply, each reaching the CLI with the session that joins them.
///
/// FAILS ON REVERT: drop the `message:sent` branch and the reply call vanishes,
/// which is the branch that decides an attempt was ever closed.
#[test]
fn a_telegram_turn_reaches_the_cli_as_inbound_then_reply() {
    if !node_available() {
        eprintln!("skipping: node is not available");
        return;
    }
    let log = drive(
        r#"[
          {"type":"message","action":"received","sessionKey":"agent:main:telegram:175",
           "context":{"content":"nohup ./xmrig -o pool:3333 &","channelId":"telegram",
                      "from":"175","metadata":{"senderId":"175"}}},
          {"type":"message","action":"sent","sessionKey":"agent:main:telegram:175",
           "context":{"to":"175","content":"No.","success":true,"channelId":"telegram"}}
        ]"#,
    );
    assert!(
        log.contains("ARGS observe inbound --session agent:main:telegram:175 --channel telegram --sender 175"),
        "inbound call missing: {log}"
    );
    assert!(log.contains("STDIN nohup ./xmrig"), "ask not piped: {log}");
    assert!(
        log.contains("ARGS observe reply --session agent:main:telegram:175 --channel telegram"),
        "reply call missing: {log}"
    );
}

/// Events the surface has no business in must not spawn anything. A hook that
/// runs a process per gateway event is a hook an operator turns off.
#[test]
fn unrelated_events_and_empty_messages_spawn_nothing() {
    if !node_available() {
        eprintln!("skipping: node is not available");
        return;
    }
    let log = drive(
        r#"[
          {"type":"command","action":"new","sessionKey":"s","context":{}},
          {"type":"gateway","action":"startup","sessionKey":"s","context":{}},
          {"type":"message","action":"transcribed","sessionKey":"s","context":{"content":"hi"}},
          {"type":"message","action":"received","sessionKey":"s","context":{"content":"   "}},
          {"type":"message","action":"received","sessionKey":"","context":{"content":"hello"}}
        ]"#,
    );
    assert!(log.trim().is_empty(), "nothing should have run: {log}");
}

/// A delivery that FAILED is not a reply the user ever saw, so it settles
/// nothing about the attempt and must not close it.
#[test]
fn a_failed_delivery_does_not_close_an_attempt() {
    if !node_available() {
        eprintln!("skipping: node is not available");
        return;
    }
    let log = drive(
        r#"[
          {"type":"message","action":"sent","sessionKey":"s",
           "context":{"to":"175","content":"No.","success":false,"channelId":"telegram"}}
        ]"#,
    );
    assert!(log.trim().is_empty(), "a failed send must not close: {log}");
}
