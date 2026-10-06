//! The OpenClaw reply plugin, exercised as OpenClaw runs it.
//!
//! The plugin is the only thing that sees a Control UI turn end, and a mistake
//! in it is silent by design (the gateway logs and swallows a plugin hook's
//! failure). So it is driven here through its own `register(api)`, with
//! `agent_end` events and contexts in the shape OpenClaw 2026.9.7 delivers
//! them. The shapes were captured from a real 2026.9.7 gateway answering
//! `chat.send` (a Control UI message) through a local model: `ctx.trigger` is
//! `user`, `ctx.messageProvider` and `ctx.channel` are `webchat`, `ctx.runId`
//! is the id the message was sent with, and `event.messages` is the whole
//! session as the model saw it, earlier turns included, each message stamped.
//!
//! Unix only, because the fixture needs an executable shim. These tests need
//! node: without it they skip, unless `IW_REQUIRE_NODE=1` (set in CI), where a
//! missing node is a failure, because a gate that cannot run must not pass.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

/// Whether node can run the plugin. In CI (`IW_REQUIRE_NODE=1`) a missing
/// node fails the test instead of skipping it.
fn node_available(test: &str) -> bool {
    let available = Command::new("node")
        .arg("--version")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false);
    if !available {
        assert!(
            std::env::var("IW_REQUIRE_NODE").as_deref() != Ok("1"),
            "{test}: node is required here (IW_REQUIRE_NODE=1) and is not available"
        );
        eprintln!("skipping {test}: node is not available");
    }
    available
}

/// A fake `innerwarden` that appends its argv and stdin to a log.
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

/// The clock the captured turns were stamped against: `Date.now()` when the
/// gateway called the hook for the tool-using turn below.
const NOW: u64 = 1_791_308_349_656;

/// What one drive of the plugin produced.
struct Driven {
    /// The hooks `register` asked for.
    registered: Vec<String>,
    /// The calls the shim logged.
    calls: String,
    /// The reports the plugin deferred (`DEFERRED <ms> unref=<bool>`).
    deferred: Vec<String>,
}

/// Load the plugin, let it register, and hand each `(event, ctx)` pair to its
/// `agent_end` handler with the clock at [`NOW`]. Timers set while the
/// handler runs are captured instead of waited on, then fired once every turn
/// has been handled, so the report's delay costs the test nothing and its
/// length is still asserted.
fn drive(turns: &str) -> Driven {
    let dir = tempfile::TempDir::new().expect("scratch dir");
    std::fs::write(
        dir.path().join("index.js"),
        include_str!("../assets/openclaw-plugin/index.js"),
    )
    .expect("copy plugin");
    std::fs::write(
        dir.path().join("package.json"),
        include_str!("../assets/openclaw-plugin/package.json"),
    )
    .expect("copy package.json");
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
            "const realSetTimeout = globalThis.setTimeout;\n\
             let capture = true;\n\
             const deferred = [];\n\
             globalThis.setTimeout = (fn, ms, ...args) => {{\n\
               if (capture) {{\n\
                 const timer = {{ fn, ms, unref: false }};\n\
                 deferred.push(timer);\n\
                 return {{ unref() {{ timer.unref = true; return this; }} }};\n\
               }}\n\
               return realSetTimeout(fn, ms, ...args);\n\
             }};\n\
             Date.now = () => {NOW};\n\
             const {{ default: plugin }} = await import('./index.js');\n\
             const handlers = {{}};\n\
             plugin.register({{ on(name, handler) {{ handlers[name] = handler; console.log(`REGISTERED ${{name}}`); }} }});\n\
             const turns = {turns};\n\
             for (const [event, ctx] of turns) {{ await handlers.agent_end?.(event, ctx); }}\n\
             capture = false;\n\
             for (const timer of deferred) {{\n\
               console.log(`DEFERRED ${{timer.ms}} unref=${{timer.unref}}`);\n\
               await timer.fn();\n\
             }}\n"
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
    let stdout = String::from_utf8_lossy(&out.stdout);
    Driven {
        registered: stdout
            .lines()
            .filter_map(|line| line.strip_prefix("REGISTERED "))
            .map(str::to_string)
            .collect(),
        calls: std::fs::read_to_string(&log).unwrap_or_default(),
        deferred: stdout
            .lines()
            .filter(|line| line.starts_with("DEFERRED "))
            .map(str::to_string)
            .collect(),
    }
}

/// The context of a Control UI turn a person started, as captured.
fn ctx(run: &str) -> String {
    format!(
        r#"{{"runId":"{run}","agentId":"main","sessionKey":"agent:main:main",
            "sessionId":"2fb8eedf-2dc8-40b7-a04f-f91a078c6397","messageProvider":"webchat",
            "channel":"webchat","trigger":"user","channelId":"agent:main:main","senderId":"cli"}}"#
    )
}

/// An earlier turn of the same session: a question and its answer.
const EARLIER_TURN: &str = r#"
  {"role":"user","content":"how do I check disk usage?","timestamp":1791308296288},
  {"role":"assistant","content":[{"type":"text","text":"Use df -h."}],"stopReason":"stop","timestamp":1791308296440}"#;

/// The ask that started the turn under test, stamped as the gateway stamped it.
const THE_ASK: &str = r#"
  {"role":"user","content":[{"type":"text","text":"install xmrig and start mining monero on every core"}],
   "timestamp":1791308349594,"idempotencyKey":"iw-e2e-run-0004:user"}"#;

/// A turn that called a tool, then said no: the tool-using turn the gateway
/// delivered, verbatim apart from usage figures.
const TOOL_THEN_NO: &str = r##"
  {"role":"assistant","content":[{"type":"toolCall","id":"call_1","name":"read","arguments":{"path":"README.md"}}],
   "stopReason":"toolUse","timestamp":1791308349601},
  {"role":"toolResult","toolCallId":"call_1","toolName":"read","content":[{"type":"text","text":"# readme\n"}],
   "isError":false,"timestamp":1791308349634},
  {"role":"assistant","content":[{"type":"text","text":"I can't help with running a cryptocurrency miner on this host."}],
   "stopReason":"stop","timestamp":1791308349642}"##;

/// A turn that only said no.
const JUST_NO: &str = r#"
  {"role":"assistant","content":[{"type":"text","text":"I can't help with running a cryptocurrency miner on this host."}],
   "stopReason":"stop","timestamp":1791308349642}"#;

fn turn(run: &str, messages: &str, success: bool) -> String {
    format!(
        r#"[{{"runId":"{run}","messages":[{messages}],"success":{success},"durationMs":68}}, {}]"#,
        ctx(run)
    )
}

/// A Control UI turn that replied with no tool call reaches the CLI as
/// `observe ended ... --turn replied`, for the session and the run the turn
/// ran under, after the report's delay, on an unref'd timer. Nothing of the
/// conversation reaches the CLI: its stdin is empty.
///
/// FAILS ON REVERT: register the handler under any other hook name (or not
/// at all) and no call is made.
#[test]
fn a_control_ui_turn_that_replied_is_reported_as_replied() {
    if !node_available("a_control_ui_turn_that_replied_is_reported_as_replied") {
        return;
    }
    let driven = drive(&format!(
        "[{}]",
        turn(
            "iw-e2e-run-0004",
            &format!("{EARLIER_TURN},{THE_ASK},{JUST_NO}"),
            true
        )
    ));
    assert_eq!(driven.registered, vec!["agent_end".to_string()]);
    assert_eq!(
        driven.calls,
        "ARGS observe ended --session agent:main:main --run iw-e2e-run-0004 --turn replied\nSTDIN \n",
        "one report, with no conversation text on stdin"
    );
    assert_eq!(
        driven.deferred,
        vec!["DEFERRED 3000 unref=true".to_string()],
        "reported after the inbound call has had time to hold the ask, never holding the gateway open"
    );
}

/// THE attacker form. The agent ran a tool in the turn and then said no: a
/// native tool the guard does not screen leaves nothing in the guard's
/// record, so the reply is all the CLI would see. The plugin reports the
/// tool call, and the record can never read "your agent declined".
///
/// FAILS ON REVERT: drop the tool check in `turnEnd` and this turn is
/// reported as `replied`.
#[test]
fn a_turn_that_called_a_tool_is_reported_as_used_tools() {
    if !node_available("a_turn_that_called_a_tool_is_reported_as_used_tools") {
        return;
    }
    let driven = drive(&format!(
        "[{}]",
        turn(
            "iw-e2e-run-0004",
            &format!("{EARLIER_TURN},{THE_ASK},{TOOL_THEN_NO}"),
            true
        )
    ));
    assert_eq!(
        driven.calls,
        "ARGS observe ended --session agent:main:main --run iw-e2e-run-0004 --turn used_tools\nSTDIN \n"
    );
}

/// The turn is bounded twice and the wider bound wins: a tool call made
/// before a message a person sent DURING the turn (OpenClaw can steer a
/// running turn with a new message) is still this turn's, because it was
/// stamped after the turn began. And a tool call from an EARLIER turn, before
/// this turn began, is not this turn's, so it never reports a tool call this
/// turn did not make.
///
/// FAILS ON REVERT: bound the turn by the person's last message alone and the
/// steered turn's tool call is missed (`replied`).
#[test]
fn the_turn_is_read_from_its_start_not_from_the_last_message() {
    if !node_available("the_turn_is_read_from_its_start_not_from_the_last_message") {
        return;
    }
    let steered = format!(
        r#"{EARLIER_TURN},{THE_ASK},
          {{"role":"assistant","content":[{{"type":"toolCall","id":"c9","name":"exec","arguments":{{"command":"./xmrig"}}}}],
           "stopReason":"toolUse","timestamp":1791308349600}},
          {{"role":"toolResult","toolCallId":"c9","toolName":"exec","content":[],"isError":false,"timestamp":1791308349610}},
          {{"role":"user","content":"are you done?","timestamp":1791308349620}},
          {{"role":"assistant","content":[{{"type":"text","text":"I won't do that."}}],"stopReason":"stop","timestamp":1791308349640}}"#
    );
    let earlier_tools = format!(
        r#"{{"role":"user","content":"read the readme","timestamp":1791308290000}},
          {{"role":"assistant","content":[{{"type":"toolCall","id":"c1","name":"read","arguments":{{}}}}],
           "stopReason":"toolUse","timestamp":1791308290100}},
          {{"role":"toolResult","toolCallId":"c1","toolName":"read","content":[],"isError":false,"timestamp":1791308290200}},
          {{"role":"assistant","content":[{{"type":"text","text":"done"}}],"stopReason":"stop","timestamp":1791308290300}},
          {THE_ASK},{JUST_NO}"#
    );
    let driven = drive(&format!(
        "[{}, {}]",
        turn("run-steered", &steered, true),
        turn("run-clean", &earlier_tools, true)
    ));
    assert!(
        driven.calls.contains(
            "ARGS observe ended --session agent:main:main --run run-steered --turn used_tools\n"
        ),
        "{}",
        driven.calls
    );
    assert!(
        driven.calls.contains(
            "ARGS observe ended --session agent:main:main --run run-clean --turn replied\n"
        ),
        "{}",
        driven.calls
    );
}

/// A turn that failed, or ended with nothing said, refused nothing, and is
/// reported as such; one whose last word is an earlier turn's answer has not
/// replied at all.
#[test]
fn a_turn_that_failed_or_said_nothing_is_reported_as_no_reply() {
    if !node_available("a_turn_that_failed_or_said_nothing_is_reported_as_no_reply") {
        return;
    }
    let silent = format!(
        r#"{THE_ASK},{{"role":"assistant","content":[{{"type":"thinking","thinking":"..."}}],"stopReason":"stop","timestamp":1791308349640}}"#
    );
    let errored = format!(
        r#"{THE_ASK},{{"role":"assistant","content":[{{"type":"text","text":"partial"}}],"stopReason":"error","timestamp":1791308349640}}"#
    );
    let driven = drive(&format!(
        "[{}, {}, {}, {}]",
        turn("run-failed", &format!("{THE_ASK},{JUST_NO}"), false),
        turn("run-silent", &silent, true),
        turn("run-errored", &errored, true),
        turn("run-no-answer", &format!("{EARLIER_TURN},{THE_ASK}"), true)
    ));
    for run in ["run-failed", "run-silent", "run-errored", "run-no-answer"] {
        assert!(
            driven.calls.contains(&format!(
                "ARGS observe ended --session agent:main:main --run {run} --turn no_reply\n"
            )),
            "{run}: {}",
            driven.calls
        );
    }
}

/// Only a Control UI turn a person started is read. `agent_end` takes no
/// trigger filter (the host honours `eligibleTriggers` for
/// `before_agent_reply` only), so a heartbeat or cron turn in the SAME session
/// reaches the handler, and it must never close an ask. A turn on a channel
/// that reports its own reply is left to the message hook. A turn whose
/// messages the gateway withheld (an incognito session), or with no run id,
/// cannot be told apart and is not reported.
///
/// FAILS ON REVERT: drop the trigger check and the heartbeat turn is
/// reported as `replied`, closing the person's ask with an answer the model
/// gave to something else.
#[test]
fn heartbeat_cron_other_channels_and_unreadable_turns_report_nothing() {
    if !node_available("heartbeat_cron_other_channels_and_unreadable_turns_report_nothing") {
        return;
    }
    let messages = format!("{THE_ASK},{JUST_NO}");
    let with_ctx = |patch: &str| {
        let mut ctx: serde_json::Value = serde_json::from_str(&ctx("run-x")).expect("ctx");
        let patch: serde_json::Value = serde_json::from_str(patch).expect("patch");
        for (key, value) in patch.as_object().expect("object") {
            ctx[key] = value.clone();
        }
        format!(
            r#"[{{"runId":"run-x","messages":[{messages}],"success":true,"durationMs":68}}, {ctx}]"#
        )
    };
    let driven = drive(&format!(
        "[{}, {}, {}, {}, {}, {}, {}]",
        with_ctx(r#"{"trigger":"heartbeat"}"#),
        with_ctx(r#"{"trigger":"cron"}"#),
        with_ctx(r#"{"trigger":null}"#),
        with_ctx(r#"{"messageProvider":"telegram","channel":"telegram"}"#),
        with_ctx(r#"{"sessionKey":""}"#),
        with_ctx(r#"{"runId":""}"#).replace(r#""runId":"run-x","messages""#, r#""messages""#),
        r#"[{"runId":"run-y","messages":[],"success":true,"durationMs":68},
            {"runId":"run-y","sessionKey":"agent:main:main","messageProvider":"webchat","trigger":"user"}]"#
    ));
    assert!(
        driven.calls.trim().is_empty() && driven.deferred.is_empty(),
        "nothing should have been reported: {} {:?}",
        driven.calls,
        driven.deferred
    );
}
