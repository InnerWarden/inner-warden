//! A change of what the guard refuses (`enforce`, `dry-run`, `agents
//! disconnect`, `agents connect --monitor`, a posture by name) leaves a
//! `guard.mode_changed` line in `guard-events.jsonl` and reaches the
//! configured channels. A switch run inside an AI agent's shell never
//! writes a line that refuses less over one with `--block-review`.
//!
//! Every run here uses a scratch home, so nothing touches a real
//! configuration.

use std::io::{Read, Write};
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

/// A home whose Claude Code runs the hook line `line`.
fn home_with(line: &str) -> tempfile::TempDir {
    let home = tempfile::TempDir::new().expect("scratch home");
    let claude = home.path().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    std::fs::write(
        claude.join("settings.json"),
        serde_json::json!({
            "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [
                { "type": "command", "command": line }
            ] } ] }
        })
        .to_string(),
    )
    .unwrap();
    home
}

fn path_without_codex() -> std::ffi::OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept = std::env::split_paths(&path)
        .filter(|dir| !dir.join("codex").exists() && !dir.join("codex.exe").exists());
    std::env::join_paths(kept).expect("folders split from PATH join back")
}

fn run(home: &Path, args: &[&str], marker: Option<&str>, notify: Option<&Path>) -> Output {
    let mut command = Command::new(bin());
    command
        .env("HOME", home)
        .env("IW_GRAPH_FILE", home.join("graph.json"))
        .env("INNERWARDEN_AGENT_URL", "off")
        .env(
            "IW_NOTIFY_CONFIG",
            notify.map_or_else(|| home.join("absent-notify.toml"), Path::to_path_buf),
        )
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

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The `guard.mode_changed` lines of the record under `home`.
fn mode_changes(home: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(home.join("guard-events.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|event| event["kind"] == "guard.mode_changed")
        .collect()
}

fn settings(home: &Path) -> String {
    std::fs::read_to_string(home.join(".claude/settings.json")).unwrap()
}

/// Every switch of mode or posture leaves one line in the record, naming
/// the command, the mode it set and whether an agent's shell ran it.
///
/// FAILS ON REVERT: take `record_mode_change` out of `cmd_mode` or out of
/// `agents_io::cmd` and the record holds no line for the switch.
#[test]
fn every_switch_of_mode_or_posture_is_recorded() {
    for (args, command, mode, posture) in [
        (&["dry-run", "--operator"][..], "dry-run", "monitor", None),
        (&["enforce"], "enforce", "enforce", None),
        (
            &["agents", "disconnect", "--operator", "--all"],
            "agents disconnect",
            "off",
            None,
        ),
        (
            &[
                "agents",
                "connect",
                "claude-code",
                "--monitor",
                "--operator",
            ],
            "agents connect",
            "monitor",
            None,
        ),
        (
            &["agents", "connect", "claude-code", "--guard", "--operator"],
            "agents connect",
            "enforce",
            Some("default"),
        ),
        (
            &["agents", "connect", "claude-code", "--strict"],
            "agents connect",
            "block-review",
            Some("strict"),
        ),
    ] {
        let home = home_with("innerwarden hook --agent claude-code");
        let out = run(home.path(), args, None, None);
        let changes = mode_changes(home.path());
        assert_eq!(changes.len(), 1, "{args:?}: {}\n{changes:?}", said(&out));
        let change = &changes[0];
        assert_eq!(change["command"], command, "{args:?}");
        assert_eq!(change["mode"], mode, "{args:?}");
        assert_eq!(change["posture"], serde_json::json!(posture), "{args:?}");
        assert_eq!(change["from_agent_shell"], false, "{args:?}");
        assert!(change["ts"].as_u64().is_some_and(|ts| ts > 0), "{args:?}");
    }
    // A connect that names no mode and no posture changes neither: no line.
    let home = home_with("innerwarden hook --agent claude-code");
    run(
        home.path(),
        &["agents", "connect", "claude-code"],
        None,
        None,
    );
    assert!(mode_changes(home.path()).is_empty());
    // Run inside an agent's shell, the line says so.
    let home = home_with("innerwarden hook --agent claude-code");
    run(home.path(), &["enforce"], Some("CLAUDECODE"), None);
    let changes = mode_changes(home.path());
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["from_agent_shell"], true);
}

/// A switch reaches the configured channel with words that say what
/// changed.
///
/// FAILS ON REVERT: take `fire_text` out of `record_mode_change` and the
/// channel gets nothing.
#[test]
fn a_switch_reaches_the_configured_channel() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the channel was never called"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("accepting the channel's request: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut body = Vec::new();
        let mut chunk = [0u8; 4096];
        while let Ok(n) = stream.read(&mut chunk) {
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n");
            if String::from_utf8_lossy(&body).contains("mode changed") {
                break;
            }
        }
        String::from_utf8_lossy(&body).into_owned()
    });
    let home = home_with("innerwarden hook --agent claude-code");
    let config = home.path().join("notify.toml");
    std::fs::write(
        &config,
        format!("slack_webhook = \"http://{address}/hook\"\n"),
    )
    .unwrap();
    let out = run(home.path(), &["dry-run", "--operator"], None, Some(&config));
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    let request = server.join().unwrap();
    assert!(
        request.contains("the guard's mode changed") && request.contains("innerwarden dry-run"),
        "{request}"
    );
}

/// Inside an AI agent's shell, `enforce`, a plain `agents connect` and a
/// plain `install` keep a line that also refuses `review`; the person's
/// `enforce` keeps it too.
///
/// FAILS ON REVERT: pass `false` for `strict` in `cmd_mode` again and
/// `enforce` writes the line without `--block-review`; take the kept flag
/// out of `agents_io::cmd` or `cmd_install` and the connect or the install
/// does.
#[test]
fn a_switch_from_an_agents_shell_keeps_block_review() {
    for (args, marker) in [
        (&["enforce"][..], Some("CLAUDECODE")),
        (&["enforce"], Some("CODEX_SANDBOX")),
        (&["enforce"], None),
        (&["agents", "connect", "claude-code"], Some("CLAUDECODE")),
        (&["agents", "connect", "--all"], Some("CLAUDECODE")),
        (&["install", "claude-code"], Some("CLAUDECODE")),
    ] {
        let home = home_with("innerwarden hook --block-review --agent claude-code");
        let out = run(home.path(), args, marker, None);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{args:?} {marker:?}: {}",
            said(&out)
        );
        let after = settings(home.path());
        assert!(
            after.contains("--block-review"),
            "{args:?} {marker:?} dropped --block-review:\n{after}\n{}",
            said(&out)
        );
    }
}

/// The person, from their own terminal, still takes `--block-review` off
/// with a plain connect, and a home with no such line is not raised by an
/// agent's `enforce`.
#[test]
fn the_person_still_lowers_it_and_nothing_is_raised_unasked() {
    let home = home_with("innerwarden hook --block-review --agent claude-code");
    let out = run(
        home.path(),
        &["agents", "connect", "claude-code"],
        None,
        None,
    );
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(
        !settings(home.path()).contains("--block-review"),
        "{}",
        said(&out)
    );

    let home = home_with("innerwarden hook --agent claude-code");
    let out = run(home.path(), &["enforce"], Some("CLAUDECODE"), None);
    assert_eq!(out.status.code(), Some(0), "{}", said(&out));
    assert!(
        !settings(home.path()).contains("--block-review"),
        "{}",
        said(&out)
    );
}

/// The same for an agent whose hook has a file of its own (Cursor,
/// Antigravity): a person connects it with `--strict`, and `enforce` or a
/// plain connect from an AI agent's shell keeps `--block-review` in its
/// file. Neither agent needs to be installed: the hook file is enough.
///
/// FAILS ON REVERT: read only Codex's and Gemini's files in
/// `agents_io::wiring_blocks_review` and the line loses the flag.
#[cfg(unix)]
#[test]
fn a_switch_keeps_block_review_in_an_agents_own_hook_file() {
    for (agent, folder, file) in [
        ("cursor", ".cursor", ".cursor/hooks.json"),
        (
            "antigravity",
            ".gemini/antigravity-cli",
            ".gemini/config/hooks.json",
        ),
    ] {
        for args in [
            &["enforce"][..],
            &["agents", "connect", agent],
            &["agents", "connect", "--all"],
        ] {
            let home = tempfile::TempDir::new().expect("scratch home");
            std::fs::create_dir_all(home.path().join(folder)).unwrap();
            let out = run(
                home.path(),
                &["agents", "connect", agent, "--strict"],
                None,
                None,
            );
            assert_eq!(out.status.code(), Some(0), "{agent}: {}", said(&out));
            let hooks = home.path().join(file);
            let before = std::fs::read_to_string(&hooks)
                .unwrap_or_else(|_| panic!("{agent}: the connect wrote no hook\n{}", said(&out)));
            assert!(before.contains("--block-review"), "{agent}: {before}");
            let out = run(home.path(), args, Some("CLAUDECODE"), None);
            let after = std::fs::read_to_string(&hooks).unwrap();
            assert!(
                after.contains("--block-review"),
                "{agent} {args:?} dropped --block-review:\n{after}\n{}",
                said(&out)
            );
        }
    }
}
