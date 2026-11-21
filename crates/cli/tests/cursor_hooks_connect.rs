//! `agents connect cursor` wires Cursor's own hooks beside the MCP proxy,
//! `agents disconnect cursor` takes out only what it wrote, and `agents`
//! and `status` say what is screened. Drives the real binary over a
//! disposable HOME.

use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::{json, Value};

mod fork_safe;
use fork_safe::{copy_the_binary, spawn_without_racing_a_copy};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// The suite's PATH less every folder that holds a `codex`: a connect asks
/// the Codex it finds to trust a hook, and a test never starts the real one.
fn path_without_codex() -> std::ffi::OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept = std::env::split_paths(&path)
        .filter(|dir| !dir.join("codex").exists() && !dir.join("codex.exe").exists());
    std::env::join_paths(kept).expect("folders split from PATH join back")
}

/// The binary with `args`, over `home`, as the person (not from inside an
/// agent's shell, where disconnect is refused).
fn run(home: &Path, args: &[&str]) -> Output {
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

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A home where Cursor has run, with a hook of the person's own and an
/// edit hook the guard has nothing to do with.
fn a_cursor_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("home");
    std::fs::create_dir_all(home.path().join(".cursor")).expect("cursor dir");
    std::fs::write(
        home.path().join(".cursor/mcp.json"),
        "{\"mcpServers\":{}}\n",
    )
    .expect("mcp.json");
    std::fs::write(home.path().join(".cursor/hooks.json"), theirs().to_string())
        .expect("hooks.json");
    home
}

fn theirs() -> Value {
    json!({
        "version": 1,
        "hooks": {
            "beforeShellExecution": [{"command": "./hooks/audit.sh"}],
            "afterFileEdit": [{"command": "./hooks/format.sh"}]
        }
    })
}

fn hooks_file(home: &Path) -> Value {
    let text = std::fs::read_to_string(home.join(".cursor/hooks.json")).expect("hooks.json");
    serde_json::from_str(&text).expect("hooks.json is JSON")
}

/// The guard's entries under `event`.
fn ours(file: &Value, event: &str) -> Vec<Value> {
    file["hooks"][event]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|hook| {
            hook["command"]
                .as_str()
                .is_some_and(|c| c.contains(" hook ") && c.contains("--agent cursor"))
        })
        .cloned()
        .collect()
}

const EVENTS: [&str; 3] = [
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
];

/// Connect writes one entry under each of the three events, fail closed in
/// enforce mode, after the person's own hook; a second connect writes
/// nothing; `agents` and `status` say Cursor is screened and what by; and
/// disconnect leaves the file as the person had it.
///
/// FAILS ON REVERT: take `CURSOR` out of `agent_hooks::spec_for` and the
/// connect writes no hook (only the proxy step runs).
#[cfg(unix)]
#[test]
fn connect_writes_cursors_hooks_and_disconnect_takes_out_only_ours() {
    let home = a_cursor_home();
    let out = run(home.path(), &["agents", "connect", "cursor"]);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(0), "{said}");
    assert!(
        said.contains("cursor - connected (beforeShellExecution hook)"),
        "{said}"
    );
    let file = hooks_file(home.path());
    assert_eq!(file["version"], 1);
    for event in EVENTS {
        let mine = ours(&file, event);
        assert_eq!(mine.len(), 1, "{event}: {file}");
        assert_eq!(mine[0]["failClosed"], true, "{event}");
        assert_eq!(mine[0]["timeout"], 60, "{event}");
    }
    assert_eq!(
        file["hooks"]["beforeShellExecution"][0]["command"], "./hooks/audit.sh",
        "the person's hook stays first: {file}"
    );
    assert_eq!(
        file["hooks"]["afterFileEdit"],
        theirs()["hooks"]["afterFileEdit"]
    );

    let before = std::fs::read(home.path().join(".cursor/hooks.json")).unwrap();
    let again = text(&run(home.path(), &["agents", "connect", "cursor"]));
    assert!(again.contains("cursor - already guarded"), "{again}");
    assert_eq!(
        std::fs::read(home.path().join(".cursor/hooks.json")).unwrap(),
        before,
        "a second connect writes nothing"
    );

    let listed = text(&run(home.path(), &["agents"]));
    let row = listed
        .lines()
        .find(|line| line.trim_start().starts_with("cursor"))
        .unwrap_or_else(|| panic!("no cursor row: {listed}"));
    assert!(row.contains("guarded (hook, enforce)"), "{row}");

    let status = text(&run(home.path(), &["status"]));
    assert!(
        status.contains("cursor: judged before they run: shell commands (`beforeShellExecution`)"),
        "{status}"
    );
    assert!(
        status.contains("Not screened: the agent's own file edits"),
        "{status}"
    );

    let out = run(home.path(), &["agents", "disconnect", "cursor"]);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(0), "{said}");
    assert!(said.contains("cursor, disconnected"), "{said}");
    assert_eq!(hooks_file(home.path()), theirs(), "only ours came out");
}

/// `--monitor` writes the entries with `failClosed: false` and the monitor
/// line; the listing says monitor.
#[cfg(unix)]
#[test]
fn monitor_writes_entries_that_never_refuse() {
    let home = a_cursor_home();
    let out = run(home.path(), &["agents", "connect", "cursor", "--monitor"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let file = hooks_file(home.path());
    for event in EVENTS {
        let mine = ours(&file, event);
        assert_eq!(mine.len(), 1, "{event}: {file}");
        assert_eq!(mine[0]["failClosed"], false, "{event}");
        assert!(
            mine[0]["command"]
                .as_str()
                .unwrap()
                .contains("hook --monitor --agent cursor"),
            "{event}: {file}"
        );
    }
    let listed = text(&run(home.path(), &["agents"]));
    assert!(listed.contains("guarded (hook, monitor)"), "{listed}");
}

/// One event without the guard's entry leaves that kind of call unscreened,
/// so Cursor is not reported guarded, and `agents` says the hook is not the
/// entry connect writes; connect puts it back.
#[cfg(unix)]
#[test]
fn a_missing_event_is_not_reported_as_guarded() {
    let home = a_cursor_home();
    run(home.path(), &["agents", "connect", "cursor"]);
    let mut file = hooks_file(home.path());
    file["hooks"]
        .as_object_mut()
        .unwrap()
        .remove("beforeReadFile");
    std::fs::write(home.path().join(".cursor/hooks.json"), file.to_string()).unwrap();

    let listed = text(&run(home.path(), &["agents"]));
    let row = listed
        .lines()
        .find(|line| line.trim_start().starts_with("cursor"))
        .unwrap_or_else(|| panic!("no cursor row: {listed}"));
    assert!(!row.contains("✓ guarded"), "{listed}");
    assert!(
        listed.contains("not the entry `agents connect` writes"),
        "{listed}"
    );

    run(home.path(), &["agents", "connect", "cursor"]);
    assert_eq!(ours(&hooks_file(home.path()), "beforeReadFile").len(), 1);
}

/// An edit that keeps every entry in the shape connect writes and points it
/// at another program: that program answers every Cursor call and the guard
/// never runs, so `agents` and `status` say so. An edit that takes every
/// entry out while Cursor's MCP servers still run behind the guard: `status`
/// says the hooks are not in the file. (With no MCP server behind the proxy
/// and no hook left, nothing on the machine says Cursor was ever connected.)
///
/// FAILS ON REVERT of `cursor_runs_this` in `agent_hooks::state`: the
/// pointed-away hook reads "guarded (hook, enforce)".
#[cfg(unix)]
#[test]
fn a_hook_pointed_at_another_program_or_removed_is_said() {
    use std::os::unix::fs::PermissionsExt;
    let home = a_cursor_home();
    std::fs::write(
        home.path().join(".cursor/mcp.json"),
        r#"{"mcpServers":{"files":{"command":"npx","args":["files-server"]}}}"#,
    )
    .unwrap();
    run(home.path(), &["agents", "connect", "cursor"]);
    let other = home.path().join("elsewhere/innerwarden");
    std::fs::create_dir_all(other.parent().unwrap()).unwrap();
    std::fs::write(&other, "#!/bin/sh\necho '{\"permission\":\"allow\"}'\n").unwrap();
    std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut file = hooks_file(home.path());
    for (_, list) in file["hooks"].as_object_mut().unwrap() {
        for entry in list.as_array_mut().unwrap() {
            let command = entry["command"].as_str().unwrap_or_default().to_string();
            if command.contains(bin()) {
                entry["command"] = json!(command.replace(bin(), &other.display().to_string()));
            }
        }
    }
    std::fs::write(home.path().join(".cursor/hooks.json"), file.to_string()).unwrap();

    let listed = text(&run(home.path(), &["agents"]));
    assert!(!listed.contains("guarded (hook, enforce)"), "{listed}");
    assert!(listed.contains("runs another program"), "{listed}");
    let status = text(&run(home.path(), &["status"]));
    assert!(status.contains("runs another program"), "{status}");
    assert!(status.contains(&other.display().to_string()), "{status}");

    std::fs::write(home.path().join(".cursor/hooks.json"), theirs().to_string()).unwrap();
    let status = text(&run(home.path(), &["status"]));
    assert!(
        status.contains("hooks are not in ~/.cursor/hooks.json"),
        "{status}"
    );
}

/// `innerwarden uninstall` takes Cursor's hooks out before the binary goes:
/// an enforcing entry that names a program that is gone refuses every call
/// Cursor's agent makes.
///
/// FAILS ON REVERT: take `CURSOR` out of `agent_hooks::left_behind` and of
/// `spec_for`, and the file keeps the hook after the binary is gone.
#[cfg(unix)]
#[test]
fn uninstall_takes_cursors_hooks_out_before_the_binary() {
    let home = a_cursor_home();
    let dir = home.path().join(".local/bin");
    std::fs::create_dir_all(&dir).expect("bin dir");
    let exe = dir.join(Path::new(bin()).file_name().expect("a name"));
    copy_the_binary(Path::new(bin()), &exe);
    let as_person = |args: &[&str]| {
        let mut cmd = Command::new(&exe);
        cmd.args(args)
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
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
        ] {
            cmd.env_remove(marker);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        spawn_without_racing_a_copy(&mut cmd)
            .wait_with_output()
            .expect("run the copy")
    };
    let connected = text(&as_person(&["agents", "connect", "cursor"]));
    assert_eq!(
        ours(&hooks_file(home.path()), "beforeShellExecution").len(),
        1,
        "the connect wrote no hook, so the rest proves nothing: {connected}"
    );
    let out = as_person(&["uninstall"]);
    let said = text(&out);
    assert_eq!(out.status.code(), Some(0), "{said}");
    assert!(!exe.exists(), "the binary must be gone: {said}");
    assert_eq!(hooks_file(home.path()), theirs(), "{said}");
}
