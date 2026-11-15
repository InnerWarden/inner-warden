//! End-to-end: the PreToolUse hook on an agent's file tools.
//!
//! These run the REAL binary the way Claude Code runs it: a JSON payload on
//! stdin, the verdict in the exit code (2 refuses, 0 lets the call run). HOME,
//! the record and the session store point into a scratch directory, so a run
//! never reads or writes the developer's own state.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        std::fs::create_dir_all(dir.path().join("home/proj/src")).expect("project");
        Self { dir }
    }

    fn home(&self) -> std::path::PathBuf {
        self.dir.path().join("home")
    }

    fn project(&self) -> std::path::PathBuf {
        self.home().join("proj")
    }

    /// Run the hook once with `payload`; the exit code and stderr.
    fn hook(&self, flags: &[&str], payload: &str) -> (Option<i32>, String) {
        self.hook_in(&self.project(), flags, payload)
    }

    /// [`Self::hook`], with the hook's own process started in `dir`.
    fn hook_in(
        &self,
        dir: &std::path::Path,
        flags: &[&str],
        payload: &str,
    ) -> (Option<i32>, String) {
        let mut child = Command::new(bin())
            .arg("hook")
            .args(flags)
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run innerwarden hook");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(payload.as_bytes())
            .expect("write stdin");
        let out = child.wait_with_output().expect("collect output");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn edit_payload(&self, tool: &str, path: &str) -> String {
        let key = if tool == "NotebookEdit" {
            "notebook_path"
        } else {
            "file_path"
        };
        serde_json::json!({
            "session_id": "s-file-tools",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": tool,
            "tool_input": { key: path, "old_string": "a", "new_string": "b", "content": "x" },
        })
        .to_string()
    }
}

fn record(host: &Host) -> String {
    std::fs::read_to_string(host.dir.path().join("graph.json")).unwrap_or_default()
}

/// The row's proof: an agent's `Edit` of its own settings is refused, with
/// the reason and who may make the change.
///
/// FAILS ON REVERT: drop `screen_file_tool` from `cmd_hook` and the edit
/// exits 0 as a call with no command.
#[test]
fn an_edit_of_the_agents_settings_is_refused() {
    let host = Host::new();
    let settings = host.home().join(".claude/settings.json");
    let (code, stderr) = host.hook(
        &["--agent", "claude-code"],
        &host.edit_payload("Edit", &settings.to_string_lossy()),
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("blocked this file change"), "{stderr}");
    assert!(stderr.contains("the guard's own configuration"), "{stderr}");
    assert!(stderr.contains("make this change yourself"), "{stderr}");
    assert!(
        record(&host).contains("privileged_file_write"),
        "a refusal is recorded"
    );
}

/// Every file tool, and the other privileged places, by the same rule.
#[test]
fn every_file_tool_is_held_to_the_privileged_list() {
    let host = Host::new();
    for (tool, path) in [
        ("Write", host.home().join(".bashrc")),
        (
            "MultiEdit",
            host.home().join(".config/innerwarden/suppress.toml"),
        ),
        ("NotebookEdit", host.home().join(".ssh/authorized_keys")),
        ("Write", host.home().join(".config/systemd/user/x.service")),
        ("Edit", host.project().join(".claude/settings.local.json")),
    ] {
        let (code, stderr) = host.hook(&[], &host.edit_payload(tool, &path.to_string_lossy()));
        assert_eq!(code, Some(2), "{tool} {}: {stderr}", path.display());
    }
}

/// The row's guard: an ordinary project edit stays silent. Exit 0, nothing
/// on stderr, and nothing written to the record.
#[test]
fn a_project_edit_is_silent() {
    let host = Host::new();
    for (tool, path) in [
        ("Edit", host.project().join("src/main.rs")),
        ("Write", host.project().join("README.md")),
        ("MultiEdit", host.project().join(".npmrc")),
        ("NotebookEdit", host.project().join("analysis.ipynb")),
    ] {
        let (code, stderr) = host.hook(&[], &host.edit_payload(tool, &path.to_string_lossy()));
        assert_eq!(code, Some(0), "{tool} {}: {stderr}", path.display());
        assert!(stderr.is_empty(), "{tool}: {stderr}");
    }
    assert!(
        !record(&host).contains("main.rs"),
        "a project edit is not recorded"
    );
}

/// Monitor never blocks: the refusal is recorded as one it would have made.
#[test]
fn monitor_records_the_file_change_and_lets_it_run() {
    let host = Host::new();
    let settings = host.home().join(".claude/settings.json");
    let (code, stderr) = host.hook(
        &["--monitor"],
        &host.edit_payload("Edit", &settings.to_string_lossy()),
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert!(record(&host).contains("privileged_file_write"));
}

/// A file tool call that names no file is refused rather than let through
/// unscreened, as a shell call with no command is.
#[test]
fn a_file_tool_call_with_no_path_is_refused_in_enforce() {
    let host = Host::new();
    let payload = r#"{"tool_name":"Edit","tool_input":{"old_string":"a","new_string":"b"}}"#;
    assert_eq!(host.hook(&[], payload).0, Some(2));
    assert_eq!(host.hook(&["--monitor"], payload).0, Some(1));
}

/// The Bash path is unchanged by the file-tools path in front of it.
#[test]
fn a_shell_command_is_still_screened_as_before() {
    let host = Host::new();
    let bash = |command: &str| {
        serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}}).to_string()
    };
    assert_eq!(host.hook(&[], &bash("ls -la")).0, Some(0));
    assert_eq!(host.hook(&[], &bash("rm -rf ~")).0, Some(2));
}

/// A tool call the way Gemini CLI sends it to a `BeforeTool` hook.
fn gemini_call(host: &Host, tool: &str, input: serde_json::Value) -> String {
    serde_json::json!({
        "session_id": "s-gemini",
        "hook_event_name": "BeforeTool",
        "cwd": host.project(),
        "tool_name": tool,
        "tool_input": input,
    })
    .to_string()
}

/// A patch the way Codex CLI sends it to a `PreToolUse` hook: the patch
/// text is the tool's `command`.
fn codex_patch(host: &Host, patch: &str) -> String {
    codex_patch_in(&host.project(), patch)
}

/// A patch's program reads a leading `~` as a folder named `~` under the
/// directory the call runs in. Run from the home, `~/../.bashrc` is the
/// home's own startup file, while the `~`-expanded reading is a file in the
/// folder above the home. From a project, `~/notes.txt` is no privileged file
/// in either reading.
///
/// FAILS ON REVERT: take the `literal` reading out of `screen_file_writes`
/// and only the `~`-expanded path is judged; `.bashrc` is held relative to
/// the home only (no rule names it wherever it is), so the patch from the
/// home passes.
#[test]
fn a_patch_path_under_a_literal_tilde_is_judged_where_the_patch_writes() {
    let host = Host::new();
    let from_home = "*** Begin Patch\n*** Add File: ~/../.bashrc\n+echo hi\n*** End Patch\n";
    let (code, stderr) = host.hook_in(
        &host.home(),
        &["--agent", "codex"],
        &codex_patch_in(&host.home(), from_home),
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(!stderr.trim().is_empty(), "a refusal must say why");

    let from_project = "*** Begin Patch\n*** Add File: ~/notes.txt\n+x\n*** End Patch\n";
    let (code, stderr) = host.hook(&["--agent", "codex"], &codex_patch(&host, from_project));
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
}

/// [`codex_patch`], for a call that runs in `cwd`.
fn codex_patch_in(cwd: &std::path::Path, patch: &str) -> String {
    serde_json::json!({
        "session_id": "s-codex",
        "turn_id": "t-1",
        "hook_event_name": "PreToolUse",
        "cwd": cwd,
        "tool_name": "apply_patch",
        "tool_input": {"command": patch},
        "tool_use_id": "call-1",
    })
    .to_string()
}

/// Gemini CLI's `write_file` and `replace` are held to the same list as
/// Claude Code's file tools, and a project edit through them stays silent.
///
/// FAILS ON REVERT: with the two names unknown to the file side, each call
/// carries no command and exits 0.
#[test]
fn geminis_file_tools_are_held_to_the_privileged_list() {
    let host = Host::new();
    let settings = host.home().join(".gemini/settings.json");
    let (code, stderr) = host.hook(
        &["--agent", "gemini"],
        &gemini_call(
            &host,
            "write_file",
            serde_json::json!({"file_path": settings, "content": "{}"}),
        ),
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(!stderr.trim().is_empty(), "a refusal must say why");

    let startup = host.home().join(".zshrc");
    let replace = |path: &std::path::Path| {
        gemini_call(
            &host,
            "replace",
            serde_json::json!({
                "file_path": path,
                "instruction": "i",
                "old_string": "a",
                "new_string": "b",
            }),
        )
    };
    assert_eq!(host.hook(&[], &replace(&startup)).0, Some(2));

    let (code, stderr) = host.hook(&[], &replace(&host.project().join("src/main.rs")));
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");

    let no_path = gemini_call(&host, "replace", serde_json::json!({"old_string": "a"}));
    assert_eq!(host.hook(&[], &no_path).0, Some(2));
    assert_eq!(host.hook(&["--monitor"], &no_path).0, Some(1));
}

/// A Codex patch is judged by every file it names, a relative one from the
/// directory the call runs in, and its text is never screened as shell.
///
/// FAILS ON REVERT: read as a shell line, the first patch is refused for the
/// line in its body; with the patch tool unknown to the file side, the
/// others carry no file path and are judged as shell text that names none.
#[test]
fn a_codex_patch_is_judged_by_the_files_it_names() {
    let host = Host::new();
    // An ordinary project patch whose body holds a line the shell side
    // refuses when it is run. Nothing runs it: it is the file's content.
    let (code, stderr) = host.hook(
        &["--agent", "codex"],
        &codex_patch(
            &host,
            "*** Begin Patch\n*** Update File: src/clean.sh\n@@\n rm -rf ~\n-echo a\n+echo b\n*** End Patch\n",
        ),
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");

    let hooks = host.home().join(".codex/hooks.json");
    for patch in [
        // Relative to the project, which sits in the home.
        "*** Begin Patch\n*** Add File: ../.zshrc\n+echo hi\n*** End Patch\n".to_string(),
        format!(
            "*** Begin Patch\n*** Delete File: {}\n*** End Patch\n",
            hooks.display()
        ),
        format!(
            "*** Begin Patch\n*** Update File: src/a.txt\n*** Move to: {}\n@@\n-a\n+b\n*** End Patch\n",
            hooks.display()
        ),
        // The privileged file is the second one named.
        "*** Begin Patch\n*** Add File: src/b.txt\n+x\n*** Update File: ~/.bashrc\n@@\n-a\n+b\n*** End Patch\n"
            .to_string(),
    ] {
        let (code, stderr) = host.hook(&["--agent", "codex"], &codex_patch(&host, &patch));
        assert_eq!(code, Some(2), "{patch}: {stderr}");
        assert!(!stderr.trim().is_empty(), "{patch}: a refusal must say why");
    }

    // A patch whose files cannot be read is refused, not let through.
    let empty = codex_patch(&host, "*** Begin Patch\n*** End Patch\n");
    assert_eq!(host.hook(&[], &empty).0, Some(2));
    assert_eq!(host.hook(&["--monitor"], &empty).0, Some(1));
}

/// A relative path in a patch is judged from the directory the payload names
/// for the call, wherever the hook's own process was started.
///
/// FAILS ON REVERT: take `hook_cwd(buf)` out of the `cwd` of
/// `screen_file_writes`, leaving the process's own directory, and the two
/// verdicts change places.
#[test]
fn a_patchs_relative_path_is_judged_from_the_payloads_directory() {
    let host = Host::new();
    let project = host.project();
    let src = project.join("src");
    let patch = "*** Begin Patch\n*** Add File: ../.zshrc\n+echo hi\n*** End Patch\n";

    // The call runs in the project, which sits in the home: the file is the
    // home's startup file. The hook's process runs one folder down.
    let (code, stderr) = host.hook_in(
        &src,
        &["--agent", "codex"],
        &codex_patch_in(&project, patch),
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(!stderr.trim().is_empty(), "a refusal must say why");

    // The call runs one folder down: the file is the project's own. The
    // hook's process runs in the project.
    let (code, stderr) = host.hook_in(
        &project,
        &["--agent", "codex"],
        &codex_patch_in(&src, patch),
    );
    assert_eq!(code, Some(0), "{stderr}");
    assert!(stderr.is_empty(), "{stderr}");
}

/// A shell call the way Codex CLI sends it to a `PreToolUse` hook.
fn codex_shell(host: &Host, command: &str) -> String {
    serde_json::json!({
        "session_id": "s-codex",
        "turn_id": "t-1",
        "hook_event_name": "PreToolUse",
        "cwd": host.project(),
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "tool_use_id": "call-1",
    })
    .to_string()
}

/// A patch handed to the patch program on a shell line is judged by the
/// files it names, as the patch tool's is: in a here-document or as the
/// program's argument, and in the folder the line changes to first; also
/// when quotes split the program's name, and when the patch is written for
/// another program to apply. One that names project files alone is left to
/// the shell rules, and one whose text is not in the command, or that a
/// program the hook does not follow starts, is refused as a call that
/// cannot be read.
///
/// FAILS ON REVERT: drop the call of `screen_shell_patch` from `cmd_hook`
/// and the refused lines exit 0, because the shell rules know no writer by
/// the patch program's name; the patch read from a file exits 0 with them.
#[test]
fn a_patch_run_from_the_shell_is_judged_by_the_files_it_names() {
    let host = Host::new();
    let hooks = host.home().join(".codex/hooks.json");
    for command in [
        format!(
            "apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: {}\n*** End Patch\nEOF\n",
            hooks.display()
        ),
        format!(
            "apply_patch '*** Begin Patch\n*** Delete File: {}\n*** End Patch'",
            hooks.display()
        ),
        // The file is named from the folder the line goes to first.
        "cd ~/.codex && apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: hooks.json\n@@\n-a\n+b\n*** End Patch\nEOF\n"
            .to_string(),
        // Relative to the project, which sits in the home.
        "cd .. && applypatch <<'EOF'\n*** Begin Patch\n*** Add File: .zshrc\n+echo hi\n*** End Patch\nEOF\n"
            .to_string(),
        // The privileged file is the second one named.
        "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: src/b.txt\n+x\n*** Update File: ~/.bashrc\n@@\n-a\n+b\n*** End Patch\nEOF\n"
            .to_string(),
    ] {
        let (code, stderr) = host.hook(&["--agent", "codex"], &codex_shell(&host, &command));
        assert_eq!(code, Some(2), "{command}: {stderr}");
        assert!(
            stderr.contains("blocked this file change"),
            "{command}: {stderr}"
        );
    }
    assert!(
        record(&host).contains("privileged_file_write"),
        "a refusal is recorded"
    );

    // The program named through quotes the shell takes out, and a patch
    // written for another program to apply later: each is refused where the
    // patch is written.
    for command in [
        format!(
            "appl''y_patch <<'EOF'\n*** Begin Patch\n*** Delete File: {}\n*** End Patch\nEOF\n",
            hooks.display()
        ),
        format!(
            "cat > /tmp/p.patch <<'EOF'\n*** Begin Patch\n*** Delete File: {}\n*** End Patch\nEOF\n",
            hooks.display()
        ),
    ] {
        let (code, stderr) = host.hook(&["--agent", "codex"], &codex_shell(&host, &command));
        assert_eq!(code, Some(2), "{command}: {stderr}");
        assert!(
            stderr.contains("blocked this file change"),
            "{command}: {stderr}"
        );
    }
    // Started by a program whose input is not read here.
    let (code, stderr) = host.hook(
        &["--agent", "codex"],
        &codex_shell(&host, "ls *.patch | xargs -n1 apply_patch"),
    );
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("could not read this tool call"), "{stderr}");

    // An ordinary project patch is not refused for the way it is given.
    let project = codex_shell(
        &host,
        "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: notes.md\n+hello\n*** End Patch\nEOF\n",
    );
    let (code, stderr) = host.hook(&["--agent", "codex"], &project);
    assert_eq!(code, Some(0), "{stderr}");

    // The text of this patch is in a file the hook does not read.
    let from_a_file = codex_shell(&host, "apply_patch < /tmp/change.patch");
    let (code, stderr) = host.hook(&["--agent", "codex"], &from_a_file);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("could not read this tool call"), "{stderr}");
    assert_eq!(host.hook(&["--monitor"], &from_a_file).0, Some(1));

    // A line that names the program and does not run it is a shell line
    // like any other.
    let (code, stderr) = host.hook(&[], &codex_shell(&host, "grep -rn apply_patch src/"));
    assert_eq!(code, Some(0), "{stderr}");
}

/// A path too long to read is not passed for an ordinary file: `./` repeated
/// in it puts any file past the length that is read. The call is refused as
/// one that cannot be read, and monitor says so and lets it run.
///
/// FAILS ON REVERT: answer `None` for a path over `MAX_PATH_BYTES` in
/// `privileged_file_write` and the write exits 0; drop the test of
/// `PATH_TOO_LONG` from `screen_file_writes` and monitor exits 0, with the
/// call recorded as a change to a file the guard holds.
#[test]
fn a_path_too_long_to_read_is_refused_as_unreadable() {
    let host = Host::new();
    let padded = format!(
        "{}/{}.gemini/settings.json",
        host.home().display(),
        "./".repeat(2100)
    );
    let write = gemini_call(
        &host,
        "write_file",
        serde_json::json!({"file_path": padded, "content": "{}"}),
    );
    let (code, stderr) = host.hook(&["--agent", "gemini"], &write);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("a path too long to be read"), "{stderr}");
    assert_eq!(host.hook(&["--monitor"], &write).0, Some(1));
}

/// Gemini CLI's shell tool is screened like any other shell tool.
#[test]
fn geminis_shell_tool_is_screened() {
    let host = Host::new();
    let shell = |command: &str| {
        gemini_call(
            &host,
            "run_shell_command",
            serde_json::json!({"command": command, "description": "d"}),
        )
    };
    assert_eq!(host.hook(&[], &shell("ls -la")).0, Some(0));
    assert_eq!(host.hook(&[], &shell("rm -rf ~")).0, Some(2));
    let no_command = gemini_call(
        &host,
        "run_shell_command",
        serde_json::json!({"description": "d"}),
    );
    assert_eq!(host.hook(&[], &no_command).0, Some(2));
}

/// Gemini CLI's shell tool can name the folder its command runs in
/// (`dir_path`, `directory` before it). The command is judged there: a
/// relative removal of Gemini's settings is refused like the one that names
/// the file in full, ordinary work in a named folder runs, and a folder that
/// cannot be read is refused in enforce and said in monitor.
///
/// FAILS ON REVERT: answer `HookInput::Command(command.to_string())` for
/// `CommandDir::Named` in `classify_hook_input` and the three removals exit
/// 0, because the line alone names no file the guard holds.
#[test]
fn geminis_shell_call_is_judged_in_the_folder_it_names() {
    let host = Host::new();
    // The `cwd` is written out so the join reads the same on every system.
    let shell = |input: serde_json::Value| {
        serde_json::json!({
            "session_id": "s-gemini",
            "hook_event_name": "BeforeTool",
            "cwd": "/work/app",
            "tool_name": "run_shell_command",
            "tool_input": input,
        })
        .to_string()
    };
    for input in [
        serde_json::json!({"command": "rm settings.json", "dir_path": "../.gemini"}),
        serde_json::json!({"command": "rm settings.json", "directory": "../.gemini"}),
        serde_json::json!({"command": "rm settings.json", "dir_path": "/home/dev/.gemini"}),
    ] {
        let payload = shell(input);
        let (code, stderr) = host.hook(&["--agent", "gemini"], &payload);
        assert_eq!(code, Some(2), "{payload}: {stderr}");
        assert!(
            !stderr.trim().is_empty(),
            "{payload}: a refusal must say why"
        );
    }

    for input in [
        serde_json::json!({"command": "ls -la", "dir_path": "src"}),
        serde_json::json!({"command": "rm settings.json", "dir_path": "config"}),
    ] {
        let payload = shell(input);
        let (code, stderr) = host.hook(&["--agent", "gemini"], &payload);
        assert_eq!(code, Some(0), "{payload}: {stderr}");
    }

    let unreadable = shell(serde_json::json!({"command": "ls -la", "dir_path": 7}));
    let (code, stderr) = host.hook(&[], &unreadable);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(!stderr.trim().is_empty(), "a refusal must say why");
    assert_eq!(host.hook(&["--monitor"], &unreadable).0, Some(1));
}

/// Claude Code, Codex CLI and Gemini CLI all run the tool when a hook exits
/// 2 with nothing on stderr. So every refusal says why, whichever agent's
/// shape the call came in.
///
/// The refusals not reached from here hold the same line in their own
/// tests: the hook's deadline (`hook_answers_or_refuses.rs`), a panic while
/// screening (`a_panic_while_screening_refuses_the_call`) and a profiles
/// file that cannot be used (`hook_profiles.rs`).
///
/// FAILS ON REVERT: drop the line printed before any `ExitCode::from(2)`
/// below and that call's stderr is empty.
#[test]
fn every_refusal_says_why_on_stderr() {
    let host = Host::new();
    let settings = host.home().join(".claude/settings.json");
    let calls: Vec<(&str, String)> = vec![
        ("empty stdin", String::new()),
        ("not JSON", "garbage".to_string()),
        (
            "a shell call with no command",
            r#"{"tool_name":"Bash","tool_input":{}}"#.to_string(),
        ),
        (
            "a refused shell command",
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "rm -rf ~"}})
                .to_string(),
        ),
        (
            "a refused Claude Code edit",
            host.edit_payload("Edit", &settings.to_string_lossy()),
        ),
        (
            "a Claude Code edit with no path",
            r#"{"tool_name":"Edit","tool_input":{"old_string":"a"}}"#.to_string(),
        ),
        (
            "a refused Gemini shell command",
            gemini_call(
                &host,
                "run_shell_command",
                serde_json::json!({"command": "rm -rf ~"}),
            ),
        ),
        (
            "a Gemini shell call with no command",
            gemini_call(&host, "run_shell_command", serde_json::json!({})),
        ),
        (
            "a refused Gemini write",
            gemini_call(
                &host,
                "write_file",
                serde_json::json!({"file_path": "~/.gemini/settings.json", "content": "{}"}),
            ),
        ),
        (
            "a Gemini write with no path",
            gemini_call(&host, "write_file", serde_json::json!({"content": "x"})),
        ),
        (
            "a refused Codex patch",
            codex_patch(
                &host,
                "*** Begin Patch\n*** Delete File: ~/.codex/hooks.json\n*** End Patch\n",
            ),
        ),
        (
            "a Codex patch that names no file",
            codex_patch(&host, "*** Begin Patch\n*** End Patch\n"),
        ),
        (
            "a Codex patch with no text",
            r#"{"tool_name":"apply_patch","tool_input":{}}"#.to_string(),
        ),
        (
            "a refused patch run from the shell",
            codex_shell(
                &host,
                "apply_patch <<'EOF'\n*** Begin Patch\n*** Delete File: ~/.codex/hooks.json\n*** End Patch\nEOF\n",
            ),
        ),
        (
            "a patch run from the shell that cannot be read",
            codex_shell(&host, "cat /tmp/change.patch | apply_patch"),
        ),
        (
            "a Gemini write to a path too long to read",
            gemini_call(
                &host,
                "write_file",
                serde_json::json!({
                    "file_path": format!("~/{}.gemini/settings.json", "./".repeat(2100)),
                    "content": "{}",
                }),
            ),
        ),
    ];
    for (what, payload) in &calls {
        let (code, stderr) = host.hook(&[], payload);
        assert_eq!(code, Some(2), "{what}: {stderr}");
        assert!(
            !stderr.trim().is_empty(),
            "{what}: exit 2 with nothing on stderr runs the tool"
        );
    }
}

fn percentile(sorted: &[u128], pct: usize) -> u128 {
    let at = (sorted.len() * pct).div_ceil(100).saturating_sub(1);
    sorted[at.min(sorted.len() - 1)]
}

/// Wall time of the hook process, p50 and p95 over `runs`, in microseconds.
fn measure(host: &Host, payload: &str, runs: usize) -> (u128, u128) {
    // One warm-up run, so the first page-in of the binary is not counted.
    let _ = host.hook(&[], payload);
    let mut times: Vec<u128> = (0..runs)
        .map(|_| {
            let start = Instant::now();
            let _ = host.hook(&[], payload);
            start.elapsed().as_micros()
        })
        .collect();
    times.sort_unstable();
    (percentile(&times, 50), percentile(&times, 95))
}

/// Not a budget: a measurement, printed for the change log. Run it on the
/// build box in release (`cargo test --release -p innerwarden --test
/// hook_file_tools -- --ignored --nocapture`).
#[test]
#[ignore]
fn measure_hook_latency() {
    let host = Host::new();
    let bash = serde_json::json!({
        "session_id": "s-latency",
        "hook_event_name": "PreToolUse",
        "cwd": host.project(),
        "tool_name": "Bash",
        "tool_input": {"command": "ls -la src"},
    })
    .to_string();
    let bash_names_verb = serde_json::json!({
        "session_id": "s-latency",
        "hook_event_name": "PreToolUse",
        "cwd": host.project(),
        "tool_name": "Bash",
        "tool_input": {"command": "grep -rn 'innerwarden mute' docs/ | head -5"},
    })
    .to_string();
    let edit_project = host.edit_payload(
        "Edit",
        &host.project().join("src/main.rs").to_string_lossy(),
    );
    let edit_settings = host.edit_payload(
        "Edit",
        &host.home().join(".claude/settings.json").to_string_lossy(),
    );
    for (name, payload) in [
        ("Bash ls -la", &bash),
        ("Bash grep naming a guard verb", &bash_names_verb),
        ("Edit project file", &edit_project),
        ("Edit ~/.claude/settings.json", &edit_settings),
    ] {
        let (p50, p95) = measure(&host, payload, 200);
        println!("hook latency {name}: p50 {p50} us, p95 {p95} us");
    }
}
