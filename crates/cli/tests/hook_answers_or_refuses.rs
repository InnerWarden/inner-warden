//! End-to-end: a hook that gives no answer.
//!
//! An agent blocks a tool call only on exit 2. A hook it has to kill at its
//! own timeout reads as a hook that failed, and the call runs unscreened. So
//! the hook ends itself first, with the answer a call it could not read gets:
//! 2 in enforce, 1 in monitor.
//!
//! Drives the REAL binary over a disposable HOME, the way an agent runs it.

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Far past any end the hook gives itself: a hook still alive here hangs.
const GIVE_UP: Duration = Duration::from_secs(30);

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        std::fs::create_dir_all(dir.path().join("home/proj/src")).expect("project");
        Self { dir }
    }

    fn hook(&self, flags: &[&str]) -> Command {
        let home = self.dir.path().join("home");
        let mut command = Command::new(env!("CARGO_BIN_EXE_innerwarden"));
        command
            .arg("hook")
            .args(flags)
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .env_remove("INNERWARDEN_HOOK_DEADLINE_MS")
            .current_dir(home.join("proj"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

/// Wait for `child` to end by itself; its exit code and stderr.
fn ended(child: Child, what: &str) -> (Option<i32>, String) {
    let (code, _, said) = ended_with_stdout(child, what);
    (code, said)
}

/// [`ended`], with what the hook wrote to stdout too.
fn ended_with_stdout(mut child: Child, what: &str) -> (Option<i32>, String, String) {
    let started = Instant::now();
    loop {
        if child.try_wait().expect("wait").is_some() {
            break;
        }
        if started.elapsed() > GIVE_UP {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what}: the hook was still running after {GIVE_UP:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("collect output");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A caller that sends a payload and never closes stdin gets the refusal at
/// the hook's deadline: 2 in enforce, 1 and a loud line in monitor.
///
/// FAILS ON REVERT: with no deadline armed before stdin is read, the hook
/// waits for the end of stdin until this test gives up on it.
#[test]
fn a_hook_whose_caller_never_closes_stdin_refuses_the_call() {
    for (flags, expected, says) in [
        (
            &[][..],
            2,
            "refusing it rather than letting it run unscreened",
        ),
        (&["--monitor"][..], 1, "it was NOT screened"),
    ] {
        let host = Host::new();
        let mut child = host
            .hook(flags)
            .env("INNERWARDEN_HOOK_DEADLINE_MS", "300")
            .spawn()
            .expect("run innerwarden hook");
        // Held open until the hook is gone: the payload is whole, its end
        // never comes.
        let mut stdin = child.stdin.take().expect("stdin");
        stdin
            .write_all(br#"{"tool_name":"Bash","tool_input":{"command":"ls -la src"}}"#)
            .expect("write stdin");
        stdin.flush().expect("flush stdin");
        let (code, said) = ended(child, "stdin held open");
        drop(stdin);
        assert_eq!(code, Some(expected), "{flags:?}: {said}");
        assert!(said.contains("did not finish in time"), "{flags:?}: {said}");
        assert!(said.contains(says), "{flags:?}: {said}");
    }
}

/// A tool call longer than the 1 MiB the hook reads is not read and is never
/// let through quietly: refused in enforce (2), said to have gone unscreened
/// in monitor (1). One just under the cap is answered as any other. The
/// caller keeps sending past the cap; the hook does not wait for the end.
///
/// FAILS ON REVERT: with stdin read whole, the long call is judged as `ls`
/// and allowed (0).
#[test]
fn a_tool_call_past_the_cap_is_not_read_and_not_allowed() {
    const CAP: usize = 1024 * 1024;
    let payload = |len: usize| {
        let bare =
            serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "ls", "pad": ""}})
                .to_string();
        let pad = "a".repeat(len - bare.len());
        serde_json::json!({"tool_name": "Bash", "tool_input": {"command": "ls", "pad": pad}})
            .to_string()
    };
    let run = |flags: &[&str], body: String| {
        let host = Host::new();
        let mut child = host.hook(flags).spawn().expect("run innerwarden hook");
        let mut stdin = child.stdin.take().expect("stdin");
        // Its own thread: a hook that stops reading at the cap leaves this
        // write with nowhere to go, and it then fails, which is fine.
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(body.as_bytes());
        });
        let out = ended(child, "long call");
        let _ = writer.join();
        out
    };
    assert_eq!(payload(CAP).len(), CAP);
    let (code, said) = run(&[], payload(CAP));
    assert_eq!(code, Some(0), "just at the cap: {said}");
    for (flags, expected, says) in [
        (
            &[][..],
            2,
            "refusing it rather than letting it run unscreened",
        ),
        (&["--monitor"][..], 1, "it was NOT screened"),
    ] {
        for len in [CAP + 1, 4 * CAP] {
            let (code, said) = run(flags, payload(len));
            assert_eq!(code, Some(expected), "{flags:?} {len}: {said}");
            assert!(
                said.contains("longer than the 1 MiB the hook reads"),
                "{said}"
            );
            assert!(said.contains(says), "{flags:?}: {said}");
        }
    }
}

/// With the net armed, a call the hook reads in time gets the answer it got
/// before: an everyday command runs (0, nothing said), a destructive one is
/// refused by the rule that names it, not by the net.
///
/// FAILS ON REVERT: a net that ends the hook before the screening answers
/// turns the first into a refusal and the second into the net's own line.
#[test]
fn a_call_the_hook_reads_in_time_is_answered_as_before() {
    let run = |command: &str| {
        let host = Host::new();
        let mut child = host.hook(&[]).spawn().expect("run innerwarden hook");
        let payload = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": command}});
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.to_string().as_bytes())
            .expect("write stdin");
        ended(child, command)
    };

    let (code, said) = run("ls -la src");
    assert_eq!(code, Some(0), "{said}");
    assert!(!said.contains("InnerWarden hook:"), "{said}");

    let (code, said) = run("rm -rf /");
    assert_eq!(code, Some(2), "{said}");
    assert!(!said.contains("did not finish in time"), "{said}");
    assert!(!said.contains("a fault stopped"), "{said}");
}

/// A tool call past the cap that already ran (PostToolUse) is not refused:
/// a large file read, edited or written, or a command with a long output,
/// has nothing left to stop, so the hook says it recorded it not read whole
/// and exits 0, in enforce and in monitor. The same call about to run
/// (PreToolUse) is refused as before, and so is one whose event is not in
/// the part read, or one that only carries the words of a PostToolUse inside
/// what it writes.
///
/// FAILS ON REVERT of `hook_too_long`: every PostToolUse below is refused (2).
#[test]
fn a_tool_result_past_the_cap_is_recorded_not_refused() {
    const BIG: usize = 2 * 1024 * 1024;
    let big = "a".repeat(BIG);
    let quoted = |s: &str| serde_json::Value::from(s).to_string();
    // Claude Code's own order: the event and the tool before what they carry.
    let call = |event: &str, tool: &str, input: String, response: String| {
        format!(
            r#"{{"session_id":"s-big","transcript_path":"/t.jsonl","cwd":"/p","permission_mode":"default","hook_event_name":{},"tool_name":{},"tool_input":{input},"tool_response":{response}}}"#,
            quoted(event),
            quoted(tool),
        )
    };
    let path = "/home/u/proj/src/threats.rs";
    let calls: Vec<(&str, String, String)> = vec![
        (
            "Read",
            format!(r#"{{"file_path":{}}}"#, quoted(path)),
            format!(
                r#"{{"type":"text","file":{{"filePath":{},"content":{}}}}}"#,
                quoted(path),
                quoted(&big)
            ),
        ),
        (
            "Edit",
            format!(
                r#"{{"file_path":{},"old_string":{},"new_string":"b"}}"#,
                quoted(path),
                quoted(&big)
            ),
            r#"{"filePath":"x"}"#.to_string(),
        ),
        (
            "MultiEdit",
            format!(
                r#"{{"file_path":{},"edits":[{{"old_string":{},"new_string":"b"}}]}}"#,
                quoted(path),
                quoted(&big)
            ),
            r#"{"filePath":"x"}"#.to_string(),
        ),
        (
            "Write",
            format!(
                r#"{{"file_path":{},"content":{}}}"#,
                quoted(path),
                quoted(&big)
            ),
            r#"{"type":"update"}"#.to_string(),
        ),
        (
            "NotebookEdit",
            format!(
                r#"{{"notebook_path":"/home/u/proj/n.ipynb","new_source":{}}}"#,
                quoted(&big)
            ),
            "{}".to_string(),
        ),
        (
            "Grep",
            r#"{"pattern":"fn ","path":"/home/u/proj"}"#.to_string(),
            format!(r#"{{"content":{}}}"#, quoted(&big)),
        ),
        (
            "Glob",
            r#"{"pattern":"**/*","path":"/home/u/proj"}"#.to_string(),
            format!(r#"{{"filenames":[{}]}}"#, quoted(&big)),
        ),
        (
            "Bash",
            r#"{"command":"cat src/threats.rs"}"#.to_string(),
            format!(r#"{{"stdout":{},"stderr":""}}"#, quoted(&big)),
        ),
    ];
    let run = |flags: &[&str], body: String| {
        let host = Host::new();
        let mut child = host.hook(flags).spawn().expect("run innerwarden hook");
        let mut stdin = child.stdin.take().expect("stdin");
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(body.as_bytes());
        });
        let out = ended(child, "long call");
        let _ = writer.join();
        out
    };
    for (tool, input, response) in &calls {
        let after = call("PostToolUse", tool, input.clone(), response.clone());
        assert!(after.len() > BIG, "{tool}: {}", after.len());
        for flags in [&[][..], &["--monitor"][..]] {
            let (code, said) = run(flags, after.clone());
            assert_eq!(code, Some(0), "{tool} {flags:?}: {said}");
            assert!(said.contains("not read whole"), "{tool}: {said}");
            assert!(said.contains(tool), "{tool}: {said}");
        }
        // The same call, as one about to run: still past the cap. A file
        // change is judged by its path and asks the person
        // (`a_large_file_write_is_judged_by_its_path`); any other call is
        // refused as one not read.
        let before = call("PreToolUse", tool, input.clone(), response.clone());
        let (code, said) = run(&[], before);
        if ["Edit", "MultiEdit", "Write", "NotebookEdit"].contains(tool) {
            assert_eq!(code, Some(0), "{tool} PreToolUse: {said}");
            assert!(!said.contains("not read whole"), "{tool}: {said}");
        } else {
            assert_eq!(code, Some(2), "{tool} PreToolUse: {said}");
            assert!(
                said.contains("longer than the 1 MiB the hook reads"),
                "{said}"
            );
        }
    }
    // The path of a file tool is named in what the hook says.
    let (_, said) = run(
        &[],
        call(
            "PostToolUse",
            "Read",
            calls[0].1.clone(),
            calls[0].2.clone(),
        ),
    );
    assert!(said.contains(path), "{said}");
    // The event only after what the call carries: not read, so the call is
    // not taken for a result. Its path is judged, and the person is asked.
    let late = format!(
        r#"{{"tool_name":"Write","tool_input":{{"file_path":"/p/a","content":{}}},"hook_event_name":"PostToolUse"}}"#,
        quoted(&big)
    );
    let (code, said) = run(&[], late);
    assert_eq!(code, Some(0), "event past the cap: {said}");
    assert!(
        !said.contains("not read whole"),
        "event past the cap: {said}"
    );
    let late_shell = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":{}}},"hook_event_name":"PostToolUse"}}"#,
        quoted(&big)
    );
    let (code, said) = run(&[], late_shell);
    assert_eq!(code, Some(2), "shell event past the cap: {said}");
    // A call about to run, with no event, whose content starts with the words
    // of a PostToolUse: those are text it writes, not its event.
    let content =
        format!(r#"{{"hook_event_name":"PostToolUse"}},"hook_event_name":"PostToolUse" {big}"#);
    let posing = format!(
        r#"{{"tool_name":"Write","tool_input":{{"content":{},"file_path":"/p/a"}}}}"#,
        quoted(&content)
    );
    let (code, said) = run(&[], posing);
    assert_eq!(code, Some(2), "posing as a result: {said}");
}

/// A file change past the cap is given for a path, and the agent sends the
/// path before the content: the path is judged as in a call read whole, and
/// the content the hook did not read never runs quietly. A 2 MiB Write to
/// an everyday file asks the person (Claude Code), and says why; the same
/// Write to the guard's own configuration, or to the keys that let a person
/// in over SSH, is refused by name. An agent that cannot ask, or a line
/// with `--block-review`, refuses it with the same reason; monitor lets it
/// run and says so. A relative path is judged from the call's folder, and
/// every path field in the head is judged. A content sent before the path
/// the tool writes to leaves nothing to judge: refused as not read, as
/// before, even with another path field in front of the content.
///
/// FAILS ON REVERT of `large_file_write`: the everyday Write is refused (2)
/// as a call not read, and nobody is asked.
#[test]
fn a_large_file_write_is_judged_by_its_path() {
    /// A tool's input, for a path.
    type Input<'a> = Box<dyn Fn(&str) -> String + 'a>;
    /// A whole call, for the host's home.
    type Body<'a> = Box<dyn Fn(&std::path::Path) -> String + 'a>;
    const BIG: usize = 2 * 1024 * 1024;
    const UNSCREENED: &str = "content longer than the hook reads, not screened";
    let big = "a".repeat(BIG);
    let quoted = |s: &str| serde_json::Value::from(s).to_string();
    // Claude Code's own order: the folder, the event and the tool before
    // what the tool carries, the path before the content.
    let call = |cwd: &std::path::Path, tool: &str, input: String| {
        format!(
            r#"{{"session_id":"s-big","transcript_path":"/t.jsonl","cwd":{},"permission_mode":"default","hook_event_name":"PreToolUse","tool_name":{},"tool_input":{input}}}"#,
            quoted(&cwd.to_string_lossy()),
            quoted(tool),
        )
    };
    let write = |path: &str| {
        format!(
            r#"{{"file_path":{},"content":{}}}"#,
            quoted(path),
            quoted(&big)
        )
    };
    // Each run on a fresh host: `body` is handed the host's home.
    let run = |flags: &[&str], body: &dyn Fn(&std::path::Path) -> String| {
        let host = Host::new();
        let home = host.dir.path().join("home");
        let body = body(&home);
        assert!(body.len() > BIG, "{}", body.len());
        let mut child = host.hook(flags).spawn().expect("run innerwarden hook");
        let mut stdin = child.stdin.take().expect("stdin");
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(body.as_bytes());
        });
        let out = ended_with_stdout(child, "long file write");
        let _ = writer.join();
        out
    };
    let in_home = |home: &std::path::Path, rel: &str| home.join(rel).to_string_lossy().into_owned();

    // An everyday file, by each of Claude Code's file tools: asked.
    let tools: Vec<(&str, Input<'_>)> = vec![
        ("Write", Box::new(write)),
        (
            "Edit",
            Box::new(|path: &str| {
                format!(
                    r#"{{"file_path":{},"old_string":"a","new_string":{}}}"#,
                    quoted(path),
                    quoted(&big)
                )
            }),
        ),
        (
            "MultiEdit",
            Box::new(|path: &str| {
                format!(
                    r#"{{"file_path":{},"edits":[{{"old_string":"a","new_string":{}}}]}}"#,
                    quoted(path),
                    quoted(&big)
                )
            }),
        ),
        (
            "NotebookEdit",
            Box::new(|path: &str| {
                format!(
                    r#"{{"notebook_path":{},"new_source":{}}}"#,
                    quoted(path),
                    quoted(&big)
                )
            }),
        ),
    ];
    for (tool, input) in &tools {
        let (code, out, said) = run(&[], &|home: &std::path::Path| {
            call(
                &home.join("proj"),
                tool,
                input(&in_home(home, "proj/src/big.txt")),
            )
        });
        assert_eq!(code, Some(0), "{tool}: {said}");
        let answer: serde_json::Value =
            serde_json::from_str(out.trim()).unwrap_or_else(|_| panic!("{tool}: {out}"));
        let decision = &answer["hookSpecificOutput"];
        assert_eq!(decision["permissionDecision"], "ask", "{tool}: {out}");
        let reason = decision["permissionDecisionReason"].as_str().unwrap_or("");
        assert!(reason.contains(UNSCREENED), "{tool}: {reason}");
        assert!(reason.contains("proj/src/big.txt"), "{tool}: {reason}");
        assert!(!said.contains("refusing it"), "{tool}: {said}");
    }

    // The guard's own configuration, and the SSH keys of the home: refused
    // by name, whatever the content. Named relative to the call's folder,
    // or in a second path field of the head, the same.
    let refused: Vec<(&str, Body<'_>)> = vec![
        (
            "guard config",
            Box::new(|home: &std::path::Path| {
                call(
                    &home.join("proj"),
                    "Write",
                    write(&in_home(home, ".config/innerwarden/x")),
                )
            }),
        ),
        (
            "authorized_keys",
            Box::new(|home: &std::path::Path| {
                call(
                    &home.join("proj"),
                    "Write",
                    write(&in_home(home, ".ssh/authorized_keys")),
                )
            }),
        ),
        // A relative path, from the call's folder.
        (
            "relative",
            Box::new(|home: &std::path::Path| {
                call(
                    &home.join("proj/src"),
                    "Write",
                    write("../../.ssh/authorized_keys"),
                )
            }),
        ),
        // The guard's own program, named from its folder: from the hook's
        // folder the same name is an everyday file.
        (
            "relative guard program",
            Box::new(|_: &std::path::Path| {
                let program = std::path::Path::new(env!("CARGO_BIN_EXE_innerwarden"));
                call(
                    program.parent().expect("the program's folder"),
                    "Write",
                    write(
                        &program
                            .file_name()
                            .expect("the program's name")
                            .to_string_lossy(),
                    ),
                )
            }),
        ),
        (
            "second path field",
            Box::new(|home: &std::path::Path| {
                call(
                    &home.join("proj"),
                    "Write",
                    format!(
                        r#"{{"file_path":{},"path":{},"content":{}}}"#,
                        quoted(&in_home(home, "proj/src/big.txt")),
                        quoted(&in_home(home, ".ssh/authorized_keys")),
                        quoted(&big)
                    ),
                )
            }),
        ),
    ];
    for (what, body) in &refused {
        let (code, out, said) = run(&[], body.as_ref());
        assert_eq!(code, Some(2), "{what}: {said}");
        assert!(said.contains("blocked this file change"), "{what}: {said}");
        assert!(!out.contains("\"ask\""), "{what}: {out}");
    }

    // An everyday file where nobody can be asked: refused, with the reason.
    let everyday = |home: &std::path::Path| {
        call(
            &home.join("proj"),
            "Write",
            write(&in_home(home, "proj/a.txt")),
        )
    };
    for flags in [
        &["--block-review"][..],
        &["--agent", "gemini"][..],
        &["--agent", "codex"][..],
    ] {
        let (code, out, said) = run(flags, &everyday);
        assert_eq!(code, Some(2), "{flags:?}: {said}");
        assert!(said.contains(UNSCREENED), "{flags:?}: {said}");
        assert!(!out.contains("\"ask\""), "{flags:?}: {out}");
    }
    // Monitor never blocks, and says the content went unscreened.
    let (code, _, said) = run(&["--monitor"], &everyday);
    assert_eq!(code, Some(1), "monitor: {said}");
    assert!(said.contains(UNSCREENED), "monitor: {said}");
    assert!(said.contains("it was NOT screened"), "monitor: {said}");

    // The content before the path: no path in the part read, so the call
    // is refused as one not read, as before.
    let (code, _, said) = run(&[], &|home: &std::path::Path| {
        call(
            &home.join("proj"),
            "Write",
            format!(
                r#"{{"content":{},"file_path":{}}}"#,
                quoted(&big),
                quoted(&in_home(home, "proj/a.txt"))
            ),
        )
    });
    assert_eq!(code, Some(2), "content first: {said}");
    assert!(
        said.contains("longer than the 1 MiB the hook reads"),
        "content first: {said}"
    );
    // A path in another field in front of the one the tool writes to, which
    // comes after the content: what the tool writes is not read, so the
    // call is refused as one not read, and nobody is asked about the other.
    let (code, out, said) = run(&[], &|home: &std::path::Path| {
        call(
            &home.join("proj"),
            "Write",
            format!(
                r#"{{"path":{},"content":{},"file_path":{}}}"#,
                quoted(&in_home(home, "proj/src/big.txt")),
                quoted(&big),
                quoted(&in_home(home, ".ssh/authorized_keys"))
            ),
        )
    });
    assert_eq!(code, Some(2), "written field after the content: {said}");
    assert!(
        said.contains("longer than the 1 MiB the hook reads"),
        "written field after the content: {said}"
    );
    assert!(
        !out.contains("\"ask\""),
        "written field after the content: {out}"
    );
}
