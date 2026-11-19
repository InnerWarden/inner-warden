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
fn ended(mut child: Child, what: &str) -> (Option<i32>, String) {
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
