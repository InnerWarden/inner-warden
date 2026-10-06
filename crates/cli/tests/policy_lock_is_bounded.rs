//! The agent-policy lock (`~/.config/innerwarden/agents.lock`) is the user's
//! file, so the guarded agent's own account can open and hold it. Every
//! command that changes agent wiring takes it first, and took it with a
//! blocking wait, so a held lock kept `innerwarden enforce` from ever
//! switching to enforce.
//!
//! Drives the REAL binary over a disposable HOME.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn cli(home: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_innerwarden"));
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("IW_GRAPH_FILE", home.join("graph.json"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// `innerwarden enforce` and `innerwarden agents auto-connect --off`, run
/// while another descriptor holds the lock, give up within the lock's wait
/// (5 s) and say which lock was held; neither changes anything.
///
/// FAILS ON REVERT: with the blocking lock, both are still waiting when the
/// test gives up on them (20 s) and kills them.
#[test]
fn a_command_that_changes_agent_wiring_gives_up_on_a_held_policy_lock() {
    use fs4::FileExt;

    let home = tempfile::TempDir::new().unwrap();
    let dir = home.path().join(".config/innerwarden");
    std::fs::create_dir_all(&dir).unwrap();
    let lock_path = dir.join("agents.lock");
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .unwrap();
    FileExt::lock(&holder).unwrap();

    for args in [&["enforce"][..], &["agents", "auto-connect", "--off"][..]] {
        let started = Instant::now();
        let mut child = cli(home.path())
            .args(args)
            .spawn()
            .expect("run innerwarden");
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if started.elapsed() > Duration::from_secs(20) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{args:?} was still waiting on the held lock after 20 s");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let out = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!status.success(), "{args:?} must fail: {stderr}");
        assert!(
            stderr.contains("agents.lock was held by another process"),
            "{args:?} must name the lock: {stderr}"
        );
        assert!(
            !dir.join("agents.toml").exists(),
            "{args:?} changed the policy while the lock was held"
        );
    }
}
