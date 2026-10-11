use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn run_with_deadline(args: &[&str]) -> Option<std::process::ExitStatus> {
    let home = tempfile::TempDir::new().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_innerwarden"))
        .arg("dashboard")
        .args(args)
        .env("HOME", home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn innerwarden");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            // It started serving instead of refusing.
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn dashboard_with_a_subcommand_exits_2_instead_of_serving() {
    for word in ["tunnel", "open"] {
        let status = run_with_deadline(&[word]);
        assert_eq!(
            status.and_then(|s| s.code()),
            Some(2),
            "`dashboard {word}` must refuse, not start a server"
        );
    }
}
