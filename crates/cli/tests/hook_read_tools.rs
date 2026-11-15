//! End-to-end: the PreToolUse hook on an agent's read tools (`Read`, `Grep`,
//! `Glob`).
//!
//! These run the REAL binary the way Claude Code runs it: a JSON payload on
//! stdin, the verdict in the exit code (2 refuses, 0 lets the call run). HOME,
//! the record and the session store point into a scratch directory, so a run
//! never reads or writes the developer's own state. The secrets are dummy
//! files in that scratch home.

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
        let home = dir.path().join("home");
        std::fs::create_dir_all(home.join("proj/.git")).expect("project");
        std::fs::create_dir_all(home.join("proj/src")).expect("project src");
        std::fs::write(home.join("proj/src/main.rs"), "fn main() {}\n").expect("main.rs");
        std::fs::write(home.join("proj/.env"), "APP_KEY=dummy\n").expect("project env");
        std::fs::create_dir_all(home.join(".ssh")).expect("ssh");
        std::fs::write(home.join(".ssh/id_ed25519"), "dummy key\n").expect("key");
        std::fs::create_dir_all(home.join(".codex")).expect("codex");
        std::fs::write(home.join(".codex/auth.json"), "{}\n").expect("auth");
        std::fs::create_dir_all(home.join(".hermes")).expect("app");
        std::fs::write(home.join(".hermes/.env"), "SLACK_BOT_TOKEN=dummy\n").expect("app env");
        Self { dir }
    }

    fn home(&self) -> std::path::PathBuf {
        self.dir.path().join("home")
    }

    fn project(&self) -> std::path::PathBuf {
        self.home().join("proj")
    }

    fn at(&self, relative: &str) -> String {
        self.home().join(relative).to_string_lossy().into_owned()
    }

    /// Run the hook once with `payload`; the exit code and stderr.
    fn hook(&self, flags: &[&str], payload: &str) -> (Option<i32>, String) {
        let mut child = Command::new(bin())
            .arg("hook")
            .args(flags)
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .current_dir(self.project())
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

    /// A payload in Claude Code's PreToolUse shape.
    fn call(&self, tool: &str, input: serde_json::Value) -> String {
        serde_json::json!({
            "session_id": "s-read-tools",
            "hook_event_name": "PreToolUse",
            "cwd": self.project(),
            "tool_name": tool,
            "tool_input": input,
        })
        .to_string()
    }

    fn read(&self, path: &str) -> String {
        self.call("Read", serde_json::json!({ "file_path": path }))
    }

    fn grep(&self, path: &str) -> String {
        self.call(
            "Grep",
            serde_json::json!({ "pattern": "TOKEN", "path": path, "output_mode": "content" }),
        )
    }
}

fn record(host: &Host) -> String {
    std::fs::read_to_string(host.dir.path().join("graph.json")).unwrap_or_default()
}

/// The row's proof: the five calls measured as passing are refused before
/// they run, each with the reason the shell read of the same file gets.
///
/// FAILS ON REVERT: take the read-tool arm out of `classify_hook_input` and
/// every call exits 0 as a call with no command.
#[test]
fn a_read_tool_call_on_a_secret_is_refused() {
    let host = Host::new();
    for (payload, reason) in [
        (host.read(&host.at(".hermes/.env")), "outside the project"),
        (host.read(&host.at(".codex/auth.json")), "auth.json"),
        (host.read(&host.at(".ssh/id_ed25519")), ".ssh/"),
        (host.grep(&host.at(".hermes")), ".hermes/.env"),
        (host.grep(&host.at(".ssh")), ".ssh/"),
    ] {
        let (code, stderr) = host.hook(&["--agent", "claude-code"], &payload);
        assert_eq!(code, Some(2), "{payload}: {stderr}");
        assert!(stderr.contains("InnerWarden blocked"), "{stderr}");
        assert!(stderr.contains(reason), "{reason}: {stderr}");
    }
    assert!(
        record(&host).contains("sensitive_credential_read"),
        "a refusal is recorded"
    );
}

/// The twins: an ordinary read, a search of the project and a listing pass
/// in silence and are not recorded; the project's own `.env` keeps the
/// verdict `cat .env` has (a review an enforcing hook lets through).
#[test]
fn an_ordinary_read_passes_in_silence() {
    let host = Host::new();
    for payload in [
        host.read(&host.project().join("src/main.rs").to_string_lossy()),
        host.read(&host.project().join(".env").to_string_lossy()),
        host.grep(&host.project().join("src").to_string_lossy()),
        host.call("Grep", serde_json::json!({ "pattern": "fn main" })),
        host.call("Glob", serde_json::json!({ "pattern": "src/**/*.rs" })),
    ] {
        let (code, stderr) = host.hook(&[], &payload);
        assert_eq!(code, Some(0), "{payload}: {stderr}");
        assert!(stderr.is_empty(), "{payload}: {stderr}");
    }
    let recorded = record(&host);
    assert!(
        !recorded.contains("main.rs"),
        "an ordinary read is not recorded: {recorded}"
    );
    // The same `.env` read through the shell: the same outcome.
    let bash = host.call("Bash", serde_json::json!({ "command": "cat .env" }));
    assert_eq!(host.hook(&[], &bash).0, Some(0));
    // `--block-review` refuses a review, through either tool.
    let env = host.read(&host.project().join(".env").to_string_lossy());
    assert_eq!(host.hook(&["--block-review"], &env).0, Some(2));
    assert_eq!(host.hook(&["--block-review"], &bash).0, Some(2));
}

/// A path that arrived in a tool result does not make a read of it a review:
/// a read sends nothing anywhere, so where its path came from is no step of
/// the two-step attack, and opening a file a search found is the work.
///
/// FAILS ON REVERT: hand a read tool's call to the session store as a shell
/// command is, and the `Read` below is a review that `--block-review` refuses.
#[test]
fn a_path_from_a_tool_result_does_not_make_a_read_a_review() {
    let host = Host::new();
    let main_rs = host.project().join("src/main.rs");
    let result = serde_json::json!({
        "session_id": "s-read-tools",
        "hook_event_name": "PostToolUse",
        "cwd": host.project(),
        "tool_name": "Bash",
        "tool_input": { "command": "git ls-files --full-name" },
        "tool_response": { "stdout": format!(" {}\n", main_rs.display()) },
    })
    .to_string();
    assert_eq!(host.hook(&[], &result).0, Some(0));
    let read = host.read(&main_rs.to_string_lossy());
    let (code, stderr) = host.hook(&["--block-review"], &read);
    assert_eq!(code, Some(0), "{stderr}");
    // The same path in a shell command is still judged on where it came
    // from: the store holds it, and the shell path reads it.
    let bash = host.call(
        "Bash",
        serde_json::json!({ "command": format!("cat {}", main_rs.display()) }),
    );
    let (code, stderr) = host.hook(&["--block-review"], &bash);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("did not come from you"), "{stderr}");
}

/// A read of a secret under another name is refused as a read of the
/// secret: a link made earlier, a hard link, a link to the folder a search
/// runs in.
///
/// FAILS ON REVERT of `other_names_of` in `file_read_call_in`.
#[cfg(unix)]
#[test]
fn a_read_of_a_secret_under_another_name_is_refused() {
    let host = Host::new();
    let elsewhere = host.dir.path().join("tmp");
    std::fs::create_dir_all(&elsewhere).expect("tmp");
    let soft = elsewhere.join("k");
    std::os::unix::fs::symlink(host.at(".ssh/id_ed25519"), &soft).expect("symlink");
    let hard = elsewhere.join("h");
    std::fs::hard_link(host.at(".ssh/id_ed25519"), &hard).expect("hard link");
    let folder = elsewhere.join("s");
    std::os::unix::fs::symlink(host.at(".ssh"), &folder).expect("folder link");
    for payload in [
        host.read(&soft.to_string_lossy()),
        host.read(&hard.to_string_lossy()),
        host.grep(&folder.to_string_lossy()),
    ] {
        let (code, stderr) = host.hook(&["--agent", "claude-code"], &payload);
        assert_eq!(code, Some(2), "{payload}: {stderr}");
        assert!(stderr.contains(".ssh/"), "{stderr}");
    }
    // The twin: a link to an ordinary file reads as that file.
    let ordinary = elsewhere.join("m");
    std::os::unix::fs::symlink(host.project().join("src/main.rs"), &ordinary).expect("link");
    let (code, stderr) = host.hook(&[], &host.read(&ordinary.to_string_lossy()));
    assert_eq!(code, Some(0), "{stderr}");
}

/// The shell reads a link, or a hard link, to a secret as the secret, as
/// the read tools do; a public key, the known hosts and the authorized keys
/// are read by either as the public files they are, unless the file of that
/// name is the private key under another name.
///
/// FAILS ON REVERT of `secret_behind` in `stored_secret_read_in_place` (the
/// shell reads of a link), or of `is_public_ssh_file` (the public reads are
/// refused again).
#[cfg(unix)]
#[test]
fn a_shell_read_of_a_secret_under_another_name_is_refused() {
    let host = Host::new();
    std::fs::write(host.at(".ssh/id_ed25519.pub"), "ssh-ed25519 AAAA dev\n").expect("pub");
    std::fs::write(host.at(".ssh/known_hosts"), "github.com ssh-ed25519 AAAA\n").expect("hosts");
    std::fs::write(host.at(".ssh/authorized_keys"), "ssh-ed25519 AAAA\n").expect("keys");
    let elsewhere = host.dir.path().join("tmp");
    std::fs::create_dir_all(&elsewhere).expect("tmp");
    let soft = elsewhere.join("k");
    std::os::unix::fs::symlink(host.at(".ssh/id_ed25519"), &soft).expect("symlink");
    let hard = elsewhere.join("h");
    std::fs::hard_link(host.at(".ssh/id_ed25519"), &hard).expect("hard link");
    let folder = elsewhere.join("s");
    std::os::unix::fs::symlink(host.at(".ssh"), &folder).expect("folder link");
    let posing = host.home().join(".ssh/deploy.pub");
    std::os::unix::fs::symlink(host.at(".ssh/id_ed25519"), &posing).expect("posing link");
    let posing_hard = elsewhere.join("x.pub");
    std::fs::hard_link(host.at(".ssh/id_ed25519"), &posing_hard).expect("posing hard link");
    let bash = |command: String| host.call("Bash", serde_json::json!({ "command": command }));
    for payload in [
        bash(format!("cat {}", soft.display())),
        bash(format!("head -c 64 {}", hard.display())),
        bash(format!("grep -r . {}", folder.display())),
        bash(format!("cat {}", posing.display())),
        bash(format!("cat {}", posing_hard.display())),
        host.read(&posing.to_string_lossy()),
        host.read(&posing_hard.to_string_lossy()),
    ] {
        let (code, stderr) = host.hook(&[], &payload);
        assert_eq!(code, Some(2), "{payload}: {stderr}");
        assert!(stderr.contains(".ssh"), "{stderr}");
    }
    let ordinary = elsewhere.join("m");
    std::os::unix::fs::symlink(host.project().join("src/main.rs"), &ordinary).expect("link");
    for payload in [
        bash(format!("cat {}", ordinary.display())),
        bash("cat ~/.ssh/id_ed25519.pub".to_string()),
        bash("grep github ~/.ssh/known_hosts".to_string()),
        host.read(&host.at(".ssh/id_ed25519.pub")),
        host.read(&host.at(".ssh/known_hosts")),
        host.read(&host.at(".ssh/authorized_keys")),
    ] {
        let (code, stderr) = host.hook(&["--block-review"], &payload);
        assert_eq!(code, Some(0), "{payload}: {stderr}");
    }
}

/// A search is judged as its shell twin: one of `~/.config` takes the login
/// one folder down with it, one for a secret over a broad root is the hunt
/// `grep -r password /etc` is, and one of a folder the home is in reads the
/// key the home keeps, as `grep -r password /` does.
///
/// FAILS ON REVERT of the second level in `secret_in_hidden_folder` (the
/// `~/.config` pair), of `credential_hunt_token` in the search arm and
/// `check_credential_hunt_beside` (the hunt pair), or of the whole-home arm
/// in `stored_secret_read_in_place` (the root pair).
#[test]
fn a_search_is_judged_as_its_shell_twin() {
    let host = Host::new();
    std::fs::create_dir_all(host.home().join(".config/gh")).expect("gh");
    std::fs::write(host.home().join(".config/gh/hosts.yml"), "oauth_token: x\n").expect("gh");
    let config = host.call(
        "Grep",
        serde_json::json!({ "pattern": "oauth_token", "path": host.at(".config"), "output_mode": "content" }),
    );
    let config_shell = host.call(
        "Bash",
        serde_json::json!({ "command": format!("grep -r oauth_token {}", host.at(".config")) }),
    );
    for payload in [&config, &config_shell] {
        let (code, stderr) = host.hook(&[], payload);
        assert_eq!(code, Some(2), "{payload}: {stderr}");
        assert!(stderr.contains("hosts.yml"), "{stderr}");
    }
    let hunt = host.call(
        "Grep",
        serde_json::json!({ "pattern": "password|BEGIN OPENSSH PRIVATE KEY", "path": "/etc", "-A": 50 }),
    );
    let hunt_shell = host.call(
        "Bash",
        serde_json::json!({ "command": "grep -r password /etc" }),
    );
    for payload in [&hunt, &hunt_shell] {
        // A hunt is a review: an enforcing hook lets it through, and
        // `--block-review` refuses it.
        assert_eq!(host.hook(&[], payload).0, Some(0), "{payload}");
        let (code, stderr) = host.hook(&["--block-review"], payload);
        assert_eq!(code, Some(2), "{payload}: {stderr}");
        assert!(
            stderr.contains("searches the filesystem for credentials"),
            "{stderr}"
        );
    }
    let root = host.call(
        "Grep",
        serde_json::json!({ "pattern": "password", "path": "/", "-A": 50 }),
    );
    let root_shell = host.call(
        "Bash",
        serde_json::json!({ "command": "grep -r password /" }),
    );
    for payload in [&root, &root_shell] {
        let (code, stderr) = host.hook(&[], payload);
        assert_eq!(code, Some(2), "{payload}: {stderr}");
        assert!(stderr.contains(".ssh/id_ed25519"), "{stderr}");
    }
    let plain = host.call(
        "Grep",
        serde_json::json!({ "pattern": "fn main", "path": "/etc" }),
    );
    assert_eq!(host.hook(&["--block-review"], &plain).0, Some(0));
}

/// Monitor never blocks: the refusal is recorded as one it would have made.
#[test]
fn monitor_records_the_read_and_lets_it_run() {
    let host = Host::new();
    let (code, stderr) = host.hook(&["--monitor"], &host.read(&host.at(".ssh/id_ed25519")));
    assert_eq!(code, Some(0), "{stderr}");
    let recorded = record(&host);
    assert!(recorded.contains("sensitive_credential_read"), "{recorded}");
    assert!(recorded.contains("would_block"), "{recorded}");
}

/// A read call that names no file is refused rather than let through
/// unscreened, as a shell call with no command is; monitor says so.
#[test]
fn a_read_call_with_no_path_is_refused_in_enforce() {
    let host = Host::new();
    let payload = host.call("Read", serde_json::json!({ "limit": 10 }));
    assert_eq!(host.hook(&[], &payload).0, Some(2));
    let (code, stderr) = host.hook(&["--monitor"], &payload);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("NOT screened"), "{stderr}");
}

fn percentile(sorted: &[u128], pct: usize) -> u128 {
    let at = (sorted.len() * pct).div_ceil(100).saturating_sub(1);
    sorted[at.min(sorted.len() - 1)]
}

/// Not a budget: a measurement, printed for the change log. Run it on the
/// build box in release (`cargo test --release -p innerwarden --test
/// hook_read_tools -- --ignored --nocapture`).
#[test]
#[ignore]
fn measure_read_hook_latency() {
    let host = Host::new();
    for (name, payload) in [
        (
            "Read project file",
            host.read(&host.project().join("src/main.rs").to_string_lossy()),
        ),
        (
            "Read ~/.ssh/id_ed25519",
            host.read(&host.at(".ssh/id_ed25519")),
        ),
        (
            "Grep project src",
            host.grep(&host.project().join("src").to_string_lossy()),
        ),
        (
            "Bash cat src/main.rs",
            host.call("Bash", serde_json::json!({ "command": "cat src/main.rs" })),
        ),
    ] {
        let _ = host.hook(&[], &payload);
        let mut times: Vec<u128> = (0..200)
            .map(|_| {
                let start = Instant::now();
                let _ = host.hook(&[], &payload);
                start.elapsed().as_micros()
            })
            .collect();
        times.sort_unstable();
        println!(
            "hook latency {name}: p50 {} us, p95 {} us",
            percentile(&times, 50),
            percentile(&times, 95)
        );
    }
}
