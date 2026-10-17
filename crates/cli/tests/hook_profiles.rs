//! End-to-end: the per-agent profiles on the hook, run the way an agent runs
//! it (a payload on stdin, the verdict in the exit code: 2 refuses, 0 lets the
//! call run). HOME, the record and the session store point into a scratch
//! directory, and the profile is the user's own file there.
//!
//! None of these run on a machine that has a system profiles file
//! (`/etc/innerwarden/agent-profiles.toml`): it would be merged in.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SYSTEM_FILE: &str = "/etc/innerwarden/agent-profiles.toml";

struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        std::fs::create_dir_all(dir.path().join("home/proj")).expect("project");
        Self { dir }
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn profiles(&self, body: &str) {
        let dir = self.home().join(".config/innerwarden");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("agent-profiles.toml");
        std::fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    }

    /// Run the hook once; the exit code and stderr.
    fn hook(&self, flags: &[&str], payload: &str) -> (Option<i32>, String) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_innerwarden"))
            .arg("hook")
            .args(flags)
            .env("HOME", self.home())
            .env("USERPROFILE", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("IW_SESSION_FILE", self.dir.path().join("sessions.json"))
            .env_remove("IW_GUARD_SESSION")
            .env("INNERWARDEN_AGENT_URL", "off")
            .current_dir(self.home().join("proj"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run innerwarden hook");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(payload.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn bash(&self, command: &str) -> String {
        serde_json::json!({
            "session_id": "s-profiles",
            "hook_event_name": "PreToolUse",
            "cwd": self.home().join("proj"),
            "tool_name": "Bash",
            "tool_input": { "command": command },
        })
        .to_string()
    }

    fn last_command_attrs(&self) -> serde_json::Value {
        let graph: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(self.dir.path().join("graph.json")).unwrap(),
        )
        .unwrap();
        graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .rev()
            .find(|n| n["kind"] == "command")
            .expect("a command node")["attrs"]
            .clone()
    }

    fn events(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.dir.path().join("guard-events.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

fn system_file_present() -> bool {
    Path::new(SYSTEM_FILE).exists()
}

const REVIEW: &str = "curl http://203.0.113.9/x";

/// No profiles file: the hook is what it was. A review runs in enforce and
/// blocks with `--block-review`, no deciding layer is recorded, no snapshot
/// is written and no profile line is emitted.
#[test]
fn without_a_profiles_file_the_hook_is_unchanged() {
    if system_file_present() {
        return;
    }
    let host = Host::new();
    assert_eq!(
        host.hook(&["--agent", "claude-code"], &host.bash(REVIEW)).0,
        Some(0)
    );
    assert_eq!(
        host.hook(
            &["--agent", "claude-code", "--block-review"],
            &host.bash(REVIEW)
        )
        .0,
        Some(2)
    );
    // The guard's LLM key: no rule of today's engine refuses the read.
    assert_eq!(
        host.hook(
            &["--agent", "claude-code"],
            &host.bash("cat ~/.config/innerwarden/llm-key")
        )
        .0,
        Some(0)
    );
    let attrs = host.last_command_attrs();
    assert!(attrs.get("deciding_layer").is_none(), "{attrs}");
    assert!(!host.dir.path().join("agent-profiles.seen.json").exists());
    assert!(host
        .events()
        .iter()
        .all(|line| line["kind"] != "guard.profile_changed"));
}

/// A profile's denial holds for an agent that is only `declared`: it is a
/// tightening, and the type it names is the one it gets. Another type is
/// untouched. The change to the profiles is reported once.
#[test]
fn a_profile_deny_refuses_the_declared_type_and_is_reported() {
    if system_file_present() {
        return;
    }
    let host = Host::new();
    host.profiles(
        "schema_version = 1\n[profile.claude-code]\ndeny_categories = [\"bare_ip_fetch\"]\n",
    );
    let (code, stderr) = host.hook(&["--agent", "claude-code"], &host.bash(REVIEW));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("agent profile denies bare_ip_fetch"),
        "{stderr}"
    );
    let attrs = host.last_command_attrs();
    assert_eq!(attrs["deciding_layer"], "agent_type");

    assert_eq!(
        host.hook(&["--agent", "cursor"], &host.bash(REVIEW)).0,
        Some(0)
    );
    assert_eq!(host.last_command_attrs()["deciding_layer"], "general");

    let changes: Vec<String> = host
        .events()
        .iter()
        .filter(|line| line["kind"] == "guard.profile_changed")
        .map(|line| format!("{} {} {}", line["layer"], line["action"], line["value"]))
        .collect();
    assert_eq!(
        changes,
        [
            "\"agent_type\" \"profile_added\" \"\"",
            "\"agent_type\" \"deny_category_added\" \"bare_ip_fetch\""
        ],
        "reported once, by the first call that saw the file"
    );
}

/// An agent outside any jail that declares itself the permissive type gets
/// the general policy: the relaxation it would need cannot even be written
/// where its own account writes. An allowance in the user's file is refused
/// at load and said, and the hook refuses rather than run half a policy. (A
/// relaxation from the system file, for a confined instance only, is pinned
/// by the pure tests; it needs a root-owned file and a jail.)
#[test]
fn a_relaxation_in_the_users_file_is_refused_and_said() {
    if system_file_present() {
        return;
    }
    let host = Host::new();
    host.profiles(
        "schema_version = 1\n[profile.claude-code]\nallow_categories = [\"bare_ip_fetch\"]\n",
    );
    let (code, stderr) = host.hook(&["--agent", "claude-code"], &host.bash(REVIEW));
    assert_eq!(code, Some(2), "{stderr}");
    assert!(stderr.contains("may relax a rule"), "{stderr}");
}

/// The hard layer refuses the guard's LLM key for every agent once profiles
/// are in force, whatever the type's profile allows.
#[test]
fn reaching_the_llm_key_is_refused_once_profiles_are_in_force() {
    if system_file_present() {
        return;
    }
    let host = Host::new();
    host.profiles(
        "schema_version = 1\n[profile.claude-code]\ndeny_categories = [\"tmp_execution\"]\n",
    );
    for agent in ["claude-code", "cursor"] {
        let (code, stderr) = host.hook(
            &["--agent", agent],
            &host.bash("cat ~/.config/innerwarden/llm-key"),
        );
        assert_eq!(code, Some(2), "{agent}: {stderr}");
        assert!(stderr.contains("LLM key"), "{stderr}");
        assert_eq!(host.last_command_attrs()["deciding_layer"], "hard");
    }
}

/// A file that cannot be used is never half applied: enforce refuses every
/// command and says why; monitor never blocks.
#[test]
fn a_profiles_file_that_cannot_be_used_refuses_in_enforce_and_never_in_monitor() {
    if system_file_present() {
        return;
    }
    let host = Host::new();
    host.profiles(
        "schema_version = 1\n[profile.claude-code]\ndeny_categories = [\"curl_to_bash\"]\n",
    );
    let (code, stderr) = host.hook(&["--agent", "claude-code"], &host.bash("ls"));
    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("`curl_to_bash` is not a signal name"),
        "{stderr}"
    );
    let (code, _) = host.hook(&["--agent", "claude-code", "--monitor"], &host.bash(REVIEW));
    assert_eq!(code, Some(0));
    assert!(host.events().iter().any(
        |line| line["kind"] == "guard.profile_changed" && line["action"] == "profiles_rejected"
    ));
}

/// The file tools are judged by the hard layer alone: a privileged write is
/// refused as before, and the record says which layer.
#[test]
fn a_file_tool_refusal_is_recorded_as_the_hard_layer() {
    if system_file_present() {
        return;
    }
    let host = Host::new();
    host.profiles("schema_version = 1\n");
    let payload = serde_json::json!({
        "session_id": "s-profiles",
        "hook_event_name": "PreToolUse",
        "cwd": host.home().join("proj"),
        "tool_name": "Write",
        "tool_input": { "file_path": host.home().join(".bashrc"), "content": "x" },
    })
    .to_string();
    assert_eq!(host.hook(&["--agent", "claude-code"], &payload).0, Some(2));
    assert_eq!(host.last_command_attrs()["deciding_layer"], "hard");
}

impl Host {
    /// Run the MCP proxy around `cat` (which echoes every forwarded line) in
    /// guard mode, send it one line and close: what reached the client.
    #[cfg(unix)]
    fn proxy(&self, line: &str) -> (Option<i32>, String) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_innerwarden"))
            .args([
                "proxy",
                "--mode",
                "guard",
                "--agent",
                "claude-code",
                "--",
                "cat",
            ])
            .env("HOME", self.home())
            .env("IW_GRAPH_FILE", self.dir.path().join("graph.json"))
            .env("INNERWARDEN_AGENT_URL", "off")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run innerwarden proxy");
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(line.as_bytes()).unwrap();
        stdin.write_all(b"\n").unwrap();
        drop(stdin);
        let out = child.wait_with_output().unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    }
}

/// The proxy applies the profile on its own path: a tool the profile denies
/// is refused in guard mode and never reaches the server; with no profiles
/// file the same call is forwarded, as before.
#[cfg(unix)]
#[test]
fn the_proxy_refuses_a_tool_the_profile_denies_and_forwards_it_without_one() {
    if system_file_present() {
        return;
    }
    let call = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"weather","arguments":{"location":"NYC"}}}"#;
    let plain = Host::new();
    let (_, echoed) = plain.proxy(call);
    assert!(
        echoed.contains("\"method\":\"tools/call\""),
        "forwarded to the server: {echoed}"
    );

    let host = Host::new();
    host.profiles("schema_version = 1\n[profile.claude-code]\nmcp_tools_deny = [\"weather\"]\n");
    let (_, replied) = host.proxy(call);
    assert!(replied.contains("AG-PROFILE-DENY"), "{replied}");
    assert!(replied.contains("\"isError\":true"), "{replied}");
    assert!(
        !replied.contains("\"method\":\"tools/call\""),
        "never forwarded: {replied}"
    );
    assert_eq!(host.last_command_attrs()["deciding_layer"], "agent_type");
}
