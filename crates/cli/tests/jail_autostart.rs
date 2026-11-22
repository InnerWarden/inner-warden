//! A Linux jail cannot leave anything the person's session runs on its own
//! at the next login, outside the jail: a desktop autostart entry, a
//! systemd user unit or the link that enables it, a login environment, an
//! upstart job, a D-Bus service. Those folders are read-only in the jail,
//! made empty first where they were not there, and a rename of a folder
//! above one does not take that away. The agent's own folder in
//! `~/.config` stays writable.
#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::Path;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// Whether a jail opens here (the same measure as the jail suite): a bwrap
/// refused its uid map under `apparmor_restrict_unprivileged_userns = 1`
/// skips outside CI, and fails in CI.
fn jail_opens_here(test: &str) -> bool {
    let Some(bwrap) = ["/usr/bin/bwrap", "/usr/local/bin/bwrap"]
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
    else {
        assert!(std::env::var_os("CI").is_none(), "{test}: no bwrap");
        let _ = std::io::stderr().write_all(format!("SKIPPED {test}: no bwrap\n").as_bytes());
        return false;
    };
    let probe = Command::new(bwrap)
        .args(["--unshare-pid", "--ro-bind", "/", "/", "true"])
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run bwrap");
    let said = String::from_utf8_lossy(&probe.stderr).to_string();
    if probe.status.success() || !said.contains("setting up uid map") {
        return true;
    }
    let why = format!("no jail opens on this host ({})", said.trim());
    assert!(std::env::var_os("CI").is_none(), "{test}: {why}");
    let _ = std::io::stderr().write_all(format!("SKIPPED {test}: {why}\n").as_bytes());
    false
}

/// What the program in the jail tries, one line each: `<what> ok` or
/// `<what> refused`. `~/.config/systemd` is there before the jail starts
/// and the other folders are not (the launcher makes them).
const SCRIPT: &str = r#"try() { what=$1; shift; if "$@" 2>/dev/null; then echo "$what ok"; else echo "$what refused"; fi; }
try autostart sh -c 'printf "[Desktop Entry]\nExec=true\n" > "$HOME/.config/autostart/x.desktop"'
try unit sh -c 'mkdir -p "$HOME/.config/systemd/user" && echo "[Service]" > "$HOME/.config/systemd/user/x.service"'
try wants sh -c 'mkdir -p "$HOME/.config/systemd/user/default.target.wants" && ln -s ../x.service "$HOME/.config/systemd/user/default.target.wants/x.service"'
try userconf sh -c 'echo "[Manager]" > "$HOME/.config/systemd/user.conf"'
try envd sh -c 'echo "LD_PRELOAD=/x" > "$HOME/.config/environment.d/x.conf"'
try upstart sh -c 'echo "exec true" > "$HOME/.config/upstart/x.conf"'
try localunit sh -c 'echo "[Service]" > "$HOME/.local/share/systemd/user/x.service"'
try dbus sh -c 'echo "[D-BUS Service]" > "$HOME/.local/share/dbus-1/services/x.service"'
try rename mv "$HOME/.config/systemd" "$HOME/.config/systemd-old"
try renameshare mv "$HOME/.local/share" "$HOME/.local/share-old"
try agent sh -c 'echo kept > "$HOME/.config/myagent/state"'
echo DONE
"#;

/// A real jail: every place the session runs from on its own refuses the
/// write, and a rename of the folder above one is refused too; the
/// agent's own folder in `~/.config` takes it. On the host afterwards
/// nothing of the jail's is in those folders, and the folders the
/// launcher made are there, empty.
///
/// FAILS ON REVERT: drop the read-only binds (every write lands on the
/// host), or the pins above them (the rename of `~/.local/share` works).
#[test]
fn a_jail_cannot_leave_what_the_session_runs_at_the_next_login() {
    let test = "a_jail_cannot_leave_what_the_session_runs_at_the_next_login";
    if !jail_opens_here(test) {
        return;
    }
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    for dir in [".config/systemd", ".config/myagent", ".local/state"] {
        std::fs::create_dir_all(h.join(dir)).unwrap();
    }
    let project = tempfile::TempDir::new().unwrap();
    let graph = tempfile::TempDir::new().unwrap();
    let mut command = Command::new(bin());
    command
        .args(["contain", "--project", project.path().to_str().unwrap()])
        .args(["--", "/bin/sh", "-c", SCRIPT])
        .env("HOME", &h)
        .env("IW_GRAPH_FILE", graph.path().join("graph.json"))
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_CONFIG_HOME");
    for marker in [
        "CLAUDECODE",
        "CLAUDE_CODE_ENTRYPOINT",
        "CODEX_SANDBOX",
        "CODEX_SANDBOX_NETWORK_DISABLED",
        "GEMINI_CLI",
        "OPENCLAW_SHELL",
    ] {
        command.env_remove(marker);
    }
    let out = command.output().expect("run the jail");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("DONE"),
        "{stdout}\n{stderr}"
    );
    for what in [
        "autostart",
        "unit",
        "wants",
        "userconf",
        "envd",
        "upstart",
        "localunit",
        "dbus",
        "rename",
        "renameshare",
    ] {
        assert!(
            stdout.lines().any(|l| l == format!("{what} refused")),
            "{what}: {stdout}\n{stderr}"
        );
    }
    assert!(
        stdout.lines().any(|l| l == "agent ok"),
        "{stdout}\n{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(h.join(".config/myagent/state")).unwrap(),
        "kept\n"
    );
    for dir in [
        ".config/autostart",
        ".config/systemd",
        ".config/environment.d",
        ".config/upstart",
        ".local/share/systemd/user",
        ".local/share/dbus-1/services",
    ] {
        let place = h.join(dir);
        assert!(place.is_dir(), "{dir} made by the launcher");
        let left: Vec<_> = std::fs::read_dir(&place)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "{dir}: {left:?}");
    }
    assert!(!h.join(".config/systemd-old").exists());
    assert!(!h.join(".local/share-old").exists());
}
