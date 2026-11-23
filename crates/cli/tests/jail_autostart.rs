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

/// Runs `script` in a real jail of a project of its own, in the home `h`,
/// with `env` set on the launcher and every agent's marker taken out.
fn run_jail(h: &Path, script: &str, env: &[(&str, &Path)]) -> std::process::Output {
    let project = tempfile::TempDir::new().unwrap();
    let graph = tempfile::TempDir::new().unwrap();
    let mut command = Command::new(bin());
    command
        .args(["contain", "--project", project.path().to_str().unwrap()])
        .args(["--", "/bin/sh", "-c", script])
        .env("HOME", h)
        .env("IW_GRAPH_FILE", graph.path().join("graph.json"))
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_DATA_DIRS");
    for (name, value) in env {
        command.env(name, value);
    }
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
    command.output().expect("run the jail")
}

/// What the program in the jail tries in the places the person's own
/// programs run from, as the person, the next time they start: git's
/// config, a shell's and an editor's startup files, a desktop launcher,
/// flatpak's exported D-Bus services, and the same under the
/// `XDG_CONFIG_HOME` and `XDG_DATA_HOME` the launcher was given.
const RUN_AS_PERSON_SCRIPT: &str = r#"try() { what=$1; shift; if "$@" 2>/dev/null; then echo "$what ok"; else echo "$what refused"; fi; }
try git sh -c 'printf "[core]\n\thooksPath = /tmp/h\n" > "$HOME/.config/git/config"'
try fish sh -c 'echo "echo hi" > "$HOME/.config/fish/config.fish"'
try nvim sh -c 'echo "vim.cmd(\"!true\")" > "$HOME/.config/nvim/init.lua"'
try zsh sh -c 'echo "true" > "$HOME/.config/zsh/.zshrc"'
try tmux sh -c 'echo "run-shell true" > "$HOME/.config/tmux/tmux.conf"'
try launcher sh -c 'printf "[Desktop Entry]\nExec=true\n" > "$HOME/.local/share/applications/firefox.desktop"'
try flatpak sh -c 'echo "[D-BUS Service]" > "$HOME/.local/share/flatpak/exports/share/dbus-1/services/x.service"'
try xdggit sh -c 'echo "[alias]" > "$HOME/.local/cfg/git/config"'
try xdgunit sh -c 'mkdir -p "$HOME/.local/cfg/systemd/user" && echo "[Service]" > "$HOME/.local/cfg/systemd/user/x.service"'
try xdgdbus sh -c 'echo "[D-BUS Service]" > "$HOME/.local/xdata/dbus-1/services/x.service"'
try renamegit mv "$HOME/.config/git" "$HOME/.config/git-old"
try renamecfg mv "$HOME/.local/cfg" "$HOME/.local/cfg-old"
try agent sh -c 'echo kept > "$HOME/.config/myagent/state"'
echo DONE
"#;

/// A real jail: git's config, the shells' and editors' startup files, the
/// desktop's launchers and flatpak's exported services refuse the write,
/// in the home and under the `XDG_CONFIG_HOME` and `XDG_DATA_HOME` the
/// person's environment names (here inside `~/.local`, which the jail
/// writes), and the folders above them cannot be renamed; the agent's own
/// folder in `~/.config` takes the write. On the host afterwards those
/// folders are there, empty.
///
/// FAILS ON REVERT: cover only the six login folders (git's config and the
/// rest land on the host), or only `~/.config` (the `XDG_CONFIG_HOME`
/// writes land).
#[test]
fn a_jail_cannot_leave_what_your_programs_run_next_as_you() {
    let test = "a_jail_cannot_leave_what_your_programs_run_next_as_you";
    if !jail_opens_here(test) {
        return;
    }
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    for dir in [
        ".config/myagent",
        ".local/state",
        ".local/cfg",
        ".local/xdata",
    ] {
        std::fs::create_dir_all(h.join(dir)).unwrap();
    }
    let cfg = h.join(".local/cfg");
    let data = h.join(".local/xdata");
    let out = run_jail(
        &h,
        RUN_AS_PERSON_SCRIPT,
        &[("XDG_CONFIG_HOME", &cfg), ("XDG_DATA_HOME", &data)],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("DONE"),
        "{stdout}\n{stderr}"
    );
    for what in [
        "git",
        "fish",
        "nvim",
        "zsh",
        "tmux",
        "launcher",
        "flatpak",
        "xdggit",
        "xdgunit",
        "xdgdbus",
        "renamegit",
        "renamecfg",
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
    for dir in [
        ".config/git",
        ".config/fish",
        ".config/nvim",
        ".config/zsh",
        ".config/tmux",
        ".local/share/applications",
        ".local/share/flatpak/exports/share/dbus-1/services",
        ".local/cfg/git",
        ".local/cfg/systemd",
        ".local/xdata/dbus-1/services",
    ] {
        let place = h.join(dir);
        assert!(place.is_dir(), "{dir} made by the launcher");
        let left: Vec<_> = std::fs::read_dir(&place)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "{dir}: {left:?}");
    }
}

/// A file where one of those folders belongs (`~/.config/git` a file)
/// refuses the jail: before, the place was left unprotected and the jail
/// started, so a program in it could replace the file with the folder.
///
/// FAILS ON REVERT: skip a place that is not a folder.
#[test]
fn a_file_where_such_a_folder_belongs_refuses_the_jail() {
    let test = "a_file_where_such_a_folder_belongs_refuses_the_jail";
    if !jail_opens_here(test) {
        return;
    }
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    std::fs::create_dir_all(h.join(".config")).unwrap();
    std::fs::write(h.join(".config/git"), "a file").unwrap();
    let out = run_jail(&h, "echo RAN", &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stdout}\n{stderr}");
    assert!(!stdout.contains("RAN"), "{stdout}");
    assert!(
        stderr.contains(".config/git") && stderr.contains("is not a folder"),
        "{stderr}"
    );
    assert_eq!(
        std::fs::read_to_string(h.join(".config/git")).unwrap(),
        "a file"
    );
}

/// A home whose `~/.config/git` and `~/.config/fish` are links into a
/// dotfiles folder (stow) opens a jail again: where a link leads into a
/// folder the jail writes, that place is read-only; where it leads to a
/// folder the jail does not show, the jail shows it nowhere. Each link is
/// said, since a program in the jail could still replace the link itself.
/// On the host afterwards neither dotfiles folder holds anything new.
///
/// FAILS ON REVERT: refuse every such link (the jail does not open), or
/// leave the place a link leads to writable (`fish` lands on the host).
#[test]
fn a_stowed_home_opens_a_jail_and_keeps_what_the_links_lead_to() {
    use std::os::unix::fs::symlink;
    let test = "a_stowed_home_opens_a_jail_and_keeps_what_the_links_lead_to";
    if !jail_opens_here(test) {
        return;
    }
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    for dir in [
        ".config",
        ".local/state",
        "dotfiles/git",
        ".local/dots/fish",
    ] {
        std::fs::create_dir_all(h.join(dir)).unwrap();
    }
    std::fs::write(h.join("dotfiles/git/config"), "[user]\n").unwrap();
    symlink(h.join("dotfiles/git"), h.join(".config/git")).unwrap();
    symlink(h.join(".local/dots/fish"), h.join(".config/fish")).unwrap();
    let script = r#"try() { what=$1; shift; if "$@" 2>/dev/null; then echo "$what ok"; else echo "$what refused"; fi; }
try fish sh -c 'echo "echo hi" > "$HOME/.config/fish/config.fish"'
try fishreal sh -c 'echo "echo hi" > "$HOME/.local/dots/fish/config.fish"'
try git sh -c 'echo "[alias]" >> "$HOME/.config/git/config"'
echo DONE
"#;
    let out = run_jail(&h, script, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("DONE"),
        "{stdout}\n{stderr}"
    );
    for what in ["fish", "fishreal", "git"] {
        assert!(
            stdout.lines().any(|l| l == format!("{what} refused")),
            "{what}: {stdout}\n{stderr}"
        );
    }
    for link in [".config/git", ".config/fish"] {
        assert!(
            stderr.contains(&format!("{link} goes through"))
                && stderr.contains("could replace the link"),
            "{link}: {stderr}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(h.join("dotfiles/git/config")).unwrap(),
        "[user]\n"
    );
    assert!(std::fs::read_dir(h.join(".local/dots/fish"))
        .unwrap()
        .next()
        .is_none());
}

/// The home's folders of programs in your `PATH` (`~/.local/bin` here)
/// are read-only in a real jail, so a program in it cannot leave a `git`
/// there that runs as you next; `starship.toml` at the top of
/// `~/.config` is read-only too, made empty first. With
/// `--writable-user-bin` the program folder takes the write, and the
/// launcher says what that lets a program in the jail do.
///
/// FAILS ON REVERT: leave the program folders writable by default, ignore
/// the flag, or leave `starship.toml` writable.
#[test]
fn your_program_folders_are_read_only_unless_you_ask() {
    let test = "your_program_folders_are_read_only_unless_you_ask";
    if !jail_opens_here(test) {
        return;
    }
    let script = r##"try() { what=$1; shift; if "$@" 2>/dev/null; then echo "$what ok"; else echo "$what refused"; fi; }
try bin sh -c 'printf "#!/bin/sh\n" > "$HOME/.local/bin/git"'
try cargobin sh -c 'printf "#!/bin/sh\n" > "$HOME/.cargo/bin/ls"'
try starship sh -c 'printf "[custom.x]\ncommand = \"true\"\n" > "$HOME/.config/starship.toml"'
echo DONE
"##;
    for writable in [false, true] {
        let home = tempfile::TempDir::new().unwrap();
        let h = std::fs::canonicalize(home.path()).unwrap();
        for dir in [".config", ".local/bin", ".local/state", ".cargo/bin"] {
            std::fs::create_dir_all(h.join(dir)).unwrap();
        }
        let out = if writable {
            let project = tempfile::TempDir::new().unwrap();
            let graph = tempfile::TempDir::new().unwrap();
            let mut command = Command::new(bin());
            command
                .args(["contain", "--writable-user-bin", "--project"])
                .arg(project.path())
                .args(["--", "/bin/sh", "-c", script])
                .env("HOME", &h)
                .env("IW_GRAPH_FILE", graph.path().join("graph.json"))
                .env_remove("XDG_STATE_HOME")
                .env_remove("XDG_CONFIG_HOME")
                .env_remove("XDG_DATA_HOME")
                .env_remove("XDG_DATA_DIRS");
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
            command.output().expect("run the jail")
        } else {
            run_jail(&h, script, &[])
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stdout.contains("DONE"),
            "{stdout}\n{stderr}"
        );
        let want = if writable { "ok" } else { "refused" };
        for what in ["bin", "cargobin"] {
            assert!(
                stdout.lines().any(|l| l == format!("{what} {want}")),
                "{what} {want}: {stdout}\n{stderr}"
            );
        }
        assert!(
            stdout.lines().any(|l| l == "starship refused"),
            "{stdout}\n{stderr}"
        );
        assert_eq!(h.join(".local/bin/git").exists(), writable);
        assert_eq!(
            std::fs::read_to_string(h.join(".config/starship.toml")).unwrap(),
            ""
        );
        assert_eq!(
            stderr.contains("--writable-user-bin:")
                && stderr.contains("runs as you, outside the jail"),
            writable,
            "{stderr}"
        );
    }
}
