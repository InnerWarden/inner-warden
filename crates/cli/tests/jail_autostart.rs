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
/// nothing of the jail's is in those folders: the folders the launcher
/// made for the jail stay there, empty.
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
/// folder in `~/.config` takes the write. On the host afterwards nothing
/// of the jail's is in those folders.
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
    // Nothing of the jail's on the host: the folders the launcher made
    // stay there, empty.
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
        // Made empty for the jail, and left there, empty.
        assert_eq!(std::fs::read(h.join(".config/starship.toml")).unwrap(), b"");
        assert_eq!(
            stderr.contains("--writable-user-bin:")
                && stderr.contains("runs as you, outside the jail"),
            writable,
            "{stderr}"
        );
    }
}

/// Runs `script` in a real jail of `project`, in the home `h`, with
/// `PATH` set to `path` on the launcher and every agent's marker taken
/// out.
fn run_jail_in(h: &Path, project: &Path, path: &str, script: &str) -> std::process::Output {
    let graph = tempfile::TempDir::new().unwrap();
    let mut command = Command::new(bin());
    command
        .args(["contain", "--project", project.to_str().unwrap()])
        .args(["--", "/bin/sh", "-c", script])
        .current_dir(project)
        .env("HOME", h)
        .env("PATH", path)
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
}

const TRY: &str = r##"try() { what=$1; shift; if "$@" 2>/dev/null; then echo "$what ok"; else echo "$what refused"; fi; }
"##;

/// Each `<what> <want>` line is in the jail's output, and it ran to its end.
fn assert_lines(out: &std::process::Output, want: &[(&str, &str)]) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("DONE"),
        "{stdout}\n{stderr}"
    );
    for (what, result) in want {
        assert!(
            stdout.lines().any(|l| l == format!("{what} {result}")),
            "{what} {result}: {stdout}\n{stderr}"
        );
    }
}

/// A folder of programs in `PATH` inside the project stays the project's
/// to write: an activated venv (`.venv/bin` there, or not made yet),
/// direnv's `node_modules/.bin`, the project itself in `PATH`, and a
/// project that is `~/bin`. The launcher makes no `.venv/bin` on the
/// host for a venv not there yet. Folders of programs outside the project
/// stay read-only.
///
/// FAILS ON REVERT: keep every folder of `PATH` in the home read-only
/// (the venv's `pytest`, the npm link and the project's own files are
/// refused, and an empty `.venv/bin` is left on the host).
#[test]
fn a_program_folder_in_the_project_stays_the_projects() {
    let test = "a_program_folder_in_the_project_stays_the_projects";
    if !jail_opens_here(test) {
        return;
    }
    let system = "/usr/local/bin:/usr/bin:/bin";
    // An activated venv that is there, and `node_modules/.bin`.
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    let p = h.join("work/proj");
    for dir in [
        ".local/bin",
        ".local/state",
        "work/proj/.venv/bin",
        "work/proj/node_modules/.bin",
    ] {
        std::fs::create_dir_all(h.join(dir)).unwrap();
    }
    let path = format!(
        "{}:{}:{}:{system}",
        p.join(".venv/bin").display(),
        p.join("node_modules/.bin").display(),
        h.join(".local/bin").display()
    );
    let script = format!(
        r##"{TRY}try pytest sh -c 'printf "#!/bin/sh\n" > "$PWD/.venv/bin/pytest"'
try npmlink ln -s ../pkg/cli.js "$PWD/node_modules/.bin/cli"
try userbin sh -c 'printf "#!/bin/sh\n" > "$HOME/.local/bin/git"'
echo DONE
"##
    );
    let out = run_jail_in(&h, &p, &path, &script);
    assert_lines(
        &out,
        &[("pytest", "ok"), ("npmlink", "ok"), ("userbin", "refused")],
    );
    assert!(p.join(".venv/bin/pytest").is_file());
    assert!(!h.join(".local/bin/git").exists());

    // A venv not made yet: nothing made on the host, and the jail makes it
    // whole.
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    let p = h.join("proj");
    for dir in [".local/state", "proj"] {
        std::fs::create_dir_all(h.join(dir)).unwrap();
    }
    let path = format!("{}:{system}", p.join(".venv/bin").display());
    let script = format!(
        r##"{TRY}try novenv test ! -e "$PWD/.venv"
try venv sh -c 'mkdir -p "$PWD/.venv/bin" && printf "#!/bin/sh\n" > "$PWD/.venv/bin/python"'
echo DONE
"##
    );
    let out = run_jail_in(&h, &p, &path, &script);
    assert_lines(&out, &[("novenv", "ok"), ("venv", "ok")]);
    assert!(p.join(".venv/bin/python").is_file());

    // The project in `PATH`, and a project that is `~/bin`.
    for named in ["proj", "bin"] {
        let home = tempfile::TempDir::new().unwrap();
        let h = std::fs::canonicalize(home.path()).unwrap();
        let p = h.join(named);
        for dir in [".local/state", named] {
            std::fs::create_dir_all(h.join(dir)).unwrap();
        }
        let path = format!("{}:{system}", p.display());
        let script = format!(
            r##"{TRY}try own sh -c 'echo x > "$PWD/notes.txt" && mkdir -p "$PWD/.git/objects"'
echo DONE
"##
        );
        let out = run_jail_in(&h, &p, &path, &script);
        assert_lines(&out, &[("own", "ok")]);
        assert!(p.join("notes.txt").is_file(), "{named}");
    }
}

/// What runs as you next from Python's user site, cargo's and rustup's
/// files, and what the links in your program folders lead to is read-only
/// in a real jail: a `.pth` or `usercustomize.py`, `~/.cargo/env`,
/// `~/.cargo/config.toml` and `~/.cargo/config` (made for the jail, empty),
/// a toolchain's `cargo` and its libraries, Claude Code's version a
/// `~/.local/bin` link runs and a pipx venv.
///
/// FAILS ON REVERT: leave any of those places writable (the write lands on
/// the host).
#[test]
fn what_python_cargo_rustup_and_your_links_run_next_is_read_only() {
    use std::os::unix::fs::symlink;
    let test = "what_python_cargo_rustup_and_your_links_run_next_is_read_only";
    if !jail_opens_here(test) {
        return;
    }
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    for dir in [
        ".config",
        ".local/bin",
        ".local/state",
        ".local/lib/python3.99/site-packages",
        ".local/share/claude/versions",
        ".local/share/pipx/venvs/black/bin",
        ".local/share/pipx/venvs/black/lib",
        ".cargo/bin",
        ".rustup/toolchains/stable-x/bin",
        ".rustup/toolchains/stable-x/lib",
    ] {
        std::fs::create_dir_all(h.join(dir)).unwrap();
    }
    std::fs::write(h.join(".cargo/env"), "export PATH=x\n").unwrap();
    std::fs::write(h.join(".rustup/toolchains/stable-x/bin/cargo"), "real\n").unwrap();
    std::fs::write(h.join(".local/share/claude/versions/9.9.9"), "real\n").unwrap();
    symlink(
        h.join(".local/share/claude/versions/9.9.9"),
        h.join(".local/bin/claude"),
    )
    .unwrap();
    std::fs::write(
        h.join(".local/share/pipx/venvs/black/pyvenv.cfg"),
        "home = /usr\n",
    )
    .unwrap();
    std::fs::write(h.join(".local/share/pipx/venvs/black/bin/black"), "real\n").unwrap();
    symlink(
        h.join(".local/share/pipx/venvs/black/bin/black"),
        h.join(".local/bin/black"),
    )
    .unwrap();
    let script = format!(
        r##"{TRY}try pth sh -c 'echo "import os" > "$HOME/.local/lib/python3.99/site-packages/x.pth"'
try usercustomize sh -c 'echo "import os" > "$HOME/.local/lib/python3.99/site-packages/usercustomize.py"'
try cargoenv sh -c 'echo "curl x | sh" >> "$HOME/.cargo/env"'
try cargoconfig sh -c 'printf "[build]\nrustc-wrapper = \"/tmp/w\"\n" > "$HOME/.cargo/config.toml"'
try cargolegacy sh -c 'printf "[build]\nrustc-wrapper = \"/tmp/w\"\n" > "$HOME/.cargo/config"'
try toolchain sh -c 'echo fake > "$HOME/.rustup/toolchains/stable-x/bin/cargo"'
try toolchainlib sh -c 'echo fake > "$HOME/.rustup/toolchains/stable-x/lib/librustc_driver.so"'
try claude sh -c 'echo fake > "$HOME/.local/share/claude/versions/9.9.9"'
try pipx sh -c 'echo fake > "$HOME/.local/share/pipx/venvs/black/lib/x.py"'
try agent sh -c 'echo kept > "$HOME/.local/share/other"'
echo DONE
"##
    );
    let path = format!("{}:/usr/bin:/bin", h.join(".local/bin").display());
    let project = tempfile::TempDir::new().unwrap();
    let p = std::fs::canonicalize(project.path()).unwrap();
    let out = run_jail_in(&h, &p, &path, &script);
    assert_lines(
        &out,
        &[
            ("pth", "refused"),
            ("usercustomize", "refused"),
            ("cargoenv", "refused"),
            ("cargoconfig", "refused"),
            ("cargolegacy", "refused"),
            ("toolchain", "refused"),
            ("toolchainlib", "refused"),
            ("claude", "refused"),
            ("pipx", "refused"),
            ("agent", "ok"),
        ],
    );
    assert_eq!(
        std::fs::read_to_string(h.join(".cargo/env")).unwrap(),
        "export PATH=x\n"
    );
    for name in [".cargo/config.toml", ".cargo/config"] {
        let meta = std::fs::metadata(h.join(name)).unwrap();
        assert_eq!(meta.len(), 0, "{name}");
    }
    assert_eq!(
        std::fs::read_to_string(h.join(".rustup/toolchains/stable-x/bin/cargo")).unwrap(),
        "real\n"
    );
    assert_eq!(
        std::fs::read_to_string(h.join(".local/share/claude/versions/9.9.9")).unwrap(),
        "real\n"
    );
    assert!(!h.join(".local/lib/python3.99/site-packages/x.pth").exists());
}

/// Every name in `dir`, below it, as paths from it. Sorted.
fn tree(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, at: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(at) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            out.push(path.strip_prefix(base).unwrap().display().to_string());
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                walk(base, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// While a second jail of the same home runs, the first, ending, takes
/// nothing away from it: the second still refuses a write to a place the
/// first made, and the folders made stay on the host, empty. A stale
/// entry of `PATH` that is a file opens the jail.
///
/// FAILS ON REVERT: refuse a file in `PATH`, or take what was made away
/// while another jail of the home runs (the late write lands).
#[test]
fn a_jail_ending_takes_nothing_from_another_of_the_home() {
    let test = "a_jail_ending_takes_nothing_from_another_of_the_home";
    if !jail_opens_here(test) {
        return;
    }
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    for dir in [".config/gh", ".local/state", ".cargo/registry"] {
        std::fs::create_dir_all(h.join(dir)).unwrap();
    }
    std::fs::write(h.join(".local/oldbin"), "a file").unwrap();
    let path = format!("{}:/usr/bin:/bin", h.join(".local/oldbin").display());
    let project = tempfile::TempDir::new().unwrap();
    let p = std::fs::canonicalize(project.path()).unwrap();

    // Two jails of the home at once: the first ends while the second
    // runs, and the second ends last.
    let spawn = |script: String| {
        let graph = tempfile::TempDir::new().unwrap();
        let mut command = Command::new(bin());
        command
            .args(["contain", "--project", p.to_str().unwrap()])
            .args(["--", "/bin/sh", "-c", &script])
            .current_dir(&p)
            .env("HOME", &h)
            .env("PATH", &path)
            .env("IW_GRAPH_FILE", graph.path().join("graph.json"))
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            .env_remove("XDG_DATA_DIRS")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
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
        (command.spawn().expect("run a jail"), graph)
    };
    let wait_for = |file: &Path| {
        let start = std::time::Instant::now();
        while !file.exists() {
            assert!(
                start.elapsed().as_secs() < 120,
                "{} never came",
                file.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    };
    let first = spawn(format!(
        r##"{TRY}touch "$PWD/first-runs"
while [ ! -e "$PWD/go-first" ]; do sleep 0.1; done
echo DONE
"##
    ));
    wait_for(&p.join("first-runs"));
    assert!(h.join(".config/fish").is_dir(), "made for the first jail");
    let second = spawn(format!(
        r##"{TRY}touch "$PWD/second-runs"
while [ ! -e "$PWD/go-second" ]; do sleep 0.1; done
try late sh -c 'echo "echo hi" > "$HOME/.config/fish/config.fish"'
echo DONE
"##
    ));
    wait_for(&p.join("second-runs"));
    std::fs::write(p.join("go-first"), "").unwrap();
    let out = first.0.wait_with_output().unwrap();
    assert_lines(&out, &[]);
    // The first ended while the second runs: nothing taken away.
    assert!(
        h.join(".config/fish").is_dir(),
        "taken away while a jail runs"
    );
    std::fs::write(p.join("go-second"), "").unwrap();
    let out = second.0.wait_with_output().unwrap();
    assert_lines(&out, &[("late", "refused")]);
    assert!(!h.join(".config/fish/config.fish").exists());
    // And a short jail alone, with the file in `PATH`.
    let short = run_jail_in(&h, &p, &path, &format!("{TRY}echo DONE\n"));
    assert_lines(&short, &[]);

    // Both ended: what was made stays, empty.
    assert!(tree(&h.join(".config/fish")).is_empty());
    assert_eq!(
        std::fs::read_to_string(h.join(".local/oldbin")).unwrap(),
        "a file"
    );
}

/// The jail of `script` in the home `h` and the project `p`, started and
/// not waited for, its output piped, every agent's marker taken out, and
/// `setup` applied to the launcher's command last.
fn launch(
    h: &Path,
    p: &Path,
    script: &str,
    setup: impl FnOnce(&mut Command),
) -> (std::process::Child, tempfile::TempDir) {
    launch_with(h, p, &[], script, setup)
}

/// [`launch`], with `flags` given to `contain` before the command.
fn launch_with(
    h: &Path,
    p: &Path,
    flags: &[&str],
    script: &str,
    setup: impl FnOnce(&mut Command),
) -> (std::process::Child, tempfile::TempDir) {
    let graph = tempfile::TempDir::new().unwrap();
    let mut command = Command::new(bin());
    command
        .args(["contain", "--project", p.to_str().unwrap()])
        .args(flags)
        .args(["--", "/bin/sh", "-c", script])
        .current_dir(p)
        .env("HOME", h)
        .env("IW_GRAPH_FILE", graph.path().join("graph.json"))
        .env_remove("XDG_STATE_HOME")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .env_remove("XDG_DATA_DIRS")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
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
    setup(&mut command);
    (command.spawn().expect("run a jail"), graph)
}

/// Waits (two minutes at most) for `file` to be there.
fn wait_for(file: &Path) {
    let start = std::time::Instant::now();
    while !file.exists() {
        assert!(
            start.elapsed().as_secs() < 120,
            "{} never came",
            file.display()
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// A folder like `/run/user/<uid>` in `dir`: this account's, 0700.
fn runtime_folder(dir: &tempfile::TempDir) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let rt = std::fs::canonicalize(dir.path()).unwrap().join("run");
    std::fs::create_dir(&rt).unwrap();
    std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o700)).unwrap();
    rt
}

/// The script of the jail that ends while the other runs.
const SHORT_RUN: &str = r##"touch "$PWD/b-runs"
while [ ! -e "$PWD/go-b" ]; do sleep 0.1; done
echo DONE
"##;

/// The script of the jail that runs on: once the other ended, it tries the
/// session's folders the other's launch made.
fn long_run() -> String {
    format!(
        r##"{TRY}touch "$PWD/a-runs"
while [ ! -e "$PWD/go-a" ]; do sleep 0.1; done
try autostart sh -c 'mkdir -p "$HOME/.config/autostart" && printf "[Desktop Entry]\nExec=true\n" > "$HOME/.config/autostart/x.desktop"'
try unit sh -c 'mkdir -p "$HOME/.config/systemd/user" && echo "[Service]" > "$HOME/.config/systemd/user/x.service"'
echo DONE
"##
    )
}

/// Two jails of one home: B opens first and its launch makes the session's
/// folders, A opens while B runs, B ends, then A writes to them. `b_env`
/// and `a_env` set each launch's environment; `between` runs once B's
/// jail runs, before A opens. A's writes are refused and nothing of them
/// is on the host.
fn two_jails_one_ends_first(
    test: &str,
    b_env: impl FnOnce(&mut Command),
    a_env: impl FnOnce(&mut Command),
    between: impl FnOnce(),
) {
    if !jail_opens_here(test) {
        return;
    }
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    for dir in [".config/myagent", ".local/state"] {
        std::fs::create_dir_all(h.join(dir)).unwrap();
    }
    let project = tempfile::TempDir::new().unwrap();
    let p = std::fs::canonicalize(project.path()).unwrap();
    let b = launch(&h, &p, SHORT_RUN, b_env);
    wait_for(&p.join("b-runs"));
    assert!(h.join(".config/autostart").is_dir(), "made for B");
    between();
    let a = launch(&h, &p, &long_run(), a_env);
    wait_for(&p.join("a-runs"));
    std::fs::write(p.join("go-b"), "").unwrap();
    let out = b.0.wait_with_output().unwrap();
    assert_lines(&out, &[]);
    assert!(
        h.join(".config/autostart").is_dir(),
        "taken away while A shows it"
    );
    std::fs::write(p.join("go-a"), "").unwrap();
    let out = a.0.wait_with_output().unwrap();
    assert_lines(&out, &[("autostart", "refused"), ("unit", "refused")]);
    assert!(!h.join(".config/autostart/x.desktop").exists());
    assert!(!h.join(".config/systemd/user/x.service").exists());
    assert!(tree(&h.join(".config/autostart")).is_empty());
}

/// A jail whose launch had no `XDG_RUNTIME_DIR` ends while one of the same
/// home that had one runs: the running jail's read-only places stay, so
/// its late autostart entry and user unit are refused and never reach the
/// host.
///
/// FAILS ON REVERT: take the places away when a jail ends, by a lock in
/// the runtime folder (B, alone with its lock in the temporary folder,
/// takes them away and A's writes land on the host).
#[test]
fn a_jail_ending_with_another_environment_leaves_the_running_one_its_places() {
    let runtime = tempfile::TempDir::new().unwrap();
    let rt = runtime_folder(&runtime);
    two_jails_one_ends_first(
        "a_jail_ending_with_another_environment_leaves_the_running_one_its_places",
        |command| {
            command.env_remove("XDG_RUNTIME_DIR");
        },
        |command| {
            command.env("XDG_RUNTIME_DIR", &rt);
        },
        || {},
    );
}

/// The launcher's files in the runtime folder vanish between two launches
/// of a home (logind empties it at the last logout, a jail still running
/// in tmux): the jail that ends first takes away nothing the other shows.
///
/// FAILS ON REVERT: take the places away when a jail ends, by a lock in
/// the runtime folder (B makes a new one, has it alone and takes them
/// away).
#[test]
fn the_runtime_folder_emptied_midway_takes_nothing_from_a_running_jail() {
    let runtime = tempfile::TempDir::new().unwrap();
    let rt = runtime_folder(&runtime);
    let empty = rt.clone();
    two_jails_one_ends_first(
        "the_runtime_folder_emptied_midway_takes_nothing_from_a_running_jail",
        |command| {
            command.env("XDG_RUNTIME_DIR", &rt);
        },
        |command| {
            command.env("XDG_RUNTIME_DIR", &rt);
        },
        move || {
            for entry in std::fs::read_dir(&empty).unwrap().flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("innerwarden-contain-")
                {
                    std::fs::remove_file(entry.path()).unwrap();
                }
            }
        },
    );
}

/// An OpenClaw jail (`--agent openclaw`) holds the places that run as the
/// person read-only too, made first where they are not there: with no
/// `~/.config/git`, git's config with a `hooksPath`, fish's startup file,
/// an autostart entry and `~/.cargo/env` are refused and never reach the
/// host.
///
/// FAILS ON REVERT: make the places only for Claude Code's jail (every
/// write lands on the host).
#[test]
fn an_openclaw_jail_holds_what_runs_as_you_read_only_too() {
    let test = "an_openclaw_jail_holds_what_runs_as_you_read_only_too";
    if !jail_opens_here(test) {
        return;
    }
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    let dir = h.join(".openclaw");
    std::fs::create_dir_all(dir.join("extensions/innerwarden-guard")).unwrap();
    std::fs::write(
        dir.join("extensions/innerwarden-guard/index.js"),
        "// guard\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("openclaw.json"),
        r#"{"plugins":{"entries":{"innerwarden-guard":{"enabled":true,"config":{"mode":"enforce"}}}}}"#,
    )
    .unwrap();
    for made in [".config", ".local/state", ".cargo"] {
        std::fs::create_dir_all(h.join(made)).unwrap();
    }
    let project = tempfile::TempDir::new().unwrap();
    let p = std::fs::canonicalize(project.path()).unwrap();
    let script = format!(
        r##"{TRY}try git sh -c 'mkdir -p "$HOME/.config/git" && printf "[core]\n\thooksPath = /tmp/h\n" > "$HOME/.config/git/config"'
try fish sh -c 'mkdir -p "$HOME/.config/fish" && echo "echo hi" > "$HOME/.config/fish/config.fish"'
try autostart sh -c 'mkdir -p "$HOME/.config/autostart" && printf "[Desktop Entry]\nExec=true\n" > "$HOME/.config/autostart/x.desktop"'
try cargoenv sh -c 'echo "curl x | sh" > "$HOME/.cargo/env"'
echo DONE
"##
    );
    let (child, _graph) = launch_with(&h, &p, &["--agent", "openclaw"], &script, |_| {});
    let out = child.wait_with_output().unwrap();
    assert_lines(
        &out,
        &[
            ("git", "refused"),
            ("fish", "refused"),
            ("autostart", "refused"),
            ("cargoenv", "refused"),
        ],
    );
    assert!(!h.join(".config/git/config").exists());
    assert!(!h.join(".config/fish/config.fish").exists());
    assert!(!h.join(".config/autostart/x.desktop").exists());
    assert_eq!(std::fs::read(h.join(".cargo/env")).unwrap(), b"");
}

/// While a jail runs, the person edits `~/.cargo/config.toml` on the host
/// with `sed -i` (a new file in its place): cargo on the host reads the
/// new config and warns of nothing, and after the jail `~/.cargo/config`
/// is still the empty file made for the jail and `config.toml` holds the
/// edit. In the jail the legacy `config` is still refused.
///
/// FAILS ON REVERT: make `config` a second name of `config.toml` (after
/// the edit the host's cargo reads the old one, warns that both exist, and
/// `config` holds the old content).
#[test]
fn editing_cargos_config_during_a_jail_leaves_no_second_config() {
    let test = "editing_cargos_config_during_a_jail_leaves_no_second_config";
    if !jail_opens_here(test) {
        return;
    }
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    for dir in [".config", ".local/state", ".cargo"] {
        std::fs::create_dir_all(h.join(dir)).unwrap();
    }
    std::fs::write(
        h.join(".cargo/config.toml"),
        "[alias]\nbefore = \"version\"\n",
    )
    .unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let p = std::fs::canonicalize(project.path()).unwrap();
    let script = format!(
        r##"{TRY}touch "$PWD/runs"
while [ ! -e "$PWD/go" ]; do sleep 0.1; done
try cargolegacy sh -c 'printf "[build]\nrustc-wrapper = \"/tmp/w\"\n" > "$HOME/.cargo/config"'
echo DONE
"##
    );
    let (child, _graph) = launch(&h, &p, &script, |_| {});
    wait_for(&p.join("runs"));
    let sed = Command::new("sed")
        .args(["-i", "s/before =/after =/"])
        .arg(h.join(".cargo/config.toml"))
        .status()
        .unwrap();
    assert!(sed.success());
    let elsewhere = tempfile::TempDir::new().unwrap();
    let cargo = Command::new(env!("CARGO"))
        .arg("after")
        .current_dir(elsewhere.path())
        .env("CARGO_HOME", h.join(".cargo"))
        .env("HOME", &h)
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&cargo.stderr);
    assert!(cargo.status.success(), "the host's cargo: {said}");
    assert!(!said.contains("both"), "the host's cargo: {said}");
    std::fs::write(p.join("go"), "").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_lines(&out, &[("cargolegacy", "refused")]);
    assert_eq!(
        std::fs::symlink_metadata(h.join(".cargo/config"))
            .unwrap()
            .len(),
        0,
        "config holds something"
    );
    assert_eq!(
        std::fs::read_to_string(h.join(".cargo/config.toml")).unwrap(),
        "[alias]\nafter = \"version\"\n"
    );
}

/// A Ctrl-C (SIGINT to the launcher's process group) while the jail runs
/// ends the jail and the launcher soon after.
///
/// FAILS ON REVERT: keep the jail running past the Ctrl-C.
#[test]
fn a_ctrl_c_ends_the_jail() {
    use std::os::unix::process::CommandExt;
    let test = "a_ctrl_c_ends_the_jail";
    if !jail_opens_here(test) {
        return;
    }
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    for dir in [".config/myagent", ".local/state", ".cargo"] {
        std::fs::create_dir_all(h.join(dir)).unwrap();
    }
    let project = tempfile::TempDir::new().unwrap();
    let p = std::fs::canonicalize(project.path()).unwrap();
    let (child, _graph) = launch(
        &h,
        &p,
        "touch \"$PWD/runs\"; sleep 60; echo DONE",
        |command| {
            command.process_group(0);
        },
    );
    wait_for(&p.join("runs"));
    assert!(h.join(".config/fish").is_dir(), "made for the jail");
    let group = format!("-{}", child.id());
    let kill = Command::new("kill")
        .args(["-INT", "--", &group])
        .status()
        .unwrap();
    assert!(kill.success());
    let start = std::time::Instant::now();
    let out = child.wait_with_output().unwrap();
    assert!(
        start.elapsed().as_secs() < 30,
        "the jail outlived the Ctrl-C"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("DONE"), "{stdout}");
}

/// Eight jails of one home opened within about 0.7 s, half with an
/// `XDG_RUNTIME_DIR` and half without, five rounds on a new home each:
/// each jail tries an autostart entry, a user unit and `~/.cargo/env`.
/// None of it reaches the host, and no jail opens without its read-only
/// places: one either opens and is refused all three, or does not open.
///
/// FAILS ON REVERT: take the places away when a jail ends (a jail that
/// opens later finds them gone and opens without them, and its writes
/// land), or open a jail whose final plan still misses a place.
#[test]
fn jails_opened_at_once_never_open_without_their_places() {
    let test = "jails_opened_at_once_never_open_without_their_places";
    if !jail_opens_here(test) {
        return;
    }
    let runtime = tempfile::TempDir::new().unwrap();
    let rt = runtime_folder(&runtime);
    let script = format!(
        r##"{TRY}try autostart sh -c 'mkdir -p "$HOME/.config/autostart" && printf "[Desktop Entry]\nExec=true\n" > "$HOME/.config/autostart/x.desktop"'
try unit sh -c 'mkdir -p "$HOME/.config/systemd/user" && echo "[Service]" > "$HOME/.config/systemd/user/x.service"'
try cargoenv sh -c 'echo "curl x | sh" >> "$HOME/.cargo/env"'
echo DONE
"##
    );
    let (mut opened, mut not_opened) = (0, 0);
    for round in 0..5 {
        let home = tempfile::TempDir::new().unwrap();
        let h = std::fs::canonicalize(home.path()).unwrap();
        for dir in [".config/myagent", ".local/state", ".cargo/bin"] {
            std::fs::create_dir_all(h.join(dir)).unwrap();
        }
        let projects: Vec<tempfile::TempDir> =
            (0..8).map(|_| tempfile::TempDir::new().unwrap()).collect();
        let mut jails = Vec::new();
        for (i, project) in projects.iter().enumerate() {
            let p = std::fs::canonicalize(project.path()).unwrap();
            let rt = rt.clone();
            jails.push(launch(&h, &p, &script, move |command| {
                if i % 2 == 0 {
                    command.env("XDG_RUNTIME_DIR", &rt);
                } else {
                    command.env_remove("XDG_RUNTIME_DIR");
                }
            }));
            std::thread::sleep(std::time::Duration::from_millis(90));
        }
        for (child, _graph) in jails {
            let out = child.wait_with_output().unwrap();
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stdout.contains("DONE") {
                opened += 1;
                assert_lines(
                    &out,
                    &[
                        ("autostart", "refused"),
                        ("unit", "refused"),
                        ("cargoenv", "refused"),
                    ],
                );
            } else {
                not_opened += 1;
                assert!(!out.status.success(), "round {round}: {stdout}\n{stderr}");
                assert!(
                    !stdout.lines().any(|line| line.ends_with(" ok")),
                    "round {round}: {stdout}\n{stderr}"
                );
            }
        }
        assert!(
            !h.join(".config/autostart/x.desktop").exists(),
            "round {round}: autostart"
        );
        assert!(
            !h.join(".config/systemd/user/x.service").exists(),
            "round {round}: unit"
        );
        assert_eq!(
            std::fs::read(h.join(".cargo/env")).unwrap_or_default(),
            b"",
            "round {round}: cargo env"
        );
    }
    let _ = std::io::stderr()
        .write_all(format!("{test}: {opened} opened, {not_opened} did not\n").as_bytes());
    assert!(opened > 0, "no jail opened");
}

/// A small crate in `p`, for cargo to read.
fn small_crate(p: &Path) {
    std::fs::create_dir_all(p.join("src")).unwrap();
    std::fs::write(
        p.join("Cargo.toml"),
        "[package]\nname = \"small\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(p.join("src/main.rs"), "fn main() {}\n").unwrap();
}

/// The real cargo of this build, run on the host in `p` with the home
/// `h`'s cargo folder: `args` and what it said on stderr, once it ran
/// to success.
fn host_cargo(h: &Path, p: &Path, args: &[&str], when: &str) -> String {
    let out = Command::new(env!("CARGO"))
        .args(args)
        .current_dir(p)
        .env("CARGO_HOME", h.join(".cargo"))
        .env("HOME", h)
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "the host's cargo {when}: {said}");
    said
}

/// With neither of cargo's config files there (rustup's default), the
/// real cargo works in the jail and on the host, while the jail runs and
/// after it, warning of nothing: `config.toml` is made empty and
/// readable, `config` with no permission. With only the person's legacy
/// `config` (an alias in it), cargo on the host still runs the alias,
/// during and after the jail, and says nothing new (only its usual
/// deprecation line). The jail cannot write either file.
///
/// FAILS ON REVERT: make both files with no permission (cargo fails with
/// "Permission denied" on `config.toml`, in the jail and on the host), or
/// make `config.toml` readable beside the person's `config` (cargo warns
/// that both exist).
#[test]
fn the_real_cargo_works_in_and_out_of_a_jail() {
    use std::os::unix::fs::PermissionsExt;
    let test = "the_real_cargo_works_in_and_out_of_a_jail";
    if !jail_opens_here(test) {
        return;
    }
    for legacy in [false, true] {
        let home = tempfile::TempDir::new().unwrap();
        let h = std::fs::canonicalize(home.path()).unwrap();
        for dir in [".config", ".local/state", ".cargo/bin"] {
            std::fs::create_dir_all(h.join(dir)).unwrap();
        }
        if legacy {
            std::fs::write(h.join(".cargo/config"), "[alias]\nmine = \"version\"\n").unwrap();
        }
        let project = tempfile::TempDir::new().unwrap();
        let p = std::fs::canonicalize(project.path()).unwrap();
        small_crate(&p);
        // The real home is not in the jail: the jail runs a copy of this
        // build's cargo, in the project.
        std::fs::create_dir_all(p.join("tools")).unwrap();
        std::fs::copy(env!("CARGO"), p.join("tools/cargo")).unwrap();
        let run = if legacy {
            "mine"
        } else {
            "metadata --no-deps --offline --format-version 1"
        };
        let script = format!(
            r##"{TRY}touch "$PWD/runs"
while [ ! -e "$PWD/go" ]; do sleep 0.1; done
try incargo sh -c 'CARGO_HOME="$HOME/.cargo" "$PWD/tools/cargo" {run} >/dev/null 2>"$PWD/incargo.err"'
try cargoconfig sh -c 'printf "[build]\nrustc-wrapper = \"/tmp/w\"\n" > "$HOME/.cargo/config.toml"'
try cargolegacy sh -c 'printf "[build]\nrustc-wrapper = \"/tmp/w\"\n" > "$HOME/.cargo/config"'
echo DONE
"##
        );
        let (child, _graph) = launch(&h, &p, &script, |_| {});
        wait_for(&p.join("runs"));
        let args: Vec<&str> = run.split(' ').collect();
        let check = |said: &str, when: &str| {
            assert!(!said.contains("both"), "{when}: {said}");
            assert!(!said.contains("ermission"), "{when}: {said}");
            assert_eq!(said.contains("deprecated"), legacy, "{when}: {said}");
        };
        check(&host_cargo(&h, &p, &args, "during"), "during");
        std::fs::write(p.join("go"), "").unwrap();
        let out = child.wait_with_output().unwrap();
        let in_jail = std::fs::read_to_string(p.join("incargo.err")).unwrap_or_default();
        assert!(
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|line| line == "incargo ok"),
            "the jail's cargo: {in_jail}"
        );
        assert_lines(
            &out,
            &[
                ("incargo", "ok"),
                ("cargoconfig", "refused"),
                ("cargolegacy", "refused"),
            ],
        );
        check(&in_jail, "in the jail");
        check(&host_cargo(&h, &p, &args, "after"), "after");
        let mode = |name: &str| {
            std::fs::symlink_metadata(h.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        if legacy {
            assert_eq!(mode(".cargo/config.toml"), 0, "legacy: config.toml");
            assert_eq!(
                std::fs::read_to_string(h.join(".cargo/config")).unwrap(),
                "[alias]\nmine = \"version\"\n"
            );
        } else {
            assert_ne!(
                mode(".cargo/config.toml") & 0o400,
                0,
                "config.toml unreadable"
            );
            assert_eq!(mode(".cargo/config"), 0, "config");
            assert_eq!(std::fs::read(h.join(".cargo/config.toml")).unwrap(), b"");
        }
    }
}
