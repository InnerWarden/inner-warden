//! A Linux jail's programs cannot reach an abstract unix socket made outside
//! the jail (an X server's `@/tmp/.X11-unix/X0` among them), and still
//! reach what the jail's work needs: TCP, a unix socket by its path, and an
//! abstract socket they made themselves.
//!
//! The jail shares the host's network namespace, where abstract sockets
//! live; the jail's command starts through `innerwarden contain-exec`,
//! which puts it under Landlock's abstract socket scope (Linux 6.12). On an
//! older kernel the command still starts and the jail says so.
#![cfg(target_os = "linux")]

use std::io::Write;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// Child mode of this test binary: set in the environment of the probe the
/// tests below start, never in a normal run.
const PROBE: &str = "IW_TEST_ABSTRACT_PROBE";

/// The highest Landlock ABI this kernel runs, `None` where it runs none.
fn landlock_abi() -> Option<i64> {
    // SAFETY: the version question (flag 1) reads no ruleset.
    let v = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            1 as libc::c_uint,
        )
    };
    (v >= 0).then_some(v)
}

fn scopes_here() -> bool {
    landlock_abi().is_some_and(|abi| abi >= 6)
}

/// An abstract name shaped like an X display's, one no real display uses.
fn display_like_name(tag: &str) -> String {
    format!(
        "/tmp/.X11-unix/X{}{}",
        7000 + std::process::id() % 2000,
        tag
    )
}

fn abstract_listener(name: &str) -> UnixListener {
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    UnixListener::bind_addr(&addr).expect("bind an abstract socket")
}

/// What a connect gave: `ok` or the errno.
fn connect_abstract(name: &str) -> String {
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    match UnixStream::connect_addr(&addr) {
        Ok(_) => "ok".into(),
        Err(e) => format!("errno{}", e.raw_os_error().unwrap_or(-1)),
    }
}

/// The probe, when run as the command of `contain-exec`: one line per
/// connect, on stdout. A normal run of the suite does nothing here.
#[test]
fn probe_connects_when_asked() {
    let Ok(outside) = std::env::var(PROBE) else {
        return;
    };
    let own = format!("{outside}-own");
    let _own = abstract_listener(&own);
    let tcp = std::env::var("IW_TEST_TCP").unwrap();
    let path = std::env::var("IW_TEST_PATH").unwrap();
    let tcp = match std::net::TcpStream::connect(tcp) {
        Ok(_) => "ok".into(),
        Err(e) => format!("errno{}", e.raw_os_error().unwrap_or(-1)),
    };
    let path = match UnixStream::connect(path) {
        Ok(_) => "ok".into(),
        Err(e) => format!("errno{}", e.raw_os_error().unwrap_or(-1)),
    };
    let mut out = std::io::stdout();
    writeln!(
        out,
        "\nPROBE outside={} own={} tcp={} path={}",
        connect_abstract(&outside),
        connect_abstract(&own),
        tcp,
        path
    )
    .unwrap();
}

/// The probe's line, from a run's stdout.
fn probe_line(stdout: &str) -> String {
    stdout
        .lines()
        .find(|l| l.starts_with("PROBE "))
        .unwrap_or_else(|| panic!("no probe line: {stdout}"))
        .to_string()
}

/// The command `contain-exec` replaces itself with keeps the scope across
/// `exec`: an abstract socket made outside answers `EPERM`; the probe's
/// own abstract socket, TCP and a unix socket by its path still connect.
/// On a kernel without scopes everything connects, and the verb says why.
///
/// FAILS ON REVERT: drop the Landlock call from `contain-exec`, or handle
/// file or network access in its ruleset (the path or TCP connect fails).
#[test]
fn contain_scope_refuses_abstract_sockets_made_outside_only() {
    let outside = display_like_name("a");
    let _x = abstract_listener(&outside);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("s");
    let _path = UnixListener::bind(&path).unwrap();
    let out = Command::new(bin())
        .arg("contain-exec")
        .arg("--")
        .arg(std::env::current_exe().unwrap())
        .args([
            "probe_connects_when_asked",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROBE, &outside)
        .env("IW_TEST_TCP", tcp.local_addr().unwrap().to_string())
        .env("IW_TEST_PATH", &path)
        .output()
        .expect("run contain-exec");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stdout}\n{stderr}");
    let line = probe_line(&stdout);
    if scopes_here() {
        assert_eq!(
            line,
            format!("PROBE outside=errno{} own=ok tcp=ok path=ok", libc::EPERM),
            "{stderr}"
        );
        assert!(!stderr.contains("Linux 6.12"), "{stderr}");
    } else {
        assert_eq!(line, "PROBE outside=ok own=ok tcp=ok path=ok", "{stderr}");
        assert!(stderr.contains("Linux 6.12 or later"), "{stderr}");
    }
}

/// The verb runs nothing without `-- <command>`.
#[test]
fn contain_scope_without_a_command_runs_nothing() {
    for args in [&[][..], &["--"][..], &["ls"][..]] {
        let out = Command::new(bin())
            .arg("contain-exec")
            .args(args)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }
}

/// Whether a jail opens here (the same measure as the jail suite): a bwrap
/// refused its uid map under `apparmor_restrict_unprivileged_userns = 1`
/// skips outside CI, and fails in CI.
fn jail_opens_here(test: &str) -> bool {
    let Some(bwrap) = ["/usr/bin/bwrap", "/usr/local/bin/bwrap"]
        .iter()
        .map(std::path::Path::new)
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

/// A real jail: its command cannot connect to a display-shaped abstract
/// socket made outside it, and still makes and reaches its own, reaches TCP
/// on the host's loopback, and starts as before. Python, where the host has
/// it, is the jail's command: the test binary sits in a target folder the
/// jail may not show.
///
/// FAILS ON REVERT: start the jail's command without `contain-exec`.
#[test]
fn a_jail_cannot_reach_an_abstract_socket_made_outside_it() {
    let test = "a_jail_cannot_reach_an_abstract_socket_made_outside_it";
    if !jail_opens_here(test) {
        return;
    }
    let Some(python) = ["/usr/bin/python3", "/bin/python3"]
        .iter()
        .find(|p| std::path::Path::new(p).is_file())
    else {
        assert!(std::env::var_os("CI").is_none(), "{test}: no python3");
        let _ = std::io::stderr().write_all(format!("SKIPPED {test}: no python3\n").as_bytes());
        return;
    };
    let outside = display_like_name("j");
    let _x = abstract_listener(&outside);
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join(".local/state")).unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let graph = tempfile::TempDir::new().unwrap();
    let script = "import os, socket\n\
def go(fam, addr):\n\
    s = socket.socket(fam)\n\
    try:\n\
        s.connect(addr)\n\
        return 'ok'\n\
    except OSError as e:\n\
        return 'errno%d' % e.errno\n\
own = socket.socket(socket.AF_UNIX)\n\
own.bind('\\0' + os.environ['IW_OUT'] + '-own')\n\
own.listen(1)\n\
host, port = os.environ['IW_TCP'].rsplit(':', 1)\n\
print('PROBE outside=%s own=%s tcp=%s' % (\n\
    go(socket.AF_UNIX, '\\0' + os.environ['IW_OUT']),\n\
    go(socket.AF_UNIX, '\\0' + os.environ['IW_OUT'] + '-own'),\n\
    go(socket.AF_INET, (host, int(port)))))\n";
    let mut command = Command::new(bin());
    command
        .args(["contain", "--project", project.path().to_str().unwrap()])
        .args(["--pass-env", "IW_OUT", "--pass-env", "IW_TCP"])
        .args(["--", python, "-c", script])
        .env("HOME", home.path())
        .env("IW_GRAPH_FILE", graph.path().join("graph.json"))
        .env("IW_OUT", &outside)
        .env("IW_TCP", tcp.local_addr().unwrap().to_string())
        .env_remove("XDG_STATE_HOME");
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
    assert!(out.status.success(), "{stdout}\n{stderr}");
    let line = probe_line(&stdout);
    if scopes_here() {
        assert_eq!(
            line,
            format!("PROBE outside=errno{} own=ok tcp=ok", libc::EPERM),
            "{stderr}"
        );
    } else {
        assert_eq!(line, "PROBE outside=ok own=ok tcp=ok", "{stderr}");
        assert!(stderr.contains("Linux 6.12 or later"), "{stderr}");
    }
}
