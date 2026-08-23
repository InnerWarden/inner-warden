//! Asking a subcommand to explain itself must EXPLAIN, and must do nothing else.
//!
//! `innerwarden allow --help` used to reach the writer that maintains the
//! guardrail's own bypass list, take `--help` as the pattern, and print success.
//! `suppress.toml` became `allow = ["--help"]`, and screening the command
//! `--help` then returned ALLOW with `[suppressed: allow --help]`. `mute --help`
//! was worse: it is not an `ATR-` id, so it landed in `mute_categories`, and a
//! muted CATEGORY suppresses every rule in it against every command.
//!
//! The blast radius was wider than the two suppression verbs: `setup --help` ran
//! the wizard, `status --help` ran the full report, `contain`, `enforce` and
//! `dry-run` errored, and `install --help` / `uninstall --help` printed the
//! TOP-LEVEL help, which looks handled and says nothing about the verb you asked
//! about.
//!
//! These run the real binary, because the defect was in what the process did to
//! the disk, not in what a function returned.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// Every invocation is pointed at a disposable home, so a test can assert on the
/// files a command wrote WITHOUT touching the developer's own config or record.
/// stdin is `/dev/null`: a verb that reads it (`check`, `hook`) must not hang the
/// suite waiting for input that will never come.
fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("IW_GRAPH_FILE", home.join("graph.json"))
        .env("IW_SUPPRESS_CONFIG", home.join("suppress.toml"))
        .env("IW_NOTIFY_CONFIG", home.join("notify.toml"))
        .stdin(Stdio::null())
        .output()
        .expect("run innerwarden")
}

fn run_with_stdin(home: &Path, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(bin())
        .args(args)
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("IW_GRAPH_FILE", home.join("graph.json"))
        .env("IW_SUPPRESS_CONFIG", home.join("suppress.toml"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn innerwarden");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input)
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn home() -> tempfile::TempDir {
    tempfile::TempDir::new().expect("disposable home")
}

/// Every verb this binary answers itself. `update` and `self-update` are aliases
/// of `upgrade`, and `monitor` of `dry-run`: an alias that explains a DIFFERENT
/// command's name is how you learn a command you cannot then find.
const VERBS: &[&str] = &[
    "check",
    "serve",
    "proxy",
    "hook",
    "setup",
    "dashboard",
    "upgrade",
    "update",
    "self-update",
    "install",
    "uninstall",
    "status",
    "agents",
    "contain",
    "enforce",
    "dry-run",
    "monitor",
    "allow",
    "mute",
    "notify",
    "observe",
    "graph",
    "llm",
    "host",
];

/// Every verb answers with ITS OWN usage, for both spellings of the flag.
///
/// The two assertions are the ones a previous attempt at this fix got wrong.
///
/// The first line must open with `innerwarden <verb>`: `install --help` and
/// `uninstall --help` printed the TOP-LEVEL help, which satisfies any weaker
/// check like "usage was printed" while telling you nothing about the verb you
/// asked about.
///
/// The footer must be there too, because several commands' NORMAL output also
/// opens with their own name: `llm --help` used to print `innerwarden llm - not
/// configured ...`, and `agents --help` its own help with no footer. Requiring
/// both means the output has to come from the per-verb usage table.
#[test]
fn every_verb_explains_itself_rather_than_running() {
    let home = home();
    for verb in VERBS {
        for flag in ["--help", "-h"] {
            let out = run(home.path(), &[verb, flag]);
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert_eq!(
                out.status.code(),
                Some(0),
                "`innerwarden {verb} {flag}` must succeed. stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let first = stdout.lines().next().unwrap_or_default();
            assert!(
                first.starts_with(&format!("innerwarden {verb}")),
                "`innerwarden {verb} {flag}` must open with `innerwarden {verb}`, \
                 not with another command's usage. Got: {first}"
            );
            assert!(
                stdout.contains("Full command list: innerwarden --help"),
                "`innerwarden {verb} {flag}` printed something other than its usage:\n{stdout}"
            );
        }
    }
}

/// THE DEFECT, as the security property it is.
///
/// `allow` and `mute` maintain the list that turns the guardrail OFF for a
/// pattern. Asking either of them for usage must leave that file BYTE
/// IDENTICAL: not "roughly the same", not "without the word help in it".
#[test]
fn asking_the_suppression_verbs_for_help_leaves_the_config_byte_identical() {
    let home = home();
    let config = home.path().join("suppress.toml");
    std::fs::write(
        &config,
        "allow = [\"git status\"]\nmute_rules = [\"ATR-2026-051\"]\nmute_categories = []\n",
    )
    .expect("seed a suppression config");
    let before = std::fs::read(&config).expect("read seeded config");

    for verb in ["allow", "mute"] {
        for flag in ["--help", "-h"] {
            let out = run(home.path(), &[verb, flag]);
            assert!(out.status.success());
            assert_eq!(
                std::fs::read(&config).expect("config still readable"),
                before,
                "`innerwarden {verb} {flag}` edited the guardrail's own bypass list"
            );
        }
    }
}

/// The same property on a machine that has never suppressed anything: the file
/// must not be CREATED either. A bypass list that springs into existence from a
/// request for usage is the same defect with an empty starting point.
#[test]
fn asking_for_help_does_not_create_a_suppression_config() {
    let home = home();
    let config = home.path().join("suppress.toml");
    for verb in ["allow", "mute"] {
        let out = run(home.path(), &[verb, "--help"]);
        assert!(out.status.success());
        assert!(
            !config.exists(),
            "`innerwarden {verb} --help` created {}",
            config.display()
        );
    }
}

/// The consequence the operator actually saw, screened end to end.
///
/// With `--help` written into the allow list, screening the command `--help`
/// came back ALLOW with `[suppressed: allow --help]`. The verdict must be the
/// RULE engine's, with no suppression in it.
///
/// This deliberately uses the stdin form. `innerwarden check -- --help` would be
/// intercepted as a help request by a blanket implementation of this fix, so a
/// probe written that way passes against a config that HAS been widened, which
/// is exactly how the previous attempt's end-to-end test proved nothing.
#[test]
fn the_literal_help_flag_is_screened_on_its_merits_after_asking_for_help() {
    let home = home();
    for verb in ["allow", "mute"] {
        assert!(run(home.path(), &[verb, "--help"]).status.success());
    }
    let out = run_with_stdin(home.path(), &["check"], b"--help\n");
    let verdict: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "`check` on stdin must print a verdict, not usage ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(verdict["command"], "--help");
    let explanation = verdict["explanation"].as_str().unwrap_or_default();
    assert!(
        !explanation.contains("suppressed"),
        "asking for help put `--help` in the bypass list: {explanation}"
    );
    assert_ne!(
        verdict["decided_by"], "user",
        "nothing the user typed here was a suppression decision"
    );
}

/// THE CARVE-OUT. `check`'s argument IS the command being screened, so a blanket
/// intercept would turn a DENY into usage and exit 0.
#[test]
fn a_dangerous_command_that_carries_a_help_flag_is_still_denied() {
    let home = home();
    let out = run(home.path(), &["check", "rm", "-rf", "/", "--help"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "`check rm -rf / --help` must still deny (exit 1), not print usage. stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let verdict: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("a verdict, not usage");
    assert_eq!(verdict["recommendation"], "deny");
    assert_eq!(verdict["command"], "rm -rf / --help");
}

/// A lone `--help` with nothing else to screen is a request for usage, and the
/// output flags do not change that: they shape the OUTPUT, they are not a
/// command.
#[test]
fn check_still_explains_itself_when_there_is_nothing_to_screen() {
    let home = home();
    for args in [
        vec!["check", "--help"],
        vec!["check", "-h"],
        vec!["check", "--json", "--help"],
    ] {
        let out = run(home.path(), &args);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{args:?} must succeed");
        assert!(
            stdout.starts_with("innerwarden check"),
            "{args:?} must print `check`'s usage. Got: {stdout}"
        );
    }
}

/// The other carve-out: `contain` and `proxy` WRAP a child command, and the
/// child's flags are not ours to answer.
#[test]
fn a_wrapped_child_command_keeps_its_own_help_flag() {
    let home = home();
    let project = tempfile::TempDir::new().expect("project outside home");

    // `contain --dry-run` builds the jail and runs nothing, so this asserts what
    // was PLANNED for the child without executing it.
    let contained = run(
        home.path(),
        &[
            "contain",
            "--dry-run",
            "--project",
            project.path().to_str().expect("utf-8 path"),
            "--",
            "echo",
            "--help",
        ],
    );
    let stdout = String::from_utf8_lossy(&contained.stdout);
    assert!(
        !stdout.contains("Full command list"),
        "`--help` after `--` belongs to the jailed command: {stdout}"
    );
    assert!(
        stdout.contains("innerwarden contain - DRY RUN"),
        "the jail should have been planned: {stdout}{}",
        String::from_utf8_lossy(&contained.stderr)
    );

    // The proxy hands the wrapped server its own command line, `--help` included.
    let proxied = run(
        home.path(),
        &["proxy", "--mode", "advisory", "--", "echo", "--help"],
    );
    assert!(
        !String::from_utf8_lossy(&proxied.stdout).contains("Full command list"),
        "`--help` after `--` belongs to the wrapped server"
    );
}

/// `setup --help` RAN THE WIZARD, and `status --help` ran the full report. A
/// request for usage must not be a request to do the thing.
#[test]
fn the_verbs_that_used_to_run_anyway_now_only_explain() {
    let home = home();
    for (verb, marker) in [
        ("setup", "Optional extras can be enabled later"),
        ("status", "[unknown] never means off"),
    ] {
        let out = run(home.path(), &[verb, "--help"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.contains(marker),
            "`innerwarden {verb} --help` ran the command instead of explaining it:\n{stdout}"
        );
    }
}

/// `uninstall` with no named agent removes the hook, the config directory and
/// THE BINARY. Asking it for usage must remove none of them.
#[test]
fn asking_uninstall_for_help_removes_nothing() {
    let home = home();
    let claude = home.path().join(".claude");
    std::fs::create_dir_all(&claude).expect("fake agent config");
    let settings = claude.join("settings.json");
    std::fs::write(
        &settings,
        "{\"hooks\":{\"PreToolUse\":[{\"matcher\":\"Bash\",\"hooks\":[{\"type\":\"command\",\
         \"command\":\"/usr/local/bin/innerwarden hook\"}]}]}}",
    )
    .expect("seed a wired hook");
    let before = std::fs::read(&settings).expect("read seeded settings");

    for flag in ["--help", "-h"] {
        let out = run(home.path(), &["uninstall", flag]);
        assert!(out.status.success(), "`uninstall {flag}` must succeed");
        assert_eq!(
            std::fs::read(&settings).expect("settings still there"),
            before,
            "`innerwarden uninstall {flag}` removed the guard hook"
        );
        assert!(
            Path::new(bin()).exists(),
            "`innerwarden uninstall {flag}` removed the binary"
        );
    }
}

/// An Active Defence verb must NOT be answered here. `innerwarden get --help`
/// belongs to the host layer: with Active Defence installed it is delegated,
/// and without it, it explains how to get it. Answering it here would make the
/// paid layer's own usage unreachable through this binary.
#[test]
fn a_host_verb_is_not_answered_by_the_community_binary() {
    let home = home();
    let out = run(home.path(), &["get", "--help"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("Full command list"),
        "`get --help` must reach the host layer or the upsell, not this table:\n{stdout}"
    );
    assert_ne!(
        out.status.code(),
        Some(0),
        "without Active Defence installed, a host verb does not succeed quietly"
    );
}
