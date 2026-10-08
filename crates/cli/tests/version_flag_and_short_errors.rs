//! `innerwarden -v` must print the version, and a typo must not bury its own error.
//!
//! # The defect this pins
//!
//! Observed on a real host. `innerwarden -v` answered:
//!
//! ```text
//! innerwarden: unknown command `-v`
//!
//! innerwarden 1.4.1 - InnerWarden Community Edition
//! ... 60 more lines of USAGE ...
//! ```
//!
//! Two separate failures that compound. `-v` is the near-universal short form
//! for version and it was the one short form missing: `--version`, `-V` and
//! `version` all worked. And the failure path printed the entire help, 61 lines
//! that wrap to 88 on an 80-column terminal, so the single line explaining the
//! problem scrolled off the top. The reader saw a wall of usage and no error.
//!
//! # Why this runs the real binary
//!
//! `unknown_command_lines` is unit-tested for shape. What a unit test cannot
//! show is that dispatch REACHES it, that `-v` is routed to the version arm
//! before it can be treated as a verb, and how many lines actually land on the
//! terminal. That is the half that was wrong, so this measures the real output.

use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// Isolated from whatever host CLI the machine running the test has: with
/// Active Defence in `/usr/local/bin`, `statsu` was delegated to the real
/// `innerwarden-ctl` and these tests failed for a reason that was not the code.
fn run(args: &[&str]) -> Output {
    run_searching(args, "")
}

/// `run` with the host CLI looked for only in `ad_dirs` (PATH-style).
fn run_searching(args: &[&str], ad_dirs: &str) -> Output {
    Command::new(bin())
        .args(args)
        .env("IW_AD_CLI_DIRS", ad_dirs)
        .output()
        .expect("run the binary")
}

/// A stand-in `innerwarden-ctl` that answers everything with a marker.
#[cfg(unix)]
fn fake_host_cli() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("tempdir");
    let ctl = dir.path().join("innerwarden-ctl");
    std::fs::write(&ctl, "#!/bin/sh\necho FAKE-HOST-CTL \"$@\"\nexit 0\n").expect("write");
    std::fs::set_permissions(&ctl, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    dir
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

/// REGRESSION ANCHOR. Every short form people actually type must answer.
///
/// FAILS ON REVERT: drop `-v` from the version arm and it falls through to the
/// unknown-command path, exits 2, and prints nothing on stdout.
#[test]
fn every_spelling_of_version_answers_with_the_version() {
    for flag in ["--version", "-V", "-v", "version"] {
        let out = run(&[flag]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "`{flag}` must succeed; stderr:\n{}",
            stderr(&out)
        );
        let said = stdout(&out);
        assert!(
            said.contains(env!("CARGO_PKG_VERSION")),
            "`{flag}` must print the version, got:\n{said}"
        );
        // One line, not a banner and not a help dump.
        assert!(
            said.lines().count() == 1,
            "`{flag}` must answer in one line, got {}:\n{said}",
            said.lines().count()
        );
    }
}

/// The error for a typo must be readable where it lands.
///
/// The bound is deliberately generous: the point is that it is a handful of
/// lines rather than the whole manual, not that it is exactly N.
///
/// FAILS ON REVERT: restore `print_help()` on the unknown-command path and this
/// sees 60+ lines.
#[test]
fn a_typo_does_not_bury_its_error_under_the_manual() {
    let out = run(&["statsu"]);
    assert_eq!(out.status.code(), Some(2), "a typo is still an error");

    let all = format!("{}{}", stdout(&out), stderr(&out));
    let lines = all.lines().filter(|l| !l.trim().is_empty()).count();
    assert!(
        lines <= 5,
        "the error must not be buried; got {lines} lines:\n{all}"
    );
    assert!(
        all.contains("unknown command `statsu`"),
        "the reason must survive:\n{all}"
    );
    assert!(
        all.contains("--help"),
        "help must still be one command away:\n{all}"
    );
}

/// The other side, so this is not "shorten everything": `--help` still prints
/// the full help. Shrinking the error must not shrink the manual.
#[test]
fn help_itself_is_still_the_full_help() {
    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    let said = stdout(&out);
    assert!(
        said.lines().count() > 20,
        "`--help` must still be the full help, got {} lines:\n{said}",
        said.lines().count()
    );
}

/// The isolation itself: a host CLI on `PATH` (as on a machine with Active
/// Defence installed) is not consulted once the search is pointed elsewhere,
/// so the typo test above measures this binary and nothing else.
///
/// FAILS ON REVERT (`IW_AD_CLI_DIRS` ignored): `PATH` is searched, the stand-in
/// answers `statsu`, and the exit is 0 with its marker on stdout.
#[cfg(unix)]
#[test]
fn a_host_cli_on_path_does_not_answer_when_the_search_is_isolated() {
    let fake = fake_host_cli();
    let path = format!(
        "{}:{}",
        fake.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let out = Command::new(bin())
        .arg("statsu")
        .env("PATH", path)
        .env("IW_AD_CLI_DIRS", "")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(2), "{}", stdout(&out));
    assert!(!stdout(&out).contains("FAKE-HOST-CTL"), "{}", stdout(&out));
}

/// `innerwarden --version` is the FREE CLI's release. With the host stack
/// installed it adds, on stderr, where the paid release is read; stdout stays
/// the one version line every script parses.
///
/// FAILS ON REVERT (no hint): stderr is empty with the host CLI present.
#[cfg(unix)]
#[test]
fn the_version_names_the_host_cli_when_active_defence_is_installed() {
    let fake = fake_host_cli();
    let out = run_searching(&["--version"], &fake.path().display().to_string());
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out).lines().count(), 1, "{}", stdout(&out));
    assert!(
        stderr(&out).contains("innerwarden-ctl --version"),
        "the paid release is one command away: {}",
        stderr(&out)
    );

    let bare = run(&["--version"]);
    assert_eq!(
        stderr(&bare),
        "",
        "a free-only machine is told nothing about a product it does not have"
    );
}
