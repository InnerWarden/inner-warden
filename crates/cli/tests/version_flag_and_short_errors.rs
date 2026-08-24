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

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("run the binary")
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
