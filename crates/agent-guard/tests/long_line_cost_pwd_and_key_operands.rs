//! Three readings of a shell line measured on 2026-11-21 against main
//! 1550074.
//!
//! - The cost of a long line of many commands grew with the square of its
//!   length: in a debug build `(X=#); echo $X; ` repeated cost 504 ms in 2 KB
//!   and 3964 ms in 8 KB, `X=# true $X; ` 320 ms and 3009 ms. The hook
//!   refuses a call that takes too long, so an ordinary long line could be
//!   refused for its time alone (BI NEW-20261121-analyze-superlinear-long-lines).
//!   Checks run once per command each walked the whole line again
//!   (`shell.rs`, `tree_lacks_kind`), and the values of every name were
//!   carried to every command (`handed_shell_lines`).
//! - `rm -rf $PWD/build` was refused as a removal of an unexpanded variable;
//!   it removes `./build` (BI FP-20261121-rm-pwd-subfolder-denied). `$PWD`
//!   is read as the folder the line stands in, and after a `cd` the line
//!   spells out as that folder: `cd /; rm -rf $PWD/etc` is still refused.
//! - `dd if=/etc/shadow of=/tmp/x` was allowed where `cat /etc/shadow` is
//!   refused: an operand that names the file a program reads as `key=path`
//!   was not read (BI NEW-20261121-dd-if-secret-read-allowed).
//!
//! The lines of `corpus/key-operands-2026-11` are the attacks and controls.

use innerwarden_agent_guard::mcp::{analyze_command, analyze_command_in, WorkingContext};
use std::time::{Duration, Instant};

#[derive(serde::Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    id: String,
    label: String,
    input: String,
}

fn corpus() -> Vec<Case> {
    let text = include_str!("../corpus/key-operands-2026-11/cases.yml");
    serde_yaml::from_str::<Corpus>(text)
        .expect("the corpus reads")
        .cases
}

fn repeated(unit: &str, bytes: usize) -> String {
    let mut line = String::with_capacity(bytes + unit.len());
    while line.len() < bytes {
        line.push_str(unit);
    }
    line
}

/// The shortest of three judgements of `line`: the least disturbed by
/// whatever else the machine runs.
fn cost(line: &str) -> Duration {
    (0..3)
        .map(|_| {
            let started = Instant::now();
            let _ = analyze_command(line, None);
            started.elapsed()
        })
        .min()
        .expect("three runs")
}

/// FAILS ON REVERT of the per-tree kind index and of the values carried per
/// command: on main each shape cost about ten times as much in 8 KB as in
/// 2 KB (3964 / 504 ms and 3009 / 320 ms in a debug build). A line four
/// times as long is held to six times the cost, five and a margin; nothing
/// is measured in absolute time.
///
/// Skipped under coverage only: instrumented, with the other tests of the
/// binary running beside it, the ratio crossed six on the runner on lines
/// whose cost had not changed (2026-11-22, the coverage job of several PRs),
/// while the build job, which runs it as shipped, kept it. The square it
/// guards against is ten times in a debug build, so the build job alone still
/// catches a revert.
#[cfg_attr(
    tarpaulin,
    ignore = "a perf ratio under instrumentation measures the instrumentation"
)]
#[test]
fn a_line_four_times_as_long_costs_about_four_times_as_much() {
    // Compiles the rules once, outside what is measured.
    let _ = analyze_command(&repeated("true; ", 512), None);
    for unit in [
        "(X=#); echo $X; ",
        "X=# true $X; ",
        "X=1 true; ",
        "echo hi | cat; ",
    ] {
        let short = cost(&repeated(unit, 2048));
        let long = cost(&repeated(unit, 8192));
        assert!(
            long <= short * 6,
            "{unit:?}: 2 KB took {short:?}, 8 KB took {long:?}"
        );
    }
}

/// FAILS ON REVERT of the key of the kind index (`kind_index_key`). Keyed
/// by the id of the root, a tree made where a dropped one had been took its
/// kinds: after other long lines, a line that calls functions it defines
/// read as one that defines none, and its refusal for reading past the
/// functions it writes out was lost. A verdict never depends on the lines
/// judged before it.
#[test]
fn a_verdict_does_not_depend_on_the_lines_judged_before_it() {
    let functions = repeated("f() { true; }; f; ", 2048);
    let alone = analyze_command(&functions, None);
    for unit in [
        "(X=#); echo $X; ",
        "X=# true $X; ",
        "echo hi | cat; ",
        "true; ",
        "X=1 true; ",
    ] {
        let _ = analyze_command(&repeated(unit, 2048), None);
        let _ = analyze_command(&repeated(unit, 8192), None);
    }
    let after = analyze_command(&functions, None);
    assert_eq!(alone.recommendation, "deny", "{}", alone.explanation);
    assert_eq!(
        (after.recommendation.as_str(), after.risk_score),
        (alone.recommendation.as_str(), alone.risk_score),
        "{}",
        after.explanation
    );
}

/// FAILS ON REVERT of `with_working_directory_named`: main refused each
/// line (deny 60) as a removal of an unexpanded variable.
#[test]
fn a_folder_under_the_working_directory_is_removed_as_the_shell_does() {
    for line in [
        "rm -rf $PWD/build",
        "rm -rf ${PWD}/build",
        "rm -rf \"$PWD/target/debug\"",
        "cd build && rm -rf $PWD/out",
    ] {
        let analysis = analyze_command(line, None);
        assert_eq!(
            analysis.recommendation, "allow",
            "{line:?}: {}",
            analysis.explanation
        );
    }
    let project = WorkingContext::discover("/home/dev/proj", Some("/home/dev")).expect("context");
    let analysis = analyze_command_in("rm -rf $PWD/build", None, Some(&project));
    assert_eq!(analysis.recommendation, "allow", "{}", analysis.explanation);
}

/// `$PWD` after a `cd` the line spells out is that folder, and one the
/// line gives a value of its own, or after a `cd` it does not spell out,
/// is read as written: each is refused, as on main.
#[test]
fn the_working_directory_after_a_move_is_where_the_line_moved() {
    for line in [
        "cd /; rm -rf $PWD/etc",
        "cd /; rm -rf ${PWD}/etc",
        "cd / && rm -rf \"$PWD/usr\"",
        "PWD=/; rm -rf $PWD/etc",
        "export PWD=/etc; rm -rf $PWD/x",
        "cd $(echo /); rm -rf $PWD/etc",
        "rm -rf $PWD/../x",
        "rm -rf $PWD/build $DEST/y",
    ] {
        let analysis = analyze_command(line, None);
        assert_eq!(
            analysis.recommendation, "deny",
            "{line:?}: {}",
            analysis.explanation
        );
    }
}

/// FAILS ON REVERT of `destructive_rm_credentials_in_place`: from the home,
/// main allowed `rm -rf ./.ssh` and `rm -rf .ssh` and refused only
/// `rm -rf $PWD/.ssh`, for its variable. Read as the folder it is, the
/// working directory must not open that removal: a credential store reached
/// by a path relative to where the line runs is the store.
#[test]
fn a_credential_store_removed_from_the_home_by_a_relative_path_is_refused() {
    let home = WorkingContext::discover("/home/dev", Some("/home/dev")).expect("context");
    for line in [
        "rm -rf $PWD/.ssh",
        "rm -rf ./.ssh",
        "rm -rf .ssh",
        "rm ./.ssh/id_ed25519",
        "rm -rf ./.aws/credentials",
        "cd ~ && rm -rf .gnupg",
    ] {
        let analysis = analyze_command_in(line, None, Some(&home));
        assert_eq!(
            analysis.recommendation, "deny",
            "{line:?}: {}",
            analysis.explanation
        );
    }
    let project = WorkingContext::discover("/home/dev/proj", Some("/home/dev")).expect("context");
    for line in ["rm -rf ./.ssh", "rm -rf .aws", "rm ./.ssh/id_ed25519.pub"] {
        let ctx = if line.ends_with(".pub") {
            &home
        } else {
            &project
        };
        let analysis = analyze_command_in(line, None, Some(ctx));
        assert_eq!(
            analysis.recommendation, "allow",
            "{line:?}: {}",
            analysis.explanation
        );
    }
}

/// FAILS ON REVERT of the `key=path` readers of `content_reader`: main
/// allowed every attack of the corpus but ko-016..ko-020.
#[test]
fn a_secret_named_as_key_equals_path_is_read() {
    let cases = corpus();
    let attacks: Vec<&Case> = cases.iter().filter(|c| c.label == "malicious").collect();
    assert!(attacks.len() >= 15, "the corpus holds its attacks");
    for case in attacks {
        let analysis = analyze_command(&case.input, None);
        assert_eq!(
            analysis.recommendation, "deny",
            "{}: {}",
            case.id, analysis.explanation
        );
    }
}

/// A copy of an image or a device, a public key, a pattern file and a
/// project folder under `$PWD` are allowed.
#[test]
fn copies_of_images_and_project_folders_are_allowed() {
    let cases = corpus();
    let controls: Vec<&Case> = cases.iter().filter(|c| c.label == "benign").collect();
    assert!(controls.len() >= 10, "the corpus holds its controls");
    for case in controls {
        let analysis = analyze_command(&case.input, None);
        assert_eq!(
            analysis.recommendation, "allow",
            "{}: {}",
            case.id, analysis.explanation
        );
    }
}
