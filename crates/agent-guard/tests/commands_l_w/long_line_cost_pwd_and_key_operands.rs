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
    let text = include_str!("../../corpus/key-operands-2026-11/cases.yml");
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

/// The processor time this thread has used so far: the work it did, not the
/// time it waited while other programs had the processor. In nanoseconds;
/// only the ratio of two costs is ever compared.
#[cfg(unix)]
fn thread_cpu() -> u128 {
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `now` is a live timespec for the call to write.
    let read = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut now) };
    assert_eq!(read, 0, "the thread's processor clock reads");
    let seconds = u128::try_from(now.tv_sec).expect("seconds");
    let nanos = u128::try_from(now.tv_nsec).expect("nanoseconds");
    seconds * 1_000_000_000 + nanos
}

/// The processor time this thread has used so far, in the processor cycles
/// Windows counts for it: the work it did, not the time it waited while
/// other programs had the processor. Only the ratio of two costs is ever
/// compared.
#[cfg(windows)]
fn thread_cpu() -> u128 {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThread() -> *mut std::ffi::c_void;
        fn QueryThreadCycleTime(thread: *mut std::ffi::c_void, cycles: *mut u64) -> i32;
    }
    let mut cycles = 0u64;
    // SAFETY: the handle is the calling thread's own pseudo handle, which is
    // never closed, and `cycles` is a live u64 for the call to write.
    let read = unsafe { QueryThreadCycleTime(GetCurrentThread(), &mut cycles) };
    assert_ne!(read, 0, "the thread's cycle count reads");
    u128::from(cycles)
}

/// What one judgement of `line` costs this thread ([`thread_cpu`]).
fn cost(line: &str) -> u128 {
    let started = thread_cpu();
    let _ = analyze_command(line, None);
    thread_cpu() - started
}

/// The middle one of `costs`.
fn median(mut costs: Vec<u128>) -> u128 {
    costs.sort_unstable();
    costs[costs.len() / 2]
}

/// FAILS ON REVERT of the per-tree kind index and of the values carried per
/// command. Measured 2026-11-26 in a debug build, 16 KB against 1 KB: with
/// `tree_lacks_kind` never saying a kind is absent, `echo hi | cat; ` cost
/// 84 times as much; with every value of the line carried to every command
/// (`handed_shell_lines` as it was before), `X=1 true; ` cost 75 times as
/// much and `(X=#); echo $X; ` 50 to 63 times. As shipped, the four shapes
/// cost 16 to 27 times as much (the lines that read `$X` in every command
/// keep a small square term). A line sixteen times as long is held to 48
/// times the cost: three times what a cost in proportion to the length
/// would be, a fifth of the square.
///
/// What is measured is the processor time of the thread that judges
/// ([`thread_cpu`]), never a clock on the wall: until 2026-11-26 this test
/// took the shortest of three wall-clock runs of 2 KB and of 8 KB, and the
/// macOS runner, shared with other jobs, failed it on lines whose cost had
/// not changed (2 KB 48 ms, 8 KB 290 ms). The two lengths are judged in
/// turn, five times each, and the medians compared, so a judgement slowed
/// by something else moves neither. The sixteenfold length keeps the
/// margins wide on both sides: at four times the length, the costliest
/// shape cost 5.1 times as much as shipped, 7.6 times with the values
/// reverted and 9.4 times with the index reverted.
///
/// Skipped under coverage only: instrumented, with the other tests of the
/// binary running beside it, a ratio measures the instrumentation (the
/// coverage job of several PRs crossed the old bound, 2026-11-22). The build
/// job runs it as shipped, so it still catches a revert.
#[cfg_attr(
    tarpaulin,
    ignore = "a perf ratio under instrumentation measures the instrumentation"
)]
#[test]
fn a_line_sixteen_times_as_long_costs_nowhere_near_the_square() {
    // Compiles the rules once, outside what is measured.
    let _ = analyze_command(&repeated("true; ", 512), None);
    for unit in [
        "(X=#); echo $X; ",
        "X=# true $X; ",
        "X=1 true; ",
        "echo hi | cat; ",
    ] {
        let short_line = repeated(unit, 1024);
        let long_line = repeated(unit, 16 * 1024);
        let (mut short, mut long) = (Vec::new(), Vec::new());
        for _ in 0..5 {
            short.push(cost(&short_line));
            long.push(cost(&long_line));
        }
        let (short, long) = (median(short), median(long));
        assert!(
            long <= short * 48,
            "{unit:?}: 1 KB cost {short}, 16 KB cost {long}, {:.1} times as much",
            long as f64 / short as f64
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
