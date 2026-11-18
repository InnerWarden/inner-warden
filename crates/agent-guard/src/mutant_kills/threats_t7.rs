//! Tests that kill mutants the weekly cargo-mutants sweep found surviving in
//! `rm_command_index` in `threats.rs` (run 42585938875, 2026-11-09), and the
//! mutants of that function the sweep's lost shards never reported.

use super::*;

use std::io::Write;
use std::sync::mpsc;
use std::time::Duration;

/// How long one read may take before it counts as never returning. A real
/// read is a few microseconds; a mutant that stops the index from advancing
/// spins forever, so the read runs on a thread of its own and this bound
/// ends the run instead of letting it time out.
const DEADLINE: Duration = Duration::from_secs(10);

/// Run `work` on a thread of its own and hand back its result. When it
/// panics (an index stepped below zero or past the last word) the test fails.
///
/// When it never returns (an index that stops advancing) the whole test
/// process is ended. Failing only this test is not enough there: other tests
/// that read the same kind of line on their own test thread hang with it, the
/// test binary never exits, and the run ends in a timeout instead of a
/// failure. Ending the process turns the hang into a failed run at once. It
/// never fires when the read returns.
fn within_deadline<T: Send + 'static>(shown: &str, work: impl FnOnce() -> T + Send + 'static) -> T {
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done_tx.send(work());
    });
    match done_rx.recv_timeout(DEADLINE) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
            "reading `{shown}` panicked: the walk over the wrappers stepped below the first \
             word or past the last"
        ),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            // Written to the stream itself, not through `eprintln!`, so the
            // test harness does not hold it back when the process ends.
            let _ = writeln!(
                std::io::stderr(),
                "reading `{shown}` never returned within {DEADLINE:?}: the walk over the \
                 wrappers stopped advancing; ending the test process so the run fails \
                 instead of hanging"
            );
            std::process::abort();
        }
    }
}

/// The index of the `rm` that `words` (one command, already split into
/// words) runs, read on a thread with a deadline.
fn rm_index(words: &[&str]) -> Option<usize> {
    let tokens: Vec<String> = words.iter().map(|word| word.to_string()).collect();
    within_deadline(&words.join(" "), move || rm_command_index(&tokens))
}

/// Whether the public screening refuses `command` (a finding that blocks),
/// read on a thread with a deadline.
fn refused(command: &'static str) -> bool {
    within_deadline(command, move || {
        matches!(check_command(command), Some((_, true)))
    })
}

/// `FOO=1 rm -rf /` runs `rm`: environment assignments in front of the
/// command word are not the program, so the walk steps over every one of them
/// to reach it. A run of nothing but assignments runs no program at all.
///
/// The rm checks (root, home, credential stores) only look at an `rm` this
/// walk finds. If the assignments are not stepped over, a single `A=1` in
/// front hides the wipe; if the step does not move forward, the walk spins or
/// steps below the first word; if it reads past the last word, a line of bare
/// assignments crashes the screening.
///
/// FAILS ON REVERT: replace `<` with `==`, `>` or `<=` in the leading
/// assignment loop (`while i < tokens.len() && is_env_assign(..)`), replace
/// `&&` with `||` there, or replace `+=` with `-=` or `*=` in its `i += 1`.
#[test]
fn leading_environment_assignments_are_stepped_over_to_the_rm() {
    assert_eq!(
        rm_index(&["FOO=1", "rm", "-rf", "/"]),
        Some(1),
        "`FOO=1 rm -rf /` runs `rm`, the word after the assignment"
    );
    assert_eq!(
        rm_index(&["A=1", "B=2", "rm", "-rf", "/"]),
        Some(2),
        "two assignments in a row must both be stepped over"
    );
    assert_eq!(
        rm_index(&["A=1"]),
        None,
        "a line of nothing but an assignment runs no `rm`, and reading it must not crash"
    );
    assert_eq!(
        rm_index(&["FOO=1", "echo", "rm", "-rf", "/"]),
        None,
        "after the assignment `echo` is the program, and it only prints `rm`"
    );
    assert!(
        refused("FOO=1 rm -rf /"),
        "a root wipe behind an assignment must be refused"
    );
}

/// `rm` itself, bare or by path (`/bin/rm`), is the command the rm checks
/// are about, and `echo rm` is not: the program decides, not a later word.
///
/// FAILS ON REVERT: delete match arm "rm" in rm_command_index.
#[test]
fn rm_as_the_program_word_is_found_where_it_stands() {
    assert_eq!(
        rm_index(&["rm", "-rf", "/"]),
        Some(0),
        "`rm -rf /` runs `rm` as its first word"
    );
    assert_eq!(
        rm_index(&["/bin/rm", "-rf", "/"]),
        Some(0),
        "`/bin/rm` is `rm` named by its path"
    );
    assert_eq!(
        rm_index(&["echo", "rm", "-rf", "/"]),
        None,
        "`echo rm -rf /` runs `echo`, which only prints"
    );
    assert!(refused("rm -rf /"), "a bare root wipe must be refused");
}

/// `sudo rm -rf /` and `doas rm -rf /` run `rm` as another user: the walk
/// steps over the launcher to the command it starts.
///
/// Without the arm, or with the step after `sudo` going nowhere (it spins) or
/// below zero (it crashes), the most common way to wipe a host as root goes
/// unseen by every rm check.
///
/// FAILS ON REVERT: delete match arm "sudo" | "doas" in rm_command_index,
/// replace `+=` with `-=` or `*=` in the `i += 1` after `sudo`, or replace
/// `&&` with `||` in either loop of the sudo arm (the option loop or the
/// assignment loop).
#[test]
fn sudo_and_doas_are_stepped_over_to_the_rm_they_start() {
    assert_eq!(
        rm_index(&["sudo", "rm", "-rf", "/"]),
        Some(1),
        "`sudo rm -rf /` runs `rm`"
    );
    assert_eq!(
        rm_index(&["doas", "rm", "-rf", "/"]),
        Some(1),
        "`doas rm -rf /` runs `rm`"
    );
    assert_eq!(
        rm_index(&["A=1", "sudo", "rm", "-rf", "/"]),
        Some(2),
        "`A=1 sudo rm -rf /` runs `rm` after the assignment and the launcher"
    );
    assert!(
        refused("sudo rm -rf /"),
        "a root wipe under sudo must be refused"
    );
}

/// `sudo -u root rm -rf /` runs `rm`: `-u`, `-g`, `-p`, `-C`, `-U` and their
/// long forms take the next word as their value, so the walk steps over the
/// option AND its value, and `sudo -E rm` steps over a flag that takes none.
///
/// Reading the value as the program (`root`) hides the `rm`; stepping over
/// the word after a flag that takes no value swallows the `rm` itself; a step
/// that goes back or stays put never ends.
///
/// FAILS ON REVERT: replace `<` with `==` or `>` in the sudo option loop, or
/// in `takes_val && i < tokens.len()`; replace `&&` with `||` in `takes_val &&
/// i < tokens.len()`; replace `+=` with `-=` or `*=` in the `i += 1` past the
/// option, or in the `i += 1` past its value.
#[test]
fn sudo_options_and_their_values_are_stepped_over_to_the_rm() {
    assert_eq!(
        rm_index(&["sudo", "-u", "root", "rm", "-rf", "/"]),
        Some(3),
        "`sudo -u root rm -rf /` runs `rm` after the option and its value"
    );
    assert_eq!(
        rm_index(&["sudo", "-E", "rm", "-rf", "/"]),
        Some(2),
        "`-E` takes no value: the word after it is the `rm`"
    );
    assert_eq!(
        rm_index(&["sudo", "-E", "-g", "wheel", "--user", "root", "rm", "-rf", "/"]),
        Some(6),
        "a flag, then two options with values, must all be stepped over in order"
    );
    assert!(
        refused("sudo -u root rm -rf /"),
        "a root wipe under `sudo -u root` must be refused"
    );
}

/// `sudo FOO=1 rm -rf /` runs `rm` with `FOO=1` in its environment: sudo
/// takes assignments after its options, and the walk steps over each.
///
/// FAILS ON REVERT: replace `<` with `==` or `>` in the sudo assignment loop,
/// or replace `+=` with `-=` or `*=` in its `i += 1`.
#[test]
fn assignments_handed_to_sudo_are_stepped_over_to_the_rm() {
    assert_eq!(
        rm_index(&["sudo", "FOO=1", "rm", "-rf", "/"]),
        Some(2),
        "`sudo FOO=1 rm -rf /` runs `rm` after the assignment"
    );
    assert_eq!(
        rm_index(&["sudo", "-E", "A=1", "B=2", "rm", "-rf", "/"]),
        Some(4),
        "assignments after an option are stepped over too"
    );
    assert!(
        refused("sudo FOO=1 rm -rf /"),
        "a root wipe under sudo with an assignment must be refused"
    );
}

/// A `sudo` with nothing after it, or with only an option or an assignment,
/// runs no `rm`. Reading such a line must end with no command, never by
/// reading a word past the last one: the screening gets every partial line an
/// agent types, and a crash there is a crash of the screening.
///
/// FAILS ON REVERT: replace `<` with `<=` in the sudo option loop, or in the
/// sudo assignment loop.
#[test]
fn a_sudo_line_that_ends_before_any_command_runs_no_rm() {
    for words in [&["sudo"][..], &["sudo", "-E"][..], &["sudo", "FOO=1"][..]] {
        assert_eq!(
            rm_index(words),
            None,
            "`{}` runs no command at all",
            words.join(" ")
        );
    }
}

/// `env rm -rf /`, `env -i FOO=1 rm -rf /`: `env` runs the command after its
/// flags and assignments, and the walk steps over both kinds of word. A word
/// is stepped over when it is a flag OR an assignment; no word is both.
///
/// FAILS ON REVERT: delete match arm "env" in rm_command_index; replace `+=`
/// with `-=` or `*=` in the `i += 1` after `env`, or in the loop over its
/// words; replace `<` with `==` or `>`, or `&&` with `||`, in that loop's
/// condition; replace `||` with `&&` between its flag and assignment tests.
#[test]
fn env_flags_and_assignments_are_stepped_over_to_the_rm() {
    assert_eq!(
        rm_index(&["env", "rm", "-rf", "/"]),
        Some(1),
        "`env rm -rf /` runs `rm`"
    );
    assert_eq!(
        rm_index(&["env", "-i", "FOO=1", "rm", "-rf", "/"]),
        Some(3),
        "`env -i FOO=1 rm -rf /` runs `rm` after a flag and an assignment"
    );
    assert_eq!(
        rm_index(&["env", "FOO=1", "rm", "-rf", "/"]),
        Some(2),
        "an assignment alone after `env` is stepped over"
    );
    assert!(
        refused("env -i FOO=1 rm -rf /"),
        "a root wipe under env must be refused"
    );
}

/// An `env` with nothing after it, or only an assignment, runs no `rm`, and
/// reading it must end there, never past the last word.
///
/// FAILS ON REVERT: replace `<` with `<=` in the loop over the words after
/// `env`.
#[test]
fn an_env_line_that_ends_before_any_command_runs_no_rm() {
    for words in [&["env"][..], &["env", "FOO=1"][..], &["env", "-i"][..]] {
        assert_eq!(
            rm_index(words),
            None,
            "`{}` runs no command at all",
            words.join(" ")
        );
    }
}

/// `nice rm -rf /`, `nice -n 5 rm -rf /`, `nice -5 rm -rf /` and `ionice -c 3
/// rm -rf /` all run `rm` at a lower priority. `-n`, `-c`, `-p` and
/// `--adjustment` take the next word as their value; any other flag
/// (`-5`) takes none, so the word after it is already the command.
///
/// Read wrong, the priority value (`5`, `3`) becomes the program and the
/// wipe behind it is not seen, or the `rm` is swallowed as a value it is
/// not, or the step back or in place never ends.
///
/// FAILS ON REVERT: delete match arm "nice" | "ionice" in rm_command_index;
/// replace `+=` with `-=` or `*=` in the `i += 1` after `nice`, in the `i +=
/// 1` past an option, or in the `i += 1` past its value; replace `<` with
/// `==` or `>`, or `&&` with `||`, in the nice option loop; replace `<` with
/// `==` or `>`, or `&&` with `||`, in `takes_val && i < tokens.len()`.
#[test]
fn nice_and_ionice_options_and_their_values_are_stepped_over_to_the_rm() {
    assert_eq!(
        rm_index(&["nice", "rm", "-rf", "/"]),
        Some(1),
        "`nice rm -rf /` runs `rm`"
    );
    assert_eq!(
        rm_index(&["nice", "-n", "5", "rm", "-rf", "/"]),
        Some(3),
        "`nice -n 5 rm -rf /` runs `rm` after the option and its value"
    );
    assert_eq!(
        rm_index(&["nice", "-5", "rm", "-rf", "/"]),
        Some(2),
        "`-5` takes no value: the word after it is the `rm`"
    );
    assert_eq!(
        rm_index(&["ionice", "-c", "3", "rm", "-rf", "/"]),
        Some(3),
        "`ionice -c 3 rm -rf /` runs `rm` after the option and its value"
    );
    assert_eq!(
        rm_index(&["nice", "-n", "5", "echo", "rm", "-rf", "/"]),
        None,
        "after `nice -n 5` the program is `echo`, which only prints"
    );
    assert!(
        refused("nice -n 5 rm -rf /"),
        "a root wipe under nice must be refused"
    );
}

/// A `nice` with nothing after it, or only options, runs no `rm`, and
/// reading it must end there, never past the last word.
///
/// FAILS ON REVERT: replace `<` with `<=` in the nice option loop.
#[test]
fn a_nice_line_that_ends_before_any_command_runs_no_rm() {
    for words in [&["nice"][..], &["nice", "-5"][..], &["nice", "-n", "5"][..]] {
        assert_eq!(
            rm_index(words),
            None,
            "`{}` runs no command at all",
            words.join(" ")
        );
    }
}

/// `timeout 5 rm -rf /` runs `rm` after the duration, and `timeout
/// --preserve-status 5 rm -rf /` after its flags and then the duration. The
/// duration is one word and is always stepped over.
///
/// Read wrong, the duration becomes the program, or a flag does, and the
/// wipe behind them is not seen; a step that goes back loops forever.
///
/// FAILS ON REVERT: delete match arm "timeout" in rm_command_index; replace
/// `+=` with `-=` or `*=` in the `i += 1` after `timeout`, in the `i += 1`
/// past a flag, or in the `i += 1` past the duration; replace `<` with `==`
/// or `>`, or `&&` with `||`, in the timeout flag loop; replace `<` with `==`
/// or `>` in `if i < tokens.len()` before the duration.
#[test]
fn timeout_flags_and_duration_are_stepped_over_to_the_rm() {
    assert_eq!(
        rm_index(&["timeout", "5", "rm", "-rf", "/"]),
        Some(2),
        "`timeout 5 rm -rf /` runs `rm` after the duration"
    );
    assert_eq!(
        rm_index(&["timeout", "--preserve-status", "5", "rm", "-rf", "/"]),
        Some(3),
        "a flag and then the duration are stepped over"
    );
    assert_eq!(
        rm_index(&["timeout", "-v", "--foreground", "5", "rm", "-rf", "/"]),
        Some(4),
        "two flags and then the duration are stepped over"
    );
    assert!(
        refused("timeout 5 rm -rf /"),
        "a root wipe under timeout must be refused"
    );
}

/// A `timeout` with nothing after it, or only a flag, runs no `rm`, and
/// reading it must end there, never past the last word.
///
/// FAILS ON REVERT: replace `<` with `<=` in the timeout flag loop.
#[test]
fn a_timeout_line_that_ends_before_any_command_runs_no_rm() {
    for words in [
        &["timeout"][..],
        &["timeout", "--foreground"][..],
        &["timeout", "5"][..],
    ] {
        assert_eq!(
            rm_index(words),
            None,
            "`{}` runs no command at all",
            words.join(" ")
        );
    }
}

/// `nohup`, `stdbuf`, `setsid`, `command`, `exec`, `time` and `xargs` each
/// run the command after their flags (`stdbuf -oL rm -rf /`), and the walk
/// steps over the launcher and every flag to reach it.
///
/// FAILS ON REVERT: delete match arm "nohup" | "stdbuf" | "setsid" |
/// "command" | "exec" | "time" | "xargs" in rm_command_index; replace `+=`
/// with `-=` or `*=` in the `i += 1` after the launcher, or in the `i += 1`
/// past a flag; replace `<` with `==` or `>`, or `&&` with `||`, in the flag
/// loop of that arm.
#[test]
fn plain_launchers_and_their_flags_are_stepped_over_to_the_rm() {
    for launcher in [
        "nohup", "stdbuf", "setsid", "command", "exec", "time", "xargs",
    ] {
        assert_eq!(
            rm_index(&[launcher, "rm", "-rf", "/"]),
            Some(1),
            "`{launcher} rm -rf /` runs `rm`"
        );
    }
    assert_eq!(
        rm_index(&["stdbuf", "-oL", "rm", "-rf", "/"]),
        Some(2),
        "`stdbuf -oL rm -rf /` runs `rm` after the flag"
    );
    assert_eq!(
        rm_index(&["xargs", "-0", "-r", "rm", "-rf"]),
        Some(3),
        "`xargs -0 -r rm -rf` runs `rm` after both flags"
    );
    assert!(
        refused("stdbuf -oL rm -rf /"),
        "a root wipe under stdbuf must be refused"
    );
}

/// A plain launcher with nothing after it, or only flags, runs no `rm`, and
/// reading it must end there, never past the last word.
///
/// FAILS ON REVERT: replace `<` with `<=` in the flag loop of the
/// "nohup" | "stdbuf" | ... arm.
#[test]
fn a_plain_launcher_line_that_ends_before_any_command_runs_no_rm() {
    for words in [&["nohup"][..], &["command", "-v"][..], &["xargs", "-0"][..]] {
        assert_eq!(
            rm_index(words),
            None,
            "`{}` runs no command at all",
            words.join(" ")
        );
    }
}

/// Wrappers stack: `sudo -u root nice -n 5 env FOO=1 timeout 5 nohup rm -rf
/// /` runs `rm` at the end of the chain. Each launcher hands the walk to the
/// next, so every arm must leave the index on the word after its own.
///
/// FAILS ON REVERT: delete match arm "sudo" | "doas", "nice" | "ionice",
/// "env", "timeout" or "nohup" | ... in rm_command_index, or any `+=`, `<` or
/// `&&` mutation named above that leaves the index on the wrong word in one
/// of those arms.
#[test]
fn stacked_wrappers_are_walked_through_to_the_rm() {
    assert_eq!(
        rm_index(&[
            "sudo", "-u", "root", "nice", "-n", "5", "env", "FOO=1", "timeout", "5", "nohup", "rm",
            "-rf", "/",
        ]),
        Some(11),
        "the `rm` at the end of five stacked launchers is the command run"
    );
    assert!(
        refused("sudo -u root nice -n 5 env FOO=1 timeout 5 nohup rm -rf /"),
        "a root wipe at the end of five stacked launchers must be refused"
    );
}
