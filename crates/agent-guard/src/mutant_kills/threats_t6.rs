//! Tests that kill mutants found surviving in `threats.rs` when every mutant
//! of `words_run_guard_loosening_verb_fed` was run on its own (2026-11-09): the
//! 2026-11-08 sweep never reached them, its shards ran out of time first.

use super::*;

/// `sh -c` wrapped `levels` times around `inner`, each level quoting the one
/// inside it the way a shell needs (`'` closed, escaped and reopened).
fn nested_sh(inner: &str, levels: usize) -> String {
    let mut command = inner.to_string();
    for _ in 0..levels {
        command = format!("sh -c '{}'", command.replace('\'', "'\\''"));
    }
    command
}

/// The reader of command strings stops after four nested `sh -c` or `eval`
/// levels. Each level must count: a hostile line can nest without end, and a
/// level that does not add to the depth lets it recurse as deep as it likes.
///
/// The stop is a bound on work, not on protection: at five levels this reader
/// gives up, and the verdict still refuses the line through the checks that do
/// not unwrap it (asserted here, so a change that makes the bound a hole fails
/// in this test rather than on a host).
///
/// FAILS ON REVERT: replace `+` with `*` in the `depth + 1` handed to
/// `runs_guard_loosening_verb` by the shell arm, or by the `eval` arm.
#[test]
fn every_nested_command_string_counts_toward_the_depth_bound() {
    let verb = "innerwarden allow x";
    assert!(
        runs_guard_loosening_verb(&nested_sh(verb, 4), 0),
        "four nested `sh -c` levels are read through to the verb"
    );
    assert!(
        !runs_guard_loosening_verb(&nested_sh(verb, 5), 0),
        "the fifth `sh -c` level is past the bound: each level must add one"
    );
    let evals = |levels: usize| format!("{}{verb}", "eval ".repeat(levels));
    assert!(
        runs_guard_loosening_verb(&evals(4), 0),
        "four nested `eval` levels are read through to the verb"
    );
    assert!(
        !runs_guard_loosening_verb(&evals(5), 0),
        "the fifth `eval` level is past the bound: each level must add one"
    );
    for deep in [nested_sh(verb, 5), nested_sh(verb, 8), evals(5), evals(8)] {
        assert_eq!(
            crate::mcp::analyze_command(&deep, None).recommendation,
            "deny",
            "past the bound the line is still refused: {deep}"
        );
    }
}

/// `npm exec`, `pnpm dlx`, `yarn x` run the package that follows, so the walk
/// steps over the subcommand to it. Only those package managers do: `echo exec
/// innerwarden allow 'rm -rf *'` prints its words, and stepping over `exec`
/// there would read the guard's CLI as run.
///
/// FAILS ON REVERT: replace `&&` with `||` between the package-manager match
/// and the `exec`/`dlx`/`x` check.
#[test]
fn only_a_package_manager_steps_over_exec_to_the_package_it_runs() {
    assert!(
        !runs_guard_loosening_verb("echo exec innerwarden allow 'rm -rf *'", 0),
        "`echo` prints `exec` and the rest; nothing runs"
    );
    assert!(
        runs_guard_loosening_verb("npm exec sh -c 'innerwarden allow x'", 0),
        "`npm exec sh -c ...` runs the shell, which runs the verb"
    );
    assert!(
        runs_guard_loosening_verb("pnpm dlx sh -c 'innerwarden dry-run'", 0),
        "`pnpm dlx` runs the package that follows the same way"
    );
}

/// Each word a launcher puts in front of the command it runs is stepped over
/// on its own merit: the value after an option (`sudo -u root`), the `$` of a
/// command substitution, `echo` inside one, an assignment, a launcher. If any
/// of those stops the walk, the shell after it is read as an unknown program
/// and the verb inside its `-c` string is never reached.
///
/// FAILS ON REVERT: replace any `||` with `&&` in `skippable` (after
/// `after_option`, after `dollar`, inside the substitution test, before
/// `is_environment_assignment`, before the number test).
#[test]
fn each_word_in_front_of_a_shell_is_stepped_over_on_its_own() {
    for (command, why) in [
        (
            "sudo -u root sh -c 'innerwarden allow x'",
            "an option's value (`root`) is not the command",
        ),
        (
            "$(sh -c 'innerwarden allow x')",
            "the `$` of a command substitution is not the command",
        ),
        (
            "$(echo innerwarden) allow 'rm -rf *'",
            "`echo` inside a substitution prints the command word, it is not a reader of it",
        ),
        (
            "PATH=/usr/bin sh -c 'innerwarden allow x'",
            "an assignment in front is not the command",
        ),
        (
            "sudo sh -c 'innerwarden allow x'",
            "a launcher is not the command",
        ),
        (
            "timeout 5 sh -c 'innerwarden allow x'",
            "a launcher's number is not the command",
        ),
    ] {
        assert!(runs_guard_loosening_verb(command, 0), "{why}: {command}");
    }
}

/// An option that takes its value as the next word (`env -u NAME`) makes that
/// next word a value, even when the value is spelled like a program that only
/// reads (`cat`). A word that is not an option (`sudo cat`) does not: `cat` is
/// then the command, it reads files named `innerwarden`, `allow` and `x`, and
/// nothing runs.
///
/// FAILS ON REVERT: replace either `&&` with `||`, or delete either `!`, in
/// `after_option = word.starts_with('-') && !word.contains('=') &&
/// !after_option`.
#[test]
fn only_an_option_makes_the_next_word_its_value() {
    assert!(
        runs_guard_loosening_verb("env -u cat innerwarden allow x", 0),
        "`cat` is the name `env -u` unsets; env then runs the guard's CLI"
    );
    assert!(
        !runs_guard_loosening_verb("sudo cat innerwarden allow x", 0),
        "`sudo cat` runs `cat`, which only reads"
    );
}
