//! Tests that kill mutants cargo-mutants found surviving in the reading of
//! the guard's name only where a program runs (pull request #471,
//! 2026-11-28): each holds one decision of that reading to what it does.

use super::*;

/// The stronger of two answers is the one with the higher score, and the
/// first of them on a tie: the first is the one a caller asked first.
///
/// FAILS ON REVERT: compare the scores in `stronger` with `<`, `==` or `>=`
/// and one of these answers is the other one.
#[test]
fn the_stronger_answer_is_the_higher_score_and_the_first_on_a_tie() {
    let held = Some(("held", GUARD_HELD_SCORE));
    let refused = Some(("refused", 60));
    let other = Some(("other", 60));
    assert_eq!(stronger(held, refused), refused);
    assert_eq!(stronger(refused, held), refused);
    assert_eq!(stronger(refused, other), refused);
    assert_eq!(stronger(other, refused), other);
    assert_eq!(stronger(None, held), held);
    assert_eq!(stronger(held, None), held);
}

/// Past the patterns, a refusal of the words is the answer, and a line the
/// words only hold for review is still refused for a loosening verb the
/// rules after them find.
///
/// FAILS ON REVERT: let a held answer of the words return at once
/// (`*score >= GUARD_HELD_SCORE`) and the first line is only held; take a
/// refusal of the words for the rules' (`*score < GUARD_HELD_SCORE`) and the
/// second one gives the reason of the loosening verb, not of the kernel.
#[test]
fn a_refusal_of_the_words_is_kept_and_a_hold_gives_way_to_a_refusal() {
    let held_then_allow = "faketime 0 innerwarden $V; innerwarden allow foo";
    assert_eq!(
        guard_self_disable_after_patterns(held_then_allow),
        Some((GUARD_LOOSENING_VERB, 60)),
        "{held_then_allow}"
    );
    let kernel_then_allow = "innerwarden agent kernel off; innerwarden allow foo";
    assert_eq!(
        guard_self_disable_after_patterns(kernel_then_allow),
        Some((KERNEL_PROTECTION_CHANGE, 60)),
        "{kernel_then_allow}"
    );
}

/// A guard name the shell assembles from quotes, handed to a program the
/// line does not know, is held; a loosening verb run under a pattern of
/// the name later on the line is still refused, and a refusal of the words
/// keeps its own reason.
///
/// FAILS ON REVERT: let the held answer return at once in
/// `guard_self_disable_by_words` (`*score >= GUARD_HELD_SCORE`, `==`) and
/// the first line is only held; take a refusal of the words for the rules'
/// (`<`) and the second gives the reason of the loosening verb.
#[test]
fn a_held_assembled_name_gives_way_to_a_loosening_verb_under_a_pattern() {
    let held_then_allow = "faketime 0 inner\"warden\" $V; inner*arden allow x";
    assert_eq!(
        guard_self_disable_by_words(held_then_allow),
        Some((GUARD_LOOSENING_VERB, 60)),
        "{held_then_allow}"
    );
    let kernel_then_allow = "inner*arden agent kernel off; inner*arden allow x";
    assert_eq!(
        guard_self_disable_by_words(kernel_then_allow),
        Some((KERNEL_PROTECTION_CHANGE, 60)),
        "{kernel_then_allow}"
    );
}

/// A reading that only holds the line gives way to a refusal another
/// reading finds: without the assignment in front of `./run` the line only
/// hands the guard on (held), and with the line's own value read into
/// `$X` it runs the guard's `allow` (refused).
///
/// FAILS ON REVERT: return the first answer of the readings whatever its
/// score (`hit.1 > GUARD_HELD_SCORE` taken for `true`, or `>=`) in
/// `check_guard_self_disable` and the line is only held.
#[test]
fn a_held_reading_gives_way_to_a_refusal_of_another_reading() {
    let line = "X=innerwarden; A=1 ./run $X \"$Y\"; $X allow x";
    assert_eq!(
        check_guard_self_disable(line).map(|(_, score)| score),
        Some(60),
        "{line}"
    );
}

/// The remote shell `rsync -e` runs is read as a command line: an `ssh` in
/// it runs what its own options name, here the guard's `allow`.
///
/// FAILS ON REVERT: read `rsync` apart from the ssh client's programs
/// (`base != "rsync"`) and the line does not run the verb.
#[test]
fn the_remote_shell_rsync_runs_is_read_for_the_guards_verb() {
    let line = "rsync -e \"ssh -o ProxyCommand='innerwarden allow x'\" x h1:y";
    assert!(runs_guard_loosening_verb(line), "{line}");
    let benign = "rsync -e \"ssh -o ProxyCommand='ssh -W %h:%p jump'\" x h1:y";
    assert!(!runs_guard_loosening_verb(benign), "{benign}");
}

/// Each command an ssh client runs from its options is read one level
/// deeper than the line that holds it: nested past the levels read, the
/// line is cut short and, naming the guard, refused.
///
/// FAILS ON REVERT: read the command at the same level (`depth * 1`) and the
/// line nested six deep is read to its end and let through.
#[test]
fn an_ssh_clients_command_nested_past_the_levels_read_is_refused() {
    fn quote(text: &str) -> String {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
    let mut line = String::from("true innerwarden-notes");
    assert!(!runs_guard_loosening_verb(&line), "{line}");
    for _ in 0..6 {
        line = format!("scp -o ProxyCommand={} x h1:y", quote(&line));
    }
    assert!(runs_guard_loosening_verb(&line), "{line}");
}

/// Each loosening verb found after a name pays for the words after it, not
/// for the words before it: a line of a name and reads of its lists is read
/// to its end within what it is given.
///
/// FAILS ON REVERT: pay `words.len() + at` and the budget runs out on the
/// second verb.
#[test]
fn a_verb_found_after_a_name_pays_for_the_words_after_it() {
    let words: Vec<String> = ["allow", "--list", "mute", "--list"]
        .iter()
        .map(|word| word.to_string())
        .collect();
    let budget = ReadingBudget {
        left: std::cell::Cell::new(6),
        ran_out: std::cell::Cell::new(false),
    };
    assert!(!loosening_verb_written_from(&words, &budget));
    assert!(!budget.ran_out(), "4 then 2 words fit in 6");
}

/// A name of the guard glued to an option of a program the line does not
/// know, with the kernel verb written further on, is the guard's.
///
/// FAILS ON REVERT: read a glued value as no name in
/// `guard_program_or_glued` (any of its conditions turned, or the name
/// asked of the guard's programs and of the line's names at once) and the
/// lines are let through.
#[test]
fn a_name_glued_to_an_option_of_an_unknown_program_is_the_guard() {
    for line in [
        "./run --bin=innerwarden x agent kernel off",
        "./run -pinnerwarden x agent kernel off",
    ] {
        assert!(changes_kernel_protection(line), "{line}");
    }
    let names = GuardNames::new();
    let assigned = ValuesAssigned::new();
    let word = |text: &str| crate::shell_words::read_line(text).commands[0].words[0].clone();
    assert!(matches!(
        guard_program_or_glued(&word("--bin=innerwarden"), &names, &assigned),
        GuardProgram::Is
    ));
    assert!(matches!(
        guard_program_or_glued(&word("--bin=mytool"), &names, &assigned),
        GuardProgram::Not
    ));
    assert!(matches!(
        guard_program_or_glued(&word("-aiw"), &names, &assigned),
        GuardProgram::Not
    ));
}

/// `lsm --apply` after the guard's name as an argument is read from the word
/// after the name: the name itself is not where the verb is.
///
/// FAILS ON REVERT: read what is written after an argument from the name
/// itself (`at * 1`) and the line is let through.
#[test]
fn the_kernel_guards_apply_after_the_name_as_an_argument_is_read() {
    for line in [
        "./run innerwarden lsm --apply",
        "ls innerwarden lsm --apply",
    ] {
        assert!(
            guard_words_refusal(line).is_some_and(|(_, score)| score == 60),
            "{line}"
        );
    }
}

/// A read of the guard's store the line hands a shell as its input, or
/// nests in substitutions past the levels read, is a read.
///
/// FAILS ON REVERT: ask the words and the input at once (`&&`), read the
/// input at a level back (`depth - 1`), or read a substitution at the same
/// level (`depth * 1`), and these lines are not reads.
#[test]
fn a_store_read_in_an_input_or_nested_deep_is_a_read() {
    assert!(reads_a_guard_store(
        "bash <<< 'cat /var/lib/innerwarden/d.jsonl'",
        0
    ));
    let mut nested = String::from("ls /var/lib/innerwarden");
    assert!(!reads_a_guard_store(&nested, 0), "{nested}");
    for _ in 0..=KERNEL_TEXT_DEPTH {
        nested = format!("echo \"$({nested})\"");
    }
    assert!(reads_a_guard_store(&nested, 0), "{nested}");
}

/// Past the levels read, a removal is any word that names one; at the last
/// level read it is still a program where it runs.
///
/// FAILS ON REVERT: compare the level with `>=` or `<` in `runs_a_removal`
/// and a word that only names `rm` at the last level, or at the first, is
/// taken for a removal.
#[test]
fn a_removal_is_read_where_it_runs_down_to_the_last_level() {
    assert!(!runs_a_removal("echo rm", 0));
    assert!(!runs_a_removal("echo rm", KERNEL_TEXT_DEPTH));
    assert!(runs_a_removal("echo rm", KERNEL_TEXT_DEPTH + 1));
    assert!(runs_a_removal("sudo rm -f x", KERNEL_TEXT_DEPTH));
}

/// What `rtk` runs: its verbose flags (`-v`, `-vv`, `--verbose`) and
/// `--skip-env` stepped past, the command after a runner's options and
/// `--`, none where it runs a string through a shell or an option it does
/// not take stands first.
///
/// FAILS ON REVERT: take `-` alone or `--v` for a verbose flag (`-` alone is
/// the tool rtk runs), step back
/// past `--skip-env`, drop the shell options of a runner, or answer
/// `word_is_an_option` `false`, and one of these starts elsewhere.
#[test]
fn where_the_command_rtk_runs_starts() {
    let words = |line: &str| -> Vec<String> { line.split(' ').map(str::to_string).collect() };
    for (line, start) in [
        ("rtk bypass ls", Some(2)),
        ("rtk -v bypass ls", Some(3)),
        ("rtk -vv --verbose bypass ls", Some(4)),
        ("rtk proxy --skip-env ls", Some(3)),
        ("rtk run -- ls", Some(3)),
        ("rtk git log", Some(1)),
        ("rtk - bypass ls", Some(1)),
        ("rtk --v bypass ls", None),
        ("rtk run -c ls", None),
        ("rtk run --command ls", None),
        ("rtk run --shell=bash ls", None),
        ("rtk run --command=ls", None),
        ("rtk run -x ls", None),
        ("rtk --version", None),
        ("rtk bypass", None),
        ("rtk run --", None),
        ("rtk run --skip-env --skip-env ls", Some(4)),
        ("rtk -v", None),
    ] {
        assert_eq!(rtk_command_start(&words(line), 0), start, "{line}");
    }
    assert!(word_is_an_option("-x"));
    assert!(word_is_an_option("--name"));
    assert!(!word_is_an_option("-"));
    assert!(!word_is_an_option("x"));
}

/// The words a shell takes for assignments run up to the program a command
/// runs, and through all the words of a builtin that sets a value.
///
/// FAILS ON REVERT: take a builtin that sets a value for the program a
/// command runs (`assignments_end` answering its place) and the values of
/// `export X=...` end before them.
#[test]
fn the_assignments_of_a_line_end_where_its_program_runs() {
    let words = |line: &str| {
        crate::shell_words::read_line(line).commands[0]
            .words
            .clone()
    };
    assert_eq!(assignments_end(&words("X=1 ls -la")), 1);
    assert_eq!(assignments_end(&words("env A=1 ls B=2")), 2);
    assert_eq!(assignments_end(&words("export X=1 Y=2")), 3);
    assert_eq!(assignments_end(&words("sudo local X=1")), 3);
}

/// Quotes `text` as one word for a shell, single quotes kept as `'\''`.
fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// An assignment's value is read one level deeper than the line: nested
/// past the levels read, the guard's program named where a program runs is
/// taken for a change. A chain of assignments with no blank in it is read
/// only this way (a word with a blank is also read whole as a line).
///
/// FAILS ON REVERT: read the value at the same level (`depth * 1` in
/// `runs_text_of`) and the bottom `innerwarden`, a bare name, is read and
/// let through.
#[test]
fn an_assignment_value_nested_past_the_levels_read_is_a_change() {
    assert!(!changes_kernel_protection("A3=A2=A1=A0=innerwarden"));
    assert!(changes_kernel_protection("A4=A3=A2=A1=A0=innerwarden"));
}

/// A store read nested in substitutions only a redirection holds, past the
/// levels read, is a read; and a removal nested in a shell's input past
/// them is any word that names one.
///
/// FAILS ON REVERT: read a nested substitution (`reads_a_guard_store`) or
/// an input (`runs_a_removal`) at the same level (`depth * 1`) and the
/// bottom, a listing or an `echo`, is read and let through.
#[test]
fn a_store_read_or_a_removal_nested_past_the_levels_read_is_taken() {
    let mut line = String::from("ls /var/lib/innerwarden");
    assert!(!reads_a_guard_store(&line, 0), "{line}");
    for _ in 0..6 {
        line = format!("cat < \"$({line})\"");
    }
    assert!(reads_a_guard_store(&line, 0), "{line}");
    let mut line = String::from("echo rm");
    assert!(!runs_a_removal(&line, 0), "{line}");
    // Five inputs deep, the bottom is read past the last level.
    for _ in 0..=KERNEL_TEXT_DEPTH {
        line = format!("bash <<< {}", quote(&line));
    }
    assert!(runs_a_removal(&line, 0), "{line}");
}

/// A stop verb pairs with the guard's name only in the same command: the
/// `;` right before the name ends the command the verb is in. (`doctor`,
/// not `status`: a line with an inspection verb is a read and never
/// reaches the pairing.)
///
/// FAILS ON REVERT: start the name's word at the `;` itself (`found * 1` in
/// `check_disable_verb_reaches_target`) and the stop of another service
/// pairs with the guard's name in the next command.
#[test]
fn a_stop_verb_pairs_with_the_name_only_in_its_own_command() {
    assert_eq!(
        check_security_tamper("systemctl stop nginx;innerwarden doctor"),
        None
    );
    assert!(check_security_tamper("systemctl stop innerwarden").is_some());
}

/// A path the text does not show whole before the name may be one of the
/// guard's places; a folder of one's own under the home is not.
///
/// FAILS ON REVERT: take a path not shown whole for a folder of one's own
/// (`unshown(before)` answering `false`) and the first two are not the
/// guard; take a letter and a `_` before the name together
/// (`is_ascii_alphanumeric() && ...`) and `$d_innerwarden` is.
#[test]
fn a_path_not_shown_before_the_name_may_be_the_guards() {
    let names = |line: &str| {
        let lower = line.to_ascii_lowercase();
        let at = lower.find("innerwarden").expect("a name");
        innerwarden_names_the_guard(&lower, at)
    };
    assert!(names("rm -rf $D/innerwarden/x"));
    assert!(names("rm -rf ${D}x/innerwarden/x"));
    assert!(!names("rm -rf ~/w/innerwarden/x"));
    assert!(!names("rm -rf $d_innerwarden/x"));
}

/// A store read nested exactly to the last level read is read as written;
/// past it, through a shell's input, it is taken for a read; a removal
/// nested past it through substitutions only a redirection holds is any
/// word that names one.
///
/// FAILS ON REVERT: stop at the last level instead of past it (`depth >=`,
/// `==`), read an input or a substitution at the same level (`depth * 1`),
/// and one of these answers moves.
#[test]
fn the_levels_of_store_reads_and_removals_end_past_the_last_one() {
    let mut line = String::from("ls /var/lib/innerwarden");
    for _ in 0..KERNEL_TEXT_DEPTH {
        line = format!("cat < \"$({line})\"");
    }
    assert!(!reads_a_guard_store(&line, 0), "{line}");
    let mut line = String::from("ls /var/lib/innerwarden");
    for _ in 0..=KERNEL_TEXT_DEPTH {
        line = format!("bash <<< {}", quote(&line));
    }
    assert!(reads_a_guard_store(&line, 0), "{line}");
    let mut line = String::from("echo rm");
    for _ in 0..=KERNEL_TEXT_DEPTH {
        line = format!("cat < \"$({line})\"");
    }
    assert!(runs_a_removal(&line, 0), "{line}");
}

/// What a search runs on each file it reads is a takedown of the guard when
/// that program takes it down; a read of the guard's store it runs is a
/// read, held elsewhere, not a takedown.
///
/// FAILS ON REVERT: keep only the store read among what a search runs
/// (`*what == GUARD_STORE_READ`) and both answers turn.
#[test]
fn a_search_running_a_takedown_is_one_and_a_store_read_is_not() {
    assert!(check_guard_takedown("rg --pre 'pkill -f innerwarden' pat").is_some());
    assert_eq!(
        check_guard_takedown("rg --pre 'cat /var/lib/innerwarden/x' pat"),
        None
    );
}
