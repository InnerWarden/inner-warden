//! Tests that kill mutants the weekly cargo-mutants sweep found surviving in
//! `threats.rs` (run 42450235934, 2026-11-08).

use super::*;

/// The reading alone, started `depth` command strings in. Since 1.6.12
/// `runs_guard_loosening_verb` also refuses a line that names the guard when
/// its reading was cut short; the tests here are about what the reading
/// itself reaches.
fn reads_a_loosening_verb(content: &str, depth: u8) -> bool {
    runs_guard_loosening_verb_in(content, depth, &ReadingBudget::for_line(content))
}

/// A word's characters with the marks the shell reader gives a brace
/// expansion in the middle of a word: `{`, `}` and `,` are pattern
/// characters, everything else is handed to the program as written.
fn brace_marked(text: &str) -> (Vec<char>, Vec<crate::shell_words::Mark>) {
    use crate::shell_words::Mark;
    let chars: Vec<char> = text.chars().collect();
    let marks: Vec<Mark> = chars
        .iter()
        .map(|&c| {
            if matches!(c, '{' | '}' | ',') {
                Mark::Pattern
            } else {
                Mark::Plain
            }
        })
        .collect();
    (chars, marks)
}

/// Interpreter code that runs the installer's short name `iw` with `agent
/// kernel` and a verb that is not a read turns the kernel protection off,
/// exactly as `innerwarden-ctl` would. The `iw` arm is the only thing that
/// recognises that short name in code; the wireless tool of the same name
/// (`iw dev wlan0 link`) is not the guard.
///
/// FAILS ON REVERT: delete match arm "iw" in code_changes_kernel_protection.
#[test]
fn interpreter_code_running_iw_agent_kernel_off_changes_kernel_protection() {
    assert!(
        code_changes_kernel_protection("subprocess.run(['iw', 'agent', 'kernel', 'off'])"),
        "`iw agent kernel off` run from code turns the kernel protection off; \
         the short name went unrecognised"
    );
    assert!(
        !code_changes_kernel_protection("subprocess.run(['iw', 'dev', 'wlan0', 'link'])"),
        "`iw` not followed by `host` or `agent` is the wireless tool, not the guard"
    );
}

/// After `agent kernel` in code, only the words that follow `kernel` are
/// weighed against the reads. The index of `kernel` is what sets where they
/// start; one short and `kernel` itself is weighed as an argument, so a
/// status read or a bare `agent kernel` is refused as a change.
///
/// FAILS ON REVERT: replace + with * in code_changes_kernel_protection
/// (either `+` beside `agent` in `tokens[at + 1 + agent + 1 + kernel]`).
#[test]
fn reading_the_kernel_protection_from_code_is_not_a_change() {
    for code in [
        "subprocess.run(['innerwarden-ctl', 'agent', 'kernel', 'status'])",
        "subprocess.run(['innerwarden', 'agent', 'kernel'])",
    ] {
        assert!(
            !code_changes_kernel_protection(code),
            "a read of the kernel protection was taken for a change, so the words \
             after `kernel` were read from the wrong place: {code}"
        );
    }
    assert!(
        code_changes_kernel_protection(
            "subprocess.run(['innerwarden-ctl', 'agent', 'kernel', 'off'])"
        ),
        "turning the kernel protection off from code must still be caught"
    );
}

/// An expansion whose text runs a guard program by its name (`$(command -v
/// innerwarden-ctl)`, `` `which iw-guard` ``) is that program, not a
/// program the shell may or may not name: the word is taken as the guard
/// itself. A name that is only a folder of a path runs nothing.
///
/// FAILS ON REVERT: replace runs_a_guard_program_by_name -> bool with false.
#[test]
fn an_expansion_that_runs_a_guard_program_by_name_is_the_guard() {
    for text in [
        "$(command -v innerwarden-ctl)",
        "$(which innerwarden)",
        "`which iw-guard`",
    ] {
        assert!(
            runs_a_guard_program_by_name(text),
            "the expansion runs a guard program by name and was not recognised: {text}"
        );
    }
    assert!(
        !runs_a_guard_program_by_name("$HOME/innerwarden/notes"),
        "a folder named innerwarden in a path runs no guard program"
    );

    let line = crate::shell_words::read_line("$(command -v innerwarden-ctl) agent kernel off");
    let word = &line.commands[0].words[0];
    assert!(
        matches!(
            guard_program(word, &GuardNames::new(), &ValuesAssigned::new()),
            GuardProgram::Is
        ),
        "a substitution that runs innerwarden-ctl by name must be taken for the guard \
         program itself, not a maybe: {}",
        word.text
    );
}

/// A brace group ends at the `}` that closes it, counting nested groups, so
/// `{a,b}` is one group and `{a,{b,c}}` closes at its last brace, not at the
/// first `}` met.
///
/// FAILS ON REVERT: replace == with != in brace_group_end.
#[test]
fn a_brace_group_ends_at_its_own_closing_brace() {
    let (chars, marks) = brace_marked("{a,b}");
    assert_eq!(
        brace_group_end(&chars, &marks, 0),
        Some(4),
        "the `}}` of `{{a,b}}` closes the group"
    );
    let (chars, marks) = brace_marked("{a,{b,c}}");
    assert_eq!(
        brace_group_end(&chars, &marks, 0),
        Some(8),
        "the outer group of `{{a,{{b,c}}}}` closes at its last brace, after the inner one"
    );
    assert_eq!(
        brace_group_end(&chars, &marks, 3),
        Some(7),
        "the inner group of `{{a,{{b,c}}}}` closes at its own brace"
    );
}

/// A guard program named through a brace expansion (`inner{w,x}arden`)
/// could be the guard: the group reads as its alternatives, and a sequence
/// (`{1..3}`) as each of its members. Without the group's end, or with the
/// inside of the group read as anything else, the name is never matched.
///
/// FAILS ON REVERT: replace brace_group_regex -> String with "xyzzy".into(),
/// or replace == with != in brace_group_end.
#[test]
fn a_brace_list_in_a_program_name_reads_as_its_alternatives() {
    let (chars, marks) = brace_marked("w,x");
    assert_eq!(
        brace_group_regex(&chars, &marks),
        "(?:w|x)",
        "a brace list reads as one alternative per member"
    );
    let (chars, marks) = brace_marked("1..3");
    assert_eq!(
        brace_group_regex(&chars, &marks),
        "(?:1|2|3)",
        "a brace sequence reads as each of its members"
    );
    let (chars, marks) = brace_marked("inner{w,x}arden");
    assert!(
        pattern_could_be(&chars, &marks, "innerwarden"),
        "`inner{{w,x}}arden` can become innerwarden, and was not read that way"
    );
}

/// A loosening verb inside nested shells is read down to the fourth level
/// in: `innerwarden dry-run` handed to a shell three levels deep is read at
/// depth four and still refused. Only text deeper than that is left unread.
///
/// FAILS ON REVERT: replace > with == in runs_guard_loosening_verb_in.
#[test]
fn a_loosening_verb_at_the_deepest_level_read_is_still_caught() {
    assert!(
        reads_a_loosening_verb("innerwarden dry-run", 4),
        "depth four is the last level read, not a level skipped"
    );
    assert!(
        reads_a_loosening_verb("sh -c 'innerwarden dry-run'", 3),
        "a shell at depth three hands its string to depth four, which is still read"
    );
}

/// Reading past `--` and past an option written with its value
/// (`--data-dir=/var/lib/innerwarden`) to the subcommand after `agent` or
/// `agents` is what lets `agent --data-dir=X disconnect` be refused while
/// `agents --data-dir=X list` is not. The index has to move past each such
/// word; if it stays put the read never ends, so it runs on a thread of its
/// own and a hang fails the test instead of timing the run out.
///
/// FAILS ON REVERT: replace += with *= in first_positional.
#[test]
fn the_subcommand_after_an_end_of_options_or_an_option_with_its_value_decides() {
    use std::sync::mpsc;
    use std::time::Duration;

    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let verdicts: Vec<bool> = [
            "innerwarden-ctl agent --data-dir=/var/lib/innerwarden disconnect",
            "innerwarden agents -- approve claude-code",
            "innerwarden agents --data-dir=/tmp/iw list",
        ]
        .iter()
        .map(|cmd| reads_a_loosening_verb(cmd, 0))
        .collect();
        let _ = done_tx.send(verdicts);
    });
    let verdicts = done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("reading past `--` or `--name=value` never returned: the index does not advance");
    assert_eq!(
        verdicts,
        [true, true, false],
        "disconnect and approve after a skipped word lower the guard; list does not"
    );
}

/// A write into the guard's configuration is read down to the fourth level
/// of nested text: at depth four a redirect into `~/.config/innerwarden/`
/// is still a write.
///
/// FAILS ON REVERT: replace > with == in writes_guard_config, or replace >
/// with >= in writes_guard_config.
#[test]
fn a_guard_config_write_at_the_deepest_level_read_is_still_caught() {
    assert!(
        writes_guard_config("echo x > ~/.config/innerwarden/suppress.toml", 4),
        "depth four is the last level read, and a write there was missed"
    );
}

/// The perl inline-code check refuses perl code that names the guard's
/// configuration and writes it. Both halves must hold: a perl one-liner that
/// only reads a file in the configuration is ordinary work, not a write.
///
/// FAILS ON REVERT: replace && with || in writes_guard_config.
#[test]
fn a_perl_one_liner_that_only_reads_the_guard_config_is_not_a_write() {
    assert!(
        !writes_guard_config("perl -ne 'print' ~/.config/innerwarden/suppress.toml", 0),
        "perl that only prints the configuration was refused as a write to it"
    );
    assert!(
        writes_guard_config(
            r#"perl -e 'open(my $f, ">>", "$ENV{HOME}/.config/innerwarden/suppress.toml")'"#,
            0
        ),
        "perl code that opens the configuration for append must still be a write"
    );
}
