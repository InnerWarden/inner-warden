//! Tests that kill mutants the weekly cargo-mutants sweep found surviving in
//! `threats.rs` (run 42450235934, 2026-11-08).

use super::*;

/// Each array a line assigns is read one level deeper than the line, so text
/// nested in arrays past [`KERNEL_TEXT_DEPTH`] is not read on: what is left
/// is taken for a change when it names a guard program. Read at the depth of
/// the line instead, no nesting of arrays ever reaches the limit, and the
/// guard program at the bottom is read as a plain `status`.
///
/// FAILS ON REVERT: replace `+` with `*` in the `depth + 1` the arrays are
/// read at in `guard_words_in`.
#[test]
fn arrays_nested_past_the_text_depth_are_taken_for_a_change() {
    let shallow = "echo a=(innerwarden status)";
    assert!(
        !changes_kernel_protection(shallow),
        "one array deep, `innerwarden status` is read, and it is a read: {shallow}"
    );
    let mut deep = String::from("innerwarden status");
    for _ in 0..=KERNEL_TEXT_DEPTH {
        deep = format!("echo a=({deep})");
    }
    assert!(
        changes_kernel_protection(&deep),
        "every array must count a level, so a guard program nested past \
         KERNEL_TEXT_DEPTH is taken for a change: {deep}"
    );
}

/// `--` ends a guard program's options: the word after it is the verb, not
/// the value of an option. `xargs innerwarden -- status` runs `status`, with
/// whatever xargs adds after it, which is no `agent` verb. Taken for an
/// option that waits for a value, `--` would swallow `status` and leave the
/// verb to the words xargs adds, refusing a read.
///
/// FAILS ON REVERT: delete the `!` in `!options_end && text == "--"` in
/// `kernel_arguments_change`.
#[test]
fn a_verb_after_the_end_of_options_is_the_verb_even_when_words_are_fed() {
    let read = "xargs innerwarden -- status";
    let line = crate::shell_words::read_line(read);
    let words = &line.commands[0].words;
    assert!(
        !kernel_arguments_change(&words[2..], true, false),
        "`status` after `--` is the verb; reading `--` as an option with a \
         value skips it and leaves the verb to the fed words"
    );
    assert!(
        !changes_kernel_protection(read),
        "`{read}` runs `status`, a read, and was refused"
    );
    assert!(
        changes_kernel_protection("xargs innerwarden --"),
        "with no verb after `--`, the words xargs adds are the verb and may \
         change the kernel protection"
    );
}

/// An expansion that is the value of an option before the guard program
/// (`sudo -u $USER`) names a user, not a program that adds words to the
/// guard's command line. Taken for one, every read run under `sudo -u` would
/// be refused as a change. An expansion that stands where a program does
/// (`$RUNNER`) may still add words.
///
/// Written against `words_are_fed` (`at > 0`), which 1.6.12 replaced with a
/// table filled word by word (`WordsFed`): what stays is the behaviour.
#[test]
fn an_options_value_before_the_guard_program_feeds_it_no_words() {
    let read = "sudo -u $USER innerwarden agent kernel status";
    assert!(
        !changes_kernel_protection(read),
        "`{read}` only reads the kernel protection and was refused"
    );
}

/// What a substitution prints becomes words of the command, so a guard
/// program printed by one, with its `agent kernel off`, runs. Here the name
/// is a pattern (`inner?arden`) that no other reading of the line takes for
/// the guard's, so only the words the substitution shows find it.
///
/// FAILS ON REVERT: make `words_with_substitutions_shown` return
/// `vec![Default::default()]`.
#[test]
fn the_words_a_substitution_prints_are_read_as_the_command() {
    let line = crate::shell_words::read_line("run $(echo a b) c");
    let shown: Vec<String> = words_with_substitutions_shown(&line.commands[0].words)
        .into_iter()
        .map(|word| word.text)
        .collect();
    assert_eq!(
        shown,
        ["run", "echo", "a", "b", "c"],
        "the substitution's words must stand where the substitution was"
    );
    let printed = "$(echo /usr/bin/inner?arden agent kernel off)";
    assert!(
        changes_kernel_protection(printed),
        "a substitution that prints the guard's `agent kernel off` was allowed: {printed}"
    );
}

/// A program named by a path that ends in a variable the line set
/// (`P=innerwarden-ctl; /usr/bin/$P`) is the program the value names: the
/// values the line assigns are what a later `$P` stands for. With them lost,
/// `agent $X` after it, a verb the text does not show, would pass.
///
/// FAILS ON REVERT: make `values_assigned` return
/// `vec![(String::new(), Default::default())]`.
#[test]
fn a_value_the_line_assigned_names_the_program_a_variable_runs() {
    let text = "P=innerwarden-ctl";
    let assigned = values_assigned(&crate::shell_words::read_line(text), text.len(), None);
    let pairs: Vec<(&str, &str)> = assigned
        .shown
        .iter()
        .flat_map(|(name, values)| {
            values
                .iter()
                .map(move |value| (name.as_str(), value.text.as_str()))
        })
        .collect();
    assert_eq!(
        pairs,
        [("P", "innerwarden-ctl")],
        "the line assigns `P` the value `innerwarden-ctl`"
    );
    let line = "P=innerwarden-ctl; /usr/bin/$P agent $X";
    assert!(
        changes_kernel_protection(line),
        "`/usr/bin/$P` runs the guard program the line put in `P`, with a hidden verb: {line}"
    );
}

/// A value's marks start right after its name and `=`: in `P=x$Y` the `$Y`
/// is the expansion, and in `P=i*en` the `*` is the pattern that, with `i`
/// and `en` written as they are, spells enough of `innerwarden` for
/// `/usr/bin/$P` to be it. Read from two characters too early, the marks
/// fall on the wrong letters: the expansion is taken as written, and the
/// `n` turns into a pattern character, leaving too little written to name
/// the guard.
///
/// Written against the marks `values_assigned` kept for `P=x$Y`; since
/// 1.6.12 it keeps only values that hold no expansion, so what stays is the
/// pattern read in its place.
#[test]
fn an_assigned_values_marks_start_right_after_the_equals_sign() {
    let line = "P=i*en; /usr/bin/$P agent $X";
    assert!(
        changes_kernel_protection(line),
        "`$P` holds a pattern that spells the guard program, with a hidden verb: {line}"
    );
}

/// `${NAME}` is the braced form of `$NAME`: the name runs to the closing
/// `}`. `P=inner; ${P}warden` is `innerwarden`, so `agent $X` after it is the
/// guard's verb hidden. Ending the name anywhere else leaves it empty, and
/// the guard program goes unrecognised.
///
/// FAILS ON REVERT: replace `==` with `!=` in the search for `}` in
/// `with_values_assigned`.
#[test]
fn a_braced_variable_is_replaced_by_its_value_up_to_the_closing_brace() {
    let text = "P=inner; ${P}warden";
    let read = crate::shell_words::read_line(text);
    let assigned = values_assigned(&read, text.len(), None);
    let Spelled::Words(words) = with_values_assigned(&read.commands[1].words[0], &assigned) else {
        panic!("`${{P}}` names a value the line assigned");
    };
    let spelt: Vec<String> = words.into_iter().map(|word| word.text).collect();
    assert_eq!(spelt, ["innerwarden"], "`${{P}}warden` with `P=inner`");
    let line = "P=inner; ${P}warden agent $X";
    assert!(
        changes_kernel_protection(line),
        "`${{P}}warden` is `innerwarden`, with a hidden verb: {line}"
    );
}

/// A `$NAME` takes the values of that name only. `Q=x; P=inner; ${P}warden`
/// is `innerwarden`, and `P=x; Q=inner; ${P}warden` is `xwarden`, which is no
/// guard program.
///
/// FAILS ON REVERT: replace `==` with `!=` in the name filter of
/// `with_values_assigned`.
#[test]
fn a_variable_takes_the_values_of_its_own_name_only() {
    let own = "Q=x; P=inner; ${P}warden agent $X";
    assert!(
        changes_kernel_protection(own),
        "`${{P}}warden` with `P=inner` is the guard program, with a hidden verb: {own}"
    );
    let other = "P=x; Q=inner; ${P}warden agent $X";
    assert!(
        !changes_kernel_protection(other),
        "`${{P}}warden` with `P=x` is `xwarden`; `Q`'s value is not `P`'s: {other}"
    );
}

/// [`MAX_ASSIGNED_SPELLINGS`] is how many spellings a word may make, and
/// that many are still made. A name given that many values on the line, one
/// of them `inner`, spells `innerwarden` among its ways, and `agent $X` after
/// it is refused.
///
/// FAILS ON REVERT: replace `>` with `==` in the spellings limit of
/// `with_values_assigned`.
#[test]
fn a_word_may_make_exactly_the_most_spellings_allowed() {
    let mut line: String = (1..MAX_ASSIGNED_SPELLINGS)
        .map(|n| format!("A=v{n}; "))
        .collect();
    line.push_str("A=inner; ${A}warden agent $X");
    let read = crate::shell_words::read_line(&line);
    let assigned = values_assigned(&read, line.len(), None);
    let word = &read
        .commands
        .last()
        .expect("the line ends with the command that runs the word")
        .words[0];
    let made = match with_values_assigned(word, &assigned) {
        Spelled::Words(spellings) => Some(spellings.len()),
        Spelled::TooMany | Spelled::Unread => None,
    };
    assert_eq!(
        made,
        Some(MAX_ASSIGNED_SPELLINGS),
        "exactly MAX_ASSIGNED_SPELLINGS ways are within the limit"
    );
    assert!(
        changes_kernel_protection(&line),
        "one of the MAX_ASSIGNED_SPELLINGS ways is `innerwarden`, with a hidden verb: {line}"
    );
}

/// `less` and `more` only show the files their words name, so their words
/// run nothing; once what they print goes to a file they are readers no
/// more, and their words are read as a command line.
///
/// FAILS ON REVERT: delete the first `!`, in `!command.writes_file`, of the
/// `less` and `more` arm in `command_only_shows_text`.
#[test]
fn a_pager_shows_text_only_while_it_writes_no_file() {
    for pager in ["less", "more"] {
        let shown = format!("{pager} innerwarden-ctl agent kernel claude-code off");
        assert!(
            command_only_shows_text(&crate::shell_words::read_line(&shown).commands, 0),
            "`{shown}` only shows files"
        );
        assert!(
            !changes_kernel_protection(&shown),
            "`{shown}` runs nothing and was refused"
        );
        let written = format!("{shown} > /tmp/pager.txt");
        assert!(
            !command_only_shows_text(&crate::shell_words::read_line(&written).commands, 0),
            "`{written}` writes a file, so it is no reader"
        );
        assert!(
            changes_kernel_protection(&written),
            "`{written}` is no reader, and its words name the guard's `agent kernel off`"
        );
    }
}
