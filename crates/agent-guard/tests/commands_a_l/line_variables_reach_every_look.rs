//! A value the line itself gives a name reaches every look the guard
//! takes at the line, not only the ones that read assignments themselves.
//! Measured 2026-11-21 on main 003699c (analyze_command, empty home), each
//! allowed where the line typed out with the value is refused:
//!
//! * `X=/; rm -rf $X`, `X=/; rm -rf "$X"`, `X=~/.ssh; rm -rf $X`, with
//!   `export`, `declare`, `local`, `readonly`, `typeset` in front, the
//!   value set before the command (`X=/ rm -rf $X`), a one-word loop, a
//!   value through another name;
//! * `X=/dev/sda; dd if=/dev/zero of=$X`;
//! * the program word from a variable (`P=rm; $P -rf /`);
//! * a file the line writes and then loads (`echo 'X=/' > e.sh; . ./e.sh;
//!   rm -rf $X`), which was held for review.
//!
//! And a file the line loads that sets a name the guard reads in its own
//! way (`PATH`) by `read`, `unset`, `printf -v`, `mapfile` or a loop is
//! held as one that assigns it.
//!
//! Nothing here is executed: every line is only screened.

use innerwarden_agent_guard::mcp::analyze_command;
use innerwarden_agent_guard::rules::RuleEngine;

fn verdict(command: &str) -> String {
    analyze_command(command, Some(&RuleEngine::load_embedded())).recommendation
}

/// FAILS ON REVERT: take `analyze_command_with_its_values` out of
/// `analyze_command_unwrapped` (mcp.rs) and each of these is allowed.
#[test]
fn a_value_the_line_assigns_reaches_the_target_of_a_removal() {
    for line in [
        "X=/; rm -rf $X",
        "X=/; rm -rf \"$X\"",
        "X=/; rm -rf ${X}",
        "X=/; rm -rf \"${X}\"",
        "X='/'; rm -rf \"$X\"",
        "X=~/.ssh; rm -rf $X",
        "X=/ rm -rf $X",
        "export X=/; rm -rf $X",
        "export X=/ && rm -rf \"$X\"",
        "declare X=/; rm -rf $X",
        "local X=/; rm -rf $X",
        "readonly X=/; rm -rf $X",
        "typeset X=/; rm -rf $X",
        "X=/etc; rm -rf $X",
        "X=/usr; rm -rf \"$X\"",
        "X=$HOME; rm -rf $X",
        "X=~; rm -rf $X",
        "for X in /; do rm -rf $X; done",
        "X=/; Y=$X; rm -rf $Y",
        "X=/; rm -rf -- \"$X\"",
        "X=/; sudo rm -rf $X",
        "X=/; sh -c \"rm -rf $X\"",
        "X=/dev/sda; dd if=/dev/zero of=$X",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// The program word from a variable the line sets.
#[test]
fn a_program_word_the_line_assigns_is_read_as_the_program() {
    for line in [
        "P=rm; $P -rf /",
        "P=rm; \"$P\" -rf /",
        "P=/bin/rm; $P -rf /",
        "P=rm; F=-rf; T=/; $P $F $T",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// The assignments of a file the line writes and then loads (#355) reach
/// the rest of the line as the same assignments typed out.
#[test]
fn a_value_from_a_file_the_line_loads_reaches_the_rest_of_it() {
    for line in [
        "echo 'X=/' > e.sh; . ./e.sh; rm -rf $X",
        "echo 'export X=/' > e.sh && source ./e.sh && rm -rf \"$X\"",
        "printf 'X=~/.ssh\\n' > e.sh; . ./e.sh; rm -rf $X",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// A value the line does not show, at a removal: a person decides.
#[test]
fn a_value_the_line_does_not_show_at_a_removal_is_held() {
    for line in [
        "read X; rm -rf $X",
        "printf -v X /; rm -rf $X",
        "rm -rf $UNKNOWN",
        "rm -rf \"$1\"",
        "X=$(cat target.txt); rm -rf \"$X\"",
    ] {
        assert_ne!(verdict(line), "allow", "{line}");
    }
}

/// Every builtin that gives a name a value, in a file the line loads,
/// counts as the assignment does for a name the guard reads in its own way
/// (the search path): the same table as the reading of a line.
#[test]
fn every_way_a_loaded_file_sets_the_search_path_is_held() {
    for line in [
        "echo 'read PATH' > e.sh; . ./e.sh; ls",
        "echo 'unset PATH' > e.sh; . ./e.sh; ls",
        "echo 'printf -v PATH /tmp/x' > e.sh; . ./e.sh; ls",
        "echo 'mapfile PATH' > e.sh; . ./e.sh; ls",
        "echo 'for PATH in /tmp/x; do :; done' > e.sh; . ./e.sh; ls",
    ] {
        assert_ne!(verdict(line), "allow", "{line}");
    }
    for line in [
        "echo 'read NAME' > e.sh; . ./e.sh; ls",
        "echo 'for F in a b; do echo $F; done' > e.sh; . ./e.sh; ls",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// A project folder in a variable stays the person's to remove and make.
#[test]
fn a_project_folder_in_a_variable_stays_allowed() {
    for line in [
        "X=build; rm -rf $X",
        "X=build; rm -rf \"$X\"",
        "X=build; rm -rf \"${X}\"",
        "D=/tmp/x; mkdir -p $D",
        "D=/tmp/x; mkdir -p \"$D\" && cd \"$D\"",
        "D=dist; rm -rf \"$D\" && mkdir -p \"$D\"",
        "X=node_modules; rm -rf ./$X",
        "OUT=target/release; ls $OUT",
        "N=3; echo $N",
        "X=/; echo \"removing $X\"",
        "X=/; git status",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

// The review of #364 (2026-11-21). Measured with analyze_command and an
// empty home; "before" is the branch of #368 this one is built on, which
// holds #364.

/// A value a line handed to another shell sets from the values around it
/// (before: deny 50 through the place a removal runs; review on main), two
/// shells deep, and through `eval`: read at the line's own level.
#[test]
fn a_value_set_inside_a_line_handed_on_is_read() {
    for line in [
        "X=/; sh -c 'Y=$X; rm -rf $Y'",
        "X=/; bash -c 'Y=$X; rm -rf \"$Y\"'",
        "X=/; sh -c 'sh -c \"Y=\\$X; rm -rf \\$Y\"'",
        "X=/; sh -c \"sh -c \\\"rm -rf \\\\\\$X\\\"\"",
        "X=/; eval 'Y=$X; rm -rf $Y'",
        "X=/; eval 'rm -rf $X'",
        "X=/ sh -c 'rm -rf $X'",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// A value made of names and plain text (before: allowed, the value was
/// not read).
#[test]
fn a_value_made_of_names_and_text_is_read() {
    for line in [
        "D=$HOME/.ssh; rm -rf $D",
        "D=${HOME}/.ssh; rm -rf \"$D\"",
        "D=$HOME; rm -rf $D/..",
        "A=/; B=${A}etc; rm -rf $B",
        "X=/; X+=etc; rm -rf $X",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// The value in effect where the name is used, not the first nor the last
/// the line gives it (before: deny 50; review on main: a name given two
/// values was not read).
#[test]
fn the_value_in_effect_where_the_name_is_used_is_read() {
    for line in [
        "X=/; rm -rf $X; X=build",
        "X=/; rm -rf $X; X=build; echo $X",
        "X=build; X=/; rm -rf $X",
        "X=/; rm -rf $X; unset X",
        "X=/; (rm -rf $X)",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// What the shell does: a name used before it is set, taken away by an
/// `unset` that surely runs, or set in a subshell that has closed does not
/// hold the value. Before: deny 90 each, from the first value the line gave
/// the name.
#[test]
fn a_value_that_does_not_hold_where_the_name_is_used_is_not_read() {
    for line in [
        "X=/; unset X; rm -rf $X",
        "(X=/); rm -rf $X",
        "X=build; rm -rf $X; X=/",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
    // A value the line does not show: held, as `rm -rf $X` alone is.
    for line in [
        "rm -rf $X; X=/",
        "sh -c 'X=/'; rm -rf $X",
        "X=/; read X <<< build; rm -rf $X",
    ] {
        assert_eq!(verdict(line), "review", "{line}");
    }
}

/// Second review of this change (2026-11-21): an unknown value never puts
/// out a known one. A value read from input, or taken away only maybe (under
/// `if`, `&&` or `||`, in a function body, in a pipeline, whose last part
/// bash runs in a subshell), leaves the value before it a candidate; a
/// function body reads any value the line gives the name, as it is called
/// later; a here-string is expanded before `read` runs; `$PWD` after a
/// `cd` the line does not spell out is not the starting folder; `read -s`
/// and `mapfile -t` take no argument; `printf -v X /` gives `/`. Each
/// line was measured on the first version of this change, before the fix:
/// allow or review except where noted.
#[test]
fn an_unknown_value_never_puts_out_a_known_one() {
    for line in [
        "X=/; read X; rm -rf $X",
        "X=/; if false; then unset X; fi; rm -rf $X",
        "X=/; f(){ unset X; }; rm -rf $X",
        "X=/; echo x | read X; rm -rf $X",
        "X=/; false && unset X; rm -rf $X",
        "f(){ rm -rf $X; }; X=/ f",
        "X=/; read X <<< \"$X\"; rm -rf $X",
        "X=/; read X <<< $X; rm -rf $X",
        "cd $(echo /); D=$PWD/etc; rm -rf $D",
        "cd /; D=$PWD/etc; rm -rf $D",
        "X=/; read -s X; rm -rf $X",
        "X=/; mapfile -t X; rm -rf $X",
        "printf -v X /; rm -rf $X",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    // `declare -n R=X` makes R another name: not read as the text `X`.
    assert_ne!(verdict("declare -n R=X; X=/; rm -rf $R"), "allow");
    for line in [
        "D=$PWD/build; rm -rf $D",
        "cd build; D=$PWD/out; rm -rf $D",
        "X=build; if true; then unset X; fi; rm -rf $X",
        "read -s PASS; echo ok",
        "mapfile -t lines < f.txt; echo \"${lines[0]}\"",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// Item 7: a project folder set through a name stays the person's.
#[test]
fn a_project_folder_through_a_composite_value_stays_allowed() {
    for line in [
        "D=/tmp/x; rm -rf $D",
        "D=$PWD/build; rm -rf $D",
        "OUT=target; cargo build --target-dir $OUT",
        "D=$HOME/x; rm -rf $D",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// A loaded file whose text says `read` in prose sets nothing: only a reader
/// where a command stands counts (before: review).
#[test]
fn prose_after_read_in_a_loaded_file_sets_no_name() {
    assert_eq!(
        verdict("echo 'echo please read PATH now' > e.sh; . ./e.sh; ls"),
        "allow"
    );
    assert_ne!(verdict("echo 'read PATH' > e.sh; . ./e.sh; ls"), "allow");
    assert_ne!(
        verdict("echo 'true; unset PATH' > e.sh; . ./e.sh; ls"),
        "allow"
    );
}

/// Final review of this change (2026-11-21): a use in a loop body reads the
/// value the same body gives the name later, the next time round (main:
/// deny 90; the first version of this change: allow). Outside a loop a use
/// before the assignment stays as `rm -rf $X` alone is.
#[test]
fn a_value_a_loop_gives_later_reaches_the_next_time_round() {
    for line in [
        "for i in 1 2; do rm -rf $X; X=/; done",
        "while true; do rm -rf $X; X=/; done",
        "until false; do rm -rf $X; X=/; done",
        "X=build; for i in 1 2; do rm -rf $X; X=/; done",
        "X=/; for i in 1 2; do rm -rf $X; X=build; done",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    assert_eq!(verdict("rm -rf $X; X=/"), "review");
    assert_eq!(
        verdict("for i in 1 2; do X=build; rm -rf $X; done"),
        "allow"
    );
}
