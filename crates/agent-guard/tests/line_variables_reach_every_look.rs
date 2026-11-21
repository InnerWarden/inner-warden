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

/// The program word from a variable the line sets (T-089, item 2).
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
