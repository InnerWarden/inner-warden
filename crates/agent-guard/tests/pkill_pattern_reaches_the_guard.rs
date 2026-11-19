//! A `pkill -f` is a kill of the guard when its pattern matches the guard.
//!
//! `pkill -f` matches its pattern, a regular expression, against every
//! process's command line. Measured 2026-11-19 on main: `pkill -f
//! innerwarden-agent-guard` (a test run of the crate) and `pkill -f 'cargo
//! test -p innerwarden-agent-guard'` were refused as a kill of the guard,
//! for the words they hold, and `pkill -f '[i]nnerwarden-agent'`, which does
//! kill the agent, was allowed. The pattern is now matched against the
//! command lines the guard's processes run with: one that matches none of
//! them kills none, and one that matches them by the guard's name, however
//! spelt, is refused.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

/// FAILS ON REVERT: read every `pkill` by its words again and each is
/// refused for naming the guard.
#[test]
fn a_pkill_whose_pattern_matches_no_guard_process_is_not_a_kill_of_the_guard() {
    for line in [
        r##"pkill -f inline_verdict_by_resolved_line"##,
        r##"pkill -f 'cargo test -p innerwarden-agent-guard'"##,
        r##"pkill -f innerwarden-agent-guard"##,
        r##"pkill -9 -f innerwarden-agent-guard"##,
        r##"timeout 5 pkill -f innerwarden-agent-guard"##,
        r##"pkill -f -- innerwarden-agent-guard"##,
        r##"pkill -f target/debug/deps/innerwarden_agent_guard"##,
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// The patterns that do reach the guard, and every form not read surely
/// (`-F` is a pidfile, two patterns, a pattern that is not a regular
/// expression), keep their refusal.
#[test]
fn a_pkill_whose_pattern_matches_a_guard_process_is_still_refused() {
    for line in [
        r##"pkill -f innerwarden"##,
        r##"pkill -f 'innerwarden-agent'"##,
        r##"pkill innerwarden"##,
        r##"sudo pkill -f innerwarden-sensor"##,
        r##"pkill -f 'INNERWARDEN'"##,
        r##"pkill -F /run/innerwarden-agent.pid"##,
        r##"pkill -f 'innerwarden(-agent)?'"##,
        r##"pkill -f 'innerwarden hook'"##,
        r##"pkill -f 'innerwarden mcp-proxy'"##,
        r##"pkill -f innerwarden-dns-guard"##,
        r##"pkill -f 'innerwarden-agent-guard|innerwarden-agent'"##,
        r##"pkill -f x; pkill -f innerwarden"##,
        r##"pkill -f innerwarden-agent-guard innerwarden"##,
        r##"pkill -f '(' innerwarden"##,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// Allowed on main (measured 2026-11-19): the pattern spells the guard's
/// name so the plain words miss it, and still matches its processes.
///
/// FAILS ON REVERT: drop the match of the pattern by the name and each is
/// allowed.
#[test]
fn a_pattern_that_spells_the_guard_another_way_is_refused() {
    for line in [
        r##"pkill -f 'inner.arden'"##,
        r##"pkill -f '[i]nnerwarden-agent'"##,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}
