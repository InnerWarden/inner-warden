//! An `xargs kill` that reads a file takes the reach of the listing that
//! filled it only when that listing is the command that wrote this file
//! last. Any other writer leaves ids the line does not show.
//!
//! Measured on main with `analyze_command` (2026-11-24):
//! `pgrep -f vite > /tmp/q; cat ids > /tmp/p; xargs kill < /tmp/p` was
//! allowed, with the reach of `pgrep -f vite`, though `/tmp/p` holds what
//! `cat ids` printed.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

fn all(lines: &[&str], expected: &str) {
    for line in lines {
        assert_eq!(verdict(line), expected, "{line}");
    }
}

/// FAILS ON REVERT: let `file_written_by_a_lister` take any lister that
/// writes some file instead of the last writer of this one, and these are
/// allowed.
#[test]
fn a_file_another_command_wrote_holds_ids_the_line_does_not_say() {
    all(
        &[
            "pgrep -f vite > /tmp/q; cat ids > /tmp/p; xargs kill < /tmp/p",
            "pgrep -f vite > /tmp/p; cat ids >> /tmp/p; xargs kill < /tmp/p",
            "pgrep -f vite > /tmp/p; cat ids > /tmp/p; xargs kill -9 < /tmp/p",
            "pgrep -f vite > /tmp/q; xargs kill < /tmp/p",
            "pidof node > q; cp ids p; xargs kill -9 < p",
        ],
        "review",
    );
}

/// The listing that wrote the file last is read, as before.
#[test]
fn the_listing_that_wrote_the_file_last_is_read() {
    all(
        &[
            "pgrep -f vite > /tmp/p; xargs kill < /tmp/p",
            "pidof node > pids; xargs kill -9 < pids",
            "cat ids > /tmp/p; pgrep -f vite > /tmp/p; xargs kill < /tmp/p",
            "pgrep -f node > /tmp/q; pgrep -f vite > /tmp/p; xargs kill < /tmp/p",
        ],
        "allow",
    );
    all(&["pgrep -f sensor > /tmp/p; xargs kill < /tmp/p"], "review");
}

/// A listing of the guard anywhere on a line that kills stays refused,
/// whichever file the kill reads.
#[test]
fn a_listing_of_the_guard_stays_refused() {
    all(
        &[
            "pgrep -f innerwarden-agent > /tmp/p; xargs kill < /tmp/p",
            "pgrep -f innerwarden-agent > /tmp/q; cat ids > /tmp/p; xargs kill < /tmp/p",
            "cat ids > /tmp/p; pgrep innerwarden > /tmp/p; xargs kill < /tmp/p",
        ],
        "deny",
    );
}
