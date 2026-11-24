//! Kills of the guard that a line reads by what it reaches: its dashboard's
//! port (`fuser`, `lsof -t`), a unit named for its shortcut, a `pkill -f` or
//! `pgrep -f` pattern made of a piece of a daemon's own file name, and an
//! `xargs kill` whose ids the line does not say.
//!
//! Measured on main with `analyze_command` (2026-11-24): every line in the
//! first three tests was allowed. The port and the unit name only the
//! guard, so they are refused. A piece of a daemon's file name (`sensor`)
//! is in other programs' names too, and ids from a file may be anyone's:
//! those are held for a person, as the default posture asks for every
//! finding outside the high-certainty class.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

fn all(lines: &[&str], expected: &str) {
    for line in lines {
        assert_eq!(verdict(line), expected, "{line}");
    }
}

/// FAILS ON REVERT: take `lsof_reach` out of `listed_reach`, or
/// `fuser_reach` out of `pgrep_feeds_a_kill_of_the_guard`, and the port
/// forms are allowed.
#[test]
fn a_kill_by_the_guards_port_is_refused() {
    all(
        &[
            "fuser -k 8787/tcp",
            "sudo fuser -k 8787/tcp",
            "fuser -km 8787/tcp",
            "fuser --kill 8787/tcp",
            "fuser -k -n tcp 8787",
            "fuser -k /usr/local/bin/innerwarden",
            "lsof -ti:8787 | xargs kill",
            "lsof -t -i :8787 | xargs kill -9",
            "lsof -ti tcp:8787 | xargs -r kill",
            "kill $(lsof -t -i:8787)",
            "kill -9 `lsof -ti:8787`",
        ],
        "deny",
    );
}

/// FAILS ON REVERT: take `shortcut_unit` out of `systemctl_lowers` and the
/// shortcut's unit is allowed.
#[test]
fn a_unit_named_for_the_guards_shortcut_is_refused() {
    all(
        &[
            "systemctl kill iw-guard",
            "sudo systemctl kill -s KILL iw-guard.service",
            "systemctl stop iw-guard",
        ],
        "deny",
    );
}

/// FAILS ON REVERT: take the file-name piece out of `GuardLine::reach_of`
/// and the daemon forms are allowed; take `xargs_kill_unread` out of
/// `feeds_kill` and the ids from a file are.
#[test]
fn a_daemons_name_piece_or_ids_the_line_does_not_say_are_held_for_review() {
    all(
        &[
            "pkill -f sensor",
            "pkill -f watchdog",
            "pkill -f dns-guard",
            "pgrep -f sensor | xargs kill",
            "pgrep -f watchdog | xargs kill -9",
            "kill $(pgrep -f dns-guard)",
            "xargs kill < pids.txt",
            "cat pids | xargs kill -9",
            "xargs -a pids.txt kill",
        ],
        "review",
    );
}

/// What reaches only other processes stays open.
#[test]
fn kills_of_other_processes_stay_allowed() {
    all(
        &[
            "fuser -k 3000/tcp",
            "fuser -v 8787/tcp",
            "lsof -ti:3000 | xargs kill",
            "lsof -i:8787",
            "pgrep vite | xargs kill",
            "pgrep -f cargo | xargs kill",
            "ps aux | grep node | awk '{print $2}' | xargs kill",
            "pkill -f x",
            "pkill -f cargo",
            "pkill -f 'cargo test'",
            "systemctl kill nginx",
            "seq 3 | xargs echo",
        ],
        "allow",
    );
}

/// The findings say what the line does: a kill by the guard's port, or a
/// kill of ids the line does not say, not a pattern or a pgrep it does not
/// hold.
///
/// FAILS ON REVERT: take `kill_by_port` or `kill_of_unread_ids` out of
/// `security_tamper_as_written` and the words are another finding's.
#[test]
fn the_findings_say_what_the_line_does() {
    let said = |line: &str| -> String {
        analyze_command(line, None)
            .signals
            .iter()
            .map(|signal| signal.detail.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    };
    for line in [
        "fuser -k 8787/tcp",
        "lsof -ti:8787 | xargs kill",
        "kill $(lsof -t -i:8787)",
    ] {
        let words = said(line);
        assert!(words.contains("dashboard's port"), "{line}: {words}");
        assert!(!words.contains("pgrep or pidof"), "{line}: {words}");
    }
    for line in ["xargs kill < pids.txt", "cat pids | xargs kill -9"] {
        let words = said(line);
        assert!(
            words.contains("ids the line does not say"),
            "{line}: {words}"
        );
        assert!(!words.contains("a pattern that matches"), "{line}: {words}");
    }
}
