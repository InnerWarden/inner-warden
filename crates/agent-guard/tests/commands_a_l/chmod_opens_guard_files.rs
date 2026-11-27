//! A mode that lets the group or everyone else write the guard's files or an
//! agent's settings hands them to whoever else runs on the machine: it is a
//! write to them as much as one made now.
//!
//! Measured on main on 2026-11-21: `chmod 777 ~/.config/innerwarden` and
//! `chmod 777 .mcp.json` were only held for review (world-writable), because a mode that keeps the
//! owner's read and write did not count as a write. Taking the owner's read
//! away was already refused, and stays so.
//!
//! FAILS ON REVERT of `mode_opens_to_others` in the `chmod` reading of
//! `writes_place`: every line of the first list is held at most for review.

use innerwarden_agent_guard::mcp::analyze_command;
use innerwarden_agent_guard::rules::RuleEngine;

fn verdict(engine: &RuleEngine, line: &str) -> String {
    analyze_command(line, Some(engine)).recommendation
}

#[test]
fn a_mode_that_opens_the_guards_files_to_others_is_refused() {
    let engine = RuleEngine::load_embedded();
    for line in [
        "chmod 777 ~/.config/innerwarden",
        "chmod 777 .mcp.json",
        "chmod -R 777 ~/.config/innerwarden",
        "chmod --recursive a+w ~/.config/innerwarden",
        "chmod go+w ~/.claude/settings.json",
        "chmod a+w ~/.config/innerwarden/config.toml",
        "chmod o=rwx ~/.claude",
        "chmod 666 ~/.codex/config.toml",
        "chmod 0777 .claude/settings.json",
        "chmod g+w,o+w .mcp.json",
        "chmod u+rw,o=u ~/.claude/settings.json",
        "install -m 777 -d ~/.config/innerwarden",
        "install -m 666 /tmp/x ~/.claude/settings.json",
        "install -m 0666 cfg.toml ~/.config/innerwarden/config.toml",
        // Taking the owner's read away, as before.
        "chmod u-r ~/.claude/settings.json",
        "chmod 000 ~/.config/innerwarden",
    ] {
        assert_eq!(verdict(&engine, line), "deny", "{line}");
    }
}

/// Closing them to others, or a mode the owner keeps, stays free; so does
/// any mode on the project's own files (`chmod 777` of a project folder
/// keeps the review it had for being world-writable, nothing more).
#[test]
fn a_mode_that_keeps_them_to_the_owner_or_touches_the_project_is_not_refused() {
    let engine = RuleEngine::load_embedded();
    for line in [
        "chmod 755 ~/.claude",
        "chmod 700 ~/.config/innerwarden",
        "chmod 600 ~/.claude/settings.json",
        "chmod 644 .mcp.json",
        "chmod +w .mcp.json",
        "chmod go-w ~/.claude",
        "chmod a+w notes.txt",
        "chmod 666 config.json",
        "chmod go+w src/app.toml",
        "chmod 775 scripts/run.sh",
        "install -m 0755 /tmp/x ~/.local/bin/",
    ] {
        assert_eq!(verdict(&engine, line), "allow", "{line}");
    }
    for line in ["chmod 777 build/out", "chmod -R 777 dist"] {
        assert_eq!(verdict(&engine, line), "review", "{line}");
    }
}
