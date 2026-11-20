//! A search from above the guard's places, judged with a home of its own.
//!
//! Moved out of `guard_files_by_path_and_ssh_config.rs` as it stood, with
//! the same lines and the same verdicts: the home is read from the
//! environment, so it is set once, in a test binary of its own, before the
//! first judgment (as in `find_reads_the_guards_folders.rs`). With the
//! account's home inside `/tmp` the line `find /tmp -name '*.toml' -delete`
//! searched from above that home and was refused (measured 2026-11-19 with a
//! home from `mktemp -d`); the test was asking about the host, not the rule.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

/// A search from ABOVE a place of the guard that removes what it matches, and
/// whose filter may match the place, a folder on the way to it or a file the
/// guard keeps there, removes it. Measured on main on 2026-11-19: every line
/// here was allowed. The lines whose verdict hangs on what the guard's
/// folders hold on this host are in `find_reads_the_guards_folders.rs`.
#[test]
fn find_from_above_the_guards_places_is_their_removal_when_its_filter_may_match() {
    // A home outside every root searched here: with the account's home in
    // `/tmp` (a disposable one), `find /tmp` was a search from above it.
    // The target folder holds none of those roots on any runner.
    let home = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("a home");
    std::fs::create_dir_all(home.path().join("proj")).expect("a project");
    for root in ["/tmp", "/etc", "/var"] {
        assert!(!home.path().starts_with(root), "{root}");
    }
    std::env::set_var("HOME", home.path());

    for line in [
        "find ~ -path '*innerwarden*' -delete",
        "find $HOME -iname '*INNERWARDEN*' -delete",
        "find /etc -name agent.toml -delete",
        "find / -name '*.toml' -delete",
        "find ~/.config -name '*.json' -exec rm {} \\;",
        "find /var -name '*.db' -delete",
        "find ~ -name .config -exec rm -rf {} +",
        "find ~ -regex '.*inner.*' -delete",
        "find ~ ! -name '*.rs' -delete",
        "find ~ -name 'settings*.json' -delete",
        "cd ~ && find . -path '*innerwarden*' -delete",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    // A filter that cannot match any of them, a root that holds none of
    // them, or a search that only reads, is what it was.
    // What a root above the guard's folders may match depends on what those
    // folders hold on this host: the cases from `~` are in
    // `find_reads_the_guards_folders.rs`, with a home of their own.
    for line in [
        "find ~/proj -name '*.json' -delete",
        "find . -name '*.json' -delete",
        "find /tmp -name '*.toml' -delete",
        "find ~ -name '*.toml' -exec cat {} \\;",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
