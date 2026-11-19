//! A search from above a folder of the guard is held to what the folder
//! holds when it is judged: inside a place of the guard every file is the
//! guard's, whatever its name.
//!
//! Measured on the branch before this on 2026-11-19: `find ~ -name
//! custom.toml -delete` was allowed with `~/.config/innerwarden/custom.toml`
//! there, as the filter was held only to a list of known names.
//!
//! A test binary of its own: the home is read from the environment, so it
//! is set once, before the first judgment.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

#[test]
fn a_search_from_above_is_held_to_what_the_guards_folders_hold() {
    let home = tempfile::tempdir().expect("a home");
    let config = home.path().join(".config/innerwarden");
    std::fs::create_dir_all(config.join("rules")).expect("the guard's folder");
    for file in ["custom.toml", "agent.env", "notes.lock", "rules/local.yml"] {
        std::fs::write(config.join(file), "x").expect("a file of the guard");
    }
    std::fs::create_dir_all(home.path().join("proj")).expect("a project");
    std::env::set_var("HOME", home.path());

    // Every file in the folder is the guard's, listed or known.
    for line in [
        "find ~ -name custom.toml -delete",
        "find ~ -name '*.env' -delete",
        "find ~ -name local.yml -delete",
        "find ~ -path '*/rules/*' -delete",
        "find ~ -name '*.lock' -exec rm {} \\;",
        "find $HOME/.config -name 'c*' -delete",
        // A folder that is not there yet is held to the names the guard
        // keeps in it; /etc/innerwarden holds agent.toml here or there.
        "find /etc -name agent.toml -delete",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    // A filter that matches nothing the folders hold is what it was.
    for line in [
        "find ~ -name '*.pyc' -delete",
        "find ~ -name '*.log' -delete",
        "find ~ -name 'z*.toml' -delete",
        "find ~ -name '*.pyc' -o -name '*.pyo' -delete",
        "find ~/proj -name custom.toml -delete",
        "find ~ -name custom.toml -exec cat {} \\;",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }

    // The folder is there and holds none of these: nothing of the guard's
    // is removed.
    for line in [
        "find ~ -name config.json -delete",
        "find ~ -name 'llm-*' -delete",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }

    // A folder of the guard that cannot be listed may hold a match.
    let unread = home.path().join(".openclaw/extensions/innerwarden-guard");
    std::fs::create_dir_all(unread.join("inside")).expect("a plugin folder");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&unread, std::fs::Permissions::from_mode(0o000)).expect("closed");
        // Root reads a closed folder anyway: nothing to show there.
        if std::fs::read_dir(&unread).is_err() {
            assert_eq!(
                verdict("find ~ -name '*.pyc' -delete"),
                "deny",
                "a folder of the guard that cannot be listed"
            );
        }
        std::fs::set_permissions(&unread, std::fs::Permissions::from_mode(0o755)).expect("opened");
    }

    // A folder of the guard not made yet is held to the names the guard
    // keeps in it.
    std::fs::remove_dir_all(&config).expect("the folder gone");
    for line in [
        "find ~ -name config.json -delete",
        "find ~ -name 'llm-*' -delete",
        "find ~ -name '[a-c]*.toml' -delete",
        "find ~ -name '*.pyc' -o -name 'suppress.*' -delete",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    assert_eq!(verdict("find ~ -name '*.pyc' -delete"), "allow");
}
