//! A folder of the guard that is itself a link (`~/.config/innerwarden`
//! linked to a dotfiles checkout) holds the guard's files all the same.
//! Measured on main (0c27d10) on 2026-11-19: the link was not followed,
//! the folder read as empty, and `find ~ -name custom.toml -delete` was allowed
//! with `custom.toml` in it.
//!
//! A test binary of its own: the home is read from the environment.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

/// FAILS ON REVERT of the link of the place followed in
/// `guard_folder_entries`.
#[cfg(unix)]
#[test]
fn a_folder_of_the_guard_that_is_a_link_is_read_where_it_leads() {
    let home = tempfile::tempdir().expect("a home");
    let dotfiles = home.path().join("dotfiles/innerwarden");
    std::fs::create_dir_all(dotfiles.join("rules")).expect("the real folder");
    for file in ["custom.toml", "notes.lock", "rules/local.yml"] {
        std::fs::write(dotfiles.join(file), "x").expect("a file of the guard");
    }
    // A link inside the folder is listed as a link, not followed.
    let elsewhere = home.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).expect("another folder");
    std::fs::write(elsewhere.join("far.txt"), "x").expect("a file elsewhere");
    std::os::unix::fs::symlink(&elsewhere, dotfiles.join("linked")).expect("a link inside");
    std::fs::create_dir_all(home.path().join(".config")).expect("config");
    std::os::unix::fs::symlink(&dotfiles, home.path().join(".config/innerwarden"))
        .expect("the guard's folder as a link");
    std::env::set_var("HOME", home.path());

    for line in [
        "find ~ -name custom.toml -delete",
        "find ~ -name '*.lock' -delete",
        "find ~/.config -name local.yml -delete",
        "find ~ -name linked -delete",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "find ~ -name '*.pyc' -delete",
        "find ~ -name far.txt -delete",
        "find ~ -name custom.toml -exec cat {} \\;",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
