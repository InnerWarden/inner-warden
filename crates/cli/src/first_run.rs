//! What a bare `innerwarden` says on a machine that has never been set up.
//!
//! Nothing in the distribution tells a fresh user they are not protected yet:
//! the npm wrapper has no postinstall by design and the `.deb`/`.rpm` packages
//! carry no scripts block. The first thing most people type after installing is
//! the bare command, and that answered with 60 lines of usage in which `setup`
//! was one of 24 subcommands. Someone who installs a guardrail and reads a wall
//! of syntax has no way to learn the only fact that matters at that moment:
//! nothing is screening anything yet.
//!
//! The panel replaces the usage text ONLY for that reader. An install that has
//! state, and every explicit `--help`, keep the full text.

use std::path::Path;

/// Whether this install has ever written its own configuration directory
/// (`~/.config/innerwarden`, or the parent of `IW_GRAPH_FILE` when set).
///
/// Every path that does something - `setup`, `install`, `agents connect`, a
/// screened command reaching the record - lands there, so its absence is the
/// closest honest reading of "this install has never done anything".
///
/// `None` means we could not tell, which callers must treat as "do not claim
/// nothing is wired" rather than as a fresh box.
pub(crate) fn config_dir_present() -> Option<bool> {
    let dir = crate::graph_io::sink_dir()?;
    Some(dir_exists(&dir))
}

fn dir_exists(dir: &Path) -> bool {
    std::fs::metadata(dir).map(|m| m.is_dir()).unwrap_or(false)
}

/// Should a bare `innerwarden` answer with the panel instead of full usage?
///
/// Both facts are passed in so the rule is testable without a filesystem: an
/// unreadable home yields `None` and keeps today's behaviour, because reporting
/// "nothing is wired" when you only established "could not look" sends the
/// reader to fix a fault that may not exist.
pub(crate) fn shows_panel(config_dir_present: Option<bool>) -> bool {
    config_dir_present == Some(false)
}

/// The five-line answer to "I just installed this, now what?".
///
/// Deliberately short. It names what the tool is, states plainly that nothing is
/// being screened yet, gives the one command that fixes that, the one command
/// that confirms it afterwards, and where the full reference lives.
pub(crate) fn panel(prog: &str, version: &str) -> String {
    format!(
        "{prog} {version} - {edition}: screens what your AI agent runs, before it runs.\n\
         Nothing is wired yet, so no agent on this machine is being screened.\n\
         \n  \
           {prog} setup     pick what to guard (arrow keys)\n  \
           {prog} status    afterwards: is it on, and is it screening anything?\n  \
           {prog} --help    every command\n",
        edition = crate::COMMUNITY_EDITION_NAME,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An install that has state is not a fresh one, and an install we could not
    /// read is not a fresh one either.
    #[test]
    fn only_a_provably_absent_config_dir_gets_the_panel() {
        assert!(shows_panel(Some(false)));
        assert!(!shows_panel(Some(true)));
        assert!(
            !shows_panel(None),
            "an unreadable home must keep today's behaviour: `could not tell` is \
             not evidence that nothing is wired"
        );
    }

    #[test]
    fn an_existing_directory_is_present_and_a_missing_one_is_not() {
        let home = tempfile::TempDir::new().unwrap();
        let dir = home.path().join(".config/innerwarden");
        assert!(!dir_exists(&dir));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(dir_exists(&dir));
        // A FILE at that path is not a configuration directory.
        let file = home.path().join("plain-file");
        std::fs::write(&file, "x").unwrap();
        assert!(!dir_exists(&file));
    }

    /// The panel exists to answer one question, so it must actually answer it:
    /// say nothing is protected, and give the command that changes that.
    #[test]
    fn the_panel_says_nothing_is_wired_and_names_the_next_command() {
        let text = panel("innerwarden", "9.9.9");

        assert!(
            text.contains("Nothing is wired yet"),
            "the whole point is telling the reader they are not protected: {text}"
        );
        assert!(
            text.contains("innerwarden setup"),
            "it must give the command that fixes that: {text}"
        );
        assert!(
            text.contains("innerwarden status"),
            "and the command that confirms it afterwards: {text}"
        );
        assert!(
            text.contains("innerwarden --help"),
            "full help must stay discoverable: {text}"
        );
    }

    /// A panel that grows back into a reference page is the defect again.
    #[test]
    fn the_panel_stays_short_and_carries_no_usage_block() {
        let text = panel("innerwarden", "9.9.9");

        assert!(
            text.lines().count() <= 6,
            "the panel must stay glanceable, got {} lines:\n{text}",
            text.lines().count()
        );
        assert!(
            !text.contains("USAGE:"),
            "the usage block is what the panel replaces: {text}"
        );
    }

    /// Every line is written from the name the user actually typed, so the
    /// `iw-guard` / dev-build aliases do not tell people to run a command that
    /// is not on their PATH.
    #[test]
    fn the_panel_uses_the_name_it_was_invoked_as() {
        let text = panel("iw-guard", "9.9.9");

        assert!(text.contains("iw-guard setup"), "{text}");
        assert!(
            !text.contains("innerwarden setup"),
            "a hardcoded name sends the reader to a command they may not have: {text}"
        );
    }
}
