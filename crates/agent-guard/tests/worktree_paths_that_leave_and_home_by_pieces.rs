//! A worktree path that goes back out of a folder it named, and a `HOME`
//! the line sets under a name written in pieces, are not the work folder a
//! `git worktree remove` of a checkout names.
//!
//! Measured 2026-11-25: main 542cc8c denied every line of the two refusal
//! tests below; the branch before this change held the `..` lines for
//! review and allowed or held the `HOME` lines, because `.worktrees` was
//! taken as a folder of checkouts with a `..` after it, and `HOME` was
//! looked for before the shell joins `HO""ME` into one name.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

/// FAILS ON REVERT of `leaves_a_folder` in `work_folder_path`
/// (mention.rs): each line is held for review again.
#[test]
fn a_dotdot_after_a_folder_of_the_path_leaves_the_work_folder() {
    for line in [
        "cd ~/.config && git worktree remove --force .worktrees/../innerwarden",
        "cd /etc && git worktree remove --force .worktrees/../innerwarden",
        "cd /usr/local/bin && git worktree remove --force .worktrees/../innerwarden",
        "cd ~/.config && git worktree remove --force wt/../innerwarden",
        "git worktree remove --force ~/innerwarden/../.config/innerwarden",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// FAILS ON REVERT of the quote and escape removal in `home_kept`
/// (mention.rs): each line is allowed or held for review again.
#[test]
fn a_home_set_under_a_name_in_pieces_is_not_the_home() {
    for line in [
        "export HO\"\"ME=/etc && git worktree remove --force $HOME/innerwarden/x",
        "export HO\\ME=/etc && git worktree remove --force $HOME/innerwarden/x",
        "export H\"O\"ME=/etc && git worktree remove --force $HOME/innerwarden/x",
        "printf -v HO\"\"ME /etc && git worktree remove --force $HOME/innerwarden/x",
        "read -r HO\"\"ME <<< /etc && git worktree remove --force $HOME/innerwarden/x",
        "HO''ME=/etc; git worktree remove --force $HOME/innerwarden/x",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// A worktree beside the project, under `.worktrees` or through a `$HOME`
/// the line leaves alone stays a work folder: held for review, as before.
#[test]
fn worktrees_that_stay_in_the_work_folder_are_held_for_review() {
    for line in [
        "git worktree remove --force ../innerwarden-wt",
        "git worktree remove --force ~/github/_innerwarden/.worktrees/t1",
        "git worktree remove --force $HOME/innerwarden/wt-review",
        "git worktree remove --force \"$HOME/innerwarden/wt-review\"",
        "echo \"$HOME\" && git worktree remove --force $HOME/innerwarden/wt-review",
    ] {
        assert_eq!(verdict(line), "review", "{line}");
    }
}
