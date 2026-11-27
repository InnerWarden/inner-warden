//! A worktree path is read where it points before the guard decides
//! whether it only names a work folder, and `HOME` named by a brace
//! expansion or a line continuation is a home the line sets.
//!
//! Measured before this change (main, 2026-11-25, `analyze_command` and
//! `analyze_command_in`): every line of
//! `a_worktree_above_a_known_folder_is_read_where_it_points` and of
//! `a_relative_worktree_from_an_unknown_folder_is_in_doubt` was held for
//! review as a mention, every line of
//! `a_worktree_through_a_dot_dot_that_stays_in_a_work_folder_is_a_mention`
//! was refused, and every line of
//! `a_home_named_by_braces_or_a_continuation_is_the_home_the_line_sets` was
//! allowed.

use innerwarden_agent_guard::mcp::{analyze_command, analyze_command_in, WorkingContext};

const PROJECT: &str = "/home/dev/src/app";
const HOME: &str = "/home/dev";

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation.to_string()
}

fn verdict_in(line: &str, cwd: &str) -> String {
    let context = WorkingContext::discover(cwd, Some(HOME)).expect("absolute folder");
    analyze_command_in(line, None, Some(&context))
        .recommendation
        .to_string()
}

/// FAILS ON REVERT of `worktree_readings` in `mention.rs`: a `..` at the
/// start of a relative path follows the folder the line runs in, and a
/// `cd` on the line.
#[test]
fn a_worktree_above_a_known_folder_is_read_where_it_points() {
    for line in [
        "cd ~/.config && git worktree remove --force ../../../etc/innerwarden",
        "cd ~/.config && git worktree remove --force ../../../usr/local/bin/innerwarden",
        "git worktree remove --force ../../../../etc/innerwarden",
        "cd /tmp && git worktree remove ../etc/innerwarden",
        "cd ~/src && git worktree remove ../../etc/innerwarden",
        "cd ~/src && git worktree remove ../../../etc/innerwarden",
        "git worktree remove ../../../../../../../../etc/innerwarden",
        "cd ~/.config/x && git worktree remove ../innerwarden",
        "rm -rf ../../../../etc/innerwarden/rules",
        "cd ~/.config && git worktree remove ../../../etc/innerwarden/x",
        "git worktree remove ../../../../etc/innerwarden; cd /tmp/a/b/c/d/e/f",
        "pushd ~/src/a/b/c/d && git worktree remove ../../../../../../etc/innerwarden",
    ] {
        assert_eq!(verdict_in(line, PROJECT), "deny", "{line}");
    }
}

/// FAILS ON REVERT of `worktree_readings`: a folder the line names is
/// known even where the folder it runs in is not, and what a path climbs
/// to from it is read.
#[test]
fn a_known_cd_is_followed_where_the_folder_the_line_runs_in_is_not() {
    for line in [
        "cd ~/.config && git worktree remove --force ../../../etc/innerwarden",
        "cd ~/.config && git worktree remove --force ../../../usr/local/bin/innerwarden",
        "cd ~/.config/x && git worktree remove ../innerwarden",
        "cd ~/.config && rm -rf ../../../etc/innerwarden/rules",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    // A relative path without `..` is read from a folder the line names
    // as well.
    for line in [
        "cd ~/.config && git worktree remove innerwarden/x",
        "cd ~/.config && rm -rf innerwarden/rules",
        "cd /etc && git worktree remove --force innerwarden/x",
        "cd /etc && rm -rf innerwarden/rules",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    assert_eq!(
        verdict_in("git worktree remove innerwarden/x", "/home/dev/.config"),
        "deny"
    );
    // A relative `cd` is not followed, the folder the line runs in is.
    assert_eq!(
        verdict_in(
            "cd app && git worktree remove ../../../../etc/innerwarden",
            PROJECT
        ),
        "deny"
    );
}

/// Where no folder the line may run in is known, a path that climbs from
/// it is in doubt: held for review as a mention, as before (main's verdict).
#[test]
fn a_relative_worktree_from_an_unknown_folder_is_in_doubt() {
    for line in [
        "git worktree remove ../innerwarden-wt",
        "git worktree remove --force ../../innerwarden-wt",
    ] {
        assert_eq!(verdict(line), "review", "{line}");
    }
    for line in [
        "cd app && git worktree remove ../innerwarden-wt",
        "pushd ~/src && git worktree remove ../innerwarden-wt; popd",
    ] {
        assert_eq!(verdict_in(line, PROJECT), "review", "{line}");
    }
}

/// FAILS ON REVERT of `resolved_path`: `/tmp/x/../wt` is `/tmp/wt` and
/// `~/src/../wt` is `~/wt`, a work folder; a relative `..` from a known
/// work folder stays one.
#[test]
fn a_worktree_through_a_dot_dot_that_stays_in_a_work_folder_is_a_mention() {
    for line in [
        "git worktree remove /tmp/x/../innerwarden-wt",
        "git worktree remove ~/src/../innerwarden-wt",
        "git worktree remove --force ~/.worktrees/../innerwarden-wt",
        "git -C ~/src/app worktree remove ../innerwarden-wt",
    ] {
        assert_eq!(verdict(line), "review", "{line}");
        assert_eq!(verdict_in(line, PROJECT), "review", "{line}");
    }
    for line in [
        "git worktree remove ../innerwarden-wt",
        "git worktree remove --force ../innerwarden-feature",
        "git worktree remove ../../innerwarden-wt",
        "cd ~/src/app && git worktree remove ../innerwarden-wt",
        "cd /tmp/x && git worktree remove ../innerwarden-wt",
        // A checkout beside the project named after the guard: git reads
        // the path, not the end of its name, when the word has `..`.
        "git worktree remove ../innerwarden",
        "git worktree remove ~/src/../innerwarden",
        "git worktree remove wt/innerwarden-x",
        "cd ~/src && git worktree remove app/innerwarden-wt",
    ] {
        assert_eq!(verdict_in(line, PROJECT), "review", "{line}");
    }
    // A removal no reading refuses stays allowed.
    assert_eq!(
        verdict_in("cd ~/src && rm -rf innerwarden-old/target", PROJECT),
        "allow"
    );
    // A project outside the home and /tmp: a worktree beside it in the
    // same top folder is one too; one that climbs out of it is not.
    assert_eq!(
        verdict_in("git worktree remove ../innerwarden-wt", "/opt/app"),
        "review"
    );
    assert_eq!(
        verdict_in("git worktree remove ../../etc/innerwarden", "/opt/app"),
        "deny"
    );
    assert_eq!(
        verdict_in("git worktree remove ../innerwarden-wt", "/etc/app"),
        "deny"
    );
}

/// What a `..` reaches is still refused: a hidden folder, a place of the
/// guard's, above the home, or the guard's own name at the end.
#[test]
fn a_worktree_through_a_dot_dot_to_the_guards_places_is_refused() {
    for line in [
        "git worktree remove ~/src/../.config/innerwarden",
        "git worktree remove /tmp/../etc/innerwarden",
        "git worktree remove ~/../../etc/innerwarden",
        "git worktree remove /tmp/x/../../etc/innerwarden",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
        assert_eq!(verdict_in(line, PROJECT), "deny", "{line}");
    }
}

/// FAILS ON REVERT of `names_spelled_out` and its uses (`with_home_named`,
/// `home_kept`, the values the line sets): the shell makes the braces and
/// joins the lines before it reads a name.
#[test]
fn a_home_named_by_braces_or_a_continuation_is_the_home_the_line_sets() {
    for line in [
        "export {HO,}ME=/etc; rm -rf $HOME/innerwarden",
        "export HO{,}ME=/etc; rm -rf $HOME/innerwarden",
        "export H{O,O}ME=/etc; rm -rf $HOME/innerwarden",
        "declare -x {HO,X}ME=/etc; rm -rf $HOME/innerwarden",
        "read -r {HO,}ME <<< /etc; rm -rf $HOME/innerwarden",
        "printf -v {HO,}ME /etc; rm -rf $HOME/innerwarden",
        "export HO\\\nME=/etc; rm -rf $HOME/innerwarden",
        "export H\\\nO\\\nME=/etc; rm -rf $HOME/innerwarden",
        "export {G..H}OME=/etc; rm -rf $HOME/innerwarden",
        "export {H{O,},}ME=/etc; rm -rf $HOME/innerwarden",
        "export {\"HO\",}ME=/etc; rm -rf $HOME/innerwarden",
        "export {HO,}ME=/etc\nrm -rf $HOME/innerwarden",
        "export {HO,}ME=/etc; git worktree remove $HOME/innerwarden",
        "export {HO,}ME=/etc; git worktree remove --force $HOME/innerwarden-wt",
        "export HO{,}ME=/etc && cd $HOME/innerwarden && git worktree remove wt",
        "export {HO,}ME=/usr/local/bin; rm -f $HOME/innerwarden",
        "export {PW,}D=/etc; rm -rf $PWD/innerwarden",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// Braces that name no value of the home are read as before.
#[test]
fn braces_that_set_nothing_the_line_reads_are_read_as_before() {
    for line in [
        "rm -rf $HOME/innerwarden-wt/{target,dist}",
        "rm -rf $HOME/.cache/{pip,npm}",
        "for f in {a,b}; do echo $f; done",
        "OUT=dist; mkdir -p $OUT/{js,css} && cp -r src/* $OUT/js",
        "export PATH=$HOME/.cargo/bin:$PATH; cargo build",
        "cd ~/src/app && cargo test \\\n  --workspace",
        "export {HO,}ME=/tmp/h; mkdir -p $HOME/x",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
    // A path set by braces is read as the same path set plainly.
    assert_eq!(
        verdict("export {PA,}TH=/tmp/x:$PATH; ls"),
        verdict("export PATH=/tmp/x:$PATH; ls")
    );
}
