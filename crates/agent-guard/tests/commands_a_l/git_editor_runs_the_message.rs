//! A git whose editor is a shell or an interpreter runs the message it is
//! handed: the text of `-m` and the body of a here-document read with
//! `-F -`. An alias that starts with `!` runs its value through a shell
//! with the words after it. Measured on main before this reading: every
//! refused line below was allowed. An ordinary editor runs nothing of the
//! message, and a message that only talks about a command stays allowed.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation.to_string()
}

/// FAILS ON REVERT of `git_editor::message_lines` in `handed_shell_lines`.
#[test]
fn a_message_a_shell_editor_runs_is_judged_as_the_line_it_is() {
    for line in [
        "git -c core.editor=sh commit -e -am \"rm -rf ~\"",
        "git -c core.editor='bash -x' commit --edit -m 'rm -rf ~'",
        "GIT_EDITOR=sh git commit -e -m 'rm -rf ~'",
        "VISUAL=bash git commit -e -m 'rm -rf ~'",
        "env EDITOR=/bin/zsh git commit -e -m 'rm -rf ~'",
        "export GIT_EDITOR=sh; git commit -e -m 'rm -rf ~'",
        "git -c core.editor=sh tag -a v1 -e -m 'rm -rf ~'",
        "git -c core.editor=sh commit -e -F - <<'EOF'\nrm -rf ~\nEOF",
        "GIT_EDITOR=perl git commit -e -m 'system(\"rm -rf ~\")'",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// FAILS ON REVERT of `git_editor::alias_lines`.
#[test]
fn an_alias_that_runs_a_shell_hands_it_the_words_after_it() {
    for line in [
        "git -c alias.x='!sh -c' x 'rm -rf ~'",
        "git -c alias.x='!bash' x -c 'rm -rf ~'",
        "git -c alias.x='!sh -c \"$1\"' x 'rm -rf ~'",
        "git -c alias.ci='!git -c core.editor=sh commit -e' ci -m 'rm -rf ~'",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

#[test]
fn an_ordinary_editor_or_a_harmless_message_stays_allowed() {
    for line in [
        "git -c core.editor=vim commit -e -m 'rm -rf ~ was a bad idea'",
        "GIT_EDITOR=true git commit -m 'rm -rf ~ is now refused'",
        "EDITOR=nano git commit -e -m 'rm -rf ~ docs'",
        "GIT_EDITOR='code --wait' git commit -e -m 'rm -rf ~ docs'",
        "git commit -F - <<'EOF'\nrm -rf ~ is refused now\nEOF",
        "git -c core.editor=sh commit -e -m 'fix typo'",
        "GIT_EDITOR=vim git rebase -i HEAD~3",
        "git -c alias.st=status st",
        "git -c alias.l='!git log --oneline' l -5",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
