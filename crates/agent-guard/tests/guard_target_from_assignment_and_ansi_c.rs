//! A lowering verb is judged on the target the line itself gives it: a value
//! set earlier on the same line (`X=v`, `export`, `declare`, `local`,
//! `readonly`, `read X <<< v`, `X=$(printf v)`) stands for the value, a
//! target no reading shows is held for review, and a `$'...'` word is read as
//! the shell decodes it. A repository slug that names the guard is an
//! argument, never the guard.
//!
//! Measured on main before the change (2026-11-19, `analyze_command` with
//! the embedded rules): `S=innerwarden-agent; systemctl stop $S` and eight
//! other spellings were allowed (the line written out is refused), `systemctl
//! stop $SVC` was allowed, `bash -c $'rm\x20-rf ~'` was a review that does
//! not stop an agent (`rm -rf ~` is refused), and a `gh api` line with a
//! repository slug and a job id in variables was refused as a kernel change.

use innerwarden_agent_guard::mcp::{analyze_command, CommandAnalysis};
use innerwarden_agent_guard::rules::RuleEngine;

fn judged(line: &str) -> CommandAnalysis {
    let engine = RuleEngine::load_embedded();
    analyze_command(line, Some(&engine))
}

fn verdict(line: &str) -> String {
    judged(line).recommendation
}

/// FAILS ON REVERT: take the assignment readings out of
/// `check_security_tamper` (or the projected readings out of the analysis)
/// and every line here is allowed.
#[test]
fn a_service_or_process_named_by_a_value_on_the_line_is_the_one_stopped() {
    for line in [
        "S=innerwarden-agent; systemctl stop $S",
        "S=innerwarden-agent; systemctl stop \"$S\"",
        "export S=innerwarden-agent; systemctl disable --now $S",
        "declare S=innerwarden-agent; systemctl mask ${S}",
        "readonly S=innerwarden-agent\nsystemctl stop $S",
        "local S=innerwarden-agent; systemctl stop $S",
        "read S <<< innerwarden-agent; systemctl stop $S",
        "S=$(printf innerwarden-agent); systemctl stop $S",
        "P=innerwarden; pkill $P",
        "P=innerwarden-agent; kill $(pgrep $P)",
        "S=$'innerwarden\\x2dagent'; systemctl stop $S",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    // As before: the guard named outright, and the other lowerings by value.
    for line in [
        "systemctl stop innerwarden-agent",
        "B=/usr/local/bin/innerwarden; rm -f $B",
        "U=innerwarden; $U uninstall",
        "X=innerwarden; $X monitor",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// FAILS ON REVERT: take `lowering_verb_target_unread` out and these are
/// allowed.
#[test]
fn a_lowering_verb_whose_target_no_reading_shows_is_held() {
    for line in [
        "systemctl stop $SVC",
        "S=$(cat svc.txt); systemctl stop $S",
        "pkill \"$NAME\"",
        "launchctl bootout $LABEL",
    ] {
        assert_eq!(verdict(line), "review", "{line}");
    }
    for line in [
        "S=nginx; systemctl stop $S",
        "S=nginx; systemctl restart $S",
        "S=innerwarden-agent; systemctl status $S",
        "S=innerwarden-agent; systemctl is-active $S",
        "S=innerwarden-agent; journalctl -u $S -n 50",
        "S=innerwarden-agent; echo \"systemctl stop $S\"",
        "M=x; git commit -m \"systemctl stop innerwarden-agent\"",
        "systemctl restart $SVC",
        "kill $PID",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// FAILS ON REVERT: take `ansi_c_decoded` out of `analyze_command_at` and
/// the removals are reviews that do not stop an agent.
#[test]
fn an_ansi_c_quoted_word_is_judged_as_the_shell_decodes_it() {
    for line in [
        "bash -c $'rm\\x20-rf ~'",
        "bash -c $'rm -rf \\176'",
        "bash -c $'rm\\u0020-rf ~'",
        "bash -c $'systemctl stop innerwarden\\x2dagent'",
        "systemctl stop $'innerwarden\\x2dagent'",
        "bash -c $'cat ~/.ssh/id\\x5frsa'",
        "$'\\x72\\x6d' -rf ~",
        "eval $'rm\\x20-rf\\x20~'",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "echo $'a\\tb'",
        "printf $'%s\\n' x",
        "bash -c $'echo hi\\nls'",
        "git commit -m $'line one\\nline two'",
        "printf $'\\e[1mbold\\e[0m\\n'",
        "bash -c $'echo \\'rm -rf ~\\''",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
    // What does not decode stays a line the guard cannot read: no escape
    // digit, a NUL, a byte above 0x7f.
    for line in [
        "bash -c $'rm\\x'",
        "bash -c $'rm\\c@ -rf ~'",
        "bash -c $'rm\\0 -rf ~'",
        "bash -c $'rm\\xff -rf ~'",
        "bash -c $'rm\\377 -rf ~'",
        "bash -c $'rm\\u00e9 -rf ~'",
    ] {
        assert_eq!(verdict(line), "review", "{line}");
    }
}

/// FAILS ON REVERT: let a folder named after the guard count as its name at
/// the last level read (`names_a_guard_program` in `Look::too_deep`) and the
/// job-log line is refused as a kernel change. The lines are the ones the
/// operator's guard refused on 2026-11-19; 1.6.11 refused all five, 1.6.14
/// and main still refused the job-log one.
#[test]
fn a_repository_slug_in_a_path_is_an_argument() {
    for line in [
        "R=InnerWarden/inner-warden; j=$(gh api repos/$R/actions/runs/44556930119/jobs --jq '.jobs[]|select(.name==\"publish\")|.id'); gh api repos/$R/actions/jobs/$j/logs --allow-escape-sequences 2>/dev/null | sed 's/\\x1b\\[[0-9;]*m//g' | grep -i -E 'skip|already|publish|version|dry' | tail -20 | cut -c30-220",
        "R=InnerWarden/inner-warden; j=$(gh api repos/$R/x); gh api repos/$R/y/$j",
        "gh api a/innerwarden/$j --jq x",
        "ls a/innerwarden/$j",
        "R=InnerWarden/innerwarden-skill; gh pr list --repo $R --json number,title; P=$(gh pr list --repo $R --head release/community-1.6.14 --json number --jq '.[0].number'); gh pr diff $P --repo $R --name-only",
        "R=InnerWarden/inner-warden; gh pr view 1 --repo $R",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
    // The guard's name where an expansion may finish it, or as a program in a
    // folder, still counts.
    for line in [
        "gh api x innerwarden$j",
        "/opt/innerwarden/$X agent kernel claude-code off",
        "\"$HOME/.local/bin/innerwarden\" dry-run",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}
