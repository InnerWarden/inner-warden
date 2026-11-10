//! The lines the guard's reading cannot vouch for.
//!
//! [`super::check_guard_self_disable`] reads a line the way the shell does
//! and refuses the ones that lower the guard. A shell has more ways to build
//! a command than a reading can follow: a function, an alias, a trap,
//! `eval`, a substitution, a word that is only known when the line runs.
//! This module is the other half. A line that holds a guard CLI name or a
//! guard-lowering verb as a word of its own, and a construct whose outcome
//! is not on the line, is refused without being followed.
//!
//! The price is a refusal of some lines that lower nothing (a commit message
//! in `$'...'` that quotes `innerwarden allow`, a comment glued to a `)`
//! beside a guard word). The person runs those from their own shell.
//!
//! One pass over the line and over each piece of nested code, paid from a
//! budget: the cost is linear in the line's length.

mod lexer;
mod rules;
mod tokens;

/// Whether `content` holds a guard name or verb beside a construct that is
/// not read.
pub(super) fn unread_beside_guard_word(content: &str) -> bool {
    rules::judge(content.as_bytes(), true).is_some()
}

#[cfg(test)]
mod tests {
    use super::super::{check_guard_self_disable, guard_verb_loosens, GUARD_VERB_HEADS};
    use super::unread_beside_guard_word;

    /// Whether the engine, which hands the check the line's executable
    /// projection and not the line, refuses `line` as a lowering of the
    /// guard.
    fn engine_refuses(line: &str) -> bool {
        crate::mcp::analyze_command(line, None)
            .signals
            .iter()
            .any(|signal| signal.signal == "guard_self_disable")
    }

    /// One line for each way a shell builds a command that is not on the
    /// line as written. Each lowered the guard when it ran under sh, bash or
    /// dash against a recording CLI (2026-11-09 and 2026-11-10), and the
    /// reading in `check_guard_self_disable` alone let most of them through.
    ///
    /// FAILS ON REVERT: take the call to `unread_beside_guard_word` out of
    /// `check_guard_self_disable` and the second assertion fails on the
    /// lines that reading does not follow (the function, the alias, the
    /// `hash -p`, the copied binary among them).
    #[test]
    fn a_guard_word_beside_a_construct_that_is_not_read_is_refused() {
        for line in [
            // A function, an alias, a trap, `eval`.
            r#"f() { "$@"; }; f innerwarden allow x"#,
            r#"function g { "$@"; }; g iw dry-run"#,
            "alias e=innerwarden; e allow x",
            "trap 'iw dry-run' EXIT",
            r#"eval "$(printf 'i%s dry-run' w)""#,
            // A substitution where the command word stands.
            "$(echo innerwarden) allow x",
            "`echo iw` dry-run",
            "bash <(echo iw dry-run)",
            // A variable, a glob, a brace list, a tilde as the command word.
            "x=innerwardenX; ${x%X} allow x",
            "/usr/local/bin/i? allow x",
            r#"{iw,dry-ru"n"}"#,
            "OLDPWD=/usr/local/bin/iw; ~- dry-run",
            // Words the line splits or sets as it runs.
            "IFS=_; x=iw_dry-run; $x",
            "read c <<< 'iw dry-run'; $c",
            r#"mapfile -t a <<< 'iw'; "${a[0]}" dry-run"#,
            "printf -v c 'i%s' w; $c dry-run",
            "declare -n r=c; c=iw; $r dry-run",
            r#"set -- iw dry-run; "$@""#,
            r#"set -- x iw dry-run; shift; "$@""#,
            r#"sh -c '"$@"' _ innerwarden allow x"#,
            // Text handed to a shell on its input.
            "bash <<< 'iw dry-run'",
            // Another name for the CLI.
            "hash -p /usr/local/bin/iw foo; foo uninstall",
            "cp /usr/local/bin/iw ./nr02; ./nr02 uninstall",
            // A verb in pieces.
            "iw agents dis$@connect claude-code",
            // Text that sh and dash do not read as bash does.
            "bash -c $'echo innerwarden allow x'",
            "true &>/dev/null bash -c 'innerwarden &>/dev/null allow x'",
            "x=$(true)# ; innerwarden allow x",
            // Code an interpreter runs: the words it hands the CLI are put
            // together there, not on the line (a list that shows `--list`
            // and is cut before it).
            r#"python3 -c "import subprocess;subprocess.run(['innerwarden','mute','--list'][:2]+['ATR-1'])""#,
        ] {
            assert!(unread_beside_guard_word(line), "{line}");
            assert!(check_guard_self_disable(line).is_some(), "{line}");
            assert!(engine_refuses(line), "{line}");
        }
    }

    /// The same constructs with no guard name and no lowering verb beside
    /// them, and a guard name with nothing unread beside it: a folder or a
    /// package that holds the name is not the name.
    ///
    /// FAILS ON REVERT: count `innerwarden` inside a longer word
    /// (`innerwarden-agent-guard`, `_innerwarden`) as the CLI's name and the
    /// first lines are refused.
    #[test]
    fn everyday_lines_that_mention_the_guard_are_not_refused() {
        for line in [
            "cargo test -p innerwarden-agent-guard",
            r#"cargo test -p innerwarden-agent-guard -- "$(cat filter.txt)""#,
            r#"f() { cargo test -p innerwarden-agent-guard "$@"; }; f --lib"#,
            "cd ~/github/_innerwarden && git status",
            r#"cd ~/github/_innerwarden && eval "$(direnv export bash)""#,
            r#"eval "$(ssh-agent)" && git -C ~/github/_innerwarden pull"#,
            "alias ll='ls -l'; ll ~/github/_innerwarden",
            "grep -r innerwarden docs/",
            r#"for f in docs/*.md; do grep -c innerwarden "$f"; done"#,
            "ls ~/.config/innerwarden/*.toml",
            "innerwarden status &>/dev/null",
            "iw doctor &>/tmp/doctor.log; tail /tmp/doctor.log",
            "innerwarden allow --list",
            r#"innerwarden hook --agent "$AGENT" < payload.json"#,
            r#"for a in claude codex; do innerwarden agents list | grep "$a"; done"#,
            r#"trap 'rm -f "$tmp"' EXIT; innerwarden status > "$tmp""#,
            r#"innerwarden status | tee "$(mktemp)""#,
            r#"git commit -m "docs: say what innerwarden allow does""#,
            r#"cd "$(git rev-parse --show-toplevel)" && cargo test -p innerwarden-agent-guard"#,
            r#"echo "$(date) deploy done" >> ~/innerwarden/notes.log"#,
            r#"allow=1; if [ "$allow" = 1 ]; then echo yes; fi"#,
            "npm install && npm run build",
        ] {
            assert!(!unread_beside_guard_word(line), "{line}");
            assert!(!engine_refuses(line), "{line}");
        }
        // What a guard CLI prints, kept in a variable: this rule passes it.
        // The reading after it refuses the line, as it did before this rule
        // was written; that refusal is not this rule's to pin.
        for line in [
            r#"VERSION=$(innerwarden --version); echo "$VERSION""#,
            r#"x=$(innerwarden --version) && echo "$x""#,
        ] {
            assert!(!unread_beside_guard_word(line), "{line}");
        }
    }

    /// The rule takes a guard CLI's first word for harmless when it is not in
    /// `GUARD_VERB_HEADS`, so the list has to hold every verb the reading
    /// refuses and no verb it never does.
    ///
    /// FAILS ON REVERT: take a verb out of `GUARD_VERB_HEADS` and its row
    /// here stops lowering, the list being what `guard_verb_loosens` checks
    /// first; add an arm to that function without the verb in the list and
    /// the count below is short.
    #[test]
    fn every_verb_head_lowers_with_the_right_words_after_it() {
        let tails: &[(&str, &[&str])] = &[
            ("allow", &["x"]),
            ("mute", &["x"]),
            ("dry-run", &[]),
            ("monitor", &[]),
            ("agents", &["disconnect", "claude-code"]),
            ("contain", &["--setup"]),
            ("install", &["claude-code", "--monitor"]),
            ("agent", &["disconnect"]),
            ("uninstall", &[]),
        ];
        assert_eq!(tails.len(), GUARD_VERB_HEADS.len());
        for head in GUARD_VERB_HEADS {
            let (_, tail) = tails
                .iter()
                .find(|(verb, _)| verb == head)
                .unwrap_or_else(|| panic!("no row for `{head}`"));
            let mut words = vec![head.to_string()];
            words.extend(tail.iter().map(|word| word.to_string()));
            assert!(guard_verb_loosens(&words), "{head}");
        }
        for verb in ["status", "doctor", "hook", "host"] {
            assert!(!guard_verb_loosens(&[verb.to_string(), "x".to_string()]));
        }
    }

    /// What the rule costs: lines that lower nothing and are refused, because
    /// telling them from the ones that do takes a reading no shell agrees
    /// on. Written down so the cost is a decision and not a surprise; a
    /// change that lets one of these through has to show the line beside it
    /// in the test above is still refused.
    #[test]
    fn lines_that_lower_nothing_and_are_refused_all_the_same() {
        for line in [
            // dash reads `$'` as a dollar sign and a plain quote.
            "echo $'innerwarden allow x'",
            r"git commit -m $'innerwarden allow x is refused\n\nmore'",
            // A comment after `)` in every shell measured; a word after a
            // substitution's `)`.
            "(true)#; innerwarden allow x",
            // What the CLI prints is run: not on the line.
            r#"eval "$(innerwarden completions zsh)""#,
            // A read of the guard's own lists through a program that adds
            // words of its own, or from an interpreter's code: what reaches
            // the CLI is not on the line. The same read asked for plainly
            // (`innerwarden allow --list`) is not refused.
            "echo x | xargs innerwarden allow --list",
            r#"python3 -c "import subprocess;subprocess.run(['innerwarden','mute','--list'])""#,
            r#"python3 -c "import subprocess;subprocess.run(['innerwarden','dry-run','--help'])""#,
        ] {
            assert!(unread_beside_guard_word(line), "{line}");
        }
    }
}
