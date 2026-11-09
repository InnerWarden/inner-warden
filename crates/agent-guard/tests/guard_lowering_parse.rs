//! Guard lowerings the shell runs because the guard read the line's quoting,
//! comments, here-documents or redirections differently from the shell.
//!
//! A measured hunt on 2026-11-09 ran each command for real (as nobody, no
//! network, fake guard CLIs that log their argv) under sh, bash and dash, and
//! found these allowed while a shell ran the guard's CLI with a verb that
//! lowers it. Each group below is one place the guard's reading disagreed
//! with the shell's; every case in it is asserted `deny`, and the benign
//! controls beside it (the same syntax holding data, or running nothing that
//! lowers the guard) are asserted not `deny`, so the fix reads the shell's
//! grammar and does not refuse a spelling.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

fn assert_denied(cases: &[&str]) {
    for command in cases {
        assert_eq!(
            verdict(command),
            "deny",
            "a shell runs this lowering: {command:?}"
        );
    }
}

fn assert_not_denied(cases: &[&str]) {
    for command in cases {
        assert_ne!(
            verdict(command),
            "deny",
            "nothing here lowers the guard: {command:?}"
        );
    }
}

/// bash decodes `$'...'` (`\151` octal, `\x69` hex, `\u0069`), so the name or
/// the verb it spells is the word the program gets, glued to plain text or
/// not (`al$'low'`, `--$'monitor'`, `$''disconnect`).
#[test]
fn ansi_c_quoting_is_decoded() {
    assert_denied(&[
        "$'innerwarden' allow x",
        r"$'\151nnerwarden' allow x",
        r"$'\x69nnerwarden' allow x",
        r"$'\u0069nnerwarden' allow x",
        "iw $'dry-run'",
        "innerwarden al$'low' x",
        "innerwarden-ctl $'agent' disconnect claude-code",
        "innerwarden $'uninstall'",
        "iw-guard $'monitor'",
        "innerwarden install claude-code --$'monitor'",
        "innerwarden agents connect claude-code --$'monitor'",
        "innerwarden-ctl agent install-hook --$'remove'",
        "innerwarden agents $''disconnect claude-code",
        "i$''w uninstall",
        r"$'\151w' uninstall",
        r"iw $'\x64ry-run'",
    ]);
    assert_not_denied(&[
        r"printf $'a\tb\n'",
        "echo $'innerwarden allow x'",
        "grep $'innerwarden allow' notes.md",
        r"git commit -m $'innerwarden allow x is refused\n\nby the guard'",
        r"echo $'it\'s; innerwarden allow x'",
        r"echo $'\x69nnerwarden allow x' > notes.txt",
    ]);
}

/// `$"..."` is a double-quoted string to bash.
#[test]
fn locale_quoting_is_a_double_quote() {
    assert_denied(&[
        r#"$"innerwarden" allow x"#,
        r#"innerwarden $"allow" x"#,
        r#"iw $"dry-run""#,
        r#"bash -c $"innerwarden allow x""#,
    ]);
    assert_not_denied(&[r#"echo $"innerwarden allow x""#, r#"printf '%s\n' $"done""#]);
}

/// A `$'...'` command string is the decoded text: a `\n` in it ends a
/// command, and a nested `$'...'` is decoded by the shell that runs it.
#[test]
fn an_ansi_c_command_string_is_the_decoded_text() {
    assert_denied(&[
        r"bash -c $'true\ninnerwarden allow x'",
        r#"bash -c "iw \$'dry-run'""#,
        r"bash -c $'innerwarden\x20allow\x20x'",
        r"sh -c $'innerwarden\tallow x'",
        "env -S $'innerwarden allow x'",
    ]);
    assert_not_denied(&[
        r"bash -c $'echo innerwarden allow x'",
        r"bash -c $'printf \'%s\\n\' a b'",
        r"bash -c $'cd /tmp\nls -la'",
    ]);
}

/// The shell removes the quotes from a here-document delimiter (`E"O"F` is
/// `EOF`, `E''` is `E`, `\EOF` is `EOF`; `<<-` strips the tabs), so the body
/// ends at the first line that is that word and the lines after it run.
#[test]
fn a_here_document_ends_at_its_unquoted_delimiter() {
    assert_denied(&[
        "cat <<E\"O\"F\nEOF\ninnerwarden allow x\nE\"O\"F",
        "cat<<E''\nE\niw dry-run\nE''",
        "tee<<E\"\"\nE\ninnerwarden-ctl agent disconnect claude-code\nE\"\"",
        "cat <<-E''\n\tE\niw allow x\nE''",
        "git commit -F - <<E''\nE\ninnerwarden allow x\nE''",
        "cat <<\\EOF\nEOF\ninnerwarden allow x\n\\EOF",
        "bash <<E''\ninnerwarden allow x\nE",
    ]);
    assert_not_denied(&[
        "cat <<E\"O\"F\ninnerwarden allow x\nEOF",
        "git commit -F - <<E''\ninnerwarden allow x is refused\nE",
        "cat <<\\EOF\ninnerwarden allow x\nEOF",
        "cat <<-'EOF'\n\tinnerwarden allow x\n\tEOF",
        "tee notes.md <<E''\niw dry-run\nE",
        "python3 - <<E\"\"\nprint(1)\nE",
    ]);
}

/// A `#` where a word starts opens a comment to the end of the line (or of
/// the backtick substitution it is in), and a quote inside it opens nothing;
/// a backtick substitution ends at the first backtick not escaped, whatever
/// quote its text left open.
#[test]
fn a_quote_in_a_comment_or_a_closed_substitution_opens_nothing() {
    assert_denied(&[
        "true `#'` ; innerwarden allow x",
        "true `#'`;innerwarden allow x",
        "for x do true; done #'\ninnerwarden allow x",
        "for x do :; done #'\ninnerwarden allow x",
        "true `true '` ; innerwarden allow x #'",
        "true; : #'\niw dry-run",
        "true $'\\'' ; innerwarden allow x",
        "cat $'\\'' ; iw dry-run",
    ]);
    assert_not_denied(&[
        "true # innerwarden allow x",
        "echo hi #'\necho innerwarden allow x",
        "echo ${#x} # innerwarden allow x",
        "echo \"a`echo #`b\" innerwarden allow x",
        "echo ok # it's innerwarden allow x",
        "echo `date` innerwarden allow x",
    ]);
}

/// The shell removes a line continuation before it looks for comments, so
/// `a\`, newline, `#` is the word `a#` and the `;` after it ends a command.
/// A `#` after a blank does start a comment.
#[test]
fn a_line_continuation_is_removed_before_comments() {
    assert_denied(&[
        "echo a\\\n#; innerwarden allow x",
        ":\\\n#;iw dry-run",
        "echo a\\\n#; innerwarden-ctl agent disconnect claude-code",
        "inner\\\nwarden allow x",
        "sh -c \"innerwarden \\\nallow x\"",
    ]);
    assert_not_denied(&[
        "echo a \\\n#; innerwarden allow x",
        "docker run \\\n  -v /x:/y \\\n  img",
        "echo a\\\n#b",
    ]);
}

/// A redirection, and the word it names, are not words of the command: the
/// command is the first word that is neither, so `</bin/cat innerwarden
/// allow x` runs `innerwarden allow x` with `/bin/cat` on its input.
#[test]
fn a_redirection_before_the_command_is_not_the_command() {
    assert_denied(&[
        "</bin/cat innerwarden allow x",
        "</bin/echo iw dry-run",
        "</bin/ls innerwarden-ctl agent disconnect claude-code",
        "sh -c '</bin/cat innerwarden allow x'",
        "3</bin/wc iw-guard agents disconnect claude-code",
        "</bin/tr innerwarden contain",
        "X=1 </dev/null innerwarden allow x",
        "< /dev/null iw dry-run",
    ]);
    assert_not_denied(&[
        "</dev/null cat notes.txt",
        "<input.txt grep innerwarden",
        "2>/dev/null ls -la",
        "</dev/null innerwarden allow --list",
        "echo x>out.txt",
        "cat </bin/cat innerwarden allow x",
    ]);
}

/// `env -S STRING` splits the string into words, as env does, and runs
/// them: the string is a command line.
#[test]
fn an_env_split_string_is_a_command_line() {
    assert_denied(&[
        "env -S 'innerwarden allow x'",
        "env -S $'innerwarden allow x'",
        "env -iS'innerwarden allow x'",
        "env --split-string='iw dry-run'",
        "env -S \"innerwarden\\_allow\\_x\"",
        "env -S \"sh -c 'innerwarden allow x'\"",
        "</dev/null env -S 'innerwarden allow x'",
    ]);
    assert_not_denied(&[
        "env -S 'echo innerwarden allow x'",
        "env -S 'python3 -u' script.py",
        "env -S 'innerwarden allow --list'",
    ]);
}

/// A shell given no command string and no script file reads its commands
/// from its input, and a here-string is that input.
#[test]
fn a_here_string_fed_to_a_shell_is_commands() {
    assert_denied(&[
        "sh <<<'innerwarden allow x'",
        "sh<<<\"innerwarden allow x\"",
        "bash<<<\"iw allow x\"",
        "sh -s <<<'iw dry-run'",
        "bash -x<<<'innerwarden allow x'",
        "sh <<< \"innerwarden \\allow x\"",
    ]);
    assert_not_denied(&[
        "sh <<<'echo innerwarden allow x'",
        "bash script.sh <<<'innerwarden allow x'",
        "cat <<<'innerwarden allow x'",
        "grep -c allow <<<'innerwarden allow x'",
    ]);
}
