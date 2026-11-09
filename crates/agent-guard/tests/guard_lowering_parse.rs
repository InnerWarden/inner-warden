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

use std::time::{Duration, Instant};

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

/// The `)` that closes a substitution (`$(`, `$((`, `<(`) or an array
/// (`a=(`) does not end the word it is in: a `#` right after it is a
/// character, so the `;` after it ends a command and the lowering after it
/// runs (review of 1877717, 2026-11-09: each was denied before and allowed
/// after, while sh, bash and dash ran it; `<(` and arrays in bash). The `)`
/// of a subshell, and of a `case` pattern, is an operator, and a `#` after
/// it does open a comment.
#[test]
fn a_hash_after_a_substitution_is_a_character() {
    assert_denied(&[
        "a=$(date)#;innerwarden allow x",
        "a=$(true)#; innerwarden allow x",
        "a=$(date)#;sudo innerwarden allow x",
        "a=<(true)#;innerwarden allow x",
        "export a=$(date)#;innerwarden allow x",
        "ts=$(date +%s)#;iw dry-run",
        "local_ts=$(date)#;innerwarden allow x",
        "sh -c 'a=$(date)#;innerwarden allow x'",
        "a=$(date)#&&innerwarden allow x",
        "a=$(date)#|innerwarden allow x",
        "cd $(pwd)#;innerwarden allow x",
        "a=$(date)#;bash -c 'innerwarden allow x'",
        "echo $((1+2))#;iw dry-run",
        "x=$(echo $(date))#;innerwarden-ctl agent disconnect claude-code",
        "cat <(true)#;iw-guard monitor",
        "echo $(case x in x) echo y;; esac)#; innerwarden allow x",
        "a=(1 2)#;innerwarden allow x",
        "echo $(true)\\\n#; innerwarden allow x",
        "a=$(true)\\\n#;innerwarden allow x",
    ]);
    assert_not_denied(&[
        "(true)#; innerwarden allow x",
        "((1+2))#; innerwarden allow x",
        "echo $(date) # innerwarden allow x",
        "a=$(date) #;innerwarden allow x",
        "ts=$(date +%s)#build-tag",
        "case $x in a)# innerwarden allow x\n;; esac",
    ]);
}

/// The command in a process substitution runs, wherever it stands in the
/// line (bash). It is read from the text between the `(` and its `)`, once,
/// not by reading the words after every `<` again.
#[test]
fn a_process_substitution_runs_its_command() {
    assert_denied(&[
        "<(innerwarden allow x)",
        "cat <(iw dry-run)",
        "< <(innerwarden allow x) cat",
        "echo hi > >(innerwarden allow x)",
        "diff <(true) <(sudo innerwarden allow x)",
        "bash -c 'wc -l <(innerwarden-ctl agent disconnect claude-code)'",
    ]);
    assert_not_denied(&[
        "diff <(sort a.txt) <(sort b.txt)",
        "cat <(echo innerwarden allow x)",
        "comm -12 <(ls a) <(ls b)",
        "echo \"<(innerwarden allow x)\"",
        "grep x <(innerwarden allow --list)",
    ]);
}

/// The shell takes a redirection out of the arguments wherever it stands,
/// so one between the CLI and its verb is not the verb, and `2>&1`, `&>`
/// and `>|` are redirections, not the end of a command (measured
/// 2026-11-09: sh, bash and dash ran each lowering below; `&>` in bash).
#[test]
fn a_redirection_after_the_cli_is_not_its_verb() {
    assert_denied(&[
        "innerwarden 2>/dev/null allow x",
        "innerwarden>/dev/null allow x",
        "innerwarden 2>&1 allow x",
        "innerwarden &>/dev/null allow x",
        "innerwarden >|/dev/null allow x",
        "iw </dev/null dry-run",
        "innerwarden-ctl >/dev/null agent disconnect claude-code",
        "sudo innerwarden 2>/dev/null allow x",
    ]);
    assert_not_denied(&[
        "innerwarden allow --list > rules.txt",
        "innerwarden status 2>/dev/null",
        "innerwarden > allow x",
        "iw agents list 2>&1 | head",
        "make 2>&1 | tee build.log",
        "ls -la 2>&1 >/dev/null; echo done",
    ]);
}

/// In `$((...))` and `((...))` a `<<` is a shift and opens no here-document,
/// so the lines after it are not taken for a body, and a here-document
/// after it ends where the shell ends it.
#[test]
fn an_arithmetic_shift_opens_no_here_document() {
    assert_denied(&[
        "echo $((1<<2))\ncat <<E\"O\"F\nEOF\niw dry-run\nE\"O\"F",
        "x=$((1<<2))\ncat <<E\"O\"F\nEOF\niw dry-run\nE\"O\"F",
        "(( y = 1<<2 ))\ncat <<E''\nE\ninnerwarden allow x\nE''",
    ]);
    assert_not_denied(&[
        "echo $((1<<2))\ncat <<'EOF'\niw dry-run\nEOF",
        "echo $((1<<2))",
    ]);
}

/// A chain of command strings deeper than the reading follows is refused
/// when it names the guard: the reading is cut short there, and a line it
/// cannot read to the end is not let through on what it did read.
#[test]
fn a_reading_cut_short_refuses_a_line_naming_the_guard() {
    assert_denied(&[&format!(
        "{}env -S 'innerwarden allow x'",
        "env -S X=1 ".repeat(5)
    )]);
    assert_not_denied(&["env -S X=1 env -S Y=2 env TZ=UTC date"]);
}

/// Lines built to make the guard's reading slow (review of 1877717,
/// 2026-11-09, on the lab box in release: 179 bytes of `< -a` before a
/// lowering took over 40 s, and 880 bytes of `env -S X=1` took 15 s, past
/// the hook's 9 to 17 s timeout). The reading is one pass per level now,
/// paid from a budget that is a bounded multiple of the line. The ceiling
/// is for a debug build on a loaded runner and is far above what these
/// take (milliseconds); what it catches is the exponential reading, which
/// takes minutes.
///
/// FAILS ON REVERT: with the reading of the words after every bare `<`, or
/// of every `env -S` string in a pass, the first cases run for minutes.
#[test]
fn a_line_built_to_be_slow_to_read_is_read_in_bounded_time() {
    let ceiling = Duration::from_secs(3);
    let lowerings = [
        format!(
            "{}innerwarden status; innerwarden allow x",
            "< -a ".repeat(28)
        ),
        format!("{}iw --version && iw dry-run", "< 1 ".repeat(28)),
        format!(
            "{}innerwarden status; innerwarden allow x",
            "env -S X=1 ".repeat(80)
        ),
    ];
    let others = [
        format!("{}innerwarden status", "< ".repeat(60)),
        format!("{}innerwarden status", "< -a ".repeat(40)),
        format!("{}innerwarden status", "env -S X=1 ".repeat(200)),
        format!("{}true", "find . -exec ".repeat(200)),
        format!("{}true", "<(".repeat(2000)),
        format!("{}true", "a=$(".repeat(2000)),
        "case x in a) ;; esac ".repeat(2000),
    ];
    for command in lowerings.iter().chain(&others) {
        let start = Instant::now();
        let verdict = verdict(command);
        let took = start.elapsed();
        assert!(
            took < ceiling,
            "{} bytes took {took:?}: {:?}",
            command.len(),
            &command[..command.len().min(80)]
        );
        if lowerings.contains(command) {
            assert_eq!(verdict, "deny", "{:?}", &command[..command.len().min(80)]);
        }
    }
}
