//! A git whose editor is a shell or an interpreter runs the message.
//!
//! Git opens the message file in the editor it is given: `core.editor` or
//! `sequence.editor` set with `-c` or by an earlier `git config` on the
//! line, or `GIT_EDITOR`, `GIT_SEQUENCE_EDITOR`, `VISUAL` or `EDITOR` set
//! for it. When that editor is a shell (`sh`, `bash -x`, `env zsh`), the
//! file is its script: the text of `-m`, and the body of a here-document or
//! a here-string git reads with `-F -`, run as shell lines. When it is an
//! interpreter (`python3`, `perl`), they run as that language's code. An
//! alias that starts with `!` runs its value through a shell with the words
//! after it appended. Measured 2026-11-25 on main 542cc8c: `git -c
//! core.editor=sh commit -e -m 'rm -rf ~'`, `GIT_EDITOR=sh git commit -F -`
//! with a here-document and `git -c alias.x='!sh -c' x 'rm -rf ~'` were all
//! allowed. An ordinary editor (`vim`, `nano`, `code --wait`, `true`)
//! runs nothing of the message, and its message is not read.

use super::{
    collect_nodes_of_kind, command_words, effective_command_words, heredoc_owner,
    interpreter_language, is_code_language, is_shell_name, node_is_in_literal_unreachable_branch,
    node_text, normalized_command_name, shell_literal_word, stdin_code_text, Assignment,
};

/// The variables git takes its editor from.
const EDITOR_VARIABLES: &[&str] = &["GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "VISUAL", "EDITOR"];

/// The settings git takes its editor from.
const EDITOR_SETTINGS: &[&str] = &["core.editor", "sequence.editor"];

/// The subcommands that write a message file and may open it in the editor.
const MESSAGE_SUBCOMMANDS: &[&str] = &["commit", "tag", "merge", "notes"];

/// Git's own options before the subcommand that take the next word.
const GIT_OPTIONS_WITH_VALUE: &[&str] = &[
    "-C",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--exec-path",
    "--config-env",
    "--super-prefix",
    "--list-cmds",
    "--attr-source",
];

/// What an editor does with the file it is handed.
#[derive(Debug, PartialEq)]
enum Runs {
    /// A shell runs it as its script.
    Shell,
    /// An interpreter, named as written, runs it as code.
    Code(String),
}

/// The lines git runs of a line's messages and aliases, as shell lines: the
/// message of a git whose editor is a shell (or, for an interpreter, a
/// line that hands the message to that interpreter as code), and the line
/// an alias that starts with `!` runs with the words after it.
pub(super) fn message_lines(
    root: tree_sitter::Node<'_>,
    bytes: &[u8],
    commands: &[tree_sitter::Node<'_>],
    assignments: &[Assignment],
) -> Vec<String> {
    let mut lines = Vec::new();
    let mut set_by_config: Vec<(usize, String)> = Vec::new();
    for command in commands {
        if node_is_in_literal_unreachable_branch(*command, bytes) {
            continue;
        }
        let Some(words) = command_words(*command, bytes) else {
            continue;
        };
        let Some(effective) = effective_command_words(&words, 0) else {
            continue;
        };
        if normalized_command_name(&effective[0]) != "git" {
            continue;
        }
        let at_command = command.start_byte();
        let git = read_git(&effective[1..]);
        // `git config core.editor sh` sets the editor of the gits after it.
        if git.subcommand.as_deref() == Some("config") {
            if let Some(value) = config_editor(&git.rest) {
                set_by_config.push((command.end_byte(), value));
            }
            continue;
        }
        let mut editors: Vec<String> = git.editors.clone();
        // `GIT_EDITOR=sh git` and `env GIT_EDITOR=sh git`.
        let mut cursor = command.walk();
        let prefix = command
            .children(&mut cursor)
            .filter(|child| child.kind() == "variable_assignment")
            .map(|child| node_text(child, bytes));
        let wrapper = words[..words.len() - effective.len()].iter().cloned();
        for assignment in prefix.chain(wrapper) {
            if let Some((name, value)) = assignment.split_once('=') {
                if EDITOR_VARIABLES.contains(&name) {
                    editors.push(shell_literal_word(value));
                }
            }
        }
        // `export GIT_EDITOR=sh; git ...`: any value set before it.
        for (name, value, at, _, _) in assignments {
            if *at <= at_command && EDITOR_VARIABLES.contains(&name.as_str()) {
                if let Some(value) = value {
                    editors.push(shell_literal_word(value));
                }
            }
        }
        editors.extend(
            set_by_config
                .iter()
                .filter(|(at, _)| *at <= at_command)
                .map(|(_, value)| value.clone()),
        );
        if let (Some(alias), Some(_)) = (git.alias_run.as_ref(), git.subcommand.as_ref()) {
            lines.extend(alias_lines(alias, &git.rest));
        }
        let Some(subcommand) = git.subcommand.as_deref() else {
            continue;
        };
        if !MESSAGE_SUBCOMMANDS.contains(&subcommand) {
            continue;
        }
        let runs: Vec<Runs> = editors
            .iter()
            .filter_map(|editor| editor_runs(editor))
            .collect();
        if runs.is_empty() {
            continue;
        }
        let (mut messages, from_stdin) = message_texts(&git.rest);
        if from_stdin {
            messages.extend(stdin_texts(root, *command, bytes));
        }
        if messages.is_empty() {
            continue;
        }
        let message = messages.join("\n\n");
        for run in runs {
            match run {
                Runs::Shell => lines.push(message.clone()),
                Runs::Code(program) => {
                    if let Some(line) = code_line(&program, &message) {
                        lines.push(line);
                    }
                }
            }
        }
    }
    lines.dedup();
    lines
}

/// A git command's words read as git reads its own options.
#[derive(Debug, Default)]
struct Git {
    /// The value of each editor setting given with `-c`.
    editors: Vec<String>,
    /// The subcommand, as written.
    subcommand: Option<String>,
    /// The line the subcommand runs when it is an alias given with `-c`
    /// that starts with `!`, without the `!`.
    alias_run: Option<String>,
    /// The words after the subcommand, quotes taken off.
    rest: Vec<String>,
}

fn read_git(args: &[String]) -> Git {
    let mut git = Git::default();
    let mut aliases: Vec<(String, String)> = Vec::new();
    let mut at = 0;
    while at < args.len() {
        let word = shell_literal_word(&args[at]);
        let setting = if word == "-c" {
            at += 1;
            args.get(at).map(|value| shell_literal_word(value))
        } else if let Some(value) = word.strip_prefix("-c").filter(|value| !value.is_empty()) {
            Some(value.to_owned())
        } else if word.starts_with('-') {
            if GIT_OPTIONS_WITH_VALUE.contains(&word.as_str()) {
                at += 1;
            }
            at += 1;
            continue;
        } else {
            git.subcommand = Some(word);
            git.rest = args[at + 1..]
                .iter()
                .map(|value| shell_literal_word(value))
                .collect();
            break;
        };
        at += 1;
        let Some((key, value)) = setting.as_deref().and_then(|s| s.split_once('=')) else {
            continue;
        };
        let key = key.to_ascii_lowercase();
        let value = shell_literal_word(value);
        if EDITOR_SETTINGS.contains(&key.as_str()) {
            git.editors.push(value);
        } else if let Some(name) = key.strip_prefix("alias.") {
            aliases.push((name.to_owned(), value));
        }
    }
    if let Some(subcommand) = git.subcommand.as_deref() {
        git.alias_run = aliases
            .iter()
            .rev()
            .find(|(name, _)| name.eq_ignore_ascii_case(subcommand))
            .and_then(|(_, value)| value.strip_prefix('!'))
            .map(str::to_owned);
    }
    git
}

/// The editor `git config [scope] core.editor <value>` sets.
fn config_editor(rest: &[String]) -> Option<String> {
    let at = rest
        .iter()
        .position(|word| EDITOR_SETTINGS.contains(&word.to_ascii_lowercase().as_str()))?;
    rest.get(at + 1).cloned()
}

/// What an editor command runs the file as, behind `env` and the other
/// wrappers: a shell's script, an interpreter's code, or nothing.
fn editor_runs(editor: &str) -> Option<Runs> {
    let words: Vec<String> = editor.split_whitespace().map(shell_literal_word).collect();
    let effective = effective_command_words(&words, 0)?;
    let name = normalized_command_name(&effective[0]);
    if is_shell_name(&name) {
        Some(Runs::Shell)
    } else if is_code_language(&name) {
        Some(Runs::Code(name))
    } else {
        None
    }
}

/// The texts of `-m`, `--message`, `-m<text>` and of a group of short
/// options that ends in `m` (`-am`), and whether the message is read
/// from stdin (`-F -`, `--file=-`). The grammar does not keep the `-`
/// of `-F - <<'EOF'` as a word, so a `-F` that ends the words reads stdin
/// too.
fn message_texts(rest: &[String]) -> (Vec<String>, bool) {
    let mut texts = Vec::new();
    let mut from_stdin = false;
    let mut at = 0;
    while at < rest.len() {
        let word = rest[at].as_str();
        if word == "--" {
            break;
        }
        let next = rest.get(at + 1);
        if let Some(value) = word.strip_prefix("--message=") {
            texts.push(shell_literal_word(value));
        } else if word == "--message" {
            texts.extend(next.cloned());
            at += 1;
        } else if matches!(word, "--file=-" | "-F-")
            || (matches!(word, "-F" | "--file") && next.is_none_or(|n| n == "-"))
        {
            from_stdin = true;
        } else if let Some(short) = word
            .strip_prefix('-')
            .filter(|s| !s.starts_with('-') && !s.is_empty())
        {
            if let Some(position) = short.find('m') {
                if short[..position].chars().all(|c| c.is_ascii_alphabetic()) {
                    let value = &short[position + 1..];
                    if value.is_empty() {
                        texts.extend(next.cloned());
                        at += 1;
                    } else {
                        texts.push(shell_literal_word(value));
                    }
                }
            }
        }
        at += 1;
    }
    (texts, from_stdin)
}

/// The texts of the here-documents and here-strings `command` reads on
/// stdin.
fn stdin_texts(
    root: tree_sitter::Node<'_>,
    command: tree_sitter::Node<'_>,
    bytes: &[u8],
) -> Vec<String> {
    let mut texts = Vec::new();
    for kind in ["heredoc_body", "herestring_redirect"] {
        let mut bodies = Vec::new();
        collect_nodes_of_kind(root, kind, &mut bodies, 0);
        for body in bodies {
            if heredoc_owner(body).is_some_and(|owner| owner.id() == command.id()) {
                texts.push(stdin_code_text(body, bytes));
            }
        }
    }
    texts
}

/// A line that hands `code` to `program` the way the guard reads inline
/// code: `python3 -c '...'`, `perl -e '...'`.
fn code_line(program: &str, code: &str) -> Option<String> {
    let flag = match interpreter_language(program) {
        "python" => "-c",
        "perl" | "ruby" | "node" | "lua" => "-e",
        "php" => "-r",
        "deno" => "eval",
        _ => return None,
    };
    Some(format!("{program} {flag} {}", single_quoted(code)))
}

/// The lines an alias that starts with `!` runs: its value with the words
/// after it appended, as git hands them to the shell, and its value with
/// `$1` ... `$9` and `$@` written out as those words.
fn alias_lines(alias: &str, words: &[String]) -> Vec<String> {
    let quoted: Vec<String> = words.iter().map(|word| single_quoted(word)).collect();
    let mut lines = Vec::new();
    if !quoted.is_empty() {
        lines.push(format!("{alias} {}", quoted.join(" ")));
    }
    if alias.contains('$') {
        let mut written = alias.to_owned();
        let all = quoted.join(" ");
        for pattern in ["\"$@\"", "\"${@}\"", "$@", "${@}", "\"$*\"", "$*"] {
            written = written.replace(pattern, &all);
        }
        for (index, word) in quoted.iter().enumerate().take(9).rev() {
            let n = index + 1;
            for pattern in [
                format!("\"${n}\""),
                format!("\"${{{n}}}\""),
                format!("${{{n}}}"),
                format!("${n}"),
            ] {
                written = written.replace(&pattern, word);
            }
        }
        if written != alias {
            lines.push(written);
        }
    }
    lines
}

/// `text` as one single-quoted shell word.
fn single_quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(line: &str) -> Vec<String> {
        crate::shell::handed_shell_lines(line).lines
    }

    /// FAILS ON REVERT of `message_lines` in `handed_shell_lines`.
    #[test]
    fn a_message_a_shell_editor_runs_is_a_line_handed_to_a_shell() {
        for (line, handed) in [
            ("git -c core.editor=sh commit -e -m 'rm -rf ~'", "rm -rf ~"),
            (
                "git -c core.editor=bash commit -e -am \"rm -rf ~\"",
                "rm -rf ~",
            ),
            ("GIT_EDITOR=sh git commit -e -m 'rm -rf ~'", "rm -rf ~"),
            (
                "env VISUAL=bash git commit --message='rm -rf ~'",
                "rm -rf ~",
            ),
            ("export EDITOR=zsh; git commit -e -m 'rm -rf ~'", "rm -rf ~"),
            (
                "git config core.editor sh && git commit -e -m 'rm -rf ~'",
                "rm -rf ~",
            ),
            (
                "git -c core.editor=sh commit -e -F - <<'EOF'\nrm -rf ~\nEOF",
                "rm -rf ~\n",
            ),
            ("git -c alias.x='!sh -c' x 'rm -rf ~'", "sh -c 'rm -rf ~'"),
            (
                "git -c alias.x='!sh -c \"$1\"' x 'rm -rf ~'",
                "sh -c 'rm -rf ~'",
            ),
            (
                "EDITOR=python3 git commit -e -m 'import os'",
                "python3 -c 'import os'",
            ),
        ] {
            assert!(
                lines(line).iter().any(|l| l == handed),
                "{line}: {:?}",
                lines(line)
            );
        }
        for line in [
            "git -c core.editor=vim commit -e -m 'rm -rf ~ was refused'",
            "GIT_EDITOR=true git commit -m 'rm -rf ~'",
            "GIT_EDITOR='code --wait' git commit -e -m 'rm -rf ~'",
            "git commit -m 'rm -rf ~'",
            "git -c core.editor=sh log -m",
            "git -c alias.st=status st",
        ] {
            assert!(
                !lines(line).iter().any(|l| l.contains("rm -rf")),
                "{line}: {:?}",
                lines(line)
            );
        }
    }

    #[test]
    fn a_message_option_takes_the_next_word() {
        let words = |list: &[&str]| list.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            message_texts(&words(&["--message", "rm -rf ~", "-e"])),
            (vec!["rm -rf ~".to_owned()], false)
        );
    }

    #[test]
    fn an_editor_is_read_behind_its_wrappers() {
        assert_eq!(editor_runs("sh"), Some(Runs::Shell));
        assert_eq!(editor_runs("/usr/bin/env bash -x"), Some(Runs::Shell));
        assert_eq!(editor_runs("perl"), Some(Runs::Code("perl".into())));
        assert_eq!(editor_runs("vim"), None);
        assert_eq!(editor_runs("code --wait"), None);
        assert_eq!(editor_runs("true"), None);
    }
}
