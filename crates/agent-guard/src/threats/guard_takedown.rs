//! The guard taken down by inline code, by a copy onto one of its places
//! and by a program a search runs on every file (decision of the operator,
//! 2026-11-21: an action that takes the guard down is refused in every
//! posture; the mention of its name is not).
//!
//! Measured 2026-11-21 against main 776a7a2, each was allowed:
//! `python3 -c "open('/etc/innerwarden/guard.toml','w')..."`,
//! `shutil.rmtree('/var/lib/innerwarden')`, a here-document handed its
//! target as `sys.argv[1]`, `psutil` killing a process of the guard,
//! `node -e unlinkSync('/usr/local/bin/innerwarden')`, a unit copied onto
//! `/etc/systemd/system/innerwarden-agent.service` and `rg --pre rm`.
//!
//! Inline code of Python, Node, Ruby, Perl, PHP and Lua is read as text: it
//! is refused when it names a place of the guard (its configuration, state,
//! program, unit or hook), in the code or in the words it is handed, and
//! calls something that writes, removes, moves or links a file; or when it
//! names the guard's processes and calls something that signals one. Code
//! that only reads or prints those names is not refused here: it is the
//! mention rule's to hold ([`crate::mention`]).

use super::{
    effective_command_index, program_name, INNERWARDEN_INSTALL_PATHS, INNERWARDEN_SELF_PATHS,
};
use crate::shell_words::read_line;
use std::sync::LazyLock;

/// A command word that is an interpreter of code, as the text spells it.
static INTERPRETER: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?m)(?:^|[\s;&|(/`])(?:python[0-9.]*|pypy[0-9.]*|node(?:js)?|deno|bun|ruby|perl[0-9.]*|php[0-9.]*|lua(?:jit)?[0-9.]*)(?:\s|$)",
    )
    .expect("static interpreter regex")
});

/// How the interpreter is handed code the line shows: an inline option
/// (`-c`, `-e`, `-E`, `-r`, alone or in a cluster), `-` for standard
/// input, a here-document or a here-string.
static INLINE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?:^|\s)-[A-Za-z]*[ceEr](?:\s|$|['\x22])|(?:^|\s)-(?:\s|$)|<<")
        .expect("static inline code regex")
});

/// Calls that write, remove, move, copy or link a file, in the languages
/// read here, lowercase. A file opened with a mode that is only a read
/// (`open(p)`, `open(p, 'r')`) is not one.
static CHANGES_FILE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(concat!(
        // Python, Ruby, PHP: a mode that writes, appends, creates or updates.
        r#"\bf?open\s*\([^()]*(?:\([^()]*\)[^()]*)*,\s*(?:mode\s*=\s*)?["'][rbt]*[wax+][rwabtx+]*["']"#,
        // Perl: `open(my $f, '>', $p)`, `open(F, ">$p")`, `+<`.
        r#"|\bopen\s*\(?\s*(?:my\s+)?[$\w]+\s*,\s*["']\s*(?:>|\+<|\|)"#,
        r"|\bunlink|\bremove\s*\(|\brmtree\b|\brmdir|\brename|\bos\.replace\s*\(|\bshutil\.\w+",
        r"|\bcopyfile|\bcopy2?\s*\(|\bwritefile|\bappendfile|\bcreatewritestream|\.write_(?:text|bytes)\s*\(",
        r"|\bfile_put_contents|\bfile\.(?:write|delete|rename|symlink|link|truncate|chmod)\b|\bfileutils\.",
        r"|\bfs\.(?:rm|unlink|rename|writefile|appendfile|truncate|copyfile|cp|symlink|chmod)",
        r"|\brmsync|\bcpsync|\btruncate|\bchmod|\bsymlink|\bos\.link\s*\(|\bdeno\.(?:remove|writetextfile|writefile|rename)",
        r"|\bio\.open\s*\([^)]*,\s*['\x22][wa]",
        r#"|\.open\s*\(\s*["'][wax]"#,
    ))
    .expect("static file change regex")
});

/// Calls that signal a process, lowercase.
static SIGNALS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(concat!(
        r"\.kill\s*\(|\.terminate\s*\(|\.send_signal\s*\(|\bos\.killpg?\s*\(|\bposix_kill\s*\(",
        r#"|\bprocess\.kill\b|\bkill\s*\(?\s*["':]?(?:-?\d+|kill|term|sig\w+|stop|hup|int)\b|\bsignal\.sig(?:kill|term|stop|int|hup)\b"#,
    ))
    .expect("static signal regex")
});

/// The places of the guard a line may name, lowercase: the folders and
/// programs Community and Pro install ([`INNERWARDEN_SELF_PATHS`],
/// [`INNERWARDEN_INSTALL_PATHS`]), its folders in a home, a unit or job of
/// it anywhere, and a hook named for it.
static GUARD_PLACE: LazyLock<regex::Regex> = LazyLock::new(|| {
    let mut alternatives: Vec<String> = INNERWARDEN_SELF_PATHS
        .iter()
        .chain(INNERWARDEN_INSTALL_PATHS)
        .map(|path| regex::escape(path))
        .collect();
    alternatives.extend(
        [
            r"\.config/innerwarden",
            r"\.local/(?:state|share|bin)/innerwarden",
            r"\.cargo/bin/innerwarden",
            r"/opt/innerwarden",
            r"/s?bin/innerwarden",
            r"innerwarden[\w.-]*\.(?:service|timer|socket|plist)",
            r"hooks?/[^\s'\x22]*innerwarden",
        ]
        .iter()
        .map(|re| (*re).to_owned()),
    );
    regex::Regex::new(&alternatives.join("|")).expect("static guard place regex")
});

/// What [`inline_code_takes_guard_down`] says.
pub(super) const CODE_CHANGES_GUARD_PLACE: &str =
    "inline code writes, removes or moves a file of the guard (its configuration, state, program, unit or hook)";
/// What [`inline_code_takes_guard_down`] says of a signal.
pub(super) const CODE_SIGNALS_GUARD: &str = "inline code signals a process of the guard";

/// Whether `content` hands an interpreter code it shows.
fn hands_inline_code(content: &str) -> bool {
    content
        .lines()
        .any(|line| INTERPRETER.is_match(line) && INLINE.is_match(line))
        || (content.contains('|') && INTERPRETER.is_match(content))
}

/// Inline code that writes, removes, moves or links a place of the guard,
/// or signals one of its processes. `None` for code that only reads or
/// prints those names.
pub(super) fn inline_code_takes_guard_down(content: &str) -> Option<&'static str> {
    let lower = content.to_ascii_lowercase();
    if !lower.contains("innerwarden") || !hands_inline_code(content) {
        return None;
    }
    let written = without_reads(&lower);
    if GUARD_PLACE.is_match(&written) && CHANGES_FILE.is_match(&written) {
        return Some(CODE_CHANGES_GUARD_PLACE);
    }
    if SIGNALS.is_match(&lower) {
        return Some(CODE_SIGNALS_GUARD);
    }
    None
}

/// Code with the paths it only reads taken out: the path of an `open` with
/// no mode or a mode that only reads, of a `read_text`/`read_bytes`, of a
/// Node or Ruby read, and the source of a copy. What a copy lands on, or
/// a file opened to write, stays.
fn without_reads(code: &str) -> String {
    static READS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(concat!(
            r#"\bopen\s*\(\s*(?:"[^"]*"|'[^']*')\s*(?:,\s*(?:mode\s*=\s*)?["']r[bt]?["']\s*)?(?:,\s*encoding\s*=\s*["'][^"']*["']\s*)?\)"#,
            r#"|\bpath\s*\(\s*(?:"[^"]*"|'[^']*')\s*\)\s*\.(?:read_text|read_bytes|exists|is_file|is_dir|stat)\s*\("#,
            r#"|\b(?:readfilesync|readfile|existssync|statsync|file\.read|file\.exist\?|file\.readlines|io\.readlines)\s*\(\s*(?:"[^"]*"|'[^']*')"#,
        ))
        .expect("static read regex")
    });
    without_copy_sources(&READS.replace_all(code, "(read)"))
}

/// Code with the first argument of every copy call (`shutil.copy`,
/// `copyfile`, `copyFileSync`, `fs.cp`, `FileUtils.cp`) taken out, to
/// the comma of the call's own level: the source of a copy is read, what it
/// lands on is written.
fn without_copy_sources(code: &str) -> String {
    static CALL: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"\b(?:copy\w*|cp(?:sync)?)\s*\(").expect("static copy call regex")
    });
    let mut out = String::with_capacity(code.len());
    let mut from = 0usize;
    for found in CALL.find_iter(code) {
        if found.start() < from {
            continue;
        }
        out.push_str(&code[from..found.end()]);
        let rest = &code[found.end()..];
        let mut depth = 0usize;
        let mut quote: Option<char> = None;
        let mut escaped = false;
        let mut end = None;
        for (at, c) in rest.char_indices() {
            if let Some(open) = quote {
                if c == open && !escaped {
                    quote = None;
                }
                escaped = c == '\\' && !escaped;
                continue;
            }
            match c {
                '\'' | '"' | '`' => quote = Some(c),
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' if depth == 0 => break,
                ')' | ']' | '}' => depth -= 1,
                ',' if depth == 0 => {
                    end = Some(at);
                    break;
                }
                _ => {}
            }
        }
        match end {
            Some(at) => {
                out.push_str("(read)");
                from = found.end() + at;
            }
            None => from = found.end(),
        }
    }
    out.push_str(&code[from..]);
    out
}

/// Inline code that writes, removes, moves or copies onto an agent's
/// settings that load the guard (`.claude/settings.json`,
/// `.codex/config.toml`, ...), the paths it only reads left out
/// ([`without_reads`]): `perl -e 'open(my $f, ">", ".claude/settings.json")'`
/// and `shutil.copyfile('x.json', '.codex/config.toml')` were allowed
/// (measured 2026-11-21).
pub(super) fn inline_code_changes_agent_settings(content: &str) -> bool {
    static SETTINGS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r"\.claude/settings(?:\.local)?\.json|\.claude\.json|\.codex/(?:config\.toml|hooks\.json)|\.cursor/(?:mcp|hooks)\.json|\.gemini/settings\.json|openclaw\.json",
        )
        .expect("static agent settings regex")
    });
    let lower = content.to_ascii_lowercase();
    if !SETTINGS.is_match(&lower) || !hands_inline_code(content) {
        return false;
    }
    let written = without_reads(&lower);
    SETTINGS.is_match(&written) && CHANGES_FILE.is_match(&written)
}

/// What [`copies_onto_guard_place`] says.
pub(super) const COPIED_ONTO_GUARD_PLACE: &str =
    "copies, installs or links a file onto a place of the guard (its configuration, program, unit or hook)";

/// Whether a command of the line copies, installs or links a file onto a
/// place of the guard: the last operand of `cp`, `install`, `ln` or
/// `rsync`, or a file `tee` writes, names one (`cp x.service
/// /etc/systemd/system/innerwarden-agent.service`). Copying FROM the
/// guard's places is a read.
pub(super) fn copies_onto_guard_place(content: &str) -> bool {
    if !content.to_ascii_lowercase().contains("innerwarden") {
        return false;
    }
    read_line(content).commands.iter().any(|command| {
        let words: Vec<String> = command.words.iter().map(|word| word.text.clone()).collect();
        let Some(at) = effective_command_index(&words) else {
            return false;
        };
        let operands: Vec<String> = words[at + 1..]
            .iter()
            .filter(|word| !word.starts_with('-'))
            .map(|word| word.to_ascii_lowercase())
            .collect();
        let names = |word: &String| GUARD_PLACE.is_match(word);
        match program_name(&words[at]).as_str() {
            "cp" | "install" | "ln" | "rsync" | "gcp" | "ginstall" => {
                operands.len() >= 2 && operands.last().is_some_and(names)
            }
            "tee" => operands.iter().any(names),
            "dd" => operands.iter().any(|word| {
                word.strip_prefix("of=")
                    .is_some_and(|of| GUARD_PLACE.is_match(of))
            }),
            _ => false,
        }
    })
}

/// The lines a search runs as a program on each file it reads: `rg --pre
/// PROG` (`PROG FILE`) and `git grep -O PROG` (`PROG FILE...`), each
/// with the paths the search names. The program is read as a command, with
/// what it is handed.
pub(super) fn programs_searches_run(content: &str) -> Vec<String> {
    let lower = content.to_ascii_lowercase();
    if !(lower.contains("--pre") || (lower.contains("git") && lower.contains("grep"))) {
        return Vec::new();
    }
    let mut lines = Vec::new();
    for command in read_line(content).commands {
        let words: Vec<String> = command.words.iter().map(|word| word.text.clone()).collect();
        let Some(at) = effective_command_index(&words) else {
            continue;
        };
        let arguments = &words[at + 1..];
        let mut program = None;
        let mut paths = Vec::new();
        match program_name(&words[at]).as_str() {
            "rg" => {
                let mut rest = arguments.iter();
                let mut positional = 0usize;
                while let Some(word) = rest.next() {
                    if word == "--pre" {
                        program = rest.next().cloned();
                    } else if let Some(value) = word.strip_prefix("--pre=") {
                        program = Some(value.to_owned());
                    } else if word == "-e"
                        || word == "--regexp"
                        || word == "-g"
                        || word == "--glob"
                        || word == "-t"
                        || word == "--type"
                    {
                        rest.next();
                    } else if !word.starts_with('-') {
                        // The first operand is the pattern, unless -e gave it.
                        if positional > 0
                            || arguments
                                .iter()
                                .any(|w| w == "-e" || w.starts_with("--regexp"))
                        {
                            paths.push(word.clone());
                        }
                        positional += 1;
                    }
                }
            }
            "git" => {
                let Some(grep) = arguments.iter().position(|word| word == "grep") else {
                    continue;
                };
                let mut rest = arguments[grep + 1..].iter();
                while let Some(word) = rest.next() {
                    if word == "-O" || word == "--open-files-in-pager" {
                        program = rest.next().cloned();
                    } else if let Some(value) = word.strip_prefix("--open-files-in-pager=") {
                        program = Some(value.to_owned());
                    } else if let Some(value) = word
                        .strip_prefix('-')
                        .filter(|short| !short.starts_with('-'))
                        .and_then(|short| short.find('O').map(|o| short[o + 1..].to_owned()))
                    {
                        program = Some(value);
                    } else if !word.starts_with('-') {
                        paths.push(word.clone());
                    }
                }
            }
            _ => continue,
        }
        if let Some(program) = program.filter(|program| !program.is_empty()) {
            lines.push(format!("{program} {}", paths.join(" ")).trim().to_owned());
        }
    }
    lines
}

/// Calls that write a file, lowercase, for [`inline_code_writes_startup_file`].
static WRITES_FILE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(concat!(
        r#"\bf?open\s*\([^()]*(?:\([^()]*\)[^()]*)*,\s*(?:mode\s*=\s*)?["'][rbt]*[wax+][rwabtx+]*["']"#,
        r#"|\bopen\s*\(?\s*(?:my\s+)?[$\w]+\s*,\s*["']\s*(?:>|\+<)"#,
        r"|\bwritefile|\bappendfile|\bcreatewritestream|\.write_(?:text|bytes)\s*\(|\bfile_put_contents",
        r"|\bfile\.write\b|\bio\.write\b|\bshutil\.copy|\bcopyfile|\bfs\.(?:cp|copyfile|symlink)|\bsymlink",
        r#"|\.open\s*\(\s*["'][wax]"#,
    ))
    .expect("static file write regex")
});

/// Whether inline code writes a file of a home that runs at login
/// (`open(os.path.expanduser('~/.zshrc'), 'a').write(...)`): a startup
/// file named in the code or in its words, whole or as the name under the
/// home the code builds (`Path.home() / '.bashrc'`).
pub(super) fn inline_code_writes_startup_file(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    if !hands_inline_code(content) || !WRITES_FILE.is_match(&lower) {
        return false;
    }
    let builds_home = [
        "home(",
        "expanduser",
        "environ",
        "getenv",
        "env.home",
        "env['home']",
        "env[\"home\"]",
        "env{home}",
        "$home",
        "homedir(",
    ]
    .iter()
    .any(|word| lower.contains(word));
    lower
        .split(|c: char| c.is_whitespace() || "'\"`,()+;[]{}=".contains(c))
        .filter(|piece| !piece.is_empty())
        .any(|value| {
            super::names_home_startup(value, false)
                || (builds_home
                    && super::HOME_STARTUP_FILES
                        .iter()
                        .any(|file| value.trim_start_matches('/') == *file))
        })
}

/// Whether a `sed` of the line writes a home's startup file with its `w`
/// or `W` command, or the `w` flag of `s///`: what it writes is lines of
/// a file the line does not show.
pub(super) fn sed_writes_startup_file(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    if !lower.contains("sed") {
        return false;
    }
    static WRITE: LazyLock<regex::Regex> = LazyLock::new(|| {
        // An address or a `s///flags`, then `w` or `W` and the file to the
        // end of the script.
        regex::Regex::new(r"(?:^|[;\n{}0-9$/,!]|^\s*)\s*[wW]\s+(\S[^;\n]*)")
            .expect("static sed write regex")
    });
    read_line(content).commands.iter().any(|command| {
        let words: Vec<String> = command.words.iter().map(|word| word.text.clone()).collect();
        let Some(at) = effective_command_index(&words) else {
            return false;
        };
        if !matches!(program_name(&words[at]).as_str(), "sed" | "gsed") {
            return false;
        }
        let mut rest = words[at + 1..].iter().peekable();
        let mut scripts = Vec::new();
        let mut given = false;
        while let Some(word) = rest.next() {
            if word == "-e" || word == "--expression" {
                given = true;
                scripts.extend(rest.next().cloned());
            } else if let Some(value) = word.strip_prefix("--expression=") {
                given = true;
                scripts.push(value.to_owned());
            } else if !word.starts_with('-') && !given && scripts.is_empty() {
                scripts.push(word.clone());
            }
        }
        scripts.iter().any(|script| {
            WRITE.captures_iter(script).any(|found| {
                found
                    .get(1)
                    .is_some_and(|file| super::names_home_startup(file.as_str().trim(), false))
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_writes_by_code() {
        assert!(inline_code_writes_startup_file(
            "node -e \"require('fs').appendFileSync(require('os').homedir()+'/.bashrc', 'alias ll=ls\\n')\""
        ));
        assert!(super::super::replaces_startup_file_unseen(
            "node -e \"require('fs').appendFileSync(require('os').homedir()+'/.bashrc', 'alias ll=ls\\n')\""
        ));
    }
}
