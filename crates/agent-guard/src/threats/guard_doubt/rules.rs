//! The fail-closed rule: deny when the line holds a guard CLI name or a
//! guard-lowering verb AND a command the reading cannot vouch for.

use super::super::{
    ctl_verb_loosens, guard_verb_loosens, skip_leading_options, GUARD_PROGRAMS as NAMES,
    GUARD_VERB_HEADS, SHELLS,
};
use super::lexer::{Command, Lexed, Lexer, Word, EXPANSION};
use super::tokens::{guard_letters, guard_tokens};

const MAX_DEPTH: usize = 6;
const KEYWORDS: &[&str] = &[
    "then", "do", "else", "elif", "if", "while", "until", "!", "{", "}", "fi", "done", "time",
    "coproc",
];
/// Programs that run the command named after their own options.
/// (name, options that take a value, positional words before the command).
const LAUNCHERS: &[(&str, &[&str], usize)] = &[
    (
        "sudo",
        &["-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U"],
        0,
    ),
    ("doas", &["-u", "-C"], 0),
    ("env", &["-u", "-C"], 0),
    ("nice", &["-n"], 0),
    ("ionice", &["-c", "-n", "-p"], 0),
    ("nohup", &[], 0),
    ("setsid", &[], 0),
    ("stdbuf", &["-i", "-o", "-e"], 0),
    ("timeout", &["-s", "-k"], 1),
    ("command", &[], 0),
    ("builtin", &[], 0),
    ("exec", &["-a"], 0),
    (
        "xargs",
        &["-I", "-n", "-P", "-d", "-E", "-L", "-s", "-a"],
        0,
    ),
    ("parallel", &["-j"], 0),
    ("watch", &["-n"], 0),
    ("chroot", &[], 1),
    ("flock", &["-w", "-E"], 1),
    ("caffeinate", &[], 0),
    ("unbuffer", &[], 0),
    ("strace", &["-o", "-e", "-p"], 0),
    ("npx", &[], 0),
    ("bunx", &[], 0),
    ("busybox", &[], 0),
];
/// Commands whose arguments are data: they run none of them.
const ONLY_DATA: &[&str] = &[
    "grep", "egrep", "fgrep", "cat", "head", "tail", "wc", "cut", "tr", "ls", "echo", "rg",
    "printf", "test", "[", "[[", "export", "declare", "typeset", "local", "readonly", "true",
    "false", ":", "cd", "pushd", "mkdir", "touch", "rm", "basename", "dirname", "which", "type",
    "man", "less", "more", "file", "stat", "diff", "sort", "uniq", "sed", "awk", "jq", "tee", "cp",
    "mv", "ln", "chmod", "chown", "git", "gh",
];

/// Programs that print text other than the text they were given.
const TRANSFORMERS: &[&str] = &[
    "printf", "tr", "sed", "gsed", "awk", "gawk", "mawk", "rev", "cut", "base64", "base32", "xxd",
    "od", "perl", "python", "ruby", "node", "paste", "fold", "iconv", "openssl", "gunzip", "zcat",
    "gzip", "bzip2", "xz", "uudecode", "dd", "envsubst", "m4", "jq", "hexdump", "tac", "php",
    "lua",
];
/// Programs that run the code they are handed in their own language.
const INTERPRETERS: &[&str] = &[
    "python",
    "py",
    "pypy",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "luajit",
    "awk",
    "gawk",
    "mawk",
    "osascript",
    "tclsh",
    "expect",
    "groovy",
    "julia",
    "rscript",
];
/// What code that starts a program holds, in one of those languages.
const RUN_MARKERS: &[&str] = &[
    "system",
    "exec",
    "popen",
    "spawn",
    "subprocess",
    "fork",
    "child_process",
    "`",
    "qx",
    "open(",
    "getline",
    "| \"",
    "|\"",
    "\" |",
    "\"|",
    "| '",
    "|'",
    "' |",
    "'|",
];

/// `python3.12` is `python`.
fn strip_version(base: &str) -> &str {
    base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')
}

/// A guard CLI name stands in `text` (lowercase) as a word of its own, in any
/// quoting: code in another language is not split the shell's way.
fn names_guard_raw(text: &str) -> bool {
    let bytes = text.as_bytes();
    let wordy = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    NAMES.iter().any(|name| {
        text.match_indices(name).any(|(at, _)| {
            let end = at + name.len();
            let left = at == 0 || !(wordy(bytes[at - 1]) || bytes[at - 1] == b'.');
            let right = match bytes.get(end) {
                None => true,
                Some(b'/') => false,
                Some(b'.') => {
                    !bytes
                        .get(end + 1)
                        .is_some_and(|b| b.is_ascii_alphanumeric())
                        || text[end..].starts_with(".exe")
                }
                Some(b) => !wordy(*b),
            };
            left && right
        })
    })
}

/// Code for an interpreter that names a guard CLI and starts a program.
fn code_runs_guard<'a>(texts: impl Iterator<Item = &'a str>) -> bool {
    let (mut named, mut runs) = (false, false);
    for text in texts {
        let low = text.to_ascii_lowercase();
        named |= names_guard_raw(&low);
        runs |= RUN_MARKERS.iter().any(|m| low.contains(m));
    }
    named && runs
}

fn is_interpreter(words: &[Word]) -> bool {
    let head = command_index(words);
    words.get(head.at).is_some_and(|cmd| {
        !cmd.dynamic() && INTERPRETERS.contains(&strip_version(&base_of(&cmd.lit)))
    })
}

fn base_of(lit: &str) -> String {
    let low = lit.to_ascii_lowercase();
    let base = low.rsplit('/').next().unwrap_or("");
    base.strip_suffix(".exe").unwrap_or(base).to_string()
}

/// The index after the class that opens at `p[at]` (`[a-z]`, `[!x]`,
/// `[[:alpha:]]`, `[]x]`).
fn class_end(p: &[char], at: usize) -> usize {
    let mut end = at + 1;
    if matches!(p.get(end), Some('!' | '^')) {
        end += 1;
    }
    if p.get(end) == Some(&']') {
        end += 1;
    }
    while end < p.len() && p[end] != ']' {
        if p[end] == '[' && matches!(p.get(end + 1), Some(':' | '.' | '=')) {
            let closer = p[end + 1];
            let mut k = end + 2;
            while k + 1 < p.len() && !(p[k] == closer && p[k + 1] == ']') {
                k += 1;
            }
            end = k + 2;
        } else {
            end += 1;
        }
    }
    (end + 1).min(p.len())
}

/// Whether `pattern` (a glob, a class read as any one char) can match `name`.
fn glob_can_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = name.chars().collect();
    let (mut pi, mut si) = (0, 0);
    let (mut star, mut mark) = (usize::MAX, 0);
    while si < s.len() {
        if pi < p.len() && p[pi] == '[' {
            // A class is read as any one char.
            pi = class_end(&p, pi);
            si += 1;
        } else if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = si;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// The guard CLI a command word names, if it does.
fn guard_name(word: &Word) -> Option<&'static str> {
    let base = base_of(&word.lit);
    if base.contains(EXPANSION) {
        return None;
    }
    if let Some(name) = NAMES.iter().find(|n| **n == base) {
        return Some(name);
    }
    if word.glob && base.contains(['*', '?', '[']) {
        return NAMES.iter().find(|n| glob_can_match(&base, n)).copied();
    }
    None
}

fn is_assignment(word: &Word) -> bool {
    let lit = &word.lit;
    let Some(eq) = lit.find('=') else {
        return false;
    };
    let name = lit[..eq].trim_end_matches('+');
    let name = name.split('[').next().unwrap_or("");
    !name.is_empty()
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn plain(word: &Word) -> bool {
    !word.quoted && !word.dynamic()
}

/// Where the command word is, and how the line got to it.
struct Head {
    /// The index of the command word: after assignments, keywords, launchers.
    at: usize,
    /// A launcher stands before it.
    launched: bool,
    /// `xargs` or `parallel` stands before it: its input adds arguments.
    fed: bool,
    /// The string that launcher puts a line of its input in place of, when
    /// an option names one (`-I@`).
    replace: Option<String>,
}

fn command_index(words: &[Word]) -> Head {
    let mut k = 0;
    let (mut launched, mut fed) = (false, false);
    let mut replace = None;
    while let Some(word) = words.get(k) {
        if is_assignment(word) && !word.lit.starts_with(EXPANSION) {
            k += 1;
            continue;
        }
        if plain(word) && KEYWORDS.contains(&word.lit.as_str()) {
            k += 1;
            continue;
        }
        if plain(word) && word.lit == "function" {
            k += 2;
            continue;
        }
        let base = base_of(&word.lit);
        let Some((_, valued, positional)) = LAUNCHERS
            .iter()
            .find(|(n, _, _)| *n == base && !word.dynamic())
        else {
            break;
        };
        if base == "command" && looks_up(&words[k + 1..]) {
            break;
        }
        k += 1;
        launched = true;
        fed |= base == "xargs" || base == "parallel";
        let mut skipped = 0;
        while let Some(next) = words.get(k) {
            let lit = next.lit.as_str();
            if lit.starts_with('-') && lit.len() > 1 && !next.dynamic() {
                k += 1;
                if base == "xargs" || base == "parallel" {
                    replace = replace_string(lit, words.get(k)).or(replace);
                }
                if valued.contains(&lit) {
                    k += 1;
                }
            } else if is_assignment(next) && base == "env" {
                k += 1;
            } else if skipped < *positional {
                skipped += 1;
                k += 1;
            } else {
                break;
            }
        }
    }
    Head {
        at: k,
        launched,
        fed,
        replace,
    }
}

/// The string an option of `xargs` or `parallel` names to be replaced with a
/// line of the input: `-I R`, `-IR`, `-iR`, `--replace=R`.
fn replace_string(option: &str, next: Option<&Word>) -> Option<String> {
    let named = if option == "-I" {
        next.map(|w| w.lit.as_str())?
    } else {
        option
            .strip_prefix("-I")
            .or_else(|| option.strip_prefix("-i"))
            .or_else(|| option.strip_prefix("--replace="))?
    };
    (!named.is_empty()).then(|| named.to_string())
}

/// The options after `command` hold `-v` or `-V`: it prints where each name
/// is found and runs none of them, so it is no launcher there.
fn looks_up(after: &[Word]) -> bool {
    after
        .iter()
        .take_while(|w| !w.dynamic() && w.lit.len() > 1 && w.lit.starts_with('-') && w.lit != "--")
        .any(|w| !w.lit.starts_with("--") && w.lit.contains(['v', 'V']))
}

fn lits(words: &[Word]) -> Vec<String> {
    words.iter().map(|w| w.lit.clone()).collect()
}

/// The words after a command word that is not spelled out, read as the
/// arguments of a guard CLI, lower it. A word among them that is not spelled
/// out may be empty when the line runs, or an operand, so they are read both
/// ways: without it, and with what is spelled of it.
fn spells_lowering(arguments: &[Word]) -> bool {
    let unspelled = |w: &Word| w.dynamic() || w.lit.contains(EXPANSION);
    let without: Vec<String> = arguments
        .iter()
        .filter(|w| !unspelled(w))
        .map(|w| w.lit.clone())
        .collect();
    let with: Vec<String> = arguments
        .iter()
        .map(|w| {
            let spelled: String = w.lit.chars().filter(|c| *c != EXPANSION).collect();
            if spelled.is_empty() {
                "x".to_string()
            } else {
                spelled
            }
        })
        .collect();
    [without, with]
        .iter()
        .any(|read| loosens("innerwarden", read) || loosens("innerwarden-ctl", read))
}

fn loosens(name: &str, arguments: &[String]) -> bool {
    if name == "innerwarden-ctl" {
        return ctl_verb_loosens(arguments);
    }
    let own = skip_leading_options(arguments);
    if own
        .first()
        .is_some_and(|verb| verb.eq_ignore_ascii_case("host"))
    {
        return ctl_verb_loosens(&own[1..]);
    }
    guard_verb_loosens(arguments)
}

/// The first argument is a literal verb that lowers nothing.
fn safe_first_verb(arguments: &[Word]) -> bool {
    arguments.first().is_some_and(|first| {
        !first.dynamic()
            && first.lit.starts_with(|c: char| c.is_ascii_lowercase())
            && first
                .lit
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !GUARD_VERB_HEADS.contains(&first.lit.as_str())
            // `host` hands the words after it to Active Defence's ctl.
            && first.lit != "host"
    })
}

fn literal(words: &[Word]) -> bool {
    words.iter().all(|w| !w.dynamic())
}

/// What a shell's own arguments say it runs.
struct ShellArgs<'a> {
    /// The string after `-c`.
    code: Option<&'a Word>,
    /// No `-c` and no script file: the script comes from its input.
    reads_input: bool,
    /// Words read to find that out.
    scanned: usize,
}

fn from_input(arg: &Word) -> bool {
    arg.substitution
        || arg.lit == "-"
        || arg.lit.starts_with("/dev/stdin")
        || arg.lit.starts_with("/dev/fd/")
        || arg.lit.starts_with("/proc/self/fd/")
}

/// Options run to the first operand or `--`; a cluster that ends in `o` or
/// `O` takes the next word (`-eo pipefail`, `-O extglob`); with `c` in any
/// cluster the first operand is the code.
fn shell_arguments(args: &[Word]) -> ShellArgs<'_> {
    let (mut has_c, mut has_s) = (false, false);
    let mut j = 0;
    while let Some(arg) = args.get(j) {
        let lit = arg.lit.as_str();
        if !arg.dynamic() && lit == "-" {
            // A lone `-` ends the options, as `--` does.
            j += 1;
            break;
        }
        if arg.dynamic() || lit.len() < 2 || !(lit.starts_with('-') || lit.starts_with('+')) {
            break;
        }
        j += 1;
        if lit == "--" {
            break;
        }
        if lit.starts_with("--") {
            if matches!(lit, "--rcfile" | "--init-file") {
                j += 1;
            }
            continue;
        }
        if lit.starts_with('-') {
            has_c |= lit.contains('c');
            has_s |= lit.contains('s');
        }
        if lit.ends_with(['o', 'O']) {
            j += 1;
        }
    }
    let operand = args.get(j);
    ShellArgs {
        code: operand.filter(|_| has_c),
        reads_input: !has_c && (has_s || operand.is_none_or(from_input)),
        scanned: j + 1,
    }
}

/// A shell (or `source`) that reads its script from its input.
fn stdin_shell(words: &[Word]) -> bool {
    let head = command_index(words);
    let Some(cmd) = words.get(head.at) else {
        return false;
    };
    if cmd.dynamic() {
        return false;
    }
    let base = base_of(&cmd.lit);
    let args = &words[head.at + 1..];
    if base == "source" || base == "." {
        return args.first().is_some_and(from_input);
    }
    if !SHELLS.contains(&base.as_str()) {
        return false;
    }
    if head.fed {
        return true;
    }
    shell_arguments(args).reads_input
}

/// The files the line creates, by base name.
#[derive(Default)]
struct Created {
    names: Vec<String>,
    /// One was made from a source the reading cannot name.
    dynamic: bool,
}

fn created_files(commands: &[Command]) -> Created {
    let mut created = Created::default();
    for command in commands {
        for target in &command.writes {
            created.names.push(base_of(&target.lit));
        }
        let head = command_index(&command.words);
        let Some(cmd) = command.words.get(head.at) else {
            continue;
        };
        let args: Vec<&Word> = command.words[head.at + 1..]
            .iter()
            .filter(|a| !a.lit.starts_with('-'))
            .collect();
        match base_of(&cmd.lit).as_str() {
            "cp" | "ln" | "mv" | "install" | "rsync" | "scp" => {
                if let Some((last, sources)) = args.split_last() {
                    created.names.push(base_of(&last.lit));
                    for source in sources {
                        // With one operand the copy keeps the source's name.
                        created.dynamic |= source.dynamic();
                    }
                    if sources.is_empty() {
                        created.dynamic |= last.dynamic();
                    }
                }
            }
            "tee" => created.names.extend(args.iter().map(|a| base_of(&a.lit))),
            "dd" => {
                for arg in &args {
                    if let Some(file) = arg.lit.strip_prefix("of=") {
                        created.names.push(base_of(file));
                    }
                }
            }
            _ => {}
        }
    }
    created
        .names
        .retain(|name| !name.is_empty() && !name.contains(EXPANSION));
    created
}

/// A command of the line runs a file the line created.
fn runs_created(commands: &[Command], created: &Created) -> bool {
    if created.names.is_empty() {
        return false;
    }
    let made = |word: &Word| created.names.contains(&base_of(&word.lit));
    commands.iter().any(|command| {
        let head = command_index(&command.words);
        let Some(cmd) = command.words.get(head.at) else {
            return false;
        };
        if made(cmd) {
            return true;
        }
        let base = base_of(&cmd.lit);
        (SHELLS.contains(&base.as_str()) || base == "source" || base == ".")
            && command.words[head.at + 1..].iter().any(made)
    })
}

/// `env -S` text with its own escapes read: `\_` and the blank escapes are a
/// space, any other escaped char is that char.
fn env_split(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('_' | 't' | 'n' | 'r' | 'f' | 'v') | None => out.push(' '),
            Some(other) => out.push(other),
        }
    }
    out
}

/// A word that is handed over as code, with the `sh` reading of a `$'...'`
/// in it: `$` and a plain string, so the program expands what follows.
fn push_code(found: &mut Vec<(String, bool, bool)>, code: &Word) {
    found.push((code.lit.clone(), code.expansion, true));
    if code.ansi_c {
        match &code.sh_alt {
            Some(alt) if code.ansi_len == code.lit.len() => {
                found.push((alt.clone(), code.expansion, true))
            }
            // More than this reading can follow: taken as code it cannot read.
            _ => found.push((String::new(), true, true)),
        }
    }
}

/// The body of an unquoted here-document as the program that reads it gets
/// it: the escapes of the line's shell taken off, each of its expansions one
/// [`EXPANSION`].
fn heredoc_script(body: &str) -> String {
    let b = body.as_bytes();
    let n = b.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i = 0;
    while i < n {
        let c = b[i];
        let next = b.get(i + 1).copied();
        match (c, next) {
            (b'\\', Some(b'\n')) => i += 2,
            (b'\\', Some(d @ (b'$' | b'`' | b'\\'))) => {
                out.push(d);
                i += 2;
            }
            (b'$', Some(open @ (b'{' | b'('))) => {
                let close = if open == b'{' { b'}' } else { b')' };
                let mut level = 0usize;
                let mut end = i + 1;
                while end < n {
                    if b[end] == open {
                        level += 1;
                    } else if b[end] == close {
                        level -= 1;
                        if level == 0 {
                            break;
                        }
                    }
                    end += 1;
                }
                out.push(1);
                i = (end + 1).min(n);
            }
            (b'$', Some(d)) if d.is_ascii_alphabetic() || d == b'_' => {
                let mut end = i + 1;
                while end < n && (b[end].is_ascii_alphanumeric() || b[end] == b'_') {
                    end += 1;
                }
                out.push(1);
                i = end;
            }
            (b'$', Some(b'@' | b'*' | b'#' | b'?' | b'-' | b'$' | b'!' | b'0'..=b'9')) => {
                out.push(1);
                i += 2;
            }
            (b'`', _) => {
                let mut end = i + 1;
                while end < n && b[end] != b'`' {
                    end += if b[end] == b'\\' { 2 } else { 1 };
                }
                out.push(1);
                i = (end + 1).min(n);
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The strings among `words` that a program will read as shell code:
/// (the code, whether the line's own expansions are part of it, whether an
/// expansion in it is in doubt by itself).
fn code_strings(words: &[Word], head: &Head) -> Vec<(String, bool, bool)> {
    let mut found = Vec::new();
    let join = |words: &[Word]| {
        words
            .iter()
            .map(|w| w.lit.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    };
    let outer = |words: &[Word]| words.iter().any(|w| w.expansion);
    let mut scanned = 0usize;
    for (i, word) in words.iter().enumerate() {
        if word.dynamic() {
            continue;
        }
        let base = base_of(&word.lit);
        let rest = &words[i + 1..];
        if scanned > words.len() * 4 + 256 {
            // Too many option runs to read: not decided.
            found.push((String::new(), true, true));
            break;
        }
        if SHELLS.contains(&base.as_str()) {
            let shell = shell_arguments(rest);
            scanned += shell.scanned;
            if let Some(code) = shell.code {
                push_code(&mut found, code);
            }
        } else if matches!(base.as_str(), "su" | "script" | "flock" | "runuser" | "sg") {
            // Their `-c` may stand after an operand (`flock FILE -c CODE`).
            scanned += rest.len();
            for (j, arg) in rest.iter().enumerate() {
                let lit = arg.lit.as_str();
                if arg.dynamic() || !lit.starts_with('-') {
                    continue;
                }
                if let Some(code) = lit
                    .strip_prefix("--command=")
                    .or_else(|| lit.strip_prefix("--session-command="))
                {
                    found.push((code.to_string(), arg.expansion, true));
                } else if matches!(lit, "--command" | "--session-command")
                    || (!lit.starts_with("--") && lit.contains('c'))
                {
                    if let Some(code) = rest.get(j + 1) {
                        push_code(&mut found, code);
                    }
                }
            }
            if base == "sg" {
                let own: Vec<Word> = rest
                    .iter()
                    .filter(|a| !a.lit.starts_with('-'))
                    .skip(1)
                    .cloned()
                    .collect();
                found.push((join(&own), outer(&own), true));
            }
        } else if base == "env" {
            // Its options, to the first word that is not one.
            let mut j = 0;
            while let Some(arg) = rest.get(j) {
                let lit = arg.lit.as_str();
                if arg.dynamic() || lit.len() < 2 || !lit.starts_with('-') || lit == "--" {
                    break;
                }
                j += 1;
                if let Some(code) = lit.strip_prefix("--split-string=") {
                    found.push((env_split(code), arg.expansion, true));
                } else if lit.starts_with("--") {
                    let takes_value = matches!(lit, "--split-string" | "--unset" | "--chdir");
                    if lit == "--split-string" {
                        if let Some(code) = rest.get(j) {
                            found.push((env_split(&code.lit), code.expansion, true));
                        }
                    }
                    j += usize::from(takes_value);
                } else if let Some(at) = lit.find(['S', 'u', 'C']) {
                    let value = &lit[at + 1..];
                    let split = lit.as_bytes()[at] == b'S';
                    if value.is_empty() {
                        if let Some(code) = rest.get(j).filter(|_| split) {
                            found.push((env_split(&code.lit), code.expansion, true));
                        }
                        j += 1;
                    } else if split {
                        found.push((env_split(value), arg.expansion, true));
                    }
                }
            }
            scanned += j + 1;
        } else if (base == "watch" || base == "parallel") && i < head.at {
            let own: Vec<Word> = rest
                .iter()
                .skip_while(|a| a.lit.starts_with('-'))
                .cloned()
                .collect();
            found.push((join(&own), false, false));
        }
    }
    let Some(cmd) = words.get(head.at) else {
        return found;
    };
    if cmd.dynamic() {
        return found;
    }
    let args = &words[head.at + 1..];
    match base_of(&cmd.lit).as_str() {
        "eval" => found.push((join(args), outer(args), true)),
        "trap" => {
            if let Some(code) = args
                .iter()
                .find(|a| !a.lit.starts_with('-') || a.lit == "-")
            {
                found.push((code.lit.clone(), code.expansion, true));
            }
        }
        "ssh" => {
            let own = ssh_command(args, &mut found);
            for arg in own {
                found.push((arg.lit.clone(), false, false));
            }
            found.push((join(own), false, false));
        }
        _ => {}
    }
    found
}

/// The keywords of `ssh -o` whose value is a command that ssh runs.
const SSH_COMMAND_KEYS: &[&str] = &[
    "proxycommand",
    "localcommand",
    "remotecommand",
    "knownhostscommand",
];

/// The command a `-o` value sets, when its keyword takes a command or is
/// not spelled out. ssh reads `Key=value`, `Key value` and `Key = value`,
/// the keyword in any case.
fn ssh_option_command(value: &str) -> Option<&str> {
    let value = value.trim_start();
    let end = value.find(|c: char| c == '=' || c.is_whitespace())?;
    let key = value[..end].to_ascii_lowercase();
    if !key.contains(EXPANSION) && !SSH_COMMAND_KEYS.contains(&key.as_str()) {
        return None;
    }
    let rest = value[end..].trim_start();
    Some(rest.strip_prefix('=').unwrap_or(rest).trim_start())
}

/// The options of `ssh` that take a value, as its option reading has them.
const SSH_VALUED: &str = "BbcDEeFIiJLlmOoPpQRSWw";

/// The words `ssh` hands the far shell as its command: what stands after the
/// options and the host. An option's value is not the host (`-p 2222 web1`),
/// and options may stand after the host as well. The value of a `-o` is
/// pushed as code when its keyword names a command that ssh runs.
fn ssh_command<'a>(args: &'a [Word], found: &mut Vec<(String, bool, bool)>) -> &'a [Word] {
    let mut options = true;
    let mut host = false;
    let mut j = 0;
    while let Some(arg) = args.get(j) {
        let lit = arg.lit.as_str();
        if options && lit == "--" {
            options = false;
            j += 1;
            continue;
        }
        if options && lit.len() > 1 && lit.starts_with('-') {
            j += 1;
            // Flags run to the first letter that takes a value: the value is
            // the rest of the word, or the next word when nothing is left.
            let letters = lit[1..].split(EXPANSION).next().unwrap_or("");
            let Some(at) = letters.find(|c| SSH_VALUED.contains(c)) else {
                continue;
            };
            let attached = &lit[1 + at + 1..];
            let value = if attached.is_empty() {
                j += 1;
                args.get(j - 1).map_or("", |w| w.lit.as_str())
            } else {
                attached
            };
            if letters.as_bytes()[at] == b'o' {
                if let Some(run) = ssh_option_command(value) {
                    found.push((run.to_string(), false, false));
                }
            }
            continue;
        }
        if !host {
            host = true;
            j += 1;
            continue;
        }
        return &args[j..];
    }
    &[]
}

/// A guard verb is a token of the command's words or of the text it is fed.
fn prints_verb(command: &Command) -> bool {
    command
        .words
        .iter()
        .chain(&command.herestrings)
        .map(|w| w.lit.as_str())
        .chain(command.heredocs.iter().map(|h| h.body.as_str()))
        .any(|text| guard_tokens(text.as_bytes(), &[]).1)
}

struct Judge {
    name: bool,
    verb: bool,
    functions: std::collections::HashSet<String>,
    /// Bytes still allowed to be read again as code.
    budget: usize,
    flat: bool,
    /// A guard CLI name stands in the raw text as a word of its own.
    raw: bool,
    /// Only that: no name or verb is a token of the shell's reading.
    raw_only: bool,
    /// A guard verb stands in the text of a substitution read so far: what
    /// it prints may be the whole lowering, name and all.
    built: bool,
    /// The guard's letters stand in the text, inside a longer word as well:
    /// the shell can cut that word down to the name.
    letters: bool,
}

type Deny = Option<String>;

fn deny(reason: &str) -> Deny {
    Some(reason.to_string())
}

impl Judge {
    fn relex(&mut self, code: &str, depth: usize) -> Deny {
        if code.trim().is_empty() {
            return None;
        }
        if depth >= MAX_DEPTH {
            return deny("deep");
        }
        if code.len() > self.budget {
            return deny("budget");
        }
        self.budget -= code.len();
        let lexed = Lexer::read_region(code.as_bytes(), false);
        self.context(&lexed, depth + 1)
    }

    fn context(&mut self, lexed: &Lexed, depth: usize) -> Deny {
        if let Some(what) = lexed.doubt.first() {
            return Some(format!("doubt:{what}"));
        }
        self.functions.extend(lexed.functions.iter().cloned());
        let commands = &lexed.commands;
        self.built |= commands.iter().any(|c| c.substituted && prints_verb(c));
        let created = created_files(commands);
        let run = runs_created(commands, &created);
        if run && self.verb && (self.name || created.dynamic) {
            return deny("write-then-run");
        }
        let feeds = run || commands.iter().any(|c| stdin_shell(&c.words));
        if self.raw {
            // Text piped into an interpreter is its code.
            for pair in commands.windows(2) {
                let fed = &pair[0];
                if fed.pipe_next
                    && is_interpreter(&pair[1].words)
                    && code_runs_guard(
                        fed.words
                            .iter()
                            .map(|w| w.lit.as_str())
                            .chain(fed.heredocs.iter().map(|h| h.body.as_str()))
                            .chain(fed.herestrings.iter().map(|w| w.lit.as_str())),
                    )
                {
                    return deny("interpreter-code");
                }
            }
        }
        for command in commands {
            if let Some(reason) = self.command(command, &command.words, feeds, depth) {
                return Some(reason);
            }
            if let Some(start) = command
                .alt_start
                .filter(|s| *s > 0 && *s < command.words.len())
            {
                if let Some(reason) = self.command(command, &command.words[start..], feeds, depth) {
                    return Some(reason);
                }
            }
        }
        None
    }

    fn command(&mut self, command: &Command, words: &[Word], feeds: bool, depth: usize) -> Deny {
        let head = command_index(words);
        let cmd = words.get(head.at);
        let args: &[Word] = if head.at < words.len() {
            &words[head.at + 1..]
        } else {
            &[]
        };
        if command.arithmetic {
            // Names and operators: only a spelled-out lowering counts.
            if let Some(name) = cmd.and_then(guard_name) {
                if literal(args) && loosens(name, &lits(args)) {
                    return deny("lowering");
                }
            }
            return None;
        }
        if self.raw
            && is_interpreter(words)
            && code_runs_guard(
                args.iter()
                    .map(|a| a.lit.as_str())
                    .chain(command.heredocs.iter().map(|h| h.body.as_str()))
                    .chain(command.herestrings.iter().map(|w| w.lit.as_str())),
            )
        {
            return deny("interpreter-code");
        }
        // The guard's name is nowhere on the line, only a word that is also
        // one of its verbs. An expansion that held the name could hold the
        // verb as well, and that line is not refused (see the module's
        // limits), so here an expansion is in doubt only where the words
        // spelled out after a command word lower the guard. A verb in the
        // text of a substitution is another matter: the command that prints
        // it is on the line, and it may print the name beside it. So is a
        // longer word that holds the guard's letters (`innerwarden/`): an
        // expansion cuts it down to the name (`${X%/}`).
        let nameless = !self.name && !self.raw && !self.built && !self.letters;
        let mut runs_input = feeds;
        'direct: {
            if self.raw_only {
                break 'direct;
            }
            if cmd.is_none() && head.fed {
                return deny("fed-command");
            }
            // `NAME="iw dry-run" program`: a value many programs run as a command.
            if cmd.is_some() && self.name && self.verb {
                for word in &words[..head.at.min(words.len())] {
                    if !is_assignment(word) {
                        continue;
                    }
                    let value = word.lit.split_once('=').map_or("", |(_, v)| v);
                    if value.contains(' ') {
                        if let Some(reason) = self.relex(value, depth) {
                            return Some(format!("assignment:{reason}"));
                        }
                    }
                }
            }
            // The shell's own tables of aliases and remembered paths.
            if words
                .iter()
                .any(|w| w.lit.starts_with("BASH_ALIASES") || w.lit.starts_with("BASH_CMDS"))
            {
                return deny("alias");
            }
            if let Some(cmd) = cmd {
                let base = base_of(&cmd.lit);
                if let Some(name) = guard_name(cmd) {
                    if literal(args) && !head.fed {
                        if (self.flat || depth > 0) && loosens(name, &lits(args)) {
                            return deny("lowering");
                        }
                    } else if !safe_first_verb(args) {
                        return deny("guard-dynamic-arguments");
                    }
                } else if !cmd.lit.starts_with('-') {
                    if cmd.extglob {
                        // `@(a|b)`: what it names is not read.
                        return deny("extglob-command");
                    }
                    if cmd.tilde && !cmd.lit.contains('/') {
                        // `~`, `~-`, `~+`, `~user`: a directory variable, run.
                        return deny("tilde-command");
                    }
                    if cmd.glob && cmd.lit.contains('{') {
                        return deny("brace-command");
                    }
                    if head.fed
                        && (cmd.lit.contains("{}")
                            || head
                                .replace
                                .as_deref()
                                .is_some_and(|named| cmd.lit.contains(named)))
                    {
                        return deny("dynamic-command");
                    }
                    if base.contains(EXPANSION) && (!nameless || spells_lowering(args)) {
                        return deny("dynamic-command");
                    }
                    if cmd.expansion && self.name {
                        return deny("dynamic-directory");
                    }
                }
                if guard_name(cmd).is_none() && !ONLY_DATA.contains(&base.as_str()) {
                    // dynamic_from[j]: a word of args[j..] is not spelled out.
                    let mut dynamic_from = vec![false; args.len() + 1];
                    for j in (0..args.len()).rev() {
                        dynamic_from[j] = dynamic_from[j + 1] || args[j].dynamic();
                    }
                    let mut only_flags = true;
                    let mut fed = head.fed;
                    // Words the argument readings may still look at: linear in the line.
                    let mut scan = args.len() * 4 + 256;
                    for (j, arg) in args.iter().enumerate() {
                        let rest = &args[j + 1..];
                        let spelled = !dynamic_from[j + 1];
                        let arg_base = base_of(&arg.lit);
                        if let Some(name) = guard_name(arg) {
                            if spelled && !fed {
                                if scan < rest.len() {
                                    return deny("budget");
                                }
                                scan -= rest.len();
                                if loosens(name, &lits(rest)) {
                                    return deny("argument-lowering");
                                }
                            } else if !safe_first_verb(rest) {
                                if fed {
                                    return deny("argument-fed");
                                }
                                if only_flags || head.launched || self.verb {
                                    return deny("argument-dynamic");
                                }
                            }
                        } else if arg_base.contains(EXPANSION)
                            && spelled
                            && !rest.is_empty()
                            && !nameless
                        {
                            // It may be any program, a guard CLI too: what follows
                            // it is read as that CLI's arguments.
                            if scan < rest.len() {
                                return deny("budget");
                            }
                            scan -= rest.len();
                            let rest = lits(rest);
                            if loosens("innerwarden", &rest) || loosens("innerwarden-ctl", &rest) {
                                return deny("argument-dynamic-lowering");
                            }
                        }
                        only_flags &= arg.lit.starts_with('-');
                        fed |= !arg.dynamic() && (arg_base == "xargs" || arg_base == "parallel");
                    }
                }
                if base == "git" && !cmd.dynamic() {
                    // Configuration git runs as a command: `-c alias.z='!...'`,
                    // `-c core.pager=...`.
                    let mut after_c = false;
                    for arg in args {
                        let value = arg.lit.split_once('=').map_or("", |(_, v)| v);
                        let bang = arg.lit.starts_with('!') || value.starts_with('!');
                        if (after_c || bang) && guard_tokens(value.as_bytes(), b"!").0 {
                            return deny("git-config-code");
                        }
                        after_c = arg.lit == "-c";
                    }
                }
                if !cmd.dynamic() {
                    match base.as_str() {
                        "alias" => {
                            let named = args.iter().any(|a| a.lit.contains('='));
                            if (named && self.name) || (args.iter().any(Word::dynamic) && self.verb)
                            {
                                return deny("alias");
                            }
                        }
                        "hash" if self.name && args.iter().any(|a| a.lit == "-p") => {
                            return deny("hash-p")
                        }
                        "source" | "." if args.iter().any(|a| a.substitution) => {
                            return deny("source-substitution")
                        }
                        "ssh" => runs_input = true,
                        _ => {}
                    }
                    if self.functions.contains(&cmd.lit) {
                        runs_input = true;
                    }
                }
            }
        }
        for (code, outer, strict) in code_strings(words, &head) {
            // An empty code stands for one that could not be read.
            if outer && strict && (!nameless || code.is_empty()) {
                return deny("dynamic-code");
            }
            if let Some(reason) = self.relex(&code, depth) {
                return Some(reason);
            }
        }
        if feeds {
            // A shell on the line reads its script from its input: any string
            // here may be that script.
            let is_line = |text: &str| {
                text.contains([
                    ' ', '\t', '\n', ';', '|', '&', '$', '`', '(', '<', EXPANSION,
                ])
            };
            for word in words {
                if is_line(&word.lit) && !self.raw_only {
                    if let Some(reason) = self.relex(&word.lit, depth) {
                        return Some(reason);
                    }
                }
            }
            if args.len() > 1 && !self.raw_only {
                let joined = args
                    .iter()
                    .map(|w| w.lit.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                if let Some(reason) = self.relex(&joined, depth) {
                    return Some(reason);
                }
            }
            if let Some(cmd) = cmd.filter(|c| !c.dynamic()) {
                // Text a program rewrites before the shell reads it.
                let base = base_of(&cmd.lit);
                let escapes =
                    base == "echo" && args.iter().any(|a| a.lit == "-e" || a.lit.contains('\\'));
                if escapes || (base != "echo" && TRANSFORMERS.contains(&strip_version(&base))) {
                    return deny("transformed-feed");
                }
            }
        }
        for heredoc in &command.heredocs {
            if !heredoc.quoted {
                if depth >= MAX_DEPTH {
                    return deny("deep");
                }
                let inside = Lexer::read_region(heredoc.body.as_bytes(), true);
                if let Some(reason) = self.context(&inside, depth + 1) {
                    return Some(reason);
                }
            }
            if runs_input {
                let script = if heredoc.quoted {
                    heredoc.body.clone()
                } else {
                    heredoc_script(&heredoc.body)
                };
                if let Some(reason) = self.relex(&script, depth) {
                    return Some(reason);
                }
            }
        }
        if runs_input {
            for string in &command.herestrings {
                if let Some(reason) = self.relex(&string.lit, depth) {
                    return Some(reason);
                }
            }
        }
        None
    }
}

/// The bytes an `IFS=` on the line makes into word separators, and whether
/// one of them is not spelled out.
fn ifs_separators(text: &[u8]) -> (Vec<u8>, bool) {
    let mut extra = Vec::new();
    let mut dynamic = false;
    let mut from = 0;
    while let Some(at) = text[from..].windows(3).position(|w| w == b"IFS") {
        let mut i = from + at + 3;
        from = i;
        if text.get(i) == Some(&b'+') {
            i += 1;
        }
        if text.get(i) != Some(&b'=') {
            continue;
        }
        i += 1;
        while let Some(&b) = text.get(i) {
            match b {
                b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b')' => break,
                b'\'' | b'"' | b'\\' => {}
                b'$' if text.get(i + 1) == Some(&b'\'') => {}
                b'$' | b'`' => dynamic = true,
                other => extra.push(other),
            }
            i += 1;
        }
    }
    (extra, dynamic)
}

/// Why the line is refused, or `None`.
pub(super) fn judge(text: &[u8], flat: bool) -> Option<String> {
    let (extra, dynamic) = ifs_separators(text);
    let (mut name, mut verb) = guard_tokens(text, &[]);
    if !extra.is_empty() {
        let (n, v) = guard_tokens(text, &extra);
        name |= n;
        verb |= v;
    }
    if dynamic && !name {
        let low = String::from_utf8_lossy(text).to_ascii_lowercase();
        name = low.contains("innerwarden") || low.contains("iw");
    }
    let raw = names_guard_raw(&String::from_utf8_lossy(text).to_ascii_lowercase());
    if !name && !verb && !raw {
        return None;
    }
    // Text that shells read differently from one another, or that this
    // reader and the shell may: `)#` (a comment after a subshell, a word
    // after a substitution), bash's `&>` (sh and dash end the command at the
    // `&`) and `$'...'` (dash reads a dollar sign and a plain quote).
    if (name || verb) && text.windows(2).any(|w| w == b")#") {
        return Some("a `)#` next to a guard word".to_string());
    }
    if name && verb && text.windows(2).any(|w| w == b"&>" || w == b"$'") {
        return Some("bash-only syntax next to a guard name and verb".to_string());
    }
    let lexed = Lexer::read(text);
    let budget = text.len().saturating_mul(32).saturating_add(4096);
    let raw_only = !name && !verb;
    let mut judge = Judge {
        name,
        verb,
        functions: Default::default(),
        budget,
        flat,
        raw,
        raw_only,
        built: false,
        letters: guard_letters(text),
    };
    judge.context(&lexed, 0)
}
