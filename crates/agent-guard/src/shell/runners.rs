//! The programs that run what they are handed, from the table in
//! `data/programs.toml`, and how what they run is read as shell lines.
//!
//! The table says which names are shells, which run their input or their
//! arguments as code, which read a script on stdin, and which option takes
//! inline code or names a file to run. [`super::is_shell_name`],
//! [`super::is_execution_sink`] and [`super::is_stdin_code_executor`] read
//! it, so a program added there is known to every reading at once.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;

/// How what a program runs is read.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Language {
    Shell,
    Python,
    Node,
    Ruby,
    Perl,
    Php,
    Lua,
    Make,
    Awk,
    Crontab,
}

/// One row of the table.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Program {
    names: Vec<String>,
    pub(crate) language: Language,
    /// A shell: a `-c` line, a script file, or its standard input.
    #[serde(default)]
    pub(crate) shell: bool,
    /// Its input or its arguments become code.
    #[serde(default)]
    pub(crate) sink: bool,
    /// It runs what it reads on stdin as code when given no other.
    #[serde(default)]
    pub(crate) stdin_code: bool,
    /// What it reads on stdin is a script for a shell, run later.
    #[serde(default)]
    pub(crate) stdin_script: bool,
    /// Its arguments are a command the guard reads after it.
    #[serde(default)]
    pub(crate) launcher: bool,
    /// The command written right after its own options is the one that
    /// runs (`env`, `command`, `nice -n 5`, `timeout 9`): read through by
    /// [`launchers_read_through`].
    #[serde(default)]
    pub(crate) prefix: bool,
    /// The option that takes code on the command line.
    #[serde(default)]
    pub(crate) inline: Option<String>,
    /// The option that names a file it runs.
    #[serde(default)]
    pub(crate) file_option: Option<String>,
}

#[derive(Deserialize)]
struct Table {
    program: Vec<Program>,
}

/// The table, by name.
fn table() -> &'static HashMap<String, Program> {
    static TABLE: LazyLock<HashMap<String, Program>> = LazyLock::new(|| {
        let table: Table = toml::from_str(include_str!("../../data/programs.toml"))
            .expect("data/programs.toml is the guard's own table");
        let mut by_name = HashMap::new();
        for program in table.program {
            for name in &program.names {
                by_name.insert(name.clone(), program.clone());
            }
        }
        by_name
    });
    &TABLE
}

/// The row of a program, by its name without version (`python` for
/// `python3.12`).
pub(crate) fn program(name: &str) -> Option<&'static Program> {
    table().get(name)
}

/// Whether `name` (without version) is a shell or a language of the table
/// that reads code when it is given none: a shell, or a program with an
/// option for inline code that reads stdin as code (`python`, `node`,
/// `perl`). Started with nothing to run, it waits for input
/// (`crate::interactive`).
pub(crate) fn reads_code_when_given_none(name: &str) -> bool {
    program(name)
        .is_some_and(|row| !row.launcher && (row.shell || (row.stdin_code && row.inline.is_some())))
}

/// The line with the launchers of the table that run the command written
/// right after them (`prefix`: `env`, `command`, `builtin`, `exec`,
/// `nice -n 5`, `nohup`, `timeout 9`, `stdbuf -oL`, `sudo`) taken off each
/// command they stand in front of, and the blanks after an operator made
/// one: the command the shell runs, where every rule that reads a command
/// by its name in place sees it (`f | env crontab -` is `f | crontab -`).
/// The options of each launcher are read by
/// [`crate::threats::effective_command_index`]; a launcher word with a
/// quote, an escape or an expansion in it is left as written. `None` when
/// nothing changes.
pub(crate) fn launchers_read_through(line: &str) -> Option<String> {
    launchers_readings(line).into_iter().next()
}

/// The readings of [`launchers_read_through`], each judged: the line with
/// the launchers cut and the redirections written among them left in front
/// of the command (`f | env 2>"/dev/null" sh` is `f | 2>"/dev/null" sh`), then
/// the same with every redirection in front of a command moved after it
/// (`f | sh 2>"/dev/null"`), and the first without the redirections of
/// output. Each is judged and the strictest verdict stands, so moving a
/// redirection never lets through what another reading refuses. Empty when
/// nothing changes.
pub(crate) fn launchers_readings(line: &str) -> Vec<String> {
    // Redirections in front of a launcher (`2>/dev/null env sh`), the
    // launchers, then the redirections a cut launcher left in front
    // (`env 2>/dev/null sh` is `2>/dev/null sh`).
    let moved = leading_redirections_moved(line);
    let first = moved.as_deref().unwrap_or(line);
    let cut = launchers_cut(first, true).unwrap_or_else(|| first.to_owned());
    // The same without the redirections of output written among the
    // launchers (`f | env 2>/dev/null crontab -` is `f | crontab -`), as review
    // round 1 read it: a rule that reads a command's last words (a table
    // piped into `crontab -` under a here-document) sees them as without it.
    let dropped = (cut != first && first.contains('>'))
        .then(|| launchers_cut(first, false))
        .flatten();
    let read = leading_redirections_moved(&cut);
    let mut readings = Vec::new();
    // The reading with the redirections moved first: it is the one most
    // often refused, and a refusal ends the judging
    // (`crate::mcp`'s `with_launchers_read_through`).
    for reading in [read, dropped, Some(cut)].into_iter().flatten() {
        if reading != line && !readings.contains(&reading) {
            readings.push(reading);
        }
    }
    readings
}

/// [`launchers_read_through`] without the redirections moved; with `keep`
/// false, the redirections of output written among the launchers are left
/// out.
fn launchers_cut(line: &str, keep: bool) -> Option<String> {
    let base = line.as_ptr() as usize;
    let mut cuts: Vec<(usize, usize, String)> = Vec::new();
    for segment in crate::threats::shell_command_segments(line) {
        let segment = without_group_head(segment);
        let Some(offset) = (segment.as_ptr() as usize).checked_sub(base) else {
            continue;
        };
        if line.get(offset..offset + segment.len()) != Some(segment) {
            continue;
        }
        let tokens = crate::threats::shell_tokens(segment);
        let keywords = tokens
            .iter()
            .take_while(|word| opens_a_command(word))
            .count();
        if tokens.get(keywords).is_none() {
            continue;
        }
        // `env -S 'rm -rf /'` runs the words its string splits into.
        if let Some(command) = crate::threats::env_split_command(&tokens[keywords..]) {
            if let Some(from) = word_start(segment, keywords) {
                cuts.push((
                    offset + from,
                    offset + segment.len(),
                    quoted_words(&command),
                ));
            }
            continue;
        }
        // Only a segment that starts with a launcher of the table is read
        // again by its words as written.
        if !program(versionless(crate::threats::token_basename(
            &tokens[keywords],
        )))
        .is_some_and(|row| row.prefix)
        {
            continue;
        }
        if let Some((from, to, with)) = launcher_cut(segment, keep) {
            cuts.push((offset + from, offset + to, with));
        }
    }
    let mut read = line.to_owned();
    for (from, to, with) in cuts.into_iter().rev() {
        read.replace_range(from..to, &with);
    }
    // A command substitution is a line of its own: `f=$(env curl URL)`
    // runs `curl URL`.
    read = substitutions_read_through(&read);
    // The blanks after an operator: `|  \tcrontab -` is `| crontab -`.
    static BLANKS: LazyLock<Option<regex::Regex>> =
        LazyLock::new(|| regex::Regex::new(r"([|;&(])(?: [ \t]+|\t[ \t]*)").ok());
    if let Some(blanks) = BLANKS.as_ref() {
        if blanks.is_match(&read) {
            read = blanks.replace_all(&read, "$1 ").into_owned();
        }
    }
    (read != line).then_some(read)
}

/// The launchers in front of the command of one segment, cut: the range of
/// the segment from the first launcher to the command it runs, and what
/// stands there instead, the redirections written among the launchers as
/// they are written (`sudo 2>/dev/null -u root sh` is `2>/dev/null sh`,
/// `env 2>"/dev/null" sh` is `2>"/dev/null" sh`). The launchers and their
/// options are read by [`crate::threats::effective_command_index`] on the
/// words without the redirections. `None` when the segment starts no
/// launcher of the table, the launcher runs no command (`exec > r.sh`), or
/// a launcher word has a quote, an escape or an expansion in it.
fn launcher_cut(segment: &str, keep: bool) -> Option<(usize, usize, String)> {
    let written = written_words(segment);
    let keywords = written
        .iter()
        .take_while(|(from, to)| opens_a_command(&segment[*from..*to]))
        .count();
    // The words read, without the redirections after the first, each with
    // its place among the words as written. A word reads as the shell gives
    // it when it is one word to [`crate::threats::shell_tokens`].
    let mut words: Vec<String> = Vec::new();
    let mut places: Vec<usize> = Vec::new();
    let mut index = 0;
    while let Some((from, to)) = written.get(index) {
        let text = &segment[*from..*to];
        if index > keywords {
            if let Some(alone) = redirection_shape(text) {
                index += if alone { 2 } else { 1 };
                continue;
            }
        }
        let mut read = crate::threats::shell_tokens(text);
        words.push(if read.len() == 1 {
            read.remove(0)
        } else {
            text.to_owned()
        });
        places.push(index);
        index += 1;
    }
    let first = words.get(keywords)?;
    if !program(versionless(crate::threats::token_basename(first))).is_some_and(|row| row.prefix) {
        return None;
    }
    // A launcher followed only by redirections runs no command: `exec >
    // r.sh` moves the output of the commands after it, and the same words
    // without `exec` (`> r.sh`) only empty the file. Measured 2026-11-22:
    // `exec > r.sh; echo hi > log; exec > /dev/tty; sh r.sh` was held for
    // review through that reading.
    let command =
        crate::threats::effective_command_index(&words[keywords..]).map(|at| at + keywords)?;
    if command <= keywords {
        return None;
    }
    let (from_word, to_word) = (places[keywords], *places.get(command)?);
    let mut kept: Vec<&str> = Vec::new();
    let mut at = from_word;
    while at < to_word {
        let (from, to) = written[at];
        let text = &segment[from..to];
        match redirection_shape(text) {
            Some(alone) if at > keywords => {
                let end = if alone {
                    written.get(at + 1).map_or(to, |next| next.1)
                } else {
                    to
                };
                if keep || !is_output_redirection(text) {
                    kept.push(&segment[from..end]);
                }
                at += if alone { 2 } else { 1 };
            }
            _ => {
                if text.contains(['\'', '"', '\\', '$', '`']) {
                    return None;
                }
                at += 1;
            }
        }
    }
    let mut with = kept.join(" ");
    if !with.is_empty() {
        with.push(' ');
    }
    Some((written[from_word].0, written[to_word].0, with))
}

/// Whether a word as written is a redirection, and whether it stands apart
/// from its target: `Some(false)` for `2>/dev/null`, `>"x"`, `2>&1`, `2>&-`,
/// `{fd}>/tmp/f`, `<<<x`, `<<EOF`; `Some(true)` for `2>`, `>`, `<<`, `<<-`,
/// `&>`, whose target is the next word. A process substitution (`<(f)`) is
/// a word, not a redirection.
fn redirection_shape(word: &str) -> Option<bool> {
    let rest = match word.strip_prefix('{') {
        Some(inside) => {
            let (name, after) = inside.split_once('}')?;
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            after
        }
        None => word.trim_start_matches(|c: char| c.is_ascii_digit()),
    };
    let rest = rest.strip_prefix('&').unwrap_or(rest);
    if !rest.starts_with(['>', '<']) || rest.starts_with("<(") || rest.starts_with(">(") {
        return None;
    }
    Some(rest == "<<-" || rest.chars().all(|c| matches!(c, '>' | '<' | '|' | '&')))
}

/// Whether a redirection word as written sends output (`2>`, `>|`, `&>`,
/// `{fd}>`), not input.
fn is_output_redirection(word: &str) -> bool {
    let rest = match word.strip_prefix('{') {
        Some(inside) => inside.split_once('}').map_or(inside, |(_, after)| after),
        None => word.trim_start_matches(|c: char| c.is_ascii_digit()),
    };
    rest.strip_prefix('&').unwrap_or(rest).starts_with('>')
}

/// Whether a word as written gives a variable a value for the command after
/// it (`FOO=1`, `PATH+=:/x`, `HOME="/tmp/h"`).
fn is_written_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let name = name.strip_suffix('+').unwrap_or(name);
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The words of one command as written, as byte ranges of `segment`: split
/// at blanks outside quotes, escapes, `$(...)`, `${...}` and backticks, up to
/// the end of its first line, a `)` that closes a group, or a comment.
fn written_words(segment: &str) -> Vec<(usize, usize)> {
    let bytes = segment.as_bytes();
    let mut words = Vec::new();
    let mut at = 0;
    loop {
        while at < bytes.len() && matches!(bytes[at], b' ' | b'\t') {
            at += 1;
        }
        if at >= bytes.len() || matches!(bytes[at], b'\n' | b')' | b'#') {
            break;
        }
        let start = at;
        let mut open = 0usize;
        let mut single = false;
        let mut double = false;
        let mut backtick = false;
        while at < bytes.len() {
            let byte = bytes[at];
            if single {
                single = byte != b'\'';
                at += 1;
                continue;
            }
            match byte {
                b'\\' => {
                    at += 2;
                    continue;
                }
                b'\'' if !double && !backtick => single = true,
                b'"' => double = !double,
                b'`' => backtick = !backtick,
                b'$' if matches!(bytes.get(at + 1), Some(b'(' | b'{')) => {
                    open += 1;
                    at += 2;
                    continue;
                }
                b'(' if open > 0 => open += 1,
                b')' | b'}' if open > 0 => open -= 1,
                b' ' | b'\t' | b'\n' | b')' if !double && !backtick && open == 0 => break,
                _ => {}
            }
            at += 1;
        }
        at = at.min(bytes.len());
        words.push((start, at));
    }
    words
}

/// Whether a word in front of a command only opens it: a keyword, so the
/// command the launchers run starts after it.
fn opens_a_command(word: &str) -> bool {
    matches!(
        word,
        "if" | "then" | "elif" | "else" | "do" | "while" | "until" | "!"
    )
}

/// The segment of a line without the head of a group or a function that
/// opens it (`{ `, `( `, `x() { `, `function x { `): [`crate::threats::shell_tokens`]
/// drops those words, so the words it gives and the words as written line
/// up only after them.
fn without_group_head(segment: &str) -> &str {
    static HEAD: LazyLock<Option<regex::Regex>> = LazyLock::new(|| {
        regex::Regex::new(
            r"^[ \t]*(?:(?:function[ \t]+)?[A-Za-z_][A-Za-z0-9_.:-]*[ \t]*\([ \t]*\)[ \t]*|function[ \t]+[A-Za-z_][A-Za-z0-9_.:-]*[ \t]+)?(?:[{(][ \t]+)*",
        )
        .ok()
    });
    let head = HEAD
        .as_ref()
        .and_then(|head| head.find(segment))
        .map_or(0, |found| found.end());
    &segment[head..]
}

/// The line with the redirections written in front of the name of each
/// command moved after it: `2>/dev/null rm -rf X` runs `rm -rf X` as
/// `rm -rf X 2>/dev/null` does, so every rule that reads a command by its
/// first word sees it. Measured 2026-11-22: `2>/dev/null rm -rf
/// ~/.innerwarden` and `f | 2>/dev/null tee -a ~/.bashrc` were allowed, the
/// same lines without the redirection refused; after review round 1 also
/// `FOO=1 2>/dev/null rm`, `time 2>/dev/null rm`, `{fd}>/tmp/f rm`, `<<<x rm`,
/// `<<EOF rm` and `2>"/dev/null" rm`. The redirections are moved as written,
/// quotes, escapes and expansions in them too; the values given in front
/// (`FOO=1`) stay in front. `None` when nothing changes.
pub(crate) fn leading_redirections_moved(line: &str) -> Option<String> {
    if !line.contains(['>', '<']) {
        return None;
    }
    let base = line.as_ptr() as usize;
    let mut cuts: Vec<(usize, usize, String)> = Vec::new();
    for segment in crate::threats::shell_command_segments(line) {
        let segment = without_group_head(segment);
        let Some(offset) = (segment.as_ptr() as usize).checked_sub(base) else {
            continue;
        };
        if line.get(offset..offset + segment.len()) != Some(segment) {
            continue;
        }
        if let Some((from, to, with)) = redirections_moved_in(segment) {
            cuts.push((offset + from, offset + to, with));
        }
    }
    if cuts.is_empty() {
        return None;
    }
    let mut read = line.to_owned();
    for (from, to, with) in cuts.into_iter().rev() {
        read.replace_range(from..to, &with);
    }
    (read != line).then_some(read)
}

/// [`leading_redirections_moved`] in one segment: the range from the first
/// word after the keywords (and `time`) to the end of the command's words
/// on its first line, and the same words with the redirections among the
/// values in front moved after them.
fn redirections_moved_in(segment: &str) -> Option<(usize, usize, String)> {
    let written = written_words(segment);
    let text = |index: usize| written.get(index).map(|(from, to)| &segment[*from..*to]);
    let mut index = 0;
    while let Some(word) = text(index) {
        if opens_a_command(word) {
            index += 1;
        } else if word == "time" {
            index += 1;
            if text(index) == Some("-p") {
                index += 1;
            }
        } else {
            break;
        }
    }
    let start = index;
    let mut kept: Vec<&str> = Vec::new();
    let mut moved: Vec<&str> = Vec::new();
    while let Some(word) = text(index) {
        if let Some(alone) = redirection_shape(word) {
            let (from, mut to) = written[index];
            if alone {
                to = written.get(index + 1)?.1;
                index += 1;
            }
            moved.push(&segment[from..to]);
            index += 1;
        } else if is_written_assignment(word) {
            kept.push(word);
            index += 1;
        } else {
            break;
        }
    }
    if moved.is_empty() {
        return None;
    }
    let (command, _) = *written.get(index)?;
    let (_, end) = *written.last()?;
    let mut with = String::new();
    for value in kept {
        with.push_str(value);
        with.push(' ');
    }
    with.push_str(&segment[command..end]);
    with.push(' ');
    with.push_str(&moved.join(" "));
    Some((written[start].0, end, with))
}

/// Where word `index` of `segment` starts, the words split at blanks as
/// written. `None` when a word before it holds a quote or an escape, so
/// the blanks do not tell where the words are.
fn word_start(segment: &str, index: usize) -> Option<usize> {
    let bytes = segment.as_bytes();
    let mut at = 0;
    for _ in 0..index {
        while at < bytes.len() && matches!(bytes[at], b' ' | b'\t') {
            at += 1;
        }
        let start = at;
        while at < bytes.len() && !matches!(bytes[at], b' ' | b'\t' | b'\n') {
            at += 1;
        }
        if segment[start..at].contains(['\'', '"', '\\']) {
            return None;
        }
    }
    while at < bytes.len() && matches!(bytes[at], b' ' | b'\t') {
        at += 1;
    }
    (at < bytes.len()).then_some(at)
}

/// `words` written back as one shell line: a word with a blank or a quote
/// in it single-quoted, the rest as they are, so an operator word (`<`)
/// stays one.
fn quoted_words(words: &[String]) -> String {
    words
        .iter()
        .map(|word| {
            if word.is_empty() || word.contains([' ', '\t', '\n', '\'', '"']) {
                format!("'{}'", word.replace('\'', "'\\''"))
            } else {
                word.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `line` with the body of each `$(...)` it holds read through by
/// [`launchers_read_through`]. A body whose closing parenthesis is not
/// found, or that holds a quote, is left as written.
fn substitutions_read_through(line: &str) -> String {
    let mut read = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(open) = rest.find("$(") {
        let body_start = open + 2;
        let mut depth = 1usize;
        let mut close = None;
        for (index, byte) in rest.bytes().enumerate().skip(body_start) {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(index);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            break;
        };
        let body = &rest[body_start..close];
        read.push_str(&rest[..body_start]);
        match launchers_read_through(body) {
            Some(through) if !body.contains(['\'', '"']) => read.push_str(&through),
            _ => read.push_str(body),
        }
        rest = &rest[close..];
    }
    read.push_str(rest);
    read
}

/// Every name of the table with its row, for the tests that hold the
/// readings to it.
#[cfg(test)]
pub(crate) fn every_program() -> impl Iterator<Item = (&'static str, &'static Program)> {
    table()
        .iter()
        .map(|(name, program)| (name.as_str(), program))
}

/// What a program reads on stdin as a script, given its words after its
/// name (unquoted): `at` and `batch` without `-f`, `make -f -`, an `awk`
/// program that calls `system()` or prints to a shell, and `parallel` with
/// no command of its own. Shells are read by their own rules.
pub(crate) fn stdin_script(name: &str, args: &[String]) -> Option<Language> {
    let program = program(name)?;
    if program.shell {
        return None;
    }
    if program.stdin_script {
        let file = program.file_option.as_deref();
        return (!args
            .iter()
            .any(|arg| Some(arg.as_str()) == file || arg.starts_with("-f")))
        .then_some(program.language);
    }
    match program.language {
        Language::Make => make_files(args)
            .iter()
            .any(|file| file == "-" || file == "/dev/stdin")
            .then_some(Language::Make),
        Language::Awk => awk_program(args)
            .is_some_and(|code| awk_runs_its_input(&code))
            .then_some(Language::Shell),
        Language::Shell if name == "parallel" => {
            parallel_reads_commands(args).then_some(Language::Shell)
        }
        Language::Crontab => (args.iter().any(|arg| arg == "-")).then_some(Language::Crontab),
        _ => None,
    }
}

/// The files a program runs, each with how it is read: a shell's or an
/// interpreter's script operand, `source` and `.`, the makefile of
/// `make` (`Makefile` when none is named), the file after `at -f`, a
/// crontab file.
pub(crate) fn file_scripts(name: &str, args: &[String]) -> Vec<(String, Language)> {
    let Some(program) = program(name) else {
        return Vec::new();
    };
    let language = program.language;
    match language {
        Language::Make => {
            let named: Vec<String> = make_files(args)
                .into_iter()
                .filter(|file| file != "-" && file != "/dev/stdin")
                .collect();
            if named.is_empty()
                && !args.iter().any(|arg| {
                    arg.starts_with("-f")
                        || arg.starts_with("--file")
                        || arg.starts_with("--makefile")
                })
            {
                ["GNUmakefile", "makefile", "Makefile"]
                    .iter()
                    .map(|file| ((*file).to_owned(), Language::Make))
                    .collect()
            } else {
                named
                    .into_iter()
                    .map(|file| (file, Language::Make))
                    .collect()
            }
        }
        Language::Crontab => crontab_file(args)
            .map(|file| vec![(file, Language::Crontab)])
            .unwrap_or_default(),
        Language::Awk => Vec::new(),
        _ if program.stdin_script => {
            let file = program.file_option.as_deref().unwrap_or("-f");
            args.iter()
                .position(|arg| arg == file)
                .and_then(|at| args.get(at + 1))
                .map(|path| vec![(path.clone(), Language::Shell)])
                .unwrap_or_default()
        }
        _ if program.launcher
            || (program.sink && program.inline.is_none() && !matches!(name, "source" | ".")) =>
        {
            Vec::new()
        }
        _ if matches!(name, "source" | ".") => args
            .first()
            .map(|path| vec![(path.clone(), Language::Shell)])
            .unwrap_or_default(),
        _ => script_operand(args, program)
            .map(|path| vec![(path, language)])
            .unwrap_or_default(),
    }
}

/// The script operand of a shell or an interpreter: the first operand when
/// no option gave it code inline, a module (`-m`) or stdin (`-s`).
fn script_operand(args: &[String], program: &Program) -> Option<String> {
    let inline = program.inline.as_deref().unwrap_or("-c");
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        if arg == "--" {
            return args
                .get(at + 1)
                .filter(|path| !is_stdin_path(path))
                .cloned();
        }
        if arg == inline || arg == "-m" || arg == "--eval" || arg == "--command" {
            return None;
        }
        if let Some(flags) = arg
            .strip_prefix('-')
            .filter(|flags| !flags.starts_with('-'))
        {
            let letter = inline.trim_start_matches('-');
            if program.shell && (flags.contains(letter) || flags.contains('s')) {
                return None;
            }
            if !program.shell && cluster_takes_code(flags, letter, program.language) {
                return None;
            }
        }
        if matches!(
            arg.as_str(),
            "-o" | "+o"
                | "-O"
                | "+O"
                | "--rcfile"
                | "--init-file"
                | "-W"
                | "-X"
                | "-r"
                | "--require"
                | "-I"
        ) && !(arg == "-r" && program.language == Language::Php)
        {
            at += 2;
            continue;
        }
        if arg.starts_with('-') || arg.starts_with('+') {
            at += 1;
            continue;
        }
        return (!is_stdin_path(arg)).then(|| arg.clone());
    }
    None
}

/// Whether a group of short flags of an interpreter (`-uc`, `-ne`, `-pe`,
/// `-le`) holds the flag that takes code inline (`letter`), or Python's
/// `-m`, wherever it stands in the group: read flag by flag up to the first
/// one that takes the rest of the group as its value (`-W`, `-X`, `-I`,
/// `-M`), so the `c` of `-Wignore::DeprecationWarning` is not read as `-c`.
/// Measured 2026-11-20: `python3 -uc CODE` read `CODE` as the script's
/// path, because only a group that starts with the letter was read.
pub(crate) fn cluster_takes_code(flags: &str, letter: &str, language: Language) -> bool {
    let Some(letter) = letter.chars().next() else {
        return false;
    };
    let (values, more_code): (&str, &str) = match language {
        Language::Python => ("WXQ", "m"),
        Language::Perl => ("IMmxiCdD", "E"),
        Language::Ruby => ("IrCEFxKTW", ""),
        Language::Node => ("r", ""),
        Language::Php => ("cdz", ""),
        Language::Lua => ("l", ""),
        _ => ("", ""),
    };
    let mut chars = flags.chars().peekable();
    while let Some(flag) = chars.next() {
        if flag == letter || more_code.contains(flag) {
            return true;
        }
        if values.contains(flag) {
            return false;
        }
        // Perl's `-l` takes octal digits, `-0` octal or `x` and hex ones.
        if language == Language::Perl && matches!(flag, 'l' | '0') {
            if flag == '0' && chars.next_if_eq(&'x').is_some() {
                while chars.next_if(char::is_ascii_hexdigit).is_some() {}
            }
            while chars.next_if(|digit| ('0'..='7').contains(digit)).is_some() {}
        }
    }
    false
}

/// The file `crontab` installs: its first operand past its options, with
/// the value of `-u USER` and `-T` taken off (`crontab -u alice f`
/// installs `f`, not `alice`).
fn crontab_file(args: &[String]) -> Option<String> {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.as_str() {
            "-u" | "-T" => at += 2,
            "--" => return args.get(at + 1).cloned(),
            _ if arg.starts_with('-') => at += 1,
            _ => return Some(arg.clone()),
        }
    }
    None
}

fn is_stdin_path(path: &str) -> bool {
    matches!(path, "-" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0")
}

/// The makefiles `make` is told to read: `-f FILE`, `-fFILE`,
/// `--file=FILE`, `--makefile=FILE`.
fn make_files(args: &[String]) -> Vec<String> {
    let mut files = Vec::new();
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        if matches!(arg.as_str(), "-f" | "--file" | "--makefile") {
            if let Some(file) = args.get(at + 1) {
                files.push(file.clone());
            }
            at += 2;
            continue;
        }
        if let Some(file) = ["--file=", "--makefile="]
            .iter()
            .find_map(|prefix| arg.strip_prefix(prefix))
            .or_else(|| arg.strip_prefix("-f").filter(|rest| !rest.is_empty()))
        {
            files.push(file.to_owned());
        }
        at += 1;
    }
    files
}

/// The program text of an `awk` command: the first operand after its
/// options, none when it reads its program from a file (`-f`).
fn awk_program(args: &[String]) -> Option<String> {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.as_str() {
            "-f" | "--file" => return None,
            "-F" | "-v" | "--assign" | "--field-separator" => at += 2,
            "--" => return args.get(at + 1).cloned(),
            _ if arg.starts_with('-') && arg.len() > 1 => at += 1,
            _ => return Some(arg.clone()),
        }
    }
    None
}

/// Whether an awk program hands what it reads to a shell: `system(` or a
/// print into a pipe (`print | "sh"`).
fn awk_runs_its_input(code: &str) -> bool {
    code.contains("system(")
        || code.contains("system (")
        || code.contains("| \"")
        || code.contains("|\"")
}

/// Whether `parallel` takes each line of its input as a command: no
/// command among its words (options only), and no `:::` list.
fn parallel_reads_commands(args: &[String]) -> bool {
    const VALUED: &[&str] = &[
        "-j",
        "--jobs",
        "-S",
        "--sshlogin",
        "--joblog",
        "--results",
        "--delay",
        "--timeout",
        "-d",
        "--delimiter",
        "-I",
        "--tmpdir",
        "--load",
        "--memfree",
    ];
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        if arg.starts_with(":::") {
            return false;
        }
        if VALUED.contains(&arg.as_str()) {
            at += 2;
            continue;
        }
        if arg.starts_with('-') {
            at += 1;
            continue;
        }
        return false;
    }
    true
}

/// The language and program a script's first line asks for (`#!/bin/sh`,
/// `#!/usr/bin/env python3`), when the table knows it.
pub(crate) fn shebang(text: &str) -> Option<(Language, String)> {
    let first = text.lines().next()?.strip_prefix("#!")?;
    let mut words = first.split_whitespace();
    let mut program = words.next()?.rsplit('/').next()?.to_owned();
    if program == "env" {
        program = words.find(|word| !word.starts_with('-'))?.to_owned();
    }
    let name = versionless(&program);
    let row = super::runners::program(name)?;
    Some((row.language, program))
}

/// A program's name without the version a binary carries (`python3.12`).
pub(crate) fn versionless(name: &str) -> &str {
    if name == "." {
        name
    } else {
        name.trim_end_matches(|character: char| character.is_ascii_digit() || character == '.')
    }
}

/// What runs in a shell when a program reads `text` as `language`, as lines
/// the guard reads: a shell script is itself; a makefile's recipe lines; a
/// crontab's commands; code in another language is the line that would run
/// it from a quoted here-document (`python3 - <<'IW_CODE'`), so the reader of
/// that language judges it as it judges such a line typed out. PHP keeps
/// `php -r '...'`, which reads code without its tags.
///
/// Written as `python3 -c '...'` before 2026-11-21, every `'` of the code
/// became `'\''`, and the reading of the guard's own words took the pieces
/// between those quotes for words beside a part it could not read: a Python
/// test file a line wrote and ran was refused where the same code typed in a
/// here-document was allowed (benchmark of 2026-11-21).
pub(crate) fn shell_lines(language: Language, text: &str, program: &str) -> Vec<String> {
    match language {
        Language::Shell | Language::Awk => vec![text.to_owned()],
        Language::Make => {
            let recipes: Vec<String> = text
                .lines()
                .filter_map(|line| line.strip_prefix('\t'))
                .map(|line| line.trim_start_matches(['@', '-', '+']).to_owned())
                .filter(|line| !line.trim().is_empty())
                .collect();
            if recipes.is_empty() {
                Vec::new()
            } else {
                vec![recipes.join("\n")]
            }
        }
        Language::Crontab => {
            let commands: Vec<String> = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .filter(|line| {
                    // `NAME=value`: a setting of the table, not an entry.
                    !line
                        .split_whitespace()
                        .next()
                        .is_some_and(|first| first.contains('=') && !first.starts_with('@'))
                })
                .filter_map(|line| {
                    let fields = if line.starts_with('@') { 1 } else { 5 };
                    let mut rest = line;
                    for _ in 0..fields {
                        rest = rest.trim_start();
                        let end = rest.find(char::is_whitespace)?;
                        rest = &rest[end..];
                    }
                    Some(rest.trim().to_owned())
                })
                .filter(|command| !command.is_empty())
                .collect();
            if commands.is_empty() {
                Vec::new()
            } else {
                vec![commands.join("\n")]
            }
        }
        _ => {
            let row = program_for(language);
            let program = if program.is_empty() { row.0 } else { program };
            let mut code = text.to_owned();
            if language == Language::Php {
                code = code.replace("<?php", "").replace("?>", "");
            }
            // A first line that names the interpreter is not code.
            if code.starts_with("#!") {
                code = code
                    .split_once('\n')
                    .map(|(_, rest)| rest.to_owned())
                    .unwrap_or_default();
            }
            if language == Language::Php {
                return vec![format!("{program} {} {}", row.1, single_quoted(&code))];
            }
            // The lines of the code are read once: the delimiter grows past
            // every line that would end the here-document early.
            let taken: std::collections::HashSet<&str> = code
                .lines()
                .map(|line| line.trim_start_matches('\t'))
                .collect();
            let mut end = String::from("IW_CODE");
            while taken.contains(end.as_str()) {
                end.push('_');
            }
            vec![format!("{program} - <<'{end}'\n{code}\n{end}")]
        }
    }
}

/// The program and inline option a language's code is run with.
fn program_for(language: Language) -> (&'static str, &'static str) {
    match language {
        Language::Python => ("python3", "-c"),
        Language::Node => ("node", "-e"),
        Language::Ruby => ("ruby", "-e"),
        Language::Perl => ("perl", "-e"),
        Language::Php => ("php", "-r"),
        Language::Lua => ("lua", "-e"),
        _ => ("sh", "-c"),
    }
}

/// `text` as one single-quoted shell word.
fn single_quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// What inline code in `language` writes to `path`: `None` when it names no
/// such file in a string, `Some(None)` when it writes it with text it does
/// not spell out, and `Some(Some(text))` when it does (`open('x.sh','w')
/// .write('...')`, `writeFileSync('x.sh', '...')`, `File.write`,
/// `file_put_contents`, Perl's `open` and `print`).
pub(crate) fn code_written_text(
    language: Language,
    code: &str,
    path: &str,
) -> Option<Option<String>> {
    let bare = path.trim_start_matches("./");
    let named = [
        format!("'{bare}'"),
        format!("\"{bare}\""),
        format!("'./{bare}'"),
        format!("\"./{bare}\""),
    ]
    .iter()
    .any(|quoted| code.contains(quoted.as_str()));
    if !named {
        return None;
    }
    let p = format!(r"(?:\./)?{}", regex::escape(bare));
    // A string in single or double quotes, captured without its quotes.
    let s = r#"(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")"#;
    let q = |inner: &str| format!(r#"(?:'{inner}'|"{inner}")"#);
    let pattern = match language {
        Language::Python => format!(
            r"open\(\s*{}\s*,\s*{}\s*\)\s*(?:\.write\(\s*{s}\s*\)|as\s+\w+\s*:\s*\w+\.write\(\s*{s}\s*\))",
            q(&p),
            q(r"[wa]\+?b?")
        ),
        Language::Node => format!(
            r"(?:writeFileSync|appendFileSync|writeFile|appendFile)\(\s*{}\s*,\s*{s}",
            q(&p)
        ),
        Language::Ruby => format!(r"File\.(?:write|binwrite)\(\s*{}\s*,\s*{s}", q(&p)),
        Language::Php => format!(r"file_put_contents\(\s*{}\s*,\s*{s}", q(&p)),
        Language::Perl => format!(
            r"open\s*\(?\s*(?:my\s+)?\$?\w+\s*,\s*(?:{}\s*,\s*{}|{})\s*\)?\s*(?:or\s+die[^;]*)?;\s*print\s+\{{?\$?\w+\}}?\s+{s}",
            q(">>?"),
            q(&p),
            q(&format!(">>?\\s*{p}"))
        ),
        _ => return Some(None),
    };
    let Ok(regex) = regex::Regex::new(&pattern) else {
        return Some(None);
    };
    let Some(found) = regex.captures(code) else {
        return Some(None);
    };
    let (text, double) = match (found.get(1).or(found.get(3)), found.get(2).or(found.get(4))) {
        (Some(single), _) => (single.as_str(), false),
        (None, Some(double)) => (double.as_str(), true),
        _ => return Some(None),
    };
    // A double-quoted string may expand in Perl, PHP and Ruby (`$x`, `#{}`),
    // and a template literal in Node: what it writes is not spelled out.
    if double
        && matches!(language, Language::Perl | Language::Php | Language::Ruby)
        && text.contains(['$', '#', '@'])
    {
        return Some(None);
    }
    if text.contains('\\') && !text.contains("\\n") && !text.contains("\\t") {
        return Some(None);
    }
    Some(Some(text.replace("\\n", "\n").replace("\\t", "\t")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    /// Every launcher row of the table is one the guard reads through: the
    /// command after it is judged. FAILS ON REVERT of a launcher's reading,
    /// or when a row is added that no reading follows.
    #[test]
    fn every_launcher_in_the_table_is_read_through() {
        let forms: &[(&str, &str)] = &[
            ("env", "env rm -rf ~/.ssh"),
            ("sudo", "sudo rm -rf ~/.ssh"),
            ("doas", "doas rm -rf ~/.ssh"),
            ("nice", "nice -n 5 rm -rf ~/.ssh"),
            ("nohup", "nohup rm -rf ~/.ssh"),
            ("timeout", "timeout 5 rm -rf ~/.ssh"),
            ("setsid", "setsid rm -rf ~/.ssh"),
            ("stdbuf", "stdbuf -oL rm -rf ~/.ssh"),
            ("busybox", "busybox rm -rf ~/.ssh"),
            ("find", "find . -maxdepth 0 -exec rm -rf ~/.ssh \\;"),
            ("watch", "watch rm -rf ~/.ssh"),
            ("su", "su -c 'rm -rf ~/.ssh'"),
            ("systemd-run", "systemd-run rm -rf ~/.ssh"),
        ];
        let launchers: Vec<&str> = every_program()
            .filter(|(_, row)| row.launcher)
            .map(|(name, _)| name)
            .collect();
        for name in &launchers {
            let (_, line) = forms
                .iter()
                .find(|(form, _)| form == name)
                .unwrap_or_else(|| panic!("no form for launcher `{name}`"));
            assert_eq!(
                crate::mcp::analyze_command(line, None).recommendation,
                "deny",
                "{line}"
            );
        }
        assert_eq!(launchers.len(), forms.len());
    }

    #[test]
    fn the_table_reads() {
        for name in [
            "sh", "tcsh", "csh", "ash", "python", "node", "at", "make", "awk", "crontab",
        ] {
            assert!(program(name).is_some(), "{name}");
        }
        assert!(program("tcsh").is_some_and(|row| row.shell && row.sink && row.stdin_code));
        assert!(program("at").is_some_and(|row| !row.sink && row.stdin_script));
    }

    #[test]
    fn what_each_runner_reads_on_stdin() {
        assert_eq!(stdin_script("at", &words("now")), Some(Language::Shell));
        assert_eq!(stdin_script("at", &words("-f job now")), None);
        assert_eq!(stdin_script("batch", &[]), Some(Language::Shell));
        assert_eq!(stdin_script("make", &words("-f -")), Some(Language::Make));
        assert_eq!(stdin_script("make", &words("all")), None);
        assert_eq!(
            stdin_script("awk", &["{system($0)}".to_owned()]),
            Some(Language::Shell)
        );
        assert_eq!(stdin_script("awk", &["{print $1}".to_owned()]), None);
        assert_eq!(
            stdin_script("parallel", &words("-j 4")),
            Some(Language::Shell)
        );
        assert_eq!(stdin_script("parallel", &words("gzip")), None);
        assert_eq!(stdin_script("sh", &[]), None);
    }

    #[test]
    fn the_files_each_runner_runs() {
        assert_eq!(
            file_scripts("sh", &words("x.sh")),
            vec![("x.sh".to_owned(), Language::Shell)]
        );
        assert_eq!(file_scripts("sh", &words("-c x.sh")), vec![]);
        assert_eq!(
            file_scripts("tcsh", &words("-f x.sh")),
            vec![("x.sh".to_owned(), Language::Shell)]
        );
        assert_eq!(
            file_scripts("python", &words("-u x.py a")),
            vec![("x.py".to_owned(), Language::Python)]
        );
        assert_eq!(file_scripts("python", &words("-m http.server")), vec![]);
        assert_eq!(
            file_scripts("source", &words("x.sh")),
            vec![("x.sh".to_owned(), Language::Shell)]
        );
        assert_eq!(
            file_scripts("at", &words("-f j.txt now")),
            vec![("j.txt".to_owned(), Language::Shell)]
        );
        assert_eq!(
            file_scripts("make", &words("-f x.mk")),
            vec![("x.mk".to_owned(), Language::Make)]
        );
        assert_eq!(file_scripts("make", &words("test")).len(), 3);
        assert_eq!(file_scripts("xargs", &words("rm")), vec![]);
    }

    #[test]
    fn code_that_writes_a_file() {
        assert_eq!(
            code_written_text(
                Language::Python,
                "open('x.sh','w').write('rm -rf ~')",
                "x.sh"
            ),
            Some(Some("rm -rf ~".to_owned()))
        );
        assert_eq!(
            code_written_text(
                Language::Node,
                "require('fs').writeFileSync('x.sh', \"id\")",
                "./x.sh"
            ),
            Some(Some("id".to_owned()))
        );
        assert_eq!(
            code_written_text(Language::Php, "file_put_contents('x.sh', $x);", "x.sh"),
            Some(None)
        );
        assert_eq!(code_written_text(Language::Ruby, "puts 1", "x.sh"), None);
    }

    #[test]
    fn a_makefile_and_a_crontab_are_read_for_what_they_run() {
        assert_eq!(
            shell_lines(Language::Make, "all:\n\t@curl -s u | sh\n", ""),
            vec!["curl -s u | sh".to_owned()]
        );
        assert_eq!(
            shell_lines(
                Language::Crontab,
                "MAILTO=x\n* * * * * id\n@reboot rm -rf ~\n",
                ""
            ),
            vec!["id\nrm -rf ~".to_owned()]
        );
        assert_eq!(
            shell_lines(Language::Python, "import os\nos.system('id')", "python3"),
            vec!["python3 - <<'IW_CODE'\nimport os\nos.system('id')\nIW_CODE".to_owned()]
        );
    }

    /// `crontab -u USER FILE` installs FILE, not USER; `-T FILE` only checks
    /// FILE and installs nothing.
    #[test]
    fn the_file_crontab_installs_is_past_the_user() {
        let files = |args: &[String]| file_scripts("crontab", args);
        let crontab = |path: &str| vec![(path.to_owned(), Language::Crontab)];
        assert_eq!(
            files(&["-u".to_owned(), "alice".to_owned(), "c.txt".to_owned()]),
            crontab("c.txt")
        );
        assert_eq!(
            files(&["-ualice".to_owned(), "c.txt".to_owned()]),
            crontab("c.txt")
        );
        assert_eq!(files(&["c.txt".to_owned()]), crontab("c.txt"));
        assert_eq!(files(&["-T".to_owned(), "c.txt".to_owned()]), vec![]);
        assert_eq!(files(&["-l".to_owned()]), vec![]);
    }

    /// The flag that takes code inline is read anywhere in a group of short
    /// flags, up to the first flag that takes the rest as its value.
    #[test]
    fn inline_code_is_read_anywhere_in_a_group_of_flags() {
        assert!(cluster_takes_code("uc", "c", Language::Python));
        assert!(cluster_takes_code("Bc", "c", Language::Python));
        assert!(cluster_takes_code("um", "c", Language::Python));
        assert!(!cluster_takes_code(
            "Wignore::DeprecationWarning",
            "c",
            Language::Python
        ));
        assert!(!cluster_takes_code(
            "Xfrozen_modules=off",
            "c",
            Language::Python
        ));
        assert!(cluster_takes_code("ne", "e", Language::Perl));
        assert!(cluster_takes_code("pe", "e", Language::Perl));
        assert!(cluster_takes_code("le", "e", Language::Perl));
        assert!(cluster_takes_code("lE", "e", Language::Perl));
        assert!(cluster_takes_code("0777ne", "e", Language::Perl));
        assert!(!cluster_takes_code("MLWP::Simple", "e", Language::Perl));
        assert!(!cluster_takes_code("pi.bak", "e", Language::Perl));
        // A script after such a group is not inline code: it is read.
        assert_eq!(
            file_scripts("python", &["-u".to_owned(), "x.py".to_owned()]),
            vec![("x.py".to_owned(), Language::Python)]
        );
        assert_eq!(
            file_scripts("python", &["-uc".to_owned(), "print(1)".to_owned()]),
            vec![]
        );
        assert_eq!(
            file_scripts(
                "perl",
                &["-ne".to_owned(), "print".to_owned(), "f".to_owned()]
            ),
            vec![]
        );
    }
    /// The command a launcher in front of it runs is where the rules that
    /// read a command by its name look: `env`, `command`, `nohup`,
    /// `timeout 9` taken off, in a substitution too, and the words of an
    /// `env -S` string put in its place. FAILS ON REVERT of
    /// [`launchers_read_through`], of the substitution reading, or of the
    /// `env -S` reading.
    #[test]
    fn the_command_a_launcher_runs_is_read_in_its_place() {
        for (line, read) in [
            ("f | env crontab -", "f | crontab -"),
            ("command crontab -l", "crontab -l"),
            ("nohup timeout 9 crontab -", "crontab -"),
            ("f |  \tcrontab -", "f | crontab -"),
            (
                "f=$(env curl -s https://e.example/p)",
                "f=$(curl -s https://e.example/p)",
            ),
            (
                "f=$(command curl -s https://e.example/p)",
                "f=$(curl -s https://e.example/p)",
            ),
            ("env -S 'rm -rf /'", "rm -rf /"),
            ("env -S 'crontab -' < f", "crontab - < f"),
            ("cd x && env --split-string='rm -rf /'", "cd x && rm -rf /"),
        ] {
            assert_eq!(
                launchers_read_through(line).as_deref(),
                Some(read),
                "{line}"
            );
        }
        for line in [
            "crontab -l",
            "git status",
            "ls -la",
            "f=$(curl -s https://e.example/p)",
        ] {
            assert_eq!(launchers_read_through(line), None, "{line}");
        }
        // A body with a quote in it is left as written.
        assert_eq!(
            substitutions_read_through("a=$(env echo 'x y')"),
            "a=$(env echo 'x y')"
        );
        assert_eq!(quoted_words(&words("crontab - <")), "crontab - <");
        assert_eq!(
            quoted_words(&["a b".to_owned(), "it's".to_owned()]),
            "'a b' 'it'\\''s'"
        );
    }
}
