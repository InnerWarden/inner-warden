//! Commands chained onto the arguments of a tool that is not a shell.
//!
//! A server that builds a shell line out of an argument (`ping -c 1 {host}`,
//! a `subprocess` call with `shell=True`) runs every command the argument
//! adds to that line: after `;`, `&`, `&&`, `||`, `|` or a line break, in a
//! subshell or a brace group, or in a command substitution. This module reads
//! each string of a tool call's arguments as the shell reads it there and
//! names the program such a command runs, when it is one a parameter has no
//! business starting on a server: a reader of files, a fetcher or relay, an
//! interpreter, a tool that changes owners, modes, mounts or processes, a
//! privilege tool, or one that prints the environment.
//!
//! # Why the shell's words, not a pattern over the text
//!
//! Chaining was screened by regular expressions over the arguments as JSON
//! text, one program list per operator. The lists drifted apart (`;` knew
//! `cat`, `&&` did not), a line break was never seen (in JSON text it is two
//! characters, `\` and `n`, and so is a tab, which the shell takes as a
//! blank), and a program written with its folder (`/bin/cat`), in quotes
//! (`'cat'`, `c'a't`) or behind a wrapper (`nohup cat`) was missed. Here the
//! value is the decoded string the server receives, read by the same word
//! reader the shell hook uses, and every operator leads to one judgement.
//!
//! # Where the value sits on the server's line
//!
//! A server may put the value on its line bare, inside single quotes or
//! inside double quotes, and a value can close the quote it was put in
//! (`x' && cat f '`). Each value is read once per place, behind a fixed word
//! that stands for the server's own program, and a command found in any of
//! the three readings counts. The first command of a reading is the server's
//! own; every later one, and every command of a substitution, is the value's.
//!
//! # What is not a chained command
//!
//! A parenthesis or a `{` where no command can start is not an operator to
//! the shell (`pets (cat videos)` is a syntax error, `const { id } = x`
//! passes `{` as a word), so neither ends a command here; a command can still
//! start after an operator or a reserved word, which is all a subshell or a
//! brace group needs. A `NAME=value` word assigns and runs nothing, which is
//! what a URL query string is to the shell (`?page=2&id=17`). A command
//! counts only when the program it runs is one of [`PROGRAMS`], so prose
//! (`R&D`, `Tom && Jerry`) and code (`a && b`) pass. Four of those programs
//! are also common words of code and are judged by what the shell would make
//! them do with the words they got: `export` and `set` print the environment
//! only with no name to act on (`export default App` names one), `id` prints
//! nothing once it has more than one operand or is handed `=` (`id = 5`), and
//! `env`, `exec` and the other wrappers are judged by the program they start
//! (`env = os.environ` starts a program named `=`), `env` alone printing the
//! environment. A quote or a substitution that never closes makes the shell
//! refuse the line, so it runs nothing (a lone `` ```bash `` line). A glob
//! without a folder names a file in the server's working directory, not a
//! program the value chose (`* item`). A builtin is matched only as the
//! shell spells it (`Set` is no command), a program on the path in any case.
//!
//! Measured on 2026-11-14 over 289,583 lines of documentation and code
//! comments (Python's library, `/usr/share/doc`, npm's modules) each sent as
//! a one-line argument: 394 lines read as a chained command, 60 of them not
//! already refused by another rule. Most are a shell command quoted in prose
//! (`` `openssl ciphers -v` ``), which runs when a shell gets it; the rest a
//! table cell or a closing parenthesis followed by a program's name.

use std::collections::{HashMap, HashSet};

use crate::shell_words::{read_line, Line, Mark, Word};

/// The programs a chained command is refused for. The list ATR-2026-111 uses
/// inside `$(...)`, the widest the rule has, plus the shells and the relay it
/// left out.
const PROGRAMS: &[&str] = &[
    "rm", "cat", "curl", "wget", "nc", "ncat", "bash", "sh", "python", "perl", "ruby", "php",
    "whoami", "id", "uname", "env", "printenv", "set", "export", "eval", "exec", "chmod", "chown",
    "kill", "pkill", "dd", "mkfs", "mount", "umount", "sudo", "su", "passwd", "base64", "xxd",
    "openssl", "tee", "zsh", "ksh", "dash", "socat",
];

/// Programs that run another program named among their operands: judged by
/// that program.
const WRAPPERS: &[&str] = &[
    "command", "builtin", "exec", "env", "nohup", "nice", "time", "timeout", "stdbuf", "setsid",
    "busybox", "toybox", "xargs", "doas", "ionice", "chrt", "taskset", "unbuffer", "coproc",
];

/// Words that open or continue a compound command: the command proper starts
/// after them.
const RESERVED: &[&str] = &[
    "!", "if", "then", "else", "elif", "while", "until", "do", "{", "}",
];

/// How deep substitutions, `eval` strings and wrappers are followed. Deeper
/// than this, the value is refused: a check that cannot finish must not pass.
const DEPTH: u8 = 8;

/// What a chained command was found to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Chained {
    /// It runs this program.
    Runs(&'static str),
    /// A substitution that only redirects a file into itself (`$(<file)`):
    /// bash reads the file into the line without running a program.
    ReadsFile,
    /// Its substitutions or wrappers nest deeper than [`DEPTH`].
    TooDeep,
}

impl Chained {
    /// The reason a refusal gives.
    pub(crate) fn describe(self, argument: &str) -> String {
        // The place is shown, and a key can be the carrier itself: no
        // control character, and no more than a short label.
        let argument: String = argument
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(64)
            .collect();
        match self {
            Chained::Runs(program) => format!(
                "argument `{argument}` adds a command to a shell line that runs `{program}`"
            ),
            Chained::ReadsFile => format!(
                "argument `{argument}` holds a substitution that reads a file into a shell line"
            ),
            Chained::TooDeep => format!(
                "argument `{argument}` nests commands deeper than the guard reads ({DEPTH} levels)"
            ),
        }
    }
}

/// The first string in `args`, a key or a value at any depth, that carries a
/// chained command, with where it sits (`host`, `targets.hosts[1]`).
pub(crate) fn chained_argument(args: &serde_json::Value) -> Option<(String, Chained)> {
    fn walk(value: &serde_json::Value, at: &str) -> Option<(String, Chained)> {
        match value {
            serde_json::Value::String(text) => {
                chained_command(text).map(|found| (at.to_string(), found))
            }
            serde_json::Value::Array(items) => items
                .iter()
                .enumerate()
                .find_map(|(index, item)| walk(item, &format!("{at}[{index}]"))),
            serde_json::Value::Object(map) => map.iter().find_map(|(key, item)| {
                let here = if at.is_empty() {
                    key.clone()
                } else {
                    format!("{at}.{key}")
                };
                chained_command(key)
                    .map(|found| (here.clone(), found))
                    .or_else(|| walk(item, &here))
            }),
            _ => None,
        }
    }
    walk(args, "")
}

/// What a command chained onto `value` runs, read as the shell reads the
/// value on a server's line, bare or inside either quote.
pub(crate) fn chained_command(value: &str) -> Option<Chained> {
    if !value.contains([';', '&', '|', '\n', '\r', '(', '`']) {
        return None;
    }
    let text = prepare(value);
    ["", "'", "\""].into_iter().find_map(|open| {
        let reading = format!("x{open}{text}");
        let line = read_line(&reading);
        let assigned = assignments(&line);
        line.commands
            .iter()
            .skip(1)
            .find_map(|command| runs(&command.words, &assigned, 0))
            .or_else(|| nested(&line, &reading, 0))
    })
}

/// `value` with a carriage return read as a line break (a server that splits
/// lines may split on it), and each `(` and lone `{` made a blank. Where one
/// opens a subshell or a group, the operator or reserved word in front of it
/// already starts the command; anywhere else the shell refuses a `(` and
/// takes a `{` as a plain word, so neither may end a command there. A `(`
/// after `$`, `<`, `>` or `=` opens a substitution or an array and is kept,
/// and so is `${`.
fn prepare(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    let mut previous = None;
    while let Some(c) = chars.next() {
        let next = chars.peek().copied();
        let kept = match c {
            '\r' => '\n',
            '(' if !matches!(previous, Some('$' | '<' | '>' | '=' | '(')) => ' ',
            '{' if previous != Some('$') && next.is_none_or(char::is_whitespace) => ' ',
            other => other,
        };
        out.push(kept);
        previous = Some(kept);
    }
    out
}

/// Every command of every substitution in `line`, the first of each
/// included: a substitution is a command line of its own.
fn nested(line: &Line, text: &str, depth: u8) -> Option<Chained> {
    let mut seen = HashSet::new();
    let mut run_by_name = None;
    for inner in &line.nested {
        if !seen.insert(inner.as_str()) {
            continue;
        }
        if depth >= DEPTH {
            return Some(Chained::TooDeep);
        }
        let read = read_line(inner);
        let assigned = assignments(&read);
        let file_read = reads_a_file(inner);
        let found = read
            .commands
            .iter()
            .find_map(|command| runs(&command.words, &assigned, depth + 1))
            .or(file_read.then_some(Chained::ReadsFile));
        // The reader hands back the inside of `${...}` with the command
        // lines: a bare name no command substitution of `text` holds is a
        // parameter (`${id}` in a template), not `$(id)`.
        let parameter = is_name(inner)
            && !run_by_name
                .get_or_insert_with(|| substituted_names(text))
                .contains(inner.as_str());
        if found.is_some() && !parameter && !never_closed(inner, text) {
            return found;
        }
        if let Some(found) = nested(&read, inner, depth + 1) {
            return Some(found);
        }
    }
    None
}

/// `inner`, a substitution's line, is one input redirection of a file and
/// nothing else (`</etc/hosts`, `<.env`): bash puts the file's text in its
/// place. A tag in a code span (`<br>`) is a redirection without a target,
/// which the shell refuses, and an operator in one (`<=version`, `<!`) names
/// no path.
fn reads_a_file(inner: &str) -> bool {
    let Some(target) = inner.trim().strip_prefix('<') else {
        return false;
    };
    let target = target.trim_start();
    let names_a_path = target
        .starts_with(|c: char| c.is_ascii_alphabetic() || "/~._$'\"".contains(c))
        && target.contains(['/', '.']);
    if !names_a_path || target.contains(['<', '>', '|', ';', '&']) {
        return false;
    }
    let read = read_line(target);
    read.commands.len() == 1 && read.commands[0].words.len() == 1
}

/// The bare names `text` runs as a command substitution: `$(name)`,
/// `` `name` ``, `<(name)`, `>(name)`. One pass over `text`.
fn substituted_names(text: &str) -> HashSet<&str> {
    let bytes = text.as_bytes();
    let mut names = HashSet::new();
    let mut at = 0;
    while at < bytes.len() {
        let (start, close) = match (bytes[at], bytes.get(at + 1)) {
            (b'$' | b'<' | b'>', Some(b'(')) => (at + 2, b')'),
            (b'`', _) => (at + 1, b'`'),
            _ => {
                at += 1;
                continue;
            }
        };
        let end = start
            + bytes[start..]
                .iter()
                .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
                .count();
        if end > start && bytes.get(end) == Some(&close) {
            names.insert(&text[start..end]);
        }
        at = start;
    }
    names
}

/// `inner` is a substitution of `text` that never closes: it runs from its
/// opening to the end of `text` (`` ```bash `` alone on a line). The shell
/// refuses such a line before running any of it.
fn never_closed(inner: &str, text: &str) -> bool {
    ["`", "$(", "<(", ">("]
        .iter()
        .any(|open| text.ends_with(&format!("{open}{inner}")))
}

/// The program `words`, a simple command, runs, when it is one of
/// [`PROGRAMS`] and runs as one: past the assignments and the reserved words
/// in front of it, and through the wrappers.
fn runs(words: &[Word], assigned: &HashMap<String, String>, depth: u8) -> Option<Chained> {
    if depth > DEPTH {
        return Some(Chained::TooDeep);
    }
    let mut at = 0;
    while let Some(word) = words.get(at) {
        if is_assignment(word) || RESERVED.contains(&word.text.as_str()) {
            at += 1;
        } else if word.text == "function" {
            // `function name { ...`: the name is not a program.
            at += 2;
        } else {
            break;
        }
    }
    let words = words.get(at..)?;
    let program = program_name(words.first()?, assigned)?;
    let operands = &words[1..];
    match program {
        "export" => operands
            .iter()
            .all(|word| word.text.starts_with('-'))
            .then_some(Chained::Runs("export")),
        "set" => operands.is_empty().then_some(Chained::Runs("set")),
        "id" => {
            let named: Vec<&Word> = operands
                .iter()
                .filter(|word| !word.text.starts_with('-'))
                .collect();
            let fails =
                named.len() > 1 || named.first().is_some_and(|word| is_operator(&word.text));
            (!fails).then_some(Chained::Runs("id"))
        }
        "eval" => {
            if depth >= DEPTH {
                return Some(Chained::TooDeep);
            }
            let joined: Vec<&str> = operands.iter().map(|word| word.text.as_str()).collect();
            let read = read_line(&prepare(&joined.join(" ")));
            let inner = assignments(&read);
            read.commands
                .iter()
                .find_map(|command| runs(&command.words, &inner, depth + 1))
                .or_else(|| nested(&read, &joined.join(" "), depth + 1))
        }
        "env" => match wrapped(operands, assigned, depth) {
            Some(found) => found,
            // Nothing to run: `env` prints the environment.
            None => Some(Chained::Runs("env")),
        },
        wrapper if WRAPPERS.contains(&wrapper) => wrapped(operands, assigned, depth).flatten(),
        program => Some(Chained::Runs(program)),
    }
}

/// What a wrapper given `operands` runs: `None` when it is given no program,
/// `Some(None)` when the program it runs is not one of [`PROGRAMS`].
///
/// Options are passed over. A word right after an option may be that option's
/// value (`timeout -s KILL`, `env -u NAME`), so it is judged as a program and,
/// when it is not one, passed over too. Numbers and durations (`nice -n 5`,
/// `timeout 5s`) and assignments (`env A=1`) are passed over.
fn wrapped(
    operands: &[Word],
    assigned: &HashMap<String, String>,
    depth: u8,
) -> Option<Option<Chained>> {
    let mut after_option = false;
    for (index, word) in operands.iter().enumerate() {
        let text = word.text.as_str();
        if text == "--" {
            return Some(runs(&operands[index + 1..], assigned, depth + 1));
        }
        if text.len() > 1 && text.starts_with('-') {
            after_option = true;
            continue;
        }
        if is_assignment(word) || is_duration(text) {
            continue;
        }
        let found = runs(&operands[index..], assigned, depth + 1);
        if !after_option || found.is_some() {
            return Some(found);
        }
        after_option = false;
    }
    None
}

/// The [`PROGRAMS`] or [`WRAPPERS`] entry `word` names as a command word:
/// its last path component, quotes and escapes taken out, a version suffix
/// dropped (`python3.11`), letters of either case. A glob is matched as the
/// shell would match it (`/bin/c?t`), a brace by its first alternative, a
/// parameter by what the line assigned it (`A=/bin/cat; $A`), and text an
/// expansion adds is left out (`c${u}at`).
fn program_name(word: &Word, assigned: &HashMap<String, String>) -> Option<&'static str> {
    if let Some(value) = parameter_of(word).and_then(|name| assigned.get(name)) {
        return known(value.rsplit('/').next().unwrap_or(value));
    }
    let (chars, marks) = first_alternative(word);
    let start = chars
        .iter()
        .zip(&marks)
        .rposition(|(c, mark)| *c == '/' && *mark == Mark::Plain)
        .map_or(0, |at| at + 1);
    let (chars, marks) = (&chars[start..], &marks[start..]);
    if marks.contains(&Mark::Pattern) {
        // Without a folder the shell matches the glob against the server's
        // working directory, not the programs on its path, so the value
        // cannot pick the program (`* item`, `/* note */` run no program the
        // value chose). With one, the name must keep two letters of its own:
        // `/bin/c*` runs whichever file sorts first, `/bin/c?t` runs `cat`.
        let literal = marks.iter().filter(|mark| **mark == Mark::Plain).count();
        if start == 0 || literal < 2 {
            return None;
        }
        return PROGRAMS
            .iter()
            .chain(WRAPPERS)
            .copied()
            .find(|name| glob_matches(chars, marks, &name.chars().collect::<Vec<_>>()));
    }
    let plain: String = chars
        .iter()
        .zip(marks)
        .filter(|(_, mark)| **mark == Mark::Plain)
        .map(|(c, _)| *c)
        .collect();
    known(&plain)
}

/// The entry `name` is, with a version suffix set aside. A program found on
/// the path is matched in either case, as a server on a case-insensitive
/// file system finds `CAT`; a builtin only as the shell spells it, since no
/// shell looks a builtin up in another case (`Set` in prose is no command).
fn known(name: &str) -> Option<&'static str> {
    const BUILTINS: &[&str] = &["set", "export", "eval", "exec", "coproc"];
    let lower = name.to_ascii_lowercase();
    let find = |candidate: &str| {
        PROGRAMS
            .iter()
            .chain(WRAPPERS)
            .copied()
            .find(|entry| *entry == candidate)
    };
    if lower.starts_with("mkfs.") {
        return Some("mkfs");
    }
    find(&lower)
        .or_else(|| find(lower.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')))
        .filter(|entry| !BUILTINS.contains(entry) || name == *entry)
}

/// `word` with each brace expansion replaced by its first alternative, which
/// is the word the program comes from (`{cat,/f}` runs `cat`).
fn first_alternative(word: &Word) -> (Vec<char>, Vec<Mark>) {
    let chars: Vec<char> = word.text.chars().collect();
    let mut out = (Vec::new(), Vec::new());
    let mut at = 0;
    while at < chars.len() {
        let (c, mark) = (chars[at], word.marks[at]);
        if c == '{' && mark == Mark::Pattern {
            let mut level = 1;
            let mut taking = true;
            at += 1;
            while at < chars.len() && level > 0 {
                let (inner, inner_mark) = (chars[at], word.marks[at]);
                let pattern = inner_mark == Mark::Pattern;
                match inner {
                    '{' if pattern => level += 1,
                    '}' if pattern => level -= 1,
                    ',' if pattern && level == 1 => taking = false,
                    '.' if pattern && level == 1 => taking = false,
                    _ => {}
                }
                if taking && level > 0 && !(pattern && matches!(inner, '{' | '}')) {
                    out.0.push(inner);
                    out.1.push(Mark::Plain);
                }
                at += 1;
            }
            continue;
        }
        out.0.push(c);
        out.1.push(mark);
        at += 1;
    }
    out
}

/// The `]` closing the bracket expression whose `[` starts `pattern`; a first
/// member may itself be `]`.
fn bracket_close(pattern: &[char], marks: &[Mark]) -> Option<usize> {
    (2..pattern.len()).find(|at| pattern[*at] == ']' && marks[*at] == Mark::Pattern)
}

/// The fewest characters `pattern` can match: one per element but `*`.
fn shortest_match(pattern: &[char], marks: &[Mark]) -> usize {
    let mut count = 0;
    let mut at = 0;
    while at < pattern.len() {
        let pattern_char = marks[at] == Mark::Pattern;
        at += match pattern[at] {
            '*' if pattern_char => 1,
            '[' if pattern_char => {
                count += 1;
                bracket_close(&pattern[at..], &marks[at..]).map_or(1, |close| close + 1)
            }
            _ => {
                count += 1;
                1
            }
        };
    }
    count
}

/// Whether the glob `pattern` (its pattern characters marked) matches `name`.
fn glob_matches(pattern: &[char], marks: &[Mark], name: &[char]) -> bool {
    // A pattern needing more characters than the name has cannot match; this
    // also bounds the search a run of `*` starts below.
    if shortest_match(pattern, marks) > name.len() {
        return false;
    }
    match (pattern.first(), marks.first()) {
        (None, _) => name.is_empty(),
        (Some('*'), Some(Mark::Pattern)) => {
            let rest = pattern
                .iter()
                .zip(marks)
                .take_while(|(c, mark)| **c == '*' && **mark == Mark::Pattern)
                .count();
            (0..=name.len())
                .any(|skip| glob_matches(&pattern[rest..], &marks[rest..], &name[skip..]))
        }
        (Some('?'), Some(Mark::Pattern)) => {
            !name.is_empty() && glob_matches(&pattern[1..], &marks[1..], &name[1..])
        }
        (Some('['), Some(Mark::Pattern)) if bracket_close(pattern, marks).is_some() => {
            let Some(close) = bracket_close(pattern, marks) else {
                return false;
            };
            let Some(first) = name.first() else {
                return false;
            };
            let members = &pattern[1..close];
            let (negated, members) = match members.first() {
                Some('!' | '^') => (true, &members[1..]),
                _ => (false, members),
            };
            let mut inside = false;
            let mut at = 0;
            while at < members.len() {
                if at + 2 < members.len() && members[at + 1] == '-' {
                    inside |= (members[at]..=members[at + 2]).contains(first);
                    at += 3;
                } else {
                    inside |= members[at] == *first;
                    at += 1;
                }
            }
            inside != negated
                && glob_matches(&pattern[close + 1..], &marks[close + 1..], &name[1..])
        }
        (Some(c), _) => {
            name.first().is_some_and(|n| n.eq_ignore_ascii_case(c))
                && glob_matches(&pattern[1..], &marks[1..], &name[1..])
        }
    }
}

/// The names the commands of `line` assign, each to its value as written.
fn assignments(line: &Line) -> HashMap<String, String> {
    let mut assigned = HashMap::new();
    for command in &line.commands {
        for word in command.words.iter().take_while(|word| is_assignment(word)) {
            if let Some((name, value)) = word.text.split_once('=') {
                assigned.insert(name.trim_end_matches('+').to_string(), value.to_string());
            }
        }
    }
    assigned
}

/// `word` is `$name` or `${name}` and nothing else: the name.
fn parameter_of(word: &Word) -> Option<&str> {
    if !word.marks.iter().all(|mark| *mark == Mark::Expansion) {
        return None;
    }
    let text = word.text.strip_prefix('$')?;
    let name = text
        .strip_prefix('{')
        .and_then(|inner| inner.strip_suffix('}'))
        .unwrap_or(text);
    is_name(name).then_some(name)
}

/// `word` assigns a variable (`NAME=value`, `NAME+=value`, `NAME[i]=value`)
/// rather than naming a program.
fn is_assignment(word: &Word) -> bool {
    let Some(equals) = word.text.find('=') else {
        return false;
    };
    let target = word.text[..equals].trim_end_matches('+');
    let name = match target.find('[') {
        Some(open) if target.ends_with(']') => &target[..open],
        _ => target,
    };
    let length = name.chars().count();
    is_name(name) && word.marks[..length].iter().all(|mark| *mark == Mark::Plain)
}

/// A shell variable name.
fn is_name(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// An assignment or comparison operator of code (`=`, `:=`, `+=`, `==`).
fn is_operator(text: &str) -> bool {
    text.contains('=') && text.chars().all(|c| "=:+-*/%!<>&|^?.".contains(c))
}

/// A number or a duration (`5`, `0.5`, `10s`, `2m`): the value of a wrapper
/// such as `timeout` or `nice`, never a program.
fn is_duration(text: &str) -> bool {
    let digits = text.trim_end_matches(['s', 'm', 'h', 'd']);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit() || c == '.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runs_program(value: &str) -> Option<&'static str> {
        match chained_command(value) {
            Some(Chained::Runs(program)) => Some(program),
            other => panic!("{value:?}: expected a program, got {other:?}"),
        }
    }

    #[test]
    fn each_operator_leads_to_the_same_judgement() {
        for value in [
            "h; cat f",
            "h;cat f",
            "h && cat f",
            "h&&cat f",
            "h || cat f",
            "h | cat f",
            "h |& cat f",
            "h & cat f",
            "h&cat f",
            "h\ncat f",
            "h\rcat f",
            "h;\tcat f",
            "h; (cat f)",
            "h && { cat f; }",
            "h; if cat f; then :; fi",
            "h; ! cat f",
            "h; while cat f; do break; done",
            "h; function f { cat g; }",
        ] {
            assert_eq!(runs_program(value), Some("cat"), "{value:?}");
        }
    }

    #[test]
    fn the_program_is_found_however_it_is_spelled() {
        for value in [
            "h; /bin/cat f",
            "h; /usr/local/bin/cat f",
            "h; 'cat' f",
            "h; \"cat\" f",
            "h; c'a't f",
            "h; \\cat f",
            "h; /bin/c?t f",
            "h; /bin/c[a]t f",
            "h; /???/ca*",
            "h; {cat,f}",
            "h; c${x}at f",
            "h; A=/bin/cat; $A f",
            "h; A=cat; ${A} f",
            "h; CAT f",
            "h; X=1 cat f",
            "h; nohup cat f",
            "h; timeout -s TERM 5 cat f",
            "h; env -u X cat f",
            "h; nice -n 5 cat f",
            "h; xargs -I{} cat {}",
            "h; command -- cat f",
            "h; eval 'cat f'",
            "h; exec cat f",
            "h; nohup timeout 5s cat f",
        ] {
            assert_eq!(runs_program(value), Some("cat"), "{value:?}");
        }
        assert_eq!(runs_program("h; python3.11 -c x"), Some("python"));
        assert_eq!(runs_program("h; mkfs.ext4 /dev/x"), Some("mkfs"));
        assert_eq!(runs_program("h; base64 f"), Some("base64"));
    }

    #[test]
    fn a_value_that_closes_the_quote_it_was_put_in_is_read_there() {
        assert_eq!(runs_program("h' && cat f '"), Some("cat"));
        assert_eq!(runs_program("h\" && cat f \""), Some("cat"));
        assert_eq!(runs_program("h\"; cat f; \""), Some("cat"));
    }

    #[test]
    fn a_substitution_runs_wherever_it_is() {
        for value in [
            "$(cat f)",
            "$( /bin/cat f )",
            "`cat f`",
            "h > $(cat f)",
            "h <(cat f)",
            "h$(id)",
            "${x:-$(cat f)}",
            "\"$(cat f)\"",
            "h <<E\n$(cat f)\nE",
        ] {
            assert!(chained_command(value).is_some(), "{value:?}");
        }
        assert_eq!(
            chained_command("h $(</etc/hosts)"),
            Some(Chained::ReadsFile)
        );
        assert_eq!(chained_command("h $(< .env)"), Some(Chained::ReadsFile));
        assert_eq!(
            chained_command("h `< '/etc/a b'`"),
            Some(Chained::ReadsFile)
        );
    }

    #[test]
    fn printing_the_environment_counts_naming_a_variable_does_not() {
        assert_eq!(runs_program("h; export"), Some("export"));
        assert_eq!(runs_program("h; export -p"), Some("export"));
        assert_eq!(runs_program("h; set"), Some("set"));
        assert_eq!(runs_program("h; env"), Some("env"));
        assert_eq!(runs_program("h; env -0"), Some("env"));
        assert_eq!(runs_program("h; env A=1"), Some("env"));
        assert_eq!(runs_program("h; printenv"), Some("printenv"));
        assert_eq!(runs_program("h; id"), Some("id"));
        assert_eq!(runs_program("h; id root"), Some("id"));
        assert_eq!(runs_program("h; id -u"), Some("id"));
        for value in [
            "a;\nexport default App;",
            "a;\nexport const x = 1;",
            "a;\nexport { id, env };",
            "a\nset -e",
            "a; SET search_path = app",
            "a\nenv = os.environ.copy()",
            "a\nid = 5",
            "a || id AS key FROM t",
            "a\nexec(compile(src, 'x', 'exec'))",
            "a\neval(expr)",
            "a\nexec",
        ] {
            assert_eq!(chained_command(value), None, "{value:?}");
        }
    }

    #[test]
    fn prose_urls_and_code_are_not_chained_commands() {
        for value in [
            "R&D",
            "Tom && Jerry",
            "AT&T; Q&A",
            "salt & pepper",
            "dogs & cats",
            "pets (cat videos)",
            "see (set to true)",
            "https://x.test/a?page=2&id=17&env=p&cat=3",
            "const ok = a && b;",
            "x | y",
            "a || b",
            "const { id } = req;",
            "fetch(`/users/${id}`)",
            "`${env}`",
            "it's a test; don't worry",
            "line one\nline two\n# heading\n",
            "find . -exec cat {} \\;",
            "a=(cat f)",
            "The `Set` and `Map` types",
            "intro\n* item one\n* item two",
            "/* note */\nint x;",
            "a\n * @param id the key",
            "c?t f; d?t g",
            "use `<br>` or `<details>`",
            "an `<IMPORTANT>` block",
            "`a < b`",
            "ranges: `<=version` or `<1.2.3`, and `<!`",
        ] {
            assert_eq!(chained_command(value), None, "{value:?}");
        }
    }

    #[test]
    fn a_parameter_is_not_a_command_substitution_of_the_same_name() {
        assert_eq!(chained_command("h ${id} `${env}`"), None);
        assert_eq!(runs_program("h ${id} $(id)"), Some("id"));
        assert_eq!(runs_program("h ${env} `env`"), Some("env"));
    }

    /// Telling a parameter from a substitution reads the text once, not once
    /// per name: with a search per name, 20,000 distinct names in one
    /// argument made a single call quadratic in its length.
    #[cfg_attr(
        tarpaulin,
        ignore = "a time ceiling under instrumentation measures the instrumentation"
    )]
    #[test]
    fn many_parameters_are_read_in_one_pass() {
        let many: Vec<String> = (0..20_000).map(|n| format!("${{id{n}}}")).collect();
        let started = std::time::Instant::now();
        assert_eq!(chained_command(&format!("h {}", many.join(" "))), None);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_builtin_counts_only_as_the_shell_spells_it_a_program_in_any_case() {
        assert_eq!(chained_command("h; SET"), None);
        assert_eq!(chained_command("h; Export"), None);
        assert_eq!(runs_program("h; Cat f"), Some("cat"));
        assert_eq!(runs_program("h; ENV"), Some("env"));
    }

    #[test]
    fn a_syntax_error_or_an_open_quote_runs_nothing() {
        // The shell refuses a quote or a substitution that never closes
        // before running the line.
        assert_eq!(chained_command("h; 'cat f"), None);
        assert_eq!(chained_command("```bash"), None);
        assert_eq!(chained_command("h `cat f"), None);
        assert_eq!(chained_command("h $(cat f"), None);
        // Closed, the same substitution runs.
        assert_eq!(runs_program("```bash\nmake\n```"), Some("bash"));
    }

    #[test]
    fn nesting_past_the_limit_is_refused() {
        let mut value = String::from("cat f");
        for _ in 0..=DEPTH {
            value = format!("$({value})");
        }
        assert!(chained_command(&format!("h {value}")).is_some());
        let mut value = String::from("true");
        for _ in 0..=DEPTH {
            value = format!("$({value})");
        }
        assert_eq!(
            chained_command(&format!("h {value}")),
            Some(Chained::TooDeep)
        );
    }

    #[test]
    fn the_argument_is_named_where_it_sits() {
        let args = serde_json::json!({"a": "ok", "b": {"c": ["ok", "h && cat f"]}});
        let (at, found) = chained_argument(&args).expect("found");
        assert_eq!(at, "b.c[1]");
        assert_eq!(found, Chained::Runs("cat"));
        assert!(chained_argument(&serde_json::json!({"h; cat f": 1})).is_some());
        assert!(chained_argument(&serde_json::json!({"q": "R&D", "n": 3})).is_none());
    }
}
