//! A word the guard watches, named as data or acted on.
//!
//! The guard refuses an agent's ACTION on its own files, processes and
//! settings and on an agent's settings: a line (or the inline code of
//! Python, Node, Ruby or Perl) that writes, deletes, moves over, changes the
//! mode or owner of, kills, stops, disables or edits one of them. It does
//! not refuse a MENTION of the name: a search pattern, the text of a
//! here-document handed to a program that only keeps it, a message (`-m`,
//! `--body`), a folder of a repository or a worktree whose name holds the
//! guard's, a string inside code that acts on nothing of the guard's.
//! Decision of the operator, 2026-11-21.
//!
//! [`masked`] writes the line again with each such slot replaced by a
//! neutral word. The caller judges both: when the line is denied only for
//! the guard's own families and the masked line is not, the refusal came
//! from the mention, and the line is held for review instead.
//!
//! A slot is masked only when its text is literal (no expansion, no
//! substitution: bash runs a substitution whatever slot it stands in), and
//! inline code only when it can act on nothing of the guard's
//! ([`code_may_act`]). A name built at run time (`'inner' + 'warden'`) is
//! not read here: that is a known limit of Community, covered by the
//! operating system's own protection and by the kernel layer of Pro.

use crate::shell::parse_bash;

/// Interpreters whose inline code is read here.
const INTERPRETERS: &[&str] = &["python", "node", "nodejs", "ruby", "perl"];

/// What makes inline code run something else, signal a process or read code
/// the text does not show, per language. Code holding any of them is never
/// taken for a mention. Python's are spelled as calls or modules: its code
/// edits text that names `exec` or `kill` as often as it runs them.
const PYTHON_RUNS: &[&str] = &[
    "subprocess",
    "os.system",
    "os.popen",
    "os.exec",
    "os.spawn",
    "os.posix_spawn",
    "os.kill",
    "os.killpg",
    "os.fork",
    "os.plock",
    "import pty",
    "pty.",
    "import signal",
    "signal.",
    "from signal",
    "eval(",
    "exec(",
    "compile(",
    "__import__",
    "importlib",
    "ctypes",
    "cffi",
    "getattr(",
    "globals(",
    "vars(",
    "__dict__",
    "builtins",
    "from os import",
    "import os as",
    "multiprocessing",
    "asyncio",
    "socket",
    "urllib",
    "requests.",
    "import requests",
    "http.client",
    "httpx",
    "dbus",
    "runpy",
    "code.interact",
    "pickle",
    "marshal",
    "expanduser",
    "expandvars",
    "environ",
    "getenv",
    ".home(",
    "getcwd",
    "glob",
    "walk(",
    "listdir",
    "scandir",
    "fileinput",
    "os.write",
    "os.open",
    "os.dup",
    "os.fdopen",
    "tempfile",
    "atexit",
    "setattr(",
    "lambda",
    "chdir",
    ") / '",
    ") / \"",
    "psutil",
    ".kill(",
    ".terminate(",
    ".send_signal(",
    "import sh",
    "from sh ",
    "plumbum",
    "pexpect",
    "fabric",
    "paramiko",
    "invoke",
    "__getattribute__",
    "operator.",
    "functools",
    "breakpoint",
];
/// The same for Node, Ruby and Perl, read loosely: their code here is rare.
const OTHER_RUNS: &[&str] = &[
    "system",
    "popen",
    "spawn",
    "fork",
    "exec",
    "eval",
    "kill",
    "signal",
    "child_process",
    "process.",
    "function(",
    "vm",
    "worker",
    "import(",
    "open3",
    "%x",
    "qx",
    "kernel",
    "send(",
    "syscall",
    "dbus",
    "socket",
    "http",
    "net.",
    "require",
    "load",
    "do ",
    "|",
    "`",
];

/// The settings an agent loads the guard by and the guard's own places: a
/// path holding one of these is what the guard protects.
const SETTINGS_PLACES: &[&str] = &[
    ".claude",
    ".codex",
    ".cursor",
    ".gemini",
    ".openclaw",
    ".hermes",
    ".goose",
    ".aider",
    ".continue",
    ".windsurf",
    ".kiro",
    ".vscode",
    ".zed",
    ".amp",
    "settings.json",
    "settings.local.json",
    "hooks.json",
    "mcp.json",
    ".mcp",
    "claude_desktop_config",
    "config.toml",
    "config.yaml",
    "config.yml",
    ".config/",
    "/etc/",
    ".innerwarden",
    "innerwarden/",
    "innerwarden.service",
    "/.local/bin",
    "/usr/local/bin",
    "/opt/",
];

/// Calls of every language read here that write, copy, move, link or open
/// a file for writing, lowercase.
const WRITES_A_FILE: &[&str] = &[
    "open(",
    "write",
    "copy",
    "cp(",
    "cp ",
    ".cp",
    "mv(",
    "mv ",
    ".mv",
    "move",
    "rename",
    "install",
    "replace(",
    "symlink",
    "link(",
    "unlink",
    "remove",
    "rmtree",
    "truncate",
    "chmod",
    "chown",
    "fileutils",
    "shutil",
    "pathlib",
    "path(",
    "fs.",
    "fs/",
    "io.",
    "file.",
    "sysopen",
    "touch",
    "mkdir",
    "dump(",
    "put_contents",
    "save",
    "store",
];

/// What makes inline code change a file.
const CHANGES_A_FILE: &[&str] = &[
    "open(",
    "write",
    "unlink",
    "remove",
    "rmtree",
    "rename",
    "os.replace",
    "chmod",
    "chown",
    "truncate",
    "symlink",
    "link(",
    "copy",
    "move",
    "mkdir",
    "rmdir",
    "touch",
    "fs.",
    "file.",
    "path(",
    "pathlib",
    "shutil",
    "io.",
    "sysopen",
    "utime",
];

/// The programs of the guard: a path whose last part is one of them may be
/// the guard's program, wherever it lies.
const GUARD_PROGRAMS: &[&str] = &[
    "innerwarden",
    "innerwarden-ctl",
    "innerwarden-config-sign",
    "iw",
    "iw-guard",
];

/// Search programs whose pattern is data.
const SEARCHERS: &[&str] = &["grep", "egrep", "fgrep", "rg", "ag", "ack"];

/// Options of the searchers that take the next word as their value.
const SEARCH_VALUE_OPTIONS: &[&str] = &[
    "-A",
    "-B",
    "-C",
    "-m",
    "-d",
    "-D",
    "-f",
    "-g",
    "-t",
    "-T",
    "-M",
    "-j",
    "--type",
    "--type-not",
    "--glob",
    "--iglob",
    "--max-count",
    "--max-depth",
    "--max-columns",
    "--context",
    "--after-context",
    "--before-context",
    "--threads",
    "--file",
    "--include",
    "--exclude",
    "--exclude-dir",
    "--color",
    "--colour",
    "--sort",
    "--sortr",
    "--encoding",
    "--type-add",
    "--max-filesize",
    "--path-separator",
    "--field-match-separator",
];

/// Options under which a searcher runs a program of the caller's choosing:
/// a search with one is not masked.
const SEARCH_RUNNERS: &[&str] = &[
    "--pre",
    "--pre-glob",
    "-O",
    "--open-files-in-pager",
    "--search-zip",
    "-z",
    "--pager",
];

/// Message options of `git`, `gh` and `glab`: their value is text.
const MESSAGE_OPTIONS: &[&str] = &[
    "-m",
    "--message",
    "--body",
    "--title",
    "--notes",
    "--subject",
    "-b",
    "-t",
];

/// The line with every slot that only names something replaced by a neutral
/// word, or `None` when it holds none, or cannot be read.
pub(crate) fn masked(command: &str, cwd: Option<&str>) -> Option<String> {
    let tree = parse_bash(command)?;
    let root = tree.root_node();
    if root.has_error() {
        return None;
    }
    let source = command.as_bytes();
    if !reads_whole(root, source) {
        return None;
    }
    let relative_ok =
        cwd.is_none_or(work_folder) && changes_folder_only_to_work_folders(root, source);
    let mut edits: Vec<(usize, usize, String)> = Vec::new();
    let mut stack = vec![(root, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > 64 {
            return None;
        }
        match node.kind() {
            "heredoc_body" => heredoc_edit(node, source, relative_ok, &mut edits),
            "herestring_redirect" => herestring_edit(node, source, relative_ok, &mut edits),
            "command" => command_edits(node, source, relative_ok, &mut edits),
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push((child, depth + 1));
        }
    }
    if edits.is_empty() || runs_a_file_code_names(root, source) {
        return None;
    }
    edits.sort_by_key(|edit| (edit.0, std::cmp::Reverse(edit.1)));
    let mut out = String::with_capacity(command.len());
    let mut at = 0usize;
    for (start, end, with) in edits {
        if start < at {
            // Inside a slot already masked.
            continue;
        }
        out.push_str(&command[at..start]);
        out.push_str(&with);
        at = end;
    }
    out.push_str(&command[at..]);
    (out != command).then_some(out)
}

fn text<'a>(node: tree_sitter::Node<'_>, source: &'a [u8]) -> &'a str {
    std::str::from_utf8(&source[node.byte_range()]).unwrap_or("")
}

/// Whether a node runs nothing and expands nothing: what it shows is what
/// the program gets.
fn literal(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "expansion"
            | "simple_expansion"
            | "command_substitution"
            | "process_substitution"
            | "arithmetic_expansion"
            | "ansi_c_string"
            | "translated_string"
            | "brace_expression" => return false,
            "word" => {
                let word = text(node, source);
                if word.contains(['$', '`', '*', '?', '[', '{']) {
                    return false;
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    true
}

/// The text a literal word hands its program, as the shell reads it: the
/// quotes taken off, an escape read as the character it escapes, the parts
/// of a word written in several quotings joined.
fn unquoted(node: tree_sitter::Node<'_>, source: &[u8]) -> String {
    let shown = text(node, source);
    match node.kind() {
        "raw_string" => shown
            .strip_prefix('\'')
            .and_then(|rest| rest.strip_suffix('\''))
            .unwrap_or(shown)
            .to_string(),
        "string" => {
            let inner = shown
                .strip_prefix('"')
                .and_then(|rest| rest.strip_suffix('"'))
                .unwrap_or(shown);
            let mut out = String::with_capacity(inner.len());
            let mut chars = inner.chars().peekable();
            while let Some(c) = chars.next() {
                match (c, chars.peek()) {
                    ('\\', Some(next)) if matches!(next, '"' | '\\' | '$' | '`') => {
                        out.push(*next);
                        chars.next();
                    }
                    _ => out.push(c),
                }
            }
            out
        }
        "concatenation" => {
            let mut cursor = node.walk();
            let parts: Vec<String> = node
                .children(&mut cursor)
                .map(|part| unquoted(part, source))
                .collect();
            parts.concat()
        }
        _ => {
            let mut out = String::with_capacity(shown.len());
            let mut chars = shown.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    if let Some(next) = chars.next() {
                        out.push(next);
                    }
                } else if c != '\'' && c != '"' {
                    out.push(c);
                }
            }
            out
        }
    }
}

/// Whether a command sets variables for itself (`X=1 python3 -c ...`): one
/// may load code into the program (`PYTHONPATH`, `NODE_OPTIONS`,
/// `PERL5OPT`, `RUBYOPT`, `LD_PRELOAD`), so nothing of it is masked.
fn sets_its_environment(command: tree_sitter::Node<'_>) -> bool {
    let mut cursor = command.walk();
    let set = command
        .children(&mut cursor)
        .any(|child| child.kind() == "variable_assignment");
    set
}

/// Programs that only reshape the text they are handed: a command piped
/// into them hands what it prints to nothing that runs it.
const TEXT_FILTERS: &[&str] = &[
    "head", "tail", "sort", "uniq", "wc", "cut", "tr", "paste", "column", "cat", "grep", "egrep",
    "fgrep", "rg", "less", "more", "nl", "fold", "fmt", "tac", "rev", "jq", "awk", "gawk", "mawk",
];

/// Whether what a command prints goes nowhere that runs it: not into a
/// function, a substitution or a file, and through a pipe only into
/// [`TEXT_FILTERS`] (an `awk` whose program runs, pipes or writes
/// nothing). A mention masked in a command whose output is run (`cat
/// <<'EOF' | sh`, `f() { ... }; f | at now`) would hide the command run.
fn output_stays(command: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    output_stays_or_in_files(command, source, false)
}

/// [`output_stays`], where `files_ok` lets the output be written to a file
/// the line names: the redirect stays in the masked line, and is judged
/// there.
fn output_stays_or_in_files(command: tree_sitter::Node<'_>, source: &[u8], files_ok: bool) -> bool {
    let mut node = command;
    let mut steps = 0;
    while let Some(parent) = node.parent() {
        steps += 1;
        if steps > 64 {
            return false;
        }
        match parent.kind() {
            "function_definition" | "command_substitution" | "process_substitution" => {
                return false
            }
            "redirected_statement" => {
                let mut cursor = parent.walk();
                let writes =
                    parent
                        .children_by_field_name("redirect", &mut cursor)
                        .any(|redirect| {
                            redirect.kind() == "file_redirect" && writes_output(redirect, source)
                        });
                if writes && !files_ok {
                    return false;
                }
                // The grammar hangs what follows a here-document's start on
                // the redirect (`python3 - <<'EOF' | sh` holds the pipe to
                // `sh` inside it).
                let mut cursor = parent.walk();
                let carried = parent
                    .children_by_field_name("redirect", &mut cursor)
                    .filter(|redirect| redirect.kind() == "heredoc_redirect")
                    .all(|redirect| heredoc_carries_nothing(redirect, source));
                if !carried {
                    return false;
                }
            }
            "pipeline" => {
                // By place among the members, not by byte: a here-document's
                // body is written after the whole pipeline (`python3 - <<'EOF'
                // | sh`), so the member that owns it ends after `sh` starts.
                let mut cursor = parent.walk();
                let members: Vec<tree_sitter::Node<'_>> = parent
                    .named_children(&mut cursor)
                    .filter(|child| child.kind() != "comment")
                    .collect();
                let Some(at) = members.iter().position(|member| member.id() == node.id()) else {
                    return false;
                };
                let later = &members[at + 1..];
                if !later.iter().all(|child| only_reshapes(*child, source)) {
                    return false;
                }
            }
            _ => {}
        }
        node = parent;
    }
    true
}

/// Whether what the grammar hangs on a here-document's redirect after its
/// start hands the output to nothing that runs it: nothing, a redirect that
/// writes no file, or a pipe into [`TEXT_FILTERS`] only.
fn heredoc_carries_nothing(redirect: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let mut cursor = redirect.walk();
    let carried: Vec<tree_sitter::Node<'_>> = redirect
        .named_children(&mut cursor)
        .filter(|child| {
            !matches!(
                child.kind(),
                "heredoc_start" | "heredoc_body" | "heredoc_end"
            )
        })
        .collect();
    carried.iter().all(|child| match child.kind() {
        "file_redirect" => !writes_output(*child, source),
        "pipeline" => {
            let mut cursor = child.walk();
            let members: Vec<tree_sitter::Node<'_>> = child.named_children(&mut cursor).collect();
            members.iter().all(|member| only_reshapes(*member, source))
        }
        _ => false,
    })
}

/// Whether a file redirect sends a command's output to a file: `>`, `>>`,
/// `&>`, `>|` to anything but `/dev/null`, or `1>`; `2>` and a
/// duplication (`2>&1`) do not.
fn writes_output(redirect: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let shown = text(redirect, source).trim();
    let descriptor_err = shown.starts_with('2');
    let duplicates = shown.contains(">&") && !shown.starts_with("&>");
    let to_null = shown.ends_with("/dev/null");
    let reads = !shown.contains('>');
    !(descriptor_err || duplicates || to_null || reads)
}

/// Whether a piped-into command only reshapes text ([`TEXT_FILTERS`]).
fn only_reshapes(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let command = match node.kind() {
        "command" => node,
        "redirected_statement" => {
            let Some(body) = node
                .child_by_field_name("body")
                .filter(|b| b.kind() == "command")
            else {
                return false;
            };
            let mut cursor = node.walk();
            let writes = node
                .children_by_field_name("redirect", &mut cursor)
                .any(|redirect| {
                    redirect.kind() != "file_redirect" || writes_output(redirect, source)
                });
            if writes {
                return false;
            }
            body
        }
        _ => return false,
    };
    let Some((program, arguments)) = program_and_arguments(command, source) else {
        return false;
    };
    if !TEXT_FILTERS.contains(&program.as_str()) {
        return false;
    }
    if program.contains("awk") {
        return arguments.iter().all(|argument| {
            literal(*argument, source) && {
                let shown = text(*argument, source);
                !["system", "|", "getline", ">"]
                    .iter()
                    .any(|word| shown.contains(word))
            }
        });
    }
    arguments.iter().all(|argument| literal(*argument, source))
}

/// The program a command runs and its arguments, as nodes. A command whose
/// program word is not literal has none.
fn program_and_arguments<'t>(
    command: tree_sitter::Node<'t>,
    source: &[u8],
) -> Option<(String, Vec<tree_sitter::Node<'t>>)> {
    let name = command.child_by_field_name("name")?;
    if !literal(name, source) {
        return None;
    }
    let program = unquoted(name, source);
    let program = program
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut cursor = command.walk();
    let arguments = command
        .children_by_field_name("argument", &mut cursor)
        .collect();
    Some((program, arguments))
}

/// The interpreter a program name is, without its version (`python3.12`).
fn interpreter(program: &str) -> Option<&'static str> {
    let bare = program.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.iter().copied().find(|name| *name == bare)
}

/// Whether inline code may act on something of the guard's or an agent's.
/// `argv` is what the code is handed as its arguments, as the shell hands
/// them (`sys.argv`), and `expanded`: a word of the interpreter's line
/// the shell expands, so it may hand the code any path.
///
/// Python's code is read for the files it changes: every path given to
/// `open`, `Path` or a call of `os` or `shutil` that changes a file is a
/// literal, a name the code gives a literal, or one of its arguments, and
/// each lies in a project or a work folder ([`project_path`]). Code that
/// runs or signals something, reads code it does not show, or reaches a path
/// another way (the home, the environment, a pattern, a walk) may act. The
/// code of Node, Ruby and Perl may act as soon as it runs anything or
/// changes a file: it is rare in this work and read loosely.
pub(crate) fn code_may_act(
    code: &str,
    argv: &[String],
    expanded: bool,
    language: &str,
    relative_ok: bool,
) -> bool {
    if expanded {
        return true;
    }
    let lower = code.to_ascii_lowercase();
    // A path of an agent's settings or of the guard's own, anywhere in code
    // that writes, copies, moves or opens a file, is never a mention, through
    // a variable or not (`p=".claude/settings.json"; FileUtils.cp("x", p)`).
    let argv_lower = argv.join(" ").to_ascii_lowercase();
    let names_settings = SETTINGS_PLACES
        .iter()
        .any(|place| lower.contains(place) || argv_lower.contains(place));
    if names_settings && WRITES_A_FILE.iter().any(|call| lower.contains(call)) {
        return true;
    }
    if language != "python" {
        // A name built from escapes, character codes, a variable's sigil or
        // an index (`'\x65xecSync'`, `String.fromCharCode`, `&$f(...)`) is
        // a call the text does not show.
        return OTHER_RUNS.iter().any(|word| other_runs_word(&lower, word))
            || CHANGES_A_FILE.iter().any(|word| lower.contains(word))
            || lower.contains(['\\', '$', '[', '&', '%', '@'])
            || [
                "fromcharcode",
                "constructor",
                "globalthis",
                "global.",
                "module.",
                "chr",
                "pack",
                "this.",
            ]
            .iter()
            .any(|word| lower.contains(word));
    }
    if PYTHON_RUNS.iter().any(|word| lower.contains(word)) {
        return true;
    }
    // A name spelled with escapes (`'\163ystem'`, `'\x73ystem'`) is one the
    // text does not show.
    let escaped = code.as_bytes().windows(2).any(|pair| {
        pair[0] == b'\\'
            && (pair[1].is_ascii_digit() || matches!(pair[1], b'x' | b'u' | b'U' | b'N'))
    });
    if escaped {
        return true;
    }
    match python_file_targets(code, &lower, argv) {
        Some(targets) => !targets
            .iter()
            .all(|target| project_path(target, relative_ok)),
        None => true,
    }
}

/// Whether code holds one of [`OTHER_RUNS`]. `system` counts only as a word
/// of its own: `systemctl` in a string the code prints runs nothing
/// (`node -e "console.log('systemctl ...')"`, BI
/// FP-20261120-guard-words-in-interpreter-code).
fn other_runs_word(lower: &str, word: &str) -> bool {
    if word != "system" {
        return lower.contains(word);
    }
    lower.match_indices(word).any(|(at, _)| {
        !lower[at + word.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// The calls of Python that open or change a file, lowercase.
const PYTHON_FILE_CALLS: &[&str] = &[
    "open(",
    "path(",
    "os.remove(",
    "os.unlink(",
    "os.rename(",
    "os.renames(",
    "os.replace(",
    "os.chmod(",
    "os.lchmod(",
    "os.chown(",
    "os.lchown(",
    "os.symlink(",
    "os.link(",
    "os.makedirs(",
    "os.mkdir(",
    "os.rmdir(",
    "os.removedirs(",
    "os.truncate(",
    "os.utime(",
    "os.mkfifo(",
    "os.mknod(",
    "shutil.",
];

/// Every path the Python code gives a call of [`PYTHON_FILE_CALLS`], or
/// `None` when one is not a literal, a name given a literal, or an argument.
fn python_file_targets(code: &str, lower: &str, argv: &[String]) -> Option<Vec<String>> {
    let mut targets = Vec::new();
    // A name read once: code that opens the same name in every line of a
    // long edit is not scanned again for each.
    let mut known: std::collections::HashMap<String, Option<String>> =
        std::collections::HashMap::new();
    for call in PYTHON_FILE_CALLS {
        for (at, _) in lower.match_indices(call) {
            let open = at + call.len();
            let open = if call.ends_with('(') {
                open
            } else {
                // `shutil.<name>(`: the arguments after the name.
                open + code[open..].find('(')? + 1
            };
            for piece in call_arguments(&code[open..])? {
                let piece = piece.trim();
                let value = match known.get(piece) {
                    Some(value) => value.clone(),
                    None => {
                        let value = python_value(code, piece, argv, 0);
                        known.insert(piece.to_string(), value.clone());
                        value
                    }
                };
                targets.push(value?);
            }
        }
    }
    Some(targets)
}

/// The arguments of a call whose text starts right after its `(`, split at
/// the commas of its own level; keyword arguments left out.
fn call_arguments(text: &str) -> Option<Vec<&str>> {
    let mut pieces = Vec::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut start = 0usize;
    let mut escaped = false;
    for (at, c) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => quote = Some(c),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' if depth > 0 => depth -= 1,
            ')' => {
                pieces.push(&text[start..at]);
                return Some(
                    pieces
                        .into_iter()
                        .filter(|piece: &&str| {
                            let piece = piece.trim();
                            !piece.is_empty() && !keyword_argument(piece)
                        })
                        .collect(),
                );
            }
            ',' if depth == 0 => {
                pieces.push(&text[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    None
}

fn keyword_argument(piece: &str) -> bool {
    piece.split_once('=').is_some_and(|(name, value)| {
        !value.starts_with('=')
            && !name.is_empty()
            && name
                .trim()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// What a Python expression holds when it is a plain string literal, a name
/// the code only ever gives plain string literals, or `sys.argv[n]`.
fn python_value(code: &str, expression: &str, argv: &[String], depth: u8) -> Option<String> {
    if depth > 8 {
        return None;
    }
    if let Some(literal) = python_literal(expression) {
        return Some(literal);
    }
    if let Some(index) = expression
        .strip_prefix("sys.argv[")
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return argv.get(index.trim().parse::<usize>().ok()?).cloned();
    }
    if expression.is_empty()
        || !expression
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let mut values = Vec::new();
    for line in code.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix(expression) else {
            continue;
        };
        let rest = rest.trim_start();
        if rest.starts_with("==") {
            continue;
        }
        if let Some(value) = rest.strip_prefix('=') {
            let value = value.trim().split(';').next().unwrap_or("").trim();
            values
                .push(python_value(code, value, argv, depth + 1).filter(|_| value != expression)?);
        } else if rest.starts_with(['+', '-', '*', '/', '%', '|', '&', '^', ':', '[', '.'])
            && rest.contains('=')
        {
            // Changed in place, or given through an index or attribute.
            return None;
        }
    }
    // A name given in a loop, a `with` or a call's result is never plain.
    let bound_otherwise = code.lines().map(str::trim_start).any(|line| {
        let words: Vec<&str> = line
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .filter(|word| !word.is_empty())
            .collect();
        let named = words.contains(&expression);
        let unpacked = line.starts_with(&format!("{expression},"))
            || line.starts_with(&format!("{expression} ,"))
            || (line.contains(&format!(", {expression}"))
                && line.contains('=')
                && !line.contains('('));
        named
            && (line.starts_with("for ")
                || line.starts_with("with ")
                || line.contains(&format!("as {expression}"))
                || unpacked)
    });
    if values.is_empty() || bound_otherwise {
        return None;
    }
    Some(values.join("\n"))
}

/// A Python string literal with no prefix that changes what it holds.
fn python_literal(expression: &str) -> Option<String> {
    let expression = expression
        .strip_prefix('r')
        .or_else(|| expression.strip_prefix('b'))
        .unwrap_or(expression);
    for quote in ["'", "\""] {
        if let Some(inner) = expression
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            if !inner.contains(quote) && !inner.contains('\\') {
                return Some(inner.to_string());
            }
        }
    }
    None
}

/// Whether a path lies in a project or a work folder: relative (when the
/// folder it is read from is one, `relative_ok`) or under `/tmp` or a
/// home, through no hidden folder, and none of the guard's
/// files or programs ([`crate::threats::names_guard_carrier_path`]). A
/// value given to several names is each of its lines.
fn project_path(path: &str, relative_ok: bool) -> bool {
    path.lines().all(|path| {
        let lower = path.trim().to_ascii_lowercase();
        if crate::threats::names_guard_carrier_path(&lower) {
            return false;
        }
        let rest = if lower.starts_with('/') {
            let Some(rest) = ["/tmp/", "/home/", "/users/"]
                .iter()
                .find_map(|root| lower.strip_prefix(root))
            else {
                return false;
            };
            rest
        } else if lower.starts_with(['~', '$']) || !relative_ok {
            return false;
        } else {
            lower.as_str()
        };
        !rest
            .split('/')
            .any(|part| part.starts_with('.') && part != "." && part != "..")
    })
}

/// A here-document's body: masked when its reader keeps it as text, or runs
/// it as code that acts on nothing of the guard's.
fn heredoc_edit(
    body: tree_sitter::Node<'_>,
    source: &[u8],
    relative_ok: bool,
    edits: &mut Vec<(usize, usize, String)>,
) {
    if !literal(body, source) || !delimiter_quoted(body, source) {
        return;
    }
    let Some(owner) = crate::shell::heredoc_owner(body) else {
        return;
    };
    if !output_stays(owner, source) || sets_its_environment(owner) {
        return;
    }
    let Some((program, arguments)) = program_and_arguments(owner, source) else {
        return;
    };
    let words: Vec<String> = arguments.iter().map(|a| unquoted(*a, source)).collect();
    let content = text(body, source);
    let ending = if content.ends_with('\n') { "\n" } else { "" };
    let keeps = match program.as_str() {
        "git" | "gh" | "glab" => takes_message_from_stdin(&words),
        _ => false,
    };
    if keeps {
        edits.push((body.start_byte(), body.end_byte(), format!("text{ending}")));
        return;
    }
    let Some(language) = interpreter(&program) else {
        return;
    };
    let (argv, expanded) = stdin_argv(&arguments, &words, source);
    if !code_on_stdin(&words) || code_may_act(content, &argv, expanded, language, relative_ok) {
        return;
    }
    let neutral = if language == "python" {
        python_neutral(content, &argv)
    } else {
        neutral_code(language).to_string()
    };
    edits.push((
        body.start_byte(),
        body.end_byte(),
        format!("{neutral}{ending}"),
    ));
}

/// Whether a here-document's delimiter is quoted (`<<'EOF'`, `<<"EOF"`,
/// `<<\EOF`), so the shell hands its body over as written; an unquoted
/// one has the body expanded, and is never masked.
fn delimiter_quoted(body: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let Some(redirect) = body.parent() else {
        return false;
    };
    let mut cursor = redirect.walk();
    let quoted = redirect
        .children(&mut cursor)
        .find(|child| child.kind() == "heredoc_start")
        .is_some_and(|start| text(start, source).contains(['\'', '"', '\\']));
    quoted
}

/// A here-string: masked when it is a message or text read from stdin, or
/// code that acts on nothing of the guard's.
fn herestring_edit(
    redirect: tree_sitter::Node<'_>,
    source: &[u8],
    relative_ok: bool,
    edits: &mut Vec<(usize, usize, String)>,
) {
    let Some(value) = redirect.named_child((redirect.named_child_count() as u32).saturating_sub(1))
    else {
        return;
    };
    if !literal(value, source) {
        return;
    }
    let Some(owner) = crate::shell::heredoc_owner(redirect) else {
        return;
    };
    if !output_stays(owner, source) || sets_its_environment(owner) {
        return;
    }
    let Some((program, arguments)) = program_and_arguments(owner, source) else {
        return;
    };
    let words: Vec<String> = arguments.iter().map(|a| unquoted(*a, source)).collect();
    let keeps = match program.as_str() {
        "git" | "gh" | "glab" => takes_message_from_stdin(&words),
        _ => interpreter(&program).is_some_and(|language| {
            let (argv, expanded) = stdin_argv(&arguments, &words, source);
            code_on_stdin(&words)
                && !code_may_act(
                    &unquoted(value, source),
                    &argv,
                    expanded,
                    language,
                    relative_ok,
                )
        }),
    };
    if keeps {
        edits.push((value.start_byte(), value.end_byte(), "'text'".to_string()));
    }
}

/// `git commit -F -`, `git tag -F -`, `gh pr create --body-file -`: the
/// message comes from stdin.
fn takes_message_from_stdin(words: &[String]) -> bool {
    // The grammar drops a lone `-` before a here-document's start: `-F`
    // last is `-F -`.
    let last_reads_stdin = words.last().is_some_and(|word| {
        matches!(
            word.as_str(),
            "-F" | "--file" | "--body-file" | "--notes-file"
        )
    });
    last_reads_stdin
        || words.windows(2).any(|pair| {
            matches!(
                pair[0].as_str(),
                "-F" | "--file" | "--body-file" | "--notes-file"
            ) && pair[1] == "-"
        })
        || words.iter().any(|word| {
            matches!(
                word.as_str(),
                "--file=-" | "--body-file=-" | "--notes-file=-"
            )
        })
}

/// Whether an interpreter's stdin is its code: no script file is named
/// before `-` or `/dev/stdin`, and no option names code of its own.
fn code_on_stdin(words: &[String]) -> bool {
    for word in words {
        match word.as_str() {
            "-" | "/dev/stdin" => return true,
            "-c" | "-e" | "-E" | "-m" | "-r" | "--eval" | "--print" | "-p" | "--require" => {
                return false
            }
            _ if word.starts_with('-') => {}
            _ => return false,
        }
    }
    true
}

/// The arguments code read from stdin is handed (`sys.argv`: the `-` or
/// `/dev/stdin` and what follows), and whether a word of the line is
/// expanded by the shell.
fn stdin_argv(
    arguments: &[tree_sitter::Node<'_>],
    words: &[String],
    source: &[u8],
) -> (Vec<String>, bool) {
    let expanded = arguments.iter().any(|node| !literal(*node, source));
    let from = words
        .iter()
        .position(|word| word == "-" || word == "/dev/stdin")
        .unwrap_or(words.len());
    let mut argv: Vec<String> = words[from..].to_vec();
    if argv.is_empty() {
        argv.push("-".to_string());
    }
    (argv, expanded)
}

/// What Python code is masked to: a write of every file it opens or
/// changes, so a later command of the line that runs one of them is still
/// seen to run a file the line wrote; `pass` when it opens none.
fn python_neutral(code: &str, argv: &[String]) -> String {
    let lower = code.to_ascii_lowercase();
    let mut targets: Vec<String> = python_file_targets(code, &lower, argv)
        .unwrap_or_default()
        .iter()
        .flat_map(|target| target.lines().map(str::to_string).collect::<Vec<_>>())
        .filter(|target| !target.is_empty())
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return "pass".to_string();
    }
    targets
        .iter()
        .map(|target| format!("open('{target}', 'w').write('text')"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Code that does nothing, in each interpreter.
fn neutral_code(language: &str) -> &'static str {
    match language {
        "python" => "pass",
        _ => "1;",
    }
}

/// The slots of one command: inline code, a message, a search pattern, a
/// worktree, and a path through a folder named after the guard.
fn command_edits(
    command: tree_sitter::Node<'_>,
    source: &[u8],
    relative_ok: bool,
    edits: &mut Vec<(usize, usize, String)>,
) {
    let stays = output_stays(command, source);
    if !stays && !output_stays_or_in_files(command, source, true) {
        return;
    }
    let Some((program, arguments)) = program_and_arguments(command, source) else {
        return;
    };
    let words: Vec<String> = arguments.iter().map(|a| unquoted(*a, source)).collect();
    let literal_at = |at: usize| arguments.get(at).is_some_and(|a| literal(*a, source));
    if !stays {
        // What the line writes to a file it names is kept, with its
        // redirect, in the masked line: a build's output to a log, and a
        // note's text to a note.
        if program == "cargo" {
            let mut mask = |at: usize, with: &str| {
                if let Some(node) = arguments.get(at) {
                    edits.push((node.start_byte(), node.end_byte(), with.to_string()));
                }
            };
            build_target_edits(&words, &literal_at, &mut mask);
        } else if matches!(program.as_str(), "echo" | "printf")
            && !words.iter().any(|word| word == "-v")
            && writes_only_notes(command, source, relative_ok)
        {
            for argument in &arguments {
                if !unquoted(*argument, source).starts_with('-') {
                    note_text_edits(*argument, source, edits);
                }
            }
        }
        return;
    }
    let mut mask = |at: usize, with: &str| {
        if let Some(node) = arguments.get(at) {
            edits.push((node.start_byte(), node.end_byte(), with.to_string()));
        }
    };
    if let Some(language) = interpreter(&program) {
        if sets_its_environment(command) {
            return;
        }
        let code_options: &[&str] = match language {
            "python" => &["-c"],
            "node" | "nodejs" => &["-e", "--eval", "-p", "--print"],
            _ => &["-e", "-E"],
        };
        if let Some(at) = words
            .iter()
            .position(|w| code_options.contains(&w.as_str()))
        {
            let mut argv = vec![words[at].clone()];
            argv.extend(words.iter().skip(at + 2).cloned());
            let expanded = arguments
                .iter()
                .enumerate()
                .any(|(index, node)| index != at + 1 && !literal(*node, source));
            let code = arguments.get(at + 1).map(|node| unquoted(*node, source));
            if literal_at(at + 1)
                && code
                    .as_deref()
                    .is_some_and(|code| !code_may_act(code, &argv, expanded, language, relative_ok))
            {
                let neutral = match (language, code.as_deref()) {
                    ("python", Some(code)) => python_neutral(code, &argv).replace('\'', "\""),
                    _ => neutral_code(language).to_string(),
                };
                mask(at + 1, &format!("'{neutral}'"));
            }
        }
        return;
    }
    match program.as_str() {
        "git" | "gh" | "glab" => {
            for (at, word) in words.iter().enumerate() {
                // `git commit -am`: a cluster of git's short flags that
                // ends in `m` takes the message as `-m` does.
                let message_cluster = program == "git"
                    && word.len() > 2
                    && word.starts_with('-')
                    && !word.starts_with("--")
                    && word.ends_with('m')
                    && word[1..].chars().all(|c| c.is_ascii_alphabetic());
                if (MESSAGE_OPTIONS.contains(&word.as_str()) || message_cluster)
                    && literal_at(at + 1)
                {
                    mask(at + 1, "'text'");
                } else if let Some((option, _)) = word.split_once('=') {
                    if MESSAGE_OPTIONS.contains(&option) && literal_at(at) {
                        mask(at, &format!("{option}=text"));
                    }
                }
            }
            if program == "git" {
                let at = git_verb_positions(&words);
                let verbs: Vec<&str> = at.iter().map(|i| words[*i].as_str()).collect();
                if verbs.first() == Some(&"grep") {
                    let from = at[0] + 1;
                    search_pattern_edits(&words[from..], from, &literal_at, &mut mask);
                }
                if verbs.first() == Some(&"worktree") && verbs.get(1) == Some(&"remove") {
                    let from = at[1] + 1;
                    // A relative worktree is read in the folder `-C` names.
                    let folder = git_folder(&words[..at[0]]);
                    for (at, word) in words.iter().enumerate().skip(from) {
                        let path = match &folder {
                            Some(folder) if !word.starts_with(['/', '~', '$']) => {
                                format!("{}/{word}", folder.trim_end_matches('/'))
                            }
                            _ => word.clone(),
                        };
                        if !word.starts_with('-')
                            && literal_at(at)
                            && work_folder(&path)
                            && !names_guard_folder_by_name(word)
                        {
                            mask(at, "wt");
                        }
                    }
                }
            }
        }
        _ if SEARCHERS.contains(&program.as_str()) => {
            search_pattern_edits(&words, 0, &literal_at, &mut mask);
        }
        "cargo" => build_target_edits(&words, &literal_at, &mut mask),
        _ => {}
    }
    // A path through a folder whose name holds the guard's, in a project or
    // a work folder: a repository or a worktree, not one of the guard's
    // places. A folder the line changes to is kept: it is where the rest of
    // the line runs.
    if matches!(program.as_str(), "cd" | "pushd")
        || words.iter().any(|word| word == "cd" || word == "pushd")
    {
        return;
    }
    let mut cursor = command.walk();
    let values: Vec<tree_sitter::Node<'_>> = command
        .children(&mut cursor)
        .filter(|child| child.kind() == "variable_assignment")
        .filter_map(|assignment| assignment.child_by_field_name("value"))
        .chain(arguments.iter().copied())
        .collect();
    for node in values {
        if !literal_or_home(node, source) {
            continue;
        }
        let shown = text(node, source);
        if work_folder_path(&shown.replace(['\'', '"'], "")) {
            let renamed = replace_ignoring_case(shown, "innerwarden", "proj");
            if renamed != shown {
                edits.push((node.start_byte(), node.end_byte(), renamed));
            }
        }
    }
}

/// git's options before its verb whose value is the next word: the folder
/// it runs in (`-C`), its repository and work tree, a setting, a
/// namespace. Their value is no verb.
const GIT_VALUE_OPTIONS: &[&str] = &["-C", "--git-dir", "--work-tree", "-c", "--namespace"];

/// The folder git's `-C` options before its verb name, each relative to
/// the one before; `None` without one, or when one is not a literal word.
fn git_folder(options: &[String]) -> Option<String> {
    let mut folder: Option<String> = None;
    let mut at = 0;
    while at < options.len() {
        if options[at] == "-C" {
            let value = options.get(at + 1)?;
            folder = Some(match folder {
                Some(before) if !value.starts_with(['/', '~', '$']) => {
                    format!("{}/{value}", before.trim_end_matches('/'))
                }
                _ => value.clone(),
            });
            at += 2;
            continue;
        }
        at += if GIT_VALUE_OPTIONS.contains(&options[at].as_str()) {
            2
        } else {
            1
        };
    }
    folder
}

/// Whether a worktree named by `word` may be one of the guard's folders:
/// git finds a worktree by the end of its path as well as by its path
/// (`git worktree remove innerwarden` removes a worktree at
/// `~/.config/innerwarden`, and so does `config/innerwarden`), so a word
/// whose last part is the guard's name is never read as a work folder.
///
/// A word with a `.` or `..` part (`../innerwarden`) is never the end of
/// a worktree's path, which git keeps whole: git reads it from the working
/// folder, and [`work_folder`] decides.
fn names_guard_folder_by_name(word: &str) -> bool {
    // `innerwarden/.`, `./innerwarden` and `innerwarden/./` name the
    // same path as `innerwarden`: a `.` part is dropped first.
    let lower = word.trim_matches(['"', '\'']).to_ascii_lowercase();
    let absolute = lower.starts_with('/');
    let lower = lower
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>()
        .join("/");
    let lower = if absolute { format!("/{lower}") } else { lower };
    if lower.split('/').any(|part| part == "..") {
        return false;
    }
    let last = lower.rsplit('/').next().unwrap_or(&lower);
    GUARD_PROGRAMS.contains(&last)
}

/// Where git's verb and the word after it are among `words` (a git
/// line's arguments): the first two words that are not options, the value
/// of an option before the verb ([`GIT_VALUE_OPTIONS`]) skipped. `git -C
/// ~/repo worktree remove ../wt` is `worktree remove`, not `~/repo
/// worktree` (BI FP-20261122-git-C-innerwarden-path-worktree-remove).
fn git_verb_positions(words: &[String]) -> Vec<usize> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < words.len() && found.len() < 2 {
        let word = words[at].as_str();
        if found.is_empty() && GIT_VALUE_OPTIONS.contains(&word) {
            at += 2;
            continue;
        }
        if !word.starts_with('-') {
            found.push(at);
        }
        at += 1;
    }
    found
}

/// Subcommands of `cargo` that build, check or test what the project holds
/// and run none of its programs as the line asks: `run` and `install` are
/// not here.
const CARGO_BUILDS: &[&str] = &[
    "test", "t", "build", "b", "check", "c", "clippy", "bench", "doc", "d", "nextest", "tree",
];

/// Options of `cargo` whose value names a package or a target of the
/// project.
const CARGO_TARGET_OPTIONS: &[&str] =
    &["-p", "--package", "--bin", "--test", "--example", "--bench"];

/// A package or a target named after the guard, in a build, a check or a
/// test of the project: `cargo test -p innerwarden --bin innerwarden contain`
/// filters the project's tests by `contain`, it starts no jail (BI
/// FP-20261120-repo-name-and-literal-variable, measured 2026-11-21 against
/// main fa63f83). `cargo run` keeps the name: it runs what it builds.
fn build_target_edits(
    words: &[String],
    literal_at: &dyn Fn(usize) -> bool,
    mask: &mut dyn FnMut(usize, &str),
) {
    let verb = words
        .iter()
        .find(|word| !word.starts_with('-') && !word.starts_with('+'));
    if !verb.is_some_and(|verb| CARGO_BUILDS.contains(&verb.as_str())) {
        return;
    }
    for (at, word) in words.iter().enumerate() {
        if CARGO_TARGET_OPTIONS.contains(&word.as_str())
            && literal_at(at + 1)
            && words
                .get(at + 1)
                .is_some_and(|value| GUARD_PROGRAMS.contains(&value.as_str()))
        {
            mask(at + 1, "proj");
        } else if let Some((option, value)) = word.split_once('=') {
            if CARGO_TARGET_OPTIONS.contains(&option)
                && literal_at(at)
                && GUARD_PROGRAMS.contains(&value)
            {
                mask(at, &format!("{option}=proj"));
            }
        }
    }
}

/// Files an agent reads as its instructions: text written to one is an
/// order, not a note.
const INSTRUCTION_FILES: &[&str] = &[
    "claude.md",
    "claude.local.md",
    "agents.md",
    "gemini.md",
    "copilot-instructions.md",
];

/// Whether every file the command's output is written to is a note: a
/// `.md`, `.txt` or `.log` file under the home or in the project, through
/// no hidden folder, and not one an agent reads as its instructions.
fn writes_only_notes(command: tree_sitter::Node<'_>, source: &[u8], relative_ok: bool) -> bool {
    let Some(parent) = command
        .parent()
        .filter(|p| p.kind() == "redirected_statement")
    else {
        return false;
    };
    let mut cursor = parent.walk();
    let redirects: Vec<tree_sitter::Node<'_>> = parent
        .children_by_field_name("redirect", &mut cursor)
        .collect();
    let mut wrote = false;
    for redirect in redirects {
        if redirect.kind() != "file_redirect" {
            return false;
        }
        if !writes_output(redirect, source) {
            continue;
        }
        let Some(destination) = redirect.child_by_field_name("destination") else {
            return false;
        };
        if !literal_or_home(destination, source) && !text(destination, source).starts_with("~/") {
            return false;
        }
        let path = unquoted(destination, source);
        if !note_path(&path, relative_ok) {
            return false;
        }
        wrote = true;
    }
    wrote
}

/// Whether a path is a note ([`writes_only_notes`]).
fn note_path(path: &str, relative_ok: bool) -> bool {
    let lower = path.to_ascii_lowercase();
    let rest = if let Some(rest) = lower
        .strip_prefix("~/")
        .or_else(|| lower.strip_prefix("$home/"))
    {
        rest
    } else if lower.starts_with('/') || lower.starts_with('~') || lower.starts_with('$') {
        return false;
    } else if relative_ok {
        lower.as_str()
    } else {
        return false;
    };
    if rest.contains(['$', '`', '\\', '*', '?', '[', '{']) || rest.contains(char::is_whitespace) {
        return false;
    }
    let mut parts = rest
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".");
    if parts.clone().any(|part| part.starts_with('.')) {
        return false;
    }
    let Some(name) = parts.next_back() else {
        return false;
    };
    [".md", ".txt", ".log"]
        .iter()
        .any(|end| name.ends_with(end))
        && !INSTRUCTION_FILES.contains(&name)
        && !lower.contains("innerwarden/guard")
}

/// The text of a note (`echo`, `printf`) masked, with every expansion and
/// substitution in it kept: bash runs a substitution whatever word it
/// stands in (`echo "$(date -u) ..." >> notes.md`).
fn note_text_edits(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    edits: &mut Vec<(usize, usize, String)>,
) {
    if literal(node, source) {
        let with = if node.kind() == "string_content" {
            "text"
        } else {
            "'text'"
        };
        edits.push((node.start_byte(), node.end_byte(), with.to_string()));
        return;
    }
    if !matches!(node.kind(), "string" | "concatenation") {
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string_content" => {
                edits.push((child.start_byte(), child.end_byte(), "text".to_string()));
            }
            "string" | "concatenation" | "word" | "raw_string" => {
                note_text_edits(child, source, edits);
            }
            _ => {}
        }
    }
}

/// [`literal`], or a word that starts with `$HOME/` and is literal after it.
fn literal_or_home(node: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    if literal(node, source) {
        return true;
    }
    let shown = text(node, source);
    let rest = shown
        .strip_prefix("$HOME/")
        .or_else(|| shown.strip_prefix("\"$HOME\"/"))
        .or_else(|| shown.strip_prefix("\"$HOME/"));
    rest.is_some_and(|rest| !rest.contains(['$', '`', '\\', '*', '?', '[', '{']))
}

/// The pattern of a search: the value of each `-e`/`--regexp`, else the
/// first word that is not an option.
fn search_pattern_edits(
    words: &[String],
    offset: usize,
    literal_at: &dyn Fn(usize) -> bool,
    mask: &mut dyn FnMut(usize, &str),
) {
    let runs = words.iter().any(|word| {
        SEARCH_RUNNERS.iter().any(|runner| {
            word == runner
                || word.starts_with(&format!("{runner}="))
                || (runner.len() == 2
                    && !word.starts_with("--")
                    && word.starts_with('-')
                    && word.contains(&runner[1..]))
        })
    });
    if runs {
        return;
    }
    let mut given = false;
    let mut at = 0usize;
    while at < words.len() {
        let word = words[at].as_str();
        if word == "--" {
            at += 1;
            break;
        }
        if word == "-e" || word == "--regexp" {
            if literal_at(offset + at + 1) {
                mask(offset + at + 1, "'pattern'");
            }
            given = true;
            at += 2;
            continue;
        }
        if word == "-f" || word == "--file" {
            given = true;
        }
        if SEARCH_VALUE_OPTIONS.contains(&word) {
            at += 2;
            continue;
        }
        if word.starts_with('-') && word.len() > 1 {
            at += 1;
            continue;
        }
        if !given && literal_at(offset + at) {
            mask(offset + at, "'pattern'");
        }
        return;
    }
    if !given && at < words.len() && literal_at(offset + at) {
        mask(offset + at, "'pattern'");
    }
}

/// Whether a path names a folder of a project or a work folder through a
/// folder whose name holds the guard's: under the home or relative, through
/// no hidden folder, and not ending in one of the guard's programs or units.
pub(crate) fn work_folder_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if !lower.contains("innerwarden") || !lower.contains('/') || lower.contains(char::is_whitespace)
    {
        return false;
    }
    let (rest, relative) = if let Some(rest) = lower
        .strip_prefix("~/")
        .or_else(|| lower.strip_prefix("$home/"))
    {
        (rest, false)
    } else if let Some(rest) = lower
        .strip_prefix("/home/")
        .or_else(|| lower.strip_prefix("/users/"))
    {
        match rest.split_once('/') {
            Some((_, rest)) => (rest, false),
            None => return false,
        }
    } else if lower.starts_with('/') || lower.starts_with('~') || lower.starts_with('$') {
        return false;
    } else {
        (lower.as_str(), true)
    };
    let parts: Vec<&str> = rest
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    if parts.iter().any(|part| hidden_part(part)) || leaves_a_folder(&parts, relative) {
        return false;
    }
    let Some(last) = parts.last() else {
        return false;
    };
    !GUARD_PROGRAMS.contains(last)
        && !last.starts_with("innerwarden-")
        && !last.ends_with(".service")
        && !crate::threats::names_guard_carrier_path(&lower)
}

/// Whether a folder is a project or a work folder: under the home, `/tmp`
/// or relative, through no hidden folder and none of the guard's places.
fn work_folder(folder: &str) -> bool {
    let lower = folder.trim_end_matches('/').to_ascii_lowercase();
    if crate::threats::names_guard_carrier_path(&lower) {
        return false;
    }
    let (rest, relative) = if let Some(rest) = lower
        .strip_prefix("~/")
        .or_else(|| lower.strip_prefix("$home/"))
        .or_else(|| lower.strip_prefix("/tmp/"))
    {
        (rest, false)
    } else if let Some(rest) = lower
        .strip_prefix("/home/")
        .or_else(|| lower.strip_prefix("/users/"))
    {
        (rest, false)
    } else if lower.starts_with(['/', '~', '$']) {
        return false;
    } else {
        (lower.as_str(), true)
    };
    let parts: Vec<&str> = rest
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    !parts.iter().any(|part| hidden_part(part)) && !leaves_a_folder(&parts, relative)
}

/// Whether a path goes back out of a folder it named: a `..` after a
/// folder of its own (`.worktrees/../x`, `wt/../../x`), or any `..` in
/// a path from the home or `/tmp`. What such a path names is no longer
/// read from its words, so it is not taken as a work folder. A relative
/// path that starts with `..` names a folder beside the project, as
/// before.
fn leaves_a_folder(parts: &[&str], relative: bool) -> bool {
    if relative {
        parts
            .iter()
            .skip_while(|part| **part == "..")
            .any(|part| *part == "..")
    } else {
        parts.contains(&"..")
    }
}

/// Whether a part of a path is a hidden folder, where settings and the
/// guard's own places live (`.config`, `.claude`, `.local`). `.` and
/// `..` are no folder of their own, and `.worktrees`, the folder a
/// repository's worktrees are commonly kept in, holds checkouts only.
fn hidden_part(part: &str) -> bool {
    part.starts_with('.') && !matches!(part, "." | ".." | ".worktrees")
}

/// Whether an expansion is `$HOME` on a line that never names `HOME`
/// otherwise: no `HOME=`, `export HOME`, `read HOME`, `for HOME in`
/// or `unset HOME` can have changed what it stands for.
fn home_kept(expansion: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    if text(expansion, source) != "$HOME" {
        return false;
    }
    // The shell joins a word's pieces before it reads a name, so
    // `HO""ME=`, `H"O"ME`, `HO\ME` and `printf -v HO''ME` all name
    // `HOME`: the line is searched with its quotes and escapes taken out.
    let line: String = String::from_utf8_lossy(source)
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect();
    line.match_indices("HOME")
        .all(|(at, _)| line[..at].ends_with('$'))
}

/// Programs that run what they read or are handed as words: text masked
/// elsewhere on their line may reach them.
const WORD_RUNNERS: &[&str] = &[
    "xargs", "parallel", "eval", "source", ".", "exec", "rush", "sem",
];

/// Whether a substitution runs only `date`, with literal arguments and no
/// option that reads a file or sets the clock.
fn only_the_date(substitution: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let mut cursor = substitution.walk();
    let inner: Vec<tree_sitter::Node<'_>> = substitution
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment")
        .collect();
    let [command] = inner.as_slice() else {
        return false;
    };
    if command.kind() != "command" || sets_its_environment(*command) {
        return false;
    }
    let Some((program, arguments)) = program_and_arguments(*command, source) else {
        return false;
    };
    program == "date"
        && arguments.iter().all(|argument| {
            literal(*argument, source) && {
                let word = unquoted(*argument, source);
                !["-f", "--file", "-r", "--reference", "-s", "--set"]
                    .iter()
                    .any(|option| word.starts_with(option))
            }
        })
}

/// Whether the line can be masked at all: it expands nothing (no variable,
/// substitution or arithmetic the shell fills in, so no `$_`, `$PWD` or
/// `$(pwd)` hands a masked word on to a later command), runs no program
/// named by an expansion, runs nothing of [`WORD_RUNNERS`] nor a `find` or
/// `fd` that runs a command per file, and has no here-document the
/// grammar may have cut at the wrong line (a body line that is its
/// delimiter: `<<E''` ends at a bare `E`).
fn reads_whole(root: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let mut stack = vec![(root, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > 64 {
            return false;
        }
        match node.kind() {
            // `$(date -u '+%F')` in a note: its output is the time, whatever
            // word the line masks.
            "command_substitution" if only_the_date(node, source) => continue,
            // `$HOME` is the home, as `~` is, on a line that sets no
            // `HOME` of its own: what a path through it names is read
            // as the same path under `~`.
            "simple_expansion" if home_kept(node, source) => continue,
            "expansion"
            | "simple_expansion"
            | "command_substitution"
            | "process_substitution"
            | "arithmetic_expansion"
            | "ansi_c_string"
            | "translated_string" => return false,
            "command" => {
                let Some((program, arguments)) = program_and_arguments(node, source) else {
                    return false;
                };
                if WORD_RUNNERS.contains(&program.as_str()) {
                    return false;
                }
                let runs_per_file = matches!(program.as_str(), "find" | "fd" | "fdfind")
                    && arguments.iter().any(|argument| {
                        let word = text(*argument, source);
                        word.starts_with("-exec")
                            || word.starts_with("-ok")
                            || matches!(word, "-x" | "-X" | "--exec" | "--exec-batch")
                    });
                if runs_per_file {
                    return false;
                }
            }
            "heredoc_redirect" => {
                let mut cursor = node.walk();
                let children: Vec<tree_sitter::Node<'_>> = node.children(&mut cursor).collect();
                let delimiter = children
                    .iter()
                    .find(|child| child.kind() == "heredoc_start")
                    .map(|start| text(*start, source).replace(['\'', '"', '\\'], ""));
                let body = children.iter().find(|child| child.kind() == "heredoc_body");
                if let (Some(delimiter), Some(body)) = (delimiter, body) {
                    let cut = text(*body, source)
                        .lines()
                        .any(|line| line.trim_start_matches('\t') == delimiter.trim());
                    if cut {
                        return false;
                    }
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push((child, depth + 1));
        }
    }
    true
}

/// Programs that run the file they are handed as a script, or run their
/// arguments as a program.
const FILE_RUNNERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "fish",
    "tcsh",
    "csh",
    "busybox",
    "source",
    ".",
    "exec",
    "python",
    "python3",
    "node",
    "nodejs",
    "ruby",
    "perl",
    "php",
    "env",
    "xargs",
    "at",
    "batch",
    "crontab",
    "nohup",
    "timeout",
    "nice",
    "sudo",
    "doas",
    "setsid",
    "stdbuf",
    "make",
    "awk",
    "gawk",
    "systemd-run",
    "watch",
    "parallel",
    "time",
    "command",
    "builtin",
    "eval",
];

/// Whether the line runs a file that the inline code of its interpreters
/// opens (`python3 - <<'EOF' ... open('n.sh', 'w') ... EOF` then `sh n.sh`):
/// masking that code would hide what the file holds from the command that
/// runs it, so nothing is masked. A file is matched by its last part.
fn runs_a_file_code_names(root: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let mut named: Vec<String> = Vec::new();
    let mut commands = Vec::new();
    let mut stack = vec![(root, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > 64 {
            return true;
        }
        match node.kind() {
            "heredoc_body"
            | "herestring_redirect"
            | "string"
            | "raw_string"
            | "word"
            | "concatenation" => {
                // The text the program gets: a word's own quotes are not a
                // string of the code it holds.
                let shown_owned = if node.kind() == "heredoc_body" {
                    text(node, source).to_string()
                } else {
                    unquoted(node, source)
                };
                let shown = shown_owned.as_str();
                for (at, _) in shown
                    .match_indices("open(")
                    .chain(shown.match_indices("Path("))
                {
                    if let Some(pieces) = call_arguments(&shown[at + 5..]) {
                        named.extend(
                            pieces
                                .iter()
                                .filter_map(|piece| python_literal(piece.trim()))
                                .filter_map(|path| last_part(&path)),
                        );
                    }
                }
                for line in shown.lines() {
                    if let Some((_, value)) = line.split_once('=') {
                        if let Some(path) =
                            python_literal(value.trim().split(';').next().unwrap_or("").trim())
                        {
                            named.extend(last_part(&path));
                        }
                    }
                }
                // Every string the code holds may be a file it writes, by a
                // call this reading does not list (`shutil.copy`, `os.rename`).
                named.extend(
                    string_literals(shown)
                        .iter()
                        .filter_map(|path| last_part(path)),
                );
            }
            "command" => commands.push(node),
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push((child, depth + 1));
        }
    }
    if named.is_empty() {
        return false;
    }
    let names = |word: &str| last_part(word).is_some_and(|part| named.contains(&part));
    commands.into_iter().any(|command| {
        // The `date` of a note's time runs nothing it is handed.
        if command.parent().is_some_and(|parent| {
            parent.kind() == "command_substitution" && only_the_date(parent, source)
        }) {
            return false;
        }
        let Some(name) = command.child_by_field_name("name") else {
            return false;
        };
        let program = unquoted(name, source);
        if names(&program) {
            return true;
        }
        let program = program
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let bare = program.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
        let runner = FILE_RUNNERS.contains(&bare) || FILE_RUNNERS.contains(&program.as_str());
        // What the command is handed: its words, and the files its redirects
        // name, on the command or on the statement around it (`sh < x.sh`,
        // `bash -s < x.sh`).
        let mut cursor = command.walk();
        let mut touched: Vec<String> = command
            .children_by_field_name("argument", &mut cursor)
            .map(|argument| unquoted(argument, source))
            .collect();
        touched.extend(redirect_targets(command, source));
        if !touched.iter().any(|word| names(word)) {
            return false;
        }
        // Run by it, or printed to a runner (`cat x.sh | sh`).
        runner || !output_stays(command, source)
    })
}

/// The files the redirects of a command name, on the command itself and on
/// each statement around it that hangs redirects on it.
fn redirect_targets(command: tree_sitter::Node<'_>, source: &[u8]) -> Vec<String> {
    let mut targets = Vec::new();
    let mut node = Some(command);
    let mut steps = 0;
    while let Some(at) = node {
        steps += 1;
        if steps > 64 {
            break;
        }
        let mut cursor = at.walk();
        for child in at.children(&mut cursor) {
            if child.kind() == "file_redirect" {
                if let Some(destination) = child.child_by_field_name("destination") {
                    targets.push(unquoted(destination, source));
                } else if let Some(last) =
                    child.named_child((child.named_child_count() as u32).saturating_sub(1))
                {
                    targets.push(unquoted(last, source));
                }
            }
        }
        node = at
            .parent()
            .filter(|parent| matches!(parent.kind(), "redirected_statement" | "pipeline" | "list"));
    }
    targets
}

/// The quoted strings of a text, read loosely: each run between a quote and
/// the same quote on one line.
fn string_literals(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines() {
        let mut rest = line;
        while let Some(start) = rest.find(['\'', '"']) {
            let quote = rest[start..].chars().next().unwrap_or('\'');
            let after = &rest[start + 1..];
            let Some(end) = after.find(quote) else {
                break;
            };
            let inner = &after[..end];
            if !inner.is_empty() && !inner.contains(char::is_whitespace) {
                found.push(inner.to_string());
            }
            rest = &after[end + 1..];
        }
    }
    found
}

/// The last part of a path, lowercase; none for an empty one.
fn last_part(path: &str) -> Option<String> {
    path.trim()
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|part| !part.is_empty())
        .map(str::to_ascii_lowercase)
}

/// Whether every change of folder on the line (`cd`, `pushd`) goes to a
/// work folder the line spells out ([`work_folder`]): a relative path in
/// code is then read from one.
fn changes_folder_only_to_work_folders(root: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let mut stack = vec![(root, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > 64 {
            return false;
        }
        if node.kind() == "command" {
            let Some((program, arguments)) = program_and_arguments(node, source) else {
                return false;
            };
            // `cd` run as itself, or behind a wrapper (`env A=1 cd ...`,
            // `sudo cd ...`): the words after it name the folder.
            let after = if program == "cd" || program == "pushd" {
                Some(&arguments[..])
            } else {
                arguments
                    .iter()
                    .position(|argument| {
                        matches!(unquoted(*argument, source).as_str(), "cd" | "pushd")
                    })
                    .map(|at| &arguments[at + 1..])
            };
            if let Some(after) = after {
                let target: Vec<_> = after
                    .iter()
                    .filter(|argument| !text(**argument, source).starts_with('-'))
                    .collect();
                let fine = match target.as_slice() {
                    [one] => {
                        literal_or_home(**one, source) && work_folder(&unquoted(**one, source))
                    }
                    _ => false,
                };
                if !fine {
                    return false;
                }
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push((child, depth + 1));
        }
    }
    true
}

fn replace_ignoring_case(text: &str, needle: &str, with: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut at = 0usize;
    while let Some(found) = lower[at..].find(needle) {
        out.push_str(&text[at..at + found]);
        out.push_str(with);
        at += found + needle.len();
    }
    out.push_str(&text[at..]);
    out
}

#[cfg(test)]
mod tests {
    use super::{code_may_act, masked, work_folder_path};

    /// FAILS ON REVERT of [`super::output_stays`]: each slot was masked
    /// though its output is run.
    #[test]
    fn a_slot_whose_output_is_run_is_not_masked() {
        for line in [
            "python3 - <<'EOF' | sh\nprint('x')\nEOF",
            "python3 -c \"print('x')\" | bash",
            "python3 -c \"print('x')\" > x.sh && sh x.sh",
            "f() { python3 -c \"print('x')\"; }; f | sh",
            "grep -e x f | xargs kill",
            "x=$(python3 -c \"print('x')\"); $x",
            "python3 - <<'EOF'\np='n.sh'\nopen(p,'w').write('x')\nEOF\nsh n.sh",
        ] {
            assert_eq!(masked(line, None), None, "{line}");
        }
    }

    #[test]
    fn a_data_slot_is_masked() {
        for line in [
            "git commit -m 'x y'",
            "gh pr create --body 'x y'",
            "grep -rn -e x src | head",
            "git grep -n 'x' origin/main -- src",
            "git worktree remove ../work-x",
            "python3 -c \"print(open('a.json').read())\" | head",
            "git commit -F - <<'EOF'\nx\nEOF",
        ] {
            assert!(masked(line, None).is_some(), "{line}");
        }
        assert_eq!(masked("rg --pre ./x.sh x .", None), None);
        assert_eq!(masked("git grep -O'less' x", None), None);
    }

    #[test]
    fn code_that_runs_or_writes_outside_the_project_may_act() {
        let argv = ["-".to_string()];
        for code in [
            "import os\nos.system('x')",
            "import subprocess\nsubprocess.run(['x'])",
            "open('/etc/x.toml','w')",
            "open('../.claude/settings.json','w')",
            "import os\nopen(os.path.expanduser('~/x'),'w')",
            "p=q\nq=p\nopen(p,'w')",
            "import psutil\n[p.kill() for p in psutil.process_iter()]",
        ] {
            assert!(code_may_act(code, &argv, false, "python", true), "{code}");
        }
        assert!(code_may_act(
            "open(sys.argv[1],'w')",
            &argv,
            true,
            "python",
            true
        ));
        assert!(code_may_act(
            "open('notes.md','w')",
            &argv,
            false,
            "python",
            false
        ));
        assert!(code_may_act(
            "File.write('a', 'b')",
            &argv,
            false,
            "ruby",
            true
        ));
        for code in [
            "p = 'src/rules.rs'\ns = open(p).read()\nopen(p, 'w').write(s.replace('a', 'b'))",
            "import json\nprint(json.load(open('report.json'))['x'])",
        ] {
            assert!(!code_may_act(code, &argv, false, "python", true), "{code}");
        }
    }

    #[test]
    fn a_work_folder_path_is_not_one_of_the_guards_places() {
        for path in [
            "~/work/innerwarden/x",
            "/home/u/innerwarden/wt-1",
            "../innerwarden-wt/a",
        ] {
            assert!(work_folder_path(path), "{path}");
        }
        for path in [
            "~/.config/innerwarden/x",
            "/etc/innerwarden/guard.toml",
            "~/innerwarden/bin/innerwarden",
            "~/work/innerwarden/innerwarden-agent.service",
            "~/.local/bin/innerwarden",
            "innerwarden",
        ] {
            assert!(!work_folder_path(path), "{path}");
        }
    }
}
