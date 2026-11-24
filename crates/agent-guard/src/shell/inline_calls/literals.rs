//! Where the strings of Perl, PHP and Lua code stand, and whether the code
//! around them calls only what starts no process.
//!
//! The rule of [`super::data_literals_blanked`] for Python, Node and Ruby,
//! for the other languages the reader reads: a string the code only prints,
//! edits or writes is not a line any process runs. Measured 2026-11-20 on
//! main: `perl -e 'print q{rm -rf "$dir"/build}'` and `lua -e
//! 'print("rm -rf $dir/build")'` were refused as a removal. These
//! languages reach a process in more ways than a list of names can hold
//! (a Perl bareword, a PHP string held as a function, a Lua call without
//! parentheses), so the code around the strings is read the other way
//! round: every name it calls must be one known to start nothing
//! ([`only_known_names`]); any other keeps the line read whole.

use super::Lang;

/// The ranges, in bytes, of the strings and comments of `code`; `None`
/// when a form is met whose text is not told apart from code here, or that
/// runs code where it stands.
pub(super) fn literal_ranges(lang: Lang, code: &str) -> Option<Vec<(usize, usize)>> {
    match lang {
        Lang::Perl => perl_ranges(code),
        Lang::Php => php_ranges(code),
        Lang::Lua => lua_ranges(code),
        _ => None,
    }
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The end (just past the closing quote) of a string opened by `quote` at
/// `at`, a backslash escaping the next byte.
fn quoted_end(bytes: &[u8], at: usize, quote: u8, newline_ends: bool) -> Option<usize> {
    let mut end = at + 1;
    loop {
        let byte = *bytes.get(end)?;
        if byte == b'\\' {
            end += 2;
            continue;
        }
        if byte == quote {
            return Some(end + 1);
        }
        if newline_ends && byte == b'\n' {
            return None;
        }
        end += 1;
    }
}

/// The close of a bracket a delimiter opens, if it is one.
fn closer(open: u8) -> Option<u8> {
    match open {
        b'(' => Some(b')'),
        b'[' => Some(b']'),
        b'{' => Some(b'}'),
        b'<' => Some(b'>'),
        _ => None,
    }
}

/// One part of a Perl quote-like form whose delimiter is at `at`: the
/// range of its text and the index past its closing delimiter.
fn delimited(bytes: &[u8], at: usize) -> Option<((usize, usize), usize)> {
    let open = *bytes.get(at)?;
    let close = closer(open).unwrap_or(open);
    let mut depth = 0usize;
    let mut end = at + 1;
    loop {
        let byte = *bytes.get(end)?;
        if byte == b'\\' {
            end += 2;
            continue;
        }
        if byte == close && depth == 0 {
            return Some(((at + 1, end), end + 1));
        }
        if close != open {
            if byte == open {
                depth += 1;
            } else if byte == close {
                depth -= 1;
            }
        }
        end += 1;
    }
}

/// Text Perl fills in where it stands that runs code: a block after `$`,
/// `@` or `$#` that is more than a name (`@{[ ... ]}`, `${\ ...}`,
/// `@{ do { ... } }`, `${ f(); \1 }`). `${name}` and `@{name}` are
/// variables.
fn perl_interpolation_runs_code(text: &str) -> bool {
    let bytes = text.as_bytes();
    (0..bytes.len()).any(|at| {
        let sigil = at > 0 && matches!(bytes[at - 1], b'$' | b'@');
        let last_index = at > 1 && bytes[at - 1] == b'#' && bytes[at - 2] == b'$';
        if bytes[at] != b'{' || !(sigil || last_index) {
            return false;
        }
        let mut i = at + 1;
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        if bytes.get(i) == Some(&b'^') {
            i += 1;
        }
        let name_start = i;
        while bytes.get(i).is_some_and(|b| is_name_byte(*b)) {
            i += 1;
        }
        while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i += 1;
        }
        !(i > name_start && bytes.get(i) == Some(&b'}'))
    })
}

/// A Perl regular expression that runs code where it stands, whatever
/// its delimiter: `(?{ })`, `(??{ })`, `(*{ })`.
fn perl_pattern_block(text: &str) -> bool {
    text.contains("(?{") || text.contains("(??{") || text.contains("(*{")
}

enum Quoted {
    /// Not a quote-like form here.
    No,
    /// One whose text is not data.
    Code,
    /// Its text ranges and the index past it.
    Data(Vec<(usize, usize)>, usize),
}

/// A Perl quote-like operator (`q`, `qq`, `qw`, `m`, `qr`, `s`, `tr`,
/// `y`, `qx`) starting at `at`.
fn perl_quote_like(code: &str, at: usize) -> Quoted {
    let bytes = code.as_bytes();
    if at > 0 {
        let before = bytes[at - 1];
        if is_name_byte(before)
            || matches!(before, b'$' | b'@' | b'%' | b'&' | b'*' | b':')
            || (before == b'>' && at > 1 && bytes[at - 2] == b'-')
        {
            return Quoted::No;
        }
    }
    let name_end = (at..bytes.len())
        .find(|&i| !is_name_byte(bytes[i]))
        .unwrap_or(bytes.len());
    let name = &code[at..name_end];
    let parts = match name {
        "q" | "qq" | "qw" | "m" | "qr" | "qx" => 1,
        "s" | "tr" | "y" => 2,
        _ => return Quoted::No,
    };
    let mut open = name_end;
    while bytes.get(open).is_some_and(|b| *b == b' ' || *b == b'\t') {
        open += 1;
    }
    let Some(&delimiter) = bytes.get(open) else {
        return Quoted::No;
    };
    // After a space only a bracket opens one (`q {x}`); a fat comma, a
    // separator or a closing bracket is the bare word.
    if (open > name_end && closer(delimiter).is_none())
        || !delimiter.is_ascii_punctuation()
        || delimiter.is_ascii_whitespace()
        || matches!(delimiter, b',' | b';' | b')' | b']' | b'}' | b'_')
        || (delimiter == b'=' && bytes.get(open + 1) == Some(&b'>'))
    {
        return Quoted::No;
    }
    if name == "qx" || delimiter == b'#' {
        return Quoted::Code;
    }
    let Some((first, mut next)) = delimited(bytes, open) else {
        return Quoted::Code;
    };
    let mut ranges = vec![first];
    if parts == 2 {
        let second_open = if closer(delimiter).is_some() {
            let mut i = next;
            while bytes.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
                i += 1;
            }
            i
        } else {
            next - 1
        };
        let Some((second, after)) = delimited(bytes, second_open) else {
            return Quoted::Code;
        };
        ranges.push(second);
        next = after;
    }
    let flags_end = (next..bytes.len())
        .find(|&i| !bytes[i].is_ascii_alphabetic())
        .unwrap_or(bytes.len());
    let flags = &code[next..flags_end];
    let interpolates = delimiter != b'\'';
    let text = |range: &(usize, usize)| &code[range.0..range.1];
    let runs = match name {
        "s" => {
            flags.contains('e')
                || perl_pattern_block(text(&ranges[0]))
                || (interpolates && perl_interpolation_runs_code(text(&ranges[0])))
                || (interpolates && perl_interpolation_runs_code(text(&ranges[1])))
        }
        "m" | "qr" => {
            perl_pattern_block(text(&ranges[0]))
                || (interpolates && perl_interpolation_runs_code(text(&ranges[0])))
        }
        "qq" => interpolates && perl_interpolation_runs_code(text(&ranges[0])),
        _ => false,
    };
    if runs {
        Quoted::Code
    } else {
        Quoted::Data(ranges, flags_end)
    }
}

fn perl_ranges(code: &str) -> Option<Vec<(usize, usize)>> {
    let bytes = code.as_bytes();
    let mut ranges = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        match byte {
            b'#' if at == 0 || bytes[at - 1] != b'$' => {
                let end = code[at..].find('\n').map_or(bytes.len(), |n| at + n);
                ranges.push((at, end));
                at = end;
            }
            b'\'' | b'"' => {
                let end = quoted_end(bytes, at, byte, false)?;
                let inner = (at + 1, end - 1);
                if byte == b'"' && perl_interpolation_runs_code(&code[inner.0..inner.1]) {
                    return None;
                }
                ranges.push(inner);
                at = end;
            }
            // A command quote, a regular expression or a division (not
            // told apart here).
            b'\x60' | b'/' | b'?' => return None,
            // A here-document.
            b'<' if code[at..].starts_with("<<") => {
                let after = bytes.get(at + 2).copied().unwrap_or(b' ');
                if after == b'"' || after == b'\'' || after == b'~' || is_name_byte(after) {
                    return None;
                }
                at += 2;
            }
            b'a'..=b'z' => match perl_quote_like(code, at) {
                Quoted::No => {
                    while at < bytes.len() && is_name_byte(bytes[at]) {
                        at += 1;
                    }
                }
                Quoted::Code => return None,
                Quoted::Data(found, next) => {
                    ranges.extend(found);
                    at = next;
                }
            },
            _ => at += 1,
        }
    }
    Some(ranges)
}

fn php_ranges(code: &str) -> Option<Vec<(usize, usize)>> {
    let bytes = code.as_bytes();
    let mut ranges = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if !code.is_char_boundary(at) {
            at += 1;
            continue;
        }
        let byte = bytes[at];
        let rest = &code[at..];
        if byte == b'#' || rest.starts_with("//") {
            let end = rest.find('\n').map_or(bytes.len(), |n| at + n);
            ranges.push((at, end));
            at = end;
            continue;
        }
        if rest.starts_with("/*") {
            let end = at + rest.find("*/")? + 2;
            ranges.push((at, end));
            at = end;
            continue;
        }
        match byte {
            b'\'' | b'"' => {
                let end = quoted_end(bytes, at, byte, false)?;
                let inner = &code[at + 1..end - 1];
                if byte == b'"' && (inner.contains("{$") || inner.contains("${")) {
                    return None;
                }
                ranges.push((at + 1, end - 1));
                at = end;
            }
            // A command quote, a here-document, text out of PHP.
            b'\x60' => return None,
            b'<' if rest.starts_with("<<<") => return None,
            b'?' if rest.starts_with("?>") => return None,
            _ => at += 1,
        }
    }
    Some(ranges)
}

/// The length of a Lua long bracket's opening (`[[`, `[==[`) at `at`, and
/// its level.
fn lua_long_open(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    if bytes.get(at) != Some(&b'[') {
        return None;
    }
    let mut level = 0;
    while bytes.get(at + 1 + level) == Some(&b'=') {
        level += 1;
    }
    (bytes.get(at + 1 + level) == Some(&b'[')).then_some((level + 2, level))
}

/// The range inside a Lua long bracket opened at `at` and the index past
/// its close.
fn lua_long(code: &str, at: usize) -> Option<((usize, usize), usize)> {
    let (open, level) = lua_long_open(code.as_bytes(), at)?;
    let close = format!("]{}]", "=".repeat(level));
    let start = at + open;
    let end = start + code[start..].find(&close)?;
    Some(((start, end), end + close.len()))
}

fn lua_ranges(code: &str) -> Option<Vec<(usize, usize)>> {
    let bytes = code.as_bytes();
    let mut ranges = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if !code.is_char_boundary(at) {
            at += 1;
            continue;
        }
        let byte = bytes[at];
        let rest = &code[at..];
        if rest.starts_with("--") {
            if lua_long_open(bytes, at + 2).is_some() {
                let (_, next) = lua_long(code, at + 2)?;
                ranges.push((at, next));
                at = next;
            } else {
                let end = rest.find('\n').map_or(bytes.len(), |n| at + n);
                ranges.push((at, end));
                at = end;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => {
                let end = quoted_end(bytes, at, byte, true)?;
                ranges.push((at + 1, end - 1));
                at = end;
            }
            b'[' if lua_long_open(bytes, at).is_some() => {
                let (inner, next) = lua_long(code, at)?;
                ranges.push(inner);
                at = next;
            }
            _ => at += 1,
        }
    }
    Some(ranges)
}

/// Perl's names that start no process and run no code given as text.
const PERL_KNOWN: &[&str] = &[
    "my", "our", "local", "print", "printf", "say", "open", "close", "binmode", "join", "split",
    "length", "substr", "index", "rindex", "sprintf", "lc", "uc", "lcfirst", "ucfirst", "chomp",
    "chop", "chr", "ord", "push", "pop", "shift", "unshift", "splice", "keys", "values", "each",
    "scalar", "defined", "exists", "die", "warn", "if", "unless", "else", "elsif", "for",
    "foreach", "while", "until", "last", "next", "return", "map", "grep", "sort", "reverse", "and",
    "or", "not", "eq", "ne", "lt", "gt", "le", "ge", "cmp", "x", "q", "qq", "qw", "m", "qr", "s",
    "tr", "y", "STDOUT", "STDERR", "STDIN", "ARGV", "abs", "int", "hex", "oct", "undef", "use",
    "strict", "warnings", "utf8",
];

/// PHP's names (any case) that start no process and run no code given as
/// text or as a function's name.
const PHP_KNOWN: &[&str] = &[
    "echo",
    "print",
    "printf",
    "sprintf",
    "file_put_contents",
    "file_get_contents",
    "fopen",
    "fwrite",
    "fputs",
    "fclose",
    "fgets",
    "file",
    "str_replace",
    "str_ireplace",
    "preg_replace",
    "preg_match",
    "preg_split",
    "substr",
    "strlen",
    "strpos",
    "stripos",
    "strrpos",
    "trim",
    "rtrim",
    "ltrim",
    "implode",
    "explode",
    "join",
    "json_encode",
    "json_decode",
    "var_dump",
    "var_export",
    "print_r",
    "count",
    "array_keys",
    "array_values",
    "in_array",
    "str_contains",
    "str_starts_with",
    "str_ends_with",
    "strtolower",
    "strtoupper",
    "ucfirst",
    "basename",
    "dirname",
    "is_file",
    "is_dir",
    "file_exists",
    "array",
    "isset",
    "empty",
    "if",
    "else",
    "elseif",
    "foreach",
    "as",
    "for",
    "while",
    "return",
    "true",
    "false",
    "null",
    "and",
    "or",
    "php_eol",
    "file_append",
    "lock_ex",
];

/// Lua's names that start no process and run no code given as text, as
/// written in a call (`io.write`; a method `:write`).
const LUA_KNOWN: &[&str] = &[
    "print",
    "tostring",
    "tonumber",
    "ipairs",
    "pairs",
    "type",
    "assert",
    "error",
    "select",
    "io.write",
    "io.open",
    "io.read",
    "io.lines",
    "string.format",
    "string.gsub",
    "string.sub",
    "string.find",
    "string.match",
    "string.gmatch",
    "string.rep",
    "string.upper",
    "string.lower",
    "string.len",
    "string.byte",
    "string.char",
    "table.concat",
    "table.insert",
    "table.remove",
    "table.sort",
    "table.unpack",
    "unpack",
];
const LUA_METHODS: &[&str] = &[
    "write", "read", "close", "lines", "gsub", "sub", "format", "find", "match", "gmatch", "rep",
    "upper", "lower", "len", "byte", "seek", "flush",
];
const LUA_KEYWORDS: &[&str] = &[
    "local", "if", "then", "else", "elseif", "end", "for", "in", "do", "while", "repeat", "until",
    "return", "and", "or", "not", "nil", "true", "false", "break",
];
/// Lua names that reach a process, code or the environment whatever is
/// done with them.
const LUA_NEVER: &[&str] = &[
    "_G",
    "_ENV",
    "load",
    "loadstring",
    "dofile",
    "loadfile",
    "require",
    "setmetatable",
    "getmetatable",
    "getfenv",
    "setfenv",
    "rawget",
    "rawset",
    "debug",
    "package",
    "os",
    "coroutine",
];

/// Whether `outside` (the code with its strings and comments blanked)
/// calls only names known to start no process and run no code.
pub(super) fn only_known_names(lang: Lang, outside: &str) -> bool {
    match lang {
        Lang::Perl => perl_only_known(outside),
        Lang::Php => php_only_known(outside),
        Lang::Lua => lua_only_known(outside),
        _ => false,
    }
}

/// The names of `text`, where each starts and ends: a run of name bytes
/// that does not start with a digit, the separators in `join` (Lua's `.`
/// and `:`) joining its parts.
fn names(text: &str, join: &[&str]) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if !is_name_byte(bytes[at]) {
            at += 1;
            continue;
        }
        let start = at;
        loop {
            while at < bytes.len() && is_name_byte(bytes[at]) {
                at += 1;
            }
            match join.iter().find(|j| text[at..].starts_with(**j)) {
                Some(j)
                    if bytes
                        .get(at + j.len())
                        .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_') =>
                {
                    at += j.len();
                }
                _ => break,
            }
        }
        if !bytes[start].is_ascii_digit() {
            found.push((start, at));
        }
    }
    found
}

fn next_non_space(text: &str, at: usize) -> Option<u8> {
    text.as_bytes()[at..]
        .iter()
        .copied()
        .find(|b| !b.is_ascii_whitespace())
}

fn perl_only_known(outside: &str) -> bool {
    if ["->(", "->$", "&$", "&{", "ENV", "\x60", "::"]
        .iter()
        .any(|form| outside.contains(form))
    {
        return false;
    }
    let bytes = outside.as_bytes();
    names(outside, &[]).into_iter().all(|(start, end)| {
        let name = &outside[start..end];
        let before = start.checked_sub(1).map(|i| bytes[i]);
        let variable = matches!(before, Some(b'$' | b'@' | b'%'))
            || (before == Some(b'#') && start >= 2 && bytes[start - 2] == b'$');
        if variable {
            return true;
        }
        if before == Some(b'&') && !(start >= 2 && bytes[start - 2] == b'&') {
            return false;
        }
        if before == Some(b'>') && start >= 2 && bytes[start - 2] == b'-' {
            return false;
        }
        // A file test: `-e $f`.
        if before == Some(b'-') && name.len() == 1 {
            return true;
        }
        // A hash key: `$h{key}`, `key => 1`.
        let after = next_non_space(outside, end);
        if (before == Some(b'{') && after == Some(b'}'))
            || outside[end..].trim_start().starts_with("=>")
        {
            return true;
        }
        PERL_KNOWN.contains(&name)
    })
}

fn php_only_known(outside: &str) -> bool {
    if ["->", "::", "$$", "${", "\x60", "<?php"]
        .iter()
        .any(|form| outside.contains(form))
    {
        return false;
    }
    // A call of what is not a name: `$f(`, `)(`, `](`, a string called.
    static CALL_OF_VALUE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let call = CALL_OF_VALUE
        .get_or_init(|| regex::Regex::new(r"(?:\$\w+|[)\]'\x22])\s*\(").expect("valid regex"));
    if call.is_match(outside) {
        return false;
    }
    let bytes = outside.as_bytes();
    names(outside, &[]).into_iter().all(|(start, end)| {
        let name = outside[start..end].to_ascii_lowercase();
        if start > 0 && bytes[start - 1] == b'$' {
            return true;
        }
        PHP_KNOWN.contains(&name.as_str())
    })
}

fn lua_only_known(outside: &str) -> bool {
    // A call of what is not a name: `)(`, `](`, `)"`, `]{`.
    static CALL_OF_VALUE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let call = CALL_OF_VALUE
        .get_or_init(|| regex::Regex::new(r"[)\]]\s*[(\x22'{\[]").expect("valid regex"));
    if call.is_match(outside) {
        return false;
    }
    let mut previous_end = 0usize;
    for (start, end) in names(outside, &[".", ":"]) {
        let name = &outside[start..end];
        let before = outside[previous_end..start].trim_end();
        previous_end = end;
        // A field reached from what is not a name (`x[1].y`, `f().y`).
        if before.ends_with(['.', ':']) {
            return false;
        }
        let (base, method) = match name.split_once(':') {
            Some((base, method)) => (base, Some(method)),
            None => (name, None),
        };
        let first = base.split('.').next().unwrap_or(base);
        if LUA_NEVER.contains(&first) {
            return false;
        }
        if let Some(method) = method {
            if (base.contains('.') && !LUA_KNOWN.contains(&base)) || !LUA_METHODS.contains(&method)
            {
                return false;
            }
            continue;
        }
        if LUA_KEYWORDS.contains(&base) {
            continue;
        }
        // Called: `f(`, `f"x"`, `f{...}`, `f[[x]]`; `t[1]` is an index.
        let rest = outside[end..].trim_start();
        let called = rest.starts_with(['(', '"', '\'', '{'])
            || rest.starts_with("[[")
            || rest.starts_with("[=");
        // A plain name not called is a variable.
        if (base.contains('.') || called) && !LUA_KNOWN.contains(&base) {
            return false;
        }
    }
    true
}
