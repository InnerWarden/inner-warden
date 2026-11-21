//! The values a line gives its own names, each read in where the name is
//! used: the value in effect at that point. Where the text cannot settle it
//! (a value taken away under a condition, in a function body or a pipeline;
//! a name made another name's with `declare -n`) the value before stays a
//! candidate, or the name is left as written: an unknown value never puts
//! out a known one.
//!
//! The reading [`crate::threats::assignment_readings`] gives a name the first
//! value the line gives it, wherever it is used. That reads a name used
//! before it is set (`rm -rf $X; X=/`), one taken away (`unset X`, `read X`),
//! one set in a subshell that has closed (`(X=/); rm -rf $X`) and one set in
//! front of a command, which the shell expands before the value holds
//! (`X=/ rm -rf $X`), as the value; and a name set again before it is used
//! (`X=/; rm -rf $X; X=build`) could not be read at all (review of #364).
//!
//! Here each `$NAME` is read against what happened to the name before it,
//! in the scopes that are still open there: a subshell, a substitution and a
//! quoted string (a line handed to another shell) each open one, whose
//! assignments end with it; a string handed to `eval` runs in the same shell
//! and opens none. A value set in front of a command reaches only that
//! command (`X=/ sh -c 'rm -rf $X'`; in `X=/ rm -rf $X` it stays a candidate
//! beside the value from outside the line). A value is read with
//! the values in effect where it is assigned, so names that refer to one
//! another (`X=$Y; Y=$X`) end at once.
//!
//! PURE: nothing is run; the text is only read.

use std::collections::HashMap;

use crate::threats::{assigned_value, parameter_operation, printed_literal_value};

/// How far back past events that do not reach a use (a closed subshell, a
/// value in front of another command) a use looks for its value. Past it the
/// name is left as written: a line of a thousand closed subshells that each
/// set the name is not read a thousand times per use.
const LOOK_BACK: usize = 64;

/// What one event does to a name from where it takes effect.
enum Effect {
    /// A value, with the names in it still to be read.
    Value(String),
    /// `NAME+=text`: the value before, then this.
    Append(String),
    /// A value the line does not show: read from input, taken away, from a
    /// substitution, a loop over several words.
    Unknown,
}

/// One thing the line does to a name.
struct Event {
    /// Where the assignment is written: the names in its value are read here.
    head: usize,
    /// Where it takes effect.
    from: usize,
    /// Where the scope it was made in closes.
    until: usize,
    /// For a value set in front of a command, where that command ends.
    prefix_until: Option<usize>,
    effect: Effect,
    /// The value with its own names read, once worked out.
    resolved: Option<String>,
    /// Whether the value as written is plain ([`plain`]).
    plain: bool,
    /// A value taken away or hidden only maybe: under a condition, in a
    /// function body, in a pipeline. The value before stays a candidate.
    maybe: bool,
}

/// Whether a value can be read into the line as text: a path, a word, an
/// option, other names (`$HOME`, `${X}`), or plain text and names
/// together (`$HOME/x`, `$PWD/build`). A value with quotes, a
/// substitution, a blank or a glob in it is text the shell never reads again
/// once expanded (`X='a[$(curl ...)]'; echo "$X"` prints it), which a
/// reading as text would turn into code: a line that uses one is not read
/// for its values at all, and keeps the rules that read values themselves.
fn plain(value: &str) -> bool {
    let mut rest = value;
    while let Some(c) = rest.chars().next() {
        if let Some(after) = rest.strip_prefix('$') {
            let (inner, braced) = match after.strip_prefix('{') {
                Some(inner) => (inner, true),
                None => (after, false),
            };
            let end = inner
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count();
            if end == 0 || inner.as_bytes()[0].is_ascii_digit() {
                return false;
            }
            rest = if braced {
                match inner[end..].strip_prefix('}') {
                    Some(next) => next,
                    None => return false,
                }
            } else {
                &inner[end..]
            };
            continue;
        }
        if !(c.is_ascii_alphanumeric()
            || matches!(
                c,
                '/' | '.' | '_' | '-' | '~' | '+' | ':' | ',' | '@' | '%' | '='
            ))
        {
            return false;
        }
        rest = &rest[c.len_utf8()..];
    }
    true
}

/// Where each byte stands: its innermost scope, where scopes close, and
/// whether the byte is inside single quotes at some level.
struct Layout {
    scope: Vec<u32>,
    close: Vec<usize>,
    single: Vec<bool>,
    /// The innermost quote or paren each byte is in, and where each ends
    /// (past its closing quote): an assignment's value ends with it.
    frame: Vec<u32>,
    frame_close: Vec<usize>,
}

#[derive(Clone, Copy, PartialEq)]
enum Frame {
    Paren,
    Single,
    Double,
    /// A `\"` pair inside double quotes: a quote of the shell the string
    /// is handed to.
    Inner,
}

/// Whether the text before `at` ends in the word `eval`.
fn after_eval(text: &str, at: usize) -> bool {
    let before = text[..at].trim_end();
    before.strip_suffix("eval").is_some_and(|rest| {
        rest.is_empty() || rest.ends_with(|c: char| c.is_whitespace() || ";&|(".contains(c))
    })
}

/// A frame pushed: the frame, the scope inside it, whether the frame
/// opened that scope, and the frame's own number.
type Open = (Frame, u32, bool, u32);

/// Where scopes and frames close, by number.
struct Closes {
    scope: Vec<usize>,
    frame: Vec<usize>,
}

fn push(frames: &mut Vec<Open>, closes: &mut Closes, n: usize, frame: Frame, opens: bool) {
    let outer = frames.last().map_or(0, |f| f.1);
    closes.frame.push(n);
    let number = u32::try_from(closes.frame.len() - 1).unwrap_or(u32::MAX);
    if opens {
        closes.scope.push(n);
        let id = u32::try_from(closes.scope.len() - 1).unwrap_or(u32::MAX);
        frames.push((frame, id, true, number));
    } else {
        frames.push((frame, outer, false, number));
    }
}

fn pop(frames: &mut Vec<Open>, closes: &mut Closes, end: usize) {
    if let Some((_, id, opened, number)) = frames.pop() {
        if let Some(slot) = closes.frame.get_mut(number as usize) {
            *slot = end;
        }
        if opened {
            if let Some(slot) = closes.scope.get_mut(id as usize) {
                *slot = end;
            }
        }
    }
}

fn layout(text: &str) -> Layout {
    let b = text.as_bytes();
    let n = b.len();
    let mut scope = vec![0u32; n];
    let mut single = vec![false; n];
    let mut frame = vec![0u32; n];
    let mut close = Closes {
        scope: vec![n],
        frame: vec![n],
    };
    let mut frames: Vec<Open> = Vec::new();
    let mut singles = 0usize;
    let mut i = 0;
    while i < n {
        let here = frames.last().map_or(0, |f| f.1);
        let inside = frames.last().map_or(0, |f| f.3);
        scope[i] = here;
        single[i] = singles > 0;
        frame[i] = inside;
        let top = frames.last().map(|f| f.0);
        let next = b.get(i + 1).copied();
        // A backslash takes the byte after it along, in the same place.
        if b[i] == b'\\' && i + 1 < n {
            scope[i + 1] = here;
            single[i + 1] = singles > 0;
            frame[i + 1] = inside;
        }
        match b[i] {
            b'\\' if top == Some(Frame::Double) && next == Some(b'"') => {
                push(&mut frames, &mut close, n, Frame::Inner, true);
                i += 2;
                continue;
            }
            b'\\' if top == Some(Frame::Inner) && next == Some(b'"') => {
                pop(&mut frames, &mut close, i + 2);
                i += 2;
                continue;
            }
            b'\\' if !(top == Some(Frame::Single) && next == Some(b'\'')) => {
                i += 2;
                continue;
            }
            b'\'' if top == Some(Frame::Single) => {
                pop(&mut frames, &mut close, i + 1);
                singles = singles.saturating_sub(1);
            }
            b'\'' if singles > 0 => {
                while let Some((kind, _, _, _)) = frames.last().copied() {
                    pop(&mut frames, &mut close, i + 1);
                    if kind == Frame::Single {
                        singles = singles.saturating_sub(1);
                        break;
                    }
                }
            }
            b'\'' if matches!(top, Some(Frame::Double | Frame::Inner)) => {}
            b'\'' => {
                push(
                    &mut frames,
                    &mut close,
                    n,
                    Frame::Single,
                    !after_eval(text, i),
                );
                singles += 1;
            }
            b'"' if top == Some(Frame::Double) => pop(&mut frames, &mut close, i + 1),
            b'"' if top == Some(Frame::Inner) => {
                pop(&mut frames, &mut close, i + 1);
                if frames.last().map(|f| f.0) == Some(Frame::Double) {
                    pop(&mut frames, &mut close, i + 1);
                }
            }
            b'"' => push(
                &mut frames,
                &mut close,
                n,
                Frame::Double,
                !after_eval(text, i),
            ),
            b'(' if !matches!(top, Some(Frame::Double | Frame::Inner))
                || (i > 0 && b[i - 1] == b'$') =>
            {
                push(&mut frames, &mut close, n, Frame::Paren, true);
            }
            b')' if top == Some(Frame::Paren) => pop(&mut frames, &mut close, i + 1),
            _ => {}
        }
        i += 1;
    }
    Layout {
        scope,
        close: close.scope,
        single,
        frame,
        frame_close: close.frame,
    }
}

/// The words of a builtin's arguments from `at` up to the end of its
/// command, with where each ends; at most 64.
fn words_from(text: &str, mut at: usize) -> Vec<(String, usize)> {
    let b = text.as_bytes();
    let mut words = Vec::new();
    while words.len() < 64 {
        while at < b.len() && matches!(b[at], b' ' | b'\t') {
            at += 1;
        }
        if at >= b.len() || b";&|<>()\n".contains(&b[at]) {
            break;
        }
        let start = at;
        if matches!(b[at], b'\'' | b'"') {
            let quote = b[at];
            at += 1;
            while at < b.len() && b[at] != quote {
                at += 1;
            }
            at = (at + 1).min(b.len());
        } else {
            while at < b.len() && !b" \t;&|<>()\n".contains(&b[at]) {
                at += 1;
            }
        }
        words.push((text[start..at].to_owned(), at));
    }
    words
}

fn is_identifier(word: &str) -> bool {
    let mut chars = word.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The names a builtin gives a value the line does not show, or takes away:
/// `unset NAME` (not `unset -f`), `read [options] NAME...`, `mapfile NAME`,
/// `getopts spec NAME`, `printf -v NAME`. The options that take an argument
/// are each builtin's own (`read -s` and `mapfile -t` take none), so the
/// name after them is read as the name. One reading for this module and
/// [`crate::threats`].
pub(crate) fn names_taken_by(builtin: &str, words: &[&str]) -> Vec<String> {
    let mut names = Vec::new();
    let mut takes_argument = false;
    let mut argument_is_name = false;
    let mut first_operand = true;
    let mut options_done = false;
    for word in words {
        let word = word.trim_matches(['\'', '"']);
        if takes_argument {
            takes_argument = false;
            if argument_is_name && is_identifier(word) {
                names.push(word.to_owned());
            }
            continue;
        }
        if word == "--" && !options_done {
            options_done = true;
            continue;
        }
        if !options_done && word.starts_with('-') && word.len() > 1 {
            match builtin {
                "unset" if word.contains('f') => return Vec::new(),
                "read" | "mapfile" | "readarray" => {
                    let with_argument = if builtin == "read" {
                        "adinNptu"
                    } else {
                        "dnOsuCc"
                    };
                    // The first letter in a cluster that takes an argument
                    // takes the rest of the word, or the next word.
                    let letters = &word[1..];
                    if let Some(at) = letters.find(|c| with_argument.contains(c)) {
                        let letter = letters.as_bytes()[at];
                        let glued = &letters[at + 1..];
                        if glued.is_empty() {
                            takes_argument = true;
                            argument_is_name = builtin == "read" && letter == b'a';
                        } else if builtin == "read" && letter == b'a' && is_identifier(glued) {
                            names.push(glued.to_owned());
                        }
                    }
                }
                "printf" => match word.strip_prefix("-v") {
                    Some("") => {
                        takes_argument = true;
                        argument_is_name = true;
                    }
                    Some(name) if is_identifier(name) => names.push(name.to_owned()),
                    _ => {}
                },
                _ => {}
            }
            continue;
        }
        match builtin {
            "printf" => break,
            "getopts" if first_operand => {}
            _ if is_identifier(word) => names.push(word.to_owned()),
            _ => {}
        }
        first_operand = false;
    }
    names
}

fn names_taken(builtin: &str, words: &[(String, usize)]) -> Vec<String> {
    let words: Vec<&str> = words.iter().map(|(word, _)| word.as_str()).collect();
    names_taken_by(builtin, &words)
}

/// The value `printf -v NAME FORMAT` gives NAME when the format is plain
/// text with nothing to fill in (`printf -v X /` gives `/`).
fn printf_value(words: &[(String, usize)]) -> Option<(String, String)> {
    let words: Vec<&str> = words.iter().map(|(word, _)| word.as_str()).collect();
    let (name, format) = match words.as_slice() {
        ["-v", name, format, ..] => (*name, *format),
        [glued, format, ..] => (glued.strip_prefix("-v")?, *format),
        _ => return None,
    };
    let format = format.trim_matches(['\'', '"']);
    (is_identifier(name) && !format.is_empty() && plain(format) && !format.contains(['%', '$']))
        .then(|| (name.to_owned(), format.to_owned()))
}

/// The patterns of the reading.
struct Patterns {
    assign: regex::Regex,
    assignment_word: regex::Regex,
    for_any: regex::Regex,
    one_word_loop: regex::Regex,
    read_here: regex::Regex,
    reader: regex::Regex,
}

/// `None` when one does not build: the line is then not read for values.
fn patterns() -> Option<&'static Patterns> {
    static PATTERNS: std::sync::OnceLock<Option<Patterns>> = std::sync::OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            Some(Patterns {
                assign: regex::Regex::new(
                    r#"(?:^|[\s;&|({'"])((?:export|local|readonly|declare|typeset)\s+(?:-[A-Za-z]+\s+)*)?([A-Za-z_][A-Za-z0-9_]*)(\+?)="#,
                )
                .ok()?,
                assignment_word: regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*\+?=").ok()?,
                for_any: regex::Regex::new(
                    r#"(?:^|[\s;&|('"])for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b"#,
                )
                .ok()?,
                one_word_loop: regex::Regex::new(
                    r#"(?:^|[\s;&|('"])for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^\s;&|()]+)\s*(?:;|\n)\s*do\b"#,
                )
                .ok()?,
                read_here: regex::Regex::new(
                    r#"(?:^|[\s;&|('"])read\s+(?:-r\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*<<<\s*('[^']*'|"[^"`\\]*"|[^\s;&|()`'"\\]+)"#,
                )
                .ok()?,
                reader: regex::Regex::new(
                    r#"(?:^|[;&|({\n'"!]|\b(?:then|do|else|elif|if|while|until|time)\b)[ \t]*(unset|read|mapfile|readarray|getopts|printf)\b"#,
                )
                .ok()?,
            })
        })
        .as_ref()
}

/// Whether the command written from `start` to `end` may not run, or runs
/// where what it does to a name does not reach the rest of the line: after
/// `&&` or `||`, in a pipeline (each part a subshell in bash), or inside an
/// `if`, a loop, a `case` or a `{ }` group still open (a function body
/// among them). Read on the words outside single quotes; a mistake only
/// keeps a value as a candidate, which can only raise a verdict.
fn runs_only_maybe(text: &str, depths: &[i32], start: usize, end: usize) -> bool {
    let before = text[..start].trim_end();
    if before.ends_with("&&") || before.ends_with("||") || before.ends_with('|') {
        return true;
    }
    let after = text[end.min(text.len())..].trim_start();
    if after.starts_with('|') || after.starts_with("&&") || after.starts_with("||") {
        return true;
    }
    depths.get(start).is_some_and(|depth| *depth > 0)
}

/// How many `if`, loop bodies, `case` and `{ }` groups are open at each
/// byte, counting the words outside single quotes.
fn block_depths(text: &str, layout: &Layout) -> Vec<i32> {
    let b = text.as_bytes();
    let mut depths = vec![0i32; b.len() + 1];
    let mut depth: i32 = 0;
    let mut word_start = None;
    for at in 0..=b.len() {
        let ends = at == b.len()
            || b" \t\n;&|()".contains(&b[at])
            || layout.single.get(at).copied().unwrap_or(false);
        if ends {
            if let Some(from) = word_start.take() {
                match &text[from..at] {
                    "if" | "do" | "case" | "{" => depth += 1,
                    "fi" | "done" | "esac" | "}" => depth -= 1,
                    _ => {}
                }
            }
        } else if word_start.is_none() {
            word_start = Some(at);
        }
        depths[at] = depth;
    }
    depths
}

/// Where the bodies of the functions the line defines are written
/// (`f(){ ...; }`, `function f { ...; }`): a name used there takes the value
/// it has where the function is called, which may be any the line gives.
fn function_bodies(text: &str, layout: &Layout) -> Vec<(usize, usize)> {
    static HEAD: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let Some(head) = HEAD
        .get_or_init(|| {
            regex::Regex::new(
                r"(?:^|[\s;&|(])(?:function\s+[A-Za-z_][A-Za-z0-9_:.-]*\s*(?:\(\s*\))?|[A-Za-z_][A-Za-z0-9_:.-]*\s*\(\s*\))\s*\{",
            )
            .ok()
        })
        .as_ref()
    else {
        return Vec::new();
    };
    let b = text.as_bytes();
    let mut bodies = Vec::new();
    for found in head.find_iter(text) {
        let open = found.end();
        let mut depth = 1usize;
        let mut at = open;
        while at < b.len() && depth > 0 {
            if !layout.single.get(at).copied().unwrap_or(false) {
                match b[at] {
                    b'{' if at == 0 || b[at - 1] != b'$' => depth += 1,
                    b'}' => depth -= 1,
                    _ => {}
                }
            }
            at += 1;
        }
        bodies.push((open, at));
        if bodies.len() >= LOOK_BACK {
            break;
        }
    }
    bodies
}

/// Everything the line does to its names, sorted by where it takes effect.
fn events_of(text: &str, layout: &Layout, patterns: &Patterns) -> Vec<(String, Event)> {
    let b = text.as_bytes();
    let n = b.len();
    let until_of = |at: usize| {
        let scope = layout.scope.get(at).copied().unwrap_or(0) as usize;
        layout.close.get(scope).copied().unwrap_or(n)
    };
    let depths = block_depths(text, layout);
    let mut events: Vec<(String, Event)> = Vec::new();
    // The end of the last command a value in front of it was found for:
    // values in a row in front of one command share it.
    let mut command_end: Option<(u32, usize, usize)> = None;
    let mut from = 0;
    while let Some(found) = patterns.assign.captures_at(text, from) {
        let (Some(whole), Some(name)) = (found.get(0), found.get(2)) else {
            break;
        };
        let setter = found.get(1).is_some();
        let append = found.get(3).is_some_and(|plus| !plus.as_str().is_empty());
        // The value ends where the quote or paren the assignment is in ends.
        let frame_end = layout
            .frame
            .get(name.start())
            .and_then(|number| layout.frame_close.get(*number as usize))
            .map_or(n, |close| {
                if *close < n {
                    close.saturating_sub(1)
                } else {
                    n
                }
            })
            .max(whole.end());
        let rest = &text[whole.end()..frame_end];
        let (value, taken) = printed_literal_value(rest)
            .map(|(value, taken)| (Some(value), taken))
            .unwrap_or_else(|| assigned_value(rest));
        let head = name.start();
        let end = whole.end() + taken;
        from = end;
        let until = until_of(head);
        // A value in front of a command: what follows it on the same
        // command, past other such values, is a word, not the end.
        let mut prefix_until = None;
        if !setter {
            let mut k = end;
            loop {
                while k < n && matches!(b[k], b' ' | b'\t') {
                    k += 1;
                }
                if k >= n || b";&|)\n}#".contains(&b[k]) || k + 1 >= until {
                    break;
                }
                if (matches!(b[k], b'\'' | b'"') && until == k + 1)
                    || (b[k] == b'\\' && until == k + 2)
                {
                    break;
                }
                if k == end {
                    // Glued to the value: more of the same word.
                    break;
                }
                if let Some(word) = patterns.assignment_word.find(&text[k..]) {
                    let (_, skipped) = assigned_value(&text[k + word.end()..]);
                    k += word.end() + skipped;
                    continue;
                }
                let scope = layout.scope.get(head).copied().unwrap_or(0);
                let stop = match command_end {
                    Some((cached, start, stop))
                        if cached == scope && start <= end && end <= stop =>
                    {
                        stop
                    }
                    _ => {
                        let stop = (end..until.min(n))
                            .find(|&q| layout.scope[q] == scope && b";&|\n".contains(&b[q]))
                            .unwrap_or(until);
                        command_end = Some((scope, end, stop));
                        stop
                    }
                };
                prefix_until = Some(stop);
                break;
            }
        }
        let plain = value.as_deref().is_none_or(plain);
        // `declare -n R=X` makes R another name for X, read where R is
        // used: not a value the line shows here.
        let nameref = found.get(1).is_some_and(|setter| {
            setter
                .as_str()
                .split_whitespace()
                .any(|flag| flag.starts_with('-') && flag.contains('n'))
        });
        let value = if nameref { None } else { value };
        let effect = match value {
            Some(value) if append => Effect::Append(value),
            Some(value) => Effect::Value(value),
            None => Effect::Unknown,
        };
        events.push((
            name.as_str().to_owned(),
            Event {
                head,
                from: end,
                until,
                prefix_until,
                effect,
                resolved: None,
                plain,
                maybe: false,
            },
        ));
    }
    let simple = |name: &str, head: usize, from: usize, effect: Effect| {
        let plain = match &effect {
            Effect::Value(value) | Effect::Append(value) => plain(value),
            Effect::Unknown => true,
        };
        (
            name.to_owned(),
            Event {
                head,
                from,
                until: until_of(head),
                prefix_until: None,
                effect,
                resolved: None,
                plain,
                maybe: false,
            },
        )
    };
    for found in patterns.for_any.captures_iter(text) {
        if let (Some(whole), Some(name)) = (found.get(0), found.get(1)) {
            events.push(simple(
                name.as_str(),
                name.start(),
                whole.end(),
                Effect::Unknown,
            ));
        }
    }
    for found in patterns.one_word_loop.captures_iter(text) {
        if let (Some(whole), Some(name), Some(word)) = (found.get(0), found.get(1), found.get(2)) {
            let word = word.as_str().trim_matches(['\'', '"']);
            if !word.contains(['$', '`', '*', '?', '[']) {
                events.push(simple(
                    name.as_str(),
                    name.start(),
                    whole.end(),
                    Effect::Value(word.to_owned()),
                ));
            }
        }
    }
    for found in patterns.reader.captures_iter(text) {
        let Some(builtin) = found.get(1) else {
            continue;
        };
        let words = words_from(text, builtin.end());
        let end = words.last().map_or(builtin.end(), |(_, end)| *end);
        // A value read from input is unknown: it never puts out a known
        // one, wherever it stands. Only `unset` that surely runs takes a
        // value away.
        let maybe =
            builtin.as_str() != "unset" || runs_only_maybe(text, &depths, builtin.start(), end);
        let shown = if builtin.as_str() == "printf" {
            printf_value(&words)
        } else {
            None
        };
        for name in names_taken(builtin.as_str(), &words) {
            let effect = match &shown {
                Some((given, value)) if *given == name => Effect::Value(value.clone()),
                _ => Effect::Unknown,
            };
            let mut event = simple(&name, builtin.start(), end, effect);
            event.1.maybe = maybe;
            events.push(event);
        }
    }
    for found in patterns.read_here.captures_iter(text) {
        if let (Some(whole), Some(name), Some(word)) = (found.get(0), found.get(1), found.get(2)) {
            // The word is expanded before `read` runs: `read X <<< "$X"`
            // leaves X as it was.
            let written = word.as_str();
            let word = written.trim_matches(['\'', '"']).to_owned();
            let effect = if written.starts_with('\'') && word.contains('$') {
                Effect::Unknown
            } else {
                Effect::Value(word)
            };
            let maybe = runs_only_maybe(text, &depths, name.start(), whole.end());
            let mut event = simple(name.as_str(), name.start(), whole.end(), effect);
            event.1.maybe = maybe;
            events.push(event);
        }
    }
    events.sort_by_key(|(_, event)| event.from);
    events
}

/// The events of each name, and the reading of names against them.
struct Values {
    events: Vec<Event>,
    by_name: HashMap<String, Vec<usize>>,
    limit: usize,
    /// Set once a use reads a value that is not plain.
    unplain_read: std::cell::Cell<bool>,
    /// The bodies of the functions the line defines ([`function_bodies`]).
    bodies: Vec<(usize, usize)>,
}

impl Values {
    /// The value of `name` at `at`: the one in effect there or, inside a
    /// function body, any the line gives the name.
    fn lookup(&self, name: &str, at: usize) -> Option<String> {
        let found = self.lookup_in_order(name, at);
        if found.is_some()
            || !self
                .bodies
                .iter()
                .any(|(open, close)| *open <= at && at < *close)
        {
            return found;
        }
        // In a function body: the value where the function is called,
        // which may be any the line gives the name (`f(){ rm -rf $X; }; X=/ f`).
        let list = self.by_name.get(name)?;
        for &index in list.iter().rev().take(LOOK_BACK) {
            let event = &self.events[index];
            if let Some(value) = &event.resolved {
                if !event.plain {
                    self.unplain_read.set(true);
                }
                return Some(value.clone());
            }
        }
        None
    }

    /// The value of `name` in effect at `at`, reading the events before it
    /// in the scopes still open there. A value taken away only maybe
    /// (`if c; then unset X; fi`) leaves the one before it in effect: an
    /// unknown value never puts out a known one.
    fn lookup_in_order(&self, name: &str, at: usize) -> Option<String> {
        let list = self.by_name.get(name)?;
        let before = list.partition_point(|&index| self.events[index].from <= at);
        for &index in list[..before].iter().rev().take(LOOK_BACK) {
            let event = &self.events[index];
            if at >= event.until {
                continue;
            }
            // A value set in front of a command holds for what that command
            // hands on unexpanded. Its own `$X` the shell expands before the
            // value holds, to a value from outside the line the text does not
            // show: the value in front stays a candidate there (`X=/ rm -rf
            // $X` is held as main holds it; an unknown value never puts out
            // a known one).
            if let Some(stop) = event.prefix_until {
                if at >= stop {
                    continue;
                }
            }
            if event.maybe && event.resolved.is_none() {
                continue;
            }
            if event.resolved.is_some() && !event.plain {
                self.unplain_read.set(true);
            }
            return event.resolved.clone();
        }
        None
    }

    /// `text` with every name in it read, each at the place `place` gives
    /// for its offset, and whether anything was read; `None` past the limit.
    fn expand(&self, text: &str, place: &dyn Fn(usize) -> usize) -> Option<(String, bool)> {
        let name_end = |text: &str| {
            text.bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count()
        };
        let mut out = String::with_capacity(text.len());
        let mut changed = false;
        let mut offset = 0;
        while let Some(found) = text[offset..].find('$') {
            let at = offset + found;
            out.push_str(&text[offset..at]);
            let after = &text[at + 1..];
            let spot = place(at);
            let mut read = None;
            if let Some(braced) = after.strip_prefix('{') {
                let end = name_end(braced);
                if end > 0 {
                    let held = self.lookup(&braced[..end], spot);
                    if braced[end..].starts_with('}') {
                        read = held.map(|value| (value, end + 2));
                    } else {
                        // An operation on the value (`${F%.pub}`) is worked
                        // out as the shell works it out.
                        read = held
                            .and_then(|value| parameter_operation(&value, &braced[end..]))
                            .map(|(value, used)| (value, 1 + end + used));
                    }
                }
            } else {
                let end = name_end(after);
                if end > 0 && !after.as_bytes()[0].is_ascii_digit() {
                    read = self.lookup(&after[..end], spot).map(|value| (value, end));
                }
            }
            match read {
                Some((value, taken)) => {
                    // `\$X` hands `$X` on to the next shell: read, it hands
                    // the value on, without the backslash.
                    if at > 0 && text.as_bytes()[at - 1] == b'\\' {
                        out.pop();
                    }
                    out.push_str(&value);
                    changed = true;
                    offset = at + 1 + taken;
                }
                None => {
                    out.push('$');
                    offset = at + 1;
                }
            }
            if out.len() > self.limit {
                return None;
            }
        }
        out.push_str(&text[offset..]);
        Some((out, changed))
    }
}

/// Where the line stands at a byte, as far as `$PWD` goes: where it
/// started (no `cd` before), a folder a `cd` spells out, or a place the
/// text does not settle (`cd $(echo /)`, `cd -`, a bare `cd`).
#[derive(Clone)]
enum Folder {
    Start,
    Known(String),
    Unknown,
}

/// Every `cd`, `pushd` and `popd` of the line: where it ends and the
/// folder it moves to, in order. Read once per line.
fn folder_moves(text: &str) -> Vec<(usize, Folder)> {
    static CD: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
    let Some(cd) = CD
        .get_or_init(|| {
            regex::Regex::new(r"(?:^|[\s;&|({])(?:cd|pushd|popd)\b[ \t]*([^\s;&|()]*)").ok()
        })
        .as_ref()
    else {
        return vec![(0, Folder::Unknown)];
    };
    cd.captures_iter(text)
        .filter_map(|found| {
            let whole = found.get(0)?;
            let target = found.get(1).map_or("", |m| m.as_str());
            let target = target.trim_matches(['\'', '"']);
            let folder = if whole.as_str().contains("popd")
                || target.is_empty()
                || target.starts_with(['-', '~'])
                || target.contains(['$', '`', '*', '?', '[', '\\'])
            {
                Folder::Unknown
            } else {
                Folder::Known(target.trim_end_matches('/').to_owned())
            };
            Some((whole.end(), folder))
        })
        .collect()
}

/// The folder the last move of [`folder_moves`] before `at` goes to.
fn folder_at(moves: &[(usize, Folder)], at: usize) -> Folder {
    let before = moves.partition_point(|(end, _)| *end <= at);
    match before.checked_sub(1) {
        Some(last) => moves[last].1.clone(),
        None => Folder::Start,
    }
}

/// A value under the working directory (`$PWD/build`) read against where
/// the line stands where it is assigned: with no `cd` before it, the
/// relative path it is (`./build`), which the rules read against the place
/// the line is at (item 7 of the review of #364: `D=$PWD/build; rm -rf $D`
/// stays the person's); after a `cd` the line spells out, under that folder
/// (`cd /; D=$PWD/etc` is `/etc`); after one it does not, as written. Only
/// a path below it, with no `..` and nothing else left to read; `$PWD`
/// itself stays as written.
fn below_working_directory(value: String, folder: Folder) -> String {
    let rest = value
        .strip_prefix("$PWD/")
        .or_else(|| value.strip_prefix("${PWD}/"));
    match rest {
        Some(rest)
            if !rest.is_empty()
                && !rest.contains('$')
                && !rest.split('/').any(|part| part == "..") =>
        {
            match folder {
                Folder::Start => format!("./{rest}"),
                Folder::Known(folder) if folder.is_empty() => format!("/{rest}"),
                Folder::Known(folder) if folder.starts_with('/') => format!("{folder}/{rest}"),
                Folder::Known(folder) => format!("./{folder}/{rest}"),
                Folder::Unknown => value,
            }
        }
        _ => value,
    }
}

/// The line with every `$NAME` of a name it sets replaced by the value in
/// effect where it is used, when that changes it: at most one reading.
/// Empty when nothing is read in, or the values grow past eight times the
/// line and a floor, as in [`crate::threats::assignment_readings`]: thirty
/// values that each name the next twice are a gigabyte otherwise.
pub(crate) fn readings_in_effect(content: &str) -> Vec<String> {
    if !content.contains('$') {
        return Vec::new();
    }
    let Some(patterns) = patterns() else {
        return Vec::new();
    };
    let layout = layout(content);
    let named = events_of(content, &layout, patterns);
    if named.is_empty() {
        return Vec::new();
    }
    let limit = content.len().saturating_mul(8).saturating_add(4096);
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    let mut events = Vec::with_capacity(named.len());
    let mut names = Vec::with_capacity(named.len());
    for (index, (name, event)) in named.into_iter().enumerate() {
        by_name.entry(name.clone()).or_default().push(index);
        names.push(name);
        events.push(event);
    }
    let mut values = Values {
        events,
        by_name,
        limit,
        unplain_read: std::cell::Cell::new(false),
        bodies: function_bodies(content, &layout),
    };
    let moves = folder_moves(content);
    // All the values worked out together may hold four times the limit.
    let mut budget = limit.saturating_mul(4);
    // In the order they take effect: a value's own names are read where it
    // is assigned, against values already worked out.
    for (index, name) in names.iter().enumerate() {
        let head = values.events[index].head;
        let place = move |_: usize| head;
        let resolved = match &values.events[index].effect {
            Effect::Unknown => None,
            Effect::Value(raw) => match values.expand(raw, &place) {
                Some((read, _)) => Some(below_working_directory(read, folder_at(&moves, head))),
                None => return Vec::new(),
            },
            Effect::Append(raw) => match values.lookup(name, head) {
                None => None,
                Some(mut before) => match values.expand(raw, &place) {
                    Some((read, _)) => {
                        before.push_str(&read);
                        Some(before)
                    }
                    None => return Vec::new(),
                },
            },
        };
        if let Some(value) = &resolved {
            match budget.checked_sub(value.len()) {
                Some(left) => budget = left,
                None => return Vec::new(),
            }
        }
        values.events[index].resolved = resolved;
    }
    match values.expand(content, &|at: usize| at) {
        Some((reading, true)) if reading != content && !values.unplain_read.get() => {
            vec![reading]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::readings_in_effect;

    fn read(line: &str) -> Option<String> {
        readings_in_effect(line).into_iter().next()
    }

    #[test]
    fn the_value_in_effect_where_the_name_is_used() {
        assert_eq!(
            read("X=/; rm -rf $X; X=build").as_deref(),
            Some("X=/; rm -rf /; X=build")
        );
        assert_eq!(read("rm -rf $X; X=/"), None);
        assert_eq!(read("X=/; unset X; rm -rf $X"), None);
        assert_eq!(
            read("X=/; read X <<< build; rm -rf $X").as_deref(),
            Some("X=/; read X <<< build; rm -rf build")
        );
        assert_eq!(read("(X=/); rm -rf $X"), None);
        // Second review: the value in front stays a candidate for the
        // command's own words, and a value read from input never puts out a
        // known one.
        assert_eq!(read("X=/ rm -rf $X").as_deref(), Some("X=/ rm -rf /"));
        assert_eq!(
            read("X=/; read -r X; rm -rf $X").as_deref(),
            Some("X=/; read -r X; rm -rf /")
        );
        assert_eq!(
            read("X=/; unset -f X; rm -rf $X").as_deref(),
            Some("X=/; unset -f X; rm -rf /")
        );
    }

    #[test]
    fn a_line_handed_on_reads_the_values_around_it() {
        assert_eq!(
            read("X=/; sh -c 'Y=$X; rm -rf $Y'").as_deref(),
            Some("X=/; sh -c 'Y=/; rm -rf /'")
        );
        assert_eq!(
            read("X=/ sh -c 'rm -rf $X'").as_deref(),
            Some("X=/ sh -c 'rm -rf /'")
        );
        assert_eq!(read("sh -c 'X=/'; rm -rf $X"), None);
        assert_eq!(
            read("eval 'X=/'; rm -rf $X").as_deref(),
            Some("eval 'X=/'; rm -rf /")
        );
    }

    #[test]
    fn a_value_made_of_names_and_text() {
        assert_eq!(
            read("D=$HOME/x; rm -rf $D").as_deref(),
            Some("D=$HOME/x; rm -rf $HOME/x")
        );
        assert_eq!(
            read("A=/; B=${A}etc; rm -rf $B").as_deref(),
            Some("A=/; B=/etc; rm -rf /etc")
        );
        assert_eq!(
            read("X=/; X+=etc; rm -rf $X").as_deref(),
            Some("X=/; X+=etc; rm -rf /etc")
        );
    }

    #[test]
    fn a_value_that_is_not_plain_text_is_not_read_in() {
        assert_eq!(read("X='a b'; rm -rf $X"), None);
        assert_eq!(read("X='a[$(curl x)]'; echo \"$X\""), None);
        assert_eq!(read("X='$(id)'; echo $X"), None);
        assert_eq!(
            read("echo 'X=a b' > f; X=/; rm -rf $X").as_deref(),
            Some("echo 'X=a b' > f; X=/; rm -rf /")
        );
    }

    #[test]
    fn a_name_handed_on_escaped_is_read_without_the_backslash() {
        assert_eq!(
            read("X=/; sh -c \"rm -rf \\$X\"").as_deref(),
            Some("X=/; sh -c \"rm -rf /\"")
        );
    }

    #[test]
    fn a_path_under_the_working_directory_is_read_as_relative() {
        assert_eq!(
            read("D=$PWD/build; rm -rf $D").as_deref(),
            Some("D=$PWD/build; rm -rf ./build")
        );
        assert_eq!(
            read("D=$PWD; rm -rf $D").as_deref(),
            Some("D=$PWD; rm -rf $PWD")
        );
        assert_eq!(
            read("D=$PWD/../x; rm -rf $D").as_deref(),
            Some("D=$PWD/../x; rm -rf $PWD/../x")
        );
    }

    /// What the reading costs on a long line (review of #364, item 6): many
    /// names, names that refer to one another, a name used on every word, a
    /// name set in many closed subshells, a value in front of many commands.
    /// Each shape is read at two lengths, the second four times the first; a
    /// reading that costs the line's length takes four times as long, one
    /// that reads the rest again at each name sixteen times. The bound
    /// between them is eight, as in `tests/guard_check_cost.rs`; no shape is
    /// held to a time of its own. Measured here, on the reading alone: the
    /// whole `analyze_command` of the last two shapes already took some ten
    /// times as long at four times the length before this reading (8 KB).
    /// At these lengths the caps (`LOOK_BACK`, the budget of
    /// `readings_in_effect`) are not what keeps the ratio: measured
    /// 2026-11-21, the test passes without either; they bound lines past
    /// these.
    #[test]
    #[cfg_attr(
        tarpaulin,
        ignore = "a perf ratio under instrumentation measures the instrumentation"
    )]
    fn reading_costs_what_the_lines_length_costs() {
        use std::time::{Duration, Instant};
        if std::env::var_os("IW_NO_WALL_CLOCK_CEILINGS").is_some() {
            return;
        }
        const SHORT: usize = 16 * 1024;
        const TIMES: u32 = 8;
        const SHORT_FLOOR: Duration = Duration::from_millis(2);
        let numbered = |head: &str, unit: &str, tail: &str, bytes: usize| {
            let mut line = String::from(head);
            let mut count = 0usize;
            while line.len() < bytes {
                line.push_str(
                    &unit
                        .replace('@', &(count + 1).to_string())
                        .replace('#', &count.to_string()),
                );
                count += 1;
            }
            line.push_str(tail);
            line
        };
        let shapes = |bytes: usize| {
            vec![
                (
                    "many names, each from the one before",
                    numbered("X0=/a; ", "X@=$X#/b; ", "rm -rf $X0", bytes),
                ),
                (
                    "names that refer to one another",
                    numbered("", "A#=$B#; B#=$A#; ", "echo $A0 $B0", bytes),
                ),
                (
                    "one name used on every word",
                    numbered("X=/tmp/x; ls", " $X/#", "", bytes),
                ),
                (
                    "a name set in many closed subshells",
                    numbered("", "(X=#); echo $X; ", "rm -rf $X", bytes),
                ),
                (
                    "a value in front of many commands",
                    numbered("", "X=# true $X; ", "", bytes),
                ),
                (
                    "many names read and unset",
                    numbered("", "X#=/; unset X#; read Y# <<< a; ", "echo $X0 $Y0", bytes),
                ),
            ]
        };
        let fastest = |line: &str| {
            let mut best = Duration::MAX;
            for _ in 0..3 {
                let start = Instant::now();
                let _ = std::hint::black_box(readings_in_effect(line));
                best = best.min(start.elapsed());
            }
            best
        };
        let too_slow = |short: Duration, long: Duration| long > TIMES * short.max(SHORT_FLOOR);
        let mut report = Vec::new();
        let mut slow = Vec::new();
        for ((name, short_line), (_, long_line)) in shapes(SHORT).into_iter().zip(shapes(4 * SHORT))
        {
            let mut short = fastest(&short_line);
            let mut long = fastest(&long_line);
            if too_slow(short, long) {
                short = short.min(fastest(&short_line));
                long = long.min(fastest(&long_line));
            }
            report.push(format!(
                "  {:>8.2} ms  {:>8.2} ms  {name}",
                short.as_secs_f64() * 1e3,
                long.as_secs_f64() * 1e3
            ));
            if too_slow(short, long) {
                slow.push(name);
            }
        }
        assert!(
            slow.is_empty(),
            "the reading took more than {TIMES} times as long at four times the length on: {slow:?}\n{}",
            report.join("\n")
        );
        if std::env::var_os("IW_PRINT_LINE_VALUES_COST").is_some() {
            println!("{}", report.join("\n"));
        }
    }

    #[test]
    fn names_that_refer_to_one_another_end() {
        assert_eq!(
            read("X=$Y; Y=$X; echo $X $Y").as_deref(),
            Some("X=$Y; Y=$Y; echo $Y $Y")
        );
        assert_eq!(
            read("PATH=$PATH:/x; echo $PATH").as_deref(),
            Some("PATH=$PATH:/x; echo $PATH:/x")
        );
    }
}
