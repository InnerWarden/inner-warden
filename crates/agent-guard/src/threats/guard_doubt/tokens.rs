//! Whether a guard CLI name or a guard-lowering verb appears as a whole token
//! anywhere in the line, with quotes and escapes taken off. One pass per
//! reading, linear in the line.

use super::super::{GUARD_LOWERING_WORDS as VERBS, GUARD_PROGRAMS as NAMES};

const MAX_BRACE_DEPTH: usize = 8;

fn is_separator(byte: u8) -> bool {
    matches!(
        byte,
        b' ' | b'\t'
            | b'\n'
            | b'\r'
            | b';'
            | b'|'
            | b'&'
            | b'('
            | b')'
            | b'<'
            | b'>'
            | b'`'
            | b'='
            | b','
            | b'{'
            | b'}'
    )
}

/// The text of `$'...'` with its escapes decoded.
pub fn decode_ansi_c(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    let n = body.len();
    while i < n {
        let c = body[i];
        if c != b'\\' || i + 1 >= n {
            out.push(c);
            i += 1;
            continue;
        }
        let e = body[i + 1];
        i += 2;
        match e {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b'a' | b'b' | b'e' | b'E' | b'f' | b'v' => out.push(b' '),
            b'\\' | b'\'' | b'"' | b'?' => out.push(e),
            b'x' => {
                let mut j = i;
                while j < n && j < i + 2 && body[j].is_ascii_hexdigit() {
                    j += 1;
                }
                if j > i {
                    let v =
                        u8::from_str_radix(std::str::from_utf8(&body[i..j]).unwrap_or("20"), 16);
                    out.push(v.unwrap_or(b' '));
                }
                i = j;
            }
            b'0'..=b'7' => {
                let mut j = i;
                while j < n && j < i + 2 && (b'0'..=b'7').contains(&body[j]) {
                    j += 1;
                }
                let mut v: u32 = u32::from(e - b'0');
                for d in &body[i..j] {
                    v = v * 8 + u32::from(d - b'0');
                }
                out.push((v & 0xFF) as u8);
                i = j;
            }
            b'u' | b'U' => {
                let width = if e == b'u' { 4 } else { 8 };
                let mut j = i;
                while j < n && j < i + width && body[j].is_ascii_hexdigit() {
                    j += 1;
                }
                if j > i {
                    let v =
                        u32::from_str_radix(std::str::from_utf8(&body[i..j]).unwrap_or("20"), 16)
                            .ok()
                            .and_then(char::from_u32)
                            .unwrap_or(' ');
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(v.encode_utf8(&mut buf).as_bytes());
                }
                i = j;
            }
            b'c' if i < n => {
                out.push(b' ');
                i += 1;
            }
            _ => out.push(e),
        }
    }
    out
}

/// Two readings of the text with quotes and escapes off: `kept` puts a space
/// where an expansion stands, `joined` deletes the expansion (`i$@w` reads
/// `iw`). The inside of `${...}` is read as more text into `tail`.
fn readings(
    text: &[u8],
    depth: usize,
    kept: &mut Vec<u8>,
    joined: &mut Vec<u8>,
    tail: &mut Vec<u8>,
) {
    let n = text.len();
    let mut i = 0;
    while i < n {
        let c = text[i];
        if c == b'\\' {
            if i + 1 < n {
                if text[i + 1] != b'\n' {
                    kept.push(text[i + 1]);
                    joined.push(text[i + 1]);
                }
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if c == b'\'' || c == b'"' {
            i += 1;
            continue;
        }
        if c == b'$' && i + 1 < n {
            let d = text[i + 1];
            if d == b'\'' {
                let mut end = i + 2;
                while end < n && text[end] != b'\'' {
                    end += if text[end] == b'\\' { 2 } else { 1 };
                }
                let decoded = decode_ansi_c(&text[i + 2..end.min(n)]);
                kept.extend_from_slice(&decoded);
                joined.extend_from_slice(&decoded);
                i = end + 1;
                continue;
            }
            if d == b'"' {
                i += 1;
                continue;
            }
            if d == b'{' {
                let mut level = 0usize;
                let mut end = i + 1;
                while end < n {
                    if text[end] == b'{' {
                        level += 1;
                    } else if text[end] == b'}' {
                        level -= 1;
                        if level == 0 {
                            break;
                        }
                    }
                    end += 1;
                }
                let inner = brace_inner(&text[i + 2..end.min(n)]);
                kept.push(b' ');
                tail.push(b' ');
                if depth < MAX_BRACE_DEPTH {
                    let mut inner_joined = Vec::new();
                    readings(&inner, depth + 1, kept, &mut inner_joined, tail);
                    tail.push(b' ');
                    tail.extend_from_slice(&inner_joined);
                } else {
                    kept.extend_from_slice(&inner);
                }
                kept.push(b' ');
                tail.push(b' ');
                i = end + 1;
                continue;
            }
            if d == b'(' {
                kept.push(b' ');
                i += if text[i..].starts_with(b"$((") { 3 } else { 2 };
                continue;
            }
            if d.is_ascii_alphabetic() || d == b'_' {
                let mut end = i + 1;
                while end < n && (text[end].is_ascii_alphanumeric() || text[end] == b'_') {
                    end += 1;
                }
                kept.push(b' ');
                i = end;
                continue;
            }
            if matches!(
                d,
                b'@' | b'*' | b'#' | b'?' | b'-' | b'$' | b'!' | b'0'..=b'9'
            ) {
                kept.push(b' ');
                i += 2;
                continue;
            }
        }
        if c == b'`' {
            kept.push(b' ');
            i += 1;
            continue;
        }
        kept.push(c);
        joined.push(c);
        i += 1;
    }
}

/// The words inside `${NAME<op>WORD}`: the operators become spaces, a dash
/// that starts a word is an operator too, and so is the one after the name.
fn brace_inner(raw: &[u8]) -> Vec<u8> {
    let mut inner: Vec<u8> = raw
        .iter()
        .map(|b| {
            if matches!(
                b,
                b':' | b'#' | b'%' | b'/' | b'^' | b'@' | b'!' | b'+' | b'?' | b'*' | b'[' | b']'
            ) {
                b' '
            } else {
                *b
            }
        })
        .collect();
    let mut at_word_start = true;
    for byte in inner.iter_mut() {
        if *byte == b'-' && at_word_start {
            *byte = b' ';
        } else {
            at_word_start = byte.is_ascii_whitespace();
        }
    }
    let start = inner
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(inner.len());
    let mut end = start;
    while end < inner.len() && (inner[end].is_ascii_alphanumeric() || inner[end] == b'_') {
        end += 1;
    }
    if end > start && inner.get(end) == Some(&b'-') {
        for byte in &mut inner[start..=end] {
            *byte = b' ';
        }
    }
    inner
}

fn scan(reading: &[u8], extra: &[u8], name: &mut bool, verb: &mut bool) {
    for token in reading.split(|b| is_separator(*b) || extra.contains(b)) {
        if token.is_empty() || token.len() > 64 {
            continue;
        }
        let low = String::from_utf8_lossy(token).to_ascii_lowercase();
        let base = low.rsplit('/').next().unwrap_or("");
        let base = base.strip_suffix(".exe").unwrap_or(base);
        if NAMES.contains(&base) {
            *name = true;
        }
        if VERBS.contains(&low.as_str()) {
            *verb = true;
        }
    }
}

/// `text` with every empty `$()`, `$(())` and `` `` `` taken out: they splice
/// two halves of a word (`i$()w`).
fn without_empty_substitutions(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len());
    let mut changed = false;
    let mut i = 0;
    while i < text.len() {
        let rest = &text[i..];
        if rest.starts_with(b"``") {
            i += 2;
            changed = true;
            continue;
        }
        if rest.starts_with(b"$(") {
            let mut j = i + 2;
            let arith = text.get(j) == Some(&b'(');
            if arith {
                j += 1;
            }
            while text.get(j).is_some_and(|b| *b == b' ' || *b == b'\t') {
                j += 1;
            }
            let closed = if arith {
                text[j..].starts_with(b"))")
            } else {
                text.get(j) == Some(&b')')
            };
            if closed {
                i = j + if arith { 2 } else { 1 };
                changed = true;
                continue;
            }
        }
        out.push(text[i]);
        i += 1;
    }
    changed.then_some(out)
}

/// The guard's letters stand in the line, inside a longer word as well
/// (`innerwarden/`, `innerwardenZ`, `_innerwarden`): `innerwarden` anywhere,
/// or `iw` with no letter or digit on either side and no dash before it
/// (`/opt/iw/`, not `grep -iw` or `kiwi`). The shell can cut such a word
/// down to the name (`${X%/}`), so a line that holds it is not one that
/// leaves the guard's name out.
pub fn guard_letters(text: &[u8]) -> bool {
    fn holds(reading: &[u8]) -> bool {
        let low = reading.to_ascii_lowercase();
        low.windows(11).any(|w| w == b"innerwarden")
            || low.windows(2).enumerate().any(|(at, w)| {
                w == b"iw"
                    && !low[..at]
                        .last()
                        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'-')
                    && !low.get(at + 2).is_some_and(|b| b.is_ascii_alphanumeric())
            })
    }
    let read = |text: &[u8]| {
        let (mut kept, mut joined, mut tail) = (Vec::new(), Vec::new(), Vec::new());
        readings(text, 0, &mut kept, &mut joined, &mut tail);
        holds(&kept) || holds(&joined) || holds(&tail)
    };
    holds(text)
        || read(text)
        || without_empty_substitutions(text).is_some_and(|spliced| read(&spliced))
}

/// (a guard CLI name is a token of the line, a guard-lowering verb is).
/// `extra`: more bytes that split words (an `IFS` the line sets).
pub fn guard_tokens(text: &[u8], extra: &[u8]) -> (bool, bool) {
    let (mut name, mut verb) = (false, false);
    let mut read = |text: &[u8]| {
        let (mut kept, mut joined, mut tail) = (Vec::new(), Vec::new(), Vec::new());
        readings(text, 0, &mut kept, &mut joined, &mut tail);
        scan(&kept, extra, &mut name, &mut verb);
        scan(&joined, extra, &mut name, &mut verb);
        scan(&tail, extra, &mut name, &mut verb);
    };
    read(text);
    if let Some(spliced) = without_empty_substitutions(text) {
        read(&spliced);
    }
    if text.windows(2).any(|w| w == b"\\_") {
        // `env -S` reads `\_` as a space.
        let spaced = String::from_utf8_lossy(text).replace("\\_", " ");
        read(spaced.as_bytes());
    }
    (name, verb)
}
