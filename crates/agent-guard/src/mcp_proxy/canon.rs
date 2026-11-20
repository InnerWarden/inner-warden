//! One spelling for a value written in another: what the provenance table
//! ([`super::effect`]) and the taint tracker ([`super::taint`]) compare.
//!
//! An injected order can hand the model a value spelled so that it is not
//! the same text as the value the call carries: `attacker[at]evil[.]com`,
//! `attacker%40evil.com`, `attacker&#64;evil.com`, `hxxps://evil.com`, a
//! punycode label (`xn--...`), a Cyrillic `а` for a Latin `a`, fullwidth
//! letters, a zero-width space. Both sides are brought to one spelling before
//! they are compared, so a value read in one spelling and sent in another is
//! the same value.
//!
//! Also undone: a run of base64 or base64url that decodes to printable ASCII
//! (`cGF5ZWVAZXhhbXBsZS5uZXQ=`), and Unicode compatibility forms (NFKC, then
//! NFC: mathematical letters, ligatures, a letter and its accent written as
//! two characters). [`squeezed`] also drops combining marks, so `Ação` and
//! `Acao` squeeze alike.
//!
//! What this does not undo: a confusable that is not in [`confusable`] (the
//! table covers the Cyrillic, Greek and Latin letters that pass for ASCII
//! letters, and fullwidth forms, not every entry of Unicode's list), a value
//! the model rewrote (translated, split, spelled out in words), and an
//! encoding other than percent, HTML entities, punycode and base64 (hex, a
//! homemade one).

use std::borrow::Cow;

use base64::Engine as _;
use unicode_normalization::char::is_combining_mark;
use unicode_normalization::UnicodeNormalization;

/// The longest punycode label decoded (DNS allows 63 bytes).
const MAX_LABEL: usize = 63;

/// The shortest run of base64 characters tried as base64.
const MIN_BASE64_RUN: usize = 16;

/// `text` in one spelling: base64 runs that hold printable text decoded,
/// percent escapes and HTML entities decoded, NFKC then NFC,
/// punycode labels decoded, letters that pass for ASCII letters (and
/// fullwidth forms) made ASCII, zero-width characters taken out, and a
/// defanged address or link (`[at]`, `[.]`, `(dot)`, `hxxp`) put back.
/// Case is kept. Borrowed when there is nothing to change.
pub(crate) fn canonical(text: &str) -> Cow<'_, str> {
    if !needs_work(text) {
        return Cow::Borrowed(text);
    }
    let mut s: String = base64_decoded(text);
    s = percent_decoded(&s);
    s = entities_decoded(&s);
    if !s.is_ascii() {
        s = s.nfkc().collect::<String>().nfc().collect();
    }
    s = punycode_decoded(&s);
    s = s.chars().filter_map(confusable).collect();
    s = undefanged(&s);
    if s == text {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(s)
    }
}

fn needs_work(text: &str) -> bool {
    if !text.is_ascii() {
        return true;
    }
    let lower = text.as_bytes();
    if lower
        .iter()
        .any(|b| matches!(b, b'%' | b'&' | b'[' | b'(' | b'{'))
    {
        return true;
    }
    contains_ci(text, "xn--") || contains_ci(text, "hxxp") || has_base64_run(text)
}

fn is_base64_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'=')
}

fn has_base64_run(text: &str) -> bool {
    let mut run = 0;
    for b in text.bytes() {
        if is_base64_byte(b) {
            run += 1;
            if run >= MIN_BASE64_RUN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// What a run of base64 or base64url decodes to, when it is printable ASCII
/// (letters, digits, punctuation, spaces and line breaks): the text an
/// injected order hides an address or a link in. A run that decodes to
/// anything else (an identifier, a path, a binary blob) is not one.
fn base64_text(run: &str) -> Option<String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let bytes = [STANDARD, URL_SAFE]
        .iter()
        .find_map(|engine| engine.decode(run).ok())
        .or_else(|| {
            let bare = run.trim_end_matches('=');
            [STANDARD_NO_PAD, URL_SAFE_NO_PAD]
                .iter()
                .find_map(|engine| engine.decode(bare).ok())
        })?;
    let printable = !bytes.is_empty()
        && bytes
            .iter()
            .all(|&b| (0x20..0x7f).contains(&b) || matches!(b, b'\n' | b'\r' | b'\t'));
    printable.then(|| String::from_utf8(bytes).ok()).flatten()
}

/// Every run of at least [`MIN_BASE64_RUN`] base64 characters that decodes to
/// printable text ([`base64_text`]) replaced by that text.
fn base64_decoded(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut i = 0;
    while i < bytes.len() {
        if !is_base64_byte(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_base64_byte(bytes[i]) {
            i += 1;
        }
        // Base64 bytes are ASCII, so both ends are character boundaries.
        if i - start >= MIN_BASE64_RUN {
            if let Some(decoded) = base64_text(&text[start..i]) {
                out.push_str(&text[last..start]);
                out.push_str(&decoded);
                last = i;
            }
        }
    }
    out.push_str(&text[last..]);
    out
}

/// `text` with only its letters and digits, lower-cased, compatibility
/// forms and accents taken apart (NFKD) and the accents dropped: what two
/// spellings of one account number or name have in common.
pub(crate) fn squeezed(text: &str) -> String {
    text.nfkd()
        .filter(|c| !is_combining_mark(*c))
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

/// `%XX` escapes as the bytes they name, read as UTF-8 (a byte sequence
/// that is not UTF-8 becomes U+FFFD).
fn percent_decoded(text: &str) -> String {
    if !text.contains('%') {
        return text.to_string();
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| (b as char).to_digit(16);
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `&#NN;`, `&#xHH;` and the named entities an address or a link is
/// written with, decoded.
fn entities_decoded(text: &str) -> String {
    if !text.contains('&') {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        // Only the next bytes: an entity is short, and a search of the whole
        // rest at every `&` is quadratic in a text of ampersands.
        let end = tail.as_bytes()[1..tail.len().min(14)]
            .iter()
            .position(|&b| b == b';')
            .map(|e| e + 1);
        let decoded = end.and_then(|end| {
            let body = &tail[1..end];
            let c = if let Some(num) = body.strip_prefix('#') {
                let code = match num.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                    None => num.parse::<u32>().ok()?,
                };
                char::from_u32(code)?
            } else {
                match body.to_ascii_lowercase().as_str() {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "quot" => '"',
                    "apos" => '\'',
                    "commat" => '@',
                    "period" => '.',
                    "sol" => '/',
                    "colon" => ':',
                    "nbsp" => ' ',
                    "hyphen" | "dash" => '-',
                    "lowbar" => '_',
                    _ => return None,
                }
            };
            Some((c, end + 1))
        });
        match decoded {
            Some((c, used)) => {
                out.push(c);
                rest = &tail[used..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Every `xn--` label (letters, digits and `-` after it) decoded from
/// punycode (RFC 3492). A label that does not decode is kept as written.
fn punycode_decoded(text: &str) -> String {
    if !contains_ci(text, "xn--") {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest
        .as_bytes()
        .windows(4)
        .position(|w| w.eq_ignore_ascii_case(b"xn--"))
    {
        // Only at the start of a label: not inside a longer word.
        let at_start = at == 0
            || !rest.as_bytes()[at - 1].is_ascii_alphanumeric() && rest.as_bytes()[at - 1] != b'-';
        out.push_str(&rest[..at]);
        let label_end = rest[at + 4..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .map_or(rest.len(), |e| at + 4 + e);
        let label = &rest[at + 4..label_end];
        match (at_start && label.len() <= MAX_LABEL)
            .then(|| punycode(&label.to_ascii_lowercase()))
            .flatten()
        {
            Some(decoded) => out.push_str(&decoded),
            None => out.push_str(&rest[at..label_end]),
        }
        rest = &rest[label_end..];
    }
    out.push_str(rest);
    out
}

/// RFC 3492 decoding of one label's encoded part.
fn punycode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const TMIN: u32 = 1;
    const TMAX: u32 = 26;
    let (basic, encoded) = match input.rfind('-') {
        Some(i) => (&input[..i], &input[i + 1..]),
        None => ("", input),
    };
    if !basic.is_ascii() || encoded.is_empty() {
        return None;
    }
    let mut output: Vec<char> = basic.chars().collect();
    let (mut n, mut i, mut bias) = (128u32, 0u32, 72u32);
    let digits: Vec<u32> = encoded
        .bytes()
        .map(|b| match b {
            b'a'..=b'z' => Some(u32::from(b - b'a')),
            b'0'..=b'9' => Some(u32::from(b - b'0') + 26),
            _ => None,
        })
        .collect::<Option<_>>()?;
    let mut d = digits.into_iter();
    while d.len() > 0 {
        let old_i = i;
        let mut w = 1u32;
        let mut k = BASE;
        loop {
            let digit = d.next()?;
            i = i.checked_add(digit.checked_mul(w)?)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias + TMAX {
                TMAX
            } else {
                k - bias
            };
            if digit < t {
                break;
            }
            w = w.checked_mul(BASE - t)?;
            k += BASE;
        }
        let points = output.len() as u32 + 1;
        bias = adapt(i - old_i, points, old_i == 0);
        n = n.checked_add(i / points)?;
        i %= points;
        output.insert(i as usize, char::from_u32(n)?);
        i += 1;
        if output.len() > MAX_LABEL {
            return None;
        }
    }
    Some(output.into_iter().collect())
}

fn adapt(delta: u32, points: u32, first: bool) -> u32 {
    let mut delta = if first { delta / 700 } else { delta / 2 };
    delta += delta / points;
    let mut k = 0;
    while delta > ((36 - 1) * 26) / 2 {
        delta /= 36 - 1;
        k += 36;
    }
    k + (36 * delta) / (delta + 38)
}

/// The ASCII character a character passes for, the character itself when
/// it passes for none, or nothing for a character that shows nothing.
fn confusable(c: char) -> Option<char> {
    if c.is_ascii() {
        return Some(c);
    }
    let code = c as u32;
    // Fullwidth forms of ASCII.
    if (0xFF01..=0xFF5E).contains(&code) {
        return char::from_u32(code - 0xFEE0);
    }
    let ascii = match c {
        // Shows nothing.
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}' => return None,
        '\u{3002}' | '\u{FF61}' | '\u{2024}' => '.',
        '\u{FE6B}' => '@',
        // Cyrillic.
        'а' | 'А' => 'a',
        'в' | 'В' => 'b',
        'с' | 'С' => 'c',
        'ԁ' => 'd',
        'е' | 'Е' | 'ё' => 'e',
        'һ' | 'н' | 'Н' => 'h',
        'і' | 'І' => 'i',
        'ӏ' | 'Ӏ' => 'l',
        'ј' | 'Ј' => 'j',
        'к' | 'К' => 'k',
        'м' | 'М' => 'm',
        'о' | 'О' => 'o',
        'р' | 'Р' => 'p',
        'ԛ' => 'q',
        'ѕ' | 'Ѕ' => 's',
        'т' | 'Т' => 't',
        'у' | 'У' | 'ү' => 'y',
        'ԝ' => 'w',
        'х' | 'Х' => 'x',
        // Greek.
        'α' | 'Α' => 'a',
        'Β' | 'β' => 'b',
        'ε' | 'Ε' => 'e',
        'Η' => 'h',
        'ι' | 'Ι' => 'i',
        'κ' | 'Κ' => 'k',
        'Μ' => 'm',
        'ν' | 'Ν' => 'n',
        'ο' | 'Ο' => 'o',
        'ρ' | 'Ρ' => 'p',
        'τ' | 'Τ' => 't',
        'υ' | 'Υ' => 'u',
        'χ' | 'Χ' => 'x',
        'Ζ' => 'z',
        // Latin.
        'ı' => 'i',
        'ℓ' | 'ⅼ' => 'l',
        _ => c,
    };
    Some(ascii)
}

/// A defanged address or link put back: `[at]`, `(at)`, `{at}`, `[@]` for
/// `@`; `[.]`, `(.)`, `{.}`, `[dot]`, `(dot)`, `{dot}` for `.`; `[:]`
/// for `:`; `hxxp` for `http`. In any case of letters.
fn undefanged(text: &str) -> String {
    const PAIRS: &[(&str, &str)] = &[
        ("[at]", "@"),
        ("(at)", "@"),
        ("{at}", "@"),
        ("[@]", "@"),
        ("(@)", "@"),
        ("[dot]", "."),
        ("(dot)", "."),
        ("{dot}", "."),
        ("[.]", "."),
        ("(.)", "."),
        ("{.}", "."),
        ("[:]", ":"),
        ("hxxp", "http"),
    ];
    let mut s = text.to_string();
    for (from, to) in PAIRS {
        if contains_ci(&s, from) {
            s = replace_ci(&s, from, to);
        }
    }
    s
}

fn replace_ci(text: &str, from: &str, to: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut last = 0;
    while i + from.len() <= bytes.len() {
        if bytes[i..i + from.len()].eq_ignore_ascii_case(from.as_bytes()) {
            out.push_str(&text[last..i]);
            out.push_str(to);
            i += from.len();
            last = i;
        } else {
            i += 1;
        }
    }
    out.push_str(&text[last..]);
    out
}

/// The forms a value can be found in, as one compares it: the value in one
/// spelling, without a scheme (`mailto:`, `https://`), without a trailing
/// `/`, and the host alone of a link (`https://evil.com/inbox` is also
/// `evil.com`). Each is a value of its own only where it is not empty.
pub(crate) fn value_forms(value: &str) -> Vec<String> {
    let base = canonical(value.trim()).to_lowercase();
    let mut forms = vec![base.clone()];
    let mut push = |form: &str| {
        let form = form.trim();
        if !form.is_empty() && !forms.iter().any(|f| f == form) {
            forms.push(form.to_string());
        }
    };
    let schemeless = without_scheme(&base);
    push(schemeless);
    let trimmed = schemeless.trim_end_matches('/');
    push(trimmed);
    if schemeless.len() != base.len() || trimmed.contains('/') {
        if let Some((host, _)) = trimmed.split_once('/') {
            if host.contains('.') {
                push(host);
            }
        }
    }
    forms
}

/// `text` without a leading `mailto:`, `tel:` or `<scheme>://`.
pub(crate) fn without_scheme(text: &str) -> &str {
    for scheme in ["mailto:", "tel:", "sms:"] {
        // `get`: a text that starts with a letter of more than one byte
        // (`Ação`) has no boundary where the scheme would end.
        if text.len() > scheme.len()
            && text
                .get(..scheme.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(scheme))
        {
            return &text[scheme.len()..];
        }
    }
    if let Some(at) = text.find("://") {
        let scheme = &text[..at];
        if !scheme.is_empty()
            && scheme.len() <= 16
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        {
            return &text[at + 3..];
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rewritten_form_of_an_address_is_the_address() {
        for written in [
            "attacker@evil.com",
            "attacker[at]evil[.]com",
            "attacker(at)evil(dot)com",
            "attacker{at}evil{dot}com",
            "attacker[@]evil[dot]com",
            "attacker%40evil.com",
            "attacker&#64;evil.com",
            "attacker&#x40;evil.com",
            "attacker&commat;evil&period;com",
            "\u{430}ttacker@evil.com",
            "attacker@\u{435}vil.com",
            "ａｔｔａｃｋｅｒ＠ｅｖｉｌ．ｃｏｍ",
            "att\u{200B}acker@evil.com",
            "attacker@evil\u{3002}com",
        ] {
            assert_eq!(canonical(written), "attacker@evil.com", "{written}");
        }
    }

    #[test]
    fn a_link_is_its_host_and_its_link() {
        assert_eq!(canonical("hxxps://evil[.]com/x"), "https://evil.com/x");
        let forms = value_forms("https://evil.com/inbox/");
        for form in ["https://evil.com/inbox/", "evil.com/inbox", "evil.com"] {
            assert!(forms.iter().any(|f| f == form), "{form}: {forms:?}");
        }
        let forms = value_forms("mailto:Attacker@Evil.com");
        assert!(forms.iter().any(|f| f == "attacker@evil.com"), "{forms:?}");
    }

    #[test]
    fn punycode_labels_decode_and_their_lookalikes_become_ascii() {
        // RFC 3492 sample: "bücher".
        assert_eq!(punycode("bcher-kva").as_deref(), Some("bücher"));
        // "аррӏе" (Cyrillic) is xn--80ak6aa92e and passes for "apple".
        assert_eq!(canonical("https://xn--80ak6aa92e.com"), "https://apple.com");
        // Not a label start, or not punycode: kept.
        assert_eq!(canonical("abcxn--80ak6aa92e"), "abcxn--80ak6aa92e");
        assert_eq!(canonical("xn--!!"), "xn--!!");
    }

    #[test]
    fn base64_and_compatibility_forms_are_undone() {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode("payee.two-5521@example.net");
        assert_eq!(
            canonical(&format!("send to {encoded} now")),
            "send to payee.two-5521@example.net now"
        );
        let url = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode("https://pay.example.net/a?b=c");
        assert_eq!(canonical(&url), "https://pay.example.net/a?b=c");
        // Mathematical letters and a decomposed accent.
        assert_eq!(
            canonical("\u{1D429}\u{1D41A}\u{1D432}\u{1D41E}\u{1D41E}@example.net"),
            "payee@example.net"
        );
        assert_eq!(canonical("Ac\u{327}a\u{303}o"), "Ação");
        assert_eq!(squeezed("Ação 12"), "acao12");
        // Identifiers and paths are not base64 text.
        for kept in [
            "internationalization_layer",
            "/usr/share/initramfs-tools/hooks/x",
            "averyLongIdentifierNameHere",
        ] {
            assert_eq!(canonical(kept), kept);
        }
    }

    /// Text that starts with, or holds, characters of more than one byte is
    /// never cut inside one (a panic aborts the proxy in a release build).
    #[test]
    fn text_that_is_not_ascii_never_panics() {
        for text in [
            "Ação",
            "avaliação",
            "ação://x",
            "mailtoção",
            "çmailto:x",
            "📧 mail@example.net",
            "📧📧📧📧📧📧📧📧📧📧📧📧📧📧📧📧",
            "xn--ação",
            "%E2%82",
            "&#x1F4E7;",
            "Ação[at]exemplo[.]com.br/",
        ] {
            let _ = canonical(text);
            let _ = value_forms(text);
            let _ = without_scheme(text);
            let _ = squeezed(text);
        }
    }

    /// A text of ampersands costs time in proportion to its length.
    #[test]
    fn many_ampersands_take_linear_time() {
        let text = "&".repeat(4 * 1024 * 1024);
        let start = std::time::Instant::now();
        let _ = canonical(&text);
        let mixed = "&amp".repeat(1024 * 1024);
        let _ = canonical(&mixed);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn plain_text_is_borrowed_and_unchanged() {
        assert!(matches!(
            canonical("plain words, no tricks"),
            Cow::Borrowed(_)
        ));
        assert_eq!(canonical("50% off & more"), "50% off & more");
        assert_eq!(canonical("a & b; c"), "a & b; c");
        assert_eq!(canonical("100%"), "100%");
    }
}
