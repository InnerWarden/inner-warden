//! Whether a word the shell still has to expand could become a program's
//! name.
//!
//! The shell's pattern characters are read as the shell reads them: `*`,
//! `?`, a bracket expression, a brace list `{a,b}`, a brace sequence
//! `{x..y}`. Everything else is taken as written, letter case aside.
//!
//! The word is walked once for each name, keeping the places in the name the
//! word could have reached, and no pattern is compiled. Compiling one cost a
//! quarter of a millisecond, a line can hold tens of thousands of different
//! ones (`./x1?y* z; ./x2?y* z; ...`), and a hook that does not answer in
//! time lets the command run.

use crate::shell_words::Mark;

/// Brace groups nested deeper than this are not followed: such a group is
/// taken for one that could become anything.
const NESTED_GROUPS: usize = 32;

/// Whether `text`, read with the shell's marks, could become `name`.
///
/// `name` is a program's name: short, ASCII, no blanks. For any other the
/// answer is that it could, which refuses more lines and never fewer.
pub(super) fn could_be(text: &[char], marks: &[Mark], name: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    if name.len() >= 63 || !name.iter().all(char::is_ascii_graphic) {
        return true;
    }
    let walk = Walk {
        text,
        marks,
        ends: group_ends(text, marks),
        name: &name,
    };
    walk.reached(0, text.len(), 1, 0) & (1 << name.len()) != 0
}

/// For each `{` the shell reads as a pattern, the `}` that closes it. Empty
/// when the word opens no group.
///
/// Found for the whole word in one pass. Looked for afresh from each `{`, a
/// word of nothing but `{` was read once for every character in it.
fn group_ends(text: &[char], marks: &[Mark]) -> Vec<Option<usize>> {
    let mut ends = Vec::new();
    let mut open = Vec::new();
    for (at, c) in text.iter().enumerate() {
        if marks.get(at) != Some(&Mark::Pattern) {
            continue;
        }
        match c {
            '{' => open.push(at),
            '}' => {
                if let Some(start) = open.pop() {
                    if ends.is_empty() {
                        ends = vec![None; text.len()];
                    }
                    ends[start] = Some(at);
                }
            }
            _ => {}
        }
    }
    ends
}

/// The characters that stand for `n` when letter case is set aside: its two
/// cases and, for `k` and `s`, the Kelvin sign and the long s, which the
/// pattern engine this reading took the place of counted as them.
fn written_as(n: char) -> [char; 3] {
    let other = match n.to_ascii_lowercase() {
        'k' => '\u{212A}',
        's' => '\u{17F}',
        _ => n,
    };
    [n.to_ascii_lowercase(), n.to_ascii_uppercase(), other]
}

/// A bracket expression.
struct Class {
    /// What it lists: a character alone is a range of one.
    ranges: Vec<(char, char)>,
    /// It opens with `!` or `^`.
    negated: bool,
    /// It holds `--` past its start, which the pattern engine read as "the
    /// first list less the second" and no shell does: it takes any
    /// character.
    any: bool,
}

impl Class {
    /// Reads the members of a bracket expression: every `-` at the start is
    /// a member, `a-z` is a range unless the `-` is the last member, and a
    /// range that runs backwards holds nothing.
    fn read(members: &[char], negated: bool) -> Self {
        let mut class = Class {
            ranges: Vec::new(),
            negated,
            any: false,
        };
        let mut at = 0;
        while members.get(at) == Some(&'-') {
            class.ranges.push(('-', '-'));
            at += 1;
        }
        while at < members.len() {
            let member = members[at];
            let dash_next = members.get(at + 1) == Some(&'-');
            if member == '-' && dash_next {
                class.any = true;
                return class;
            }
            match members.get(at + 2) {
                Some(end) if dash_next && *end != '-' => {
                    if member <= *end {
                        class.ranges.push((member, *end));
                    }
                    at += 3;
                }
                _ => {
                    class.ranges.push((member, member));
                    at += 1;
                }
            }
        }
        class
    }

    /// Whether the expression takes `n`, letter case aside.
    fn takes(&self, n: char) -> bool {
        if self.any {
            return true;
        }
        let listed = self.ranges.iter().any(|(low, high)| {
            written_as(n)
                .iter()
                .any(|written| low <= written && written <= high)
        });
        listed != self.negated
    }
}

/// One word read against one name.
///
/// A set of places is a `u64`: bit N says the word so far could have spelled
/// the first N characters of the name.
struct Walk<'a> {
    text: &'a [char],
    marks: &'a [Mark],
    ends: Vec<Option<usize>>,
    name: &'a [char],
}

impl Walk<'_> {
    /// Whether the shell reads the character at `at` as a pattern.
    fn is_pattern(&self, at: usize) -> bool {
        self.marks.get(at) == Some(&Mark::Pattern)
    }

    /// The places after one more character of the name, for the ones
    /// `takes` accepts.
    fn step(&self, places: u64, takes: impl Fn(char) -> bool) -> u64 {
        let mut next = 0;
        for (at, n) in self.name.iter().enumerate() {
            if places & (1 << at) != 0 && takes(*n) {
                next |= 1 << (at + 1);
            }
        }
        next
    }

    /// The places after a character taken as written.
    fn written(&self, places: u64, c: char) -> u64 {
        self.step(places, |n| written_as(n).contains(&c))
    }

    /// The places after any run of characters, an empty one too.
    fn any_run(&self, places: u64) -> u64 {
        if places == 0 {
            return 0;
        }
        let all = (1u64 << (self.name.len() + 1)) - 1;
        all & !((1u64 << places.trailing_zeros()) - 1)
    }

    /// The bracket expression opening at `at` in a piece of the word that
    /// ends before `to`, and where its `]` is. Its first member never closes
    /// it.
    fn class_at(&self, at: usize, to: usize) -> Option<(Class, usize)> {
        let negated = at + 1 < to && matches!(self.text[at + 1], '!' | '^');
        let first = if negated { at + 2 } else { at + 1 };
        let end = ((first + 1).min(to)..to).find(|at| self.text[*at] == ']')?;
        Some((Class::read(&self.text[first..end], negated), end))
    }

    /// The places after the piece of the word from `from` up to `to`.
    fn reached(&self, from: usize, to: usize, mut places: u64, depth: usize) -> u64 {
        let mut at = from;
        while at < to && places != 0 {
            let c = self.text[at];
            if !self.is_pattern(at) {
                places = self.written(places, c);
                at += 1;
                continue;
            }
            match c {
                '*' => places = self.any_run(places),
                '?' => places = self.step(places, |_| true),
                '[' => {
                    if let Some((class, end)) = self.class_at(at, to) {
                        places = self.step(places, |n| class.takes(n));
                        at = end + 1;
                        continue;
                    }
                    places = self.written(places, c);
                }
                '{' => {
                    let end = self.ends.get(at).copied().flatten();
                    if let Some(end) = end.filter(|end| *end < to) {
                        places = self.group(at + 1, end, places, depth);
                        at = end + 1;
                        continue;
                    }
                    places = self.written(places, c);
                }
                _ => places = self.written(places, c),
            }
            at += 1;
        }
        places
    }

    /// The places after a brace group whose inside runs from `from` up to
    /// `to`: a sequence `x..y`, a list `a,b`, or (neither) the braces as
    /// written.
    fn group(&self, from: usize, to: usize, places: u64, depth: usize) -> u64 {
        if depth >= NESTED_GROUPS {
            return self.any_run(places);
        }
        let inside: String = self.text[from..to].iter().collect();
        if let Some((first, last)) = inside.split_once("..") {
            let last = last.split("..").next().unwrap_or(last);
            return match (first.parse::<i64>(), last.parse::<i64>()) {
                (Ok(a), Ok(b)) if a.abs_diff(b) <= 64 => {
                    (a.min(b)..=a.max(b)).fold(0, |reached, item| {
                        let item = item.to_string();
                        reached
                            | item
                                .chars()
                                .fold(places, |places, c| self.written(places, c))
                    })
                }
                _ => match (super::single_char(first), super::single_char(last)) {
                    (Some(a), Some(b)) => {
                        let (low, high) = (a.min(b), a.max(b));
                        self.step(places, |n| {
                            written_as(n)
                                .iter()
                                .any(|written| low <= *written && *written <= high)
                        })
                    }
                    _ => self.any_run(places),
                },
            };
        }
        let mut reached = 0;
        let mut listed = false;
        let mut nested = 0usize;
        let mut start = from;
        for at in from..to {
            if !self.is_pattern(at) {
                continue;
            }
            match self.text[at] {
                '{' => nested += 1,
                '}' => nested = nested.saturating_sub(1),
                ',' if nested == 0 => {
                    reached |= self.reached(start, at, places, depth + 1);
                    start = at + 1;
                    listed = true;
                }
                _ => {}
            }
        }
        if !listed {
            let opened = self.written(places, '{');
            return self.written(self.reached(from, to, opened, depth + 1), '}');
        }
        reached | self.reached(start, to, places, depth + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{pattern_regex, GUARD_PROGRAMS, WORD_FEEDERS};
    use super::{could_be, NESTED_GROUPS};
    use crate::shell_words::Mark;

    /// A word as the shell marks it: `*`, `?`, `[`, `]`, `{`, `}` and `,`
    /// are patterns unless a backslash stands before them.
    fn word(spec: &str) -> (Vec<char>, Vec<Mark>) {
        let (mut text, mut marks) = (Vec::new(), Vec::new());
        let mut chars = spec.chars();
        while let Some(c) = chars.next() {
            let (c, mark) = match c {
                '\\' => (chars.next().unwrap_or('\\'), Mark::Plain),
                '*' | '?' | '[' | ']' | '{' | '}' | ',' => (c, Mark::Pattern),
                _ => (c, Mark::Plain),
            };
            text.push(c);
            marks.push(mark);
        }
        (text, marks)
    }

    /// FAILS ON REVERT: each row names the piece of the reading it holds
    /// (take the range out of `Class::read` and `[a-z]w` is no longer `iw`;
    /// answer a list with its first item alone and `{x,iw}` is not either).
    #[test]
    fn a_word_is_read_as_the_shell_expands_it() {
        for (spec, name, could) in [
            ("iw", "iw", true),
            ("IW", "iw", true),
            ("iwx", "iw", false),
            ("i", "iw", false),
            // `?` and `*`.
            ("i?", "iw", true),
            ("i?", "innerwarden", false),
            ("?", "iw", false),
            ("*", "iw", true),
            ("inner*", "innerwarden", true),
            ("inner*", "innerwarden-ctl", true),
            ("*-ctl", "innerwarden-ctl", true),
            ("*-ctl", "innerwarden", false),
            ("i*w*", "iw", true),
            ("x0?y*", "xargs", false),
            // Quoted, they are themselves.
            (r"i\?", "iw", false),
            (r"\*", "iw", false),
            // A bracket expression.
            ("[a-z]w", "iw", true),
            ("[A-Z]w", "iw", true),
            ("[a-h]w", "iw", false),
            ("[!a-h]w", "iw", true),
            ("[^i]w", "iw", false),
            ("[xi]w", "iw", true),
            ("i[w-]", "iw", true),
            ("iw[-]guard", "iw-guard", true),
            ("iw[a-]guard", "iw-guard", true),
            ("iw[+--]guard", "iw-guard", true),
            ("[z-a]w", "iw", false),
            ("[]i]w", "iw", true),
            ("[iw", "iw", false),
            // What the old reading and the shell do not agree on.
            ("[a-z--i]w", "iw", true),
            // A brace list.
            ("{x,iw}", "iw", true),
            ("{iw,x}", "iw", true),
            ("iw{,-guard}", "iw", true),
            ("iw{,-guard}", "iw-guard", true),
            ("{i,{x,y}}w", "iw", true),
            ("{x,{y,i}}w", "iw", true),
            ("{x,y}w", "iw", false),
            ("se{d,m}", "sem", true),
            (r"{x\,iw}", "iw", false),
            // No list and no sequence: the braces as written.
            ("{iw}", "iw", false),
            ("{iw", "iw", false),
            // A brace sequence.
            ("i{v..x}", "iw", true),
            ("i{x..v}", "iw", true),
            ("i{a..c}", "iw", false),
            ("x{8..12}", "x10", true),
            ("x{12..8}", "x9", true),
            ("x{8..12}", "x13", false),
            ("x{8..12..2}", "x9", true),
            ("x{1..900}", "xyz", true),
            ("x{a..}", "xyz", true),
        ] {
            let (text, marks) = word(spec);
            assert_eq!(could_be(&text, &marks, name), could, "{spec} as {name}");
        }
    }

    /// A group nested past the limit is one that could be anything, and a
    /// word that only opens groups costs one pass.
    ///
    /// FAILS ON REVERT: follow the groups however deep they go and the
    /// first answer is `false`.
    #[test]
    fn a_group_nested_past_the_limit_could_be_anything() {
        let nested = |depth: usize| format!("{}b{}", "{a,".repeat(depth), "}".repeat(depth));
        let (text, marks) = word(&nested(NESTED_GROUPS + 1));
        assert!(could_be(&text, &marks, "iw"));
        let (text, marks) = word(&nested(NESTED_GROUPS));
        assert!(!could_be(&text, &marks, "iw"));
        let (text, marks) = word(&"{".repeat(200_000));
        assert!(!could_be(&text, &marks, "iw"));
    }

    /// The reading answers as the compiled pattern it took the place of, on
    /// some thousands of words made of the characters that matter and marked
    /// every which way.
    ///
    /// The two are allowed to part in one direction only, and only where the
    /// pattern could not be compiled or the word holds `--`: there this
    /// reading may say "could" where the pattern said "could not".
    ///
    /// FAILS ON REVERT: any change to what a character, a bracket expression
    /// or a group takes shows up here as a word the two answer differently.
    #[test]
    fn the_reading_answers_as_the_compiled_pattern_did() {
        const ALPHABET: &[char] = &[
            'i', 'w', 's', 'k', 'a', 'x', 'z', 'I', 'S', 'Z', '0', '1', '9', '-', '-', '*', '*',
            '?', '[', '[', ']', ']', '!', '^', '{', '{', '}', '}', ',', ',', '.', '.', '\u{212A}',
            '\u{17F}', '\\', ' ', '\u{e9}',
        ];
        let names: Vec<&str> = GUARD_PROGRAMS
            .iter()
            .chain(WORD_FEEDERS)
            .copied()
            .chain(["i", "s", "k", "x", "-", "1", "10", "a-", "sk", "x9"])
            .collect();
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = |below: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as usize % below
        };
        let (mut compiled, mut could, mut parted) = (0, 0, 0);
        for _ in 0..4_000 {
            let length = 1 + next(7);
            let text: Vec<char> = (0..length)
                .map(|_| ALPHABET[next(ALPHABET.len())])
                .collect();
            let marks: Vec<Mark> = text
                .iter()
                .map(|c| {
                    let special = "*?[]{},.!^-".contains(*c);
                    match (special, next(6)) {
                        (true, 0) | (false, 1..) => Mark::Plain,
                        (false, 0) if next(2) == 0 => Mark::Expansion,
                        _ => Mark::Pattern,
                    }
                })
                .collect();
            let shown: String = text.iter().collect();
            let pattern = format!("(?i)^(?:{})$", pattern_regex(&text, &marks));
            let pattern = regex::Regex::new(&pattern).ok();
            compiled += usize::from(pattern.is_some());
            for name in &names {
                let read = could_be(&text, &marks, name);
                let old = pattern.as_ref().is_some_and(|re| re.is_match(name));
                could += usize::from(read);
                if pattern.is_none() || shown.contains("--") {
                    assert!(read || !old, "{shown:?} {marks:?} as {name}");
                    parted += usize::from(read != old);
                } else {
                    assert_eq!(read, old, "{shown:?} {marks:?} as {name}");
                }
            }
        }
        // Not a test that passes because nothing compiled or nothing matched.
        assert!(compiled > 3_000, "{compiled} compiled");
        assert!(could > 300, "{could} could");
        assert!(parted < 200, "{parted} parted");
    }
}
