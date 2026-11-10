//! A flat, single-pass reading of a shell line into its simple commands, in
//! every context the shell runs: the line, `$( )`, backticks, `<( )`, `( )`.
//! Where the reading is not certain it says so (`doubt`) instead of guessing.

use super::tokens::decode_ansi_c;

/// Stands in a word where an expansion was.
pub const EXPANSION: char = '\u{1}';
const MAX_FRAMES: usize = 24;

#[derive(Default, Clone, Debug)]
pub struct Word {
    /// Quotes off, escapes resolved, each expansion one [`EXPANSION`].
    pub lit: String,
    /// Holds `$...` or a backtick substitution.
    pub expansion: bool,
    /// Holds an unquoted `*`, `?`, `[`, a brace list or a leading `~`.
    pub glob: bool,
    pub quoted: bool,
    /// Holds `$( )`, backticks or `<( )`: text a command printed.
    pub substitution: bool,
    /// Starts with an unquoted `~`: the shell puts a directory there.
    pub tilde: bool,
    /// Holds an extended glob group, `@( )` and the like.
    pub extglob: bool,
    /// Holds `$'...'`, which `sh` reads as `$` and a plain quoted string.
    pub ansi_c: bool,
    /// The `sh` reading of the word, when it ends with its one `$'...'`.
    pub sh_alt: Option<String>,
    /// The length of `lit` right after that `$'...'`.
    pub ansi_len: usize,
    brace_open: bool,
    brace_list: bool,
}

impl Word {
    pub fn dynamic(&self) -> bool {
        self.expansion || self.glob
    }
}

#[derive(Default, Clone, Debug)]
pub struct Heredoc {
    pub body: String,
    pub quoted: bool,
}

#[derive(Default, Clone, Debug)]
pub struct Command {
    pub words: Vec<Word>,
    /// Its output is piped into the next command.
    pub pipe_next: bool,
    /// Files its output is redirected to.
    pub writes: Vec<Word>,
    pub heredocs: Vec<Heredoc>,
    pub herestrings: Vec<Word>,
    /// `a &>f b`: where the words of the `sh` reading (`>f b`) start.
    pub alt_start: Option<usize>,
    /// Read inside `(( ))`: arithmetic unless the reading is in doubt.
    pub arithmetic: bool,
    id: usize,
}

#[derive(Default, Debug)]
pub struct Lexed {
    pub commands: Vec<Command>,
    pub doubt: Vec<&'static str>,
    /// The functions the text defines.
    pub functions: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Top,
    Subst,
    Backtick,
    Subshell,
    /// `$((` or `((`: arithmetic, or two nested openers.
    Dual,
    /// `${ ... }`
    Param,
    /// `a=( ... )` or an extglob group: words, not commands.
    Array,
}

#[derive(Clone, Copy, PartialEq)]
enum Redirect {
    None,
    Read,
    Write,
    HereString,
}

#[derive(Clone, Copy, PartialEq)]
enum Case {
    AwaitIn,
    Pattern,
    Body,
}

struct Frame {
    kind: Kind,
    command: Command,
    word: Option<Word>,
    double_quoted: bool,
    redirect: Redirect,
    cases: Vec<Case>,
    /// A `Dual` frame opened by `$((`, not by `((`.
    dollar: bool,
    /// Every word of the command so far is a keyword.
    lead: bool,
}

struct Pending {
    delimiter: Vec<u8>,
    strip_tabs: bool,
    quoted: bool,
    owner: usize,
}

pub struct Lexer<'a> {
    text: &'a [u8],
    frames: Vec<Frame>,
    pending: Vec<Pending>,
    out: Lexed,
    next_id: usize,
    /// The text is a here-document body: its own words are data.
    heredoc_body: bool,
}

const KEYWORDS: &[&str] = &[
    "then", "do", "else", "elif", "if", "while", "until", "!", "{", "}", "fi", "done", "time",
];

impl<'a> Lexer<'a> {
    pub fn read(text: &'a [u8]) -> Lexed {
        Self::read_region(text, false)
    }

    /// `as_heredoc_body`: the text is read as inside double quotes that never
    /// close (only its substitutions run).
    pub fn read_region(text: &'a [u8], as_heredoc_body: bool) -> Lexed {
        let mut lexer = Lexer {
            text,
            frames: Vec::new(),
            pending: Vec::new(),
            out: Lexed::default(),
            next_id: 0,
            heredoc_body: as_heredoc_body,
        };
        lexer.push(Kind::Top);
        if as_heredoc_body {
            lexer.top().double_quoted = true;
            lexer.top().word = Some(Word::default());
        }
        lexer.run(as_heredoc_body);
        lexer.out
    }

    fn top(&mut self) -> &mut Frame {
        self.frames
            .last_mut()
            .expect("the base frame is never popped")
    }

    fn push(&mut self, kind: Kind) {
        if self.frames.len() >= MAX_FRAMES {
            // Past the limit nothing nests: the reading is in doubt from here.
            self.doubt("deep");
            return;
        }
        if matches!(kind, Kind::Subst | Kind::Backtick | Kind::Dual) {
            if let Some(word) = self.frames.last_mut().and_then(|f| f.word.as_mut()) {
                word.substitution = true;
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        self.frames.push(Frame {
            kind,
            command: Command {
                id,
                ..Command::default()
            },
            word: None,
            double_quoted: false,
            redirect: Redirect::None,
            cases: Vec::new(),
            dollar: false,
            lead: true,
        });
    }

    fn doubt(&mut self, what: &'static str) {
        if !self.out.doubt.contains(&what) {
            self.out.doubt.push(what);
        }
    }

    /// An expansion starts in the current word.
    fn mark_expansion(&mut self) {
        let frame = self.top();
        let word = frame.word.get_or_insert_with(Word::default);
        word.lit.push(EXPANSION);
        word.expansion = true;
    }

    fn put(&mut self, byte: u8) {
        let word = self.top().word.get_or_insert_with(Word::default);
        // Bytes above ASCII are kept one char each: only ASCII is compared.
        word.lit.push(if byte.is_ascii() {
            byte as char
        } else {
            '\u{fffd}'
        });
    }

    fn end_word(&mut self) {
        let frame = self.top();
        let Some(mut word) = frame.word.take() else {
            return;
        };
        if word.brace_list {
            word.glob = true;
        }
        match frame.redirect {
            Redirect::None => {}
            Redirect::Read => {
                frame.redirect = Redirect::None;
                return;
            }
            Redirect::Write => {
                frame.redirect = Redirect::None;
                frame.command.writes.push(word);
                return;
            }
            Redirect::HereString => {
                frame.redirect = Redirect::None;
                frame.command.herestrings.push(word);
                return;
            }
        }
        if frame.kind == Kind::Param || frame.kind == Kind::Array {
            return;
        }
        let plain = !word.quoted && !word.dynamic();
        let leading = frame.lead;
        frame.lead = leading && plain && KEYWORDS.contains(&word.lit.as_str());
        match frame.cases.last().copied() {
            Some(Case::AwaitIn) => {
                if plain && word.lit == "in" && frame.command.words.len() >= 2 {
                    *frame.cases.last_mut().expect("checked") = Case::Pattern;
                    frame.command.words.clear();
                    frame.lead = true;
                    return;
                }
            }
            Some(Case::Pattern) => {
                if plain && word.lit == "esac" && frame.command.words.is_empty() {
                    frame.cases.pop();
                }
                // A pattern word: it is matched, not run.
                return;
            }
            Some(Case::Body) if plain && word.lit == "esac" && leading => {
                frame.cases.pop();
                frame.command.words.clear();
                frame.lead = true;
                return;
            }
            Some(Case::Body) | None => {}
        }
        if plain && word.lit == "case" && leading {
            if frame.kind == Kind::Dual {
                self.doubt("case-in-arithmetic");
            } else {
                frame.cases.push(Case::AwaitIn);
            }
            let frame = self.top();
            frame.command.words.push(word);
            return;
        }
        frame.command.words.push(word);
    }

    fn end_command(&mut self, pipe: bool) {
        self.end_word();
        let id = self.next_id;
        self.next_id += 1;
        let body_text = self.heredoc_body && self.frames.len() == 1;
        let frame = self.top();
        frame.redirect = Redirect::None;
        frame.lead = true;
        let mut command = std::mem::replace(
            &mut frame.command,
            Command {
                id,
                ..Command::default()
            },
        );
        command.pipe_next = pipe;
        command.arithmetic = frame.kind == Kind::Dual;
        let keep = frame.kind != Kind::Param && frame.kind != Kind::Array && !body_text;
        if keep
            && (!command.words.is_empty()
                || !command.writes.is_empty()
                || !command.heredocs.is_empty()
                || !command.herestrings.is_empty())
        {
            self.out.commands.push(command);
        } else if keep {
            // An empty command keeps its id: a here-document may name it.
            frame.command.id = command.id;
        }
    }

    fn pop(&mut self) {
        self.end_command(false);
        if !self.pending.is_empty() {
            self.doubt("heredoc-open-at-close");
        }
        if self.frames.len() > 1 {
            self.frames.pop();
        }
    }

    fn at_word_start(&mut self) -> bool {
        self.top().word.is_none()
    }

    fn run(&mut self, heredoc_body: bool) {
        let text = self.text;
        let n = text.len();
        let mut i = 0;
        while i < n {
            let c = text[i];
            let kind = self.top().kind;
            if c == 1 {
                // An expansion of the line this text was an argument of.
                self.mark_expansion();
                i += 1;
                continue;
            }
            if self.top().double_quoted {
                match c {
                    b'"' if !(heredoc_body && self.frames.len() == 1) => {
                        self.top().double_quoted = false;
                        i += 1;
                    }
                    b'\\' if i + 1 < n => {
                        let d = text[i + 1];
                        if d == b'\n' {
                        } else if matches!(d, b'$' | b'"' | b'\\' | b'`') {
                            if d == b'`' && self.frames.iter().any(|f| f.kind == Kind::Backtick) {
                                self.doubt("nested-backtick");
                            }
                            self.put(d);
                        } else {
                            self.put(b'\\');
                            self.put(d);
                        }
                        i += 2;
                    }
                    b'$' => i = self.dollar(i),
                    b'`' => {
                        if self.frames.iter().any(|f| f.kind == Kind::Backtick) {
                            self.doubt("nested-backtick");
                        }
                        self.mark_expansion();
                        self.push(Kind::Backtick);
                        i += 1;
                    }
                    _ => {
                        self.put(c);
                        i += 1;
                    }
                }
                continue;
            }
            if kind == Kind::Param {
                match c {
                    b'}' => {
                        self.pop();
                        i += 1;
                    }
                    b'\\' => i += 2,
                    b'\'' => {
                        i += 1;
                        while i < n && text[i] != b'\'' {
                            i += 1;
                        }
                        i += 1;
                    }
                    b'"' => {
                        self.top().double_quoted = true;
                        i += 1;
                    }
                    b'$' => i = self.dollar(i),
                    b'`' => {
                        if self.frames.iter().any(|f| f.kind == Kind::Backtick) {
                            self.doubt("nested-backtick");
                        }
                        self.mark_expansion();
                        self.push(Kind::Backtick);
                        i += 1;
                    }
                    _ => i += 1,
                }
                continue;
            }
            match c {
                b'\\' => {
                    if i + 1 >= n {
                        i += 1;
                    } else if text[i + 1] == b'\n' {
                        i += 2;
                    } else {
                        if kind == Kind::Backtick && text[i + 1] == b'`' {
                            self.doubt("nested-backtick");
                        }
                        self.put(text[i + 1]);
                        self.top().word.as_mut().expect("just put").quoted = true;
                        i += 2;
                    }
                }
                b'\'' => {
                    let start = i + 1;
                    let mut end = start;
                    while end < n && text[end] != b'\'' {
                        end += 1;
                    }
                    if text[start..end.min(n)].contains(&b'`')
                        && self.frames.iter().any(|f| f.kind == Kind::Backtick)
                    {
                        self.doubt("nested-backtick");
                    }
                    let word = self.top().word.get_or_insert_with(Word::default);
                    word.quoted = true;
                    word.lit
                        .push_str(&String::from_utf8_lossy(&text[start..end]));
                    i = end + 1;
                }
                b'"' => {
                    let frame = self.top();
                    frame.word.get_or_insert_with(Word::default).quoted = true;
                    frame.double_quoted = true;
                    i += 1;
                }
                b'$' => i = self.dollar(i),
                b'`' => {
                    if kind == Kind::Backtick {
                        self.pop();
                    } else {
                        if self.frames.iter().any(|f| f.kind == Kind::Backtick) {
                            // The shell closes the outer one here.
                            self.doubt("nested-backtick");
                        }
                        self.mark_expansion();
                        self.push(Kind::Backtick);
                    }
                    i += 1;
                }
                b' ' | b'\t' | b'\r' => {
                    self.end_word();
                    i += 1;
                }
                b'\n' => {
                    let in_pattern = self.top().cases.last() == Some(&Case::Pattern);
                    if kind == Kind::Array || in_pattern {
                        self.end_word();
                        if !self.pending.is_empty() {
                            self.doubt("heredoc-in-list");
                        }
                    } else {
                        self.end_command(false);
                    }
                    i += 1;
                    if !self.pending.is_empty() {
                        i = self.heredoc_bodies(i);
                    }
                }
                b'#' if self.at_word_start() => {
                    if kind == Kind::Dual {
                        self.doubt("comment-in-arithmetic");
                        self.put(c);
                        i += 1;
                    } else {
                        // Inside backticks the comment ends where they close.
                        let ticked = self.frames.iter().any(|f| f.kind == Kind::Backtick);
                        while i < n && text[i] != b'\n' && !(ticked && text[i] == b'`') {
                            i += if ticked && text[i] == b'\\' { 2 } else { 1 };
                        }
                        i = i.min(n);
                    }
                }
                b';' => {
                    let mut len = 1;
                    while i + len < n && matches!(text[i + len], b';' | b'&') && len < 3 {
                        len += 1;
                    }
                    self.end_command(false);
                    if len > 1 {
                        if let Some(state) = self.top().cases.last_mut() {
                            *state = Case::Pattern;
                        }
                        i += len;
                    } else {
                        i += 1;
                    }
                }
                b'&' => {
                    if text.get(i + 1) == Some(&b'&') {
                        self.end_command(false);
                        i += 2;
                    } else if text.get(i + 1) == Some(&b'>') {
                        // bash: a redirection of both streams. sh: `&`, then `>`.
                        self.end_word();
                        let frame = self.top();
                        frame.command.alt_start = Some(frame.command.words.len());
                        frame.redirect = Redirect::Write;
                        i += 2;
                        if text.get(i) == Some(&b'>') {
                            i += 1;
                        }
                    } else {
                        self.end_command(false);
                        i += 1;
                    }
                }
                b'|' => {
                    let in_pattern = self.top().cases.last() == Some(&Case::Pattern);
                    if in_pattern {
                        self.end_word();
                        i += 1;
                    } else if text.get(i + 1) == Some(&b'|') {
                        self.end_command(false);
                        i += 2;
                    } else {
                        self.end_command(true);
                        i += if text.get(i + 1) == Some(&b'&') { 2 } else { 1 };
                    }
                }
                b'(' => i = self.open_paren(i),
                b')' => i = self.close_paren(i),
                b'<' | b'>' => i = self.redirection(i),
                b'{' | b'}'
                    if self.at_word_start()
                        && text.get(i + 1).is_none_or(|b| {
                            matches!(b, b' ' | b'\t' | b'\n' | b';' | b')' | b'|' | b'&')
                        }) =>
                {
                    self.put(c);
                    self.end_word();
                    i += 1;
                }
                _ => {
                    if matches!(c, b'*' | b'?' | b'[') {
                        self.top().word.get_or_insert_with(Word::default).glob = true;
                    }
                    let fresh = self.at_word_start();
                    let word = self.top().word.get_or_insert_with(Word::default);
                    match c {
                        b'~' if fresh => {
                            word.glob = true;
                            word.tilde = true;
                        }
                        b'{' => word.brace_open = true,
                        b',' if word.brace_open => word.brace_list = true,
                        b'.' if word.brace_open && text.get(i + 1) == Some(&b'.') => {
                            word.brace_list = true
                        }
                        _ => {}
                    }
                    self.put(c);
                    i += 1;
                }
            }
        }
        while self.frames.len() > 1 {
            self.pop();
        }
        self.end_command(false);
    }

    /// At a `$`. Returns the index to read next.
    fn dollar(&mut self, i: usize) -> usize {
        let text = self.text;
        let n = text.len();
        let quoted = self.top().double_quoted;
        let Some(&d) = text.get(i + 1) else {
            self.put(b'$');
            return i + 1;
        };
        match d {
            b'\'' if !quoted => {
                let start = i + 2;
                let mut end = start;
                while end < n && text[end] != b'\'' {
                    end += if text[end] == b'\\' { 2 } else { 1 };
                }
                let body = &text[start.min(n)..end.min(n)];
                if body.windows(2).any(|w| w == b"\\'") {
                    // `sh` closes the string at that quote, bash does not.
                    self.doubt("ansi-c-quote");
                }
                let decoded = decode_ansi_c(body);
                let word = self.top().word.get_or_insert_with(Word::default);
                word.sh_alt = if word.ansi_c {
                    None
                } else {
                    Some(format!("{}${}", word.lit, String::from_utf8_lossy(body)))
                };
                word.ansi_c = true;
                word.quoted = true;
                word.lit.push_str(&String::from_utf8_lossy(&decoded));
                word.ansi_len = word.lit.len();
                end + 1
            }
            // `$"..."`: a translated string, read as a double-quoted one.
            b'"' if !quoted => i + 1,
            b'{' => {
                self.mark_expansion();
                self.push(Kind::Param);
                i + 2
            }
            b'(' => {
                self.mark_expansion();
                if text.get(i + 2) == Some(&b'(') {
                    self.push(Kind::Dual);
                    self.top().dollar = true;
                    i + 3
                } else {
                    self.push(Kind::Subst);
                    i + 2
                }
            }
            _ if d.is_ascii_alphabetic() || d == b'_' => {
                let mut end = i + 1;
                while end < n && (text[end].is_ascii_alphanumeric() || text[end] == b'_') {
                    end += 1;
                }
                self.mark_expansion();
                end
            }
            b'[' => {
                // `$[ ... ]`: the old arithmetic. Nothing in it is a command
                // unless it holds a substitution.
                let mut end = i + 2;
                let mut level = 1usize;
                while end < n {
                    match text[end] {
                        b'[' => level += 1,
                        b']' => {
                            level -= 1;
                            if level == 0 {
                                break;
                            }
                        }
                        b'`' => self.doubt("substitution-in-arithmetic"),
                        b'$' if text.get(end + 1) == Some(&b'(') => {
                            self.doubt("substitution-in-arithmetic")
                        }
                        _ => {}
                    }
                    end += 1;
                }
                self.mark_expansion();
                (end + 1).min(n)
            }
            b'@' | b'*' | b'#' | b'?' | b'-' | b'$' | b'!' | b'0'..=b'9' => {
                self.mark_expansion();
                i + 2
            }
            _ => {
                self.put(b'$');
                i + 1
            }
        }
    }

    /// At an unquoted `(`.
    fn open_paren(&mut self, i: usize) -> usize {
        let text = self.text;
        let kind = self.top().kind;
        if self.top().cases.last() == Some(&Case::Pattern) {
            // `(pattern)`: the optional opening parenthesis of a case pattern.
            return i + 1;
        }
        if kind == Kind::Array {
            self.push(Kind::Array);
            return i + 1;
        }
        let mut close = i + 1;
        while text.get(close).is_some_and(|b| *b == b' ' || *b == b'\t') {
            close += 1;
        }
        let empty = text.get(close) == Some(&b')');
        if let Some(word) = self.top().word.as_mut() {
            let last = word.lit.chars().last();
            if last == Some('=') {
                // `name=( ... )`: the words of an array.
                self.push(Kind::Array);
                return i + 1;
            }
            if matches!(last, Some('?' | '*' | '+' | '@' | '!')) && !empty {
                // An extended glob group.
                word.glob = true;
                word.extglob = true;
                self.push(Kind::Array);
                return i + 1;
            }
            if empty {
                // `name()`: a function is defined; its body is read as commands.
                if let Some(word) = self.top().word.take() {
                    self.out.functions.push(word.lit);
                }
                return close + 1;
            }
            self.end_word();
            self.push(Kind::Subshell);
            return i + 1;
        }
        if empty {
            // `name ()`: the same definition, or an empty group.
            let frame = self.top();
            if frame.command.words.len() == 1 {
                let name = frame.command.words.remove(0).lit;
                self.out.functions.push(name);
            }
            return close + 1;
        }
        if text.get(i + 1) == Some(&b'(') {
            self.push(Kind::Dual);
            return i + 2;
        }
        self.push(Kind::Subshell);
        i + 1
    }

    /// At an unquoted `)`.
    fn close_paren(&mut self, i: usize) -> usize {
        let text = self.text;
        self.end_word();
        match self.top().cases.last().copied() {
            Some(Case::Pattern) => {
                *self.top().cases.last_mut().expect("checked") = Case::Body;
                return i + 1;
            }
            // `case x in a) b) ...`: which construct this closes is not certain.
            Some(Case::Body) => self.doubt("paren-in-case-body"),
            _ => {}
        }
        match self.top().kind {
            Kind::Top | Kind::Backtick => {
                self.end_command(false);
                i + 1
            }
            Kind::Dual => {
                if text.get(i + 1) == Some(&b')') {
                    self.pop();
                    i + 2
                } else {
                    // Not arithmetic: two openers, closed apart.
                    self.doubt("dual-closed-apart");
                    self.end_command(false);
                    let frame = self.top();
                    frame.kind = if frame.dollar {
                        Kind::Subst
                    } else {
                        Kind::Subshell
                    };
                    i + 1
                }
            }
            _ => {
                self.pop();
                i + 1
            }
        }
    }

    /// At an unquoted `<` or `>`.
    fn redirection(&mut self, i: usize) -> usize {
        let text = self.text;
        let n = text.len();
        let c = text[i];
        let next = text.get(i + 1).copied();
        // A file descriptor before the operator is part of it.
        let is_fd = self.top().word.as_ref().is_some_and(|w| {
            !w.quoted
                && !w.lit.is_empty()
                && (w.lit.bytes().all(|b| b.is_ascii_digit())
                    || (w.lit.starts_with('{') && w.lit.ends_with('}')))
        });
        if is_fd {
            self.top().word = None;
        } else {
            self.end_word();
        }
        if next == Some(b'(') {
            // Process substitution: its inside runs.
            self.mark_expansion();
            self.push(Kind::Subst);
            return i + 2;
        }
        if c == b'<' && next == Some(b'<') {
            if text.get(i + 2) == Some(&b'<') {
                self.top().redirect = Redirect::HereString;
                return i + 3;
            }
            if self.frames.iter().any(|f| f.kind == Kind::Dual) {
                // A shift in arithmetic, a here-document in a command.
                self.doubt("heredoc-in-arithmetic");
                return i + 2;
            }
            let mut j = i + 2;
            let strip_tabs = text.get(j) == Some(&b'-');
            if strip_tabs {
                j += 1;
            }
            while j < n && matches!(text[j], b' ' | b'\t') {
                j += 1;
            }
            let mut delimiter = Vec::new();
            let mut quoted = false;
            while j < n {
                match text[j] {
                    b' ' | b'\t' | b'\n' | b';' | b'|' | b'&' | b'(' | b')' | b'<' | b'>' => break,
                    b'\\' => {
                        quoted = true;
                        if j + 1 < n {
                            delimiter.push(text[j + 1]);
                        }
                        j += 2;
                    }
                    q @ (b'\'' | b'"') => {
                        quoted = true;
                        j += 1;
                        while j < n && text[j] != q {
                            delimiter.push(text[j]);
                            j += 1;
                        }
                        j += 1;
                    }
                    b'$' | b'`' => {
                        // The shell takes it literally; few readers agree how.
                        self.doubt("heredoc-delimiter");
                        delimiter.push(text[j]);
                        j += 1;
                    }
                    other => {
                        delimiter.push(other);
                        j += 1;
                    }
                }
            }
            if delimiter.is_empty() && !quoted {
                self.doubt("heredoc-delimiter");
            }
            let owner = self.top().command.id;
            self.pending.push(Pending {
                delimiter,
                strip_tabs,
                quoted,
                owner,
            });
            return j.min(n);
        }
        let mut j = i + 1;
        let mut write = c == b'>';
        match next {
            // `<>`: opened for reading and writing.
            Some(b'>') if c == b'<' => {
                write = true;
                j += 1;
            }
            Some(b'>') | Some(b'|') if c == b'>' => j += 1,
            Some(b'&') => {
                j += 1;
                let mut k = j;
                while k < n && matches!(text[k], b' ' | b'\t') {
                    k += 1;
                }
                // `>&2`, `<&-`: a descriptor, not a file.
                if text
                    .get(k)
                    .is_some_and(|b| b.is_ascii_digit() || *b == b'-')
                {
                    write = false;
                }
            }
            _ => {}
        }
        self.top().redirect = if write {
            Redirect::Write
        } else {
            Redirect::Read
        };
        j
    }

    /// After a newline with here-documents pending: reads their bodies.
    fn heredoc_bodies(&mut self, mut i: usize) -> usize {
        let text = self.text;
        let n = text.len();
        for pending in std::mem::take(&mut self.pending) {
            let start = i;
            let mut end = n;
            let mut after = n;
            while i <= n {
                let line_end = text[i.min(n)..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(n, |p| i + p);
                let mut line = &text[i.min(n)..line_end];
                if pending.strip_tabs {
                    while line.first() == Some(&b'\t') {
                        line = &line[1..];
                    }
                }
                if line == pending.delimiter.as_slice() {
                    end = i.min(n);
                    after = (line_end + 1).min(n);
                    break;
                }
                if line_end >= n {
                    break;
                }
                i = line_end + 1;
            }
            let body = String::from_utf8_lossy(&text[start.min(n)..end]).into_owned();
            let heredoc = Heredoc {
                body,
                quoted: pending.quoted,
            };
            let owner = pending.owner;
            if let Some(command) = self.out.commands.iter_mut().rev().find(|c| c.id == owner) {
                command.heredocs.push(heredoc);
            } else if let Some(frame) = self.frames.iter_mut().rev().find(|f| f.command.id == owner)
            {
                frame.command.heredocs.push(heredoc);
            } else {
                let id = self.next_id;
                self.next_id += 1;
                self.out.commands.push(Command {
                    id,
                    heredocs: vec![heredoc],
                    ..Command::default()
                });
            }
            i = after;
        }
        i
    }
}
