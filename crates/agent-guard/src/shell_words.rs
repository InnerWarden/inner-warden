//! The words of a shell command line as the shell hands them to the programs
//! it runs. Read, never run: no variable is looked up, no substitution is
//! carried out, no file is matched. What the shell would still change is
//! marked on each character instead, so a check can tell a word the text
//! shows from one it does not.
//!
//! Small on purpose. It reads what decides which program runs with which
//! words: quotes, escapes and line continuations; the operators that end a
//! command (`;`, `&`, `|`, a newline, parentheses, a brace group's `{` and
//! `}`); redirections, whose targets are not words of the command;
//! here-documents and here-strings, the text a command reads on its input;
//! substitutions, each a command line of its own; and array assignments.
//! A carriage return is a character of a word, as it is to the shell.

/// How the shell treats one character of a word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mark {
    /// Handed to the program as written: plain, quoted or escaped.
    Plain,
    /// An unquoted pattern character the shell may still act on: a glob's
    /// `*`, `?` and `[`, and a brace expansion's `{`, `}`, `,` and `..`.
    Pattern,
    /// Text the shell replaces when it runs the line: a parameter, a command
    /// or process substitution, arithmetic, or a quote that never closes.
    Expansion,
}

/// One word of a simple command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Word {
    /// The characters with quotes and escapes taken out; an expansion's text
    /// is kept as written.
    pub(crate) text: String,
    /// How the shell treats each character of `text`, in order.
    pub(crate) marks: Vec<Mark>,
    /// Some of it was quoted or escaped.
    pub(crate) quoted: bool,
    /// What the substitutions in it put in its place: the command line of a
    /// command substitution, the default of a `${name:-default}`.
    pub(crate) substitutions: Vec<String>,
}

impl Word {
    fn push(&mut self, c: char, mark: Mark) {
        self.text.push(c);
        self.marks.push(mark);
    }

    fn push_str(&mut self, s: &str, mark: Mark) {
        for c in s.chars() {
            self.push(c, mark);
        }
    }

    /// Every character is handed to the program as written.
    pub(crate) fn is_plain(&self) -> bool {
        self.marks.iter().all(|mark| *mark == Mark::Plain)
    }

    /// Some character is marked `mark`.
    pub(crate) fn has(&self, mark: Mark) -> bool {
        self.marks.contains(&mark)
    }

    /// The part after the last `/` the program receives as written (a
    /// program's name without its folder), with its marks.
    pub(crate) fn last_component(&self) -> (Vec<char>, Vec<Mark>) {
        let chars: Vec<char> = self.text.chars().collect();
        let start = chars
            .iter()
            .zip(&self.marks)
            .rposition(|(c, mark)| *c == '/' && *mark == Mark::Plain)
            .map_or(0, |at| at + 1);
        (chars[start..].to_vec(), self.marks[start..].to_vec())
    }
}

/// One simple command: its words, and what it does with its input and output.
#[derive(Debug, Clone, Default)]
pub(crate) struct Command {
    pub(crate) words: Vec<Word>,
    /// What it prints goes into the next command through a pipe.
    pub(crate) piped: bool,
    /// It sends what it prints to a file (`/dev/null` is none).
    pub(crate) writes_file: bool,
    /// Text it reads on its input from the line itself: a here-document's
    /// body, a here-string's word.
    pub(crate) inputs: Vec<String>,
    redirected: bool,
}

/// A command line, read.
#[derive(Debug, Clone, Default)]
pub(crate) struct Line {
    /// Its simple commands, in order.
    pub(crate) commands: Vec<Command>,
    /// The command lines the shell runs from inside this one: every command
    /// substitution, wherever it is (a word, a redirection's target, a
    /// here-document that expands), and the inside of every `${...}`.
    pub(crate) nested: Vec<String>,
    /// The lists assigned to an array (`a=(...)`), as written: words a
    /// later command may run.
    pub(crate) arrays: Vec<String>,
}

/// Read `text` as the shell reads a command line.
pub(crate) fn read_line(text: &str) -> Line {
    let mut lexer = Lexer {
        chars: text.chars().collect(),
        at: 0,
        line: Line::default(),
        command: Command::default(),
        word: None,
        braces: 0,
        heredocs: Vec::new(),
    };
    lexer.run();
    lexer.line
}

/// The command substitutions in text the shell expands but does not split
/// into commands: the body of a here-document whose delimiter is not quoted.
pub(crate) fn substitutions_in(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut found = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        match chars[at] {
            '\\' => at += 2,
            '$' if matches!(chars.get(at + 1), Some('(' | '{')) => {
                let (open, close) = if chars[at + 1] == '(' {
                    ('(', ')')
                } else {
                    ('{', '}')
                };
                let end = matching_close(&chars, at + 1, open, close);
                found.push(chars[at + 2..end.unwrap_or(chars.len())].iter().collect());
                at = end.map_or(chars.len(), |end| end + 1);
            }
            '`' => {
                let (inner, end) = backtick_body(&chars, at);
                found.push(inner);
                at = end;
            }
            _ => at += 1,
        }
    }
    found
}

struct Heredoc {
    /// The index the command that reads it has (or will have) in the line.
    command: usize,
    delimiter: String,
    strip_tabs: bool,
    expands: bool,
}

struct Lexer {
    chars: Vec<char>,
    at: usize,
    line: Line,
    command: Command,
    word: Option<Word>,
    /// Unquoted `{` not yet closed in the word being read.
    braces: usize,
    /// Here-documents whose body starts at the next newline.
    heredocs: Vec<Heredoc>,
}

impl Lexer {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    fn word(&mut self) -> &mut Word {
        self.word.get_or_insert_with(Word::default)
    }

    fn end_word(&mut self) {
        if let Some(word) = self.word.take() {
            self.command.words.push(word);
        }
        self.braces = 0;
    }

    fn end_command(&mut self, piped: bool) {
        self.end_word();
        let mut command = std::mem::take(&mut self.command);
        if !command.words.is_empty() || command.redirected || !command.inputs.is_empty() {
            command.piped = piped;
            self.line.commands.push(command);
        }
    }

    fn run(&mut self) {
        while let Some(c) = self.peek(0) {
            match c {
                ' ' | '\t' => {
                    self.end_word();
                    self.at += 1;
                }
                '\n' => {
                    self.end_command(false);
                    self.at += 1;
                    self.read_heredocs();
                }
                ';' => {
                    self.end_command(false);
                    self.at += 1;
                }
                '&' if self.peek(1) == Some('>') => {
                    self.end_word();
                    self.redirection();
                }
                '&' => {
                    self.end_command(false);
                    self.at += if self.peek(1) == Some('&') { 2 } else { 1 };
                }
                '|' => {
                    if self.peek(1) == Some('|') {
                        self.end_command(false);
                        self.at += 2;
                    } else {
                        self.end_command(true);
                        self.at += if self.peek(1) == Some('&') { 2 } else { 1 };
                    }
                }
                '(' if self.word.as_ref().is_some_and(is_array_name) => self.array(),
                '(' | ')' => {
                    self.end_command(false);
                    self.at += 1;
                }
                '<' | '>' if self.peek(1) == Some('(') => self.process_substitution(),
                '<' | '>' => {
                    self.drop_descriptor();
                    self.redirection();
                }
                '{' | '}' if self.word.is_none() && self.reserved_brace(c) => {
                    self.end_command(false);
                    self.at += 1;
                }
                _ => self.word_unit(),
            }
        }
        self.end_command(false);
    }

    /// A `{` or `}` standing alone where a word starts: a brace group's.
    fn reserved_brace(&self, c: char) -> bool {
        match self.peek(1) {
            None => true,
            Some(next) if next.is_whitespace() => true,
            Some(';' | '&' | '|' | ')') => c == '}',
            _ => false,
        }
    }

    /// One piece of a word: an escape, a quote, an expansion, or a character.
    fn word_unit(&mut self) {
        let Some(c) = self.peek(0) else { return };
        match c {
            '\\' => match self.peek(1) {
                // A line continuation: the shell joins the two lines.
                Some('\n') => self.at += 2,
                Some('\r') if self.peek(2) == Some('\n') => self.at += 3,
                Some(next) => {
                    let word = self.word();
                    word.push(next, Mark::Plain);
                    word.quoted = true;
                    self.at += 2;
                }
                None => {
                    self.word().push('\\', Mark::Plain);
                    self.at += 1;
                }
            },
            '\'' => self.single_quoted(),
            '"' => {
                self.at += 1;
                self.word().quoted = true;
                self.double_quoted();
            }
            '$' => self.dollar(false),
            '`' => self.backtick(),
            '*' | '?' | '[' => {
                self.word().push(c, Mark::Pattern);
                self.at += 1;
            }
            '{' => {
                self.braces += 1;
                self.word().push(c, Mark::Pattern);
                self.at += 1;
            }
            '}' if self.braces > 0 => {
                self.braces -= 1;
                self.word().push(c, Mark::Pattern);
                self.at += 1;
            }
            ',' if self.braces > 0 => {
                self.word().push(c, Mark::Pattern);
                self.at += 1;
            }
            '.' if self.braces > 0 && self.peek(1) == Some('.') => {
                let word = self.word();
                word.push('.', Mark::Pattern);
                word.push('.', Mark::Pattern);
                self.at += 2;
            }
            _ => {
                self.word().push(c, Mark::Plain);
                self.at += 1;
            }
        }
    }

    fn single_quoted(&mut self) {
        self.at += 1;
        let word = self.word.get_or_insert_with(Word::default);
        word.quoted = true;
        let start = word.marks.len();
        while let Some(&c) = self.chars.get(self.at) {
            self.at += 1;
            if c == '\'' {
                return;
            }
            word.push(c, Mark::Plain);
        }
        never_closed(word, start, '\'');
    }

    /// The inside of a double quote, its opening quote already read.
    fn double_quoted(&mut self) {
        let start = self.word().marks.len();
        loop {
            let Some(c) = self.peek(0) else {
                let word = self.word();
                never_closed(word, start, '"');
                return;
            };
            match c {
                '"' => {
                    self.at += 1;
                    return;
                }
                '\\' => match self.peek(1) {
                    Some('\n') => self.at += 2,
                    Some(next @ ('$' | '`' | '"' | '\\')) => {
                        self.word().push(next, Mark::Plain);
                        self.at += 2;
                    }
                    _ => {
                        self.word().push('\\', Mark::Plain);
                        self.at += 1;
                    }
                },
                '$' => self.dollar(true),
                '`' => self.backtick(),
                _ => {
                    self.word().push(c, Mark::Plain);
                    self.at += 1;
                }
            }
        }
    }

    fn dollar(&mut self, in_double: bool) {
        match self.peek(1) {
            Some('\'') if !in_double => self.ansi_c_quoted(),
            Some('"') if !in_double => {
                self.at += 2;
                self.word().quoted = true;
                self.double_quoted();
            }
            Some('(') => {
                let open = self.at + 1;
                let close = matching_close(&self.chars, open, '(', ')');
                let inner: String = self.chars[open + 1..close.unwrap_or(self.chars.len())]
                    .iter()
                    .collect();
                self.expansion_to(close.map_or(self.chars.len(), |close| close + 1));
                self.line.nested.push(inner.clone());
                self.word().substitutions.push(inner);
            }
            Some('{') => {
                let open = self.at + 1;
                let close = matching_close(&self.chars, open, '{', '}');
                let inner: String = self.chars[open + 1..close.unwrap_or(self.chars.len())]
                    .iter()
                    .collect();
                self.expansion_to(close.map_or(self.chars.len(), |close| close + 1));
                if let Some(default) = parameter_default(&inner) {
                    self.word().substitutions.push(default.to_string());
                }
                self.line.nested.push(inner);
            }
            Some(next) if next == '_' || next.is_ascii_alphabetic() => {
                let mut end = self.at + 1;
                while self
                    .chars
                    .get(end)
                    .is_some_and(|c| *c == '_' || c.is_ascii_alphanumeric())
                {
                    end += 1;
                }
                self.expansion_to(end);
            }
            Some(next) if next.is_ascii_digit() || "@*#?$!-".contains(next) => {
                self.expansion_to(self.at + 2);
            }
            _ => {
                self.word().push('$', Mark::Plain);
                self.at += 1;
            }
        }
    }

    /// The text from here to `end`, as an expansion of the word.
    fn expansion_to(&mut self, end: usize) {
        let raw: String = self.chars[self.at..end].iter().collect();
        self.at = end;
        self.word().push_str(&raw, Mark::Expansion);
    }

    /// `$'...'`: the shell decodes its escapes, and the program gets the
    /// result as written.
    fn ansi_c_quoted(&mut self) {
        self.at += 2;
        let word = self.word.get_or_insert_with(Word::default);
        word.quoted = true;
        let start = word.marks.len();
        while let Some(&c) = self.chars.get(self.at) {
            self.at += 1;
            match c {
                '\'' => return,
                '\\' => {
                    let (decoded, used) = ansi_c_escape(&self.chars[self.at..]);
                    self.at += used;
                    if let Some(decoded) = decoded {
                        word.push(decoded, Mark::Plain);
                    }
                }
                _ => word.push(c, Mark::Plain),
            }
        }
        never_closed(word, start, '\'');
    }

    fn backtick(&mut self) {
        let (inner, end) = backtick_body(&self.chars, self.at);
        self.expansion_to(end);
        self.line.nested.push(inner.clone());
        self.word().substitutions.push(inner);
    }

    /// `<(...)` or `>(...)`: a command line run beside this one, whose
    /// output or input the word names.
    fn process_substitution(&mut self) {
        let open = self.at + 1;
        let close = matching_close(&self.chars, open, '(', ')');
        let inner: String = self.chars[open + 1..close.unwrap_or(self.chars.len())]
            .iter()
            .collect();
        self.expansion_to(close.map_or(self.chars.len(), |close| close + 1));
        self.line.nested.push(inner.clone());
        self.word().substitutions.push(inner);
    }

    /// `name=(...)`: the list an array is given.
    fn array(&mut self) {
        let close = matching_close(&self.chars, self.at, '(', ')');
        let inner: String = self.chars[self.at + 1..close.unwrap_or(self.chars.len())]
            .iter()
            .collect();
        self.expansion_to(close.map_or(self.chars.len(), |close| close + 1));
        self.line.arrays.push(inner);
    }

    /// The digits right before a redirection name a descriptor, not a word.
    fn drop_descriptor(&mut self) {
        let descriptor = self.word.as_ref().is_some_and(|word| {
            !word.text.is_empty()
                && word.is_plain()
                && word.text.chars().all(|c| c.is_ascii_digit())
        });
        if descriptor {
            self.word = None;
            self.braces = 0;
        } else {
            self.end_word();
        }
    }

    fn redirection(&mut self) {
        const OPERATORS: &[&str] = &[
            "<<<", "<<-", "&>>", "<<", "<>", "<&", ">>", ">|", ">&", "&>", "<", ">",
        ];
        let ahead: String = self.chars[self.at..(self.at + 3).min(self.chars.len())]
            .iter()
            .collect();
        let operator = OPERATORS
            .iter()
            .copied()
            .find(|op| ahead.starts_with(op))
            .unwrap_or(">");
        self.at += operator.len();
        self.command.redirected = true;
        while matches!(self.peek(0), Some(' ' | '\t')) {
            self.at += 1;
        }
        let target = self.target_word();
        let to_a_file = target.text != "/dev/null";
        match operator {
            "<<" | "<<-" => self.heredocs.push(Heredoc {
                command: self.line.commands.len(),
                delimiter: target.text,
                strip_tabs: operator == "<<-",
                expands: !target.quoted,
            }),
            "<<<" => self.command.inputs.push(target.text),
            ">" | ">>" | ">|" | "&>" | "&>>" | "<>" => self.command.writes_file |= to_a_file,
            ">&" => {
                let descriptor =
                    target.text == "-" || target.text.chars().all(|c| c.is_ascii_digit());
                self.command.writes_file |= to_a_file && !descriptor;
            }
            _ => {}
        }
    }

    /// The word a redirection names: read like any word, never one of the
    /// command's.
    fn target_word(&mut self) -> Word {
        let saved = self.word.take();
        let braces = std::mem::take(&mut self.braces);
        loop {
            match self.peek(0) {
                None | Some(' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')') => break,
                Some('<' | '>') if self.peek(1) == Some('(') => self.process_substitution(),
                Some('<' | '>') => break,
                Some(_) => self.word_unit(),
            }
        }
        let target = self.word.take().unwrap_or_default();
        self.word = saved;
        self.braces = braces;
        target
    }

    /// The bodies of the here-documents of the line just ended.
    fn read_heredocs(&mut self) {
        for heredoc in std::mem::take(&mut self.heredocs) {
            let mut body = String::new();
            while self.at < self.chars.len() {
                let end = self.chars[self.at..]
                    .iter()
                    .position(|c| *c == '\n')
                    .map_or(self.chars.len(), |found| self.at + found);
                let line: String = self.chars[self.at..end].iter().collect();
                self.at = (end + 1).min(self.chars.len());
                let compared = if heredoc.strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line.as_str()
                };
                if compared == heredoc.delimiter {
                    break;
                }
                body.push_str(&line);
                body.push('\n');
            }
            if heredoc.expands {
                self.line.nested.extend(substitutions_in(&body));
            }
            match self.line.commands.get_mut(heredoc.command) {
                Some(command) => command.inputs.push(body),
                None => self.command.inputs.push(body),
            }
        }
    }
}

/// A quote that never closes: the shell refuses the line or waits for
/// more, so nothing read since `start` is taken as written.
fn never_closed(word: &mut Word, start: usize, quote: char) {
    for mark in &mut word.marks[start..] {
        *mark = Mark::Expansion;
    }
    word.push(quote, Mark::Expansion);
}

/// `name=` or `name+=` as written: what an array assignment starts with.
fn is_array_name(word: &Word) -> bool {
    word.is_plain()
        && word
            .text
            .strip_suffix('=')
            .map(|name| name.strip_suffix('+').unwrap_or(name))
            .is_some_and(|name| {
                let mut chars = name.chars();
                chars
                    .next()
                    .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
                    && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
            })
}

/// The default a `${name:-default}` (or `-`, `:=`, `=`, `:+`, `+`) puts in
/// its place, as written.
fn parameter_default(inner: &str) -> Option<&str> {
    let name_end = inner
        .find(|c: char| !(c == '_' || c.is_ascii_alphanumeric()))
        .unwrap_or(inner.len());
    let rest = &inner[name_end..];
    let rest = rest.strip_prefix(':').unwrap_or(rest);
    rest.strip_prefix(['-', '=', '+'])
}

/// The command line of the backtick substitution that starts at `start`,
/// unescaped, and the index just past its closing backtick.
fn backtick_body(chars: &[char], start: usize) -> (String, usize) {
    let mut inner = String::new();
    let mut at = start + 1;
    while let Some(&c) = chars.get(at) {
        match c {
            '\\' => {
                match chars.get(at + 1) {
                    Some(&next @ ('`' | '\\' | '$')) => inner.push(next),
                    Some(&next) => {
                        inner.push('\\');
                        inner.push(next);
                    }
                    None => inner.push('\\'),
                }
                at += 2;
            }
            '`' => return (inner, at + 1),
            _ => {
                inner.push(c);
                at += 1;
            }
        }
    }
    (inner, chars.len())
}

/// The index of the `close` that ends the `open` at `start`, skipping
/// quoted text, escapes and backticks; `None` when it never closes.
fn matching_close(chars: &[char], start: usize, open: char, close: char) -> Option<usize> {
    let mut depth = 0usize;
    let mut at = start;
    while at < chars.len() {
        match chars[at] {
            '\\' => {
                at += 2;
                continue;
            }
            quote @ ('\'' | '"' | '`') => {
                at += 1;
                while at < chars.len() && chars[at] != quote {
                    if chars[at] == '\\' && quote != '\'' {
                        at += 1;
                    }
                    at += 1;
                }
            }
            c if c == open => depth += 1,
            c if c == close => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
        at += 1;
    }
    None
}

/// One escape of a `$'...'` string, `chars` starting after its backslash:
/// the character it stands for (none for `\c` at the end) and how many
/// characters it used.
fn ansi_c_escape(chars: &[char]) -> (Option<char>, usize) {
    let Some(&first) = chars.first() else {
        return (Some('\\'), 0);
    };
    let digits = |radix: u32, max: usize, skip: usize| {
        let taken: String = chars[skip..]
            .iter()
            .take(max)
            .take_while(|c| c.is_digit(radix))
            .collect();
        let value = u32::from_str_radix(&taken, radix)
            .ok()
            .and_then(char::from_u32);
        (value, skip + taken.chars().count())
    };
    match first {
        'a' => (Some('\u{7}'), 1),
        'b' => (Some('\u{8}'), 1),
        'e' | 'E' => (Some('\u{1b}'), 1),
        'f' => (Some('\u{c}'), 1),
        'n' => (Some('\n'), 1),
        'r' => (Some('\r'), 1),
        't' => (Some('\t'), 1),
        'v' => (Some('\u{b}'), 1),
        '0'..='7' => digits(8, 3, 0),
        'x' => match digits(16, 2, 1) {
            (Some(c), used) => (Some(c), used),
            (None, _) => (Some('x'), 1),
        },
        'u' => digits(16, 4, 1),
        'U' => digits(16, 8, 1),
        'c' => match chars.get(1) {
            Some(c) => (char::from_u32(u32::from(*c) & 0x1f), 2),
            None => (None, 1),
        },
        other => (Some(other), 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &Line) -> Vec<Vec<String>> {
        line.commands
            .iter()
            .map(|command| command.words.iter().map(|w| w.text.clone()).collect())
            .collect()
    }

    /// Quotes and escapes are taken out, a line continuation joins two
    /// lines (inside a word too), and a carriage return is a character of a
    /// word, as it is to the shell.
    #[test]
    fn words_are_what_the_program_gets() {
        let line = read_line("sudo inner''warden-ctl 'agent' \"ker\"nel a\\ b ker\\\nnel x\\\r\ny");
        assert_eq!(
            words(&line),
            [[
                "sudo",
                "innerwarden-ctl",
                "agent",
                "kernel",
                "a b",
                "kernel",
                "xy"
            ]]
        );
        assert!(line.commands[0].words.iter().all(Word::is_plain));
        let line = read_line("innerwarden-ctl \\\n  agent kernel off");
        assert_eq!(
            words(&line),
            [["innerwarden-ctl", "agent", "kernel", "off"]]
        );
        let line = read_line("a 2>err.txt\r b");
        assert_eq!(words(&line), [["a", "b"]]);
        let line = read_line("a status\r");
        assert_eq!(words(&line), [["a", "status\r"]]);
    }

    /// The operators end a command; a pipe says so; a redirection's target
    /// is not a word, whatever its operator (`>|` and `&>` included), and
    /// only a file counts as a write.
    #[test]
    fn commands_end_where_the_shell_ends_them() {
        let line = read_line("a; b && c || d | e |& f & g\nh (i) { j; }");
        assert_eq!(
            words(&line),
            [
                vec!["a"],
                vec!["b"],
                vec!["c"],
                vec!["d"],
                vec!["e"],
                vec!["f"],
                vec!["g"],
                vec!["h"],
                vec!["i"],
                vec!["j"]
            ]
        );
        let piped: Vec<bool> = line.commands.iter().map(|c| c.piped).collect();
        assert_eq!(
            piped,
            [false, false, false, true, true, false, false, false, false, false]
        );
        for (text, writes) in [
            ("a >|out.txt b", true),
            ("a >| out.txt b", true),
            ("a 2>&1 b", false),
            ("a &>/dev/null b", false),
            ("a &>log b", true),
            ("a >/dev/null b", false),
            ("a >>log b", true),
            ("a < in b", false),
        ] {
            let line = read_line(text);
            assert_eq!(words(&line), [["a", "b"]], "{text}");
            assert_eq!(line.commands[0].writes_file, writes, "{text}");
        }
    }

    /// What the shell would still change is marked: expansions, globs and
    /// brace expansions; `{}` and a quoted `*` are not expansions.
    #[test]
    fn what_the_shell_changes_is_marked() {
        let line = read_line(
            "a $X ${Y} \"$Z\" `w` $(v) k{e..e}rnel inner*-ctl '*' x,y {a,b} $'\\x61gent'",
        );
        let w = &line.commands[0].words;
        assert!(w[0].is_plain());
        for word in &w[1..=5] {
            assert!(word.has(Mark::Expansion), "{}", word.text);
        }
        assert!(w[6].has(Mark::Pattern) && !w[6].has(Mark::Expansion));
        assert!(w[7].has(Mark::Pattern));
        assert!(w[8].is_plain() && w[8].text == "*");
        assert!(w[9].is_plain());
        assert!(w[10].has(Mark::Pattern));
        assert!(w[11].is_plain() && w[11].text == "agent");
        assert_eq!(line.nested, ["Y", "w", "v"]);
        // A quote that never closes is not taken as written.
        assert!(!read_line("a 'agent").commands[0].words[1].is_plain());
    }

    /// Substitutions are command lines of their own, found wherever they
    /// are; here-documents are the input of the command that names them,
    /// and their substitutions run only where the delimiter is not quoted.
    #[test]
    fn nested_lines_and_inputs_are_found() {
        let line = read_line("x > \"$(a b)\" <<< 'c d'");
        assert_eq!(line.nested, ["a b"]);
        assert_eq!(line.commands[0].inputs, ["c d"]);
        let line = read_line("cat <<EOF | sh\nrun $(e f)\nEOF\nnext");
        assert_eq!(words(&line), [vec!["cat"], vec!["sh"], vec!["next"]]);
        assert_eq!(line.commands[0].inputs, ["run $(e f)\n"]);
        assert_eq!(line.nested, ["e f"]);
        let line = read_line("cat <<'EOF'\nrun $(e f)\nEOF\n");
        assert!(line.nested.is_empty());
        let line = read_line("a=(x y) b \"${c:-d e}\"");
        assert_eq!(line.arrays, ["x y"]);
        assert_eq!(line.commands[0].words[2].substitutions, ["d e"]);
        assert_eq!(read_line("diff <(a) b").nested, ["a"]);
    }
}
