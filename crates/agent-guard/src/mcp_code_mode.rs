//! Code mode: an MCP server that exposes one tool that runs a script against
//! its API (Cloudflare's `search` and `execute`, a `run_code` or an `eval`). The
//! call carries a TypeScript or JavaScript script and the server runs it in
//! its sandbox, so what the call does is the API calls inside the script.
//! Before, the guard saw one `execute(script)` and read none of them.
//!
//! The script is read as code ([`read_script`]):
//!
//! * a call to a destructive method or one that makes or changes a
//!   credential (`zones.delete`, `cache.purge`, `tokens.create`,
//!   `workers.scripts.update`, an HTTP `DELETE` or `PUT`, a `DROP TABLE`) is a
//!   review: the call runs with a warning under the default posture and is
//!   refused under the strict one;
//! * a read (`list`, `get`, an HTTP `GET`) is allowed;
//! * what cannot be read (an `eval` of a string, a dynamic `import`, a method
//!   named at run time) is a review.
//!
//! What decides is the tables below (the names of the tools that run code,
//! the argument that holds it, the verbs of a method), never the server's
//! name. The same reading is used by the hook ([`hook_verdict`]) and the MCP
//! proxy ([`code_mode_alert`]).

use serde_json::Value;

/// The rule a finding of this reader is reported under in the proxy.
pub const CODE_MODE_RULE: &str = "AG-CODE-MODE";

/// The signal a call that changes what the API serves is reported under in
/// the hook: the same name the shell analyzer gives a cloud CLI that does.
const CHANGE_SIGNAL: &str = "cloud_control_plane";

/// The signal a script that cannot be read is reported under in the hook.
const UNREAD_SIGNAL: &str = "shell_line_not_literal";

/// The score of a finding: a review ([`crate::mcp::recommendation_for_score`]).
const REVIEW_SCORE: u32 = 30;

/// The most of a script that is read. Past it the script is not read.
const MAX_SCRIPT_BYTES: usize = 256 * 1024;

/// Tool names (the last part of a namespaced name, lower case, any other
/// character read as `_`) that run the script they are handed.
const CODE_TOOLS: &[&str] = &[
    "execute",
    "execute_script",
    "execute_js",
    "execute_javascript",
    "execute_typescript",
    "run_code",
    "run_script",
    "run_js",
    "run_javascript",
    "run_typescript",
    "eval",
    "evaluate",
    "eval_code",
    "eval_js",
    "code_mode",
    "codemode",
];

/// Tool names that run code in more than one language and say which in no
/// argument of their own: read here only when an argument says JavaScript
/// or TypeScript. Hermes Agent's `execute_code` runs Python; its hook judges
/// that as a `python3 -c` line (`crate::hermes_hook::shell_line_of`).
const LANGUAGE_NAMED_TOOLS: &[&str] = &["execute_code"];

/// Argument names that hold the script.
const CODE_KEYS: &[&str] = &[
    "code",
    "script",
    "source",
    "source_code",
    "program",
    "snippet",
    "js",
    "javascript",
    "typescript",
    "ts",
];

/// Argument names that say the language of the script. A language other
/// than JavaScript or TypeScript is not read here.
const LANGUAGE_KEYS: &[&str] = &["language", "lang", "runtime"];

/// Languages read as JavaScript.
const SCRIPT_LANGUAGES: &[&str] = &[
    "js",
    "javascript",
    "ts",
    "typescript",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ecmascript",
];

/// Words of a method name that destroy or take away.
const DESTRUCTIVE_VERBS: &[&str] = &[
    "delete",
    "del",
    "remove",
    "destroy",
    "purge",
    "drop",
    "truncate",
    "wipe",
    "erase",
    "revoke",
    "terminate",
    "reset",
    "flushall",
    "flushdb",
    "nuke",
];

/// Words of a method name that create, change or publish. `set`, `add`,
/// `replace`, `apply`, `push` and `send` are left out: plain JavaScript calls
/// them on its own values (`Map.set`, `Set.add`, `String.replace`,
/// `Function.apply`).
const CHANGE_VERBS: &[&str] = &[
    "create",
    "update",
    "edit",
    "put",
    "patch",
    "post",
    "upsert",
    "insert",
    "deploy",
    "publish",
    "upload",
    "rollback",
    "rename",
    "transfer",
    "enable",
    "disable",
    "attach",
    "detach",
    "invite",
    "grant",
    "roll",
    "rotate",
    "regenerate",
    "restore",
    "overwrite",
    "move",
    "migrate",
    "promote",
    "modify",
    "change",
];

/// Words of a resource that is a credential: a change to one makes, moves
/// or takes away a way in.
const CREDENTIAL_WORDS: &[&str] = &[
    "token",
    "tokens",
    "apitoken",
    "apitokens",
    "key",
    "keys",
    "apikey",
    "apikeys",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "password",
    "passwords",
];

/// Path segments of a credential in an HTTP path.
const CREDENTIAL_PATHS: &[&str] = &[
    "/tokens",
    "/api_tokens",
    "/api-tokens",
    "/keys",
    "/api_keys",
    "/api-keys",
    "/apikeys",
    "/access_keys",
    "/secrets",
    "/credentials",
];

/// SQL statements that change or destroy, at the start of a string (lower
/// case), and whether they destroy.
const SQL_STATEMENTS: &[(&str, bool)] = &[
    ("drop table", true),
    ("drop database", true),
    ("drop schema", true),
    ("drop index", true),
    ("drop view", true),
    ("truncate ", true),
    ("delete from", true),
    ("insert into", false),
    ("alter table", false),
    ("grant ", false),
    ("revoke ", true),
];

/// What one call in a script does, as this reader judges it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeKind {
    /// Deletes, purges or takes away.
    Destructive,
    /// Makes, changes or takes away a credential.
    Credential,
    /// Creates, changes or publishes.
    Change,
    /// Cannot be read: what runs is decided when it runs.
    Unreadable,
}

/// One finding of [`read_script`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeFinding {
    pub kind: CodeKind,
    /// The call as written (`cloudflare.zones.delete`), or what could not be
    /// read.
    pub what: String,
}

impl CodeFinding {
    fn describe(&self) -> String {
        match self.kind {
            CodeKind::Destructive => format!("`{}` deletes, purges or takes away", self.what),
            CodeKind::Credential => format!("`{}` makes or changes a credential", self.what),
            CodeKind::Change => format!("`{}` creates, changes or publishes", self.what),
            CodeKind::Unreadable => {
                format!("{} (what it runs is decided when it runs)", self.what)
            }
        }
    }
}

/// A call to a tool that runs a script, as read: the findings, empty for a
/// script that only reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeReading {
    pub tool: String,
    pub script: String,
    pub findings: Vec<CodeFinding>,
}

impl CodeReading {
    /// One line for a person: the tool and what its script does.
    pub fn explanation(&self) -> String {
        let shown: Vec<String> = self
            .findings
            .iter()
            .take(4)
            .map(CodeFinding::describe)
            .collect();
        let more = self.findings.len().saturating_sub(shown.len());
        let more = if more > 0 {
            format!(" (and {more} more)")
        } else {
            String::new()
        };
        format!(
            "code-mode script handed to `{}`: {}{more}",
            printable(&self.tool, 80),
            shown.join("; ")
        )
    }
}

fn canonical(text: &str) -> String {
    text.trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Whether a tool runs the script it is handed, by its name.
pub fn is_code_tool(tool_name: &str) -> bool {
    let last = canonical(tool_name.rsplit("__").next().unwrap_or(tool_name));
    CODE_TOOLS.contains(&last.as_str()) || LANGUAGE_NAMED_TOOLS.contains(&last.as_str())
}

/// Whether a script handed with no language named is written in another
/// language than JavaScript: it starts with a `#` comment (Python, a shell,
/// Ruby) or a `#!` line that names no JavaScript runtime. A JavaScript
/// script never starts so (`#` outside a class is no JavaScript, and a
/// `#!` line is read only at the very start), and nothing comes before the
/// start, so no other reading of the script can make it one.
fn another_language(script: &str) -> bool {
    let start = script.trim_start();
    if !start.starts_with('#') {
        return false;
    }
    let Some(line) = start.strip_prefix("#!") else {
        return true;
    };
    let line = line.lines().next().unwrap_or("");
    !["node", "deno", "bun", "tsx", "ts-node"]
        .iter()
        .any(|runtime| line.split(['/', ' ', '\t']).any(|word| word == *runtime))
}

/// The findings of a reading, each once, in the order they were found.
#[derive(Default)]
struct Findings {
    list: Vec<CodeFinding>,
    seen: std::collections::HashSet<(CodeKind, String)>,
}

impl Findings {
    fn add(&mut self, kind: CodeKind, what: String) {
        if self.seen.insert((kind, what.clone())) {
            self.list.push(CodeFinding { kind, what });
        }
    }
}

/// A call to a tool that runs a script, read ([`read_script`]). `None` for any
/// other call: a tool not in [`CODE_TOOLS`], no argument in [`CODE_KEYS`], or
/// a language other than JavaScript or TypeScript.
pub fn read_code_call(tool_name: &str, args: &Value) -> Option<CodeReading> {
    if !is_code_tool(tool_name) {
        return None;
    }
    let object = args.as_object()?;
    let language = object.iter().find_map(|(key, value)| {
        LANGUAGE_KEYS
            .contains(&canonical(key).as_str())
            .then(|| value.as_str())
            .flatten()
    });
    match language {
        Some(language) => {
            if !SCRIPT_LANGUAGES.contains(&language.trim().to_ascii_lowercase().as_str()) {
                return None;
            }
        }
        None => {
            let last = canonical(tool_name.rsplit("__").next().unwrap_or(tool_name));
            if LANGUAGE_NAMED_TOOLS.contains(&last.as_str()) {
                return None;
            }
        }
    }
    let scripts: Vec<&Value> = object
        .iter()
        .filter(|(key, _)| CODE_KEYS.contains(&canonical(key).as_str()))
        .map(|(_, value)| value)
        .collect();
    if scripts.is_empty() {
        return None;
    }
    let mut findings = Findings::default();
    let mut shown = String::new();
    for value in scripts {
        match value {
            // Written in another language, with none named: not this
            // reader's (the MCP proxy still reads it as a shell line).
            Value::String(script) if language.is_none() && another_language(script) => {}
            Value::String(script) => {
                if shown.is_empty() {
                    shown.clone_from(script);
                }
                for finding in read_script(script) {
                    findings.add(finding.kind, finding.what);
                }
            }
            Value::Null => {}
            _ => findings.add(CodeKind::Unreadable, "the script is not a string".into()),
        }
    }
    Some(CodeReading {
        tool: tool_name.to_string(),
        script: shown,
        findings: findings.list,
    })
}

/// The proxy's alert for a call to a tool that runs a script that changes,
/// destroys or cannot be read: blocking, so the strict and kill modes refuse
/// it; the other modes forward it with the alert
/// ([`crate::mcp_proxy::enforce::lower_code_mode_refusals`]).
pub(crate) fn code_mode_alert(tool_name: &str, args: &Value) -> Option<crate::mcp::VerdictAlert> {
    let reading = read_code_call(tool_name, args)?;
    if reading.findings.is_empty() {
        return None;
    }
    Some(crate::mcp::VerdictAlert::builtin(
        CODE_MODE_RULE,
        reading.explanation(),
        true,
    ))
}

/// The hook's verdict for a tool call (the payload an agent's PreToolUse
/// hook gets: `tool_name` and `tool_input`) to a tool that runs a script, in
/// the shape the shell analyzer gives a line: `(script, verdict)`. `None` for
/// a call that is not one, and for a script that only reads.
pub fn hook_verdict(payload: &Value) -> Option<(String, Value)> {
    let tool = payload
        .get("tool_name")
        .or_else(|| payload.get("tool"))
        .and_then(Value::as_str)?;
    let input = payload.get("tool_input")?;
    let reading = read_code_call(tool, input)?;
    if reading.findings.is_empty() {
        return None;
    }
    let signals: Vec<Value> = reading
        .findings
        .iter()
        .map(|finding| {
            serde_json::json!({
                "signal": match finding.kind {
                    CodeKind::Unreadable => UNREAD_SIGNAL,
                    _ => CHANGE_SIGNAL,
                },
                "score": REVIEW_SCORE,
                "detail": finding.describe(),
            })
        })
        .collect();
    let command = if reading.script.trim().is_empty() {
        format!("{tool} (script not readable)")
    } else {
        shown_command(reading.script.trim())
    };
    let verdict = serde_json::json!({
        "command": command,
        "risk_score": REVIEW_SCORE,
        "severity": "medium",
        "signals": signals,
        "recommendation": crate::mcp::recommendation_for_score(REVIEW_SCORE),
        "explanation": reading.explanation(),
    });
    Some((command, verdict))
}

/// The most of a script the hook's verdict carries as its command: it goes
/// to the guard's record, the session store and the second opinion.
const MAX_COMMAND_CHARS: usize = 1024;

/// A script as the hook's verdict names it: whole up to
/// [`MAX_COMMAND_CHARS`], else its start, its size and its SHA-256, so two
/// scripts with the same start are still told apart.
fn shown_command(script: &str) -> String {
    if script.chars().count() <= MAX_COMMAND_CHARS {
        return script.to_string();
    }
    use sha2::{Digest, Sha256};
    let hex: String = Sha256::digest(script.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let start: String = script.chars().take(MAX_COMMAND_CHARS).collect();
    format!(
        "{start} ... (script of {} bytes, sha256:{hex})",
        script.len()
    )
}

/// `text` cut to `max` characters, control characters dropped.
fn printable(text: &str, max: usize) -> String {
    let mut out: String = text.chars().filter(|c| !c.is_control()).take(max).collect();
    if text.chars().count() > max {
        out.push_str("...");
    }
    out
}

/// A token of a script.
#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    /// A string or template literal: its text with every escape decoded and
    /// what a template substitutes left out. `plain`: written out whole,
    /// with no substitution and no escape that hides a character (`\x`,
    /// `\u`, an octal one). A template's substitutions come before it, in
    /// parentheses, as the call of a tag they are.
    Str {
        text: String,
        plain: bool,
        template: bool,
    },
    Num,
    Punct(char),
    /// `?.`
    OptChain,
    /// `++` or `--`, and whether it follows an operand (`a++`) or comes
    /// before one (`++a`).
    Update(bool),
}

/// Why a script could not be split into tokens.
struct Unsplit(&'static str);

/// Keywords after which a `/` starts a regular expression.
const REGEX_AFTER_WORDS: &[&str] = &[
    "return",
    "typeof",
    "case",
    "do",
    "else",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "yield",
    "await",
    "instanceof",
];

/// Keywords whose `(...)` is a statement's head: a `/` after its `)`
/// starts a regular expression (`if (x) /re/.test(s)`).
const CONTROL_WORDS: &[&str] = &["if", "while", "for", "with"];

/// Whether a `/` after these tokens starts a regular expression and not a
/// division. `after_control`: the last token is the `)` of a statement's
/// head. A keyword after a dot is a member's name (`res.of / 2`).
fn regex_may_start(tokens: &[Tok], after_control: bool) -> bool {
    match tokens.last() {
        None | Some(Tok::OptChain) => true,
        Some(Tok::Punct(')')) => after_control,
        Some(Tok::Punct(c)) => !matches!(c, ']' | '}'),
        Some(Tok::Update(after_operand)) => !after_operand,
        Some(Tok::Ident(word)) => {
            REGEX_AFTER_WORDS.contains(&word.as_str())
                && !is_dot(tokens.len().checked_sub(2).and_then(|p| tokens.get(p)))
        }
        _ => false,
    }
}

/// A character that ends a line in JavaScript: it ends a `//` comment, and a
/// string or a regular expression may not hold one.
fn line_end(c: char) -> bool {
    matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')
}

/// What an escape in a string or a template stands for.
enum Escape {
    /// A character written plainly (`\n`, `\"`).
    Char(char),
    /// A character written so that it does not show (`\x64`, `\u0064`,
    /// `\u{64}`, `\144`).
    Hidden(char),
    /// A code unit that is no character on its own (half of a pair).
    Unknown,
    /// A backslash before the end of a line: the line goes on.
    Continuation,
}

/// The value of `count` hexadecimal digits at `*i`.
fn hex_digits(src: &[char], i: &mut usize, count: usize) -> Result<u32, Unsplit> {
    let mut value = 0u32;
    for _ in 0..count {
        let digit = src
            .get(*i)
            .and_then(|c| c.to_digit(16))
            .ok_or(Unsplit("an escape that is not one"))?;
        value = value * 16 + digit;
        *i += 1;
    }
    Ok(value)
}

/// The escape after a backslash in a string or template, at `*i`.
fn escaped(src: &[char], i: &mut usize) -> Result<Escape, Unsplit> {
    let Some(&e) = src.get(*i) else {
        return Err(Unsplit("a string is not closed"));
    };
    *i += 1;
    let hidden = |value: u32| char::from_u32(value).map_or(Escape::Unknown, Escape::Hidden);
    Ok(match e {
        'x' => hidden(hex_digits(src, i, 2)?),
        'u' if src.get(*i) == Some(&'{') => {
            *i += 1;
            let mut value = 0u32;
            let mut digits = 0;
            loop {
                match src.get(*i) {
                    Some('}') if digits > 0 => {
                        *i += 1;
                        break;
                    }
                    Some(c) if c.is_ascii_hexdigit() && digits < 8 => {
                        value = value.saturating_mul(16) + c.to_digit(16).unwrap_or(0);
                        digits += 1;
                        *i += 1;
                    }
                    _ => return Err(Unsplit("an escape that is not one")),
                }
            }
            hidden(value)
        }
        'u' => hidden(hex_digits(src, i, 4)?),
        '0'..='7' => {
            let mut value = e.to_digit(8).unwrap_or(0);
            for _ in 0..2 {
                match src.get(*i).and_then(|c| c.to_digit(8)) {
                    Some(digit) if value * 8 + digit <= 0o377 => {
                        value = value * 8 + digit;
                        *i += 1;
                    }
                    _ => break,
                }
            }
            hidden(value)
        }
        '8' | '9' => Escape::Hidden(e),
        'n' => Escape::Char('\n'),
        't' => Escape::Char('\t'),
        'r' => Escape::Char('\r'),
        'b' => Escape::Char('\u{8}'),
        'f' => Escape::Char('\u{c}'),
        'v' => Escape::Char('\u{b}'),
        '\r' => {
            if src.get(*i) == Some(&'\n') {
                *i += 1;
            }
            Escape::Continuation
        }
        '\n' | '\u{2028}' | '\u{2029}' => Escape::Continuation,
        other => Escape::Char(other),
    })
}

/// A script split into tokens, and where the text of every string,
/// template, regular expression and comment in it is ([`hidden_calls`]
/// reads it again).
struct Scan<'a> {
    src: &'a [char],
    i: usize,
    bodies: Vec<(usize, usize)>,
}

impl Scan<'_> {
    /// Split from `self.i` into `tokens`. In a substitution of a template
    /// (`in_substitution`), stop after the `}` that closes it.
    fn run(
        &mut self,
        tokens: &mut Vec<Tok>,
        in_substitution: bool,
        depth: usize,
    ) -> Result<(), Unsplit> {
        if depth > 32 {
            return Err(Unsplit("templates nested too deep"));
        }
        let src = self.src;
        let mut braces = 0usize;
        // For each open `(`: whether it is a statement's head.
        let mut parens: Vec<bool> = Vec::new();
        // The length of `tokens` just after a statement's head closed.
        let mut control_closed: Option<usize> = None;
        // A `#!` line at the very start (Node runs it as a comment).
        if depth == 0 && self.i == 0 && src.starts_with(&['#', '!']) {
            while self.i < src.len() && !line_end(src[self.i]) {
                self.i += 1;
            }
        }
        while self.i < src.len() {
            let c = src[self.i];
            let next = src.get(self.i + 1).copied();
            if c.is_whitespace() {
                self.i += 1;
                continue;
            }
            if c == '/' && next == Some('/') {
                self.i += 2;
                let start = self.i;
                while self.i < src.len() && !line_end(src[self.i]) {
                    self.i += 1;
                }
                self.bodies.push((start, self.i));
                continue;
            }
            if c == '/' && next == Some('*') {
                self.i += 2;
                let start = self.i;
                loop {
                    if self.i + 1 >= src.len() {
                        return Err(Unsplit("a comment is not closed"));
                    }
                    if src[self.i] == '*' && src[self.i + 1] == '/' {
                        self.bodies.push((start, self.i));
                        self.i += 2;
                        break;
                    }
                    self.i += 1;
                }
                continue;
            }
            if c == '/' && regex_may_start(tokens, control_closed == Some(tokens.len())) {
                self.i += 1;
                let start = self.i;
                let mut class = false;
                loop {
                    let Some(&r) = src.get(self.i) else {
                        return Err(Unsplit("a regular expression is not closed"));
                    };
                    self.i += 1;
                    match r {
                        '\\' => {
                            if src.get(self.i).is_none_or(|e| line_end(*e)) {
                                return Err(Unsplit("a regular expression is not closed"));
                            }
                            self.i += 1;
                        }
                        '[' => class = true,
                        ']' => class = false,
                        '/' if !class => break,
                        r if line_end(r) => {
                            return Err(Unsplit("a regular expression is not closed"))
                        }
                        _ => {}
                    }
                }
                self.bodies.push((start, self.i - 1));
                while src.get(self.i).is_some_and(|f| f.is_ascii_alphabetic()) {
                    self.i += 1;
                }
                tokens.push(Tok::Str {
                    text: String::new(),
                    plain: true,
                    template: false,
                });
                continue;
            }
            if c == '"' || c == '\'' {
                self.i += 1;
                let start = self.i;
                let mut text = String::new();
                let mut plain = true;
                loop {
                    let Some(&s) = src.get(self.i) else {
                        return Err(Unsplit("a string is not closed"));
                    };
                    self.i += 1;
                    if s == c {
                        break;
                    }
                    match s {
                        '\\' => match escaped(src, &mut self.i)? {
                            Escape::Char(ch) => text.push(ch),
                            Escape::Hidden(ch) => {
                                text.push(ch);
                                plain = false;
                            }
                            Escape::Unknown => plain = false,
                            Escape::Continuation => {}
                        },
                        '\n' | '\r' => return Err(Unsplit("a string is not closed")),
                        other => text.push(other),
                    }
                }
                self.bodies.push((start, self.i - 1));
                tokens.push(Tok::Str {
                    text,
                    plain,
                    template: false,
                });
                continue;
            }
            if c == '`' {
                self.i += 1;
                let mut part = self.i;
                let mut text = String::new();
                let mut plain = true;
                let mut substituted = Vec::new();
                loop {
                    let Some(&s) = src.get(self.i) else {
                        return Err(Unsplit("a template is not closed"));
                    };
                    self.i += 1;
                    match s {
                        '`' => break,
                        '\\' => match escaped(src, &mut self.i)? {
                            Escape::Char(ch) => text.push(ch),
                            Escape::Hidden(ch) => {
                                text.push(ch);
                                plain = false;
                            }
                            Escape::Unknown => plain = false,
                            Escape::Continuation => {}
                        },
                        '$' if src.get(self.i) == Some(&'{') => {
                            self.bodies.push((part, self.i - 1));
                            self.i += 1;
                            plain = false;
                            substituted.push(Tok::Punct('('));
                            self.run(&mut substituted, true, depth + 1)?;
                            substituted.push(Tok::Punct(')'));
                            part = self.i;
                        }
                        other => text.push(other),
                    }
                }
                self.bodies.push((part, self.i - 1));
                tokens.extend(substituted);
                tokens.push(Tok::Str {
                    text,
                    plain,
                    template: true,
                });
                continue;
            }
            if c == '\\' {
                return Err(Unsplit("an escape in a name"));
            }
            if c.is_alphabetic() || c == '_' || c == '$' {
                let start = self.i;
                while src
                    .get(self.i)
                    .is_some_and(|w| w.is_alphanumeric() || *w == '_' || *w == '$')
                {
                    self.i += 1;
                }
                if src.get(self.i) == Some(&'\\') {
                    return Err(Unsplit("an escape in a name"));
                }
                tokens.push(Tok::Ident(src[start..self.i].iter().collect()));
                continue;
            }
            if c.is_ascii_digit() || (c == '.' && next.is_some_and(|n| n.is_ascii_digit())) {
                while src
                    .get(self.i)
                    .is_some_and(|w| w.is_ascii_alphanumeric() || *w == '.' || *w == '_')
                {
                    self.i += 1;
                }
                tokens.push(Tok::Num);
                continue;
            }
            if c == '?'
                && next == Some('.')
                && !src.get(self.i + 2).is_some_and(|d| d.is_ascii_digit())
            {
                self.i += 2;
                tokens.push(Tok::OptChain);
                continue;
            }
            if (c == '+' || c == '-') && next == Some(c) {
                self.i += 2;
                let after_operand = !regex_may_start(tokens, control_closed == Some(tokens.len()));
                tokens.push(Tok::Update(after_operand));
                continue;
            }
            self.i += 1;
            if in_substitution {
                if c == '{' {
                    braces += 1;
                } else if c == '}' {
                    if braces == 0 {
                        return Ok(());
                    }
                    braces -= 1;
                }
            }
            if c == '(' {
                let head = matches!(tokens.last(), Some(Tok::Ident(word)) if CONTROL_WORDS.contains(&word.as_str()))
                    && !is_dot(tokens.len().checked_sub(2).and_then(|p| tokens.get(p)));
                parens.push(head);
            }
            tokens.push(Tok::Punct(c));
            if c == ')' && parens.pop() == Some(true) {
                control_closed = Some(tokens.len());
            }
        }
        if in_substitution {
            return Err(Unsplit("a template is not closed"));
        }
        Ok(())
    }
}

/// The words of a name: split at `_`, digits, a lower-to-upper case change
/// and the end of a run of capitals (`deleteDnsRecord` is `delete dns
/// record`, `DNSDelete` is `dns delete`), lower case.
fn words(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut out = Vec::new();
    let mut word = String::new();
    for (k, &c) in chars.iter().enumerate() {
        if !c.is_alphabetic() {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            continue;
        }
        let previous = k.checked_sub(1).map(|p| chars[p]);
        let following = chars.get(k + 1).copied();
        let boundary = c.is_uppercase()
            && match previous {
                Some(p) if p.is_lowercase() => true,
                Some(p) if p.is_uppercase() => following.is_some_and(char::is_lowercase),
                _ => false,
            };
        if boundary && !word.is_empty() {
            out.push(std::mem::take(&mut word));
        }
        word.extend(c.to_lowercase());
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

fn is_dot(tok: Option<&Tok>) -> bool {
    matches!(tok, Some(Tok::Punct('.') | Tok::OptChain))
}

/// No bracket matches here.
const UNMATCHED: usize = usize::MAX;

/// For each bracket token the index of the one that matches it, matched
/// once with a stack (the reading of a script built of thousands of
/// brackets stays linear).
fn match_brackets(tokens: &[Tok]) -> Vec<usize> {
    let mut matches = vec![UNMATCHED; tokens.len()];
    let mut stack: Vec<(usize, char)> = Vec::new();
    for (k, tok) in tokens.iter().enumerate() {
        let Tok::Punct(c) = tok else { continue };
        match c {
            '(' | '[' | '{' => stack.push((k, *c)),
            ')' | ']' | '}' => {
                let open = match c {
                    ')' => '(',
                    ']' => '[',
                    _ => '{',
                };
                if stack.last().is_some_and(|(_, o)| *o == open) {
                    if let Some((at, _)) = stack.pop() {
                        matches[at] = k;
                        matches[k] = at;
                    }
                }
            }
            _ => {}
        }
    }
    matches
}

fn matched(matches: &[usize], at: usize) -> Option<usize> {
    matches.get(at).copied().filter(|m| *m != UNMATCHED)
}

/// The names before a member, root first (`cloudflare.user.tokens` for
/// `create`), and the index of the root's token. `access` is the index of
/// the member's own dot or `[`.
fn chain_before(tokens: &[Tok], matches: &[usize], access: usize) -> (Vec<String>, Option<usize>) {
    let mut chain = Vec::new();
    let mut root = None;
    let mut k = access;
    let mut steps = 0;
    'walk: while steps < 32 {
        steps += 1;
        let Some(mut end) = k.checked_sub(1) else {
            break;
        };
        // `?.[`: the bracket's own optional dot.
        if matches!(tokens.get(k), Some(Tok::Punct('[')))
            && matches!(tokens.get(end), Some(Tok::OptChain))
        {
            let Some(e) = end.checked_sub(1) else { break };
            end = e;
        }
        // Calls on the way (`client.tokens().create`) are passed over.
        while matches!(tokens.get(end), Some(Tok::Punct(')'))) {
            steps += 1;
            let Some(e) = (steps < 32)
                .then(|| matched(matches, end))
                .flatten()
                .and_then(|open| open.checked_sub(1))
            else {
                break 'walk;
            };
            end = e;
        }
        match tokens.get(end) {
            Some(Tok::Ident(name)) => {
                chain.push(name.clone());
                root = Some(end);
                match end.checked_sub(1) {
                    Some(dot) if is_dot(tokens.get(dot)) => k = dot,
                    _ => break,
                }
            }
            Some(Tok::Punct(']')) => {
                let Some(open) = matched(matches, end) else {
                    break;
                };
                if let [Tok::Str { text, .. }] = &tokens[open + 1..end] {
                    chain.push(text.clone());
                }
                k = open;
            }
            _ => break,
        }
    }
    chain.reverse();
    (chain, root)
}

/// Whether the token before `at` makes a `[` there an access to a member
/// (`api["delete"]`) and not an array.
fn accessed_before(tokens: &[Tok], at: usize) -> bool {
    match at.checked_sub(1).and_then(|p| tokens.get(p)) {
        Some(Tok::Ident(word)) => !REGEX_AFTER_WORDS.contains(&word.as_str()),
        Some(Tok::Punct(')' | ']') | Tok::OptChain | Tok::Str { .. }) => true,
        _ => false,
    }
}

/// Whether the tokens after `at` call what ends at `at` (`(`, `?.(`,
/// `.call(`, `.apply(`, `.bind(`, a tagged template).
fn called_after(tokens: &[Tok], at: usize) -> bool {
    match tokens.get(at + 1) {
        Some(Tok::Punct('(')) => true,
        Some(Tok::Str { template: true, .. }) => true,
        Some(Tok::OptChain) => matches!(tokens.get(at + 2), Some(Tok::Punct('('))),
        Some(Tok::Punct('.')) => matches!(
            tokens.get(at + 2),
            Some(Tok::Ident(word)) if matches!(word.as_str(), "call" | "apply" | "bind")
        ),
        _ => false,
    }
}

/// What a member named `name`, reached through `chain`, does.
fn member_kind(name: &str, chain: &[String]) -> Option<CodeKind> {
    let verbs = words(name);
    let destroys = verbs
        .iter()
        .any(|w| DESTRUCTIVE_VERBS.contains(&w.as_str()));
    let changes = verbs.iter().any(|w| CHANGE_VERBS.contains(&w.as_str()));
    if !destroys && !changes {
        return None;
    }
    let credential = chain
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(name))
        .flat_map(words)
        .any(|w| CREDENTIAL_WORDS.contains(&w.as_str()));
    Some(if credential {
        CodeKind::Credential
    } else if destroys {
        CodeKind::Destructive
    } else {
        CodeKind::Change
    })
}

/// Names of a member that reach code built from a string: `eval`,
/// `Function`, a function's `constructor`.
const CODE_FROM_STRING_NAMES: &[&str] = &["eval", "Function", "constructor"];

/// Constructors of values that live in the script (a `Map`, a `Headers`):
/// a method called on one changes nothing outside it.
const LOCAL_CONSTRUCTORS: &[&str] = &[
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "Headers",
    "URLSearchParams",
    "FormData",
    "URL",
    "Array",
    "Object",
    "Date",
    "RegExp",
    "Error",
    "AbortController",
    "TextEncoder",
    "TextDecoder",
    "Blob",
    "Request",
    "Response",
    "DOMParser",
    "Uint8Array",
    "ArrayBuffer",
];

/// Globals that live in the script (or the page it runs in), whatever is
/// called on them.
const LOCAL_ROOTS: &[&str] = &["document", "localStorage", "sessionStorage", "console"];

/// The language's own objects: a method called right on one (`Object.create`,
/// `Reflect.deleteProperty`) changes nothing outside the script.
const LANGUAGE_OBJECTS: &[&str] = &[
    "Object", "Reflect", "Array", "JSON", "Math", "Promise", "Number", "String", "Date", "Symbol",
    "Intl", "Atomics", "Iterator",
];

/// Calls that make a value that lives in the script (a hash, an element of
/// the page), on `crypto`, `require(...)`, `document` or one such value.
const LOCAL_MAKERS: &[&str] = &[
    "createHash",
    "createHmac",
    "createCipheriv",
    "createDecipheriv",
    "createSign",
    "createVerify",
    "querySelector",
    "querySelectorAll",
    "getElementById",
    "getElementsByClassName",
    "getElementsByTagName",
    "createElement",
    "createTextNode",
    "createDocumentFragment",
    "closest",
    "cloneNode",
];

/// Roots a [`LOCAL_MAKERS`] call is read on.
const MAKER_ROOTS: &[&str] = &["crypto", "require", "document"];

/// Whether a member reached through `chain` (root at `root`) is called on
/// a value that lives in the script: one of [`LOCAL_CONSTRUCTORS`] built
/// there (`new Map().delete(k)`), a name bound to one (`locals`), a
/// [`LOCAL_ROOTS`] global, a language object, or what a [`LOCAL_MAKERS`]
/// call made.
fn local_receiver(
    tokens: &[Tok],
    chain: &[String],
    root: Option<usize>,
    locals: &std::collections::HashSet<String>,
) -> bool {
    let Some(first) = chain.first() else {
        return false;
    };
    let constructed = root.is_some_and(|r| {
        matches!(tokens.get(r), Some(Tok::Ident(name)) if *name == *first)
            && matches!(r.checked_sub(1).and_then(|p| tokens.get(p)), Some(Tok::Ident(w)) if w == "new")
    });
    if constructed {
        return LOCAL_CONSTRUCTORS.contains(&first.as_str());
    }
    if locals.contains(first) || LOCAL_ROOTS.contains(&first.as_str()) {
        return true;
    }
    if chain.len() == 1 && LANGUAGE_OBJECTS.contains(&first.as_str()) {
        return true;
    }
    (MAKER_ROOTS.contains(&first.as_str()) || LOCAL_MAKERS.contains(&first.as_str()))
        && chain
            .iter()
            .any(|name| LOCAL_MAKERS.contains(&name.as_str()))
}

/// What an HTTP method does: `Some(None)` for a read, `None` for a word that
/// is no method.
fn http_method_kind(method: &str) -> Option<Option<CodeKind>> {
    match method.trim().to_ascii_uppercase().as_str() {
        "DELETE" => Some(Some(CodeKind::Destructive)),
        "PUT" | "PATCH" | "POST" => Some(Some(CodeKind::Change)),
        "GET" | "HEAD" | "OPTIONS" => Some(None),
        _ => None,
    }
}

/// A string written as an HTTP request line or a method alone, in capitals
/// (`"DELETE"`, `"PUT /zones/x"`, `"DELETE\t/x"`): what it does.
fn request_line_kind(text: &str) -> Option<CodeKind> {
    let text = text.trim_start();
    let first = text.split(char::is_whitespace).next().unwrap_or("");
    if first.is_empty() || first != first.to_ascii_uppercase() {
        return None;
    }
    let rest = &text[first.len()..];
    let path = rest.trim_start();
    if !rest.is_empty()
        && (path.len() == rest.len() || !(path.starts_with('/') || path.starts_with("http")))
    {
        return None;
    }
    http_method_kind(first).flatten()
}

/// `text` with SQL comments (`-- ...`, `/* ... */`) left out.
fn without_sql_comments(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("--") {
            rest = after.find('\n').map_or("", |n| &after[n..]);
        } else if let Some(after) = rest.strip_prefix("/*") {
            rest = after.find("*/").map_or("", |n| &after[n + 2..]);
            out.push(' ');
        } else {
            let mut chars = rest.chars();
            if let Some(c) = chars.next() {
                out.push(c);
            }
            rest = chars.as_str();
        }
    }
    out
}

/// A string that holds an SQL statement that changes or destroys, alone or
/// among others (`"SELECT 1; DROP TABLE users"`), however spaced: what the
/// worst of them does.
fn sql_kind(text: &str) -> Option<CodeKind> {
    let lower = without_sql_comments(&text.to_ascii_lowercase());
    let mut worst = None;
    for statement in lower.split(';') {
        let statement = statement.split_whitespace().collect::<Vec<_>>().join(" ");
        let statement = statement.trim_start_matches(['(', ' ']);
        let kind = if let Some((_, destroys)) = SQL_STATEMENTS
            .iter()
            .find(|(s, _)| statement.starts_with(s) || *s == statement.trim_end())
        {
            Some(if *destroys {
                CodeKind::Destructive
            } else {
                CodeKind::Change
            })
        } else {
            // `UPDATE <table> SET`
            let mut parts = statement.split(' ');
            (parts.next() == Some("update") && parts.nth(1) == Some("set"))
                .then_some(CodeKind::Change)
        };
        match kind {
            Some(CodeKind::Destructive) => return kind,
            Some(_) => worst = kind,
            None => {}
        }
    }
    worst
}

/// What a token is in a destructuring pattern (`const { purge } = cache`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum PatternRole {
    None,
    /// A key: a member taken out of an object.
    Key,
    /// The `[` of a key computed from a value (`{ ["delete"]: f }`).
    ComputedKey,
}

/// The role every token has in the destructuring patterns of the script.
/// A pattern inside one already gone through is not gone through again.
fn destructured_keys(tokens: &[Tok], matches: &[usize]) -> Vec<PatternRole> {
    let mut roles = vec![PatternRole::None; tokens.len()];
    let mut covered_until = 0usize;
    for (open, tok) in tokens.iter().enumerate() {
        if *tok != Tok::Punct('{') || open < covered_until {
            continue;
        }
        let Some(close) = matched(matches, open) else {
            continue;
        };
        let assigned = matches!(tokens.get(close + 1), Some(Tok::Punct('=')))
            && !matches!(tokens.get(close + 2), Some(Tok::Punct('=' | '>')));
        let declared = matches!(
            open.checked_sub(1).and_then(|p| tokens.get(p)),
            Some(Tok::Ident(word)) if matches!(word.as_str(), "const" | "let" | "var")
        );
        if !assigned && !declared {
            continue;
        }
        covered_until = close;
        for k in open + 1..close {
            // A key: followed by one of `: , } =` and not itself a value.
            let key_position = matches!(tokens.get(k + 1), Some(Tok::Punct(':' | ',' | '}' | '=')))
                && !matches!(tokens.get(k - 1), Some(Tok::Punct(':')));
            if key_position && matches!(tokens[k], Tok::Ident(_) | Tok::Str { .. }) {
                roles[k] = PatternRole::Key;
            }
            if tokens[k] == Tok::Punct('[')
                && matched(matches, k)
                    .is_some_and(|m| matches!(tokens.get(m + 1), Some(Tok::Punct(':'))))
            {
                roles[k] = PatternRole::ComputedKey;
            }
        }
    }
    roles
}

/// Every assignment to a plain name (`const m = ...`, `method = ...`, a
/// default in a pattern), in order: the name and the index of the value's
/// first token (past an `await`).
fn assignments(tokens: &[Tok]) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for (k, tok) in tokens.iter().enumerate() {
        let Tok::Ident(name) = tok else { continue };
        if !matches!(tokens.get(k + 1), Some(Tok::Punct('=')))
            || matches!(tokens.get(k + 2), Some(Tok::Punct('=' | '>')))
            || is_dot(k.checked_sub(1).and_then(|p| tokens.get(p)))
        {
            continue;
        }
        let mut value = k + 2;
        if matches!(tokens.get(value), Some(Tok::Ident(w)) if w == "await") {
            value += 1;
        }
        out.push((name.clone(), value));
    }
    out
}

/// The names bound to a value that lives in the script ([`local_receiver`]):
/// `const m = new Map()`, `const h = crypto.createHash("sha256")`,
/// `const e = document.querySelector("p")`, `const o = Object.create(null)`,
/// and a name bound to one of those.
fn local_names(
    tokens: &[Tok],
    matches: &[usize],
    assigned: &[(String, usize)],
) -> std::collections::HashSet<String> {
    let mut locals = std::collections::HashSet::new();
    for (name, value) in assigned {
        let mut k = *value;
        let constructed = matches!(tokens.get(k), Some(Tok::Ident(w)) if w == "new");
        if constructed {
            k += 1;
        }
        let Some(Tok::Ident(root)) = tokens.get(k) else {
            continue;
        };
        if constructed {
            if LOCAL_CONSTRUCTORS.contains(&root.as_str()) {
                locals.insert(name.clone());
            }
            continue;
        }
        let mut chain = vec![root.clone()];
        let mut at = k + 1;
        for _ in 0..64 {
            match tokens.get(at) {
                Some(Tok::Punct('.') | Tok::OptChain) => match tokens.get(at + 1) {
                    Some(Tok::Ident(member)) => {
                        chain.push(member.clone());
                        at += 2;
                    }
                    _ => break,
                },
                Some(Tok::Punct('(' | '[')) => match matched(matches, at) {
                    Some(close) => at = close + 1,
                    None => break,
                },
                _ => break,
            }
        }
        let made = (locals.contains(root)
            || MAKER_ROOTS.contains(&root.as_str())
            || LOCAL_MAKERS.contains(&root.as_str()))
            && chain.iter().any(|m| LOCAL_MAKERS.contains(&m.as_str()));
        if locals.contains(root)
            || LOCAL_ROOTS.contains(&root.as_str())
            || made
            || (chain.len() == 2 && root == "Object" && chain[1] == "create")
        {
            locals.insert(name.clone());
        }
    }
    locals
}

/// Whether a string of the script names a credential's path (`/user/tokens`).
fn names_a_credential_path(tokens: &[Tok]) -> bool {
    tokens.iter().any(|tok| match tok {
        Tok::Str { text, .. } => {
            let lower = text.to_ascii_lowercase();
            CREDENTIAL_PATHS.iter().any(|path| {
                lower.match_indices(path).any(|(at, _)| {
                    !lower[at + path.len()..]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                })
            })
        }
        _ => false,
    })
}

/// What a name at `at` (a `member` or not) reaches that cannot be read, if
/// anything: code built from a string (`eval` in any place, `Function`,
/// `.constructor`), a dynamic `import`, a `require` of a name made at run
/// time, a timer handed a string.
fn unreadable_call(tokens: &[Tok], at: usize, name: &str, member: bool) -> Option<String> {
    let previous = at.checked_sub(1).and_then(|p| tokens.get(p));
    let next = tokens.get(at + 1);
    let called = matches!(next, Some(Tok::Punct('(')));
    match name {
        // Anywhere but as an object's own key (`{ eval: true }`).
        "eval"
            if member
                || !(matches!(next, Some(Tok::Punct(':')))
                    && matches!(previous, Some(Tok::Punct('{' | ',')))) =>
        {
            Some("`eval` of a string".into())
        }
        "Function" if !matches!(previous, Some(Tok::Ident(w)) if w == "instanceof") => {
            Some("code built by `Function`".into())
        }
        // `(async () => {}).constructor("...")`; `x.constructor.name` and a
        // comparison read nothing.
        "constructor"
            if member
                && !matches!(next, Some(Tok::Punct('.')))
                && !(matches!(next, Some(Tok::Punct('=' | '!')))
                    && matches!(tokens.get(at + 2), Some(Tok::Punct('=')))) =>
        {
            Some("code built by a function's `constructor`".into())
        }
        "setTimeout" | "setInterval" | "setImmediate"
            if called && matches!(tokens.get(at + 2), Some(Tok::Str { .. })) =>
        {
            Some(format!("`{name}` of a string"))
        }
        "import" if !member && called => Some("a dynamic `import`".into()),
        "require"
            if !member
                && called
                && !matches!(
                    (tokens.get(at + 2), tokens.get(at + 3)),
                    (Some(Tok::Str { plain: true, .. }), Some(Tok::Punct(')')))
                ) =>
        {
            Some("a `require` of a name made at run time".into())
        }
        "with" if !member && called => Some("a `with` block".into()),
        _ => None,
    }
}

/// The HTTP methods a value of the script can hold: the literal strings it
/// is, through names bound to them (`const method = "delete"`), and whether
/// some part of it is chosen at run time. `None` for a TypeScript type
/// (`method: string`).
fn method_values(
    tokens: &[Tok],
    assigned: &std::collections::HashMap<String, Vec<usize>>,
    value: usize,
    depth: usize,
    out: &mut Vec<String>,
) -> Option<bool> {
    match tokens.get(value) {
        Some(Tok::Str { text, plain, .. }) => {
            out.push(text.clone());
            Some(!plain)
        }
        Some(Tok::Ident(word)) if word == "string" => None,
        Some(Tok::Ident(word)) if depth < 4 => {
            let Some(values) = assigned.get(word) else {
                return Some(true);
            };
            let mut unknown = false;
            for v in values {
                unknown |= method_values(tokens, assigned, *v, depth + 1, out).unwrap_or(true);
            }
            Some(unknown)
        }
        _ => Some(true),
    }
}

/// The calls a script makes that change or destroy, and what in it cannot be
/// read. Empty for a script that only reads.
pub fn read_script(script: &str) -> Vec<CodeFinding> {
    let mut findings = Findings::default();
    if script.len() > MAX_SCRIPT_BYTES {
        findings.add(
            CodeKind::Unreadable,
            format!(
                "the script is {} bytes, more than the {MAX_SCRIPT_BYTES} the guard reads",
                script.len()
            ),
        );
        return findings.list;
    }
    let src: Vec<char> = script.chars().collect();
    let mut scan = Scan {
        src: &src,
        i: 0,
        bodies: Vec::new(),
    };
    let mut tokens = Vec::new();
    if let Err(Unsplit(why)) = scan.run(&mut tokens, false, 0) {
        findings.add(
            CodeKind::Unreadable,
            format!("the script cannot be read: {why}"),
        );
        return findings.list;
    }
    read_tokens(&tokens, &mut findings);
    hidden_calls(&src, &scan.bodies, &mut findings);
    findings.list
}

/// [`read_script`] on the tokens of a script.
fn read_tokens(tokens: &[Tok], findings: &mut Findings) {
    let matches = match_brackets(tokens);
    let roles = destructured_keys(tokens, &matches);
    let assigned_list = assignments(tokens);
    let locals = local_names(tokens, &matches, &assigned_list);
    let mut assigned: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    for (name, value) in &assigned_list {
        assigned.entry(name.clone()).or_default().push(*value);
    }
    let credential_path = names_a_credential_path(tokens);
    // A request's method or line: a credential when the script names a
    // credential's path.
    let request = |kind: CodeKind| {
        if credential_path {
            CodeKind::Credential
        } else {
            kind
        }
    };
    // The method a request is sent with, from the value at `value`.
    let judge_method = |findings: &mut Findings, value: usize| {
        let mut methods = Vec::new();
        let Some(unknown) = method_values(tokens, &assigned, value, 0, &mut methods) else {
            return;
        };
        for method in methods {
            if let Some(Some(kind)) = http_method_kind(&method) {
                findings.add(
                    request(kind),
                    format!("an HTTP {} request", method.trim().to_ascii_uppercase()),
                );
            }
        }
        if unknown {
            findings.add(
                CodeKind::Unreadable,
                "an HTTP method chosen at run time".into(),
            );
        }
    };

    for (at, tok) in tokens.iter().enumerate() {
        let previous = at.checked_sub(1).and_then(|p| tokens.get(p));
        let member = is_dot(previous);
        let next = tokens.get(at + 1);
        // A key `method` (`method: "DELETE"`, `"method": "delete"`) or an
        // assignment to one (`opts.method = m`).
        let method_key = match tok {
            Tok::Ident(name) => name == "method",
            Tok::Str { text, plain, .. } => *plain && text == "method",
            _ => false,
        } && roles[at] == PatternRole::None;
        if method_key {
            if matches!(next, Some(Tok::Punct(':'))) && !member {
                judge_method(findings, at + 2);
                continue;
            }
            if member
                && matches!(next, Some(Tok::Punct('=')))
                && !matches!(tokens.get(at + 2), Some(Tok::Punct('=')))
            {
                judge_method(findings, at + 2);
                continue;
            }
            // Shorthand (`fetch(u, { method })`): the value is the name's.
            if matches!(tok, Tok::Ident(_))
                && !member
                && matches!(next, Some(Tok::Punct(',' | '}')))
                && matches!(previous, Some(Tok::Punct('{' | ',')))
                && assigned.contains_key("method")
            {
                judge_method(findings, at);
                continue;
            }
        }
        match tok {
            Tok::Ident(name) => {
                if roles[at] == PatternRole::Key && CODE_FROM_STRING_NAMES.contains(&name.as_str())
                {
                    findings.add(
                        CodeKind::Unreadable,
                        format!("`{name}` taken out of an object"),
                    );
                    continue;
                }
                if let Some(what) = unreadable_call(tokens, at, name, member) {
                    findings.add(CodeKind::Unreadable, what);
                    continue;
                }
                if name == "Reflect" && !member {
                    reflect_call(tokens, &matches, at, findings);
                }
                // A command object built by name (`new DeleteObjectCommand(...)`,
                // the AWS SDK's shape) is the call it is sent as.
                let constructed = !member
                    && matches!(previous, Some(Tok::Ident(w)) if w == "new")
                    && !LOCAL_CONSTRUCTORS.contains(&name.as_str());
                if member || roles[at] == PatternRole::Key || constructed {
                    let (mut chain, root) = if member {
                        chain_before(tokens, &matches, at - 1)
                    } else {
                        (Vec::new(), None)
                    };
                    if member && local_receiver(tokens, &chain, root, &locals) {
                        continue;
                    }
                    // A maker of a local value, on its own root
                    // (`crypto.createHash`, `document.createElement`).
                    if member
                        && LOCAL_MAKERS.contains(&name.as_str())
                        && chain.first().is_some_and(|r| {
                            MAKER_ROOTS.contains(&r.as_str()) || locals.contains(r)
                        })
                    {
                        continue;
                    }
                    // An iterator's `drop(n)`.
                    if name == "drop"
                        && matches!(
                            (next, tokens.get(at + 2), tokens.get(at + 3)),
                            (Some(Tok::Punct('(')), Some(Tok::Num), Some(Tok::Punct(')')))
                        )
                    {
                        continue;
                    }
                    if let Some(kind) = member_kind(name, &chain) {
                        chain.push(name.clone());
                        findings.add(kind, printable(&chain.join("."), 80));
                    }
                }
            }
            Tok::Str { text, plain, .. } => {
                if roles[at] == PatternRole::Key {
                    if CODE_FROM_STRING_NAMES.contains(&text.as_str()) {
                        findings.add(
                            CodeKind::Unreadable,
                            format!("`{}` taken out of an object", printable(text, 40)),
                        );
                    }
                    if !plain {
                        findings.add(CodeKind::Unreadable, "a member named at run time".into());
                    }
                    if let Some(kind) = member_kind(text, &[]) {
                        findings.add(kind, printable(text, 80));
                    }
                }
                if let Some(kind) = request_line_kind(text) {
                    findings.add(
                        request(kind),
                        format!("an HTTP request `{}`", printable(text, 80)),
                    );
                } else if let Some(kind) = sql_kind(text) {
                    findings.add(kind, format!("the SQL `{}`", printable(text, 80)));
                }
            }
            Tok::Punct('[')
                if accessed_before(tokens, at) || roles[at] == PatternRole::ComputedKey =>
            {
                let Some(close) = matched(&matches, at) else {
                    continue;
                };
                let computed_key = roles[at] == PatternRole::ComputedKey;
                match &tokens[at + 1..close] {
                    [Tok::Str { text, plain, .. }] => {
                        if CODE_FROM_STRING_NAMES.contains(&text.as_str()) {
                            findings.add(
                                CodeKind::Unreadable,
                                format!("`{}` reached by its name", printable(text, 40)),
                            );
                        }
                        let (mut chain, root) = if computed_key {
                            (Vec::new(), None)
                        } else {
                            chain_before(tokens, &matches, at)
                        };
                        if !computed_key && local_receiver(tokens, &chain, root, &locals) {
                            continue;
                        }
                        if !plain && (computed_key || called_after(tokens, close)) {
                            findings.add(CodeKind::Unreadable, "a method named at run time".into());
                        }
                        if let Some(kind) = member_kind(text, &chain) {
                            chain.push(text.clone());
                            findings.add(kind, printable(&chain.join("."), 80));
                        }
                    }
                    _ if computed_key || called_after(tokens, close) => {
                        findings.add(CodeKind::Unreadable, "a method named at run time".into());
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

/// `Reflect.get(obj, "delete")`, `Reflect.apply(...)`: the names its
/// arguments give in strings are members reached by name, and a
/// `Reflect.get` whose name is not written out and whose result is called
/// is a method named at run time.
fn reflect_call(tokens: &[Tok], matches: &[usize], at: usize, findings: &mut Findings) {
    let (Some(Tok::Punct('.')), Some(Tok::Ident(method)), Some(Tok::Punct('('))) =
        (tokens.get(at + 1), tokens.get(at + 2), tokens.get(at + 3))
    else {
        return;
    };
    if !matches!(
        method.as_str(),
        "get" | "apply" | "construct" | "getOwnPropertyDescriptor"
    ) {
        return;
    }
    let open = at + 3;
    let Some(close) = matched(matches, open) else {
        return;
    };
    // The arguments at the call's own level: nested brackets are passed over.
    let mut arguments: Vec<Vec<&Tok>> = vec![Vec::new()];
    let mut k = open + 1;
    while k < close {
        match &tokens[k] {
            Tok::Punct(',') => arguments.push(Vec::new()),
            Tok::Punct('(' | '[' | '{') => {
                if let Some(last) = arguments.last_mut() {
                    last.push(&tokens[k]);
                }
                k = matched(matches, k).unwrap_or(close);
            }
            tok => {
                if let Some(last) = arguments.last_mut() {
                    last.push(tok);
                }
            }
        }
        k += 1;
    }
    for argument in &arguments {
        if let [Tok::Str { text, .. }] = argument.as_slice() {
            if CODE_FROM_STRING_NAMES.contains(&text.as_str()) {
                findings.add(
                    CodeKind::Unreadable,
                    format!("`{}` reached by its name", printable(text, 40)),
                );
            }
            if let Some(kind) = member_kind(text, &[]) {
                findings.add(
                    kind,
                    format!("Reflect.{method}(..., \"{}\")", printable(text, 60)),
                );
            }
        }
    }
    let named = arguments
        .get(1)
        .is_some_and(|argument| matches!(argument.as_slice(), [Tok::Str { plain: true, .. }]));
    if method == "get" && !named && called_after(tokens, close) {
        findings.add(CodeKind::Unreadable, "a method named at run time".into());
    }
}

/// The text of every string, template, regular expression and comment, read
/// again for a call written out inside it (`a.b.delete(`): where the reading
/// above and JavaScript's own could part (a `/` read as a division where it
/// starts a regular expression), the call is not lost. One found is a
/// review: what runs depends on how the script is read.
fn hidden_calls(src: &[char], bodies: &[(usize, usize)], findings: &mut Findings) {
    let starts_name = |c: char| c.is_alphabetic() || c == '_' || c == '$';
    let in_name = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    for &(start, end) in bodies {
        let body = &src[start.min(src.len())..end.min(src.len())];
        let mut k = 0;
        while k < body.len() {
            if !starts_name(body[k]) || (k > 0 && in_name(body[k - 1])) {
                k += 1;
                continue;
            }
            let mut parts: Vec<String> = Vec::new();
            let mut j = k;
            loop {
                let from = j;
                while j < body.len() && in_name(body[j]) {
                    j += 1;
                }
                parts.push(body[from..j].iter().collect());
                let dot = match (body.get(j), body.get(j + 1)) {
                    (Some('.'), _) => 1,
                    (Some('?'), Some('.')) => 2,
                    _ => 0,
                };
                if dot > 0 && body.get(j + dot).is_some_and(|c| starts_name(*c)) {
                    j += dot;
                } else {
                    break;
                }
            }
            let mut p = j;
            while body.get(p).is_some_and(|c| c.is_whitespace()) {
                p += 1;
            }
            if parts.len() >= 2 && body.get(p) == Some(&'(') {
                if let Some(name) = parts.pop() {
                    if member_kind(&name, &parts).is_some() {
                        parts.push(name);
                        findings.add(
                            CodeKind::Unreadable,
                            format!(
                                "a call written inside a string, regular expression or comment: `{}`",
                                printable(&parts.join("."), 80)
                            ),
                        );
                    }
                }
            }
            k = j.max(k + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(script: &str) -> Vec<CodeKind> {
        read_script(script).into_iter().map(|f| f.kind).collect()
    }

    /// Ten scripts that only read, in the shapes code-mode servers take:
    /// each is allowed (no finding).
    pub(crate) const READS: &[&str] = &[
        "async () => {\n  const zones = await cloudflare.zones.list();\n  return zones.result.map((z) => z.name);\n}",
        "async () => cloudflare.request({ method: \"GET\", path: `/zones/${zoneId}/dns_records` })",
        "async () => cloudflare.request({ method: \"GET\", path: \"/zones/\" + zoneId + \"/dns_records\" })",
        "async () => {\n  const r = await cloudflare.dns.records.list({ zone_id: \"z1\" });\n  return r.result.filter((x) => x.type === \"A\").length;\n}",
        "async () => (await cloudflare.workers.scripts.get(\"edge\", { account_id: \"a1\" })).etag",
        "async () => { const { result } = await cloudflare.accounts.list(); return result[0]?.id; }",
        "async () => cloudflare.request({ path: \"/user/tokens/verify\" })",
        "async () => {\n  const out = [];\n  for await (const z of cloudflare.zones.list({ per_page: 50 })) out.push(z.id);\n  return JSON.stringify(out);\n}",
        "const res = await octokit.request(\"GET /repos/{owner}/{repo}/issues\", { owner: \"o\", repo: \"r\" });\nreturn res.data.map(i => i.title);",
        "async () => { const seen = new Map(); seen.set(\"a\", 1); const s = new Set([1]); s.add(2); return [...seen.keys(), s.size]; }",
        "// list the analytics, no change\nasync () => (await cloudflare.analytics.query({ zone: \"z\", since: -60 })).totals.requests.all / 2",
    ];

    #[test]
    fn scripts_that_only_read_are_allowed() {
        for script in READS {
            assert_eq!(read_script(script), Vec::new(), "{script}");
        }
    }

    /// FAILS ON REVERT: without the reader every one is allowed.
    #[test]
    fn destructive_and_credential_calls_are_found() {
        let cases: &[(&str, CodeKind)] = &[
            ("await cloudflare.zones.delete({ zone_id: \"z\" })", CodeKind::Destructive),
            ("cloudflare.cache.purge({ zone_id: \"z\", purge_everything: true })", CodeKind::Destructive),
            ("await cloudflare.dns.records.delete(\"r\", { zone_id: \"z\" })", CodeKind::Destructive),
            ("await cloudflare.dns.records.update(\"r\", { zone_id: \"z\", content: \"1.2.3.4\" })", CodeKind::Change),
            ("await cloudflare.user.tokens.create({ name: \"ci\" })", CodeKind::Credential),
            ("await cloudflare.workers.scripts.update(\"edge\", { account_id: \"a\" })", CodeKind::Change),
            ("cloudflare.request({ method: \"DELETE\", path: \"/zones/z\" })", CodeKind::Destructive),
            ("cloudflare.request({ method: \"post\", path: \"/user/tokens\" })", CodeKind::Credential),
            ("octokit.request(\"DELETE /repos/{owner}/{repo}\", { owner: \"o\", repo: \"r\" })", CodeKind::Destructive),
            ("await stripe.customers.del(\"cus_1\")", CodeKind::Destructive),
            ("await s3.send(new DeleteObjectCommand({ Bucket: \"b\", Key: \"k\" }))", CodeKind::Destructive),
            ("await iam.send(new CreateAccessKeyCommand({ UserName: \"u\" }))", CodeKind::Credential),
            ("await env.DB.prepare(\"DROP TABLE users\").run()", CodeKind::Destructive),
            ("await env.DB.prepare(\"update users set admin = 1\").run()", CodeKind::Change),
            // Taken out of the object first, or under another name.
            ("const { purge } = cloudflare.cache; await purge({ zone_id: \"z\" })", CodeKind::Destructive),
            ("const { delete: d } = cloudflare.zones; await d({ zone_id: \"z\" })", CodeKind::Destructive),
            ("const del = cloudflare.zones.delete; await del({ zone_id: \"z\" })", CodeKind::Destructive),
            ("await cloudflare.zones[\"delete\"]({ zone_id: \"z\" })", CodeKind::Destructive),
            ("await cloudflare?.zones?.[\"delete\"]?.({ zone_id: \"z\" })", CodeKind::Destructive),
            ("await client.tokens().create({})", CodeKind::Credential),
            ("await cloudflare.zones.list().then(() => cloudflare.zones.delete({ zone_id: \"z\" }))", CodeKind::Destructive),
            // Inside a template's substitution.
            ("`${await cloudflare.zones.delete({ zone_id: \"z\" })}`", CodeKind::Destructive),
        ];
        for (script, kind) in cases {
            assert!(
                kinds(script).contains(kind),
                "{script}: {:?}",
                read_script(script)
            );
        }
    }

    /// FAILS ON REVERT: a script whose calls are decided when it runs is a
    /// review, never an allow.
    #[test]
    fn what_cannot_be_read_is_a_review() {
        for script in [
            "eval(atob(\"Y2xvdWRmbGFyZS56b25lcy5kZWxldGUoKQ==\"))",
            "new Function(\"return cloudflare.zones\")()",
            "Function(src)()",
            "const m = await import(url); await m.run()",
            "const verb = \"del\" + \"ete\"; await cloudflare.zones[verb]({ zone_id: \"z\" })",
            "await cloudflare.zones[`${\"del\"}ete`]({})",
            "await cloudflare.zones[\"\\x64elete\"]({})",
            "await cloudflare.zones[verb].call(cloudflare.zones, {})",
            "await cloudflare.request({ method: m, path: \"/zones/z\" })",
            "await cloudflare.request({ method: `${m}`, path: \"/zones/z\" })",
            "await cloudflare.zones.\\u0064elete({})",
            "setTimeout(\"cloudflare.zones.delete({})\", 0)",
            "const x = require(name)",
            "await cloudflare.zones.list(\"unclosed)",
            "/* never closed",
        ] {
            assert!(
                kinds(script).contains(&CodeKind::Unreadable),
                "{script}: {:?}",
                read_script(script)
            );
        }
    }

    #[test]
    fn tools_and_arguments_come_from_the_tables() {
        let script = serde_json::json!({"code": "await cloudflare.zones.delete({})"});
        for tool in [
            "execute",
            "mcp__cloudflare__execute",
            "mcp__anything__run_code",
            "eval",
        ] {
            assert!(read_code_call(tool, &script).is_some(), "{tool}");
        }
        // A tool that runs more than one language is read when an argument
        // says JavaScript (Hermes's `execute_code` runs Python).
        assert!(read_code_call("mcp__x__execute-code", &script).is_none());
        let named = serde_json::json!({"code": "await cloudflare.zones.delete({})", "lang": "js"});
        assert!(read_code_call("mcp__x__execute-code", &named).is_some());
        for tool in [
            "search",
            "mcp__cloudflare__search",
            "execute_command",
            "bash",
            "list_zones",
        ] {
            assert!(read_code_call(tool, &script).is_none(), "{tool}");
        }
        // The server's name does not decide.
        let other = read_code_call("mcp__my-own-api__execute", &script).unwrap();
        assert_eq!(other.findings.len(), 1);
        // Another language is not read here.
        let python = serde_json::json!({"code": "client.zones.delete()", "language": "python"});
        assert!(read_code_call("run_code", &python).is_none());
        let typescript =
            serde_json::json!({"script": "await api.zones.delete()", "language": "TypeScript"});
        assert_eq!(
            read_code_call("run_code", &typescript)
                .unwrap()
                .findings
                .len(),
            1
        );
        // A script that is not a string is not read.
        let listed = serde_json::json!({"code": ["cloudflare.zones.delete()"]});
        assert_eq!(
            read_code_call("execute", &listed).unwrap().findings[0].kind,
            CodeKind::Unreadable
        );
    }

    /// The hook's verdict: a review for a script that changes, none for one
    /// that only reads.
    #[test]
    fn the_hook_verdict_is_a_review() {
        let payload = |code: &str| {
            serde_json::json!({
                "hook_event_name": "PreToolUse",
                "tool_name": "mcp__cloudflare__execute",
                "tool_input": {"code": code},
            })
        };
        let (command, verdict) =
            hook_verdict(&payload("await cloudflare.cache.purge({})")).unwrap();
        assert_eq!(command, "await cloudflare.cache.purge({})");
        assert_eq!(verdict["recommendation"], "review");
        assert!(!crate::posture::verdict_is_high_certainty(&verdict));
        assert!(verdict["explanation"]
            .as_str()
            .unwrap()
            .contains("cloudflare.cache.purge"));
        for read in READS {
            assert!(hook_verdict(&payload(read)).is_none(), "{read}");
        }
    }

    /// The proxy's verdict: a refusal under `AG-CODE-MODE` beside the
    /// verdict on the arguments, none for a script that only reads.
    #[test]
    fn the_proxy_verdict_refuses_with_its_rule() {
        let verdict = crate::mcp::inspect_tool_call(
            "execute",
            &serde_json::json!({"code": "await cloudflare.zones.delete({ zone_id: \"z\" })"}),
            None,
        );
        assert!(!verdict.allowed);
        assert!(verdict
            .alerts
            .iter()
            .any(|alert| alert.rule == CODE_MODE_RULE && alert.block));
        for read in READS {
            let verdict = crate::mcp::inspect_tool_call(
                "execute",
                &serde_json::json!({ "code": read }),
                None,
            );
            assert!(
                verdict
                    .alerts
                    .iter()
                    .all(|alert| alert.rule != CODE_MODE_RULE),
                "{read}"
            );
        }
    }

    /// Hermes Agent's `execute_code` runs Python and names no language: not
    /// read here (its hook judges it as a `python3 -c` line). A script handed
    /// with no language that starts as another language's does is not read
    /// either; a `#!` line that names Node is.
    #[test]
    fn python_and_shell_scripts_are_not_read_as_javascript() {
        for code in [
            "import json\n# list what's there\nprint(json.dumps(sorted(os.listdir('.'))))",
            "import pandas as pd\ndf = pd.DataFrame(rows).reset_index()\nprint(df.head())",
            "d = {}\nd.update(a=1)\nprint(d)",
        ] {
            let call = serde_json::json!({ "code": code });
            assert!(read_code_call("execute_code", &call).is_none(), "{code}");
        }
        let named =
            serde_json::json!({"code": "await api.zones.delete({})", "language": "javascript"});
        assert_eq!(
            read_code_call("execute_code", &named)
                .unwrap()
                .findings
                .len(),
            1
        );
        for code in [
            "# clean the build\nrm -rf build && echo \"it's done\"",
            "#!/bin/bash\ncurl -X DELETE https://example.invalid/x",
            "  #!/usr/bin/env python3\nos.remove(p)",
        ] {
            let call = serde_json::json!({ "code": code });
            let reading = read_code_call("execute", &call).unwrap();
            assert!(
                reading.findings.is_empty(),
                "{code}: {:?}",
                reading.findings
            );
        }
        let node =
            serde_json::json!({"code": "#!/usr/bin/env node\nawait cloudflare.zones.delete({})"});
        assert_eq!(
            read_code_call("execute", &node).unwrap().findings[0].kind,
            CodeKind::Destructive
        );
    }

    /// Methods of values that live in the script change nothing outside it.
    #[test]
    fn built_in_values_are_not_the_api() {
        for script in [
            "const m = new Map(); m.set(\"a\", 1); m.delete(\"a\"); return m.size;",
            "const q = new URLSearchParams(s); q.delete(\"a\"); return q.toString();",
            "const h = new Headers({ a: \"1\" }); h.delete(\"a\"); return [...h];",
            "const f = new FormData(); f.delete(\"a\");",
            "const u = new URL(href); u.searchParams.delete(\"utm\"); return u.href;",
            "new URL(href).searchParams.delete(\"utm\")",
            "const o = Object.create(null); o.x = 1; return o;",
            "Reflect.deleteProperty(o, \"x\")",
            "const sum = crypto.createHash(\"sha256\").update(body).digest(\"hex\");",
            "const mac = require(\"crypto\").createHmac(\"sha256\", k).update(body).digest(\"hex\");",
            "const rest = [1, 2, 3].values().drop(1).toArray();",
            "const e = document.querySelector(\"#banner\"); e.remove();",
            "document.getElementById(\"x\").remove()",
            "const e = document.createElement(\"p\"); e.classList.remove(\"hidden\");",
        ] {
            assert_eq!(read_script(script), Vec::new(), "{script}");
        }
        // The same names on the API still count.
        for script in [
            "const z = cloudflare.zones; await z.delete({})",
            "await cloudflare.zones.drop()",
            "await api.headers.delete(\"x\")",
        ] {
            assert!(!read_script(script).is_empty(), "{script}");
        }
    }

    /// FAILS ON REVERT: each of these destroyed and was read as nothing.
    #[test]
    fn methods_templates_escapes_and_dynamic_code_are_found() {
        let cases: &[(&str, CodeKind)] = &[
            ("const method = \"delete\"; await fetch(u, { method })", CodeKind::Destructive),
            ("await fetch(u, { \"method\": \"delete\" })", CodeKind::Destructive),
            ("const m = \"delete\"; await fetch(u, { method: m })", CodeKind::Destructive),
            ("opts.method = \"DELETE\"; await fetch(u, opts)", CodeKind::Destructive),
            ("await octokit.request(`DELETE /repos/${o}/${r}`)", CodeKind::Destructive),
            ("await env.DB.prepare(`DELETE FROM users WHERE id=${id}`).run()", CodeKind::Destructive),
            ("await octokit.request(\"\\x44ELETE /repos/o/r\")", CodeKind::Destructive),
            ("await octokit.request(\"\\u{44}ELETE /repos/o/r\")", CodeKind::Destructive),
            ("await octokit.request(\"\\104ELETE /repos/o/r\")", CodeKind::Destructive),
            ("await cloudflare.request({ method: \"\\u0044ELETE\", path: \"/zones/z\" })", CodeKind::Destructive),
            ("(0, eval)(\"cloudflare.zones.delete({})\")", CodeKind::Unreadable),
            ("(async () => {}).constructor(\"return 1\")()", CodeKind::Unreadable),
            ("const F = (async () => {}).constructor; await F(s)()", CodeKind::Unreadable),
            ("globalThis.eval(s)", CodeKind::Unreadable),
            ("globalThis[\"eval\"](s)", CodeKind::Unreadable),
            ("const { eval: e } = globalThis; e(s)", CodeKind::Unreadable),
            ("Reflect.get(cloudflare.zones, \"delete\").call(cloudflare.zones, { zone_id: \"z\" })", CodeKind::Destructive),
            ("Reflect.get(cloudflare.zones, name).call(cloudflare.zones, {})", CodeKind::Unreadable),
            ("const { [\"delete\"]: f } = cloudflare.zones; await f({ zone_id: \"z\" })", CodeKind::Destructive),
            ("const { [verb]: f } = cloudflare.zones; await f({})", CodeKind::Unreadable),
            ("await env.DB.exec(\"SELECT 1; DROP TABLE users\")", CodeKind::Destructive),
            ("await env.DB.exec(\"DROP  TABLE users\")", CodeKind::Destructive),
            ("await env.DB.exec(\"drop\\n\\ttable users\")", CodeKind::Destructive),
            ("await env.DB.exec(\"/* x */ DELETE FROM users\")", CodeKind::Destructive),
            ("await api.request(\"DELETE  /zones/z\")", CodeKind::Destructive),
            ("await api.request(\"DELETE\\t/zones/z\")", CodeKind::Destructive),
            ("await dns.DNSDelete({ id: 1 })", CodeKind::Destructive),
            ("await cloudflare.zones.delete``", CodeKind::Destructive),
        ];
        for (script, kind) in cases {
            assert!(
                kinds(script).contains(kind),
                "{script}: {:?}",
                read_script(script)
            );
        }
        assert_eq!(words("DNSDelete"), ["dns", "delete"]);
        assert_eq!(words("deleteDNSRecord"), ["delete", "dns", "record"]);
    }

    /// FAILS ON REVERT: a `/` the reader took the other way from JavaScript,
    /// or a comment it ended at the wrong place, hid the call after it.
    #[test]
    fn the_reader_keeps_in_step_with_javascript() {
        for script in [
            "let a = 0; a++ /cloudflare.zones.delete({ zone_id: 'z' })/ 1",
            "let a = 0; a-- /cloudflare.zones.delete({ zone_id: 'z' })/ 1",
            "{} /\"/; await cloudflare.zones.delete({ zone_id: 'z' }); //\"",
            "if (1) /\"/; await cloudflare.zones.delete({ zone_id: 'z' }); //\"",
            "while (0) /'/; await cloudflare.zones.delete({ zone_id: 'z' }); //'",
            "res.of /cloudflare.zones.delete()/ 1",
            "x.return /cloudflare.zones.delete()/ 1",
            "`${a}` /cloudflare.zones.delete()/ 1",
            "// x\rawait cloudflare.zones.delete({ zone_id: 'z' })",
            "// x\u{2028}await cloudflare.zones.delete({ zone_id: 'z' })",
            "// x\u{2029}await cloudflare.zones.delete({ zone_id: 'z' })",
            "const note = \"see cloudflare.zones.delete( for this\";",
            "/* cloudflare.cache.purge({}) */",
        ] {
            assert!(!read_script(script).is_empty(), "{script:?}");
        }
        // Read as JavaScript reads them, these hold nothing.
        for script in [
            "const r = /a\\/b/.test(s); return r;",
            "if (ok) /x/.test(s); return 1;",
            "let i = 0; i++; return i / 2;",
            "const s = \"a\\\r\nb\"; return s;",
            "const s = \"a\\\nb\"; return s;",
            "return list.map((x) => x.id) // the ids\r\n",
        ] {
            assert_eq!(read_script(script), Vec::new(), "{script:?}");
        }
    }

    /// FAILS ON REVERT (the brackets were matched again for each one): a
    /// script built of brackets, as large as is read, reads in linear time.
    #[test]
    fn a_built_script_reads_in_linear_time() {
        let n = MAX_SCRIPT_BYTES;
        let shapes = [
            "{".repeat(n),
            format!("{}{}", "{".repeat(n / 2), "}".repeat(n / 2)),
            format!("const {} = x", "{a = ".repeat(n / 6)),
            format!("x{}.b.c.d", "()".repeat(n / 2 - 4)),
            format!("x{}", "[".repeat(n - 1)),
            format!("x{}", ".a()".repeat(n / 4 - 1)),
            "Reflect.get(".repeat(n / 12),
            format!("\"{}\"", "a.b.c(".repeat(n / 6 - 1)),
        ];
        for shape in &shapes {
            assert!(shape.len() <= n);
            let started = std::time::Instant::now();
            let _ = read_script(shape);
            let took = started.elapsed();
            assert!(
                took < std::time::Duration::from_secs(2),
                "{} bytes starting {:?}: {took:?}",
                shape.len(),
                &shape[..20]
            );
        }
    }

    /// The hook's verdict names a long script by its start, its size and
    /// its hash, never whole.
    #[test]
    fn the_hook_verdict_names_a_long_script_by_its_hash() {
        let script = format!(
            "await cloudflare.zones.delete({{}}); {}",
            "x;".repeat(100_000)
        );
        let payload = serde_json::json!({
            "tool_name": "mcp__cloudflare__execute",
            "tool_input": {"code": script},
        });
        let (command, verdict) = hook_verdict(&payload).unwrap();
        assert!(command.len() < 2_000, "{}", command.len());
        assert!(command.contains("sha256:"));
        assert_eq!(verdict["command"], command);
    }
}
