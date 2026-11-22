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
    "execute_code",
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    let last = tool_name.rsplit("__").next().unwrap_or(tool_name);
    CODE_TOOLS.contains(&canonical(last).as_str())
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
    if let Some(language) = language {
        if !SCRIPT_LANGUAGES.contains(&language.trim().to_ascii_lowercase().as_str()) {
            return None;
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
    let mut findings: Vec<CodeFinding> = Vec::new();
    let mut shown = String::new();
    for value in scripts {
        match value {
            Value::String(script) => {
                if shown.is_empty() {
                    shown.clone_from(script);
                }
                for finding in read_script(script) {
                    if !findings.contains(&finding) {
                        findings.push(finding);
                    }
                }
            }
            Value::Null => {}
            _ => findings.push(CodeFinding {
                kind: CodeKind::Unreadable,
                what: "the script is not a string".into(),
            }),
        }
    }
    Some(CodeReading {
        tool: tool_name.to_string(),
        script: shown,
        findings,
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
        reading.script.trim().to_string()
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
    /// A string or template literal. `plain`: written out whole, with no
    /// substitution and no escape that hides a character (`\x`, `\u`).
    Str {
        text: String,
        plain: bool,
    },
    Num,
    Punct(char),
    /// `?.`
    OptChain,
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

fn regex_may_start(tokens: &[Tok]) -> bool {
    match tokens.last() {
        None | Some(Tok::OptChain) => true,
        Some(Tok::Punct(c)) => !matches!(c, ')' | ']' | '}'),
        Some(Tok::Ident(word)) => REGEX_AFTER_WORDS.contains(&word.as_str()),
        _ => false,
    }
}

/// The escape after a backslash in a string or template, at `*i`: the
/// character it stands for, or `None` for one that hides a character.
fn escaped(src: &[char], i: &mut usize) -> Result<Option<char>, Unsplit> {
    let Some(&e) = src.get(*i) else {
        return Err(Unsplit("a string is not closed"));
    };
    *i += 1;
    Ok(match e {
        'x' | 'u' | '0'..='9' => None,
        'n' => Some('\n'),
        't' => Some('\t'),
        other => Some(other),
    })
}

/// Split `src` from `*i` into `tokens`. In a substitution of a template
/// (`in_substitution`), stop after the `}` that closes it.
fn scan(
    src: &[char],
    i: &mut usize,
    tokens: &mut Vec<Tok>,
    in_substitution: bool,
    depth: usize,
) -> Result<(), Unsplit> {
    if depth > 32 {
        return Err(Unsplit("templates nested too deep"));
    }
    let mut braces = 0usize;
    while *i < src.len() {
        let c = src[*i];
        let next = src.get(*i + 1).copied();
        if c.is_whitespace() {
            *i += 1;
            continue;
        }
        if c == '/' && next == Some('/') {
            while *i < src.len() && src[*i] != '\n' {
                *i += 1;
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            *i += 2;
            loop {
                if *i + 1 >= src.len() {
                    return Err(Unsplit("a comment is not closed"));
                }
                if src[*i] == '*' && src[*i + 1] == '/' {
                    *i += 2;
                    break;
                }
                *i += 1;
            }
            continue;
        }
        if c == '/' && regex_may_start(tokens) {
            *i += 1;
            let mut class = false;
            loop {
                let Some(&r) = src.get(*i) else {
                    return Err(Unsplit("a regular expression is not closed"));
                };
                *i += 1;
                match r {
                    '\\' => *i += 1,
                    '[' => class = true,
                    ']' => class = false,
                    '/' if !class => break,
                    '\n' => return Err(Unsplit("a regular expression is not closed")),
                    _ => {}
                }
            }
            while src.get(*i).is_some_and(|f| f.is_ascii_alphabetic()) {
                *i += 1;
            }
            tokens.push(Tok::Str {
                text: String::new(),
                plain: true,
            });
            continue;
        }
        if c == '"' || c == '\'' {
            *i += 1;
            let mut text = String::new();
            let mut plain = true;
            loop {
                let Some(&s) = src.get(*i) else {
                    return Err(Unsplit("a string is not closed"));
                };
                *i += 1;
                if s == c {
                    break;
                }
                match s {
                    '\\' => match escaped(src, i)? {
                        Some('\n') if src.get(*i - 1) == Some(&'\n') => {}
                        Some(ch) => text.push(ch),
                        None => plain = false,
                    },
                    '\n' => return Err(Unsplit("a string is not closed")),
                    other => text.push(other),
                }
            }
            tokens.push(Tok::Str { text, plain });
            continue;
        }
        if c == '`' {
            *i += 1;
            let mut text = String::new();
            let mut plain = true;
            let mut inner = Vec::new();
            loop {
                let Some(&s) = src.get(*i) else {
                    return Err(Unsplit("a template is not closed"));
                };
                *i += 1;
                match s {
                    '`' => break,
                    '\\' => match escaped(src, i)? {
                        Some(ch) => text.push(ch),
                        None => plain = false,
                    },
                    '$' if src.get(*i) == Some(&'{') => {
                        *i += 1;
                        plain = false;
                        scan(src, i, &mut inner, true, depth + 1)?;
                    }
                    other => text.push(other),
                }
            }
            tokens.push(Tok::Str { text, plain });
            tokens.extend(inner);
            continue;
        }
        if c == '\\' {
            return Err(Unsplit("an escape in a name"));
        }
        if c.is_alphabetic() || c == '_' || c == '$' {
            let start = *i;
            while src
                .get(*i)
                .is_some_and(|w| w.is_alphanumeric() || *w == '_' || *w == '$')
            {
                *i += 1;
            }
            if src.get(*i) == Some(&'\\') {
                return Err(Unsplit("an escape in a name"));
            }
            tokens.push(Tok::Ident(src[start..*i].iter().collect()));
            continue;
        }
        if c.is_ascii_digit() || (c == '.' && next.is_some_and(|n| n.is_ascii_digit())) {
            while src
                .get(*i)
                .is_some_and(|w| w.is_ascii_alphanumeric() || *w == '.' || *w == '_')
            {
                *i += 1;
            }
            tokens.push(Tok::Num);
            continue;
        }
        if c == '?' && next == Some('.') && !src.get(*i + 2).is_some_and(|d| d.is_ascii_digit()) {
            *i += 2;
            tokens.push(Tok::OptChain);
            continue;
        }
        *i += 1;
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
        tokens.push(Tok::Punct(c));
    }
    if in_substitution {
        return Err(Unsplit("a template is not closed"));
    }
    Ok(())
}

/// The words of a name: split at `_`, digits and a lower-to-upper case
/// change, lower case (`deleteDnsRecord` is `delete dns record`).
fn words(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut previous_lower = false;
    for c in name.chars() {
        if !c.is_alphabetic() {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            previous_lower = false;
            continue;
        }
        if c.is_uppercase() && previous_lower && !word.is_empty() {
            out.push(std::mem::take(&mut word));
        }
        previous_lower = c.is_lowercase();
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

/// The pair of a bracket character.
fn pair(c: char) -> Option<(char, char)> {
    match c {
        '(' | ')' => Some(('(', ')')),
        '[' | ']' => Some(('[', ']')),
        '{' | '}' => Some(('{', '}')),
        _ => None,
    }
}

/// The index of the token that opens the group closed at `close`.
fn opening(tokens: &[Tok], close: usize) -> Option<usize> {
    let Some(Tok::Punct(c)) = tokens.get(close) else {
        return None;
    };
    let (open_c, close_c) = pair(*c)?;
    let mut depth = 0usize;
    let mut k = close;
    loop {
        match &tokens[k] {
            Tok::Punct(t) if *t == close_c => depth += 1,
            Tok::Punct(t) if *t == open_c => {
                depth -= 1;
                if depth == 0 {
                    return Some(k);
                }
            }
            _ => {}
        }
        k = k.checked_sub(1)?;
    }
}

/// The index of the token that closes the group opened at `open`.
fn closing(tokens: &[Tok], open: usize) -> Option<usize> {
    let Some(Tok::Punct(c)) = tokens.get(open) else {
        return None;
    };
    let (open_c, close_c) = pair(*c)?;
    let mut depth = 0usize;
    for (k, tok) in tokens.iter().enumerate().skip(open) {
        match tok {
            Tok::Punct(t) if *t == open_c => depth += 1,
            Tok::Punct(t) if *t == close_c => {
                depth -= 1;
                if depth == 0 {
                    return Some(k);
                }
            }
            _ => {}
        }
    }
    None
}

/// The names before a member, root first (`cloudflare.user.tokens` for
/// `create`). `access` is the index of the member's own dot or `[`.
fn chain_before(tokens: &[Tok], access: usize) -> Vec<String> {
    let mut chain = Vec::new();
    let mut k = access;
    for _ in 0..32 {
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
            let Some(e) = opening(tokens, end).and_then(|open| open.checked_sub(1)) else {
                chain.reverse();
                return chain;
            };
            end = e;
        }
        match tokens.get(end) {
            Some(Tok::Ident(name)) => {
                chain.push(name.clone());
                match end.checked_sub(1) {
                    Some(dot) if is_dot(tokens.get(dot)) => k = dot,
                    _ => break,
                }
            }
            Some(Tok::Punct(']')) => {
                let Some(open) = opening(tokens, end) else {
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
    chain
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
/// `.call(`, `.apply(`, `.bind(`).
fn called_after(tokens: &[Tok], at: usize) -> bool {
    match tokens.get(at + 1) {
        Some(Tok::Punct('(')) => true,
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
/// (`"DELETE"`, `"PUT /zones/x"`): what it does.
fn request_line_kind(text: &str) -> Option<CodeKind> {
    let first = text.split(' ').next().unwrap_or("");
    if first.is_empty() || first != first.to_ascii_uppercase() {
        return None;
    }
    let rest = &text[first.len()..];
    if !rest.is_empty() && !rest.starts_with(" /") && !rest.starts_with(" http") {
        return None;
    }
    http_method_kind(first).flatten()
}

/// A string that is an SQL statement that changes or destroys: what it does.
fn sql_kind(text: &str) -> Option<CodeKind> {
    let lower = text.trim_start().to_ascii_lowercase();
    if let Some((_, destroys)) = SQL_STATEMENTS.iter().find(|(s, _)| lower.starts_with(s)) {
        return Some(if *destroys {
            CodeKind::Destructive
        } else {
            CodeKind::Change
        });
    }
    // `UPDATE <table> SET`
    let mut parts = lower.split_whitespace();
    if parts.next() == Some("update") && parts.nth(1) == Some("set") {
        return Some(CodeKind::Change);
    }
    None
}

/// The keys of every destructuring pattern (`const { purge } = cache`), by
/// token index: each is a member taken out of an object.
fn destructured_keys(tokens: &[Tok]) -> Vec<bool> {
    let mut keys = vec![false; tokens.len()];
    for (open, tok) in tokens.iter().enumerate() {
        if *tok != Tok::Punct('{') {
            continue;
        }
        let Some(close) = closing(tokens, open) else {
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
        for k in open + 1..close {
            // A key: followed by one of `: , } =` and not itself a value.
            let key_position = matches!(tokens.get(k + 1), Some(Tok::Punct(':' | ',' | '}' | '=')))
                && !matches!(tokens.get(k - 1), Some(Tok::Punct(':')));
            if key_position && matches!(tokens[k], Tok::Ident(_) | Tok::Str { .. }) {
                keys[k] = true;
            }
        }
    }
    keys
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

/// What a bare name followed by `(` runs that cannot be read, if anything.
fn unreadable_call(tokens: &[Tok], at: usize, name: &str) -> Option<String> {
    let previous = at.checked_sub(1).and_then(|p| tokens.get(p));
    let called = matches!(tokens.get(at + 1), Some(Tok::Punct('(')));
    match name {
        "eval" if called => Some("`eval` of a string".into()),
        "Function" if called || matches!(previous, Some(Tok::Ident(w)) if w == "new") => {
            Some("code built by `Function`".into())
        }
        "import" if called => Some("a dynamic `import`".into()),
        "require"
            if called
                && !matches!(
                    (tokens.get(at + 2), tokens.get(at + 3)),
                    (Some(Tok::Str { plain: true, .. }), Some(Tok::Punct(')')))
                ) =>
        {
            Some("a `require` of a name made at run time".into())
        }
        "setTimeout" | "setInterval" | "setImmediate"
            if called && matches!(tokens.get(at + 2), Some(Tok::Str { .. })) =>
        {
            Some(format!("`{name}` of a string"))
        }
        "with" if called => Some("a `with` block".into()),
        _ => None,
    }
}

/// The calls a script makes that change or destroy, and what in it cannot be
/// read. Empty for a script that only reads.
pub fn read_script(script: &str) -> Vec<CodeFinding> {
    let mut findings: Vec<CodeFinding> = Vec::new();
    let mut add = |kind: CodeKind, what: String| {
        let finding = CodeFinding { kind, what };
        if !findings.contains(&finding) {
            findings.push(finding);
        }
    };
    if script.len() > MAX_SCRIPT_BYTES {
        add(
            CodeKind::Unreadable,
            format!(
                "the script is {} bytes, more than the {MAX_SCRIPT_BYTES} the guard reads",
                script.len()
            ),
        );
        return findings;
    }
    let src: Vec<char> = script.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    if let Err(Unsplit(why)) = scan(&src, &mut i, &mut tokens, false, 0) {
        add(
            CodeKind::Unreadable,
            format!("the script cannot be read: {why}"),
        );
        return findings;
    }
    let destructured = destructured_keys(&tokens);
    let credential_path = names_a_credential_path(&tokens);
    // A request's method or line: a credential when the script names a
    // credential's path.
    let request = |kind: CodeKind| {
        if credential_path {
            CodeKind::Credential
        } else {
            kind
        }
    };

    for (at, tok) in tokens.iter().enumerate() {
        let member = is_dot(at.checked_sub(1).and_then(|p| tokens.get(p)));
        match tok {
            Tok::Ident(name) => {
                if !member {
                    if let Some(what) = unreadable_call(&tokens, at, name) {
                        add(CodeKind::Unreadable, what);
                        continue;
                    }
                    if name == "method" && matches!(tokens.get(at + 1), Some(Tok::Punct(':'))) {
                        match tokens.get(at + 2) {
                            Some(Tok::Str { text, plain: true }) => {
                                if let Some(Some(kind)) = http_method_kind(text) {
                                    add(
                                        request(kind),
                                        format!(
                                            "an HTTP {} request",
                                            text.trim().to_ascii_uppercase()
                                        ),
                                    );
                                }
                            }
                            Some(Tok::Ident(word)) if word == "string" => {}
                            _ => add(
                                CodeKind::Unreadable,
                                "an HTTP method chosen at run time".into(),
                            ),
                        }
                        continue;
                    }
                }
                // A command object built by name (`new DeleteObjectCommand(...)`,
                // the AWS SDK's shape) is the call it is sent as.
                let constructed = !member
                    && matches!(at.checked_sub(1).and_then(|p| tokens.get(p)), Some(Tok::Ident(w)) if w == "new");
                if member || destructured[at] || constructed {
                    let mut chain = if member {
                        chain_before(&tokens, at - 1)
                    } else {
                        Vec::new()
                    };
                    if let Some(kind) = member_kind(name, &chain) {
                        chain.push(name.clone());
                        add(kind, printable(&chain.join("."), 80));
                    }
                }
            }
            Tok::Str { text, plain } => {
                if destructured[at] {
                    if !plain {
                        add(CodeKind::Unreadable, "a member named at run time".into());
                    } else if let Some(kind) = member_kind(text, &[]) {
                        add(kind, printable(text, 80));
                    }
                }
                if *plain {
                    if let Some(kind) = request_line_kind(text) {
                        add(
                            request(kind),
                            format!("an HTTP request `{}`", printable(text, 80)),
                        );
                    } else if let Some(kind) = sql_kind(text) {
                        add(kind, format!("the SQL `{}`", printable(text, 80)));
                    }
                }
            }
            Tok::Punct('[') if accessed_before(&tokens, at) => {
                let Some(close) = closing(&tokens, at) else {
                    continue;
                };
                match &tokens[at + 1..close] {
                    [Tok::Str { text, plain: true }] => {
                        let mut chain = chain_before(&tokens, at);
                        if let Some(kind) = member_kind(text, &chain) {
                            chain.push(text.clone());
                            add(kind, printable(&chain.join("."), 80));
                        }
                    }
                    _ if called_after(&tokens, close) => {
                        add(CodeKind::Unreadable, "a method named at run time".into());
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    findings
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
            "mcp__x__execute-code",
        ] {
            assert!(read_code_call(tool, &script).is_some(), "{tool}");
        }
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
}
