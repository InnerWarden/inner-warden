//! What crosses the proxy as content rather than as a call.
//!
//! Two screens live here, both pure:
//!
//! * **Secret-shaped values in what the server sends.** Any server answer
//!   (a `resources/read`, a tool result, a prompt, an error, a notification)
//!   goes into the model's context. A secret the server keeps in its own
//!   memory and hands back in a message has no file read or program run on the
//!   host to refuse: the message is the only place it can be stopped.
//!   [`scan_message`] finds API keys, cloud keys, private key blocks, JWTs,
//!   bearer and basic credentials, passwords written as a key and a value (in
//!   config, prose, a table or markup) or inside a connection string,
//!   flag-like tokens, and any of these written in base64 or hex;
//!   [`mask_message`] replaces each with `[REDACTED]` and leaves every other
//!   byte of the text, the id and the shape of the answer as they were. A
//!   session token a server issues in answer to a call that itself supplied a
//!   credential (a login) is the client's own and stays in place
//!   ([`AnswerContext`]).
//! * **The location a `resources/read` asks for** ([`inspect_resource_read`]):
//!   a path that climbs out of its root, a secret store on disk or a tool's
//!   credential store, a password in the location, the cloud metadata
//!   service, a location that names secret material, and one the server never
//!   announced.
//!
//! False positives are the cost to watch: documentation that names the word
//! password, source code that names a secret in an expression, commit hashes
//! and other high-entropy ids, and images. A value is masked when its shape
//! says secret (a provider prefix, a JWT, a private key header), or when a
//! secret's key names it and the value reads as a literal: not code (a call,
//! an index, an attribute path, a variable), not a placeholder, and, inside a
//! sentence, shaped like a password. Encoded runs are masked only when they
//! decode to text that holds a secret.

use std::collections::{BTreeSet, HashSet};
use std::sync::OnceLock;

use base64::Engine as _;
use regex::Regex;
use serde_json::Value;

use crate::mcp::{self, Verdict, VerdictAlert};
use crate::rules::RuleEngine;

/// What a masked value is replaced with, the same marker the rest of the
/// guard redacts with.
pub(crate) const MASK: &str = "[REDACTED]";

/// The rule a secret-shaped value in a server answer is reported under.
pub const SECRET_OUT_RULE: &str = "AG-SECRET-OUT";

/// The rule a finding on the location of a `resources/read` is reported
/// under.
pub const RESOURCE_URI_RULE: &str = "AG-RES-URI";

/// A value at least this long, once found to be a secret, is masked wherever
/// else it appears in the same message. Shorter values are too likely to be
/// ordinary words elsewhere.
const MIN_REPEATED_SECRET: usize = 8;

/// The shortest value after a secret's key that is read as one.
const MIN_KEYED_SECRET: usize = 6;

/// How many layers of encoding are looked through: base64 inside base64 is
/// seen, a third layer is not. Each layer is at most three quarters the size
/// of the one around it, so the work stays linear in the size of the answer.
const MAX_DECODE_DEPTH: usize = 2;

/// The kinds of secret-shaped value the server-side screen knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretKind {
    PrivateKey,
    ApiKey,
    CloudKey,
    Jwt,
    BearerToken,
    BasicCredential,
    ConnectionPassword,
    CredentialValue,
    FlagToken,
    EncodedSecret,
}

impl SecretKind {
    /// How the kind is named in an alert. Never the value.
    pub fn label(self) -> &'static str {
        match self {
            SecretKind::PrivateKey => "private key block",
            SecretKind::ApiKey => "API key",
            SecretKind::CloudKey => "cloud access key",
            SecretKind::Jwt => "JWT",
            SecretKind::BearerToken => "bearer token",
            SecretKind::BasicCredential => "basic auth credential",
            SecretKind::ConnectionPassword => "password in a connection string",
            SecretKind::CredentialValue => "credential value",
            SecretKind::FlagToken => "flag-like token",
            SecretKind::EncodedSecret => "secret written in base64 or hex",
        }
    }
}

/// What one screen of a message found: the kinds (for the alert) and the
/// values (so each is masked wherever else it appears in the message).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SecretFindings {
    pub kinds: BTreeSet<SecretKind>,
    values: BTreeSet<String>,
    /// Session tokens the answer issues to the client in exchange for a
    /// credential it supplied ([`AnswerContext`]): left in place.
    kept: BTreeSet<String>,
}

impl SecretFindings {
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    fn found(&mut self, kind: SecretKind, value: &str) {
        self.kinds.insert(kind);
        if value.len() >= MIN_REPEATED_SECRET {
            self.values.insert(value.to_string());
        }
    }

    /// The alert for these findings. `masked` says whether the message was
    /// rewritten (guard and kill) or forwarded as it came (advisory, warn).
    pub fn alert(&self, masked: bool) -> VerdictAlert {
        let kinds: Vec<&str> = self.kinds.iter().map(|kind| kind.label()).collect();
        let what = if masked {
            "each was masked before the client received the answer, so it never reaches the model"
        } else {
            "this mode forwards answers unchanged, so the client received them; \
             guard mode masks them"
        };
        let mut alert = VerdictAlert::builtin(
            SECRET_OUT_RULE,
            format!(
                "the server's answer carried secret-shaped values ({}); {what}",
                kinds.join(", ")
            ),
            false,
        );
        alert.owasp = Some(vec!["ASI07".to_string()]);
        alert
    }
}

/// What the proxy knows about the request a server answer is for.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AnswerContext {
    /// The answer is to a tool call that itself supplied a credential (a
    /// password, a token, a secret): a login, a token refresh. A session token
    /// the answer issues under a session key (`token`, `access_token`,
    /// `session_token`) is the client's own, exchanged for what it already
    /// holds, and must reach it for the next call of the session to work; it
    /// is left in place. Every other secret in that answer is still masked,
    /// and the same token in any other answer is masked.
    pub credential_exchange: bool,
}

/// Whether the arguments of a tool call supply a credential: a non-empty
/// string under a secret's key (`password`, `token`, `client_secret`).
pub fn supplies_credential(arguments: &Value) -> bool {
    arguments.as_object().is_some_and(|args| {
        args.iter().any(|(key, value)| {
            crate::redact::sensitive_key(key)
                && value.as_str().is_some_and(|text| !text.trim().is_empty())
        })
    })
}

// ── patterns ────────────────────────────────────────────────────────────

/// One secret-shaped pattern: where the secret is in a match, what kind it
/// is, and the test the matched value must pass.
struct SecretPattern {
    re: Regex,
    /// The capture group that holds the secret (0 = the whole match).
    value: usize,
    kind: SecretKind,
    accept: fn(&str) -> bool,
}

fn patterns() -> &'static [SecretPattern] {
    static P: OnceLock<Vec<SecretPattern>> = OnceLock::new();
    P.get_or_init(|| {
        let mk = |re: &str, value, kind, accept: fn(&str) -> bool| SecretPattern {
            re: Regex::new(re).expect("static secret regex"),
            value,
            kind,
            accept,
        };
        vec![
            // A private key block, header to footer (or to the end of the text
            // when the footer was cut), so the key material goes with it.
            mk(
                r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----(?s:.*?)(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----|\z)",
                0,
                SecretKind::PrivateKey,
                always,
            ),
            // Cloud access key ids.
            mk(
                r"\b(?:AKIA|ASIA)[0-9A-Z]{16,}",
                0,
                SecretKind::CloudKey,
                always,
            ),
            // An AWS secret access key: 40 characters of base64 after its key
            // (`aws_secret_access_key = `, `secret_key:`, `AWS Secret Key:`), or
            // after an access key id on its line or the next one. Measured
            // 2026-11-20: `AWS Secret Key: wJalr...` reached the client in clear
            // while the key id beside it was masked. Which values count is
            // [`aws_secret_shape`].
            mk(
                r#"(?i)\b(?:aws[ _\-]?)?secret[ _\-]?(?:access[ _\-]?)?key["']?[ \t]*[:=][ \t]*["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|\z)"#,
                1,
                SecretKind::CloudKey,
                aws_secret_shape,
            ),
            mk(
                r"\b(?:AKIA|ASIA)[0-9A-Z]{16,}\b[^\n]{0,200}?(?:\n[^\n]{0,200}?)?[^A-Za-z0-9/+=]([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|\z)",
                1,
                SecretKind::CloudKey,
                aws_secret_shape,
            ),
            // Provider API keys and tokens by their prefix. A real one carries
            // digits; a hyphenated word that happens to start the same way
            // does not.
            mk(
                r"\b(?:sk-[A-Za-z0-9_\-]{16,}|[sr]k_(?:live|test)_[A-Za-z0-9]{10,}|gh[opsur]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_\-]{20,}|xox[abposr]-[A-Za-z0-9\-]{10,}|npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_\-]{35}|SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})",
                0,
                SecretKind::ApiKey,
                has_digit,
            ),
            // A JWT: a JSON header, then either a JSON payload or two more
            // base64url segments.
            mk(
                r"\beyJ[A-Za-z0-9_\-]{6,}\.(?:eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*|[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,})",
                0,
                SecretKind::Jwt,
                always,
            ),
            // A bearer token (the scheme word stays readable).
            mk(
                r"(?i)\bbearer[ \t]+([A-Za-z0-9_.~+/\-]{12,}=*)",
                1,
                SecretKind::BearerToken,
                has_digit,
            ),
            // A basic credential (the scheme word stays readable): base64 of
            // `user:password`.
            mk(
                r"(?i)\bbasic[ \t]+([A-Za-z0-9+/]{8,}={0,2})",
                1,
                SecretKind::BasicCredential,
                user_and_password_b64,
            ),
            // A registry login as a container tool keeps it:
            // `"auth": "<base64 of user:password>"`.
            mk(
                r#"(?i)["']auth["'][ \t]*:[ \t]*["']([A-Za-z0-9+/]{8,}={0,2})["']"#,
                1,
                SecretKind::BasicCredential,
                user_and_password_b64,
            ),
            // The password of a connection string: scheme://user:PASSWORD@host.
            // The password may itself hold an `@`; the host is what follows the
            // last one.
            mk(
                r#"\b[A-Za-z][A-Za-z0-9+.\-]{1,30}://[^\s:/@'"<>]{1,128}:([^\s/'"<>]{1,256})@[^\s/@'"<>]+"#,
                1,
                SecretKind::ConnectionPassword,
                not_placeholder,
            ),
            // A user and password pair after a credentials key, as logs write
            // it: `credentials: admin / x`, `credentials=admin:x`.
            mk(
                r#"(?i)\bcredentials?["']?[ \t]*[:=][ \t]*["']?[^\s"'/:]{1,64}[ \t]*[/:][ \t]*([^\s"'`,;/]{6,})"#,
                1,
                SecretKind::CredentialValue,
                reads_as_a_secret,
            ),
            // A flag-like token: a name, then braces around a value
            // (`NAME{s0me_v4lue}`). Not when the name is a variable or a macro
            // (`$ENV{...}`, `\cmd{...}`); which names count is [`flag_like`].
            mk(
                r"(?:^|[^A-Za-z0-9_$%@#\\{])([A-Za-z][A-Za-z0-9_]{1,23}\{[A-Za-z0-9_\-!@#$%^&*.?+=]{6,100}\})",
                1,
                SecretKind::FlagToken,
                flag_like,
            ),
        ]
    })
}

fn always(_: &str) -> bool {
    true
}

/// An AWS secret access key as it is written: 40 characters of base64 with
/// capitals, small letters and a digit or a `/` or `+`. A word of prose or
/// a run of one case is not one. The documentation's own sample key counts:
/// it is shaped as a real one, and a server that hands it out hands out the
/// shape a real one would take.
fn aws_secret_shape(value: &str) -> bool {
    value.len() == 40
        && value.bytes().any(|b| b.is_ascii_uppercase())
        && value.bytes().any(|b| b.is_ascii_lowercase())
        && value
            .bytes()
            .any(|b| b.is_ascii_digit() || b == b'/' || b == b'+')
}

fn has_digit(value: &str) -> bool {
    value.bytes().any(|b| b.is_ascii_digit())
}

/// A flag-like token `NAME{value}`: the name says flag (`flag`, `ctf`) or is
/// written in capitals (`CTF`, `HTB`, `CTF_FLAG`), whatever the value holds
/// (hex, words, hyphens). A word glued to an interpolated variable in a
/// format string (`chunk{chunk_id}`, `Order{order_id}`) is neither.
fn flag_like(value: &str) -> bool {
    let Some((name, body)) = value.split_once('{') else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    let named = lower.contains("flag") || lower.contains("ctf");
    let letters = name.chars().filter(char::is_ascii_alphabetic).count();
    let capitals = letters >= 2 && !name.chars().any(|c| c.is_ascii_lowercase());
    // A brace-initialized constant (`TIMEOUT_MS{300000}`) holds a number.
    (named || capitals) && body.chars().any(|c| c.is_ascii_alphabetic())
}

/// Base64 that decodes to `user:password`, the form of a basic credential.
fn user_and_password_b64(value: &str) -> bool {
    decoded_text(value).is_some_and(|text| {
        text.len() <= 512
            && !text.chars().any(char::is_whitespace)
            && text
                .split_once(':')
                .is_some_and(|(user, password)| !user.is_empty() && !password.is_empty())
    })
}

/// Not a stand-in for a value: a template, a variable, a mask, an example.
fn not_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.is_empty()
        || lower.starts_with(['<', '$', '%', '{', '[', '(', '*'])
        || lower
            .chars()
            .all(|c| matches!(c, '*' | 'x' | '.' | '#' | '-' | '_' | '?'))
    {
        return false;
    }
    const STAND_INS: &[&str] = &[
        "redacted",
        "placeholder",
        "your",
        "example",
        "process.env",
        "environ",
        "getenv",
        "xxxx",
    ];
    if STAND_INS.iter().any(|word| lower.contains(word)) {
        return false;
    }
    !matches!(
        lower.as_str(),
        "password" | "passwd" | "pass" | "pwd" | "secret" | "token" | "bearer" | "basic"
    )
}

/// A value after a secret's key that reads as one: not a placeholder, not a
/// path or a URL, not punctuation alone (an underline), and not a plain word
/// (a word of prose, `required`, `string`): it has a digit or a symbol, or is
/// long.
fn reads_as_a_secret(value: &str) -> bool {
    if !plausible_value(value) {
        return false;
    }
    let symbol = value
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !matches!(c, '-' | '_' | '.'));
    has_digit(value) || symbol || value.chars().count() >= 12
}

/// Could be a literal value at all: not a placeholder, not a path or a URL,
/// not punctuation alone.
fn plausible_value(value: &str) -> bool {
    not_placeholder(value)
        && !value.contains("://")
        && value.chars().any(|c| c.is_ascii_alphanumeric())
        && !value.starts_with('/')
        && !value.starts_with("./")
        && !value.starts_with("../")
        && !value.starts_with("~/")
}

/// Words that stand where a value is described rather than given: a type,
/// a state, a yes or a no.
fn ordinary_word(value: &str) -> bool {
    const WORDS: &[&str] = &[
        "true",
        "false",
        "null",
        "none",
        "nil",
        "undefined",
        "required",
        "optional",
        "string",
        "hidden",
        "masked",
        "unset",
        "empty",
        "invalid",
        "expired",
        "revoked",
        "missing",
        "provided",
        "supplied",
        "configured",
        "enabled",
        "disabled",
        "default",
        "unknown",
        "sensitive",
        "encrypted",
        "hashed",
        "rotated",
        "generated",
        "changed",
        "updated",
        "integer",
        "number",
        "boolean",
        "object",
        "secretstr",
        "secretbytes",
        "bytes",
        "base64",
        "anonymous",
    ];
    let lower = value.to_ascii_lowercase();
    WORDS.contains(&lower.as_str())
}

/// The character classes a value mixes: lower case, upper case, digits and
/// symbols (whitespace and the joiners `-`, `_`, `.` do not count).
fn char_classes(value: &str) -> usize {
    let lower = value.chars().any(|c| c.is_ascii_lowercase());
    let upper = value.chars().any(|c| c.is_ascii_uppercase());
    let digit = has_digit(value);
    let symbol = value
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace() && !matches!(c, '-' | '_' | '.'));
    [lower, upper, digit, symbol].iter().filter(|&&b| b).count()
}

/// How many runs of digits sit between two letters (`r3d1s` has two), the
/// way a password spells a word. Version numbers and words that end in
/// digits (`base64`, `sha256`, `rotate2026`) have none or one.
fn leet_runs(value: &str) -> usize {
    let chars: Vec<char> = value.chars().collect();
    let mut runs = 0;
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let before = start > 0 && chars[start - 1].is_ascii_alphabetic();
            let after = i < chars.len() && chars[i].is_ascii_alphabetic();
            if before && after {
                runs += 1;
            }
        } else {
            i += 1;
        }
    }
    runs
}

/// Shaped like a password whatever surrounds it: three character classes,
/// or a word spelled with digits.
fn strong_secret(value: &str) -> bool {
    value.chars().count() >= 8 && (char_classes(value) >= 3 || leet_runs(value) >= 2)
}

/// Keys whose value is a token that is not a credential: paging and progress
/// handles a server hands back so the client can continue.
fn non_secret_token_key(normalized: &str) -> bool {
    const HANDLES: &[&str] = &[
        "pagetoken",
        "cursortoken",
        "continuationtoken",
        "synctoken",
        "progresstoken",
        "resumetoken",
        "nexttoken",
    ];
    HANDLES.iter().any(|handle| normalized.ends_with(handle))
}

fn normalized_key(key: &str) -> String {
    key.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

// ── a secret written as a key and a value ───────────────────────────────

/// How a value was given to its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Assign {
    /// `key = value`, `key := value`, `key=value` with a key in lower case:
    /// how code assigns a variable or passes an argument.
    Equals,
    /// `KEY=value` with no spaces and a key in capitals: an env file.
    EnvFile,
    /// `key: value`, `key => value`, a table cell, an element.
    Colon,
    /// `the password is value`: a sentence.
    Prose,
}

/// Where a value sits on its line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ending {
    /// The value ends its line or its field: `password: x`, `"password": "x",`.
    Field,
    /// More words follow on the same line: `password: x, 1 symbol`.
    Sentence,
}

/// One value after a secret's key, by byte offsets into the text.
struct KeyValue<'t> {
    key: &'t str,
    value: &'t str,
    start: usize,
    end: usize,
    assign: Assign,
    quoted: bool,
    ending: Ending,
}

/// The words a key that names a secret ends with.
const SECRET_KEY_WORDS: &str = r"password|passwd|passphrase|pass|pwd|secret|token|api[ _\-]?key|access[ _\-]?key|account[ _\-]?key|private[ _\-]?key|master[ _\-]?key|encryption[ _\-]?key|signing[ _\-]?key|credentials?";

fn key_value_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(&format!(
            r#"(?i)(?-u:\b)([A-Za-z0-9_.\-]{{0,40}}?(?:{SECRET_KEY_WORDS}))(["']?)([ \t]*(?:=>|:=|->|[:=])[ \t]*|[ \t]+(?:is|was)[ \t]+)(["']?)([^\s"'`,;]{{1,256}})"#
        ))
        .expect("static key-value regex")
    })
}

/// Whether a whole name (a table header, an element) names a secret.
fn names_a_secret(name: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(&format!(
            r"(?i)^[A-Za-z0-9_.\-]{{0,40}}?(?:{SECRET_KEY_WORDS})$"
        ))
        .expect("static key name regex")
    });
    re.is_match(name) && secret_key_name(name)
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("static regex"))
}

/// A call, an index or a generic: `get(`, `form.data[`, `env::var(`,
/// `Option<`.
fn call_or_index_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"^[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.|::|->|\?\.)[A-Za-z_$][A-Za-z0-9_$]*)*[(\[<]",
    )
}

/// An attribute path: `config.api_key`, `settings.SECRET_KEY`,
/// `Config::TOKEN`, `user?.token`.
fn dotted_path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"^[A-Za-z_$][A-Za-z0-9_$]*(?:(?:\.|::|->|\?\.)[A-Za-z_$][A-Za-z0-9_$]*)+$",
    )
}

fn identifier_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r"^[A-Za-z_][A-Za-z0-9_]*$")
}

/// The start of the next key on a line: `user: x`, `"user": x`.
fn next_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r#"^[A-Za-z_][A-Za-z0-9_.\-]*["']?[ \t]*[:=]"#)
}

/// A key that names a secret. `pass` and `pwd` count only as a word of the
/// key (`DB_PASS`, `MYSQL_PWD`), never as the end of one (`bypass`).
fn secret_key_name(key: &str) -> bool {
    if non_secret_token_key(&normalized_key(key)) {
        return false;
    }
    let lower = key.to_ascii_lowercase();
    for short in ["pass", "pwd"] {
        if let Some(head) = lower.strip_suffix(short) {
            return head.is_empty() || head.ends_with(['_', '-', '.', ' ']);
        }
    }
    true
}

/// A value that is source code, not a literal: a call or an index, an
/// attribute path, or a variable name. After `=` (outside an env file) any
/// name with no digit, or one in camelCase or snake_case, is a variable;
/// after `:` (an object literal or a config file) only a camelCase or
/// snake_case name with no digit is, since a config file writes literal
/// words there. A quoted value is a literal and never reaches here.
fn looks_like_code(value: &str, assign: Assign) -> bool {
    if call_or_index_re().is_match(value) {
        return true;
    }
    if assign == Assign::EnvFile || leet_runs(value) >= 2 {
        return false;
    }
    if dotted_path_re().is_match(value) {
        return true;
    }
    if !identifier_re().is_match(value) {
        return false;
    }
    let camel = value
        .as_bytes()
        .windows(2)
        .any(|pair| pair[0].is_ascii_lowercase() && pair[1].is_ascii_uppercase());
    let parts = value.trim_matches('_').contains('_');
    match assign {
        Assign::Equals => !has_digit(value) || camel || parts,
        _ => !has_digit(value) && (camel || parts),
    }
}

/// Whether what follows a value on its line ends the field (nothing, a
/// comment, the next key, closing punctuation) or goes on as a sentence.
fn ending_of(rest: &str) -> Ending {
    let rest = rest.trim_start_matches(|c: char| {
        matches!(
            c,
            ' ' | '\t' | '\r' | ',' | ';' | ')' | ']' | '}' | '"' | '\'' | '`' | '>'
        )
    });
    if rest.is_empty()
        || rest.starts_with(['#', '|', '{', '[', '<'])
        || rest.starts_with("//")
        || rest.starts_with("/*")
        || rest.starts_with("--")
        || next_key_re().is_match(rest)
    {
        Ending::Field
    } else {
        Ending::Sentence
    }
}

/// Every value after a secret's key in `text`.
fn key_values(text: &str) -> Vec<KeyValue<'_>> {
    let mut out = Vec::new();
    for caps in key_value_re().captures_iter(text) {
        let (Some(key), Some(sep), Some(quote), Some(raw)) =
            (caps.get(1), caps.get(3), caps.get(4), caps.get(5))
        else {
            continue;
        };
        if !secret_key_name(key.as_str()) {
            continue;
        }
        let quote = quote.as_str().chars().next();
        let start = raw.start();
        let (end, after) = match quote {
            // A quoted value runs to its closing quote on the same line.
            Some(q) => {
                let rest = &text[start..];
                match rest.find([q, '\n']) {
                    Some(at) if rest[at..].starts_with(q) => (start + at, start + at + 1),
                    _ => (raw.end(), raw.end()),
                }
            }
            None => {
                let trimmed = raw
                    .as_str()
                    .trim_end_matches(['.', ')', ']', '}', '>', ':']);
                (start + trimmed.len(), start + trimmed.len())
            }
        };
        if end <= start {
            continue;
        }
        let sep_text = sep.as_str().trim();
        let spaced = sep.as_str() != sep_text;
        let assign = match sep_text.to_ascii_lowercase().as_str() {
            "is" | "was" => Assign::Prose,
            ":=" => Assign::Equals,
            "=" if !spaced && !key.as_str().chars().any(|c| c.is_ascii_lowercase()) => {
                Assign::EnvFile
            }
            "=" => Assign::Equals,
            _ => Assign::Colon,
        };
        let line_rest = text[after..].split('\n').next().unwrap_or_default();
        out.push(KeyValue {
            key: key.as_str(),
            value: &text[start..end],
            start,
            end,
            assign,
            quoted: quote.is_some(),
            ending: ending_of(line_rest),
        });
    }
    out
}

/// Whether a value after a secret's key is a secret. A literal at the end
/// of its field is, unless it is a word that describes rather than gives a
/// value; a value inside a sentence, or written as a sentence, only when it
/// is shaped like a password; source code never.
fn keyed_value_is_secret(value: &str, quoted: bool, assign: Assign, ending: Ending) -> bool {
    if value.chars().count() < MIN_KEYED_SECRET || !plausible_value(value) || ordinary_word(value) {
        return false;
    }
    if !quoted && looks_like_code(value, assign) {
        return false;
    }
    if assign == Assign::Prose || ending == Ending::Sentence || value.contains(char::is_whitespace)
    {
        return strong_secret(value);
    }
    true
}

/// The cells of a table row, by byte offset into the row.
fn table_cells(row: &str) -> Vec<(usize, &str)> {
    let mut cells = Vec::new();
    let mut at = 0;
    for (i, part) in row.split('|').enumerate() {
        if i > 0 {
            cells.push((at, part));
        }
        at += part.len() + 1;
    }
    if cells.last().is_some_and(|(_, cell)| cell.trim().is_empty()) {
        cells.pop();
    }
    cells
}

fn table_row(line: &str) -> bool {
    line.trim_start().starts_with('|')
}

fn table_rule(line: &str) -> bool {
    let line = line.trim();
    line.starts_with('|')
        && line.contains('-')
        && line
            .chars()
            .all(|c| matches!(c, '|' | '-' | ':' | ' ' | '\t'))
}

/// Secrets in the columns of a markdown table whose header names a secret.
fn table_spans(text: &str, kept: &BTreeSet<String>, findings: &mut SecretFindings) -> Vec<Span> {
    let mut spans = Vec::new();
    if !text.contains('|') {
        return spans;
    }
    let mut lines = Vec::new();
    let mut at = 0;
    for line in text.split('\n') {
        lines.push((at, line));
        at += line.len() + 1;
    }
    let mut i = 0;
    while i + 1 < lines.len() {
        let (_, header) = lines[i];
        if !(table_row(header) && table_rule(lines[i + 1].1)) {
            i += 1;
            continue;
        }
        let columns: Vec<bool> = table_cells(header)
            .iter()
            .map(|(_, cell)| names_a_secret(cell.trim().trim_matches(['*', '`'])))
            .collect();
        let mut j = i + 2;
        while j < lines.len() && table_row(lines[j].1) {
            if columns.iter().any(|&secret| secret) {
                let (offset, row) = lines[j];
                for (column, (cell_at, cell)) in table_cells(row).into_iter().enumerate() {
                    if !columns.get(column).copied().unwrap_or(false) {
                        continue;
                    }
                    let lead = cell.len() - cell.trim_start().len();
                    let value = cell.trim().trim_matches(['`', '"', '\'']);
                    if value.is_empty() || value.contains(char::is_whitespace) {
                        continue;
                    }
                    let inner = cell.trim().find(value).unwrap_or(0);
                    if kept.contains(value)
                        || !keyed_value_is_secret(value, false, Assign::Colon, Ending::Field)
                    {
                        continue;
                    }
                    let start = offset + cell_at + lead + inner;
                    findings.found(SecretKind::CredentialValue, value);
                    spans.push(Span {
                        start,
                        end: start + value.len(),
                    });
                }
            }
            j += 1;
        }
        i = j;
    }
    spans
}

/// Secrets inside a markup element that names one: `<password>x</password>`.
fn element_spans(text: &str, kept: &BTreeSet<String>, findings: &mut SecretFindings) -> Vec<Span> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = regex(
        &RE,
        r"<([A-Za-z_][A-Za-z0-9_.:\-]{0,40})>[ \t]*([^<>\s]{1,256})[ \t]*</([A-Za-z_][A-Za-z0-9_.:\-]{0,40})>",
    );
    let mut spans = Vec::new();
    if !text.contains("</") {
        return spans;
    }
    for caps in re.captures_iter(text) {
        let (Some(open), Some(value), Some(close)) = (caps.get(1), caps.get(2), caps.get(3)) else {
            continue;
        };
        let name = open.as_str();
        if name != close.as_str() || !names_a_secret(name) {
            continue;
        }
        let value_text = value.as_str();
        if kept.contains(value_text)
            || !keyed_value_is_secret(value_text, false, Assign::Colon, Ending::Field)
        {
            continue;
        }
        findings.found(SecretKind::CredentialValue, value_text);
        spans.push(Span {
            start: value.start(),
            end: value.end(),
        });
    }
    spans
}

// ── encoded secrets ─────────────────────────────────────────────────────

/// Base64 wrapped over lines (`base64` writes 76 columns), as one run.
fn wrapped_base64_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"(?:[A-Za-z0-9+/]{40,}[ \t]*\r?\n[ \t]*)+[A-Za-z0-9+/]+={0,2}",
    )
}

/// A run of base64 or base64url on one line.
fn base64_run_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(&RE, r"[A-Za-z0-9+/_\-]{16,}={0,2}")
}

/// A run of hex, on one line or wrapped.
fn hex_run_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    regex(
        &RE,
        r"(?:[0-9A-Fa-f]{32,}[ \t]*\r?\n[ \t]*)*[0-9A-Fa-f]{16,}",
    )
}

/// Base64 decoded leniently: line breaks and other whitespace ignored,
/// padding optional, the standard or the URL alphabet.
fn decode_base64(encoded: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
    let compact: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let body = compact.trim_end_matches('=');
    if body.is_empty() || body.len() % 4 == 1 {
        return None;
    }
    if body.contains(['-', '_']) {
        URL_SAFE_NO_PAD.decode(body).ok()
    } else {
        STANDARD_NO_PAD.decode(body).ok()
    }
}

fn decode_hex(encoded: &str) -> Option<Vec<u8>> {
    let compact: Vec<u8> = encoded
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if !compact.len().is_multiple_of(2) {
        return None;
    }
    compact
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

/// Decoded bytes that are text: UTF-8 with no control characters other than
/// whitespace, and some letters. Images and other binary data are not.
fn as_text(bytes: Vec<u8>) -> Option<String> {
    let text = String::from_utf8(bytes).ok()?;
    let readable = text.chars().count() >= 6
        && text.chars().any(|c| c.is_ascii_alphabetic())
        && !text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'));
    readable.then_some(text)
}

/// A base64 field (a `blob`, the `data` of a block) as text, when it is text.
fn decoded_text(encoded: &str) -> Option<String> {
    decode_base64(encoded).and_then(as_text)
}

/// Runs of base64 or hex in `text` that decode to text holding a secret.
/// Each such run is masked whole: the encoded form gives away the secret as
/// surely as the plain one.
fn encoded_spans(
    text: &str,
    kept: &BTreeSet<String>,
    depth: usize,
    findings: &mut SecretFindings,
) -> Vec<Span> {
    let mut spans = Vec::new();
    if depth >= MAX_DECODE_DEPTH {
        return spans;
    }
    let mut look = |start: usize, end: usize, decoded: Option<String>| {
        let Some(decoded) = decoded else {
            return;
        };
        let mut inner = SecretFindings::default();
        secret_spans_at(&decoded, kept, depth + 1, &mut inner);
        if inner.is_empty() {
            return;
        }
        findings.kinds.extend(inner.kinds);
        findings.values.extend(inner.values);
        findings.found(SecretKind::EncodedSecret, &text[start..end]);
        spans.push(Span { start, end });
    };
    for run in wrapped_base64_re().find_iter(text) {
        look(run.start(), run.end(), decoded_text(run.as_str()));
    }
    for run in base64_run_re().find_iter(text) {
        look(run.start(), run.end(), decoded_text(run.as_str()));
    }
    for run in hex_run_re().find_iter(text) {
        look(
            run.start(),
            run.end(),
            decode_hex(run.as_str()).and_then(as_text),
        );
    }
    spans
}

// ── spans and masking ───────────────────────────────────────────────────

/// A secret span in a text, by byte offsets.
#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
}

/// Every secret span in `text`, and what was found, into `findings`. A value
/// in `kept` is the session's own token and is skipped.
fn secret_spans(text: &str, kept: &BTreeSet<String>, findings: &mut SecretFindings) -> Vec<Span> {
    secret_spans_at(text, kept, 0, findings)
}

fn secret_spans_at(
    text: &str,
    kept: &BTreeSet<String>,
    depth: usize,
    findings: &mut SecretFindings,
) -> Vec<Span> {
    let mut spans = Vec::new();
    for pattern in patterns() {
        for caps in pattern.re.captures_iter(text) {
            let Some(value) = caps.get(pattern.value) else {
                continue;
            };
            if kept.contains(value.as_str()) || !(pattern.accept)(value.as_str()) {
                continue;
            }
            findings.found(pattern.kind, value.as_str());
            spans.push(Span {
                start: value.start(),
                end: value.end(),
            });
        }
    }
    for kv in key_values(text) {
        if kept.contains(kv.value)
            || !keyed_value_is_secret(kv.value, kv.quoted, kv.assign, kv.ending)
        {
            continue;
        }
        findings.found(SecretKind::CredentialValue, kv.value);
        spans.push(Span {
            start: kv.start,
            end: kv.end,
        });
    }
    spans.extend(table_spans(text, kept, findings));
    spans.extend(element_spans(text, kept, findings));
    spans.extend(encoded_spans(text, kept, depth, findings));
    spans
}

/// `text` with every span, and every other occurrence of a known secret
/// value, replaced by [`MASK`]. `None` when nothing in it is secret.
fn masked_text(text: &str, known: &BTreeSet<String>, kept: &BTreeSet<String>) -> Option<String> {
    let mut scratch = SecretFindings::default();
    let mut spans = secret_spans(text, kept, &mut scratch);
    for value in known {
        for (start, _) in text.match_indices(value.as_str()) {
            spans.push(Span {
                start,
                end: start + value.len(),
            });
        }
    }
    if spans.is_empty() {
        return None;
    }
    // Overlapping spans (one value read by two patterns) become one mask.
    spans.sort_by_key(|span| span.start);
    let mut merged: Vec<Span> = Vec::with_capacity(spans.len());
    for span in spans {
        match merged.last_mut() {
            Some(last) if span.start < last.end => last.end = last.end.max(span.end),
            _ => merged.push(span),
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0usize;
    for span in merged {
        out.push_str(&text[at..span.start]);
        out.push_str(MASK);
        at = span.end;
    }
    out.push_str(&text[at..]);
    Some(out)
}

/// Mask the secrets in a free text, as [`mask_message`] does in a message.
/// `None` when it holds none.
pub fn mask_text(text: &str) -> Option<(String, SecretFindings)> {
    let mut findings = SecretFindings::default();
    let none = BTreeSet::new();
    secret_spans(text, &none, &mut findings);
    if findings.is_empty() {
        return None;
    }
    let masked = masked_text(text, &findings.values, &none).unwrap_or_else(|| text.to_string());
    Some((masked, findings))
}

// ── structured values ───────────────────────────────────────────────────

/// The JSON keys a structured secret is kept under (`password`, `apiKey`,
/// `client_secret`), excluding paging and progress handles.
fn secret_key(key: &str) -> bool {
    crate::redact::sensitive_key(key) && !non_secret_token_key(&normalized_key(key))
}

/// The keys under which a nested object or list holds secrets: a secret's
/// key, or its plural (`passwords`, `secrets`, `tokens`).
fn secret_container_key(key: &str) -> bool {
    secret_key(key)
        || key
            .strip_suffix('s')
            .or_else(|| key.strip_suffix('S'))
            .is_some_and(secret_key)
}

/// Keys that describe a credential rather than hold it, inside an object
/// under a secret's key: `{"credentials": {"type": "oauth2", "username": ..}}`.
fn descriptive_key(key: &str) -> bool {
    const KEYS: &[&str] = &[
        "type",
        "kind",
        "name",
        "id",
        "username",
        "user",
        "login",
        "email",
        "scope",
        "scopes",
        "role",
        "roles",
        "expiresin",
        "expiresat",
        "expires",
        "expiry",
        "issuedat",
        "createdat",
        "updatedat",
        "created",
        "updated",
        "url",
        "uri",
        "host",
        "hostname",
        "port",
        "method",
        "algorithm",
        "alg",
        "provider",
        "issuer",
        "description",
        "title",
        "label",
        "format",
        "pattern",
        "enum",
        "required",
        "status",
        "hint",
        "comment",
        "note",
        "tokentype",
    ];
    KEYS.contains(&normalized_key(key).as_str())
}

/// The keys whose string value is base64 (a resource `blob`, the `data` of
/// an image or audio block). Looked into only when it decodes to text.
fn base64_key(key: &str) -> bool {
    matches!(key, "blob" | "data")
}

/// The key of a registry login whose value is base64 of `user:password`.
fn auth_key(key: &str) -> bool {
    matches!(normalized_key(key).as_str(), "auth" | "basicauth")
}

/// A structured secret: a string under a secret's key that is not empty, a
/// placeholder, a boolean-ish word or a path.
fn structured_secret(key: &str, value: &str) -> bool {
    if !secret_key(key) || value.chars().count() < 4 || !not_placeholder(value) {
        return false;
    }
    !ordinary_word(value) && !value.starts_with('/') && !value.contains("://")
}

/// A number under a secret's key that is long enough to be a PIN or a code,
/// not a count or a limit.
fn structured_secret_number(key: &str, number: &serde_json::Number) -> bool {
    let normalized = normalized_key(key);
    let count = ["max", "min", "num", "total"]
        .iter()
        .any(|prefix| normalized.starts_with(prefix));
    secret_key(key)
        && !count
        && (number.is_u64() || number.is_i64())
        && number.to_string().trim_start_matches('-').len() >= 4
}

/// The session keys a login answer issues the client's own token under.
fn session_key(key: &str) -> bool {
    matches!(
        normalized_key(key).as_str(),
        "token"
            | "accesstoken"
            | "sessiontoken"
            | "usertoken"
            | "idtoken"
            | "authtoken"
            | "authenticationtoken"
            | "refreshtoken"
            | "bearertoken"
            | "sessionid"
            | "jwt"
            | "sessionjwt"
    )
}

/// A value that can be the session's own token: one opaque word or a JWT,
/// and nothing else a secret can be (a provider key, a private key, a
/// password in a URL, a flag, an encoded secret).
fn session_value(value: &str) -> bool {
    if value.len() < 8
        || value.len() > 8192
        || value.contains(char::is_whitespace)
        || !not_placeholder(value)
    {
        return false;
    }
    let mut findings = SecretFindings::default();
    secret_spans(value, &BTreeSet::new(), &mut findings);
    findings.kinds.iter().all(|kind| {
        matches!(
            kind,
            SecretKind::Jwt | SecretKind::BearerToken | SecretKind::CredentialValue
        )
    })
}

/// The session tokens an answer to a credential exchange issues: values
/// under a session key, in structured content or written in text.
fn collect_session_tokens(value: &Value, key: Option<&str>, kept: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            if key.is_some_and(session_key) && session_value(text) {
                kept.insert(text.clone());
            }
            for kv in key_values(text) {
                if kv.assign != Assign::Prose && session_key(kv.key) && session_value(kv.value) {
                    kept.insert(kv.value.to_string());
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_session_tokens(item, None, kept);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                collect_session_tokens(item, Some(key), kept);
            }
        }
        _ => {}
    }
}

/// One pass over a value: finds the secrets in it and, when `mask` holds the
/// known secret values, returns the value with each one masked (`None` when
/// nothing changed). `inherited` says an ancestor's key names a secret.
fn walk(
    value: &Value,
    key: Option<&str>,
    inherited: bool,
    kept: &BTreeSet<String>,
    mask: Option<&BTreeSet<String>>,
    findings: &mut SecretFindings,
) -> Option<Value> {
    match value {
        Value::String(text) => {
            if kept.contains(text) {
                return None;
            }
            let keyed = key.is_some_and(|key| structured_secret(key, text));
            let nested = inherited
                && !key.is_some_and(descriptive_key)
                && reads_as_a_secret(text)
                && !ordinary_word(text);
            let login = key.is_some_and(auth_key) && user_and_password_b64(text);
            if keyed || nested || login {
                let kind = if login {
                    SecretKind::BasicCredential
                } else {
                    SecretKind::CredentialValue
                };
                findings.found(kind, text);
                return mask.map(|_| Value::String(MASK.to_string()));
            }
            if key.is_some_and(base64_key) {
                if let Some(decoded) = decoded_text(text) {
                    match mask {
                        Some(known) => {
                            if let Some(masked) = masked_text(&decoded, known, kept) {
                                return Some(Value::String(
                                    base64::engine::general_purpose::STANDARD.encode(masked),
                                ));
                            }
                        }
                        None => {
                            secret_spans_at(&decoded, kept, 1, findings);
                        }
                    }
                }
            }
            match mask {
                Some(known) => masked_text(text, known, kept).map(Value::String),
                None => {
                    secret_spans(text, kept, findings);
                    None
                }
            }
        }
        Value::Number(number) => {
            if key.is_some_and(|key| structured_secret_number(key, number)) {
                findings.found(SecretKind::CredentialValue, &number.to_string());
                return mask.map(|_| Value::String(MASK.to_string()));
            }
            None
        }
        Value::Array(items) => {
            let inherited = (inherited && !key.is_some_and(descriptive_key))
                || key.is_some_and(secret_container_key);
            let mut changed: Option<Vec<Value>> = None;
            for (i, item) in items.iter().enumerate() {
                if let Some(new) = walk(item, None, inherited, kept, mask, findings) {
                    changed.get_or_insert_with(|| items.clone())[i] = new;
                }
            }
            changed.map(Value::Array)
        }
        Value::Object(map) => {
            let inherited = (inherited && !key.is_some_and(descriptive_key))
                || key.is_some_and(secret_container_key);
            let mut changed: Option<serde_json::Map<String, Value>> = None;
            for (child_key, item) in map {
                if let Some(new) = walk(item, Some(child_key), inherited, kept, mask, findings) {
                    changed
                        .get_or_insert_with(|| map.clone())
                        .insert(child_key.clone(), new);
                }
            }
            changed.map(Value::Object)
        }
        _ => None,
    }
}

/// The parts of a message that carry content to the client.
const CONTENT_FIELDS: &[&str] = &["result", "error", "params"];

/// What secret-shaped values a server message (one JSON-RPC object) carries
/// in its `result`, `error` or `params`. Read only.
pub fn scan_message(message: &Value) -> SecretFindings {
    scan_answer(message, AnswerContext::default())
}

/// [`scan_message`] for an answer whose request is known
/// ([`AnswerContext`]).
pub fn scan_answer(message: &Value, context: AnswerContext) -> SecretFindings {
    let mut findings = SecretFindings::default();
    let Some(object) = message.as_object() else {
        return findings;
    };
    if context.credential_exchange {
        if let Some(result) = object.get("result") {
            collect_session_tokens(result, None, &mut findings.kept);
        }
    }
    let kept = std::mem::take(&mut findings.kept);
    for field in CONTENT_FIELDS {
        if let Some(value) = object.get(*field) {
            walk(value, None, false, &kept, None, &mut findings);
        }
    }
    findings.kept = kept;
    findings
}

/// Mask, in place, what [`scan_message`] found in `message`: each secret
/// value is replaced by [`MASK`], everything else (the id, the shape, the
/// other text) is left as it was.
pub fn mask_message(message: &mut Value, findings: &SecretFindings) {
    if let Some(object) = message.as_object_mut() {
        for field in CONTENT_FIELDS {
            if let Some(value) = object.get_mut(*field) {
                let mut scratch = SecretFindings::default();
                if let Some(masked) = walk(
                    value,
                    None,
                    false,
                    &findings.kept,
                    Some(&findings.values),
                    &mut scratch,
                ) {
                    *value = masked;
                }
            }
        }
    }
}

// ── resources/read ──────────────────────────────────────────────────────

/// Most resource URIs a session remembers from the server's listings.
const MAX_ANNOUNCED_URIS: usize = 4096;
/// Most resource templates a session remembers.
const MAX_ANNOUNCED_TEMPLATES: usize = 256;
/// Longest URI or template remembered.
const MAX_ANNOUNCED_URI_BYTES: usize = 2048;

/// The resources a server announced this session: the URIs its
/// `resources/list` answers named, the templates its
/// `resources/templates/list` answers named, and the resource links its tool
/// results carried. Only a read of a location none of them covers is told so.
#[derive(Debug, Default)]
pub struct ResourceCatalog {
    /// A listing was heard, so a location it does not hold means something.
    listed: bool,
    /// A listing held more than is kept, so absence proves nothing.
    overflowed: bool,
    uris: HashSet<Box<str>>,
    templates: Vec<Box<str>>,
}

impl ResourceCatalog {
    /// Remember what a `resources/list` or `resources/templates/list` answer
    /// announces.
    pub fn record_listing(&mut self, method: &str, result: &Value) {
        let (field, uri_key) = match method {
            "resources/list" => ("resources", "uri"),
            "resources/templates/list" => ("resourceTemplates", "uriTemplate"),
            _ => return,
        };
        self.listed = true;
        let Some(items) = result.get(field).and_then(Value::as_array) else {
            return;
        };
        for item in items {
            if let Some(uri) = item.get(uri_key).and_then(Value::as_str) {
                if uri_key == "uri" {
                    self.keep_uri(uri);
                } else {
                    self.keep_template(uri);
                }
            }
        }
    }

    /// Remember the resources a tool result links to or embeds: a client may
    /// read those without a listing naming them.
    pub fn record_links(&mut self, result: &Value) {
        let Some(blocks) = result.get("content").and_then(Value::as_array) else {
            return;
        };
        for block in blocks {
            let uri = match block.get("type").and_then(Value::as_str) {
                Some("resource_link") => block.get("uri"),
                Some("resource") => block.get("resource").and_then(|r| r.get("uri")),
                _ => None,
            };
            if let Some(uri) = uri.and_then(Value::as_str) {
                self.keep_uri(uri);
            }
        }
    }

    fn keep_uri(&mut self, uri: &str) {
        if self.uris.contains(uri) {
            return;
        }
        if uri.len() > MAX_ANNOUNCED_URI_BYTES || self.uris.len() >= MAX_ANNOUNCED_URIS {
            self.overflowed = true;
            return;
        }
        self.uris.insert(uri.into());
    }

    fn keep_template(&mut self, template: &str) {
        if self.templates.iter().any(|kept| &**kept == template) {
            return;
        }
        if template.len() > MAX_ANNOUNCED_URI_BYTES
            || self.templates.len() >= MAX_ANNOUNCED_TEMPLATES
        {
            self.overflowed = true;
            return;
        }
        self.templates.push(template.into());
    }

    /// Whether the server announced `uri`: `None` when no listing was heard
    /// (or one held more than is kept), so nothing can be said.
    pub fn announced(&self, uri: &str) -> Option<bool> {
        if !self.listed || self.overflowed {
            return None;
        }
        Some(
            self.uris.contains(uri)
                || self
                    .templates
                    .iter()
                    .any(|template| template_matches(template, uri)),
        )
    }
}

/// Whether `uri` is one an RFC 6570 template can expand to, each expression
/// (`{name}`, `{+path}`, `{?q}`) standing for any text.
fn template_matches(template: &str, uri: &str) -> bool {
    let mut literals = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        literals.push(&rest[..open]);
        match rest[open..].find('}') {
            Some(close) => rest = &rest[open + close + 1..],
            None => {
                rest = "";
                break;
            }
        }
    }
    literals.push(rest);
    if literals.len() == 1 {
        return template == uri;
    }
    let first = literals[0];
    let last = literals[literals.len() - 1];
    if uri.len() < first.len() + last.len() || !uri.starts_with(first) || !uri.ends_with(last) {
        return false;
    }
    let mut middle = &uri[first.len()..uri.len() - last.len()];
    for literal in &literals[1..literals.len() - 1] {
        match middle.find(literal) {
            Some(at) => middle = &middle[at + literal.len()..],
            None => return false,
        }
    }
    true
}

/// `uri` with its percent-escapes decoded, again until it no longer changes
/// (an escape can be escaped), at most a few rounds.
fn percent_decoded(uri: &str) -> String {
    let mut current = uri.to_string();
    for _ in 0..4 {
        let bytes = current.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        let next = String::from_utf8_lossy(&out).into_owned();
        if next == current {
            break;
        }
        current = next;
    }
    current
}

/// Whether a path in the (decoded) URI climbs out of where it starts: a `..`
/// segment, with either slash.
fn climbs_out(decoded: &str) -> bool {
    let path = decoded.split(['?', '#']).next().unwrap_or_default();
    path.split(['/', '\\'])
        .any(|segment| segment == ".." || segment.starts_with("..;"))
}

/// Where a network URI points, when that is the host or its platform.
enum NetworkTarget {
    /// The cloud metadata service or another link-local address.
    Metadata,
    /// Loopback, a private range, or the unspecified address.
    Local,
}

fn network_target(decoded: &str) -> Option<NetworkTarget> {
    let (scheme, rest) = decoded.split_once("://")?;
    const NETWORK: &[&str] = &[
        "http", "https", "ftp", "ws", "wss", "gopher", "dict", "ldap", "tftp",
    ];
    if !NETWORK.contains(&scheme.to_ascii_lowercase().as_str()) {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if let Some(inner) = host_port.strip_prefix('[') {
        inner.split(']').next().unwrap_or_default()
    } else {
        host_port.split(':').next().unwrap_or_default()
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "metadata.google.internal" || host == "metadata" {
        return Some(NetworkTarget::Metadata);
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return Some(NetworkTarget::Local);
    }
    match host.parse::<std::net::IpAddr>().ok()? {
        std::net::IpAddr::V4(ip) => {
            if ip.is_link_local() || ip.octets() == [100, 100, 100, 200] {
                Some(NetworkTarget::Metadata)
            } else if ip.is_loopback() || ip.is_private() || ip.is_unspecified() {
                Some(NetworkTarget::Local)
            } else {
                None
            }
        }
        std::net::IpAddr::V6(ip) => {
            let segments = ip.segments();
            // fe80::/10 link-local, and the instance metadata address of one
            // cloud (fd00:ec2::254).
            let metadata = std::net::Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);
            if segments[0] & 0xffc0 == 0xfe80 || ip == metadata {
                Some(NetworkTarget::Metadata)
            } else if ip.is_loopback() || ip.is_unspecified() || segments[0] & 0xfe00 == 0xfc00 {
                Some(NetworkTarget::Local)
            } else {
                None
            }
        }
    }
}

/// What a location says about secret material ([`secret_location`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum SecretLocation {
    /// A scheme whose every location is a secret store (`vault://`,
    /// `keyring://`, `secrets://`): refused in a mode that blocks.
    Store(String),
    /// A location that names a credential by its word, where a read is for
    /// the credential (`internal://credentials`, `kv://apiToken`): refused
    /// in a mode that blocks.
    Credential(String),
    /// A credential word in a document or source file about it
    /// (`docs://credentials-guide`, `file:///repo/src/auth/token.rs`), or
    /// a scheme that only says private (`internal://settings`): alerted.
    Named(String),
}

/// Schemes whose every location is a secret store.
const SECRET_STORE_SCHEMES: &[&str] = &[
    "secret",
    "secrets",
    "vault",
    "keyring",
    "keychain",
    "kv",
    "env",
    "ssm",
    "secretsmanager",
    "creds",
    "credentials",
];

/// Schemes that only say private.
const PRIVATE_SCHEMES: &[&str] = &["internal", "private"];

/// Schemes of documentation: a credential word there names a topic.
const DOC_SCHEMES: &[&str] = &[
    "docs", "doc", "help", "man", "readme", "guide", "manual", "wiki", "kb",
];

/// Schemes whose locations are files or web pages: only the last segment
/// says what is read (`/repo/src/auth/token.rs` is a source file).
const FILE_OR_WEB_SCHEMES: &[&str] = &["file", "http", "https"];

/// The extensions of a document or a source file. Not a configuration one
/// (`.json`, `.yaml`, `.env`): `credentials.json` holds credentials.
const DOC_EXTENSIONS: &[&str] = &[
    "md", "markdown", "txt", "rst", "adoc", "html", "htm", "pdf", "ipynb", "rs", "py", "js", "jsx",
    "ts", "tsx", "go", "java", "kt", "c", "h", "cc", "cpp", "hpp", "rb", "php", "cs", "swift",
    "scala", "sh",
];

/// Words of a segment that make it a document about a credential, not the
/// credential: `auth_tokens_schema`, `token-limits`, `password-reset`.
const DOC_WORDS: &[&str] = &[
    "guide",
    "guides",
    "doc",
    "docs",
    "documentation",
    "schema",
    "schemas",
    "spec",
    "reset",
    "limit",
    "limits",
    "policy",
    "policies",
    "faq",
    "help",
    "howto",
    "tutorial",
    "readme",
    "example",
    "examples",
    "template",
    "templates",
    "format",
    "usage",
    "overview",
    "reference",
    "rotation",
];

/// The words of a piece of a location: split on every character that is
/// not a letter or digit and between a small letter and a capital
/// (`adminCredentials` is `admin credentials`), lowercased, with letters
/// drawn like Latin ones read as them (`сredentials`, Cyrillic `с`).
fn location_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut previous_small = false;
    for c in text.chars() {
        let small = c.is_lowercase();
        let folded: String = c
            .to_lowercase()
            .map(crate::description_poison::confusable)
            .collect();
        let letter = folded.chars().all(|f| f.is_ascii_alphanumeric());
        if (!letter || (c.is_uppercase() && previous_small)) && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        if letter {
            word.push_str(&folded);
        }
        previous_small = small;
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

/// The word of a location that names a credential (`credentials`,
/// `tokens`, `master key`, `ssh key`), if any.
fn credential_word(words: &[String]) -> Option<String> {
    const WORDS: &[&str] = &[
        "credential",
        "credentials",
        "cred",
        "creds",
        "secret",
        "secrets",
        "password",
        "passwords",
        "passwd",
        "passphrase",
        "pass",
        "pwd",
        "token",
        "tokens",
        "jwt",
        "jwts",
        "bearer",
        "apikey",
        "apikeys",
        "apitoken",
        "authtoken",
        "accesstoken",
        "privatekey",
        "masterkey",
        "sshkey",
    ];
    const KEY_OWNERS: &[&str] = &[
        "api",
        "private",
        "master",
        "signing",
        "encryption",
        "access",
        "ssh",
        "auth",
    ];
    for (i, word) in words.iter().enumerate() {
        if WORDS.contains(&word.as_str()) {
            return Some(word.clone());
        }
        if matches!(word.as_str(), "key" | "keys")
            && i > 0
            && KEY_OWNERS.contains(&words[i - 1].as_str())
        {
            return Some(format!("{} {word}", words[i - 1]));
        }
    }
    None
}

/// What a (decoded) location says about secret material, if anything.
///
/// A secret store scheme is a secret whatever the rest says. A credential
/// word counts in the last segment of a file or a web page, and anywhere in
/// a location of another scheme; it names a credential, refused, unless the
/// scheme is one of documentation or the last segment is a document or a
/// source file about it (by its extension or a word such as `guide`,
/// `schema`, `limits`, `reset`). Measured 2026-11-20 against a held-out
/// set: `docs://credentials-guide`, `config://auth_tokens_schema`,
/// `file:///repo/src/auth/token.rs`, `file:///repo/docs/password-reset.md`
/// and `https://.../token-limits` were refused by the first version of
/// this check, and `kv://apiToken`, `vault://x` and `internal://сredentials`
/// (Cyrillic `с`) were not.
fn secret_location(decoded: &str) -> Option<SecretLocation> {
    let (scheme, rest) = match decoded.split_once("://") {
        Some((scheme, rest)) => (location_words(scheme).join(""), rest),
        None => (String::new(), decoded),
    };
    if SECRET_STORE_SCHEMES.contains(&scheme.as_str()) {
        return Some(SecretLocation::Store(format!("{scheme}://")));
    }
    let path = rest.split(['?', '#']).next().unwrap_or_default();
    let last = path
        .split(['/', '\\'])
        .rfind(|segment| !segment.is_empty())
        .unwrap_or_default();
    let extension = last
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .unwrap_or_default();
    let last_words = location_words(last);
    let about_it = DOC_SCHEMES.contains(&scheme.as_str())
        || DOC_EXTENSIONS.contains(&extension.as_str())
        || last_words
            .iter()
            .any(|word| DOC_WORDS.contains(&word.as_str()));
    let named = if FILE_OR_WEB_SCHEMES.contains(&scheme.as_str()) {
        credential_word(&last_words)
    } else {
        credential_word(&location_words(path))
    };
    if let Some(word) = named {
        return Some(if about_it {
            SecretLocation::Named(word)
        } else {
            SecretLocation::Credential(word)
        });
    }
    PRIVATE_SCHEMES
        .contains(&scheme.as_str())
        .then(|| SecretLocation::Named(format!("{scheme}://")))
}

/// The credential stores of common tools, by the last segments of their
/// path. Reading one hands over a live credential (a cluster's client key, a
/// registry login, a command line tool's OAuth token, a pod's service account
/// token), so a read of one is refused as a private key is. A file of the
/// same name elsewhere (`project/docker/config.json`) is not one.
const CREDENTIAL_STORES: &[&[&str]] = &[
    &[".kube", "config"],
    &[".docker", "config.json"],
    &[".config", "gh", "hosts.yml"],
    &[".config", "hub"],
    &[".aws", "credentials"],
    &[".netrc"],
    &["_netrc"],
    &[".git-credentials"],
    &[".pgpass"],
    &[".vault-token"],
    &[".config", "gcloud", "application_default_credentials.json"],
    &[".config", "gcloud", "credentials.db"],
    &[".config", "gcloud", "access_tokens.db"],
    &[".azure", "accesstokens.json"],
    &[".azure", "msal_token_cache.json"],
    &["kubernetes.io", "serviceaccount", "token"],
];

/// The credential store a (decoded) location points at, if any. The path is
/// compared segment by segment, case folded, with empty and `.` segments
/// dropped, so `//` and `/./` do not hide one.
fn credential_store(decoded: &str) -> Option<String> {
    let path = decoded.split(['?', '#']).next().unwrap_or_default();
    let path = path.split_once("://").map_or(path, |(_, rest)| rest);
    let segments: Vec<String> = path
        .split(['/', '\\'])
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .map(str::to_ascii_lowercase)
        .collect();
    CREDENTIAL_STORES
        .iter()
        .find(|store| {
            segments.len() >= store.len()
                && segments[segments.len() - store.len()..]
                    .iter()
                    .zip(store.iter())
                    .all(|(segment, part)| segment == part)
        })
        .map(|store| store.join("/"))
}

/// Whether a location carries a password in its user info
/// (`scheme://user:password@host`), as sent or percent-decoded.
fn location_password(uri: &str, decoded: &str) -> bool {
    [uri, decoded].iter().any(|location| {
        let Some((_, rest)) = location.split_once("://") else {
            return false;
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        authority
            .rsplit_once('@')
            .and_then(|(userinfo, _)| userinfo.split_once(':'))
            .is_some_and(|(_, password)| not_placeholder(password))
    })
}

/// Inspect the location a client `resources/read` asks for.
///
/// Refused (in guard and kill): a path that climbs out of its root (plain or
/// percent-encoded), a secret store on disk or a tool's credential store, a
/// password in the location's user info, the cloud metadata service, a
/// location that names a credential by its word (`internal://credentials`,
/// `vault://master_key`, `config://auth_tokens`: the person's call), and
/// what the tool-call rules refuse in an argument. Alerted only: the host's
/// own loopback or private network, a scheme that only says private
/// (`internal://settings`), and one the server never announced (`catalog`,
/// after a listing was heard). Those are not refused because an ordinary
/// server can name its resources that way, and whatever secret such a read
/// returns is masked in the answer.
pub fn inspect_resource_read(
    uri: &str,
    catalog: Option<&ResourceCatalog>,
    engine: Option<&RuleEngine>,
) -> Verdict {
    let decoded = percent_decoded(uri);
    // The URI is the argument of the read: the tool-call screens (a secret
    // store path, a credential, a supply chain IOC, the ATR rules) see it as
    // sent, and decoded when it was escaped.
    let args = if decoded == uri {
        serde_json::json!({ "uri": uri })
    } else {
        serde_json::json!({ "uri": uri, "decoded_uri": decoded })
    };
    let mut verdict = mcp::inspect_tool_call("resources/read", &args, engine);
    let mut push = |detail: String, block: bool| {
        verdict
            .alerts
            .push(VerdictAlert::builtin(RESOURCE_URI_RULE, detail, block));
    };
    if climbs_out(&decoded) {
        push(
            "the resource location climbs out of its root with a `..` segment".into(),
            true,
        );
    }
    if let Some(store) = credential_store(&decoded) {
        push(
            format!("the resource location is a tool's credential store (`{store}`)"),
            true,
        );
    }
    if location_password(uri, &decoded) {
        push(
            "the resource location carries a password in its user info".into(),
            true,
        );
    }
    match network_target(&decoded) {
        Some(NetworkTarget::Metadata) => push(
            "the resource location is the cloud metadata service or a link-local address".into(),
            true,
        ),
        Some(NetworkTarget::Local) => push(
            "the resource location is this host's loopback or a private network".into(),
            false,
        ),
        None => {}
    }
    // A location that names a credential by its word (`credentials`,
    // `auth_tokens`, `master_key`), or a secret store scheme (`vault://`),
    // is the person's call in a mode that blocks, as a read of
    // `~/.aws/credentials` in the shell is: the agent is refused and the
    // person reads it if it is theirs to read. A document or a source file
    // about a credential, and a scheme that only says private
    // (`internal://settings`), stay an alert. Measured 2026-11-20 (DVMCP
    // ch1, 2, 4, 5, 6, 14, 15): every such read passed with an alert and
    // handed the client what the masking did not know as a secret.
    match secret_location(&decoded) {
        Some(SecretLocation::Store(scheme)) => push(
            format!(
                "the resource location is a secret store (`{scheme}`): reading it is the \
                 person's call, as a read of a credentials file in the shell is"
            ),
            true,
        ),
        Some(SecretLocation::Credential(word)) => push(
            format!(
                "the resource location names a credential (`{word}`): reading it is the \
                 person's call, as a read of a credentials file in the shell is"
            ),
            true,
        ),
        Some(SecretLocation::Named(word)) => push(
            format!("the resource location names secret material (`{word}`)"),
            false,
        ),
        None => {}
    }
    if catalog.and_then(|catalog| catalog.announced(uri)) == Some(false) {
        push(
            "the server did not announce this resource in its listings this session".into(),
            false,
        );
    }
    verdict.allowed = !verdict.alerts.iter().any(|alert| alert.block);
    verdict
}

/// The text a `resources/read` result hands the client, for the injection
/// screen: each content's `text`, and each `blob` that decodes to text. A
/// non-empty result with neither is scanned whole, as a tool result of an
/// unknown shape is.
pub fn resource_text(result: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(contents) = result.get("contents").and_then(Value::as_array) {
        for item in contents {
            if let Some(text) = item.get("text").and_then(Value::as_str) {
                parts.push(text.to_string());
            } else if let Some(text) = item
                .get("blob")
                .and_then(Value::as_str)
                .and_then(decoded_text)
            {
                parts.push(text);
            }
        }
    }
    if parts.is_empty() && result.as_object().is_some_and(|map| !map.is_empty()) {
        parts.push(result.to_string());
    }
    parts.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Synthetic values, assembled so no provider-shaped literal lives in the
    /// source.
    fn api_key() -> String {
        format!("sk-{}", "lab-reporting-key-7c41d09e2b")
    }

    fn masked(text: &str) -> String {
        mask_text(text)
            .map(|(masked, _)| masked)
            .unwrap_or_else(|| text.to_string())
    }

    fn kinds(text: &str) -> Vec<SecretKind> {
        mask_text(text)
            .map(|(_, findings)| findings.kinds.into_iter().collect())
            .unwrap_or_default()
    }

    /// An AWS secret access key is masked after its key, in any of the ways
    /// a file, a log or a page writes it, and after an access key id on its
    /// line or the next. Measured 2026-11-20 (DVMCP ch14): the key id was
    /// masked and `AWS Secret Key: <40 characters>` reached the client.
    ///
    /// FAILS ON REVERT of either AWS secret key pattern.
    #[test]
    fn an_aws_secret_access_key_is_masked() {
        // The documentation's sample key, assembled so it is not a literal.
        let secret = format!("{}/{}/{}", "wJalrXUtnFEMI", "K7MDENG", "bPxRfiCYEXAMPLEKEY");
        let id = format!("AKIA{}", "1234567890EXAMPLE");
        for text in [
            format!("AWS Access Key: {id}\nAWS Secret Key: {secret}\n"),
            format!("[default]\naws_secret_access_key = {secret}\n"),
            format!("{{\"secret_key\": \"{secret}\"}}"),
            format!("SECRET_ACCESS_KEY={secret}"),
            format!("credentials {id} {secret}"),
            format!("key id {id}\nthen {secret}\n"),
        ] {
            let out = masked(&text);
            assert!(!out.contains(&secret), "{text:?} -> {out:?}");
            assert!(kinds(&text).contains(&SecretKind::CloudKey), "{text:?}");
        }
        // Forty characters of one case, or with no digit, `/` or `+`, are
        // not a key; nor is a 40-character run far from any key id or key.
        for text in [
            format!("secret_key: {}", "a".repeat(40)),
            format!("secret_key: {}", "AbcdefghijAbcdefghijAbcdefghijAbcdefghij"),
            format!("commit {}", "0123456789abcdef0123456789abcdef01234567"),
        ] {
            assert!(!kinds(&text).contains(&SecretKind::CloudKey), "{text:?}");
        }
    }

    #[test]
    fn masks_each_secret_class_and_keeps_the_text_around_it() {
        let jwt = format!(
            "eyJhbGciOiJIUzI1NiJ9.{}.{}",
            "eyJzdWIiOiJsYWIifQ", "c2lnbmF0dXJl"
        );
        let cases: Vec<(String, &str, SecretKind)> = vec![
            (format!("service_key {}", api_key()), "service_key", SecretKind::ApiKey),
            (format!("billing sk_{}_{}", "live", "51LabKey0123456789"), "billing", SecretKind::ApiKey),
            (format!("mirror gh{}", "p_LabFakeToken0123456789abcdefABCD"), "mirror", SecretKind::ApiKey),
            (format!("chat xox{}", "b-000000000-LabFake1111"), "chat", SecretKind::ApiKey),
            (format!("aws AKIA{}", "LABEXAMPLE7Q2W9ZKEY"), "aws", SecretKind::CloudKey),
            (format!("session {jwt}"), "session", SecretKind::Jwt),
            (format!("header Authorization: Bearer {}", "lab0token0value0123"), "Bearer [REDACTED]", SecretKind::BearerToken),
            ("admin_password: Lab-Pass-4471!".to_string(), "admin_password: [REDACTED]", SecretKind::CredentialValue),
            ("Master Key: mk_0x4e7b_lab_key".to_string(), "Master Key: [REDACTED]", SecretKind::CredentialValue),
            (r#"{"api_key": "plainvalue2026"}"#.to_string(), r#"{"api_key": "[REDACTED]"}"#, SecretKind::CredentialValue),
            ("db postgres://report:Db-Lab@Pw-2026@db.lab.internal:5432/sales".to_string(), "postgres://report:[REDACTED]@db.lab.internal:5432/sales", SecretKind::ConnectionPassword),
            ("flag: LAB{st0len_by_th3_read_9c2e}".to_string(), "flag: [REDACTED]", SecretKind::FlagToken),
            (format!("key\n-----BEGIN {k} PRIVATE KEY-----\nAAAAlabkeymaterial\n-----END {k} PRIVATE KEY-----\nend", k = "OPENSSH"), "key\n[REDACTED]\nend", SecretKind::PrivateKey),
        ];
        for (text, kept, kind) in cases {
            let out = masked(&text);
            assert!(out.contains(MASK), "nothing masked in {text:?}: {out:?}");
            assert!(out.contains(kept), "{kept:?} not kept in {out:?}");
            assert!(
                kinds(&text).contains(&kind),
                "{text:?} not read as {kind:?}"
            );
        }
    }

    #[test]
    fn a_secret_found_once_is_masked_wherever_else_it_appears() {
        let text =
            "db: postgres://admin:Pr0d-Lab-Pw!@db.internal/prod\nretry as admin / Pr0d-Lab-Pw!";
        let out = masked(text);
        assert!(!out.contains("Pr0d-Lab-Pw!"), "{out}");
        assert!(out.contains("retry as admin / [REDACTED]"), "{out}");
    }

    /// Lab case: a log line that writes the user and the password as a pair.
    #[test]
    fn a_user_and_password_pair_after_a_credentials_key_is_masked() {
        let out = masked("Retry with credentials: admin / Pr0d-Lab-Pw!26");
        assert_eq!(out, "Retry with credentials: admin / [REDACTED]");
        assert_eq!(
            masked("credentials=deploy:Lab-Deploy-77"),
            "credentials=[REDACTED]"
        );
    }

    /// Lab case: a heading underlined on the next line is not a value of the
    /// key the heading ends with.
    #[test]
    fn a_key_never_takes_its_value_from_the_next_line() {
        for text in [
            "MASTER KEY & CREDENTIALS\n========================\nnothing else",
            "Password\n: see the vault policy 2026",
            "credentials: see /etc/app/creds for the format",
            "Credentials: OAuth 2.0 / OpenID Connect",
        ] {
            assert!(mask_text(text).is_none(), "{text:?}: {:?}", masked(text));
        }
    }

    #[test]
    fn a_private_key_cut_before_its_footer_is_masked_to_the_end() {
        let text = format!(
            "-----BEGIN {} PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0",
            "RSA"
        );
        assert_eq!(masked(&text), MASK);
    }

    #[test]
    fn ordinary_text_is_left_untouched() {
        for text in [
            "To change your password: open Settings, then Security.",
            "Passwords must be at least 12 characters long.",
            "The token: expires after one hour of inactivity.",
            "Set the key with export API_KEY=<your key> before you start.",
            "password: ${DB_PASSWORD}",
            "token: string (required)",
            "secret: false",
            "password_file: /run/secrets/db",
            "token_url: https://auth.lab.internal/token",
            "Release commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
            "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "request_id: req_7f3a9b2c trace 123e4567-e89b-12d3-a456-426614174000",
            "result = sum(range(10))\nmax_tokens=4096\nprompt_tokens: 1247",
            "def get_password(user):\n    return vault.read(user)",
            "nextPageToken: CAoQAAabc123",
            "Use the risk-assessment-framework-2026 document",
            "my $home = $ENV{HOME_DIR_2};  \\section{step_1_overview}",
            "https://user@github.com:22/org/repo and http://localhost:8080/path?mail=a@b.c",
            "Bearer authentication is used by this API.",
            "postgres://user:password@localhost/db is the example DSN",
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
        ] {
            assert!(mask_text(text).is_none(), "masked ordinary text {text:?}: {:?}", masked(text));
        }
    }

    #[test]
    fn a_message_is_masked_field_by_field_and_keeps_its_shape() {
        let key = api_key();
        let mut message = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "result": {
                "content": [{"type": "text", "text": format!("key {key} ok")}],
                "structuredContent": {"host": "db", "password": "hunter2lab", "nextPageToken": "CAoQAAabc123"},
                "_meta": {"progressToken": "progress-0001-lab"}
            }
        });
        let findings = scan_message(&message);
        assert!(findings.kinds.contains(&SecretKind::ApiKey));
        assert!(findings.kinds.contains(&SecretKind::CredentialValue));
        mask_message(&mut message, &findings);
        assert_eq!(message["id"], 7);
        assert_eq!(message["result"]["content"][0]["text"], "key [REDACTED] ok");
        assert_eq!(message["result"]["structuredContent"]["password"], MASK);
        assert_eq!(message["result"]["structuredContent"]["host"], "db");
        assert_eq!(
            message["result"]["structuredContent"]["nextPageToken"],
            "CAoQAAabc123"
        );
        assert_eq!(
            message["result"]["_meta"]["progressToken"],
            "progress-0001-lab"
        );
    }

    #[test]
    fn a_text_blob_is_looked_into_and_an_image_is_not() {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("API_KEY={}\n", api_key()));
        let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
        let mut message = json!({"jsonrpc": "2.0", "id": 1, "result": {"contents": [
            {"uri": "file:///lab/.env", "mimeType": "text/plain", "blob": encoded},
            {"uri": "file:///lab/pixel.png", "mimeType": "image/png", "blob": png}
        ]}});
        let findings = scan_message(&message);
        assert!(findings.kinds.contains(&SecretKind::ApiKey), "{findings:?}");
        mask_message(&mut message, &findings);
        let decoded =
            decoded_text(message["result"]["contents"][0]["blob"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, "API_KEY=[REDACTED]\n");
        assert_eq!(message["result"]["contents"][1]["blob"], png);
    }

    #[test]
    fn a_clean_message_has_no_findings() {
        let message = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{
            "name": "login",
            "description": "Authenticate with a username and password.",
            "inputSchema": {"type": "object", "properties": {
                "password": {"type": "string"}, "token": {"type": "string"}
            }, "required": ["password"]}
        }]}});
        assert!(scan_message(&message).is_empty());
    }

    #[test]
    fn the_alert_names_kinds_never_values() {
        let key = api_key();
        let (_, findings) = mask_text(&format!("k {key}")).expect("found");
        for masked in [true, false] {
            let alert = findings.alert(masked);
            assert_eq!(alert.rule, SECRET_OUT_RULE);
            assert!(alert.detail.contains("API key"), "{}", alert.detail);
            assert!(!alert.detail.contains(&key));
        }
    }

    // ── resources/read ──────────────────────────────────────────────────

    fn rules(verdict: &Verdict) -> Vec<&str> {
        verdict.alerts.iter().map(|a| a.rule.as_str()).collect()
    }

    #[test]
    fn a_read_that_climbs_out_or_reaches_a_key_store_or_metadata_is_refused() {
        for uri in [
            "file:///srv/app/data/../../../etc/passwd",
            "file:///srv/app/data/%2e%2e/%2E%2E/etc/hosts",
            "file:///srv/app/data/%252e%252e/secret",
            "notes://a/..\\..\\b",
            "file:///home/dev/.ssh/id_ed25519",
            "file:///home/dev/%2Essh/id_rsa",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
        ] {
            let verdict = inspect_resource_read(uri, None, None);
            assert!(!verdict.allowed, "{uri} was allowed: {:?}", rules(&verdict));
        }
    }

    #[test]
    fn ordinary_reads_are_allowed_without_an_alert() {
        let engine = RuleEngine::load_embedded();
        for uri in [
            "info://help",
            "docs://search_help",
            "weather://help",
            "math://help",
            "files://public/readme",
            "docs://usage",
            "docs://workflow",
            "release://notes",
            "file:///srv/app/data/readme.txt",
            "file:///home/dev/project/src/main.rs",
            "https://example.com/report.html",
            "notes://2026/q1..q2-summary",
        ] {
            let verdict = inspect_resource_read(uri, None, Some(&engine));
            assert!(verdict.allowed, "{uri} refused: {:?}", verdict.alerts);
            assert!(
                verdict.alerts.is_empty(),
                "{uri} alerted: {:?}",
                verdict.alerts
            );
        }
    }

    /// A location that names a credential by its word, or a secret store
    /// scheme, is refused in a mode that blocks (the person's call, as a
    /// credentials file read in the shell is): in any case and spelling the
    /// DVMCP challenges used, and in the ones a held-out set of 2026-11-20
    /// added (camelCase, short words, store schemes, a Cyrillic `с`).
    ///
    /// FAILS ON REVERT of the `Store` or `Credential` arm in
    /// `inspect_resource_read`, of the camelCase split or the confusable
    /// fold in `location_words`, or of the new words in `credential_word`.
    #[test]
    fn a_location_that_names_a_credential_is_refused() {
        for (uri, why) in [
            ("internal://credentials", "credentials"),
            ("vault://master_key", "vault://"),
            ("config://auth_tokens", "tokens"),
            ("system://admin_credentials", "credentials"),
            ("internal://secret_config", "secret"),
            ("INTERNAL://Credentials", "credentials"),
            ("internal://%63redentials", "credentials"),
            ("files://team/api-keys", "api key"),
            ("internal://adminCredentials", "credentials"),
            ("config://apiToken", "token"),
            ("config://authToken", "token"),
            ("store://creds", "creds"),
            ("store://db_pwd", "pwd"),
            ("store://admin/pass", "pass"),
            ("session://jwt", "jwt"),
            ("session://bearer", "bearer"),
            ("host://deploy/ssh_key", "ssh key"),
            ("keyring://login", "keyring://"),
            ("keychain://github", "keychain://"),
            ("kv://app/settings", "kv://"),
            ("vault://x", "vault://"),
            ("env://DATABASE_URL", "env://"),
            ("ssm://prod/db", "ssm://"),
            ("secrets://x", "secrets://"),
            ("secret://notes", "secret://"),
            ("internal://\u{0441}redentials", "credentials"),
            ("file:///srv/app/db_password", "password"),
            ("https://intranet.example/ops/credentials", "credentials"),
        ] {
            let verdict = inspect_resource_read(uri, None, None);
            assert!(!verdict.allowed, "{uri} allowed: {:?}", verdict.alerts);
            assert!(
                verdict.alerts.iter().any(|a| a.rule == RESOURCE_URI_RULE
                    && a.block
                    && a.detail.contains(why)
                    && a.detail.contains("person's call")),
                "{uri}: {:?}",
                verdict.alerts
            );
        }
    }

    /// A document or a source file about a credential is read, with an
    /// alert: the held-out set's five URIs, which the first version of the
    /// refusal took for credentials.
    ///
    /// FAILS ON REVERT of `about_it` or of the last-segment rule for files
    /// and web pages in `secret_location`.
    #[test]
    fn a_document_about_a_credential_is_alerted_not_refused() {
        for uri in [
            "docs://credentials-guide",
            "config://auth_tokens_schema",
            "file:///repo/src/auth/token.rs",
            "file:///repo/docs/password-reset.md",
            "https://docs.example.com/api/token-limits",
            "help://passwords",
            "file:///repo/credentials/README.md",
            "file:///repo/src/auth/tokens/mod_list.txt",
        ] {
            let verdict = inspect_resource_read(uri, None, None);
            assert!(verdict.allowed, "{uri} refused: {:?}", verdict.alerts);
        }
    }

    #[test]
    fn a_secret_looking_or_local_location_is_alerted_not_refused() {
        for (uri, why) in [
            ("internal://settings", "internal://"),
            ("docs://credentials-guide", "credentials"),
            ("http://127.0.0.1:8080/status", "loopback"),
        ] {
            let verdict = inspect_resource_read(uri, None, None);
            assert!(verdict.allowed, "{uri} refused: {:?}", verdict.alerts);
            assert!(
                verdict
                    .alerts
                    .iter()
                    .any(|a| a.rule == RESOURCE_URI_RULE && a.detail.contains(why)),
                "{uri}: {:?}",
                verdict.alerts
            );
        }
    }

    #[test]
    fn a_read_the_server_never_announced_is_alerted_once_a_listing_was_heard() {
        let mut catalog = ResourceCatalog::default();
        assert_eq!(catalog.announced("docs://usage"), None);
        catalog.record_listing(
            "resources/list",
            &json!({"resources": [{"uri": "docs://usage", "name": "usage"}]}),
        );
        catalog.record_listing(
            "resources/templates/list",
            &json!({"resourceTemplates": [{"uriTemplate": "users://{id}/profile", "name": "p"}]}),
        );
        catalog.record_links(&json!({"content": [
            {"type": "resource_link", "uri": "reports://q1", "name": "q1"}
        ]}));
        assert_eq!(catalog.announced("docs://usage"), Some(true));
        assert_eq!(catalog.announced("users://alice/profile"), Some(true));
        assert_eq!(catalog.announced("reports://q1"), Some(true));
        assert_eq!(catalog.announced("users://alice/keys"), Some(false));
        let verdict = inspect_resource_read("docs://hidden", Some(&catalog), None);
        assert!(verdict.allowed);
        assert!(verdict
            .alerts
            .iter()
            .any(|a| a.detail.contains("did not announce")));
        let verdict = inspect_resource_read("docs://usage", Some(&catalog), None);
        assert!(verdict.alerts.is_empty(), "{:?}", verdict.alerts);
    }

    #[test]
    fn templates_match_by_their_literal_parts() {
        assert!(template_matches("file:///{+path}", "file:///a/b.txt"));
        assert!(template_matches("a://{x}/b/{y}", "a://1/b/2"));
        assert!(!template_matches("a://{x}/b/{y}", "a://1/c/2"));
        assert!(template_matches("plain://x", "plain://x"));
        assert!(!template_matches("plain://x", "plain://y"));
        assert!(!template_matches("ab{x}ba", "aba"));
    }

    #[test]
    fn resource_text_reads_texts_and_text_blobs() {
        let blob = base64::engine::general_purpose::STANDARD.encode("from a blob");
        let result = json!({"contents": [{"uri": "a://1", "text": "plain"}, {"uri": "a://2", "blob": blob}]});
        assert_eq!(resource_text(&result), "plain\nfrom a blob");
        assert_eq!(resource_text(&json!({"other": 1})), r#"{"other":1}"#);
        assert_eq!(resource_text(&json!({})), "");
    }

    // ── review findings ─────────────────────────────────────────────────

    fn b64(text: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(text)
    }

    fn hex(text: &str) -> String {
        text.bytes().map(|b| format!("{b:02x}")).collect()
    }

    /// A synthetic password with a digit, a symbol and both cases.
    fn strong_password() -> String {
        format!("Pr0d-Lab!{}", 2026)
    }

    /// REGRESSION ANCHOR (review 2C-FP-1: an ordinary Django view read
    /// through a files server came back with `[REDACTED]` in place of
    /// expressions, so an agent editing the file would write the marker back
    /// into the source). A value after a secret's key that is code (a call,
    /// an index, an attribute path, a variable, an interpolated string) or a
    /// line of prose is not a secret.
    ///
    /// FAILS ON REVERT: each line was masked.
    #[test]
    fn code_and_documentation_that_name_a_secret_are_left_untouched() {
        let view = "from django.conf import settings\n\
                    def login_view(request):\n    \
                    token = request.headers.get(\"Authorization\")\n    \
                    api_key = config.api_key\n    \
                    password=form.cleaned_data[\"password\"]\n    \
                    session = jwt.encode(payload, settings.SECRET_KEY, algorithm=\"HS256\")\n    \
                    return token";
        for text in [
            view,
            r#"token = jwt.encode(payload, key, algorithm="HS256")"#,
            "secret = Secret(name=secret_name, value=value)",
            "UPDATE users SET password = crypt('x', gen_salt('bf'))",
            r#"logger.info(f"chunk{chunk_id_0} done")"#,
            r#"var msg = $"Order{order_id2} shipped";"#,
            "password: min12chars, 1 symbol",
            "- token: rotate2026 now runs nightly",
            "password = userPassword",
            "secret = ENV_SECRET_KEY",
            "api_key = os.getenv(\"API_KEY\")",
            "The password is required for every login.",
        ] {
            assert!(
                mask_text(text).is_none(),
                "masked code or prose {text:?}: {:?}",
                masked(text)
            );
        }
    }

    /// The FP guard for the key-value rule across languages and documents:
    /// variables, calls, paths and type names after a secret's key, prose
    /// around one, constants in braces, tables and markup that describe a
    /// secret. Each is code or documentation an agent reads to edit.
    #[test]
    fn code_and_documents_in_other_languages_are_left_untouched() {
        for text in [
            "let token = env::var_os(KEY_NAME)",
            "const secret = Config::SIGNING_SECRET;",
            "return { token: tokenValue, password: hashedPassword };",
            "headers = {\"token\": token_value}",
            "connect(host=host, password=db_password)",
            "api_key: Optional[str] = None",
            "password: SecretStr",
            "token = await get_token()",
            "secret = os.urandom(32)",
            "String password = request.getParameter(\"pw\");",
            "$password = $_POST['password'];",
            "token: The access token (string)",
            "Your token is about to expire.",
            "The signing secret is rotated every night.",
            "Default password: admin123 (change it on first login)",
            "constexpr auto TIMEOUT_MS{300000};",
            "| Parameter | Type | Description |\n|---|---|---|\n| token | string | The API token |",
            "<token>{{ session_token }}</token>",
            "password_hash = crypt(password, salt)",
            "tokenizer: cl100k_base",
        ] {
            assert!(
                mask_text(text).is_none(),
                "masked {text:?}: {:?}",
                masked(text)
            );
        }
    }

    /// REGRESSION ANCHOR (review 2C-EV-1): a flag-shaped value is masked
    /// whatever its body looks like: hex, no underscore, no digit, a name
    /// with an underscore, hyphens in place of underscores.
    ///
    /// FAILS ON REVERT: each passed unmasked.
    #[test]
    fn flag_shaped_values_are_masked_in_every_common_form() {
        for (text, body) in [
            ("flag{9e107d9d372bb6826bd81d3542a419d6}", "9e107d9d372bb"),
            ("CTF{h1dd3nv4lu3}", "h1dd3nv4lu3"),
            ("FLAG{only_words_in_here}", "only_words_in_here"),
            ("CTF_FLAG{t4k3n_fr0m_m3m_4a1b}", "t4k3n_fr0m_m3m"),
            ("FLAG: LAB{ch4-p1p3-l34k-7f2a}", "ch4-p1p3-l34k"),
        ] {
            let out = masked(text);
            assert!(out.contains(MASK), "nothing masked in {text:?}: {out:?}");
            assert!(!out.contains(body), "{body:?} kept in {out:?}");
        }
    }

    /// REGRESSION ANCHOR (review 2C-EV-1 and 2C-EV-2): a secret written in
    /// base64 or hex inside ordinary text (a tool told to encode its output,
    /// a kubeconfig's key data) is looked into and masked whole.
    ///
    /// FAILS ON REVERT: only `blob` and `data` fields were decoded.
    #[test]
    fn a_secret_encoded_as_base64_or_hex_in_text_is_masked() {
        let flag = "LAB{st0len_by_th3_read_9c2e}";
        let pem = format!(
            "-----BEGIN {k} PRIVATE KEY-----\nMIIEowIBAAKCAQEAlabfakekeymaterial0123456789\n-----END {k} PRIVATE KEY-----\n",
            k = "RSA"
        );
        let encoded_flag = b64(&format!("FLAG: {flag}\n"));
        let encoded_key = b64(&pem);
        let hex_flag = hex(&format!("FLAG: {flag}"));
        for (text, encoded) in [
            (encoded_flag.clone(), encoded_flag.as_str()),
            (
                format!("output: {encoded_flag} (done)"),
                encoded_flag.as_str(),
            ),
            (
                format!("users:\n- name: lab\n  user:\n    client-key-data: {encoded_key}\n"),
                encoded_key.as_str(),
            ),
            (hex_flag.clone(), hex_flag.as_str()),
        ] {
            let out = masked(&text);
            assert!(out.contains(MASK), "nothing masked in {text:?}");
            assert!(
                !out.contains(encoded),
                "the encoded secret was kept: {out:?}"
            );
        }
        // Encoded data that holds no secret is left alone.
        let certificate = format!("client-certificate-data: {}", b64("LabCertificateOnly"));
        assert!(
            mask_text(&certificate).is_none(),
            "{:?}",
            masked(&certificate)
        );
    }

    /// REGRESSION ANCHOR (review 2C-EV-2): passwords in the notations config
    /// files, prose, markup, tables and auth headers use.
    ///
    /// FAILS ON REVERT: each one was forwarded byte for byte.
    #[test]
    fn a_password_in_any_common_notation_is_masked() {
        let pw = strong_password();
        let account_key = b64("lab-storage-account-key-0123456789abcdef");
        let cases: Vec<(String, String)> = vec![
            (format!("    'password' => '{pw}',"), pw.clone()),
            (format!("The admin password is {pw} until Friday."), pw.clone()),
            (format!("<password>{pw}</password>"), pw.clone()),
            (format!("DB_PASS={pw}"), pw.clone()),
            (format!("MYSQL_PWD={pw}"), pw.clone()),
            ("Redis password: sunshine".to_string(), "sunshine".to_string()),
            ("admin_password: letmein".to_string(), "letmein".to_string()),
            (
                format!("Proxy: Authorization: Basic {}", b64(&format!("admin:{pw}"))),
                b64(&format!("admin:{pw}")),
            ),
            (
                format!("DefaultEndpointsProtocol=https;AccountName=lab;AccountKey={account_key};EndpointSuffix=core.windows.net"),
                account_key.clone(),
            ),
            (
                format!("mail key SG.{}.{}", "LabFakeSendGrid0123ab", "LabFakeSendGridSecret0123456789abcdef"),
                "LabFakeSendGridSecret0123456789abcdef".to_string(),
            ),
            (
                "| service | secret |\n|---|---|\n| cache | c4ch3_l4b_2026 |".to_string(),
                "c4ch3_l4b_2026".to_string(),
            ),
            (
                format!(r#"{{"auths": {{"registry.lab": {{"auth": "{}"}}}}}}"#, b64(&format!("lab:{pw}"))),
                b64(&format!("lab:{pw}")),
            ),
        ];
        for (text, secret) in cases {
            let out = masked(&text);
            assert!(out.contains(MASK), "nothing masked in {text:?}");
            assert!(!out.contains(&secret), "{secret:?} kept in {out:?}");
        }
    }

    /// The other half of the notation fix: the same notations around values
    /// that are not secrets stay as they were.
    #[test]
    fn a_secret_notation_around_an_ordinary_value_is_left_untouched() {
        for text in [
            "| field | token |\n|---|---|\n| header | string |\n| scope | required |",
            "<password>required</password>",
            "Authorization: Basic authentication is supported.",
            "client-certificate-data is optional.",
            "bypass=allow_listed_hosts",
            r#"{"auth": "oauth2"}"#,
        ] {
            assert!(mask_text(text).is_none(), "{text:?}: {:?}", masked(text));
        }
    }

    /// REGRESSION ANCHOR (review 2C-EV-3): a secret nested under a secret's
    /// key (an object, a list, a number), base64 under any key, and a blob
    /// wrapped at 76 columns or left unpadded.
    ///
    /// FAILS ON REVERT: `scan_message` found nothing in each.
    #[test]
    fn a_secret_nested_under_a_secret_key_or_encoded_in_any_field_is_masked() {
        let pw = strong_password();
        let flag = "LAB{st0len_by_th3_read_9c2e}";
        let env = format!(
            "API_KEY={}\nDB_PASSWORD={pw}\nFLAG={flag}\n# padding so the encoding wraps over more than one line of output\n",
            api_key()
        );
        let wrapped = b64(&env)
            .as_bytes()
            .chunks(76)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let unpadded = b64(&env).trim_end_matches('=').to_string();
        let cases: Vec<(Value, Vec<String>)> = vec![
            (
                json!({"structuredContent": {"credentials": {"admin": pw}}}),
                vec![pw.clone()],
            ),
            (
                json!({"structuredContent": {"passwords": [pw]}}),
                vec![pw.clone()],
            ),
            (
                json!({"structuredContent": {"pin_password": 93817264}}),
                vec!["93817264".to_string()],
            ),
            (
                json!({"structuredContent": {"path": "secret.txt", "encoding": "base64", "content": b64(flag)}}),
                vec![b64(flag)],
            ),
            (
                json!({"contents": [{"uri": "file:///lab/.env", "blob": wrapped}]}),
                vec![wrapped.lines().next().unwrap_or_default().to_string()],
            ),
            (
                json!({"contents": [{"uri": "file:///lab/.env", "blob": unpadded}]}),
                vec![unpadded[..40].to_string()],
            ),
        ];
        for (result, secrets) in cases {
            let mut message = json!({"jsonrpc": "2.0", "id": 1, "result": result});
            let findings = scan_message(&message);
            assert!(!findings.is_empty(), "nothing found in {message}");
            mask_message(&mut message, &findings);
            let text = message.to_string();
            for secret in &secrets {
                assert!(!text.contains(secret.as_str()), "{secret:?} kept in {text}");
            }
            assert_eq!(message["id"], 1);
        }
    }

    /// The other half: counts, schemas, word lists and identities under keys
    /// that name a secret are not secrets.
    #[test]
    fn structured_values_that_are_not_secrets_stay_untouched() {
        let message = json!({"jsonrpc": "2.0", "id": 1, "result": {"structuredContent": {
            "usage": {"max_tokens": 4096, "prompt_tokens": 1247, "token_count": 88},
            "password_min_length": 12,
            "tokens": ["the", "quick", "brown"],
            "credentials": {"type": "oauth2", "username": "alice", "expires_in": 3600},
            "inputSchema": {"properties": {"password": {"type": "string", "description": "The account password"}}}
        }}});
        let findings = scan_message(&message);
        assert!(findings.is_empty(), "{findings:?}");
    }

    /// REGRESSION ANCHOR (review 2C-EV-4): the credential stores of common
    /// tools are refused as a resource, as a private key is.
    ///
    /// FAILS ON REVERT: each was allowed, at most with an alert.
    #[test]
    fn a_read_of_a_tool_credential_store_is_refused() {
        let engine = RuleEngine::load_embedded();
        for uri in [
            "file:///home/dev/.kube/config",
            "file:///home/dev/.docker/config.json",
            "file:///home/dev/.config/gh/hosts.yml",
            "file:///var/run/secrets/kubernetes.io/serviceaccount/token",
            "file:///home/dev/.aws/credentials",
            "file:///home/dev/.netrc",
        ] {
            let verdict = inspect_resource_read(uri, None, Some(&engine));
            assert!(!verdict.allowed, "{uri} was allowed: {:?}", verdict.alerts);
        }
        for uri in [
            "file:///home/dev/project/docker/config.json",
            "file:///home/dev/project/docs/kube/config.md",
        ] {
            let verdict = inspect_resource_read(uri, None, Some(&engine));
            assert!(verdict.allowed, "{uri} refused: {:?}", verdict.alerts);
        }
    }

    /// REGRESSION ANCHOR (review 2C-FP-3): a template with placeholder values
    /// and a public key are not secret stores.
    ///
    /// FAILS ON REVERT: both were refused.
    #[test]
    fn a_read_of_a_template_or_a_public_key_is_allowed() {
        let engine = RuleEngine::load_embedded();
        for uri in [
            "file:///home/dev/project/.env.example",
            "file:///home/dev/project/tests/fixtures/id_rsa.pub",
        ] {
            let verdict = inspect_resource_read(uri, None, Some(&engine));
            assert!(verdict.allowed, "{uri} refused: {:?}", verdict.alerts);
        }
        // The same names do not open a way around the screen.
        for uri in [
            "file:///home/dev/project/.env",
            "file:///home/dev/project/id_rsa",
            "file:///home/dev/project/id_rsa%00.pub",
            "file:///home/dev/project/id_rsa.pub/../id_rsa",
            "file:///home/dev/.ssh/id_rsa.pub",
        ] {
            let verdict = inspect_resource_read(uri, None, Some(&engine));
            assert!(!verdict.allowed, "{uri} was allowed: {:?}", verdict.alerts);
        }
    }

    /// REGRESSION ANCHOR (review 2C-COR-1): a password in the user info of
    /// the location is refused, plain or percent-encoded.
    ///
    /// FAILS ON REVERT: both were allowed with no alert.
    #[test]
    fn a_read_whose_location_carries_a_password_is_refused() {
        let engine = RuleEngine::load_embedded();
        for uri in [
            "https://admin:Pr0dPass2026x@example.com/report",
            "https://admin:Pr0d%40Lab2026@example.com/report",
        ] {
            let verdict = inspect_resource_read(uri, None, Some(&engine));
            assert!(!verdict.allowed, "{uri} was allowed: {:?}", verdict.alerts);
        }
        for uri in [
            "https://user@example.com/org/repo",
            "https://example.com/report?mail=a@b.c",
        ] {
            let verdict = inspect_resource_read(uri, None, Some(&engine));
            assert!(verdict.allowed, "{uri} refused: {:?}", verdict.alerts);
        }
    }

    /// REGRESSION ANCHOR (review 2C-FP-2): in the answer to a call that
    /// supplied a credential, the session token issued under a session key
    /// stays, in text and in structured content. Everything else the same
    /// answer leaks (another account's token, a bearer for the system, a
    /// master key, a signing secret) is still masked, and so is a provider key
    /// or a flag written under a session key.
    ///
    /// FAILS ON REVERT: the session token was masked with the rest.
    #[test]
    fn a_login_answer_keeps_the_session_token_and_masks_the_rest() {
        let session = format!(
            "{}.{}.{}",
            "eyJ0eXAiOiJKV1QifQ", "eyJzdWIiOiJndWVzdCJ9", "c2lnLWd1ZXN0LTAx"
        );
        let admin = format!(
            "{}.{}.{}",
            "eyJ0eXAiOiJKV1QifQ", "eyJzdWIiOiJhZG1pbiJ9", "c2lnLWFkbWluLTAy"
        );
        let bearer = format!("{}{}", "lab0system0bearer", "0c41d09e");
        let signing = format!("hmac-{}-s3cr3t-k3y", "sha256");
        let text = format!(
            "Authentication OK\n  username: guest\n  user_token: {session}\n  expires_in: 3600\n  admin_token: {admin}\n  system_bearer: Bearer {bearer}\n  master_api_key: {key}\n  session_signing_secret: {signing}\n",
            key = api_key()
        );
        let message = json!({"jsonrpc": "2.0", "id": 4, "result": {
            "content": [{"type": "text", "text": text}],
            "structuredContent": {"access_token": session, "role": "guest"}
        }});
        let exchange = AnswerContext {
            credential_exchange: true,
        };
        let findings = scan_answer(&message, exchange);
        let mut masked = message.clone();
        mask_message(&mut masked, &findings);
        let out = masked["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_default();
        assert!(out.contains(&format!("user_token: {session}")), "{out}");
        assert_eq!(
            masked["result"]["structuredContent"]["access_token"],
            session
        );
        for leaked in [&admin, &bearer, &api_key(), &signing] {
            assert!(!out.contains(leaked.as_str()), "{leaked} kept in {out}");
        }
        assert!(out.contains("expires_in: 3600"), "{out}");

        // Without the exchange the same answer masks the session token too.
        let findings = scan_answer(&message, AnswerContext::default());
        let mut masked = message.clone();
        mask_message(&mut masked, &findings);
        assert!(!masked.to_string().contains(&session), "{masked}");

        // A provider key, a flag or a private key under a session key is not
        // a session token, exchange or not.
        for value in [
            api_key(),
            "LAB{st0len_by_th3_read_9c2e}".to_string(),
            b64("FLAG: LAB{st0len_by_th3_read_9c2e}"),
        ] {
            let message = json!({"jsonrpc": "2.0", "id": 5, "result": {
                "content": [{"type": "text", "text": format!("token: {value}")}],
                "structuredContent": {"token": value}
            }});
            let findings = scan_answer(&message, exchange);
            let mut masked = message.clone();
            mask_message(&mut masked, &findings);
            assert!(
                !masked.to_string().contains(&value),
                "{value} kept: {masked}"
            );
        }
    }

    #[test]
    fn a_call_supplies_a_credential_only_with_a_value_under_a_secret_key() {
        assert!(supplies_credential(
            &json!({"username": "guest", "password": "guest"})
        ));
        assert!(supplies_credential(&json!({"refresh_token": "r-0123"})));
        assert!(!supplies_credential(&json!({"username": "guest"})));
        assert!(!supplies_credential(&json!({"password": ""})));
        assert!(!supplies_credential(&json!({"password": 1234})));
        assert!(!supplies_credential(&json!("password=guest")));
    }
}
