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
//!   bearer tokens, passwords written as a key and a value or inside a
//!   connection string, and flag-like tokens; [`mask_message`] replaces each
//!   with `[REDACTED]` and leaves every other byte of the text, the id and the
//!   shape of the answer as they were.
//! * **The location a `resources/read` asks for** ([`inspect_resource_read`]):
//!   a path that climbs out of its root, a secret store on disk, the cloud
//!   metadata service, a location that names secret material, and one the
//!   server never announced.
//!
//! False positives are the cost to watch: documentation that names the word
//! password, commit hashes and other high-entropy ids, code, and images. A
//! value is masked only when its shape says secret (a provider prefix, a JWT,
//! a private key header) or a secret's key names it and the value does not
//! read as prose or a placeholder; base64 payloads are looked into only when
//! they decode to text.

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

/// The kinds of secret-shaped value the server-side screen knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecretKind {
    PrivateKey,
    ApiKey,
    CloudKey,
    Jwt,
    BearerToken,
    ConnectionPassword,
    CredentialValue,
    FlagToken,
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
            SecretKind::ConnectionPassword => "password in a connection string",
            SecretKind::CredentialValue => "credential value",
            SecretKind::FlagToken => "flag-like token",
        }
    }
}

/// What one screen of a message found: the kinds (for the alert) and the
/// values (so each is masked wherever else it appears in the message).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SecretFindings {
    pub kinds: BTreeSet<SecretKind>,
    values: BTreeSet<String>,
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

/// One secret-shaped pattern: where the secret is in a match, what kind it
/// is, and the test the matched value must pass.
struct SecretPattern {
    re: Regex,
    /// The capture group that holds the secret (0 = the whole match).
    value: usize,
    /// The capture group that holds the key naming the secret, when the
    /// pattern is a key and a value.
    key: Option<usize>,
    kind: SecretKind,
    accept: fn(&str) -> bool,
}

fn patterns() -> &'static [SecretPattern] {
    static P: OnceLock<Vec<SecretPattern>> = OnceLock::new();
    P.get_or_init(|| {
        let mk = |re: &str, value, key, kind, accept: fn(&str) -> bool| SecretPattern {
            re: Regex::new(re).expect("static secret regex"),
            value,
            key,
            kind,
            accept,
        };
        vec![
            // A private key block, header to footer (or to the end of the text
            // when the footer was cut), so the key material goes with it.
            mk(
                r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----(?s:.*?)(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----|\z)",
                0,
                None,
                SecretKind::PrivateKey,
                always,
            ),
            // Cloud access key ids.
            mk(
                r"\b(?:AKIA|ASIA)[0-9A-Z]{16,}",
                0,
                None,
                SecretKind::CloudKey,
                always,
            ),
            // Provider API keys and tokens by their prefix. A real one carries
            // digits; a hyphenated word that happens to start the same way
            // does not.
            mk(
                r"\b(?:sk-[A-Za-z0-9_\-]{16,}|[sr]k_(?:live|test)_[A-Za-z0-9]{10,}|gh[opsur]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_\-]{20,}|xox[abposr]-[A-Za-z0-9\-]{10,}|npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_\-]{35})",
                0,
                None,
                SecretKind::ApiKey,
                has_digit,
            ),
            // A JWT: a JSON header, then either a JSON payload or two more
            // base64url segments.
            mk(
                r"\beyJ[A-Za-z0-9_\-]{6,}\.(?:eyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]*|[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,})",
                0,
                None,
                SecretKind::Jwt,
                always,
            ),
            // A bearer token (the scheme word stays readable).
            mk(
                r"(?i)\bbearer[ \t]+([A-Za-z0-9_.~+/\-]{12,}=*)",
                1,
                None,
                SecretKind::BearerToken,
                has_digit,
            ),
            // The password of a connection string: scheme://user:PASSWORD@host.
            // The password may itself hold an `@`; the host is what follows the
            // last one.
            mk(
                r#"\b[A-Za-z][A-Za-z0-9+.\-]{1,30}://[^\s:/@'"<>]{1,128}:([^\s/'"<>]{1,256})@[^\s/@'"<>]+"#,
                1,
                None,
                SecretKind::ConnectionPassword,
                not_placeholder,
            ),
            // A secret written as a key and a value, in prose, config or JSON
            // text: `admin_password: x`, `Master Key = x`, `"api_key": "x"`.
            mk(
                r#"(?i)\b([A-Za-z0-9_\-]{0,40}(?:password|passwd|passphrase|secret|token|api[ _\-]?key|access[ _\-]?key|private[ _\-]?key|master[ _\-]?key|encryption[ _\-]?key|signing[ _\-]?key|credentials?))["']?[ \t]*[:=][ \t]*["']?([^\s"'`,;]{6,})"#,
                2,
                Some(1),
                SecretKind::CredentialValue,
                reads_as_a_secret,
            ),
            // A user and password pair after a credentials key, as logs write
            // it: `credentials: admin / x`, `credentials=admin:x`.
            mk(
                r#"(?i)\bcredentials?["']?[ \t]*[:=][ \t]*["']?[^\s"'/:]{1,64}[ \t]*[/:][ \t]*([^\s"'`,;/]{6,})"#,
                1,
                None,
                SecretKind::CredentialValue,
                reads_as_a_secret,
            ),
            // A flag-like token: a short name, then braces around a value with
            // an underscore and a digit (`NAME{s0me_v4lue}`). Not when the
            // name is a variable or a macro (`$ENV{...}`, `\cmd{...}`).
            mk(
                r"(?:^|[^A-Za-z0-9_$%@#\\{])([A-Za-z][A-Za-z0-9]{1,15}\{[A-Za-z0-9_\-!@#$%^&*.?+=]{6,100}\})",
                1,
                None,
                SecretKind::FlagToken,
                flag_body,
            ),
        ]
    })
}

fn always(_: &str) -> bool {
    true
}

fn has_digit(value: &str) -> bool {
    value.bytes().any(|b| b.is_ascii_digit())
}

fn flag_body(value: &str) -> bool {
    let body = value
        .split_once('{')
        .map(|(_, body)| body)
        .unwrap_or_default();
    body.contains('_') && has_digit(body)
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
    if !not_placeholder(value)
        || value.contains("://")
        || !value.chars().any(|c| c.is_ascii_alphanumeric())
    {
        return false;
    }
    if value.starts_with('/') || value.starts_with("./") || value.starts_with("~/") {
        return false;
    }
    let symbol = value
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !matches!(c, '-' | '_' | '.'));
    has_digit(value) || symbol || value.chars().count() >= 12
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

/// A secret span in a text, by byte offsets.
#[derive(Debug, Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
}

/// Every secret span in `text`, and what was found, into `findings`.
fn secret_spans(text: &str, findings: &mut SecretFindings) -> Vec<Span> {
    let mut spans = Vec::new();
    for pattern in patterns() {
        for caps in pattern.re.captures_iter(text) {
            let Some(value) = caps.get(pattern.value) else {
                continue;
            };
            if let Some(key) = pattern.key.and_then(|group| caps.get(group)) {
                if non_secret_token_key(&normalized_key(key.as_str())) {
                    continue;
                }
            }
            if !(pattern.accept)(value.as_str()) {
                continue;
            }
            findings.found(pattern.kind, value.as_str());
            spans.push(Span {
                start: value.start(),
                end: value.end(),
            });
        }
    }
    spans
}

/// `text` with every span, and every other occurrence of a known secret
/// value, replaced by [`MASK`]. `None` when nothing in it is secret.
fn masked_text(text: &str, known: &BTreeSet<String>) -> Option<String> {
    let mut scratch = SecretFindings::default();
    let mut spans = secret_spans(text, &mut scratch);
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
    secret_spans(text, &mut findings);
    if findings.is_empty() {
        return None;
    }
    let masked = masked_text(text, &findings.values).unwrap_or_else(|| text.to_string());
    Some((masked, findings))
}

/// The JSON keys a structured secret is kept under (`password`, `apiKey`,
/// `client_secret`), excluding paging and progress handles.
fn secret_key(key: &str) -> bool {
    crate::redact::sensitive_key(key) && !non_secret_token_key(&normalized_key(key))
}

/// The keys whose string value is base64 (a resource `blob`, the `data` of
/// an image or audio block). Looked into only when it decodes to text.
fn base64_key(key: &str) -> bool {
    matches!(key, "blob" | "data")
}

fn decoded_text(encoded: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// A structured secret: a string under a secret's key that is not empty, a
/// placeholder, a boolean-ish word or a path.
fn structured_secret(key: &str, value: &str) -> bool {
    if !secret_key(key) || value.chars().count() < 4 || !not_placeholder(value) {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    !matches!(
        lower.as_str(),
        "true"
            | "false"
            | "null"
            | "none"
            | "required"
            | "optional"
            | "string"
            | "hidden"
            | "masked"
            | "unset"
            | "empty"
    ) && !value.starts_with('/')
        && !value.contains("://")
}

fn scan_value(value: &Value, key: Option<&str>, findings: &mut SecretFindings) {
    match value {
        Value::String(text) => {
            if key.is_some_and(|key| structured_secret(key, text)) {
                findings.found(SecretKind::CredentialValue, text);
                return;
            }
            if key.is_some_and(base64_key) {
                if let Some(decoded) = decoded_text(text) {
                    secret_spans(&decoded, findings);
                }
            }
            secret_spans(text, findings);
        }
        Value::Array(items) => {
            for item in items {
                scan_value(item, None, findings);
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                scan_value(item, Some(key), findings);
            }
        }
        _ => {}
    }
}

fn mask_value(value: &mut Value, key: Option<&str>, known: &BTreeSet<String>) {
    match value {
        Value::String(text) => {
            if key.is_some_and(|key| structured_secret(key, text)) {
                *text = MASK.to_string();
                return;
            }
            if key.is_some_and(base64_key) {
                if let Some(decoded) = decoded_text(text) {
                    if let Some(masked) = masked_text(&decoded, known) {
                        *text = base64::engine::general_purpose::STANDARD.encode(masked);
                        return;
                    }
                }
            }
            if let Some(masked) = masked_text(text, known) {
                *text = masked;
            }
        }
        Value::Array(items) => {
            for item in items {
                mask_value(item, None, known);
            }
        }
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                mask_value(item, Some(key), known);
            }
        }
        _ => {}
    }
}

/// The parts of a message that carry content to the client.
const CONTENT_FIELDS: &[&str] = &["result", "error", "params"];

/// What secret-shaped values a server message (one JSON-RPC object) carries
/// in its `result`, `error` or `params`. Read only.
pub fn scan_message(message: &Value) -> SecretFindings {
    let mut findings = SecretFindings::default();
    if let Some(object) = message.as_object() {
        for field in CONTENT_FIELDS {
            if let Some(value) = object.get(*field) {
                scan_value(value, None, &mut findings);
            }
        }
    }
    findings
}

/// Mask, in place, what [`scan_message`] found in `message`: each secret
/// value is replaced by [`MASK`], everything else (the id, the shape, the
/// other text) is left as it was.
pub fn mask_message(message: &mut Value, findings: &SecretFindings) {
    if let Some(object) = message.as_object_mut() {
        for field in CONTENT_FIELDS {
            if let Some(value) = object.get_mut(*field) {
                mask_value(value, None, &findings.values);
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

/// The word that makes a location read as secret material
/// (`internal://credentials`, `vault://master_key`), if any.
fn secret_location_word(decoded: &str) -> Option<String> {
    let lower = decoded.to_ascii_lowercase();
    if let Some((scheme, _)) = lower.split_once("://") {
        if matches!(scheme, "internal" | "private" | "secret" | "secrets") {
            return Some(format!("{scheme}://"));
        }
    }
    let words: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
        .collect();
    const WORDS: &[&str] = &[
        "credential",
        "credentials",
        "secret",
        "secrets",
        "password",
        "passwords",
        "passwd",
        "passphrase",
        "token",
        "tokens",
        "apikey",
        "apikeys",
        "privatekey",
        "masterkey",
    ];
    const KEY_OWNERS: &[&str] = &[
        "api",
        "private",
        "master",
        "signing",
        "encryption",
        "access",
    ];
    for (i, word) in words.iter().enumerate() {
        if WORDS.contains(word) {
            return Some((*word).to_string());
        }
        if matches!(*word, "key" | "keys") && i > 0 && KEY_OWNERS.contains(&words[i - 1]) {
            return Some(format!("{} {word}", words[i - 1]));
        }
    }
    None
}

/// Inspect the location a client `resources/read` asks for.
///
/// Refused (in guard and kill): a path that climbs out of its root (plain or
/// percent-encoded), a secret store on disk, a credential in the URI, the
/// cloud metadata service, and what the tool-call rules refuse in an
/// argument. Alerted only: the host's own loopback or private network, a
/// location that names secret material, and one the server never announced
/// (`catalog`, after a listing was heard). Those are not refused because an
/// ordinary server can name its resources that way, and whatever secret such
/// a read returns is masked in the answer.
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
    if let Some(word) = secret_location_word(&decoded) {
        push(
            format!("the resource location names secret material (`{word}`)"),
            false,
        );
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

    #[test]
    fn a_secret_looking_or_local_location_is_alerted_not_refused() {
        for (uri, why) in [
            ("internal://credentials", "internal://"),
            ("vault://master_key", "master key"),
            ("config://auth_tokens", "tokens"),
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
}
