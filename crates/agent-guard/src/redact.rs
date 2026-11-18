//! Secret / PII redaction transform (OWASP Agentic **ASI07, Memory Leakage**).
//!
//! An AI agent that reads a tool response, a retrieved document, or a file and
//! carries it into its context window leaks whatever secrets/PII that content
//! held into the model's short-term memory (and often into downstream logs and
//! replies). This transform scrubs the primary leakage vector, obvious secrets
//! and PII, from any text crossing INTO the agent's context, so injected
//! credentials never become part of what the model remembers.
//!
//! Scope note (honest): this covers the primary vector (secrets/PII in
//! text-crossing-the-boundary). It is NOT a full memory-store scrubber; a
//! persistent long-term memory store needs its own turn-level scrubbing.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

/// Result of redacting a blob: the scrubbed text and how many spans were masked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redaction {
    pub text: String,
    pub count: usize,
}

struct Pattern {
    re: Regex,
    /// The capture groups that hold the secret, in order: the first one that
    /// took part in the match is masked (keeps the `key=` prefix, a URL's user
    /// name or a flag readable). Empty: the whole match is masked.
    groups: &'static [usize],
}

/// Names a program reads a password from on its own command line, as a short
/// flag. Kept to programs where that flag means a password, so `-p` of `mkdir`
/// or `ssh` is never touched.
const PASSWORD_FLAG_PROGRAMS: &str =
    r"(?:mysql|mariadb|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck|mariadb-dump|sshpass)";

fn patterns() -> &'static [Pattern] {
    static P: OnceLock<Vec<Pattern>> = OnceLock::new();
    P.get_or_init(|| {
        let mk = |re: &str, groups: &'static [usize]| Pattern {
            re: Regex::new(re).expect("static redaction regex"),
            groups,
        };
        // A value as a shell or a config writes it: quoted whole, or up to the
        // next blank or quote. Groups: 1 single-quoted, 2 double-quoted, 3 bare.
        let value = r#"(?:'([^']*)'|"([^"]*)"|([^\s'"]+))"#;
        vec![
            // PEM private keys (whole block header, enough to flag+mask).
            mk(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", &[]),
            // AWS access key id.
            mk(r"AKIA[0-9A-Z]{16}", &[]),
            // A password in a URL: scheme://user:PASSWORD@host. The user name
            // stays, the password goes, whatever its length.
            mk(
                r#"(?i)\b[a-z][a-z0-9+.\-]*://[^\s/:@'"]*:([^\s/@'"]+)@"#,
                &[1],
            ),
            // Authorization (and Proxy-Authorization) headers, any scheme:
            // Basic <base64>, Bearer <token>, Token <x>, or a bare value.
            mk(
                r#"(?i)authorization['"]?\s*[:=]\s*(?:(?:basic|bearer|token|digest|negotiate)\s+)?([^\s'",]+)"#,
                &[1],
            ),
            // Bearer tokens outside a header.
            mk(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}", &[]),
            // A long flag that takes a secret, with a blank or `=`:
            // --password VALUE, --token=VALUE, --api-key 'VALUE'. Short values too.
            mk(
                &format!(
                    r"(?i)(?:^|[\s'\x22])--?(?:password|passwd|pass|pwd|token|auth[_-]?token|access[_-]?token|secret|client[_-]?secret|api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key)(?:\s+|=){value}"
                ),
                &[1, 2, 3],
            ),
            // A short flag that is a password only for some programs:
            // mysql -pVALUE, mysql -p VALUE, sshpass -p VALUE.
            mk(
                &format!(
                    r"(?i:\b{PASSWORD_FLAG_PROGRAMS})\b[^|;&\n]*?\s-p\s*(?:'([^']*)'|\x22([^\x22]*)\x22|([^\s'\x22\-][^\s'\x22]*))"
                ),
                &[1, 2, 3],
            ),
            // curl/wget style user:password (a URL after -u is the URL rule's).
            mk(
                r#"(?:^|\s)(?:-u|--user|--proxy-user)\s+['"]?[^\s:'"/]+:([^\s'"/][^\s'"]*|/[^\s'"/][^\s'"]*)"#,
                &[1],
            ),
            // key=value / key: value secrets, quoted or not, any length:
            // password / passwd / token / secret / api[_-]key / access[_-]key.
            mk(
                &format!(
                    r#"(?i)(?:password|passwd|token|secret|api[_-]?key|access[_-]?key)['"]?\s*[=:]\s*{value}"#
                ),
                &[1, 2, 3],
            ),
            // Provider API tokens by distinctive prefix, caught even when pasted
            // bare (not in a key=value), which is how an AI agent most often leaks
            // one into a shell command (`curl -H "Authorization: sk-…"`, a raw arg).
            mk(r"sk-[A-Za-z0-9_\-]{20,}", &[]), // OpenAI (incl. sk-proj-…)
            mk(r"gh[opsur]_[A-Za-z0-9]{20,}", &[]), // GitHub PAT / OAuth / server tokens
            mk(r"github_pat_[A-Za-z0-9_]{20,}", &[]), // GitHub fine-grained PAT
            mk(r"xox[baprs]-[A-Za-z0-9\-]{10,}", &[]), // Slack
            mk(r"AIza[0-9A-Za-z_\-]{35}", &[]), // Google API key
            // JWT (three base64url segments).
            mk(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}", &[]),
            // US SSN.
            mk(r"\b\d{3}-\d{2}-\d{4}\b", &[]),
            // 16-digit card number (grouped or not).
            mk(r"\b(?:\d[ -]?){15}\d\b", &[]),
        ]
    })
}

const MASK: &str = "[REDACTED]";

pub(crate) fn sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    matches!(
        normalized.as_str(),
        "password"
            | "passwd"
            | "token"
            | "secret"
            | "apikey"
            | "accesskey"
            | "authorization"
            | "credential"
            | "credentials"
            | "privatekey"
    ) || normalized.ends_with("password")
        || normalized.ends_with("passwd")
        || normalized.ends_with("token")
        || normalized.ends_with("secret")
        || normalized.ends_with("apikey")
        || normalized.ends_with("accesskey")
        || normalized.ends_with("privatekey")
        || normalized.ends_with("credential")
        || normalized.ends_with("credentials")
}

/// Redact a JSON value structurally. Values under secret-bearing keys are
/// replaced even when they are ordinary strings with no provider-specific
/// prefix; all other string leaves still pass through [`redact_secrets`].
pub fn redact_json_secrets(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(redact_secrets(text).text),
        Value::Array(values) => Value::Array(values.iter().map(redact_json_secrets).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| {
                    let value = if sensitive_key(key) && !value.is_null() {
                        Value::String(MASK.to_string())
                    } else {
                        redact_json_secrets(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Scrub obvious secrets and PII from `input`, returning the redacted text and
/// the number of spans masked. Deterministic and allocation-light on the common
/// (nothing-to-redact) path.
pub fn redact_secrets(input: &str) -> Redaction {
    let mut text = input.to_string();
    let mut count = 0usize;
    for p in patterns() {
        // Collect matches first (mutating while iterating a live regex is awkward);
        // replace group-or-whole, right-to-left so byte offsets stay valid.
        let spans: Vec<(usize, usize)> =
            p.re.captures_iter(&text)
                .filter_map(|c| {
                    if p.groups.is_empty() {
                        c.get(0)
                    } else {
                        p.groups.iter().find_map(|&g| c.get(g))
                    }
                    .map(|m| (m.start(), m.end()))
                })
                .collect();
        for (start, end) in spans.into_iter().rev() {
            // An earlier pattern already masked this span (a header caught as
            // Authorization and again as Bearer, say): nothing left to hide.
            // An empty quoted value has nothing to hide either.
            if start == end || &text[start..end] == MASK {
                continue;
            }
            text.replace_range(start..end, MASK);
            count += 1;
        }
    }
    Redaction { text, count }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_common_secrets_and_pii() {
        let raw =
            "here is my key AKIA1234567890ABCDEF and password=hunter2secret and ssn 123-45-6789";
        let r = redact_secrets(raw);
        assert!(r.count >= 3, "expected >=3 redactions, got {}", r.count);
        assert!(!r.text.contains("AKIA1234567890ABCDEF"));
        assert!(!r.text.contains("hunter2secret"));
        assert!(!r.text.contains("123-45-6789"));
        // The key= prefix stays so the shape is still readable.
        assert!(r.text.contains("password=[REDACTED]"));
    }

    #[test]
    fn leaves_clean_text_untouched() {
        let r = redact_secrets("ls -la /home/user/project && git status");
        assert_eq!(r.count, 0);
        assert_eq!(r.text, "ls -la /home/user/project && git status");
    }

    #[test]
    fn masks_bare_provider_tokens() {
        // The shapes an AI agent pastes raw into a shell command, masked even
        // without a `key=` prefix so they never reach the graph file or the LLM.
        // The tokens are ASSEMBLED from fragments at runtime (prefix + body split)
        // so no contiguous provider-token literal lives in the source, these are
        // synthetic, and the split also keeps GitHub push-protection quiet.
        let openai = format!("sk-proj{}", "-FAKEfake1111fake2222fake3333xyz789");
        let github = format!("gh{}", "p_FAKEfake1111fake2222fake3333xyz789");
        let github_pat = format!("github{}", "_pat_FAKEfake1111fake2222fake3333xyz789");
        let slack = format!("xox{}", "b-000000000-FAKEfake1111fake2222");
        let google = format!("AIz{}", "aFAKEfake1111fake2222fake3333xyz789ABCDE");
        let cases = [
            format!("curl -H \"Authorization: {openai}\" x"),
            format!("git remote set-url o https://{github}@h"),
            format!("export TOK={github_pat}"),
            format!("slack --token {slack}"),
            format!("gcloud --key {google}"),
        ];
        for (raw, tok) in cases.iter().zip([
            openai.as_str(),
            github.as_str(),
            github_pat.as_str(),
            slack.as_str(),
            google.as_str(),
        ]) {
            let r = redact_secrets(raw);
            assert!(r.count >= 1, "expected a redaction in {raw:?}");
            assert!(r.text.contains("[REDACTED]"), "masked something in {raw:?}");
            assert!(!r.text.contains(tok), "leaked {tok} from {raw:?}");
        }
    }

    #[test]
    fn masks_pem_private_key_and_jwt() {
        let raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\ntoken: eyJhbGciOi.eyJzdWIiOiI.SflKxwRJ";
        let r = redact_secrets(raw);
        assert!(!r.text.contains("BEGIN RSA PRIVATE KEY"));
        assert!(r.count >= 2);
    }

    /// Every secret below is assembled at runtime, so no credential-shaped
    /// literal sits whole in the source.
    fn pw() -> String {
        format!("hun{}", "ter2")
    }

    #[test]
    fn masks_a_password_in_a_url_and_keeps_the_user() {
        let pw = pw();
        for raw in [
            format!("psql postgres://app:{pw}@db.internal:5432/main"),
            format!("git clone https://bob:{pw}@git.example/x.git"),
            format!("curl 'https://u:{pw}@api.example/v1'"),
            format!("redis-cli -u redis://:{pw}@cache:6379"),
        ] {
            let r = redact_secrets(&raw);
            assert!(!r.text.contains(&pw), "leaked from {raw:?}: {}", r.text);
            assert!(r.text.contains(":[REDACTED]@"), "{}", r.text);
        }
        let r = redact_secrets(&format!("psql postgres://app:{pw}@db/main"));
        assert!(r.text.contains("postgres://app:"), "user stays: {}", r.text);
        // A URL with no password is left alone.
        let clean = "curl https://api.example:8443/v1 && ssh git@host";
        assert_eq!(redact_secrets(clean).text, clean);
    }

    #[test]
    fn masks_a_secret_flag_written_with_a_blank() {
        let pw = pw();
        for raw in [
            format!("app login --password {pw}"),
            format!("app login --password x{pw}"),
            format!("deploy --token {pw} --region eu"),
            format!("cli --api-key '{pw} with space'"),
            format!("cli --client-secret=\"{pw}\""),
            format!("openssl enc -pass pass:{pw} -in f"),
        ] {
            let r = redact_secrets(&raw);
            assert!(!r.text.contains(&pw), "leaked from {raw:?}: {}", r.text);
            assert!(r.text.contains("[REDACTED]"), "{}", r.text);
        }
        // The rest of the line stays readable.
        let r = redact_secrets(&format!("deploy --token {pw} --region eu"));
        assert_eq!(r.text, "deploy --token [REDACTED] --region eu");
        // A one-character password is still a password.
        let r = redact_secrets("app login --password x");
        assert_eq!(r.text, "app login --password [REDACTED]");
        // A flag that names a file, not a secret, is left alone.
        let clean = "app login --password-file /run/pw --token-file t.txt";
        assert_eq!(redact_secrets(clean).text, clean);
    }

    #[test]
    fn masks_minus_p_only_where_it_means_a_password() {
        let pw = pw();
        for raw in [
            format!("mysql -u root -p{pw} shop"),
            format!("mysql -u root -p {pw}"),
            format!("mysqldump -uroot -p'{pw}' shop > dump.sql"),
            format!("sshpass -p {pw} ssh host"),
        ] {
            let r = redact_secrets(&raw);
            assert!(!r.text.contains(&pw), "leaked from {raw:?}: {}", r.text);
        }
        // -p of other programs, and mysql -P (port), are not passwords.
        for clean in [
            "mkdir -p build/out",
            "ssh -p 2222 host",
            "mysql -u root -P 3306 -h db",
            "mysql -u root -p -h db",
        ] {
            assert_eq!(redact_secrets(clean).text, clean, "{clean}");
        }
    }

    #[test]
    fn masks_basic_and_any_authorization_header() {
        let basic = format!("dXNl{}", "cjpodW50ZXIy");
        let short = format!("t{}", "0k");
        for (raw, secret) in [
            (
                format!("curl -H 'Authorization: Basic {basic}' https://x"),
                &basic,
            ),
            (
                format!("curl -H \"authorization: basic {basic}\" x"),
                &basic,
            ),
            (
                format!("curl -H 'Proxy-Authorization: Basic {basic}' x"),
                &basic,
            ),
            (format!("curl -H 'Authorization: Bearer {short}' x"), &short),
            (format!("curl -H 'Authorization: {short}' x"), &short),
        ] {
            let r = redact_secrets(&raw);
            assert!(
                !r.text.contains(secret.as_str()),
                "leaked from {raw:?}: {}",
                r.text
            );
        }
        let r = redact_secrets(&format!("curl -H 'Authorization: Basic {basic}' https://x"));
        assert_eq!(
            r.text,
            "curl -H 'Authorization: Basic [REDACTED]' https://x"
        );
        assert_eq!(r.count, 1, "masked once, not once per pattern");
    }

    #[test]
    fn masks_short_and_quoted_key_values() {
        let pw = pw();
        for raw in [
            "PASSWORD=ab".to_string(),
            format!("export DB_PASSWORD='{pw} two words'"),
            format!("{{\"token\": \"{pw}\"}}"),
            format!("secret: {pw}"),
        ] {
            let r = redact_secrets(&raw);
            assert!(!r.text.contains(&pw), "leaked from {raw:?}: {}", r.text);
            assert!(r.text.contains("[REDACTED]"), "{}", r.text);
        }
        assert_eq!(redact_secrets("PASSWORD=ab").text, "PASSWORD=[REDACTED]");
        let r = redact_secrets(&format!("export DB_PASSWORD='{pw} two words' && run"));
        assert_eq!(r.text, "export DB_PASSWORD='[REDACTED]' && run");
    }

    #[test]
    fn curl_user_and_password() {
        let pw = pw();
        let r = redact_secrets(&format!("curl -u admin:{pw} https://x"));
        assert_eq!(r.text, "curl -u admin:[REDACTED] https://x");
        let clean = "mysql -u root -h db && sort -u list.txt";
        assert_eq!(redact_secrets(clean).text, clean);
    }

    #[test]
    fn masks_plain_json_secret_values_by_key() {
        let value = serde_json::json!({
            "password": "hunter2secret",
            "nested": {"api-key": "ordinary-value", "safe": "hello"},
            "items": [{"access_token": "short"}]
        });
        let redacted = redact_json_secrets(&value);
        let text = redacted.to_string();
        assert!(!text.contains("hunter2secret"));
        assert!(!text.contains("ordinary-value"));
        assert!(!text.contains("short"));
        assert!(text.contains("hello"));
        assert_eq!(redacted["password"], MASK);
    }
}
