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
    /// When set, only this capture group is masked (keeps the `key=` prefix so
    /// the shape is still readable); otherwise the whole match is masked.
    group: Option<usize>,
}

fn patterns() -> &'static [Pattern] {
    static P: OnceLock<Vec<Pattern>> = OnceLock::new();
    P.get_or_init(|| {
        let mk = |re: &str, group: Option<usize>| Pattern {
            re: Regex::new(re).expect("static redaction regex"),
            group,
        };
        vec![
            // PEM private keys (whole block header, enough to flag+mask).
            mk(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", None),
            // AWS access key id.
            mk(r"AKIA[0-9A-Z]{16}", None),
            // Bearer / authorization tokens.
            mk(r"(?i)bearer\s+[A-Za-z0-9._\-]{16,}", None),
            // key=value secrets: password / passwd / token / secret / api[_-]key.
            mk(
                r#"(?i)(password|passwd|token|secret|api[_-]?key|access[_-]?key)\s*[=:]\s*['"]?([^\s'"]{6,})"#,
                Some(2),
            ),
            // Provider API tokens by distinctive prefix, caught even when pasted
            // bare (not in a key=value), which is how an AI agent most often leaks
            // one into a shell command (`curl -H "Authorization: sk-…"`, a raw arg).
            mk(r"sk-[A-Za-z0-9_\-]{20,}", None), // OpenAI (incl. sk-proj-…)
            mk(r"gh[opsur]_[A-Za-z0-9]{20,}", None), // GitHub PAT / OAuth / server tokens
            mk(r"github_pat_[A-Za-z0-9_]{20,}", None), // GitHub fine-grained PAT
            mk(r"xox[baprs]-[A-Za-z0-9\-]{10,}", None), // Slack
            mk(r"AIza[0-9A-Za-z_\-]{35}", None), // Google API key
            // JWT (three base64url segments).
            mk(r"eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}", None),
            // US SSN.
            mk(r"\b\d{3}-\d{2}-\d{4}\b", None),
            // 16-digit card number (grouped or not).
            mk(r"\b(?:\d[ -]?){15}\d\b", None),
        ]
    })
}

const MASK: &str = "[REDACTED]";

fn sensitive_key(key: &str) -> bool {
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
                .filter_map(|c| match p.group {
                    Some(g) => c.get(g).map(|m| (m.start(), m.end())),
                    None => c.get(0).map(|m| (m.start(), m.end())),
                })
                .collect();
        for (start, end) in spans.into_iter().rev() {
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
