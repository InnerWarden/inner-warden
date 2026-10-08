//! What a flagged decision was reaching for, and the few words a list row
//! names its rule by. Two CLOSED tables keyed by the rule and signal ids the
//! guard itself emits (`agent-guard`'s `analyze_command`).
//!
//! Only ids whose meaning is certain are listed. A rule this table does not
//! know is `other` and has no short words of its own; the dashboard then cuts
//! the rule's own first words instead. Guessing a concern would put an offer
//! on screen for a product that does not answer the situation: a fetch from a
//! bare IP address never asks DNS, so it is not a DNS concern, however much it
//! looks like one.

/// What a decision reached for, as far as its rules say for certain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Concern {
    /// Read or searched for a credential file.
    CredentialRead,
    /// Fetched from the internet by host name.
    DomainFetch,
    /// Anything else, including every rule this table does not list.
    Other,
}

impl Concern {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CredentialRead => "credential_read",
            Self::DomainFetch => "domain_fetch",
            Self::Other => "other",
        }
    }
}

/// Rules that fire only when a command reads, or searches for, a credential.
const CREDENTIAL_READ: &[&str] = &[
    "sensitive_credential_read",
    "credential_hunt",
    "protected_secret_read",
];

/// Rules that fire only on a fetch from a host NAME: the host component of the
/// URL is matched against named hosts (paste sites, URL shorteners), so there
/// was a name to resolve. `bare_ip_fetch` is deliberately absent, and so is
/// `download_and_execute`, whose URL may be a bare address.
const DOMAIN_FETCH: &[&str] = &["fetch_exec_ephemeral_host", "fetch_exec_shortened_source"];

/// The concern of a decision, from all of its rule ids. A credential read wins
/// over a fetch: it is the more specific thing the command reached for.
pub fn concern_for(rules: &[String]) -> Concern {
    if rules
        .iter()
        .any(|rule| CREDENTIAL_READ.contains(&rule.as_str()))
    {
        return Concern::CredentialRead;
    }
    if rules
        .iter()
        .any(|rule| DOMAIN_FETCH.contains(&rule.as_str()))
    {
        return Concern::DomainFetch;
    }
    Concern::Other
}

/// A few words for a rule, for the one line under a list row.
const SHORT_WORDS: &[(&str, &str)] = &[
    ("anti_forensics", "erasing records"),
    ("bare_ip_fetch", "fetch from a bare IP address"),
    ("cloud_control_plane", "cloud control plane"),
    ("credential_exposure", "a secret in the command"),
    ("credential_hunt", "search for credentials"),
    ("dangerous_command", "dangerous command"),
    ("data_destruction", "destroys data"),
    ("destructive_command", "destructive command"),
    ("download_and_execute", "download run by a shell"),
    ("download_chmod_execute", "download made executable"),
    ("dynamic_code_execution", "data fed to an interpreter"),
    ("fetch_exec_decoder", "decoded download run"),
    ("fetch_exec_ephemeral_host", "download from a paste site"),
    ("fetch_exec_no_tls", "download without TLS run"),
    ("fetch_exec_shortened_source", "download from a short link"),
    ("fetch_exec_unanalyzable", "download run, not analysable"),
    ("guard_self_disable", "turning the guard off"),
    ("insecure_permissions", "world-writable permissions"),
    ("internal_network_target", "internal address"),
    ("kubernetes_escalation", "cluster escalation"),
    ("kubernetes_secret_read", "cluster secret read"),
    (
        "local_credential_or_kernel_tamper",
        "session or kernel tampering",
    ),
    ("obfuscated_command", "obfuscated command"),
    ("package_typosquat", "look-alike package name"),
    ("persistence_attempt", "runs again later"),
    ("persistence_install", "runs again later"),
    ("protected_secret_read", "protected secret"),
    ("reverse_shell", "reverse shell"),
    ("security_tooling_tamper", "security tool tampering"),
    ("sensitive_credential_read", "credential path"),
    ("sensitive_file_overwrite", "overwrites a sensitive file"),
    ("tls_verification_disabled", "TLS checks off"),
    ("tmp_execution", "world-writable folder"),
    ("untrusted_software_source", "untrusted software source"),
];

pub fn short_words(rule: &str) -> Option<&'static str> {
    SHORT_WORDS
        .iter()
        .find(|(id, _)| *id == rule)
        .map(|(_, words)| *words)
}

/// How the guard words each of its own reasons, by the fixed text it opens
/// with (`analyze_command` writes `format!("<this text>{detail}")`).
///
/// A decision recorded before rule ids were kept carries only those words.
/// This is the producer reading its own sentence back, the same way the
/// dashboard reads a channel from the proxy's own label prefix: a prefix is
/// listed only when it is literal in the guard's source and belongs to one
/// rule, and a test fails the moment either stops being true.
const WORDING: &[(&str, &str)] = &[
    (
        "credential exposure in executable command: ",
        "credential_exposure",
    ),
    (
        "shell data is structurally fed into a code interpreter",
        "dynamic_code_execution",
    ),
    ("reverse shell indicator: ", "reverse_shell"),
    (
        "dangerous pipeline: download piped to shell interpreter",
        "download_and_execute",
    ),
    (
        "download is staged to a file and then executed",
        "download_chmod_execute",
    ),
    ("obfuscation pattern: ", "obfuscated_command"),
    ("persistence indicator: ", "persistence_attempt"),
    ("references world-writable directory: ", "tmp_execution"),
    (
        "recursive removal of a root / system directory",
        "destructive_command",
    ),
    (
        "disabling or tampering with security monitoring: ",
        "security_tooling_tamper",
    ),
    (
        "reads sensitive credential path: ",
        "sensitive_credential_read",
    ),
    ("searches the filesystem for credentials", "credential_hunt"),
    ("dangerous command: ", "dangerous_command"),
    (
        "structure of a fetch-and-execute could not be analysed",
        "fetch_exec_unanalyzable",
    ),
];

/// The rule behind one reason's words, when the words open with the fixed
/// text of exactly one rule. `None` for anything else.
pub fn rule_from_words(words: &str) -> Option<&'static str> {
    let words = words.trim_start();
    WORDING
        .iter()
        .find(|(prefix, _)| words.starts_with(prefix))
        .map(|(_, rule)| *rule)
}

/// `text` cut at a word boundary to at most `max` characters, with an
/// ellipsis when anything was cut. Never splits a word or a character.
pub fn cut_words(text: &str, max: usize) -> String {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.chars().count() <= max {
        return text;
    }
    let mut out = String::new();
    for word in text.split(' ') {
        let next = if out.is_empty() {
            word.chars().count()
        } else {
            out.chars().count() + 1 + word.chars().count()
        };
        if next > max.saturating_sub(1) {
            break;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    if out.is_empty() {
        out = text.chars().take(max.saturating_sub(1)).collect();
    }
    format!("{out}…")
}

/// Whether a rule id is an ATR rule, the only kind `innerwarden mute` accepts
/// (`suppress::apply`: a base signal can never be muted).
pub fn is_mutable_rule(rule: &str) -> bool {
    rule.to_ascii_uppercase().starts_with("ATR-")
}

/// A title in the case a sentence uses: "High-Risk Tool Invocation" is
/// "high-risk tool invocation". A word with two or more capitals (an acronym
/// such as MCP or SSRF, or OAuth) keeps its case.
fn sentence_case(title: &str) -> String {
    title
        .split(' ')
        .map(|word| {
            if word.chars().filter(|c| c.is_uppercase()).count() >= 2 && !word.contains('-') {
                word.to_string()
            } else {
                word.to_lowercase()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A few words for an ATR rule, from its title in the rules this binary
/// ships (`rules/atr`), read once. `None` for an id those rules do not hold.
pub fn atr_short_words(rule: &str) -> Option<String> {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    static TITLES: OnceLock<HashMap<String, String>> = OnceLock::new();
    if !is_mutable_rule(rule) {
        return None;
    }
    let titles = TITLES.get_or_init(|| {
        innerwarden_agent_guard::rules::RuleEngine::load_embedded()
            .titles()
            .into_iter()
            .collect()
    });
    titles
        .get(rule)
        .map(|title| cut_words(&sentence_case(title), 40))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    #[test]
    fn an_atr_rule_is_named_by_its_title_in_sentence_case() {
        assert_eq!(
            atr_short_words("ATR-2026-099").as_deref(),
            Some("high-risk tool invocation without human…")
        );
        assert_eq!(
            sentence_case("MCP Tool Supply Chain Poisoning"),
            "MCP tool supply chain poisoning"
        );
        assert_eq!(
            sentence_case("OAuth and API Token Interception"),
            "OAuth and API token interception"
        );
        assert_eq!(atr_short_words("ATR-1999-000"), None);
        assert_eq!(atr_short_words("tmp_execution"), None);
    }

    #[test]
    fn concern_table_maps_only_listed_rules() {
        assert_eq!(
            concern_for(&rules(&["sensitive_credential_read"])),
            Concern::CredentialRead
        );
        assert_eq!(
            concern_for(&rules(&["fetch_exec_ephemeral_host"])),
            Concern::DomainFetch
        );
        // A bare IP never asks DNS; a pipe may fetch from one. Neither is a
        // DNS concern.
        assert_eq!(concern_for(&rules(&["bare_ip_fetch"])), Concern::Other);
        assert_eq!(
            concern_for(&rules(&["download_and_execute"])),
            Concern::Other
        );
        // An unknown rule, an ATR id and nothing at all are `other`.
        assert_eq!(concern_for(&rules(&["ATR-2026-001"])), Concern::Other);
        assert_eq!(concern_for(&rules(&["made_up_rule"])), Concern::Other);
        assert_eq!(concern_for(&[]), Concern::Other);
        // The credential read wins when both are present.
        assert_eq!(
            concern_for(&rules(&["fetch_exec_ephemeral_host", "credential_hunt"])),
            Concern::CredentialRead
        );
    }

    #[test]
    fn every_listed_rule_is_one_the_guard_emits() {
        // The ids the analyzer writes as `signal: "<id>"` or as a fetch
        // aggravator label. A table entry for anything else is dead text.
        let source = concat!(
            include_str!("../../agent-guard/src/mcp.rs"),
            include_str!("../../agent-guard/src/threats.rs"),
        );
        for (id, _) in SHORT_WORDS {
            assert!(
                source.contains(&format!("\"{id}\"")),
                "{id} is not emitted by the guard"
            );
        }
        for id in CREDENTIAL_READ.iter().chain(DOMAIN_FETCH) {
            assert!(short_words(id).is_some(), "{id} has no short words");
        }
    }

    #[test]
    fn every_wording_is_the_guards_own_and_names_one_rule() {
        let source = include_str!("../../agent-guard/src/mcp.rs");
        for (prefix, rule) in WORDING {
            assert!(
                source.contains(prefix.trim_end()),
                "`{prefix}` is not literal in the guard's source"
            );
            assert!(short_words(rule).is_some(), "{rule} has no short words");
            // No prefix is a prefix of another: the first match is the only one.
            for (other, _) in WORDING {
                assert!(
                    other == prefix || !other.starts_with(prefix),
                    "{prefix} shadows {other}"
                );
            }
        }
        assert_eq!(
            rule_from_words("reads sensitive credential path: `.ssh/`"),
            Some("sensitive_credential_read")
        );
        assert_eq!(
            rule_from_words("references world-writable directory: /tmp/"),
            Some("tmp_execution")
        );
        assert_eq!(rule_from_words("something the guard never says"), None);
        assert_eq!(rule_from_words(""), None);
    }

    #[test]
    fn short_words_are_short_and_cut_words_keeps_whole_words() {
        for (_, words) in SHORT_WORDS {
            assert!(words.chars().count() <= 32, "{words}");
        }
        assert_eq!(
            cut_words("references world-writable directory: /tmp/", 32),
            "references world-writable…"
        );
        assert_eq!(cut_words("short", 32), "short");
        assert_eq!(cut_words("  spaced   out  ", 32), "spaced out");
        let long = "x".repeat(50);
        assert_eq!(cut_words(&long, 10).chars().count(), 10);
    }

    #[test]
    fn only_an_atr_rule_can_be_muted() {
        assert!(is_mutable_rule("ATR-2026-051"));
        assert!(is_mutable_rule("atr-2026-051"));
        assert!(!is_mutable_rule("tmp_execution"));
    }
}
