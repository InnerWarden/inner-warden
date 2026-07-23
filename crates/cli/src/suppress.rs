//! User suppression - the "stop bugging me about this" layer.
//!
//! A guardrail that cries wolf and cannot be quieted gets uninstalled. So the user
//! can, locally and immediately (no upgrade), tell the guard to stand down on
//! things they trust, at four granularities:
//!   - an exact command or a glob (`tar czf *`)  -> `innerwarden allow`
//!   - an ATR rule id (`ATR-2026-051`)           -> `innerwarden mute`
//!   - an ATR category (`privilege-escalation`)  -> `innerwarden mute`
//!
//! Applied AFTER the deterministic rules but BEFORE the LLM second opinion and the
//! notification, so a suppressed command neither escalates (no cost) nor alerts.
//! Safety: an `allow` is an explicit user trust and forces `allow`. A `mute` only
//! downgrades to `allow` when EVERY reason the verdict flagged is muted - if any
//! non-muted danger signal remains (e.g. a base `download_and_execute`), the
//! verdict stands. Muting can never silently clear a command that still has an
//! un-muted reason to worry. All of this is pure and unit-tested.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The user's suppression config (TOML).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SuppressConfig {
    /// Command glob patterns that are force-allowed.
    #[serde(default)]
    pub allow: Vec<String>,
    /// ATR rule ids whose match no longer counts against a command.
    #[serde(default)]
    pub mute_rules: Vec<String>,
    /// ATR categories whose match no longer counts.
    #[serde(default)]
    pub mute_categories: Vec<String>,
}

impl SuppressConfig {
    pub fn from_toml(s: &str) -> SuppressConfig {
        toml::from_str(s).unwrap_or_default()
    }
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }
}

/// Minimal glob match: `*` matches any (possibly empty) run of characters; every
/// other character is literal. No pattern (no `*`) means an exact-string match.
/// Pure.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text; // no wildcard -> exact
    }
    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !text[pos..].starts_with(part) {
                return false;
            }
            pos += part.len();
        } else if i == parts.len() - 1 {
            // last non-empty part must be a suffix at/after pos
            return text[pos..].ends_with(part);
        } else {
            match text[pos..].find(part) {
                Some(idx) => pos += idx + part.len(),
                None => return false,
            }
        }
    }
    true
}

/// The verdict when a command is suppressed by an explicit user rule.
fn user_allow(verdict: &Value, reason: &str) -> Value {
    let mut out = verdict.clone();
    if let Some(obj) = out.as_object_mut() {
        obj.insert("recommendation".into(), json!("allow"));
        obj.insert("decided_by".into(), json!("user"));
        let base = verdict
            .get("explanation")
            .and_then(|e| e.as_str())
            .unwrap_or("");
        obj.insert(
            "explanation".into(),
            json!(format!("{base} [suppressed: {reason}]").trim()),
        );
    }
    out
}

/// Apply user suppression to a rules verdict. Returns an overriding `allow` verdict
/// (`decided_by = user`) when the command is force-allowed or fully muted, else
/// `None` to keep the original verdict. Pure/tested.
pub fn apply(command: &str, verdict: &Value, cfg: &SuppressConfig) -> Option<Value> {
    // 1. Explicit allow-list: the user trusts this command pattern.
    if let Some(pat) = cfg.allow.iter().find(|p| glob_match(p, command)) {
        return Some(user_allow(verdict, &format!("allow {pat}")));
    }
    // 2. Mute: only relevant for a flagged verdict with mutes configured.
    let rec = verdict.get("recommendation").and_then(|r| r.as_str());
    if !matches!(rec, Some("deny") | Some("review")) {
        return None;
    }
    if cfg.mute_rules.is_empty() && cfg.mute_categories.is_empty() {
        return None;
    }
    let muted_cat = |c: &str| cfg.mute_categories.iter().any(|m| m == c);
    let muted_rule = |r: &str| cfg.mute_rules.iter().any(|m| m == r);

    // Every ATR match must be muted (by rule id or category)...
    let atr = verdict
        .get("atr_matches")
        .and_then(|a| a.as_array())
        .cloned()
        .unwrap_or_default();
    let mut matched_mutes = Vec::new();
    let all_atr_muted = !atr.is_empty()
        && atr.iter().all(|m| {
            let rule = m.get("rule_id").and_then(|r| r.as_str()).unwrap_or("");
            let cat = m.get("category").and_then(|c| c.as_str()).unwrap_or("");
            if !rule.is_empty() && muted_rule(rule) {
                matched_mutes.push(format!("rule {rule}"));
                true
            } else if !cat.is_empty() && muted_cat(cat) {
                matched_mutes.push(format!("category {cat}"));
                true
            } else {
                false
            }
        });
    // ...and no BASE (non-ATR) danger signal may remain: a heuristic like
    // `download_and_execute` is not something a rule/category mute can clear, so
    // its presence keeps the verdict. The `atr:<category>` signals are already
    // covered by `all_atr_muted` above.
    let signals = verdict
        .get("signals")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();
    let has_base_signal = signals.iter().any(|s| {
        let name = s.get("signal").and_then(|n| n.as_str()).unwrap_or("");
        !name.starts_with("atr:")
    });

    if all_atr_muted && !has_base_signal {
        matched_mutes.sort();
        matched_mutes.dedup();
        return Some(user_allow(
            verdict,
            &format!("mute {}", matched_mutes.join("; ")),
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_exact_prefix_suffix_middle() {
        assert!(glob_match("git status", "git status"));
        assert!(!glob_match("git status", "git stat"));
        assert!(glob_match("tar czf *", "tar czf /tmp/backup.tgz /home"));
        assert!(!glob_match("tar czf *", "rm -rf /"));
        assert!(glob_match("* | bash", "curl x | bash"));
        assert!(glob_match("curl*bash", "curl http://x | bash"));
        assert!(!glob_match("curl*bash", "curl http://x | sh"));
        assert!(glob_match("*", "anything at all"));
    }

    fn deny(cats: &[&str]) -> Value {
        json!({
            "recommendation": "deny",
            "explanation": "dangerous",
            "atr_matches": cats.iter().map(|c| json!({"rule_id": format!("ATR-{c}"), "category": c})).collect::<Vec<_>>(),
            "signals": cats.iter().map(|c| json!({"signal": format!("atr:{c}")})).collect::<Vec<_>>(),
        })
    }

    #[test]
    fn allow_glob_forces_allow_with_user_attribution() {
        let cfg = SuppressConfig {
            allow: vec!["tar czf *".into()],
            ..Default::default()
        };
        let v = apply("tar czf /tmp/b.tgz /home", &deny(&["x"]), &cfg).unwrap();
        assert_eq!(v["recommendation"], "allow");
        assert_eq!(v["decided_by"], "user");
        assert!(v["explanation"]
            .as_str()
            .unwrap()
            .contains("suppressed: allow tar czf"));
        // non-matching command is untouched
        assert!(apply("rm -rf /", &deny(&["x"]), &cfg).is_none());
    }

    #[test]
    fn mute_category_clears_only_when_all_reasons_muted() {
        let cfg = SuppressConfig {
            mute_categories: vec!["privilege-escalation".into()],
            ..Default::default()
        };
        // sole reason muted -> allowed
        let v = apply("chmod 777 x", &deny(&["privilege-escalation"]), &cfg).unwrap();
        assert_eq!(v["recommendation"], "allow");
        assert_eq!(v["decided_by"], "user");
        // a second, un-muted category remains -> verdict stands
        assert!(apply(
            "x",
            &deny(&["privilege-escalation", "tool-poisoning"]),
            &cfg
        )
        .is_none());
    }

    #[test]
    fn mute_rule_id_clears_by_rule() {
        let cfg = SuppressConfig {
            mute_rules: vec!["ATR-priv".into()],
            ..Default::default()
        };
        let verdict = apply("x", &deny(&["priv"]), &cfg).unwrap();
        assert!(verdict["recommendation"] == "allow");
        assert!(verdict["explanation"]
            .as_str()
            .unwrap()
            .contains("rule ATR-priv"));
    }

    #[test]
    fn mute_provenance_only_names_matches_that_caused_suppression() {
        let cfg = SuppressConfig {
            mute_rules: vec!["ATR-exact".into()],
            mute_categories: vec!["matched-category".into(), "unrelated-category".into()],
            ..Default::default()
        };
        let verdict = json!({
            "recommendation": "deny",
            "explanation": "dangerous",
            "atr_matches": [
                {"rule_id": "ATR-exact", "category": "other"},
                {"rule_id": "ATR-category", "category": "matched-category"}
            ],
            "signals": [
                {"signal": "atr:other"},
                {"signal": "atr:matched-category"}
            ]
        });

        let muted = apply("x", &verdict, &cfg).unwrap();
        let explanation = muted["explanation"].as_str().unwrap();
        assert!(explanation.contains("rule ATR-exact"));
        assert!(explanation.contains("category matched-category"));
        assert!(!explanation.contains("unrelated-category"));
    }

    #[test]
    fn mute_does_not_clear_a_base_danger_signal() {
        // deny driven by a BASE heuristic (download_and_execute), not an ATR rule:
        // muting a category must NOT clear it.
        let v = json!({
            "recommendation": "deny",
            "atr_matches": [{"rule_id": "ATR-x", "category": "tool-poisoning"}],
            "signals": [{"signal": "download_and_execute"}, {"signal": "atr:tool-poisoning"}],
        });
        let cfg = SuppressConfig {
            mute_categories: vec!["tool-poisoning".into()],
            ..Default::default()
        };
        assert!(
            apply("curl x | bash", &v, &cfg).is_none(),
            "base signal keeps the block"
        );
    }

    #[test]
    fn allow_and_review_untouched_without_config() {
        assert!(apply(
            "ls",
            &json!({"recommendation": "allow"}),
            &SuppressConfig::default()
        )
        .is_none());
        assert!(apply("x", &deny(&["a"]), &SuppressConfig::default()).is_none());
    }

    #[test]
    fn config_toml_round_trip() {
        let cfg = SuppressConfig {
            allow: vec!["tar czf *".into()],
            mute_rules: vec!["ATR-2026-051".into()],
            mute_categories: vec!["privilege-escalation".into()],
        };
        assert_eq!(SuppressConfig::from_toml(&cfg.to_toml()), cfg);
        assert_eq!(SuppressConfig::from_toml(""), SuppressConfig::default());
    }
}
