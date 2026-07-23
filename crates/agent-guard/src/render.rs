//! Human/JSON rendering of a command verdict, shared so Community's
//! `innerwarden check` and Active Defence's `innerwarden check` print byte-identical
//! output, the "learn once, upgrade never relearns" promise starts with the core
//! `check` verb looking the same in both products.

use serde_json::Value;

/// Render a verdict for the terminal. `as_json` prints the full machine JSON (what
/// a hook/automation consumes); the default is a short, human-readable summary so
/// a person is not buried in an ATR/MITRE JSON wall on their first `check`. Pure.
pub fn render_verdict(command: &str, verdict: &Value, as_json: bool) -> String {
    if as_json {
        return serde_json::to_string_pretty(verdict).unwrap_or_default();
    }
    let rec = verdict
        .get("recommendation")
        .and_then(|r| r.as_str())
        .unwrap_or("allow");
    let (icon, word) = match rec {
        "deny" => ("🚫", "DENY"),
        "review" => ("⚠️", "REVIEW"),
        _ => ("✓", "ALLOW"),
    };
    let mut out = format!("{icon} {word}");
    if let Some(r) = verdict.get("risk_score").and_then(|r| r.as_i64()) {
        out.push_str(&format!("  (risk {r})"));
    }
    out.push_str(&format!("\n   {command}"));
    let reason = verdict
        .get("explanation")
        .and_then(|e| e.as_str())
        .unwrap_or("")
        .trim();
    if !reason.is_empty() {
        out.push_str(&format!("\n   {reason}"));
    }
    if rec == "deny" || rec == "review" {
        out.push_str("\n   (run with --json for the full ATR / OWASP-Agentic detail)");
    }
    out
}

/// True when a verdict's recommendation is `deny` (the CLI exits 1 on this so a
/// PreToolUse hook / a `check "$CMD" || ...` gate can block on the exit code).
pub fn is_deny(verdict: &Value) -> bool {
    verdict.get("recommendation").and_then(|r| r.as_str()) == Some("deny")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn render_verdict_human_default() {
        let v = json!({"recommendation":"deny","risk_score":90,"explanation":"pipe to shell"});
        let h = render_verdict("curl x | bash", &v, false);
        assert!(h.contains("🚫") && h.contains("DENY") && h.contains("risk 90"));
        assert!(h.contains("curl x | bash") && h.contains("pipe to shell"));
        assert!(h.contains("--json"), "deny hints at --json for detail");
        assert!(
            !h.contains("atr_matches"),
            "human output is NOT the JSON wall"
        );
    }

    #[test]
    fn render_verdict_allow_and_review() {
        let a = render_verdict("git status", &json!({"recommendation":"allow"}), false);
        assert!(a.contains("✓") && a.contains("ALLOW") && !a.contains("--json"));
        let r = render_verdict("x", &json!({"recommendation":"review"}), false);
        assert!(r.contains("⚠️") && r.contains("REVIEW"));
    }

    #[test]
    fn render_verdict_json_is_machine_output() {
        let v = json!({"recommendation":"deny","atr_matches":[1,2]});
        let j = render_verdict("x", &v, true);
        assert!(j.contains("atr_matches") && j.contains("recommendation"));
        assert_eq!(serde_json::from_str::<Value>(&j).unwrap(), v);
    }

    #[test]
    fn is_deny_only_on_deny() {
        assert!(is_deny(&json!({"recommendation":"deny"})));
        assert!(!is_deny(&json!({"recommendation":"review"})));
        assert!(!is_deny(&json!({"recommendation":"allow"})));
        assert!(!is_deny(&json!({})));
    }
}
