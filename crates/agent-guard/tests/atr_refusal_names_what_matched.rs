//! A refusal by an ATR rule says what of the call matched, not only the
//! rule's title. Measured 2026-11-20 (AgentDojo): a direct message was
//! refused as "Unauthorized Financial Action" and a file deletion as
//! "Privilege Escalation", and neither reason said that the `"recipient":`
//! key or the tool name `delete_file` was what matched.

use innerwarden_agent_guard::mcp::inspect_tool_call;
use innerwarden_agent_guard::rules::RuleEngine;

/// FAILS ON REVERT of `AtrMatch::matched` in the alert's detail.
#[test]
fn the_reason_names_what_matched() {
    let engine = RuleEngine::load_embedded();
    for (tool, args, rule, said) in [
        (
            "send_direct_message",
            serde_json::json!({"recipient": "Alice", "body": "see you at noon"}),
            "ATR-2026-098",
            "(matched the arguments `\"recipient\":\"`)",
        ),
        (
            "delete_file",
            serde_json::json!({"file_id": "13"}),
            "ATR-2026-040",
            "(matched the tool name `delete_file`)",
        ),
        (
            "send_money",
            serde_json::json!({"recipient": "GB29NWBK60161331926819", "amount": 10}),
            "ATR-2026-098",
            "(matched the tool name `send_money`)",
        ),
    ] {
        let verdict = inspect_tool_call(tool, &args, Some(&engine));
        let alert = verdict
            .alerts
            .iter()
            .find(|a| a.rule == rule)
            .unwrap_or_else(|| panic!("{tool}: no {rule} in {:?}", verdict.alerts));
        assert!(alert.detail.ends_with(said), "{tool}: {}", alert.detail);
    }
}

/// A secret in what matched is masked before it is said.
#[test]
fn a_secret_in_what_matched_is_masked() {
    let engine = RuleEngine::load_embedded();
    let token = format!("ghp_{}", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8");
    let verdict = inspect_tool_call(
        "run_command",
        &serde_json::json!({"command": format!("echo {token}")}),
        Some(&engine),
    );
    for alert in &verdict.alerts {
        assert!(!alert.detail.contains(&token), "{}", alert.detail);
    }
}
