//! A rule file of the operator's that does not load leaves no engine with
//! fewer rules in silence: every call is refused, the refusal naming the file
//! and the line, and a monitor mode forwards it with that warning.
//!
//! FAILS ON REVERT: before, the broken file was skipped with a log warning,
//! and the call its rule refuses was forwarded in every mode.

use std::path::Path;

use innerwarden_agent_guard::mcp_proxy::enforce::{apply_layers, ProxyAction, ProxyMode};
use innerwarden_agent_guard::mcp_proxy::jsonrpc::{parse_line, ParsedLine};
use innerwarden_agent_guard::mcp_proxy::router::{route_message, Direction};
use innerwarden_agent_guard::rules::{RuleEngine, BROKEN_RULES_ID};

/// A rule of the operator's that refuses a call carrying `exfiltrate-now`.
const USER_RULE: &str = "title: \"operator rule\"
id: ATR-TEST-OPERATOR
severity: critical
detection_tier: pattern
agent_source:
  type: tool_call
tags:
  category: test
detection:
  conditions:
    - field: tool_args
      operator: regex
      value: 'exfiltrate-now'
      description: \"operator marker\"
";

/// A rule whose pattern no regex engine accepts, on line 12.
const BROKEN_PATTERN: &str = "title: \"broken operator rule\"
id: ATR-TEST-BROKEN
severity: critical
detection_tier: pattern
agent_source:
  type: tool_call
tags:
  category: test
detection:
  conditions:
    - field: tool_args
      value: '[unclosed(exfiltrate'
      operator: regex
      description: \"does not compile\"
";

/// A rule whose YAML does not parse (an unclosed flow sequence on line 3).
const BROKEN_YAML: &str = "title: \"broken yaml\"
id: ATR-TEST-YAML
tags: [one, two
severity: critical
";

const MARKED: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup","arguments":{"q":"exfiltrate-now"}}}"#;
const BENIGN: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"weather","arguments":{"location":"NYC"}}}"#;

fn rules_dir(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in files {
        std::fs::write(dir.path().join(name), body).unwrap();
    }
    dir
}

/// The proxy's action for `line` and the reasons its verdict gives.
fn action(engine: &RuleEngine, line: &str, mode: ProxyMode) -> (ProxyAction, Vec<String>) {
    let ParsedLine::Message(env) = parse_line(line) else {
        panic!("not a message: {line}");
    };
    let mut d = route_message(&env, Direction::ClientToServer, None, Some(engine), None);
    let act = apply_layers(&mut d, &env, None, Some(engine), mode, false);
    let reasons = d
        .verdict
        .alerts
        .iter()
        .map(|a| format!("{} {} {}", a.rule, a.block, a.detail))
        .collect();
    (act, reasons)
}

fn blocked(a: &ProxyAction) -> bool {
    matches!(a, ProxyAction::Block { .. } | ProxyAction::Kill { .. })
}

#[test]
fn a_rule_that_does_not_compile_refuses_naming_file_and_line() {
    let dir = rules_dir(&[
        ("operator.yaml", USER_RULE),
        ("broken.yaml", BROKEN_PATTERN),
    ]);
    let engine = RuleEngine::load(dir.path()).unwrap();

    let failures = engine.load_failures();
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert!(failures[0].path.ends_with("broken.yaml"), "{failures:?}");
    assert_eq!(failures[0].line, Some(12), "{failures:?}");

    for line in [MARKED, BENIGN] {
        let (act, reasons) = action(&engine, line, ProxyMode::Guard);
        assert!(
            blocked(&act),
            "guard must refuse {line}: {act:?} {reasons:?}"
        );
        let named = reasons
            .iter()
            .find(|r| r.starts_with(BROKEN_RULES_ID))
            .unwrap();
        assert!(named.contains("broken.yaml line 12"), "{named}");
        assert!(named.contains("[unclosed(exfiltrate"), "{named}");

        for monitor in [ProxyMode::Advisory, ProxyMode::Warn] {
            let (act, reasons) = action(&engine, line, monitor);
            assert_eq!(act, ProxyAction::ForwardWithAlert, "{line}: {reasons:?}");
            assert!(
                reasons.iter().any(|r| r.starts_with(BROKEN_RULES_ID)),
                "{reasons:?}"
            );
        }
    }
}

#[test]
fn a_rule_whose_yaml_does_not_parse_refuses_naming_file_and_line() {
    let dir = rules_dir(&[("operator.yaml", USER_RULE), ("broken.yaml", BROKEN_YAML)]);
    for engine in [
        RuleEngine::load(dir.path()).unwrap(),
        RuleEngine::load_with_overlay(dir.path()),
    ] {
        let failures = engine.load_failures();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].line.is_some(), "{failures:?}");
        let m = engine.check_tool_args("anything");
        assert!(
            m.iter().any(|m| m.rule_id == BROKEN_RULES_ID
                && m.severity == "critical"
                && m.matched_condition.contains("broken.yaml line")),
            "{m:?}"
        );
    }
}

#[test]
fn an_overlay_rule_that_does_not_compile_refuses_too() {
    let dir = rules_dir(&[("broken.yaml", BROKEN_PATTERN)]);
    let engine = RuleEngine::load_with_overlay(dir.path());
    assert_eq!(engine.load_failures().len(), 1);
    let (act, reasons) = action(&engine, BENIGN, ProxyMode::Guard);
    assert!(blocked(&act), "{act:?} {reasons:?}");
}

/// The same folder without the broken file: the verdicts main gives. The
/// operator's rule refuses the marked call under its own id, the other call
/// is forwarded, and no refusal names a broken rule.
#[test]
fn without_the_broken_file_the_verdicts_are_unchanged() {
    let dir = rules_dir(&[("operator.yaml", USER_RULE)]);
    let engine = RuleEngine::load(dir.path()).unwrap();
    assert!(engine.load_failures().is_empty());
    assert_eq!(engine.rule_count(), 1);

    let (act, reasons) = action(&engine, MARKED, ProxyMode::Guard);
    assert!(blocked(&act), "{act:?} {reasons:?}");
    assert!(
        reasons
            .iter()
            .any(|r| r.starts_with("ATR-TEST-OPERATOR true")),
        "{reasons:?}"
    );
    assert!(
        !reasons.iter().any(|r| r.starts_with(BROKEN_RULES_ID)),
        "{reasons:?}"
    );

    let (act, reasons) = action(&engine, BENIGN, ProxyMode::Guard);
    assert_eq!(act, ProxyAction::Forward, "{reasons:?}");

    let missing = RuleEngine::load(Path::new("/nonexistent/rules/dir")).unwrap();
    assert!(missing.load_failures().is_empty());
    assert_eq!(
        action(&missing, BENIGN, ProxyMode::Guard).0,
        ProxyAction::Forward
    );
}

/// The embedded corpus is not read from a folder: it never refuses for a
/// broken file (`every_embedded_condition_compiles` holds it to compiling).
#[test]
fn the_embedded_corpus_has_no_load_failure() {
    let engine = RuleEngine::load_embedded();
    assert!(engine.load_failures().is_empty());
    assert!(!engine
        .check_tool_args("weather in NYC")
        .iter()
        .any(|m| m.rule_id == BROKEN_RULES_ID));
}
