//! The upstream ATR rules imported after v0.4.0, read through the proxy's own
//! routing (`route_message`), the path production takes.
//!
//! For each imported rule:
//! - it loads from the embedded corpus;
//! - it fires on every one of its own upstream true positives, on the surface
//!   InnerWarden runs it on (a tool result or a tool description), and on none
//!   of its own true negatives;
//! - it never fires on a `tools/call`, the only message the proxy can refuse,
//!   so an imported rule only ever raises an alert;
//! - it fires on none of the repo's benign MCP texts
//!   (`tests/data/atr-benign-mcp.json`) and on none of the true negatives of
//!   any shipped rule.
//!
//! The upstream benign corpora (real MCP tool descriptions and tool outputs)
//! and the DVMCP benign sessions are third-party data whose licences do not
//! clearly allow bundling them here, so the same zero-hit check on them runs in
//! an evaluator kept outside the repo, before a rule is imported.

use std::path::{Path, PathBuf};

use innerwarden_agent_guard::mcp;
use innerwarden_agent_guard::mcp_proxy::enforce::{apply_mode, ProxyAction, ProxyMode};
use innerwarden_agent_guard::mcp_proxy::jsonrpc::envelope_of;
use innerwarden_agent_guard::mcp_proxy::router::{
    route_message, Direction, PendingRequest, ProxyDecision,
};
use innerwarden_agent_guard::rules::RuleEngine;
use serde_json::{json, Value};

/// The rule files taken at upstream commit a5616495a, relative to
/// `rules/atr`. NOTICE names each of them.
const IMPORTED: &[&str] = &[
    "prompt-injection/ATR-2026-00511-mcp-web-context-poisoning.yaml",
    "tool-poisoning/ATR-2026-00434-mcp-remote-authorization-endpoint-command-injection.yaml",
    "tool-poisoning/ATR-2026-00714-tool-camouflage-forced-tool-call.yaml",
    "tool-poisoning/ATR-2026-00715-tool-knowledge-hijack-identity-injection.yaml",
    "tool-poisoning/ATR-2026-01301-tool-description-exclusive-tool-override.yaml",
    "tool-poisoning/ATR-2026-01302-fake-tool-result-instruction-injection.yaml",
    "tool-poisoning/ATR-2026-01306-mcp-oauth-command-injection.yaml",
    "tool-poisoning/ATR-2026-01307-mcp-dns-rebinding-attack.yaml",
    "tool-poisoning/ATR-2026-01310-mcp-tool-description-compliance-history-exfil.yaml",
];

/// Keys of a test case that describe it rather than carry its input.
const CASE_META: &[&str] = &[
    "expected",
    "description",
    "reason",
    "notes",
    "matched_condition",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Surface {
    /// What a `tools/call` returned (the rule declares `mcp_exchange`).
    ToolResult,
    /// A tool's own description in a `tools/list` answer (the rule declares
    /// `tool_call` and reads only the `tool_description` field).
    ToolDescription,
}

struct Imported {
    id: String,
    file: String,
    surface: Surface,
    positives: Vec<String>,
    negatives: Vec<String>,
}

fn atr_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/atr")
}

fn read_yaml(path: &Path) -> serde_yaml::Value {
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// The input of every case under `test_cases.<kind>`. A case is a mapping
/// with exactly one input key besides its prose, or a bare string.
fn cases(doc: &serde_yaml::Value, kind: &str, file: &str) -> Vec<String> {
    let Some(list) = doc.get("test_cases").and_then(|t| t.get(kind)) else {
        return Vec::new();
    };
    let list = list
        .as_sequence()
        .unwrap_or_else(|| panic!("{file}: test_cases.{kind} is not a list"));
    list.iter()
        .map(|case| match case {
            serde_yaml::Value::String(text) => text.clone(),
            serde_yaml::Value::Mapping(map) => {
                let inputs: Vec<String> = map
                    .iter()
                    .filter(|(key, _)| !CASE_META.contains(&key.as_str().unwrap_or("")))
                    .filter_map(|(_, value)| value.as_str().map(str::to_string))
                    .collect();
                assert_eq!(
                    inputs.len(),
                    1,
                    "{file}: a {kind} case must carry exactly one input: {case:?}"
                );
                inputs.into_iter().next().unwrap()
            }
            other => panic!("{file}: unreadable {kind} case {other:?}"),
        })
        .collect()
}

fn imported() -> Vec<Imported> {
    IMPORTED
        .iter()
        .map(|file| {
            let doc = read_yaml(&atr_dir().join(file));
            let id = doc["id"].as_str().expect("id").to_string();
            let source = doc["agent_source"]["type"].as_str().unwrap_or("");
            let fields: Vec<&str> = doc["detection"]["conditions"]
                .as_sequence()
                .expect("conditions")
                .iter()
                .map(|c| c["field"].as_str().unwrap_or(""))
                .collect();
            let surface = match source {
                "mcp_exchange" => Surface::ToolResult,
                "tool_call" if fields.iter().all(|f| *f == "tool_description") => {
                    Surface::ToolDescription
                }
                other => panic!(
                    "{file}: an imported rule must run on tool results or tool \
                     descriptions only; `{other}` with fields {fields:?} is a surface \
                     this test does not cover (and may refuse a call)"
                ),
            };
            Imported {
                id,
                file: file.to_string(),
                surface,
                positives: cases(&doc, "true_positives", file),
                negatives: cases(&doc, "true_negatives", file),
            }
        })
        .collect()
}

fn routed(
    engine: &RuleEngine,
    msg: Value,
    dir: Direction,
    responded: Option<PendingRequest>,
) -> ProxyDecision {
    let env = envelope_of(&msg).expect("a JSON-RPC envelope");
    route_message(&env, dir, responded.as_ref(), Some(engine), None)
}

fn tool_result(engine: &RuleEngine, tool: &str, text: &str) -> ProxyDecision {
    routed(
        engine,
        json!({"jsonrpc": "2.0", "id": 7,
               "result": {"content": [{"type": "text", "text": text}]}}),
        Direction::ServerToClient,
        Some(PendingRequest {
            method: "tools/call".into(),
            tool: Some(tool.into()),
        }),
    )
}

fn tool_description(engine: &RuleEngine, tool: &str, text: &str) -> ProxyDecision {
    routed(
        engine,
        json!({"jsonrpc": "2.0", "id": 7, "result": {"tools": [
            {"name": tool, "description": text, "inputSchema": {"type": "object"}}]}}),
        Direction::ServerToClient,
        Some(PendingRequest {
            method: "tools/list".into(),
            tool: None,
        }),
    )
}

fn tool_call(engine: &RuleEngine, tool: &str, args: Value) -> ProxyDecision {
    routed(
        engine,
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
               "params": {"name": tool, "arguments": args}}),
        Direction::ClientToServer,
        None,
    )
}

fn on_surface(engine: &RuleEngine, surface: Surface, text: &str) -> ProxyDecision {
    match surface {
        Surface::ToolResult => tool_result(engine, "fetch", text),
        Surface::ToolDescription => tool_description(engine, "probe", text),
    }
}

fn fired(decision: &ProxyDecision, id: &str) -> bool {
    decision.verdict.alerts.iter().any(|a| a.rule == id)
}

#[test]
fn every_imported_rule_loads_and_names_its_surface() {
    let engine = RuleEngine::load_embedded();
    let loaded: Vec<String> = engine.titles().into_iter().map(|(id, _)| id).collect();
    let rules = imported();
    assert_eq!(rules.len(), IMPORTED.len());
    for rule in &rules {
        assert!(
            loaded.contains(&rule.id),
            "{} ({}) is not in the embedded corpus",
            rule.id,
            rule.file
        );
        assert!(
            !rule.positives.is_empty() && !rule.negatives.is_empty(),
            "{} carries no upstream true positive or true negative to check",
            rule.id
        );
    }
}

/// Each rule matches what upstream says it matches, through the proxy, on
/// the surface it runs on; and it stays silent on what upstream says it must
/// not match.
#[test]
fn every_imported_rule_fires_on_its_own_true_positives_and_not_its_true_negatives() {
    let engine = RuleEngine::load_embedded();
    let mut missed = Vec::new();
    let mut wrong = Vec::new();
    for rule in imported() {
        for text in &rule.positives {
            if !fired(&on_surface(&engine, rule.surface, text), &rule.id) {
                missed.push(format!("{} {:?}: {text:?}", rule.id, rule.surface));
            }
        }
        for text in &rule.negatives {
            if fired(&on_surface(&engine, rule.surface, text), &rule.id) {
                wrong.push(format!("{} {:?}: {text:?}", rule.id, rule.surface));
            }
        }
    }
    assert!(missed.is_empty(), "true positives not caught: {missed:#?}");
    assert!(wrong.is_empty(), "true negatives flagged: {wrong:#?}");
}

/// An imported rule raises alerts only. Its own attack texts, sent as the
/// arguments of a `tools/call` (the only message the proxy can refuse), are
/// not matched by it; and where it does match, the guard mode forwards the
/// server's answer with the alert instead of refusing anything.
#[test]
fn an_imported_rule_never_makes_the_proxy_refuse() {
    let engine = RuleEngine::load_embedded();
    for rule in imported() {
        for text in &rule.positives {
            let call = tool_call(&engine, "fetch", json!({ "input": text }));
            assert!(
                !fired(&call, &rule.id),
                "{} fired on a tools/call carrying {text:?}: it would refuse calls",
                rule.id
            );
            let answer = on_surface(&engine, rule.surface, text);
            assert!(fired(&answer, &rule.id), "{} missed {text:?}", rule.id);
            for mode in [ProxyMode::Guard, ProxyMode::Kill] {
                let action = apply_mode(&answer, mode, false);
                assert!(
                    matches!(action, ProxyAction::ForwardWithAlert),
                    "{} under {mode:?} must forward with an alert, got {action:?}",
                    rule.id
                );
            }
        }
    }
}

/// Every true negative of every shipped rule, ours and upstream's.
fn shipped_true_negatives() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .map(|e| e.expect("dir entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
                out.push(path);
            }
        }
    }
    fn strings(value: &serde_yaml::Value, out: &mut Vec<String>) {
        match value {
            serde_yaml::Value::String(text) => out.push(text.clone()),
            serde_yaml::Value::Sequence(items) => items.iter().for_each(|i| strings(i, out)),
            serde_yaml::Value::Mapping(map) => {
                for (key, item) in map {
                    if !CASE_META.contains(&key.as_str().unwrap_or("")) {
                        strings(item, out);
                    }
                }
            }
            _ => {}
        }
    }
    let mut files = Vec::new();
    walk(&atr_dir(), &mut files);
    let mut out = Vec::new();
    for path in files {
        let doc = read_yaml(&path);
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        if let Some(negatives) = doc.get("test_cases").and_then(|t| t.get("true_negatives")) {
            let mut texts = Vec::new();
            strings(negatives, &mut texts);
            out.extend(texts.into_iter().map(|t| (name.clone(), t)));
        }
    }
    out
}

fn alerts(decision: ProxyDecision) -> Vec<mcp::VerdictAlert> {
    decision.verdict.alerts
}

/// A text written with no surface, screened as a tool result, a tool
/// description and the argument of a tool call.
fn text_on_every_surface(
    engine: &RuleEngine,
    text: &str,
) -> Vec<(&'static str, Vec<mcp::VerdictAlert>)> {
    vec![
        ("a result", alerts(tool_result(engine, "fetch", text))),
        (
            "a description",
            alerts(tool_description(engine, "probe", text)),
        ),
        (
            "a call",
            alerts(tool_call(engine, "fetch", json!({ "input": text }))),
        ),
    ]
}

/// The repo's benign MCP texts and every shipped rule's true negatives,
/// screened on each surface they could reach; no imported rule may fire.
#[test]
fn no_imported_rule_fires_on_the_repo_benign_mcp_texts() {
    let engine = RuleEngine::load_embedded();
    let ids: Vec<String> = imported().into_iter().map(|r| r.id).collect();
    let mut hits = Vec::new();
    let mut check = |alerts: Vec<mcp::VerdictAlert>, from: &str, surface: &str| {
        for alert in &alerts {
            if ids.contains(&alert.rule) {
                hits.push(format!("{} on {surface} ({from})", alert.rule));
            }
        }
    };

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/atr-benign-mcp.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&fixture).expect("fixture"))
        .expect("fixture json");
    let items = doc["items"].as_array().expect("items");
    // A gate over nothing reports clean: refuse a fixture that lost its items.
    assert!(
        items.len() >= 100,
        "only {} benign items in the fixture",
        items.len()
    );
    for item in items {
        let from = item["from"].as_str().unwrap_or("?");
        let surface = item["surface"].as_str().expect("surface");
        let tool = item["tool"].as_str().unwrap_or("tool");
        let text = item["text"].as_str().unwrap_or("");
        let found: Vec<(&str, Vec<mcp::VerdictAlert>)> = match surface {
            "tool_call" => vec![(
                surface,
                alerts(tool_call(&engine, tool, item["args"].clone())),
            )],
            "tool_description" => vec![(surface, alerts(tool_description(&engine, tool, text)))],
            "tool_result" => vec![(surface, alerts(tool_result(&engine, tool, text)))],
            "resource_uri" => vec![(
                surface,
                alerts(routed(
                    &engine,
                    json!({"jsonrpc": "2.0", "id": 7, "method": "resources/read",
                           "params": {"uri": item["uri"]}}),
                    Direction::ClientToServer,
                    None,
                )),
            )],
            "resource_contents" => vec![(
                surface,
                alerts(routed(
                    &engine,
                    json!({"jsonrpc": "2.0", "id": 7, "result": {"contents": [
                        {"uri": item["uri"], "text": text}]}}),
                    Direction::ServerToClient,
                    Some(PendingRequest {
                        method: "resources/read".into(),
                        tool: None,
                    }),
                )),
            )],
            "user_input" => vec![(surface, mcp::inspect_user_input(text, Some(&engine)).alerts)],
            "text" => text_on_every_surface(&engine, text),
            other => panic!("unknown surface {other} in the fixture"),
        };
        for (on, list) in found {
            check(list, from, on);
        }
    }

    let negatives = shipped_true_negatives();
    assert!(
        negatives.len() >= 300,
        "only {} true negatives in the shipped corpus",
        negatives.len()
    );
    for (file, text) in &negatives {
        for (on, list) in text_on_every_surface(&engine, text) {
            check(list, file, on);
        }
    }

    assert!(
        hits.is_empty(),
        "imported rules fired on benign text: {hits:#?}"
    );
}

/// NOTICE says which files came from upstream commit a5616495a.
#[test]
fn notice_names_every_imported_file() {
    let notice =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../NOTICE"))
            .expect("NOTICE");
    assert!(
        notice.contains("a5616495a"),
        "NOTICE does not name the upstream commit"
    );
    for file in IMPORTED {
        assert!(
            notice.contains(&format!("rules/atr/{file}")),
            "NOTICE does not name rules/atr/{file}"
        );
    }
}
