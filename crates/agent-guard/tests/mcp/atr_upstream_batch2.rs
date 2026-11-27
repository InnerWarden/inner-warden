//! Upstream ATR batch 2: eight rules upstream marks stable and writes for
//! conversation text (`llm_io`), taken at upstream commit a5616495a and
//! re-declared for what an MCP tool returns. Read through the proxy's own
//! routing (`route_message`), the path production takes.
//!
//! For each rule:
//! - it loads from the embedded corpus, declares `mcp_exchange`, and reads only
//!   `tool_response` or `content`, pinned in [`BATCH2`] rather than read back
//!   from the file, so a rule cannot drift back to `llm_io` (where the proxy
//!   would never run it) or onto `tools/call` arguments (where a match can
//!   refuse a call) with this test still green;
//! - it fires, as a tool result, on every upstream true positive except the
//!   ones pinned as lost, and does NOT fire on those: they matched only the
//!   conditions left out, so the narrowing stays visible;
//! - it fires on none of its own true negatives;
//! - it never fires on a `tools/call` or a tool description, and in guard and
//!   kill modes a tool result it matches is forwarded with an alert;
//! - it fires on no item of any `tests/data/atr-benign-*.json` file and on no
//!   true negative of any shipped rule, each screened as a tool result.
//!
//! The upstream benign corpora and the DVMCP sessions are third-party data
//! whose licences do not clearly allow bundling them here; the same zero-hit
//! check on them ran in an evaluator kept outside the repo before import.

use std::path::{Path, PathBuf};

use innerwarden_agent_guard::mcp;
use innerwarden_agent_guard::mcp_proxy::enforce::{apply_mode, ProxyAction, ProxyMode};
use innerwarden_agent_guard::mcp_proxy::jsonrpc::envelope_of;
use innerwarden_agent_guard::mcp_proxy::router::{
    route_message, Direction, PendingRequest, ProxyDecision,
};
use innerwarden_agent_guard::rules::RuleEngine;
use serde_json::{json, Value};

/// The batch-2 files, relative to `rules/atr`, each with the upstream true
/// positives (1-based, as the file lists them) that no longer fire here
/// because only a condition left out matched them. NOTICE names every file.
const BATCH2: &[(&str, &[usize])] = &[
    (
        "context-exfiltration/ATR-2026-00851-indirect-pi-financial-payment-exfil.yaml",
        &[3, 4],
    ),
    (
        "context-exfiltration/ATR-2026-00853-indirect-pi-genetic-data-exfil.yaml",
        &[3, 4],
    ),
    (
        "context-exfiltration/ATR-2026-00855-indirect-pi-browsing-history-exfil.yaml",
        &[3, 4],
    ),
    (
        "context-exfiltration/ATR-2026-01459-variable-clone-sysprompt-technique.yaml",
        &[3],
    ),
    (
        "prompt-injection/ATR-2026-01020-spikee-doc-embedded-base64-payload.yaml",
        &[],
    ),
    (
        "prompt-injection/ATR-2026-01021-spikee-doc-embedded-translation-injection.yaml",
        &[3],
    ),
    (
        "prompt-injection/ATR-2026-01026-evasion-unicode-glitch-token-anomaly.yaml",
        &[1],
    ),
    (
        "prompt-injection/ATR-2026-01304-indirect-injection-carrier-important-override.yaml",
        &[],
    ),
];

/// The only surface a batch-2 rule may declare, and the only fields it may read.
const SURFACE: &str = "mcp_exchange";
const FIELDS: &[&str] = &["tool_response", "content"];

/// Keys of a test case that describe it rather than carry its input.
const CASE_META: &[&str] = &[
    "expected",
    "description",
    "reason",
    "notes",
    "matched_condition",
];

struct Rule {
    id: String,
    file: String,
    lost: Vec<usize>,
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

/// The input of every case under `test_cases.<kind>`.
fn cases(doc: &serde_yaml::Value, kind: &str, file: &str) -> Vec<String> {
    let Some(list) = doc.get("test_cases").and_then(|t| t.get(kind)) else {
        return Vec::new();
    };
    list.as_sequence()
        .unwrap_or_else(|| panic!("{file}: test_cases.{kind} is not a list"))
        .iter()
        .map(|case| {
            let inputs: Vec<String> = case
                .as_mapping()
                .unwrap_or_else(|| panic!("{file}: unreadable {kind} case {case:?}"))
                .iter()
                .filter(|(key, _)| !CASE_META.contains(&key.as_str().unwrap_or("")))
                .filter_map(|(_, value)| value.as_str().map(str::to_string))
                .collect();
            assert_eq!(
                inputs.len(),
                1,
                "{file}: a {kind} case must carry one input: {case:?}"
            );
            inputs.into_iter().next().unwrap()
        })
        .collect()
}

fn batch2() -> Vec<Rule> {
    BATCH2
        .iter()
        .map(|&(file, lost)| {
            let doc = read_yaml(&atr_dir().join(file));
            let source = doc["agent_source"]["type"].as_str().unwrap_or("");
            assert_eq!(
                source, SURFACE,
                "{file}: declares `{source}`. Upstream's `llm_io` is a surface the proxy never \
                 runs, and `tool_call` would screen call arguments, where a match can refuse"
            );
            for condition in doc["detection"]["conditions"]
                .as_sequence()
                .expect("conditions")
            {
                let field = condition["field"].as_str().unwrap_or("");
                assert!(
                    FIELDS.contains(&field),
                    "{file}: reads `{field}`; a tool result sets only {FIELDS:?}"
                );
            }
            Rule {
                id: doc["id"].as_str().expect("id").to_string(),
                file: file.to_string(),
                lost: lost.to_vec(),
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
    let decision = route_message(&env, dir, responded.as_ref(), Some(engine), None);
    // A message the proxy passed through without inspecting it can never
    // fire, so it would only make a zero-hit count look bigger than what was
    // checked.
    assert!(
        decision.method.is_some(),
        "this message reached the proxy's pass-through: nothing was screened"
    );
    decision
}

fn tool_result(engine: &RuleEngine, text: &str) -> ProxyDecision {
    routed(
        engine,
        json!({"jsonrpc": "2.0", "id": 7,
               "result": {"content": [{"type": "text", "text": text}]}}),
        Direction::ServerToClient,
        Some(PendingRequest {
            method: "tools/call".into(),
            tool: Some("fetch".into()),
        }),
    )
}

fn tool_description(engine: &RuleEngine, text: &str) -> ProxyDecision {
    routed(
        engine,
        json!({"jsonrpc": "2.0", "id": 7, "result": {"tools": [
            {"name": "probe", "description": text, "inputSchema": {"type": "object"}}]}}),
        Direction::ServerToClient,
        Some(PendingRequest {
            method: "tools/list".into(),
            tool: None,
        }),
    )
}

fn tool_call(engine: &RuleEngine, text: &str) -> ProxyDecision {
    routed(
        engine,
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
               "params": {"name": "fetch", "arguments": {"input": text}}}),
        Direction::ClientToServer,
        None,
    )
}

fn fired(decision: &ProxyDecision, id: &str) -> bool {
    decision.verdict.alerts.iter().any(|a| a.rule == id)
}

#[test]
fn every_batch2_rule_loads_on_the_results_surface() {
    let engine = RuleEngine::load_embedded();
    let loaded: Vec<String> = engine.titles().into_iter().map(|(id, _)| id).collect();
    let rules = batch2();
    assert_eq!(rules.len(), 8);
    for rule in &rules {
        assert!(
            loaded.contains(&rule.id),
            "{} ({}) is not in the embedded corpus",
            rule.id,
            rule.file
        );
        assert!(
            !rule.negatives.is_empty(),
            "{} carries no upstream true negative to check",
            rule.id
        );
        assert!(
            rule.lost.len() * 2 <= rule.positives.len(),
            "{}: {} of {} upstream true positives lost; a rule that keeps fewer than half \
             was left out of this batch",
            rule.id,
            rule.lost.len(),
            rule.positives.len()
        );
        assert!(
            rule.lost
                .iter()
                .all(|&n| n >= 1 && n <= rule.positives.len()),
            "{}: a pinned lost true positive is not in the file",
            rule.id
        );
    }
}

/// Each rule matches, as a tool result, what upstream says it matches, except
/// the true positives pinned as lost, which it must NOT match; and it stays
/// silent on what upstream says it must not match.
#[test]
fn every_batch2_rule_fires_on_its_true_positives_as_a_tool_result() {
    let engine = RuleEngine::load_embedded();
    let mut wrong = Vec::new();
    for rule in batch2() {
        for (n, text) in rule.positives.iter().enumerate() {
            let expected = !rule.lost.contains(&(n + 1));
            if fired(&tool_result(&engine, text), &rule.id) != expected {
                wrong.push(format!(
                    "{} true positive {} {}: {text:?}",
                    rule.id,
                    n + 1,
                    if expected {
                        "missed"
                    } else {
                        "fired, though pinned as lost"
                    }
                ));
            }
        }
        for text in &rule.negatives {
            if fired(&tool_result(&engine, text), &rule.id) {
                wrong.push(format!("{} flagged its true negative {text:?}", rule.id));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A batch-2 rule raises alerts only. Its own attack texts, sent as the
/// arguments of a `tools/call` (the only message the proxy can refuse) or as
/// a tool description, are not matched by it; and where it matches a tool
/// result, guard and kill modes forward the answer with the alert.
#[test]
fn a_batch2_rule_never_makes_the_proxy_refuse() {
    let engine = RuleEngine::load_embedded();
    for rule in batch2() {
        for (n, text) in rule.positives.iter().enumerate() {
            assert!(
                !fired(&tool_call(&engine, text), &rule.id),
                "{} fired on a tools/call",
                rule.id
            );
            assert!(
                !fired(&tool_description(&engine, text), &rule.id),
                "{} fired on a tool description",
                rule.id
            );
            if rule.lost.contains(&(n + 1)) {
                continue;
            }
            let answer = tool_result(&engine, text);
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

fn yaml_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            yaml_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            out.push(path);
        }
    }
}

/// Every true negative of every shipped rule.
fn shipped_true_negatives() -> Vec<(String, String)> {
    /// Every input string of a case, whatever field it was written under:
    /// some shipped cases carry two (a prompt and a tool response).
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
    yaml_files(&atr_dir(), &mut files);
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

/// Every item of every `tests/data/atr-benign-*.json`: this batch's ordinary
/// tool output, and any other benign corpus kept in that format.
fn benign_items() -> Vec<(String, String)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("tests/data")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .to_string()
        })
        .filter(|n| n.starts_with("atr-benign-") && n.ends_with(".json"))
        .collect();
    names.sort();
    assert!(
        names.iter().any(|n| n == "atr-benign-results.json"),
        "this batch's benign corpus is missing: {names:?}"
    );
    let mut out = Vec::new();
    for name in names {
        let doc: Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join(&name)).unwrap_or_else(|e| panic!("{name}: {e}")),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        let items = doc["items"]
            .as_array()
            .unwrap_or_else(|| panic!("{name}: no items"));
        assert!(!items.is_empty(), "{name}: empty");
        for item in items {
            // A text, or a call's arguments, or a resource URI: whatever the
            // item carries is screened as if a tool had returned it.
            let text = item["text"]
                .as_str()
                .map(str::to_string)
                .or_else(|| item.get("args").map(Value::to_string))
                .or_else(|| item["uri"].as_str().map(str::to_string))
                .unwrap_or_else(|| panic!("{name}: item with no text, args or uri: {item}"));
            out.push((name.clone(), text));
        }
    }
    out
}

/// Every benign text, screened as a tool result (the one surface these rules
/// run on, whatever surface the text was written for): no batch-2 rule may
/// fire.
#[test]
fn no_batch2_rule_fires_on_benign_text() {
    let engine = RuleEngine::load_embedded();
    let ids: Vec<String> = batch2().into_iter().map(|r| r.id).collect();
    let benign = benign_items();
    let negatives = shipped_true_negatives();
    assert!(benign.len() >= 300, "only {} benign items", benign.len());
    // Every exfiltration condition kept here ends at an email address, so
    // benign text without one never reaches its last step and passes for
    // free. The review counted 12 of 238 items with an address.
    let with_address = benign.iter().filter(|(_, text)| text.contains('@')).count();
    assert!(
        with_address >= 90,
        "only {with_address} benign items carry an email address"
    );
    assert!(
        negatives.len() >= 300,
        "only {} shipped true negatives",
        negatives.len()
    );
    let mut hits = Vec::new();
    for (from, text) in benign.iter().chain(negatives.iter()) {
        let alerts: Vec<mcp::VerdictAlert> = tool_result(&engine, text).verdict.alerts;
        for alert in alerts.iter().filter(|a| ids.contains(&a.rule)) {
            hits.push(format!("{} on {from}: {text:?}", alert.rule));
        }
    }
    assert!(
        hits.is_empty(),
        "batch-2 rules fired on benign text: {hits:#?}"
    );
}

/// NOTICE names every batch-2 file as taken at a5616495a and modified.
#[test]
fn notice_names_every_batch2_file() {
    let notice =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../NOTICE"))
            .expect("NOTICE");
    assert!(
        notice.contains("a5616495a"),
        "NOTICE does not name the upstream commit"
    );
    for (file, _) in BATCH2 {
        assert!(
            notice.contains(&format!("rules/atr/{file} (modified)")),
            "NOTICE does not list rules/atr/{file} as modified"
        );
    }
}
