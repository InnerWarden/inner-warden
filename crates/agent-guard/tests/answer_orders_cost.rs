//! The cost of reading tool answers for orders to the model, measured on
//! ordinary tool output: every benign text this repository holds as a tool
//! result must reach the model, none held back.
//!
//! Added 2026-11-20 with the order to act after a step written as "do",
//! "adhere to" or "comply with" (`description_poison`): a reading of an
//! answer is added only when this count does not grow, so a new reading that
//! holds back ordinary tool output fails here before it reaches a user.

use innerwarden_agent_guard::benchmark::{Corpus, Label, Surface};
use innerwarden_agent_guard::mcp::inspect_answer_orders;

/// Every `tests/data/atr-benign-*.json` item and every benign `tool_result`
/// case of every corpus: none is held back for orders, but the four that the
/// `read-and-disclose` reading already held on main when this was written
/// (2026-11-20, 747b946): an API quickstart that says "retrieve the API key
/// ... and send a test message", and a security Q&A quoting "retrieve my
/// password and send it". They are listed so the number cannot grow.
///
/// FAILS when a reading of answers holds back more ordinary tool output.
#[test]
fn ordinary_tool_output_is_not_held_for_orders() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data");
    let mut texts: Vec<(String, String)> = Vec::new();
    for entry in std::fs::read_dir(dir).expect("tests/data") {
        let path = entry.expect("entry").path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !(name.starts_with("atr-benign-") && name.ends_with(".json")) {
            continue;
        }
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        for (i, item) in doc["items"].as_array().expect("items").iter().enumerate() {
            if let Some(text) = item["text"].as_str() {
                texts.push((format!("{name}#{i}"), text.to_string()));
            }
        }
    }
    let corpora = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus");
    let mut files = vec![std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/benchmarks/agent_attack_corpus.yml"
    ))];
    for entry in std::fs::read_dir(corpora).expect("corpus") {
        let cases = entry.expect("entry").path().join("cases.yml");
        if cases.exists() {
            files.push(cases);
        }
    }
    for file in files {
        let corpus = Corpus::from_yaml(&std::fs::read_to_string(&file).expect("read"))
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        for case in corpus.cases {
            if case.label == Label::Benign && case.surface == Surface::ToolResult {
                texts.push((case.id, case.input));
            }
        }
    }
    assert!(texts.len() > 100, "only {} texts read", texts.len());
    let held: Vec<String> = texts
        .iter()
        .filter_map(|(id, text)| {
            let verdict = inspect_answer_orders(text);
            (!verdict.allowed).then(|| {
                let why: Vec<&str> = verdict.alerts.iter().map(|a| a.detail.as_str()).collect();
                format!(
                    "{id}: {} [{}]",
                    text.chars().take(100).collect::<String>(),
                    why.join("; ")
                )
            })
        })
        .collect();
    const HELD_ON_MAIN: [&str; 4] = [
        "atr-benign-results.json#71",
        "atr-benign-results.json#72",
        "atr-benign-results.json#284",
        "atr-benign-results.json#285",
    ];
    let new: Vec<&String> = held
        .iter()
        .filter(|line| {
            !HELD_ON_MAIN
                .iter()
                .any(|id| line.starts_with(&format!("{id}: ")))
        })
        .collect();
    assert!(
        new.is_empty() && held.len() <= HELD_ON_MAIN.len(),
        "{} of {} held back:\n{}",
        held.len(),
        texts.len(),
        held.join("\n")
    );
    eprintln!(
        "answer orders: {} of {} ordinary tool outputs held back (all held on main)",
        held.len(),
        texts.len()
    );
}
