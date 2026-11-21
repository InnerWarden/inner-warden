//! The measure of [`super::structure::injection_structure`] on texts its
//! authors did not tune it to: the held-out corpus
//! `corpus/injection-structure-2026-11/texts.yml` (attacks by style and the
//! benign texts of the same shape), the injected AgentDojo text in
//! `corpus/external-2026-11`, and every benign input of every corpus of the
//! repository, read as a text a server sent.
//!
//! ```text
//! cargo test -p innerwarden-agent-guard structure_corpus -- --nocapture
//! ```
//!
//! prints the attacks found per style and every benign text marked. It fails
//! when a benign text of any of them is marked, when an AgentDojo text is
//! missed, or when the held-out attacks found fall under the floor below.

use super::structure::injection_structure;
use std::collections::BTreeMap;
use std::path::Path;

/// Held-out attacks found at the last accepted state; fewer fails.
const HELD_OUT_FLOOR: usize = 158;

fn yaml(path: &Path) -> serde_yaml::Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn field<'a>(case: &'a serde_yaml::Value, key: &str) -> &'a str {
    case.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

/// Every case of every corpus: the proof corpus and each `corpus/*/cases.yml`.
fn repo_cases() -> Vec<(String, serde_yaml::Value)> {
    let guard = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![(
        "proof".to_string(),
        guard.join("benchmarks/agent_attack_corpus.yml"),
    )];
    let mut dirs: Vec<_> = std::fs::read_dir(guard.join("corpus"))
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.join("cases.yml").is_file())
        .collect();
    dirs.sort();
    for d in dirs {
        let name = d.file_name().unwrap().to_string_lossy().to_string();
        files.push((name, d.join("cases.yml")));
    }
    let mut out = Vec::new();
    for (name, path) in files {
        let doc = yaml(&path);
        let cases = doc
            .get("cases")
            .and_then(|c| c.as_sequence())
            .cloned()
            .or_else(|| doc.as_sequence().cloned())
            .unwrap_or_default();
        out.extend(cases.into_iter().map(|c| (name.clone(), c)));
    }
    out
}

#[test]
fn structure_corpus_held_out_and_benign() {
    let guard = Path::new(env!("CARGO_MANIFEST_DIR"));
    let doc = yaml(&guard.join("corpus/injection-structure-2026-11/texts.yml"));
    let texts = doc["texts"].as_sequence().expect("texts").clone();
    // style -> (attacks found, attacks, benign marked, benign)
    let mut per_style: BTreeMap<String, (usize, usize, usize, usize)> = BTreeMap::new();
    let mut per_batch: BTreeMap<String, (usize, usize, usize, usize)> = BTreeMap::new();
    let mut misses = Vec::new();
    let mut marked = Vec::new();
    for t in &texts {
        let (id, style, label, text) = (
            field(t, "id"),
            field(t, "style"),
            field(t, "label"),
            field(t, "text"),
        );
        let found = injection_structure(text).is_some();
        let batch = t
            .get("batch")
            .and_then(|b| b.as_u64())
            .unwrap_or(1)
            .to_string();
        let b_row = per_batch.entry(batch).or_default();
        if label == "malicious" {
            b_row.1 += 1;
            b_row.0 += usize::from(found);
        } else {
            b_row.3 += 1;
            b_row.2 += usize::from(found);
        }
        let row = per_style.entry(style.to_string()).or_default();
        if label == "malicious" {
            row.1 += 1;
            if found {
                row.0 += 1;
            } else {
                misses.push(id.to_string());
                if std::env::var_os("IW_STRUCTURE_EXPLAIN").is_some() {
                    for (s, m) in super::structure::explain(text) {
                        println!("  {id} {m:#06x} {s}");
                    }
                }
            }
        } else {
            row.3 += 1;
            if found {
                row.2 += 1;
                marked.push(format!("held-out/{id}"));
                if std::env::var_os("IW_STRUCTURE_EXPLAIN").is_some() {
                    for (s, m) in super::structure::explain(text) {
                        println!("  {id} {m:#06x} {s}");
                    }
                }
            }
        }
    }
    let (mut af, mut at, mut bm, mut bt) = (0, 0, 0, 0);
    println!("style                attacks found   benign marked");
    for (style, (f, a, m, b)) in &per_style {
        println!("{style:<20} {f:>3} / {a:<3}       {m:>3} / {b}");
        af += f;
        at += a;
        bm += m;
        bt += b;
    }
    println!(
        "{:<20} {af:>3} / {at:<3}       {bm:>3} / {bt}",
        "held-out total"
    );
    for (batch, (f, a, m, b)) in &per_batch {
        println!(
            "{:<20} {f:>3} / {a:<3}       {m:>3} / {b}",
            format!("batch {batch}")
        );
    }
    println!("held-out attacks missed: {}", misses.join(" "));

    // AgentDojo's injected text, and every benign input of the repository.
    let (mut dojo_found, mut dojo_total, mut benign_total) = (0, 0, 0);
    let mut dojo_missed = Vec::new();
    for (corpus, case) in repo_cases() {
        let (id, label, input) = (
            field(&case, "id"),
            field(&case, "label"),
            field(&case, "input"),
        );
        if corpus == "external-2026-11" && field(&case, "category") == "agentdojo_injection" {
            dojo_total += 1;
            if injection_structure(input).is_some() {
                dojo_found += 1;
            } else {
                dojo_missed.push(id.to_string());
            }
        }
        if label == "benign" {
            benign_total += 1;
            if injection_structure(input).is_some() {
                marked.push(format!("{corpus}/{id}"));
            }
        }
    }
    println!("AgentDojo injected text found: {dojo_found} / {dojo_total}");
    println!("repository benign inputs read: {benign_total}");
    println!("benign marked: {}", marked.join(" "));

    assert!(marked.is_empty(), "benign texts marked: {marked:?}");
    assert!(
        dojo_missed.is_empty(),
        "AgentDojo texts missed: {dojo_missed:?}"
    );
    assert!(
        af >= HELD_OUT_FLOOR,
        "held-out attacks found {af} < {HELD_OUT_FLOOR}"
    );
}
