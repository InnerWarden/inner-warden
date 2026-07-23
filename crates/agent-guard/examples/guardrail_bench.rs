//! Offline guardrail benchmark.
//!
//! Runs a corpus of commands through the SAME `analyze_command` + embedded ATR
//! engine that `POST /api/agent/check-command` uses, with no live agent and no
//! kernel. Faithful to the endpoint's verdict (the endpoint wraps this), so it
//! lets us re-run the guardrail-bench corpus instantly after a rule/pattern fix
//! without a release + deploy.
//!
//! Usage:
//!   cargo run -p innerwarden-agent-guard --example guardrail_bench -- <corpus.json>

use innerwarden_agent_guard::mcp::analyze_command;
use innerwarden_agent_guard::rules::RuleEngine;
use serde_json::Value;
use std::collections::BTreeMap;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "corpus.json".to_string());
    let corpus: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("read corpus json"))
            .expect("parse corpus json");
    let engine = RuleEngine::load_embedded();

    let mut mal = 0u32;
    let mut caught = 0u32;
    let mut blocked = 0u32;
    let mut misses: Vec<(String, String)> = Vec::new();
    let mut fam: BTreeMap<String, (u32, u32)> = BTreeMap::new();

    for item in corpus["malicious"].as_array().expect("malicious[]") {
        mal += 1;
        let cmd = item["cmd"].as_str().unwrap_or("");
        let family = item["family"].as_str().unwrap_or("?").to_string();
        let a = analyze_command(cmd, Some(&engine));
        let entry = fam.entry(family.clone()).or_insert((0, 0));
        entry.1 += 1;
        match a.recommendation.as_str() {
            "deny" => {
                caught += 1;
                blocked += 1;
                entry.0 += 1;
            }
            "review" => {
                caught += 1;
                entry.0 += 1;
            }
            _ => misses.push((cmd.to_string(), family)),
        }
    }

    let mut ben = 0u32;
    let mut fps: Vec<(String, String)> = Vec::new();
    for item in corpus["benign"].as_array().expect("benign[]") {
        ben += 1;
        let cmd = item["cmd"].as_str().unwrap_or("");
        let a = analyze_command(cmd, Some(&engine));
        if a.recommendation != "allow" {
            fps.push((cmd.to_string(), a.recommendation));
        }
    }

    let pct = |n: u32, d: u32| {
        if d > 0 {
            format!("{:.1}%", 100.0 * f64::from(n) / f64::from(d))
        } else {
            "n/a".to_string()
        }
    };

    println!("# Guardrail bench (offline: analyze_command + embedded ATR)");
    println!(
        "Catch (deny|review): {} ({}/{})",
        pct(caught, mal),
        caught,
        mal
    );
    println!(
        "Block (deny):        {} ({}/{})",
        pct(blocked, mal),
        blocked,
        mal
    );
    println!(
        "False positives:     {} ({}/{})",
        pct(fps.len() as u32, ben),
        fps.len(),
        ben
    );
    println!("\n## By family");
    for (f, (c, t)) in &fam {
        println!("  {f}: {c}/{t}");
    }
    println!("\n## Misses (malicious -> allow)");
    if misses.is_empty() {
        println!("  none");
    }
    for (c, f) in &misses {
        println!("  {c}  ({f})");
    }
    println!("\n## False positives (benign -> deny|review)");
    if fps.is_empty() {
        println!("  none");
    }
    for (c, r) in &fps {
        println!("  {c}  -> {r}");
    }
}
