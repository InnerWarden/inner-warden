//! Reads the embedded ATR corpus (`rules/atr`) once, at build time, into
//! a table the binary carries (`atr_embedded.rs` in `OUT_DIR`, included
//! by `src/rules.rs`): each pattern-tier rule with its conditions and the
//! literals each pattern cannot match without. A process that judges one
//! call and exits (the hook) then parses no YAML and compiles only the
//! rules whose literals are in the text.
//!
//! The file is read by the same code the library reads a rule from disk with
//! (`src/atr_corpus.rs`); `the_built_table_is_the_corpus` in `rules.rs`
//! holds the two to the same rules.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

#[path = "src/atr_corpus.rs"]
#[allow(dead_code)]
mod atr_corpus;

/// The rule files under `dir`, in the order the engine has always loaded
/// them (`include_dir`'s): a folder's files by name, then its folders by
/// name.
fn rule_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .collect();
    entries.sort();
    for path in entries.iter().filter(|p| p.is_file()) {
        if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            out.push(path.clone());
        }
    }
    for path in entries.iter().filter(|p| p.is_dir()) {
        rule_files(path, out);
    }
}

fn list(items: &[String]) -> String {
    let mut out = String::from("&[");
    for item in items {
        let _ = write!(out, "{item:?},");
    }
    out.push(']');
    out
}

fn main() {
    let manifest =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let corpus = manifest.join("../../rules/atr");
    println!("cargo:rerun-if-changed=src/atr_corpus.rs");
    println!("cargo:rerun-if-changed={}", corpus.display());
    let mut files = Vec::new();
    rule_files(&corpus, &mut files);
    let mut table = String::from("&[\n");
    for path in &files {
        println!("cargo:rerun-if-changed={}", path.display());
        let Ok(content) = std::fs::read_to_string(path) else {
            println!(
                "cargo:warning=embedded ATR rule is not valid UTF-8, skipped: {}",
                path.display()
            );
            continue;
        };
        let rule = match atr_corpus::parse_rule(&content) {
            Ok(Some(rule)) => rule,
            Ok(None) => continue,
            Err(e) => {
                println!(
                    "cargo:warning=embedded ATR rule does not parse, skipped: {}: {e}",
                    path.display()
                );
                continue;
            }
        };
        let _ = write!(
            table,
            "EmbeddedRule {{ id: {:?}, title: {:?}, severity: {:?}, category: {:?}, source_type: {:?}, all: {}, references: [{}, {}, {}, {}], conditions: &[",
            rule.id,
            rule.title,
            rule.severity,
            rule.category,
            rule.source_type,
            rule.all,
            list(&rule.references[0]),
            list(&rule.references[1]),
            list(&rule.references[2]),
            list(&rule.references[3]),
        );
        for cond in &rule.conditions {
            let literals = match atr_corpus::required_literals(&cond.pattern) {
                Some(literals) => format!("Some({})", list(&literals)),
                None => "None".to_string(),
            };
            let _ = write!(
                table,
                "EmbeddedCondition {{ field: {:?}, pattern: {:?}, description: {:?}, literals: {literals} }},",
                cond.field, cond.pattern, cond.description,
            );
        }
        table.push_str("] },\n");
    }
    table.push(']');
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR")).join("atr_embedded.rs");
    std::fs::write(&out, table).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
}
