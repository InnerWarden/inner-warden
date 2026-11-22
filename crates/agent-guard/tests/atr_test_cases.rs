//! Every ATR rule's YAML `test_cases` is run through the engine, and its
//! verdict is compared with the case's `expected` field.
//!
//! Each case is inspected with the context its rule's `agent_source.type`
//! names, and a case is `triggered` when the engine reports that rule's own id.
//! The cases that disagree are pinned, one line each, in
//! `tests/data/atr-known-mismatches.txt`. The test requires that list to equal
//! the current set exactly: a new mismatch fails it, and a fixed case must be
//! removed from the list. This test changes no rule; each real mismatch is
//! tracked as its own issue.
//!
//! A case whose text sits in a shape this harness does not read (a nested
//! `input:` map, `tool_call: {name, args}`, `agent_output`) is inspected as
//! nothing and reads as `not_triggered`; those are among the known mismatches.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use innerwarden_agent_guard::rules::{AtrContext, AtrSource, RuleEngine};

const KNOWN_MISMATCHES: &str = "tests/data/atr-known-mismatches.txt";

fn rule_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .expect("read rules/atr")
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rule_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "yaml") {
            out.push(path);
        }
    }
}

/// A conversation-text context on `source`, as `AtrContext::user_input` sets it.
fn conversation(source: AtrSource, text: &str) -> AtrContext<'_> {
    AtrContext {
        source,
        user_input: Some(text),
        tool_args: None,
        tool_response: None,
        tool_name: None,
        content: Some(text),
    }
}

/// The context a case is inspected with. A plain `input` string takes the
/// constructor its `agent_source.type` names; a case that writes its text under
/// a field name (`tool_args`, `tool_response`, `content`, `tool_name`,
/// `tool_description`) gets exactly those fields, on the source the rule
/// declares. `None` when the case holds no text the engine can read.
fn context_for<'a>(source_type: &str, case: &'a serde_yaml::Value) -> Option<AtrContext<'a>> {
    let text = |key: &str| case.get(key).and_then(|v| v.as_str());
    if let Some(input) = text("input") {
        return Some(match source_type {
            "llm_io" => AtrContext::user_input(input),
            "tool_call" => AtrContext::tool_call("test_tool", input),
            "mcp_exchange" => AtrContext::tool_response(input),
            "shell_command" => AtrContext::shell_command(input),
            "multi_agent_comm" => conversation(AtrSource::MultiAgentComm, input),
            "agent_communication" => conversation(AtrSource::AgentCommunication, input),
            "memory_access" => conversation(AtrSource::MemoryAccess, input),
            "context_window" => conversation(AtrSource::ContextWindow, input),
            other => panic!("unknown agent_source.type {other:?}"),
        });
    }
    let source = match source_type {
        "llm_io" => AtrSource::LlmIo,
        "tool_call" => AtrSource::ToolCall,
        "mcp_exchange" => AtrSource::McpExchange,
        "shell_command" => AtrSource::ShellCommand,
        "multi_agent_comm" => AtrSource::MultiAgentComm,
        "agent_communication" => AtrSource::AgentCommunication,
        "memory_access" => AtrSource::MemoryAccess,
        "context_window" => AtrSource::ContextWindow,
        other => panic!("unknown agent_source.type {other:?}"),
    };
    let mut context = AtrContext {
        source,
        user_input: None,
        tool_args: None,
        tool_response: None,
        tool_name: None,
        content: None,
    };
    if let Some(args) = text("tool_args") {
        context.tool_args = Some(args);
    }
    if let Some(response) = text("tool_response") {
        context.tool_response = Some(response);
    }
    if let Some(name) = text("tool_name") {
        context.tool_name = Some(name);
    }
    if let Some(description) = text("tool_description") {
        context.user_input = Some(description);
        context.content = Some(description);
    }
    if let Some(content) = text("content") {
        context.content = Some(content);
    }
    let any_field = context.tool_args.is_some()
        || context.tool_response.is_some()
        || context.tool_name.is_some()
        || context.content.is_some();
    any_field.then_some(context)
}

/// Every `test_cases` entry as `"<rule id> <section>[<index>] expected=<verdict>"`
/// paired with whether the engine disagrees with that verdict.
fn disagreements(engine: &RuleEngine) -> (usize, BTreeSet<String>) {
    let mut files = Vec::new();
    rule_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/atr"),
        &mut files,
    );
    let mut total = 0;
    let mut mismatched = BTreeSet::new();
    for file in files {
        let doc: serde_yaml::Value =
            serde_yaml::from_str(&fs::read_to_string(&file).expect("read rule"))
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        let Some(cases) = doc.get("test_cases").and_then(|v| v.as_mapping()) else {
            continue;
        };
        let id = doc
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{}: no id", file.display()));
        let source_type = doc
            .get("agent_source")
            .and_then(|s| s.get("type"))
            .and_then(|t| t.as_str())
            .unwrap_or_else(|| panic!("{}: no agent_source.type", file.display()));
        for (section, list) in cases {
            let section = section.as_str().expect("section name");
            for (index, case) in list.as_sequence().into_iter().flatten().enumerate() {
                total += 1;
                let expected = case
                    .get("expected")
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| panic!("{id} {section}[{index}]: no expected"));
                let triggered = context_for(source_type, case).is_some_and(|context| {
                    engine
                        .check_context(context)
                        .iter()
                        .any(|m| m.rule_id == id)
                });
                let agrees = match expected {
                    "triggered" => triggered,
                    "not_triggered" => !triggered,
                    other => panic!("{id} {section}[{index}]: expected {other:?}"),
                };
                if !agrees {
                    mismatched.insert(format!("{id} {section}[{index}] expected={expected}"));
                }
            }
        }
    }
    (total, mismatched)
}

#[test]
fn every_rule_test_case_matches_its_expected_verdict_or_is_known() {
    let engine = RuleEngine::load_embedded();
    let (total, actual) = disagreements(&engine);
    assert!(
        total > 500,
        "expected the corpus's test cases, found {total}"
    );

    let known_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(KNOWN_MISMATCHES);
    let known: BTreeSet<String> = fs::read_to_string(&known_path)
        .expect("read known mismatch list")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect();

    let new: Vec<&String> = actual.difference(&known).collect();
    let fixed: Vec<&String> = known.difference(&actual).collect();
    assert!(
        new.is_empty() && fixed.is_empty(),
        "test cases disagree with expected and are not in the known mismatch list \
         ({} new): {new:#?}\nlisted as known but now agree, remove them ({} fixed): {fixed:#?}",
        new.len(),
        fixed.len()
    );
}
