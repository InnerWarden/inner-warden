//! The rules folder is shared (`/etc/innerwarden/rules` also holds the
//! host's Sigma rules and other YAML), and the ATR engine reads only its own
//! format. A valid Sigma rule whose shape the ATR reader refuses (a
//! `condition` list, several YAML documents, `references` as maps) is left
//! out with a warning that names the file and why; it is never a broken rule
//! refusing every call. A broken ATR rule still refuses every call.
//!
//! FAILS ON REVERT: before, each of the three Sigma files below was a rule
//! that did not load, and every call of every agent was refused under
//! `AG-RULES-BROKEN`.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Once;

use innerwarden_agent_guard::mcp_proxy::enforce::{apply_layers, ProxyAction, ProxyMode};
use innerwarden_agent_guard::mcp_proxy::jsonrpc::{parse_line, ParsedLine};
use innerwarden_agent_guard::mcp_proxy::router::{route_message, Direction};
use innerwarden_agent_guard::rules::{AtrContext, RuleEngine, BROKEN_RULES_ID};

/// A Sigma rule whose `condition` is a list.
const SIGMA_CONDITION_LIST: &str = "title: Download piped into a shell
id: 6b4f0a52-2c4e-4d1e-9f3a-7b2c1d0e9a11
status: experimental
description: A download piped straight into a shell.
references:
  - https://example.com/download-pipe-shell
author: test
date: 2026-11-25
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  product: linux
  category: process_creation
detection:
  selection_download:
    Image|endswith: '/curl'
  selection_pipe:
    CommandLine|contains: '| sh'
  condition:
    - selection_download and selection_pipe
    - selection_pipe
falsepositives:
  - Installers
level: high
";

/// A Sigma rule collection: several YAML documents in one file.
const SIGMA_MULTI_DOCUMENT: &str = "action: global
title: Shell started by a web server
id: 0f3c5d2a-8e1b-4c7d-a6f9-2b5e8d1c3a70
status: experimental
detection:
  condition: selection
level: high
---
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '/nginx'
---
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: EXECVE
";

/// A Sigma rule whose `references` are maps.
const SIGMA_REFERENCE_MAPS: &str = "title: Kernel module loaded from a temp folder
id: 3d9e7c41-5a2b-4f60-8e13-c4b7a9d2e605
status: test
references:
  - url: https://example.com/kernel-module-temp
    note: first report
  - url: https://example.com/kernel-module-temp-2
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: '/insmod'
    CommandLine|contains: '/tmp/'
  condition: selection
level: medium
";

/// YAML of another kind: a top-level list.
const OTHER_YAML_LIST: &str = "- name: nightly-backup
  path: /usr/local/bin/backup
- name: log-rotate
  path: /usr/sbin/logrotate
";

/// An operator ATR rule that refuses a call carrying `exfiltrate-now`.
const ATR_RULE: &str = "title: \"operator rule\"
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

/// An ATR rule with the shape a Sigma rule may have (a `condition` list):
/// a broken ATR rule.
const ATR_RULE_CONDITION_LIST: &str = "title: \"operator rule written wrong\"
id: ATR-TEST-CONDITION-LIST
severity: critical
detection_tier: pattern
agent_source:
  type: tool_call
tags:
  category: test
detection:
  condition:
    - any
  conditions:
    - field: tool_args
      operator: regex
      value: 'exfiltrate-now'
";

const SIGMA_FILES: [(&str, &str); 3] = [
    ("condition-list.yml", SIGMA_CONDITION_LIST),
    ("multi-document.yml", SIGMA_MULTI_DOCUMENT),
    ("reference-maps.yaml", SIGMA_REFERENCE_MAPS),
];

const MARKED: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup","arguments":{"q":"exfiltrate-now"}}}"#;
const BENIGN: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"weather","arguments":{"location":"NYC"}}}"#;

fn rules_dir(files: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for (name, body) in files {
        let path = dir.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
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

/// Every rule id a check of benign text on each surface returns.
fn benign_matches(engine: &RuleEngine) -> Vec<String> {
    [
        engine.check_tool_args(r#"{"location":"NYC"}"#),
        engine.check_tool_name("weather"),
        engine.check_user_input("what is the weather in NYC tomorrow"),
        engine.check_tool_response("Sunny, 21 C"),
        engine.check_context(AtrContext::shell_command("git status")),
    ]
    .into_iter()
    .flatten()
    .map(|m| m.rule_id)
    .collect()
}

thread_local! {
    /// The WARN events of this thread, while a test of this thread collects
    /// them ([`warnings_while`]).
    static SEEN: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
}

/// Install [`Capture`] as the one subscriber of this test binary, before
/// any test logs. A subscriber set for one thread only beside none at all
/// let tracing decide a warning's interest once for every thread: a test
/// running at the same time without it could leave the warning unseen by
/// the one that collects it (measured on macOS CI, tracing-core 0.1.36).
/// Every test calls it first.
fn capture_installed() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        tracing::subscriber::set_global_default(Capture).expect("one subscriber per test binary");
    });
}

/// The WARN events logged on this thread while `load` runs, each as its
/// fields.
fn warnings_while<T>(load: impl FnOnce() -> T) -> (T, Vec<String>) {
    capture_installed();
    SEEN.with(|seen| *seen.borrow_mut() = Some(Vec::new()));
    let out = load();
    let warnings = SEEN.with(|seen| seen.borrow_mut().take().unwrap_or_default());
    (out, warnings)
}

/// Keeps each WARN event for the thread that logged it, when that thread
/// collects them.
struct Capture;

impl tracing::Subscriber for Capture {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::always()
    }
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        if *event.metadata().level() != tracing::Level::WARN {
            return;
        }
        SEEN.with(|seen| {
            if let Some(seen) = seen.borrow_mut().as_mut() {
                let mut text = String::new();
                event.record(&mut Fields(&mut text));
                seen.push(text);
            }
        });
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

struct Fields<'a>(&'a mut String);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={:?} ", field.name(), value);
    }
}

#[test]
fn a_valid_sigma_rule_in_the_rules_folder_refuses_no_call() {
    capture_installed();
    for (name, body) in SIGMA_FILES {
        let dir = rules_dir(&[(name, body)]);
        let (overlay, warnings) = warnings_while(|| RuleEngine::load_with_overlay(dir.path()));
        let from_disk = RuleEngine::load(dir.path()).unwrap();
        for engine in [&overlay, &from_disk] {
            assert!(
                engine.load_failures().is_empty(),
                "{name}: {:?}",
                engine.load_failures()
            );
            let ignored = engine.ignored_files();
            assert_eq!(ignored.len(), 1, "{name}: {ignored:?}");
            assert!(ignored[0].path.ends_with(name), "{ignored:?}");
            assert!(ignored[0].reason.contains("Sigma"), "{ignored:?}");

            let matched = benign_matches(engine);
            assert!(
                !matched.iter().any(|id| id == BROKEN_RULES_ID),
                "{name}: {matched:?}"
            );
            for mode in [ProxyMode::Guard, ProxyMode::Advisory, ProxyMode::Warn] {
                let (act, reasons) = action(engine, BENIGN, mode);
                assert_eq!(act, ProxyAction::Forward, "{name} {mode:?}: {reasons:?}");
            }
        }
        assert_eq!(
            overlay.rule_count(),
            RuleEngine::load_embedded().rule_count(),
            "{name}"
        );

        let warning = warnings
            .iter()
            .find(|w| w.contains(name))
            .unwrap_or_else(|| panic!("{name}: no warning names the file: {warnings:?}"));
        assert!(warning.contains("Sigma"), "{warning}");
        assert!(warning.contains("not an ATR rule"), "{warning}");
        assert!(
            !warnings.iter().any(|w| w.contains("every check refuses")),
            "{name}: {warnings:?}"
        );
    }
}

#[test]
fn yaml_of_another_kind_is_ignored_and_named() {
    capture_installed();
    let dir = rules_dir(&[("allow/jobs.yaml", OTHER_YAML_LIST)]);
    let (engine, warnings) = warnings_while(|| RuleEngine::load_with_overlay(dir.path()));
    assert!(
        engine.load_failures().is_empty(),
        "{:?}",
        engine.load_failures()
    );
    let ignored = engine.ignored_files();
    assert_eq!(ignored.len(), 1, "{ignored:?}");
    assert!(ignored[0].path.ends_with("allow/jobs.yaml"), "{ignored:?}");
    assert!(
        ignored[0].reason.contains("no field of an ATR rule"),
        "{ignored:?}"
    );
    assert!(
        ignored[0]
            .to_string()
            .contains("jobs.yaml: no field of an ATR rule"),
        "{}",
        ignored[0]
    );
    assert!(
        warnings.iter().any(|w| w.contains("jobs.yaml")),
        "{warnings:?}"
    );
    assert_eq!(
        action(&engine, BENIGN, ProxyMode::Guard).0,
        ProxyAction::Forward
    );
}

/// The operator's ATR rule in the same folder as the Sigma rules runs: it
/// refuses the call it names, under its own id, and lets the rest through.
#[test]
fn an_atr_rule_beside_sigma_rules_still_runs() {
    capture_installed();
    let mut files = vec![("operator.yaml", ATR_RULE)];
    files.extend(SIGMA_FILES.iter().map(|(name, body)| (*name, *body)));
    let dir = rules_dir(&files);
    for engine in [
        RuleEngine::load_with_overlay(dir.path()),
        RuleEngine::load(dir.path()).unwrap(),
    ] {
        assert!(
            engine.load_failures().is_empty(),
            "{:?}",
            engine.load_failures()
        );
        assert_eq!(
            engine.ignored_files().len(),
            3,
            "{:?}",
            engine.ignored_files()
        );

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
    }
    assert_eq!(
        RuleEngine::load_with_overlay(dir.path()).rule_count(),
        RuleEngine::load_embedded().rule_count() + 1
    );
}

/// What did not change: an ATR rule that does not load still refuses every
/// call, naming its file, beside Sigma rules that are only ignored. That
/// includes an ATR rule written in a shape a Sigma rule may have, and a file
/// with an ATR document among several.
#[test]
fn a_broken_atr_rule_still_refuses_every_call() {
    capture_installed();
    let atr_among_documents = format!("{SIGMA_REFERENCE_MAPS}---\n{ATR_RULE}");
    for (name, body) in [
        ("operator.yaml", ATR_RULE_CONDITION_LIST),
        ("operator.yaml", atr_among_documents.as_str()),
    ] {
        let mut files = vec![(name, body)];
        files.extend(SIGMA_FILES.iter().map(|(name, body)| (*name, *body)));
        let dir = rules_dir(&files);
        let engine = RuleEngine::load_with_overlay(dir.path());

        let failures = engine.load_failures();
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert!(failures[0].path.ends_with(name), "{failures:?}");
        assert_eq!(
            engine.ignored_files().len(),
            3,
            "{:?}",
            engine.ignored_files()
        );

        let (act, reasons) = action(&engine, BENIGN, ProxyMode::Guard);
        assert!(blocked(&act), "{act:?} {reasons:?}");
        let named = reasons
            .iter()
            .find(|r| r.starts_with(BROKEN_RULES_ID))
            .unwrap_or_else(|| panic!("{reasons:?}"));
        assert!(named.contains(name), "{named}");
        for (sigma, _) in SIGMA_FILES {
            assert!(
                !named.contains(sigma),
                "a Sigma file is named broken: {named}"
            );
        }
    }
}

/// An engine of the embedded corpus alone ignores nothing.
#[test]
fn the_embedded_corpus_ignores_nothing() {
    capture_installed();
    assert!(RuleEngine::load_embedded().ignored_files().is_empty());
    let missing = RuleEngine::load_with_overlay(Path::new("/nonexistent/rules/dir"));
    assert!(missing.ignored_files().is_empty());
    assert!(missing.load_failures().is_empty());
}
