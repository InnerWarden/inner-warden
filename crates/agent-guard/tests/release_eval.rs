//! The release safety suite: one measure of the guard per release.
//!
//! Runs seven corpora through the same inspectors as the proof benchmark
//! (`benchmark::run`, embedded rules):
//!
//! - `benchmarks/agent_attack_corpus.yml`: the curated proof corpus;
//! - `corpus/attack-2026-11/cases.yml`: the lines the guard's own tests fixed;
//! - `corpus/real/cases.yml`: lines agents really ran, labelled after review;
//! - `corpus/external-2026-11/cases.yml`: attacks the guard's authors did not
//!   write: AgentDojo and a poisoned model (DVMCP results only in RESULTS.md,
//!   its cases stay out for licence), with benign controls from the same
//!   sources;
//! - `corpus/own-work/cases.yml`: clean versions of ordinary work the guard
//!   refused to its own developers, all benign, all meant to be allowed;
//! - `corpus/line-variables-2026-11/cases.yml`: a value the line gives a name,
//!   read where the name is used, with project-folder controls;
//! - `corpus/cd-glob-owner-2026-11/cases.yml`: a `cd` that sets where a glob
//!   removal runs, and owner or mode changes of the whole system.
//!
//! It prints, per corpus, attacks caught / total, attacks stopped for an agent,
//! false positives / benign total, and every case whose verdict differs from
//! `corpus/reference.tsv`, the verdicts measured at the last accepted state.
//!
//! It fails when, against the reference, any corpus catches fewer attacks, stops
//! fewer for an agent or raises more false positives; when a single case goes
//! from caught to missed or from passing to a false positive; or when the
//! reference and the corpora no longer hold the same cases.
//!
//! Run:
//!   cargo test -p innerwarden-agent-guard --test release_eval -- --nocapture
//!
//! The reference changes only in a pull request that says why, with a line in
//! `corpus/REFERENCE-CHANGES.md`; CI refuses a reference change without one.
//! To rewrite it after a deliberate change:
//!   IW_RELEASE_EVAL_WRITE=1 cargo test -p innerwarden-agent-guard --test release_eval

use std::collections::BTreeMap;
use std::fmt::Write as _;

use innerwarden_agent_guard::benchmark::{run, CaseResult, Corpus, Label, Outcome, Scoreboard};
use innerwarden_agent_guard::rules::RuleEngine;

const CORPORA: [(&str, &str); 7] = [
    (
        "proof",
        include_str!("../benchmarks/agent_attack_corpus.yml"),
    ),
    (
        "attack-2026-11",
        include_str!("../corpus/attack-2026-11/cases.yml"),
    ),
    ("real", include_str!("../corpus/real/cases.yml")),
    (
        "external-2026-11",
        include_str!("../corpus/external-2026-11/cases.yml"),
    ),
    ("own-work", include_str!("../corpus/own-work/cases.yml")),
    (
        "line-variables-2026-11",
        include_str!("../corpus/line-variables-2026-11/cases.yml"),
    ),
    (
        "cd-glob-owner-2026-11",
        include_str!("../corpus/cd-glob-owner-2026-11/cases.yml"),
    ),
];

const REFERENCE_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus/reference.tsv");

type Key = (String, String);

/// `(corpus, id) -> verdict` from the reference file. Lines starting with `#` are
/// comments.
fn parse_reference(text: &str) -> BTreeMap<Key, String> {
    let mut out = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            parts.len(),
            3,
            "reference line {} is not corpus, id, verdict",
            n + 1
        );
        let prev = out.insert(
            (parts[0].to_string(), parts[1].to_string()),
            parts[2].to_string(),
        );
        assert!(prev.is_none(), "reference line {} repeats a case", n + 1);
    }
    out
}

fn render_reference(results: &[(&str, Vec<CaseResult>)]) -> String {
    let mut s = String::from(
        "# Verdicts of the release safety suite at the last accepted state.\n\
         # Changes only with a line in REFERENCE-CHANGES.md saying why.\n\
         # corpus\tid\tverdict\n",
    );
    for (name, rs) in results {
        for r in rs {
            let _ = writeln!(s, "{name}\t{}\t{}", r.id, r.recommendation);
        }
    }
    s
}

/// The outcome a reference verdict would have had for this case.
fn outcome_of(r: &CaseResult, verdict: &str, expect: Option<&str>) -> Outcome {
    innerwarden_agent_guard::benchmark::classify_with_expectation(r.label, verdict, expect)
}

fn worse(before: Outcome, after: Outcome) -> bool {
    matches!(
        (before, after),
        (Outcome::Caught, Outcome::Missed) | (Outcome::Ok, Outcome::FalsePositive)
    )
}

/// Totals for a corpus scored with the given verdicts.
fn board_with(
    results: &[CaseResult],
    expects: &BTreeMap<String, Option<String>>,
    verdicts: impl Fn(&CaseResult) -> String,
) -> Scoreboard {
    let rescored: Vec<CaseResult> = results
        .iter()
        .map(|r| {
            let v = verdicts(r);
            let mut c = r.clone();
            c.outcome = outcome_of(r, &v, expects[&r.id].as_deref());
            if v != r.recommendation {
                // A verdict from the reference carries no signals: count a review as
                // stopping an agent only if it was a deny then, so a change from deny
                // to review shows as one fewer stopped.
                c.charged_signals = Vec::new();
            }
            c.recommendation = v;
            c
        })
        .collect();
    Scoreboard::from_results(&rescored)
}

/// Some verdicts read the place they are judged in: what the home holds (a
/// search from `~` that deletes is held to the guard's files found there, the
/// SSH keys present) and the working folder. Measured on 2026-11-19: on a host
/// with the guard installed, `find ~ -name config.json -delete` was denied, and
/// allowed from an empty home. Every run judges from the same empty home and
/// folder, so the number is the same on a laptop, a lab machine and CI. Not under
/// `/tmp`: `find /tmp -name '*.toml' -delete` would then search the home.
///
/// The place may sit inside a git work tree (CI puts the cargo target inside
/// the checkout): `GIT_CEILING_DIRECTORIES` names the place, so neither git
/// nor the guard's reading of git looks for a repository above it, and a
/// checkout around it does not count as a repository holding the home.
///
/// The guard reads the home from the process environment, not from an argument,
/// so this binary holds ONE test on purpose: nothing else runs beside it while
/// the home is changed, and the home, `XDG_CONFIG_HOME` and the working folder
/// are put back when the place is dropped.
struct EmptyPlace {
    _dir: tempfile::TempDir,
    home: Option<std::ffi::OsString>,
    xdg: Option<std::ffi::OsString>,
    ceilings: Option<std::ffi::OsString>,
    cwd: std::path::PathBuf,
}

impl EmptyPlace {
    fn enter() -> Self {
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("an empty place");
        let home = dir.path().join("home");
        let work = dir.path().join("work");
        std::fs::create_dir_all(&home).expect("an empty home");
        std::fs::create_dir_all(&work).expect("an empty working folder");
        let saved = EmptyPlace {
            home: std::env::var_os("HOME"),
            xdg: std::env::var_os("XDG_CONFIG_HOME"),
            ceilings: std::env::var_os("GIT_CEILING_DIRECTORIES"),
            cwd: std::env::current_dir().expect("the working folder"),
            _dir: dir,
        };
        std::env::set_var("GIT_CEILING_DIRECTORIES", saved._dir.path());
        std::env::set_var("HOME", &home);
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::set_current_dir(&work).expect("judge from the empty folder");
        saved
    }
}

impl Drop for EmptyPlace {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.cwd);
        match &self.home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        match &self.xdg {
            Some(x) => std::env::set_var("XDG_CONFIG_HOME", x),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        match &self.ceilings {
            Some(c) => std::env::set_var("GIT_CEILING_DIRECTORIES", c),
            None => std::env::remove_var("GIT_CEILING_DIRECTORIES"),
        }
    }
}

#[test]
fn release_safety_suite_holds_against_the_reference() {
    // The checks of this file's own helpers run first, before the home changes.
    a_reference_line_must_have_three_fields();
    a_loosening_is_worse_and_a_tightening_is_not();
    let _place = EmptyPlace::enter();
    let engine = RuleEngine::load_embedded();
    let mut all: Vec<(&str, Vec<CaseResult>)> = Vec::new();
    let mut expects: BTreeMap<&str, BTreeMap<String, Option<String>>> = BTreeMap::new();
    for (name, yaml) in CORPORA {
        let corpus = Corpus::from_yaml(yaml).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!corpus.cases.is_empty(), "{name} holds no case");
        let mut ids = std::collections::BTreeSet::new();
        for c in &corpus.cases {
            assert!(ids.insert(c.id.clone()), "{name}: id {} repeats", c.id);
        }
        expects.insert(
            name,
            corpus
                .cases
                .iter()
                .map(|c| (c.id.clone(), c.expect.clone()))
                .collect(),
        );
        all.push((name, run(&corpus, &engine)));
    }

    if std::env::var_os("IW_RELEASE_EVAL_WRITE").is_some() {
        std::fs::write(REFERENCE_PATH, render_reference(&all)).expect("write the reference");
        println!("reference written to {REFERENCE_PATH}");
    }
    let reference = parse_reference(
        &std::fs::read_to_string(REFERENCE_PATH).expect("corpus/reference.tsv is in the repo"),
    );

    let mut report = String::new();
    let mut failures: Vec<String> = Vec::new();
    let _ = writeln!(report, "## Release safety suite\n");
    let _ = writeln!(
        report,
        "| corpus | attacks caught | stopped for an agent | false positives | changed |"
    );
    let _ = writeln!(report, "|---|---|---|---|---|");
    let mut changes = String::new();
    let mut seen: std::collections::BTreeSet<Key> = std::collections::BTreeSet::new();

    for (name, results) in &all {
        let exp = &expects[name];
        let now = Scoreboard::from_results(results);
        let mut missing = Vec::new();
        let mut changed = 0usize;
        for r in results {
            let key = (name.to_string(), r.id.clone());
            seen.insert(key.clone());
            let Some(before) = reference.get(&key) else {
                missing.push(r.id.clone());
                continue;
            };
            if *before == r.recommendation {
                continue;
            }
            changed += 1;
            let was = outcome_of(r, before, exp[&r.id].as_deref());
            let mark = if worse(was, r.outcome) {
                failures.push(format!(
                    "{name}/{}: {before} -> {} ({:?} -> {:?})",
                    r.id, r.recommendation, was, r.outcome
                ));
                "WORSE"
            } else {
                "changed"
            };
            let preview: String = r.input.chars().take(70).collect();
            let _ = writeln!(
                changes,
                "| {mark} | {name}/{} | {:?} | {before} -> {} | `{}` |",
                r.id,
                r.label,
                r.recommendation,
                preview.replace('|', "\\|").replace('\n', " ")
            );
        }
        if !missing.is_empty() {
            failures.push(format!(
                "{name}: {} case(s) not in the reference: {}",
                missing.len(),
                missing.join(", ")
            ));
        }
        let then = board_with(results, exp, |r| {
            reference
                .get(&(name.to_string(), r.id.clone()))
                .cloned()
                .unwrap_or_else(|| r.recommendation.clone())
        });
        if now.caught < then.caught {
            failures.push(format!(
                "{name}: caught {} < reference {}",
                now.caught, then.caught
            ));
        }
        if now.false_positives > then.false_positives {
            failures.push(format!(
                "{name}: false positives {} > reference {}",
                now.false_positives, then.false_positives
            ));
        }
        if now.agent_blocked < then.agent_blocked {
            failures.push(format!(
                "{name}: stopped for an agent {} < reference {}",
                now.agent_blocked, then.agent_blocked
            ));
        }
        let _ = writeln!(
            report,
            "| {name} | {}/{} (reference {}) | {}/{} | {}/{} (reference {}) | {changed} |",
            now.caught,
            now.malicious_total,
            then.caught,
            now.agent_blocked,
            now.malicious_total,
            now.false_positives,
            now.benign_total,
            then.false_positives,
        );
        for r in results
            .iter()
            .filter(|r| matches!(r.outcome, Outcome::Missed | Outcome::FalsePositive))
        {
            let preview: String = r.input.chars().take(70).collect();
            let _ = writeln!(
                changes,
                "| {} | {name}/{} | {:?} | {} | `{}` |",
                if r.label == Label::Malicious {
                    "miss"
                } else {
                    "false positive"
                },
                r.id,
                r.label,
                r.recommendation,
                preview.replace('|', "\\|").replace('\n', " ")
            );
        }
    }
    let gone: Vec<String> = reference
        .keys()
        .filter(|k| !seen.contains(*k))
        .map(|(c, i)| format!("{c}/{i}"))
        .collect();
    if !gone.is_empty() {
        failures.push(format!(
            "{} reference case(s) no longer in a corpus: {}",
            gone.len(),
            gone.join(", ")
        ));
    }

    let _ = writeln!(
        report,
        "\nCaught: deny or review, or deny alone where the case says `expect: deny`. \
         Stopped for an agent: deny, or review with a signal the default policy enforces. \
         A false positive is a deny of a benign line marked `expect: review`, or any \
         review or deny of the other benign lines.\n"
    );
    if changes.is_empty() {
        let _ = writeln!(
            report,
            "No verdict differs from the reference, and nothing is missed or wrongly held."
        );
    } else {
        let _ = writeln!(report, "| what | case | label | verdict | input |");
        let _ = writeln!(report, "|---|---|---|---|---|");
        report.push_str(&changes);
    }
    if !failures.is_empty() {
        let _ = writeln!(report, "\n### Failures\n");
        for f in &failures {
            let _ = writeln!(report, "- {f}");
        }
    }

    println!("{report}");
    if let Some(path) = std::env::var_os("GITHUB_STEP_SUMMARY") {
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
        {
            let _ = f.write_all(report.as_bytes());
        }
    }
    assert!(
        failures.is_empty(),
        "the release safety suite fell against corpus/reference.tsv:\n{}",
        failures.join("\n")
    );
}

fn a_reference_line_must_have_three_fields() {
    let r = parse_reference("# c\nproof\trs-001\tdeny\n");
    assert_eq!(r[&("proof".into(), "rs-001".into())], "deny");
    let bad = std::panic::catch_unwind(|| parse_reference("proof\trs-001\n"));
    assert!(bad.is_err());
}

fn a_loosening_is_worse_and_a_tightening_is_not() {
    assert!(worse(Outcome::Caught, Outcome::Missed));
    assert!(worse(Outcome::Ok, Outcome::FalsePositive));
    assert!(!worse(Outcome::Missed, Outcome::Caught));
    assert!(!worse(Outcome::FalsePositive, Outcome::Ok));
}
