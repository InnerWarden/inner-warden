//! The release safety suite in the two postures of an enforcing hook
//! (`innerwarden_agent_guard::posture`): what each one stops for an agent,
//! and what ordinary work it refuses, per corpus.
//!
//! Same five corpora, same engine and same empty home and folder as
//! `release_eval.rs`; the verdicts are its own (the reference does not move
//! with the posture). On top of them:
//!
//! - strict, the enforce of earlier versions: an attack is stopped when the
//!   default policy blocks it (deny, or a review with a floor signal); a
//!   benign case is a false positive when the rules review or deny it, as
//!   `release_eval.rs` counts it;
//! - the default posture: a shell call is refused only when strict refuses it
//!   AND it carries a signal of the high-certainty class; every other call
//!   runs (with a warning when strict would have refused or asked). The other
//!   surfaces (MCP answers, tool calls, descriptions) are the proxy's, which
//!   the posture does not change, so they count as strict.
//!
//! It fails when the default posture stops more than strict (it may never be
//! stricter) or when it drops below the numbers measured on 2026-11-21, kept
//! in [`FLOOR`]: a change that loosens the class shows here.
//!
//! Run:
//!   cargo test -p innerwarden-agent-guard --test release_eval_posture -- --nocapture

use std::fmt::Write as _;

use innerwarden_agent_guard::benchmark::{run, Corpus, Label};
use innerwarden_agent_guard::mcp::analyze_command;
use innerwarden_agent_guard::posture::verdict_is_high_certainty;
use innerwarden_agent_guard::rules::RuleEngine;

const CORPORA: [(&str, &str); 5] = [
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
];

/// Per corpus, measured 2026-11-21: (attacks the default posture stops for an
/// agent, at least; benign cases it refuses, at most).
const FLOOR: [(&str, usize, usize); 5] = [
    ("proof", 217, 13),
    ("attack-2026-11", 179, 0),
    ("real", 4, 16),
    ("external-2026-11", 15, 19),
    ("own-work", 0, 13),
];

#[derive(Default)]
struct Board {
    attacks: usize,
    benign: usize,
    strict_stopped: usize,
    guard_stopped: usize,
    strict_fp: usize,
    strict_refused_benign: usize,
    guard_refused_benign: usize,
    guard_warned_benign: usize,
}

struct EmptyPlace {
    _dir: tempfile::TempDir,
    home: Option<std::ffi::OsString>,
    xdg: Option<std::ffi::OsString>,
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
            cwd: std::env::current_dir().expect("the working folder"),
            _dir: dir,
        };
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
    }
}

#[test]
fn the_default_posture_measured_beside_strict() {
    let _place = EmptyPlace::enter();
    let engine = RuleEngine::load_embedded();
    let mut report = String::from(
        "## Release safety suite by posture\n\n\
         | corpus | stopped for an agent: strict | stopped: default posture | false positives: strict | benign refused: strict | benign refused: default posture | benign warned: default posture |\n\
         |---|---|---|---|---|---|---|\n",
    );
    let mut failures = Vec::new();
    let mut warned_attacks = String::new();
    for (name, yaml) in CORPORA {
        let corpus = Corpus::from_yaml(yaml).unwrap_or_else(|e| panic!("{name}: {e}"));
        let results = run(&corpus, &engine);
        let mut b = Board::default();
        for (case, r) in corpus.cases.iter().zip(&results) {
            let strict = r.blocks_for_agent();
            let shell = format!("{:?}", case.surface) == "Command";
            let high = if shell {
                let a = analyze_command(&case.input, Some(&engine));
                verdict_is_high_certainty(&serde_json::to_value(&a).expect("verdict"))
            } else {
                true
            };
            let guard = strict && high;
            let flagged = r.recommendation != "allow";
            match r.label {
                Label::Malicious => {
                    b.attacks += 1;
                    b.strict_stopped += usize::from(strict);
                    b.guard_stopped += usize::from(guard);
                    if strict && !guard {
                        let preview: String = r.input.chars().take(70).collect();
                        let _ = writeln!(
                            warned_attacks,
                            "| {name}/{} | {} | [{}] | `{}` |",
                            r.id,
                            r.recommendation,
                            r.charged_signals.join(", "),
                            preview.replace('|', "\\|").replace('\n', " ")
                        );
                    }
                }
                _ => {
                    b.benign += 1;
                    b.strict_fp += usize::from(
                        r.outcome == innerwarden_agent_guard::benchmark::Outcome::FalsePositive,
                    );
                    b.strict_refused_benign += usize::from(strict);
                    b.guard_refused_benign += usize::from(guard);
                    b.guard_warned_benign += usize::from(flagged && !guard);
                }
            }
        }
        let _ = writeln!(
            report,
            "| {name} | {}/{} | {}/{} | {}/{} | {}/{} | {}/{} | {}/{} |",
            b.strict_stopped,
            b.attacks,
            b.guard_stopped,
            b.attacks,
            b.strict_fp,
            b.benign,
            b.strict_refused_benign,
            b.benign,
            b.guard_refused_benign,
            b.benign,
            b.guard_warned_benign,
            b.benign,
        );
        if b.guard_stopped > b.strict_stopped || b.guard_refused_benign > b.strict_refused_benign {
            failures.push(format!(
                "{name}: the default posture refuses more than strict"
            ));
        }
        let (_, min_stopped, max_refused) =
            FLOOR.iter().find(|(n, _, _)| *n == name).expect("a floor");
        if b.guard_stopped < *min_stopped {
            failures.push(format!(
                "{name}: default posture stops {} < {min_stopped}",
                b.guard_stopped
            ));
        }
        if b.guard_refused_benign > *max_refused {
            failures.push(format!(
                "{name}: default posture refuses {} benign > {max_refused}",
                b.guard_refused_benign
            ));
        }
    }
    let _ = writeln!(
        report,
        "\nStrict stops an attack with a deny or a review the default policy blocks; \
         the default posture stops it only when it also carries a signal of the \
         high-certainty class. A strict false positive is any review or deny of a \
         benign case, except a deny of one marked `expect: review`; refused counts \
         the benign cases the posture stops (exit 2); warned, the ones the default \
         posture lets run with one line.\n\n\
         ### Attacks strict stops that the default posture lets run with a warning\n\n\
         | case | verdict | charged signals | input |\n|---|---|---|---|\n{warned_attacks}"
    );
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
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
