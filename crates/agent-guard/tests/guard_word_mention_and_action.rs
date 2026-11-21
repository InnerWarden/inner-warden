//! A word the guard watches, acted on or only named (decision of the
//! operator, 2026-11-21): the guard refuses the ACTION on its files,
//! processes and settings and on an agent's settings, not the MENTION of the
//! name.
//!
//! Measured 2026-11-21 against main 37af662: a search pattern, the text of a
//! message, a folder of a repository or a worktree, and inline Python that
//! edits a project file whose text names the guard were refused (own-work
//! own-001..own-016, own-028, own-045, own-046, own-048 and own-052..own-055;
//! 13 of 31 lines of a sample of a week of refusals labelled legitimate work).
//! They are held for review now ([guard_word_mention]); every action of
//! `corpus/guard-word-mention-2026-11` stays refused.

use innerwarden_agent_guard::mcp::{analyze_command, analyze_command_in, WorkingContext};
use innerwarden_agent_guard::rules::{AtrSource, RuleEngine};

fn engine() -> RuleEngine {
    RuleEngine::load_embedded_for(AtrSource::ShellCommand)
}

fn verdict(command: &str) -> (String, Vec<String>, String) {
    let analysis = analyze_command(command, Some(&engine()));
    let signals = analysis.signals.iter().map(|s| s.signal.clone()).collect();
    (analysis.recommendation, signals, analysis.explanation)
}

#[derive(serde::Deserialize)]
struct Corpus {
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    id: String,
    label: String,
    input: String,
}

fn corpus() -> Vec<Case> {
    let text = include_str!("../corpus/guard-word-mention-2026-11/cases.yml");
    serde_yaml::from_str::<Corpus>(text)
        .expect("the corpus reads")
        .cases
}

/// FAILS ON REVERT of `mention_only` (mcp.rs): each line is a deny.
#[test]
fn a_mention_of_the_guard_is_held_for_review_not_refused() {
    let mentions = [
        // A search pattern.
        "git grep -n \"snapshot.*eval\\|eval '\\|shell_snapshot\" origin/main -- crates | head -20",
        "git grep -n -e 'systemctl stop innerwarden-agent' origin/main -- crates",
        // A message.
        "gh pr create --title 'Guard: refuse systemctl stop innerwarden-agent by unit glob' --body 'systemctl stop innerwarden-agent and pkill -f innerwarden stay refused'",
        // A folder of a repository or a worktree.
        "git worktree remove ../innerwarden",
        "git worktree remove --force /home/u/src/innerwarden-fix",
        "mv ~/work/innerwarden/scripts/kill-cases.json ~/work/innerwarden/scripts/k.json",
        // A string in code that acts on nothing of the guard's.
        "python3 - <<'EOF'\np = 'src/rules.rs'\ns = open(p).read()\ns = s.replace('systemctl stop innerwarden-agent', 'innerwarden status')\nopen(p, 'w').write(s)\nEOF",
        "python3 -c \"import json; d = json.load(open('report.json')); print(d['innerwarden']['mode'])\"",
        "cd ~/work/innerwarden && python3 - <<'EOF'\np = 'crates/guard/src/rules.rs'\ns = open(p).read()\ns = s.replace('innerwarden-ctl exec-gate disarm', 'innerwarden-ctl exec-gate status')\nopen(p, 'w').write(s)\nEOF\ncargo test -q -p guard 2>&1 | tail -3",
    ];
    for line in mentions {
        let (recommendation, signals, why) = verdict(line);
        assert_eq!(recommendation, "review", "{line:?}: {why}");
        assert!(
            signals.iter().any(|s| s == "guard_word_mention"),
            "{line:?}: {signals:?}"
        );
    }
    for case in corpus().iter().filter(|case| case.label == "benign") {
        let (recommendation, _, why) = verdict(&case.input);
        assert_eq!(recommendation, "review", "{}: {why}", case.id);
    }
}

/// The actions beside and inside those slots stay refused: a message or a
/// pattern next to a stop, code that runs or signals something or writes
/// one of the guard's places or an agent's settings, a slot whose output is
/// run, a file the code writes and the line runs.
#[test]
fn an_action_on_the_guard_stays_refused_whatever_slot_it_stands_beside() {
    let cases = corpus();
    let actions: Vec<&Case> = cases
        .iter()
        .filter(|case| case.label == "malicious")
        .collect();
    assert!(actions.len() >= 30, "the corpus holds its actions");
    for case in actions {
        let (recommendation, _, why) = verdict(&case.input);
        assert_eq!(
            recommendation, "deny",
            "{}: {:?}: {why}",
            case.id, case.input
        );
    }
}

/// A search pattern is data, never the folder searched: the line a person
/// saw refused on 2026-11-21 as a read of `/` (BI
/// FP-20261120-search-pattern-with-watched-word). Not reproduced from the
/// text, nor from a home holding a key with the work folder or the home as
/// the folder it runs in; pinned here so it stays allowed.
#[test]
fn a_fixed_search_pattern_is_not_a_folder_read() {
    let line = "git grep -n -F -e 'unset X' -e '(X=/)' origin/main -- crates/agent-guard/corpus";
    let (recommendation, _, why) = verdict(line);
    assert_eq!(recommendation, "allow", "{why}");
    let base = tempfile::tempdir().expect("temp");
    let home = base.path().join("home");
    std::fs::create_dir_all(home.join(".ssh")).expect("ssh");
    std::fs::write(home.join(".ssh/id_ed25519"), "k\n").expect("key");
    std::fs::create_dir_all(home.join("work/.git")).expect("work");
    let home_text = home.to_str().expect("utf-8").to_string();
    for cwd in [
        format!("{home_text}/work"),
        home_text.clone(),
        "/".to_string(),
    ] {
        let Some(context) = WorkingContext::discover(&cwd, Some(&home_text)) else {
            continue;
        };
        let analysis = analyze_command_in(line, Some(&engine()), Some(&context));
        assert_ne!(analysis.recommendation, "deny", "{cwd}: {analysis:?}");
        assert!(
            !analysis
                .signals
                .iter()
                .any(|s| s.signal == "sensitive_credential_read"),
            "{cwd}: {analysis:?}"
        );
    }
}
