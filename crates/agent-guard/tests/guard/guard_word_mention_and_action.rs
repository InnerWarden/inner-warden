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
    #[serde(default)]
    expect: Option<String>,
}

fn corpus() -> Vec<Case> {
    let text = include_str!("../../corpus/guard-word-mention-2026-11/cases.yml");
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
    // Each benign line of the corpus is held as its `expect` says: a
    // mention in a slot of data for review, a folder of one's own in the
    // middle of a path let through (gwm-c01, since 2026-11-27).
    for case in corpus().iter().filter(|case| case.label == "benign") {
        let (recommendation, _, why) = verdict(&case.input);
        let expected = case.expect.as_deref().unwrap_or("review");
        assert_eq!(recommendation, expected, "{}: {why}", case.id);
    }
    // A file whose name holds `kill` (`kill-cases.json`) is moved: no stop
    // or kill verb stands as a word of its own, so nothing is refused and
    // there is no mention to hold.
    let (recommendation, _, why) =
        verdict("mv ~/work/innerwarden/scripts/kill-cases.json ~/work/innerwarden/scripts/k.json");
    assert_eq!(recommendation, "allow", "{why}");
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

/// A package or a target of the project named after the guard, in a build,
/// a check or a test, is a name: `cargo test -p innerwarden --bin innerwarden
/// contain` filters the tests by `contain` and starts no jail (BI
/// FP-20261120-repo-name-and-literal-variable). Measured 2026-11-21 against
/// main fa63f83: refused as "starts a jail", with a pipe to `grep` or the
/// output in a log. `cargo run` runs what it builds and keeps the name.
#[test]
fn a_test_filter_of_the_guards_package_starts_no_jail() {
    for line in [
        "cargo test -p innerwarden --bin innerwarden contain",
        "cd ~/work/wt-1 && cargo test -p innerwarden --bin innerwarden contain 2>&1 | grep -E 'FAILED|test result'",
        "CARGO_TARGET_DIR=/home/u/work/target cargo test -p innerwarden --bin innerwarden contain > /home/u/work/t.log 2>&1",
        "cargo test --package=innerwarden contain",
    ] {
        let (recommendation, signals, why) = verdict(line);
        assert_eq!(recommendation, "review", "{line:?}: {why}");
        assert!(signals.iter().any(|s| s == "guard_word_mention"), "{line:?}: {signals:?}");
    }
    for line in [
        "cargo run --bin innerwarden contain",
        "cargo run -p innerwarden -- contain",
        "cargo test -p innerwarden contain && innerwarden contain",
        "cargo test -p innerwarden contain > run.sh; sh run.sh",
    ] {
        let (recommendation, _, why) = verdict(line);
        assert_eq!(recommendation, "deny", "{line:?}: {why}");
    }
}

/// The text of a note (`echo`, `printf`) written to a `.md`, `.txt` or
/// `.log` file of the home or the project is text, with its time from
/// `$(date ...)`: a journal line that quoted a refused path was refused
/// (BI FP-20261120-message-text-quoting-refused-forms; measured 2026-11-21
/// against main fa63f83). The same text to a file an agent or the shell
/// reads as orders, or beside a substitution that acts, stays refused.
#[test]
fn a_note_that_quotes_a_refused_path_is_text() {
    for line in [
        "echo \"x /etc/sudoers.d/a b\" >> ~/journal/T-1.md",
        "echo \"$(date -u '+%F') x /etc/sudoers.d/a\" >> ~/journal/T-1.md",
        "echo \"$(date -u '+%Y-%m-%d %H:%M UTC') FEITO: (\"/etc/sudoers.d/a b\\n\") stays refused\" >> ~/journal/T-1.md",
        "printf '%s\\n' 'see /etc/sudoers.d/90-cloud' >> docs/notes.md",
    ] {
        let (recommendation, signals, why) = verdict(line);
        assert_eq!(recommendation, "review", "{line:?}: {why}");
        assert!(signals.iter().any(|s| s == "guard_word_mention"), "{line:?}: {signals:?}");
    }
    for line in [
        "echo 'systemctl stop innerwarden-agent' >> ~/.bashrc",
        "echo 'x /etc/sudoers.d/a' >> ~/.claude/CLAUDE.md",
        "echo 'x /etc/sudoers.d/a' >> CLAUDE.md",
        "echo \"ALL ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers.d/x",
        "echo \"$(date -u) $(systemctl stop innerwarden-agent)\" >> notes.md",
        "echo \"$(date; systemctl stop innerwarden-agent) x\" >> notes.md",
        "echo \"$(date -f /etc/shadow) x /etc/sudoers.d/a\" >> notes.md",
        "echo \"$(date -u) x /etc/sudoers.d/a\" >> notes.md && $_",
    ] {
        let (recommendation, _, why) = verdict(line);
        assert_eq!(recommendation, "deny", "{line:?}: {why}");
    }
}

/// `systemctl` in a string that Node prints runs nothing; a call of
/// `system` or a child process does (BI
/// FP-20261120-guard-words-in-interpreter-code, measured 2026-11-21 against
/// main fa63f83: `system` was found inside `systemctl`).
#[test]
fn node_code_that_prints_a_unit_name_runs_nothing() {
    let (recommendation, _, why) =
        verdict("node -e \"console.log('systemctl disable innerwarden-agent')\"");
    assert_eq!(recommendation, "review", "{why}");
    for line in [
        "node -e \"require('child_process').execSync('systemctl stop innerwarden-agent')\"",
        "ruby -e \"system('systemctl stop innerwarden-agent')\"",
        "ruby -e \"system 'systemctl stop innerwarden-agent'\"",
        "perl -e 'system(\"systemctl stop innerwarden-agent\")'",
    ] {
        let (recommendation, _, why) = verdict(line);
        assert_eq!(recommendation, "deny", "{line:?}: {why}");
    }
}
