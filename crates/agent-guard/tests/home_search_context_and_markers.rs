//! A search of the whole home whose output can carry a key keeps the hard
//! refusal, in the shell as in the agent's own `Grep`.
//!
//! Measured 2026-11-20 on main (analyze_command_in, a home that holds
//! `~/.ssh/id_ed25519`): `grep -r -A 40 OPENSSH ~` was a `review` the hook
//! let through, and grep prints the key whole from the lines after its first;
//! `grep -r -e sk_live ~` the same. `ag --hidden`, `ag -u`, `ack` and
//! `git grep --no-index` over the home were `allow`.

use innerwarden_agent_guard::mcp::{analyze_command_in, WorkingContext};
use innerwarden_agent_guard::threats::pattern_is_narrow;

fn home_with_a_key() -> (std::path::PathBuf, WorkingContext) {
    let base = std::env::temp_dir().join(format!(
        "iw-home-search-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let home = base.join("home");
    std::fs::create_dir_all(home.join(".ssh")).expect("ssh");
    std::fs::write(home.join(".ssh/id_ed25519"), "k\n").expect("key");
    std::fs::create_dir_all(home.join("work/.git")).expect("work");
    let home_text = home.to_str().expect("utf-8").to_string();
    let context =
        WorkingContext::discover(&format!("{home_text}/work"), Some(&home_text)).expect("context");
    (base, context)
}

fn verdicts(context: &WorkingContext, lines: &[&str], want: &str) {
    for command in lines {
        let analysis = analyze_command_in(command, None, Some(context));
        assert_eq!(analysis.recommendation, want, "{command}: {analysis:?}");
    }
}

/// FAILS ON REVERT of the context arms in `searches_for_narrow_text`
/// (threats.rs): each line is a `review`.
#[test]
fn a_home_search_with_lines_of_context_is_denied() {
    let (base, context) = home_with_a_key();
    verdicts(
        &context,
        &[
            "grep -r -A 40 OPENSSH ~",
            "grep -r -B 5 -A 40 TODO ~",
            "grep -r -C 40 TODO ~",
            "grep -r -A40 TODO ~",
            "grep -rA 40 TODO ~",
            "grep -rn -40 TODO ~",
            "grep -r --after-context=40 TODO ~",
            "grep -r --before-context 3 TODO ~",
            "grep -r --context 40 TODO ~",
            "grep -r -A 3 TODO $HOME",
        ],
        "deny",
    );
    std::fs::remove_dir_all(&base).ok();
}

/// FAILS ON REVERT of `openssh` and `sk_(live|test)` in
/// `names_credential_marker`: the shell lines are a `review` and the
/// patterns are narrow text, so the agent's `Grep` of the home for them is
/// judged as a narrow search too.
#[test]
fn a_home_search_for_a_key_marker_is_denied() {
    for marker in [
        "OPENSSH",
        "BEGIN OPENSSH",
        "sk_live",
        "sk_test",
        "rk_live",
        "xoxb-",
        "AIza",
        "AKIA",
        "ssh-ed25519",
        "b3BlbnNzaC1rZXk",
    ] {
        assert!(!pattern_is_narrow(marker, false), "{marker}");
        assert!(!pattern_is_narrow(marker, true), "{marker}");
    }
    assert!(pattern_is_narrow("TODO", false));
    assert!(pattern_is_narrow("task_list", false));
    let (base, context) = home_with_a_key();
    verdicts(
        &context,
        &[
            "grep -r OPENSSH ~",
            "grep -r -e sk_live ~",
            "grep -r -e sk_test ~",
            "grep -r xoxb- ~",
            "grep -r AIza ~",
            "grep -r AKIA ~",
            "grep -r ssh-ed25519 ~",
            "grep -r b3BlbnNzaC1rZXk ~",
        ],
        "deny",
    );
    std::fs::remove_dir_all(&base).ok();
}

/// FAILS ON REVERT of `ag` and `ack` in `content_reader`, or of the `ag -u`
/// and `git grep --no-index` arms of `reads_folders_whole`: each line is
/// an `allow`.
#[test]
fn other_searchers_of_the_whole_home_are_denied() {
    let (base, context) = home_with_a_key();
    verdicts(
        &context,
        &[
            "rg --hidden -A 40 OPENSSH ~",
            "rg -uu -C 5 TODO ~",
            "ag --hidden -A 40 OPENSSH ~",
            "ag -u -A 40 TODO ~",
            "ack -A 40 OPENSSH ~",
            "ack TODO ~",
            "git grep --no-index -A 40 OPENSSH ~",
            "git grep --no-index -A 40 TODO -- ~",
            "git -C ~ grep --no-index -A 40 TODO",
        ],
        "deny",
    );
    std::fs::remove_dir_all(&base).ok();
}

/// What stays as it was: a home search for a narrow text with no context is
/// a person's call, and searches of the project, with context or not, pass.
#[test]
fn narrow_and_project_searches_keep_their_verdict() {
    let (base, context) = home_with_a_key();
    verdicts(
        &context,
        &[
            "grep -r TODO ~",
            "grep -rn 'fn main' ~",
            "grep -rl -m 3 TODO ~",
        ],
        "review",
    );
    verdicts(
        &context,
        &[
            "grep -rn -A 3 TODO src",
            "grep -rn -C 2 OPENSSH src",
            "rg -A 3 TODO src",
            "rg -A 40 OPENSSH ~",
            "ag -A 3 TODO src",
            "ack -C 2 TODO src",
            "git grep -A 3 TODO",
            "grep -A 40 OPENSSH notes.txt",
        ],
        "allow",
    );
    std::fs::remove_dir_all(&base).ok();
}
