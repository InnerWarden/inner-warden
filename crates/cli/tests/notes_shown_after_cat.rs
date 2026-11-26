//! The hook lets notes run that `cat` writes into a notes file and the
//! line then shows (`cat`, `head`), and still refuses the line that runs
//! the same file or pipes it into a shell. Notes that quote a here-document
//! handed to an interpreter which rewrites an agent's settings were refused
//! once a `cat` of the file followed.
//!
//! Measured 2026-11-26 on the branch before the change: each shown line
//! below exited 2.
//!
//! Drives the REAL binary over a disposable HOME, with the hook line Claude
//! Code runs (`innerwarden hook --agent claude-code`, default posture).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::json;

fn bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_innerwarden"))
}

/// The exit code of the hook for one shell line.
fn hook_exit(home: &Path, line: &str) -> Option<i32> {
    let payload = json!({
        "session_id": "notes-shown-after-cat",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": line},
        "cwd": home,
    });
    let mut child = Command::new(bin())
        .args(["hook", "--agent", "claude-code"])
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .env("IW_GRAPH_FILE", home.join("graph.json"))
        .env("IW_TEST_ACCOUNT_HOME", home)
        .current_dir(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the hook");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(payload.to_string().as_bytes())
        .expect("write the payload");
    child.wait_with_output().expect("hook ran").status.code()
}

const NOTES: &str = "cat >> ~/j.md <<EOF\nNotes on the hook test\npython3 - <<'EOF'\nopen('/home/u/.claude/settings.json','w').write('{}')\nEOF\n";

/// FAILS ON REVERT of `command_shows_files_only` in
/// `crates/agent-guard/src/shell.rs`: each line exits 2.
#[test]
fn the_hook_lets_notes_shown_after_cat_run() {
    let home = tempfile::tempdir().unwrap();
    for then in ["cat ~/j.md", "head -n 20 ~/j.md", "tail ~/j.md"] {
        let line = format!("{NOTES}{then}");
        assert_eq!(hook_exit(home.path(), &line), Some(0), "{line}");
    }
}

/// The same notes run, sourced or piped into a shell stay refused.
#[test]
fn the_hook_refuses_the_notes_file_run() {
    let home = tempfile::tempdir().unwrap();
    for then in [
        "bash ~/j.md",
        "source ~/j.md",
        "cat ~/j.md | sh",
        "python3 ~/j.md",
    ] {
        let line = format!("{NOTES}{then}");
        assert_eq!(hook_exit(home.path(), &line), Some(2), "{line}");
    }
}

/// A journal entry as an agent writes one: the date and a commit taken by
/// command substitution before notes appended by `cat` that quote a
/// here-document handed to `python3`, then the file shown. Measured
/// 2026-11-26 on the branch before this change: exit 2, with and without
/// the last `cat`.
///
/// FAILS ON REVERT of the head reading in `text_written_by_cat_blanked`
/// (`crates/agent-guard/src/shell.rs`).
#[test]
fn the_hook_lets_a_journal_entry_with_substitutions_run() {
    let home = tempfile::tempdir().unwrap();
    let entry = "mkdir -p ~/journal && D=$(date -u +%Y-%m-%dT%H:%MZ) && SHA=$(git -C ~/src/repo rev-parse --short HEAD) && cat >> ~/journal/T-1.md <<EOF\n$D PR ready (commit $SHA)\n$D OUT OF SCOPE: python3 - <<'EOF' + open('~/.claude/settings.json','w') -> allow on main\nEOF\n";
    for then in ["", "cat ~/journal/T-1.md"] {
        let line = format!("{entry}{then}");
        assert_eq!(hook_exit(home.path(), &line), Some(0), "{line}");
    }
    let run = format!("{entry}bash ~/journal/T-1.md");
    assert_eq!(hook_exit(home.path(), &run), Some(2), "{run}");
}

/// A substitution before the notes that sends a run of the notes file to
/// the background outlives the head and runs the notes once written.
/// Measured 2026-11-26 in review: exit 0 on the branch before this change.
///
/// FAILS ON REVERT of `command_substitutes_only_listed` in
/// `crates/agent-guard/src/shell.rs`.
#[test]
fn the_hook_refuses_a_head_substitution_that_outlives_it() {
    let home = tempfile::tempdir().unwrap();
    for head in [
        "D=$( (sleep 2; bash ~/j.md) >/dev/null 2>&1 & ) && ",
        "D=$(date -u +%F) && SHA=$( (sleep 2; bash ~/j.md) >/dev/null 2>&1 & echo abc) && ",
        "true >(sleep 2; bash ~/j.md) && ",
    ] {
        let line = format!("{head}{NOTES}cat ~/j.md");
        assert_eq!(hook_exit(home.path(), &line), Some(2), "{line}");
    }
}
