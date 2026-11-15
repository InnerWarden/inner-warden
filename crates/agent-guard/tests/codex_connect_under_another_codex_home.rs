//! `agents connect codex` with `CODEX_HOME` naming another folder. For the
//! home this process runs under, the Codex started from here reads its hooks
//! there, so the hook written in ~/.codex is said not to be active, with the
//! folder Codex reads instead. For another home the variable says nothing:
//! that home's Codex is not the one started from here.
//!
//! A test binary of its own, and one test in it: it sets `HOME` and
//! `CODEX_HOME` for the whole process, which no other test may see.

use innerwarden_agent_guard::agent_hooks::{connect_noting_write, Outcome, CODEX};
use std::path::Path;

fn why_not_active(home: &Path) -> String {
    std::fs::create_dir_all(home.join(".codex")).unwrap();
    let guard = home.join("bin/innerwarden");
    let connected =
        connect_noting_write(home, &CODEX, &guard, false, false, None).expect("connect");
    assert!(home.join(".codex/hooks.json").is_file());
    match connected.outcome {
        Outcome::NotActive { why, .. } => why,
        other => panic!("{other:?}"),
    }
}

/// FAILS ON REVERT: read `==` as `!=` in the test of Codex's answer in
/// `agent_hooks::connect_noting_write`, or `!=` as `==` in the test of the
/// agent in `where_codex_reads`, and with no Codex asked the hook in this
/// process's home is said to be not trusted yet; read `||` as `&&` there and
/// the variable is read for the other home too.
#[test]
fn connect_under_another_codex_home_names_the_folder_codex_reads() {
    let home = tempfile::TempDir::new().unwrap();
    let elsewhere = home.path().join("codex-home");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::env::set_var("HOME", home.path());
    std::env::set_var("USERPROFILE", home.path());
    std::env::set_var("CODEX_HOME", &elsewhere);

    assert_eq!(
        why_not_active(home.path()),
        format!(
            "Codex does not read it: CODEX_HOME is set to {}",
            elsewhere.display()
        )
    );

    let other = tempfile::TempDir::new().unwrap();
    assert_eq!(
        why_not_active(other.path()),
        "Codex skips it: it is not trusted yet"
    );
}
