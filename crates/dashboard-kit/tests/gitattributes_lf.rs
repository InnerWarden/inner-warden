//! Text files must be checked out with LF on every platform. The digest pins
//! in the CLI hash files embedded with `include_str!`, and a CRLF checkout on
//! Windows changes those bytes. `* text=auto eol=lf` has to come before any
//! other rule, because a later rule wins for the paths it matches.

use std::path::Path;
use std::process::Command;

fn repo_root() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

#[test]
fn the_first_gitattributes_rule_normalises_text_to_lf() {
    let path = repo_root().join(".gitattributes");
    let attrs = std::fs::read_to_string(&path).expect("read .gitattributes");
    let first_rule = attrs
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'));
    assert_eq!(
        first_rule,
        Some("* text=auto eol=lf"),
        "the first rule in .gitattributes must normalise text to LF"
    );
}

#[test]
fn git_resolves_pinned_text_files_to_lf_eol() {
    // Ask Git itself what it will do at checkout. A pinned file that has no
    // effective `eol=lf` (or is not treated as text) gets CRLF on Windows.
    let pinned = [
        "crates/cli/assets/openclaw-hook/handler.js",
        "crates/cli/src/observe_io.rs",
    ];
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root())
        .args(["check-attr", "eol", "text", "--"])
        .args(pinned)
        .output()
        .expect("run git check-attr");
    assert!(output.status.success(), "git check-attr failed: {output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for file in pinned {
        assert!(
            stdout.contains(&format!("{file}: eol: lf")),
            "git must check {file} out with eol=lf; check-attr said:\n{stdout}"
        );
        assert!(
            stdout.contains(&format!("{file}: text: auto")),
            "git must normalise {file} as text; check-attr said:\n{stdout}"
        );
    }
}
