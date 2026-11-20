//! The Windows install command every user reads names the host that serves
//! the installer, not the bare domain. The bare domain answers with a 308
//! to `www`, and Windows PowerShell 5.1 (the shell every Windows box has)
//! does not follow a 308: `irm` stops at the redirect and `iex` runs
//! nothing. `www` answers with a 307 to the signed release asset, which 5.1
//! follows; the `windows-latest` job of `free-install-smoke.yml` runs the
//! command under 5.1. Measured 2026-11-20 with `curl -sI`:
//! `https://innerwarden.com/free.ps1` 308, `https://www.innerwarden.com/free.ps1`
//! 307 to the release asset.
//!
//! FAILS ON REVERT of the URL in any README, doc, npm launcher or CLI source.

use std::path::{Path, PathBuf};

const BARE: &str = "innerwarden.com/free.ps1";

/// Every text a user can read: the READMEs and docs, the npm package (its
/// launcher prints the command), and the sources of every crate (their
/// output). The changelog is history and is left as it was written.
fn user_texts(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![
        root.join("README.md"),
        root.join("DISTRIBUTION.md"),
        root.join("SECURITY.md"),
        root.join("CONTRIBUTING.md"),
        root.join("docs"),
        root.join("npm"),
        root.join("packaging"),
        root.join("crates"),
    ];
    while let Some(path) = stack.pop() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if matches!(name, "node_modules" | "target" | ".git") {
            continue;
        }
        if path.is_dir() {
            for entry in std::fs::read_dir(&path).expect("read dir") {
                stack.push(entry.expect("entry").path());
            }
        } else if path.is_file()
            && matches!(
                path.extension().and_then(|e| e.to_str()),
                Some(
                    "md" | "rs"
                        | "js"
                        | "mjs"
                        | "json"
                        | "txt"
                        | "ps1"
                        | "sh"
                        | "toml"
                        | "yml"
                        | "yaml"
                )
            )
        {
            out.push(path);
        }
    }
    out
}

#[test]
fn no_user_text_names_the_bare_domain_for_the_windows_installer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let this_file = Path::new(file!()).file_name().unwrap().to_owned();
    let mut found = Vec::new();
    let mut named_www = 0;
    for path in user_texts(&root) {
        if path.file_name() == Some(this_file.as_os_str()) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            for (at, _) in line.match_indices(BARE) {
                if line[..at].ends_with("www.") {
                    named_www += 1;
                } else {
                    found.push(format!(
                        "{}:{}: {}",
                        path.display(),
                        number + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "the bare domain, which 5.1 cannot follow:\n{}",
        found.join("\n")
    );
    // The README, the npm README and the npm launcher each print it.
    assert!(named_www >= 3, "only {named_www} places name the installer");
}
