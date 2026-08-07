//! Guard: no em dash (U+2014) may enter the user-facing source trees.
//!
//! The operator's writing rule bans the character outright. It reached the
//! live dashboard once (the Overview hero), so the ban is enforced here
//! rather than remembered:
//!
//! * the dashboard web tree (`web/src` plus `web/index.html`) is scanned as
//!   raw text, comments included, because everything in it is shipped copy
//!   or one edit away from being shipped copy;
//! * every Rust string literal in `crates/` is scanned, because Rust strings
//!   are what dashboard payload summaries and API messages are built from.
//!
//! The character and its escape spellings are constructed at runtime so this
//! file cannot trip its own scan. The backslash-u escape forms used by
//! TypeScript and Rust are caught too; they decode to the same character in
//! the browser.

use std::fs;
use std::path::{Path, PathBuf};

fn em_dash() -> char {
    char::from_u32(0x2014).expect("U+2014 is a valid scalar")
}

/// The TypeScript/JavaScript escape spelling, built without writing it out.
fn ts_escape() -> String {
    format!("{}u2014", '\\')
}

/// The Rust escape spelling, built without writing it out.
fn rust_escape() -> String {
    format!("{}u{{2014}}", '\\')
}

const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "dist",
    "test-results",
    "playwright-report",
];

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("guard cannot read {}: {e}", dir.display()));
    for entry in entries {
        let entry = entry.expect("readable directory entry");
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn line_of(text: &str, byte_index: usize) -> usize {
    text[..byte_index].matches('\n').count() + 1
}

/// Scan raw text (comments included) for the character and both escape
/// spellings. Returns `file:line` findings.
fn scan_raw(path: &Path, findings: &mut Vec<String>) {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("guard cannot read {}: {e}", path.display()));
    for needle in [em_dash().to_string(), ts_escape(), rust_escape()] {
        for (index, _) in text.match_indices(&needle) {
            findings.push(format!(
                "{}:{}: em dash ({needle:?})",
                path.display(),
                line_of(&text, index)
            ));
        }
    }
}

/// Scan only the string literals of a Rust source file.
///
/// Comments are allowed to carry the character (they never reach a user);
/// string literals are not, because they are exactly what gets serialized
/// into dashboard payloads, log lines and assertion output.
fn scan_rust_strings(path: &Path, findings: &mut Vec<String>) {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("guard cannot read {}: {e}", path.display()));
    let banned_char = em_dash();
    let banned_escape = rust_escape();
    let bytes: Vec<char> = text.chars().collect();
    let n = bytes.len();
    let mut i = 0usize;
    let mut line = 1usize;

    #[derive(PartialEq, Clone, Copy)]
    enum Mode {
        Code,
        LineComment,
        BlockComment(u32),
        Str,
        RawStr(usize),
    }
    let mut mode = Mode::Code;
    let mut literal_start_line = 0usize;
    let mut literal = String::new();

    let flush = |literal: &mut String, start_line: usize, findings: &mut Vec<String>| {
        if literal.contains(banned_char) || literal.contains(&banned_escape) {
            findings.push(format!(
                "{}:{}: em dash inside a Rust string literal",
                path.display(),
                start_line
            ));
        }
        literal.clear();
    };

    while i < n {
        let c = bytes[i];
        if c == '\n' {
            line += 1;
            if mode == Mode::LineComment {
                mode = Mode::Code;
            }
            if matches!(mode, Mode::Str | Mode::RawStr(_)) {
                literal.push(c);
            }
            i += 1;
            continue;
        }
        match mode {
            Mode::Code => {
                if c == '/' && i + 1 < n && bytes[i + 1] == '/' {
                    mode = Mode::LineComment;
                    i += 2;
                } else if c == '/' && i + 1 < n && bytes[i + 1] == '*' {
                    mode = Mode::BlockComment(1);
                    i += 2;
                } else if c == '"' {
                    mode = Mode::Str;
                    literal_start_line = line;
                    i += 1;
                } else if c == 'r' || c == 'b' {
                    // Possible raw string prefix: r"...", br#"..."#, rb"...".
                    let mut j = i;
                    let mut saw_r = false;
                    while j < n && (bytes[j] == 'r' || bytes[j] == 'b') && j - i < 2 {
                        if bytes[j] == 'r' {
                            saw_r = true;
                        }
                        j += 1;
                    }
                    let mut hashes = 0usize;
                    let mut k = j;
                    while saw_r && k < n && bytes[k] == '#' {
                        hashes += 1;
                        k += 1;
                    }
                    if saw_r && k < n && bytes[k] == '"' {
                        mode = Mode::RawStr(hashes);
                        literal_start_line = line;
                        i = k + 1;
                    } else {
                        i += 1;
                    }
                } else if c == '\'' {
                    // Char literal or lifetime.
                    if i + 1 < n && bytes[i + 1] == '\\' {
                        let mut j = i + 2;
                        while j < n && bytes[j] != '\'' {
                            j += 1;
                        }
                        i = j + 1;
                    } else if i + 2 < n && bytes[i + 2] == '\'' {
                        i += 3;
                    } else {
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            Mode::LineComment => i += 1,
            Mode::BlockComment(depth) => {
                if c == '/' && i + 1 < n && bytes[i + 1] == '*' {
                    mode = Mode::BlockComment(depth + 1);
                    i += 2;
                } else if c == '*' && i + 1 < n && bytes[i + 1] == '/' {
                    mode = if depth == 1 {
                        Mode::Code
                    } else {
                        Mode::BlockComment(depth - 1)
                    };
                    i += 2;
                } else {
                    i += 1;
                }
            }
            Mode::Str => {
                if c == '\\' && i + 1 < n {
                    if bytes[i + 1] == '\n' {
                        line += 1;
                    }
                    literal.push(c);
                    literal.push(bytes[i + 1]);
                    i += 2;
                } else if c == '"' {
                    flush(&mut literal, literal_start_line, findings);
                    mode = Mode::Code;
                    i += 1;
                } else {
                    literal.push(c);
                    i += 1;
                }
            }
            Mode::RawStr(hashes) => {
                if c == '"' {
                    let mut matched = 0usize;
                    while matched < hashes && i + 1 + matched < n && bytes[i + 1 + matched] == '#' {
                        matched += 1;
                    }
                    if matched == hashes {
                        flush(&mut literal, literal_start_line, findings);
                        mode = Mode::Code;
                        i += 1 + matched;
                    } else {
                        literal.push(c);
                        i += 1;
                    }
                } else {
                    literal.push(c);
                    i += 1;
                }
            }
        }
    }
}

#[test]
fn user_facing_sources_contain_no_em_dash() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let web_src = manifest.join("web").join("src");
    let index_html = manifest.join("web").join("index.html");
    let crates_root = manifest.join("..");

    assert!(
        web_src.is_dir(),
        "guard is vacuous: {} is missing",
        web_src.display()
    );
    assert!(
        index_html.is_file(),
        "guard is vacuous: {} is missing",
        index_html.display()
    );
    assert!(
        crates_root.is_dir(),
        "guard is vacuous: {} is missing",
        crates_root.display()
    );

    let mut findings = Vec::new();

    let mut web_files = Vec::new();
    walk(&web_src, &mut web_files);
    web_files.push(index_html);
    web_files.sort();
    for file in &web_files {
        scan_raw(file, &mut findings);
    }

    let mut rust_files = Vec::new();
    walk(&crates_root, &mut rust_files);
    rust_files.sort();
    let mut rust_scanned = 0usize;
    for file in rust_files
        .iter()
        .filter(|f| f.extension().is_some_and(|e| e == "rs"))
    {
        scan_rust_strings(file, &mut findings);
        rust_scanned += 1;
    }
    assert!(
        rust_scanned > 10,
        "guard is vacuous: only {rust_scanned} Rust files scanned"
    );

    assert!(
        findings.is_empty(),
        "em dash (U+2014) found in user-facing sources; replace it with a period, comma, colon or a rewording:\n{}",
        findings.join("\n")
    );
}
