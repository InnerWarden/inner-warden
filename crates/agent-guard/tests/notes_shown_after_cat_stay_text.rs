//! Notes that `cat` writes into a notes file are text, and showing that
//! file afterwards (`cat`, `head`, `tail`, `less`, `more`, `bat`) does
//! not make them a script: showing a file never runs it. Notes that quote a
//! here-document handed to an interpreter which rewrites an agent's
//! settings were refused as that rewrite once a `cat` of the same file
//! followed on the line.
//!
//! What runs the file afterwards (a shell, `source`, `.`, an interpreter,
//! `chmod +x` and the file run, the file piped into a shell or an
//! interpreter, a pager told to run a command or to load a key file) and a
//! here-document handed to an interpreter stay refused.
//!
//! Measured 2026-11-26 on the branch before the change: every shown line
//! below was refused (`guard_self_disable`), every refused line was
//! refused too. Asserted through [`analyze_command`], the entry point the
//! hook uses.

use innerwarden_agent_guard::mcp::analyze_command;

/// What the notes say: a here-document handed to `python3` that opens an
/// agent's settings for writing, quoted inside the notes.
const NOTES: &[&str] = &[
    "Seen in the review: python3 - <<'EOF' then open('/home/u/.claude/settings.json','w') rewrites it",
    "Notes on the hook test\npython3 - <<'EOF'\nimport json\nopen('/home/u/.claude/settings.json','w').write('{}')\nmore prose",
];

/// How the notes are written: appended or replaced, delimiter quoted or not.
const WRITES: &[(&str, &str)] = &[(">>", "EOF"), (">>", "'EOF'"), (">", "EOF"), (">", "'EOF'")];

/// Commands that only show the file.
const SHOWN: &[&str] = &[
    "cat ~/j.md",
    "cat -n ~/j.md",
    "head ~/j.md",
    "head -n 5 ~/j.md > /dev/null",
    "tail -n 20 ~/j.md",
    "less ~/j.md",
    "more ~/j.md",
    "bat ~/j.md",
];

/// Commands that run the file, or hand it to something that may.
const RUN: &[&str] = &[
    "bash ~/j.md",
    "sh ~/j.md",
    "zsh ~/j.md",
    "source ~/j.md",
    ". ~/j.md",
    "python3 ~/j.md",
    "chmod +x ~/j.md && ~/j.md",
    "cat ~/j.md | sh",
    "cat ~/j.md | bash",
    "cat ~/j.md | python3",
    "cat ~/j.md | python3 -",
    "head ~/j.md | sh",
    "tail ~/j.md | python3 -",
    "less +!sh ~/j.md",
    "less '+!python3 ~/j.md' ~/j.md",
    "less --lesskey-src=~/j.md ~/j.md",
    "bat --pager sh ~/j.md",
    "cat ~/j.md > ~/.claude/settings.json",
    "cat ~/j.md > run.sh && sh run.sh",
];

fn written_then(notes: &str, op: &str, delimiter: &str, then: &str) -> String {
    format!("cat {op} ~/j.md <<{delimiter}\n{notes}\nEOF\n{then}")
}

/// FAILS ON REVERT of `command_shows_files_only` in `shell.rs` (read by
/// `text_written_by_cat_blanked`): every line is refused for taking the
/// guard down.
#[test]
fn notes_written_by_cat_and_then_shown_stay_text() {
    for notes in NOTES {
        for (op, delimiter) in WRITES {
            for shown in SHOWN {
                let line = written_then(notes, op, delimiter, shown);
                let analysis = analyze_command(&line, None);
                assert_eq!(analysis.recommendation, "allow", "{line}: {analysis:?}");
            }
        }
    }
}

#[test]
fn notes_written_by_cat_and_then_run_stay_refused() {
    for notes in NOTES {
        for (op, delimiter) in WRITES {
            for run in RUN {
                let line = written_then(notes, op, delimiter, run);
                let analysis = analyze_command(&line, None);
                assert_eq!(analysis.recommendation, "deny", "{line}: {analysis:?}");
            }
        }
    }
}

#[test]
fn a_here_document_handed_to_an_interpreter_stays_refused() {
    for line in [
        "python3 - <<'EOF'\nopen('/home/u/.claude/settings.json','w').write('{}')\nEOF",
        "bash <<EOF\npython3 -c \"open('/home/u/.claude/settings.json','w').write('{}')\"\nEOF",
        "cat > ~/j.md <<'EOF'\nnote\nEOF\npython3 - <<'EOF'\nopen('/home/u/.claude/settings.json','w').write('{}')\nEOF",
    ] {
        let analysis = analyze_command(line, None);
        assert_eq!(analysis.recommendation, "deny", "{line}: {analysis:?}");
    }
}
