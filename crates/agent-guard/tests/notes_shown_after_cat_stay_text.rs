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

/// A journal entry as an agent writes one: a folder made, the date and a
/// commit taken by command substitution, notes appended by `cat` that
/// quote a here-document handed to `python3` which opens an agent's
/// settings, the date and the commit expanded in the notes, and the file
/// shown. Measured 2026-11-26 on the branch before this change: refused
/// (`guard_self_disable`), with and without the last `cat`.
const JOURNAL_HEAD: &str = "mkdir -p ~/journal && D=$(date -u +%Y-%m-%dT%H:%MZ) && SHA=$(git -C ~/src/repo rev-parse --short HEAD) && ";
const JOURNAL_NOTES: &str = "cat >> ~/journal/T-1.md <<EOF
$D PR ready: repo fix/heredoc \"Guard: read a quoted here-document\" (commit $SHA; tests green)
$D OUT OF SCOPE: a python here-document that writes an agent's settings passes on main (python3 - <<'EOF' + open('~/.claude/settings.json','w') -> allow), while python3 -c is refused (\"rewrites an agent's configuration through an interpreter\").
$D OUT OF SCOPE: python3 -c \"...s.replace('innerwarden allow x', ...)...\" stays refused.
EOF
";

/// FAILS ON REVERT of the head reading in `text_written_by_cat_blanked`
/// (`shell.rs`: a line with any command substitution read whole): each
/// line is refused for taking the guard down.
#[test]
fn a_journal_entry_with_substitutions_before_the_notes_stays_text() {
    let heads = [
        JOURNAL_HEAD,
        "D=$(date -u +%Y-%m-%dT%H:%MZ) && SHA=$(git -C ~/src/repo rev-parse --short HEAD) && ",
        "mkdir -p ~/journal && D=$(date -u +%Y-%m-%dT%H:%MZ) && ",
        "D=$(date -u +%Y-%m-%dT%H:%MZ) && ",
        "mkdir -p ~/journal; D=`date -u +%F`; ",
    ];
    for head in heads {
        for tail in ["", "cat ~/journal/T-1.md", "tail -n 3 ~/journal/T-1.md"] {
            let line = format!("{head}{JOURNAL_NOTES}{tail}");
            let analysis = analyze_command(&line, None);
            assert_eq!(analysis.recommendation, "allow", "{line}: {analysis:?}");
        }
    }
}

/// A substitution that may run the notes, or text not yet blanked, keeps
/// the line read whole: after the notes, in a body that expands, beside the
/// notes through a pipe, a `&` or a group, or a variable that changes what
/// runs next.
///
/// FAILS ON REVERT of each guard around the head reading in
/// `text_written_by_cat_blanked` (`shell.rs`): `command_substitutes`
/// after the notes, `inputs_run` in `command_substitutes` (a body that
/// expands), and `background`, `groups` and the pipe before the notes.
#[test]
fn substitutions_that_may_run_the_notes_stay_refused() {
    let notes = "cat > ~/j.md <<'EOF'\nNotes on the hook test\npython3 - <<'EOF'\nopen('/home/u/.claude/settings.json','w').write('{}')\nEOF\n";
    let mut lines: Vec<String> = [
        "X=$(bash ~/j.md)",
        "echo $(bash ~/j.md)",
        "echo \"$(sh ~/j.md)\"",
        "echo `python3 ~/j.md`",
        "cat <(bash ~/j.md)",
        "echo ${X:-$(bash ~/j.md)}",
    ]
    .iter()
    .map(|tail| format!("{notes}{tail}"))
    .collect();
    lines.extend([
        format!("D=$(sleep 1; bash ~/j.md) & {notes}"),
        format!("D=$(sleep 1; bash ~/j.md) | {notes}"),
        format!("{{ D=$(sleep 1; bash ~/j.md); }} & {notes}"),
        format!("(D=$(sleep 1; bash ~/j.md)) | {notes}"),
        "cat > ~/j.md <<EOF\nNotes\n$(python3 - <<'PY'\nopen('/home/u/.claude/settings.json','w').write('{}')\nPY\n)\nEOF\ncat ~/j.md".to_string(),
        "cat > ~/j.md <<EOF\nNotes\n`python3 -c \"open('/home/u/.claude/settings.json','w').write('{}')\"`\nEOF".to_string(),
    ]);
    for line in &lines {
        let analysis = analyze_command(line, None);
        assert_eq!(analysis.recommendation, "deny", "{line}: {analysis:?}");
    }
}

/// A journal entry whose head takes its values only through the closed
/// list of commands that print a value and end (`date`, `git log` with a
/// format, `git branch --show-current`, `git describe`, `hostname`,
/// `whoami`, `id -un`, `uname`, `basename`, `dirname`, `pwd`,
/// `printf`) stays text, as the date and the commit do.
#[test]
fn a_journal_entry_whose_head_runs_only_listed_commands_stays_text() {
    for head in [
        "D=$(git log -1 --format=%h) && ",
        "D=$(git -C ~/src/repo log -n 1 --pretty=format:%s main) && ",
        "B=$(git -C ~/src/repo branch --show-current) && V=$(git describe --tags --always) && ",
        "H=$(hostname -s) && U=$(whoami) && I=$(id -un) && K=$(uname -r) && ",
        "R=$(basename \"$(pwd)\") && P=$(dirname ~/journal/T-1.md) && ",
        "D=$(date -u +%F 2>/dev/null) && T=$(printf '%s-%s' a b) && ",
    ] {
        let line = format!("{head}{JOURNAL_NOTES}cat ~/journal/T-1.md");
        let analysis = analyze_command(&line, None);
        assert_eq!(analysis.recommendation, "allow", "{line}: {analysis:?}");
    }
}

/// A substitution before the notes that starts something which outlives
/// it runs the notes once written: a `&` inside it, a process
/// substitution, a pipe into a shell, a launcher, a command off the list,
/// a git option that runs a program, `printf -v`, a nested substitution
/// off the list. Measured 2026-11-26 in review: allowed by the branch
/// before this change, and bash ran the notes after the line returned in
/// four of these spellings.
///
/// FAILS ON REVERT of `command_substitutes_only_listed` in
/// `text_written_by_cat_blanked` (`shell.rs`).
#[test]
fn a_substitution_before_the_notes_that_may_outlive_it_stays_refused() {
    let notes = "cat >> ~/j.md <<EOF\nNotes on the hook test\npython3 - <<'EOF'\nopen('/home/u/.claude/settings.json','w').write('{}')\nEOF\n";
    for head in [
        "D=$( (sleep 2; bash ~/j.md) >/dev/null 2>&1 & ) && ",
        "D=$( { sleep 2; bash ~/j.md; } >/dev/null 2>&1 & echo x) && ",
        "D=$(date -u +%F) && SHA=$( (sleep 2; bash ~/j.md) >/dev/null 2>&1 & echo abc) && ",
        "D=$(tail -n0 -F ~/j.md 2>/dev/null | sh >/dev/null 2>&1 &) && ",
        "D=$(nohup sh -c 'sleep 2; sh ~/j.md' >/dev/null 2>&1 &) && ",
        "true >(sleep 2; bash ~/j.md) && ",
        "mkdir -p <(sleep 2; bash ~/j.md) && ",
        "D=$(setsid -f bash -c 'sleep 2; bash ~/j.md') && ",
        "D=$(date -u +%F $(sleep 2 &)) && ",
        "D=`(sleep 2; bash ~/j.md) &` && ",
        "D=${X:-$( (sleep 2; bash ~/j.md) & )} && ",
        "D=$(git -c core.pager='sh ~/j.md' log -1) && ",
        "D=$(git log -1 --output=/home/u/.bashrc) && ",
        "D=$(printf -v X %s 1) && ",
        "D=$(date > ~/j.md) && ",
        "D=$(date <<< x) && ",
        "mkdir -p <(date) && ",
        "P='$( (sleep 2; bash ~/j.md) & )' && D=${P@P} && ",
    ] {
        for tail in ["", "cat ~/j.md"] {
            let line = format!("{head}{notes}{tail}");
            let analysis = analyze_command(&line, None);
            assert_eq!(analysis.recommendation, "deny", "{line}: {analysis:?}");
        }
    }
}

/// Showing the notes into a file that is not a notes file (a shell's
/// startup file, an agent's instructions, a file in an agent's folder)
/// writes them where they are read or run: the line stays read whole.
///
/// FAILS ON REVERT of the write condition of `command_shows_files_only`
/// (`shell.rs`): the startup files and the instructions go to review, the
/// file in `~/.config` to allow.
#[test]
fn notes_shown_into_a_file_that_is_read_or_run_stay_refused() {
    for notes in NOTES {
        for (op, delimiter) in WRITES {
            for shown in [
                "cat ~/j.md > ~/.bashrc",
                "cat ~/j.md > ~/.profile",
                "cat ~/j.md > ~/.zshrc",
                "cat ~/j.md >> ~/AGENTS.md",
                "cat ~/j.md > ~/.config/x.md",
            ] {
                let line = written_then(notes, op, delimiter, shown);
                let analysis = analyze_command(&line, None);
                assert_eq!(analysis.recommendation, "deny", "{line}: {analysis:?}");
            }
        }
    }
}
