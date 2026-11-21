//! The files an agent reads as its instructions, and the lines that put
//! another file in their place.
//!
//! Claude Code reads `CLAUDE.md`, Codex and others `AGENTS.md`, Gemini CLI
//! `GEMINI.md`, Cursor `.cursorrules`, Copilot
//! `.github/copilot-instructions.md`, at the start of every session, and
//! takes what they say as the operator's word. The shell side reads the text
//! a line writes into one ([`crate::threats`], `instruction_files`); the
//! file side reads what an agent's own file tool writes there
//! ([`crate::file_tools::written_texts`]); both judge it with
//! [`crate::mcp::written_instruction_order`].
//!
//! A copy, move or link over such a file ([`overwrites`]) writes text that is
//! not on the line: `cp /tmp/x.md CLAUDE.md` says nothing of what `x.md`
//! holds. Such a line is a review; when the same line wrote the file it
//! copies, that text is read as if it were written into the instruction
//! file itself.

use crate::threats::{
    effective_command_index, is_shell_program, shell_command_segments, shell_tokens, token_basename,
};

/// The names of the files agents read as their instructions, lower case.
pub(crate) const INSTRUCTION_NAMES: &[&str] = &[
    "claude.md",
    "claude.local.md",
    "agents.md",
    "agents.override.md",
    "gemini.md",
    "copilot-instructions.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
    ".roorules",
    ".goosehints",
];

/// Folders whose every file an agent reads as its rules.
pub(crate) const INSTRUCTION_FOLDERS: &[&str] = &[
    ".claude/rules/",
    ".cursor/rules/",
    ".windsurf/rules/",
    ".clinerules/",
    ".roo/rules/",
    ".kiro/steering/",
    ".github/instructions/",
];

/// Whether `path` names a file an agent reads as its instructions.
pub fn is_instruction_file(path: &str) -> bool {
    let lower = path
        .trim_matches(|c: char| c == '"' || c == '\'')
        .to_ascii_lowercase()
        .replace('\\', "/");
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    INSTRUCTION_NAMES.contains(&name)
        || name.ends_with(".instructions.md")
        || INSTRUCTION_FOLDERS
            .iter()
            .any(|folder| lower.starts_with(folder) || lower.contains(&format!("/{folder}")))
}

/// The line a shell runs from its `-c` (`-lc`, `-ec`): the word after it.
pub(crate) fn shell_line(args: &[String]) -> Option<&str> {
    let at = args.iter().position(|arg| {
        arg.len() > 1
            && arg.starts_with('-')
            && !arg.starts_with("--")
            && arg[1..].chars().all(|c| c.is_ascii_alphabetic())
            && arg.contains('c')
    })?;
    args.get(at + 1).map(String::as_str)
}

/// How many shells deep a `-c` line is read for a copy.
const SHELL_DEPTH: u8 = 3;

/// A copy, move or link that puts other files in the place of an
/// instruction file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Overwrite {
    /// The instruction file replaced, as the line names it (a folder the
    /// line names joined with the name of the file copied into it).
    pub(crate) file: String,
    /// The files put in its place, as the line names them.
    pub(crate) sources: Vec<String>,
}

/// Whether a line mentions an instruction file at all: the cheap test
/// before it is parsed.
pub(crate) fn mentions_one(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    INSTRUCTION_NAMES
        .iter()
        .chain(INSTRUCTION_FOLDERS)
        .any(|name| lower.contains(name.trim_end_matches('/')))
        || lower.contains(".instructions.md")
}

/// Every `cp`, `mv` or `ln` of a line (and of the line a shell's `-c` runs)
/// that puts a file in the place of an instruction file: named as the
/// target, or a file of an instruction file's name copied into `.`, `..`,
/// `~`, a path that ends in `/` or the folder of `-t`. A target folder
/// named any other way is not known to be one, and is not read.
pub(crate) fn overwrites(content: &str) -> Vec<Overwrite> {
    overwrites_at(content, 0)
}

fn overwrites_at(content: &str, depth: u8) -> Vec<Overwrite> {
    if !mentions_one(content) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for segment in shell_command_segments(content) {
        let words = shell_tokens(segment);
        let Some(at) = effective_command_index(&words) else {
            continue;
        };
        let name = token_basename(&words[at]).to_ascii_lowercase();
        if is_shell_program(&name) {
            if let Some(line) = shell_line(&words[at + 1..]) {
                if depth < SHELL_DEPTH {
                    out.extend(overwrites_at(line, depth + 1));
                }
                continue;
            }
        }
        // GNU's names on macOS (`gcp`, `gmv`, `gln`) are the same programs.
        let program = match name.as_str() {
            "cp" | "gcp" => "cp",
            "mv" | "gmv" => "mv",
            "ln" | "gln" => "ln",
            _ => continue,
        };
        out.extend(placed(program, &words[at + 1..]));
    }
    out
}

/// Whether a word is a redirection: `>`, `2>`, `&>`, `2>/dev/null`.
fn is_redirection(word: &str) -> bool {
    let rest = word.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
    rest.starts_with('>') || rest.starts_with('<')
}

/// The instruction file one `cp`/`mv`/`ln` replaces, from its arguments.
fn placed(program: &str, args: &[String]) -> Option<Overwrite> {
    let mut operands: Vec<String> = Vec::new();
    let mut folder: Option<String> = None;
    let mut options_over = false;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        at += 1;
        if is_redirection(arg) {
            // A bare operator names its file in the next word.
            if arg
                .trim_start_matches(|c: char| c.is_ascii_digit() || matches!(c, '&' | '>' | '<'))
                .is_empty()
            {
                at += 1;
            }
            continue;
        }
        if options_over || !arg.starts_with('-') || arg == "-" {
            operands.push(arg.clone());
        } else if arg == "--" {
            options_over = true;
        } else if arg == "-t" || arg == "--target-directory" {
            folder = args.get(at).cloned();
            at += 1;
        } else if let Some(named) = arg.strip_prefix("--target-directory=") {
            folder = Some(named.to_string());
        } else if arg == "-S" || arg == "--suffix" {
            at += 1;
        }
    }
    let (target, sources, is_folder) = match folder {
        Some(folder) => (folder, operands, true),
        None if operands.len() >= 2 => {
            let target = operands.pop()?;
            (target, operands, false)
        }
        // `ln -s ../x/CLAUDE.md` makes the link in the working folder.
        None if program == "ln" && operands.len() == 1 => (".".to_string(), operands, true),
        None => return None,
    };
    let folder_like = is_folder
        || matches!(target.as_str(), "." | ".." | "~")
        || target.ends_with('/')
        || target.ends_with('\\');
    if !folder_like {
        return is_instruction_file(&target).then_some(Overwrite {
            file: target,
            sources,
        });
    }
    let mut file = None;
    let mut named = Vec::new();
    for source in &sources {
        let base = source
            .trim_end_matches(['/', '\\'])
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(source);
        let joined = format!("{}/{base}", target.trim_end_matches(['/', '\\']));
        if is_instruction_file(&joined) {
            file.get_or_insert(joined);
            named.push(source.clone());
        }
    }
    file.map(|file| Overwrite {
        file,
        sources: named,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(line: &str) -> Vec<String> {
        overwrites(line).into_iter().map(|o| o.file).collect()
    }

    #[test]
    fn a_copy_move_or_link_over_an_instruction_file_is_found() {
        for (line, file) in [
            ("cp /tmp/x.md CLAUDE.md", "CLAUDE.md"),
            ("mv -f notes.md ./AGENTS.md", "./AGENTS.md"),
            ("ln -sf ../evil.md GEMINI.md", "GEMINI.md"),
            ("cp -t . /tmp/drop/CLAUDE.md", "./CLAUDE.md"),
            ("cp /tmp/drop/AGENTS.md ~/proj/", "~/proj/AGENTS.md"),
            ("cp x.mdc .cursor/rules/", ".cursor/rules/x.mdc"),
            ("ln -s ../../x/CLAUDE.md", "./CLAUDE.md"),
            ("bash -c 'cp /tmp/x .cursorrules'", ".cursorrules"),
            ("cp a.md CLAUDE.md 2>/dev/null", "CLAUDE.md"),
            ("gcp -- -odd.md AGENTS.md", "AGENTS.md"),
        ] {
            assert_eq!(files(line), vec![file.to_string()], "{line}");
        }
    }

    #[test]
    fn copies_that_put_nothing_in_an_instruction_files_place_are_not() {
        for line in [
            "cp CLAUDE.md CLAUDE.md.bak",
            "cp AGENTS.md docs/agents-copy.md",
            "mv README.md docs/",
            "cp -r src dist",
            "cat CLAUDE.md",
            "echo cp x CLAUDE.md",
        ] {
            assert!(files(line).is_empty(), "{line}");
        }
    }
}
