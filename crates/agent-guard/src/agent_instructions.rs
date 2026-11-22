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

/// The line with the body of each here-document a message reader takes
/// (`git commit -F -`, `gh pr create --body-file -`) left out: that body is
/// the message, data to git, never lines a shell runs. A commit message that
/// quotes the line it fixes (an order written into `CLAUDE.md`) writes
/// nothing into `CLAUDE.md`. A body under an unquoted delimiter that holds
/// a `$(...)` or a backquote runs it, and is kept; so is any other
/// here-document ([`message_heredoc`]), and a body whose delimiter never
/// closes on a line of its own.
///
/// A body is left out only when its `<<` is the only one of the whole
/// content: a message here-document inside another here-document (`sh
/// <<'X'`, `cat <<'X' | sh`) is that one's body, and its own body holds
/// lines the outer shell runs after the outer delimiter. Nor when the line
/// before it ends in `\` (the git line goes on another command).
pub(crate) fn without_message_bodies(content: &str) -> std::borrow::Cow<'_, str> {
    if content.matches("<<").count() != 1 {
        return std::borrow::Cow::Borrowed(content);
    }
    let all: Vec<&str> = content.lines().collect();
    let mut kept: Vec<&str> = Vec::new();
    let mut dropped = false;
    let mut index = 0;
    while let Some(line) = all.get(index) {
        index += 1;
        kept.push(line);
        let continued = index
            .checked_sub(2)
            .and_then(|before| all.get(before))
            .is_some_and(|before| before.trim_end().ends_with('\\'));
        let Some(heredoc) = message_heredoc(line).filter(|_| !continued) else {
            continue;
        };
        // The shell ends the body at the first line that is the delimiter
        // itself (past leading tabs under `<<-`); a body that never ends
        // is not known to be the message, and is kept.
        let Some(close) = all[index..].iter().position(|candidate| {
            let candidate = if heredoc.strips_tabs {
                candidate.trim_start_matches('\t')
            } else {
                candidate
            };
            candidate == heredoc.tag
        }) else {
            continue;
        };
        let body = &all[index..index + close];
        // An unquoted delimiter expands the body: a `$(...)` or a backquote
        // in it runs. Such a body is kept to be read.
        let runs_something = body
            .iter()
            .any(|line| line.contains("$(") || line.contains('\x60'));
        if heredoc.quoted || !runs_something {
            dropped |= !body.is_empty();
        } else {
            kept.extend(body);
        }
        kept.push(all[index + close]);
        index += close + 1;
    }
    if dropped {
        std::borrow::Cow::Owned(kept.join("\n"))
    } else {
        std::borrow::Cow::Borrowed(content)
    }
}

/// A here-document whose body is a message reader's message.
#[derive(Debug, PartialEq, Eq)]
struct MessageHeredoc {
    /// The delimiter, without its quotes.
    tag: String,
    /// Whether the delimiter was quoted (the body is not expanded).
    quoted: bool,
    /// `<<-`: the closing line may start with tabs.
    strips_tabs: bool,
}

/// The here-document a line hands a message reader, when nothing else on
/// the line can make its body run or land in a file: one `<<` on the
/// line; a delimiter that is a bare name, whole or in one pair of quotes,
/// with nothing after it (`<<E'OF'`, `<<'E'OF` and `<<EOF.` end at
/// another line than the name read here, and are kept); no `>` nor `|`
/// anywhere on the line (`git commit -F - <<'EOF' > CLAUDE.md` writes
/// git's output there); and a command of [`reads_message_from_stdin`].
fn message_heredoc(line: &str) -> Option<MessageHeredoc> {
    if line.matches("<<").count() != 1 || line.contains("<<<") || line.contains(['>', '|']) {
        return None;
    }
    let (head, tail) = line.split_once("<<")?;
    let (strips_tabs, tail) = match tail.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, tail),
    };
    let tail = tail.trim_start_matches([' ', '\t']);
    let word = tail.split_whitespace().next()?;
    if !tail[word.len()..].trim().is_empty() {
        return None;
    }
    let (tag, quoted) = match word.as_bytes() {
        [open @ (b'\'' | b'"'), .., close] if open == close && word.len() > 2 => {
            (&word[1..word.len() - 1], true)
        }
        _ => (word, false),
    };
    let is_name = tag
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && tag.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !is_name || !reads_message_from_stdin(head) {
        return None;
    }
    Some(MessageHeredoc {
        tag: tag.to_string(),
        quoted,
        strips_tabs,
    })
}

/// Whether `head`, the command a here-document feeds, is a fixed message
/// reader taking its message from stdin and running nothing it is handed:
/// `git commit`, `git tag`, `git notes add|append` with `-F -` or
/// `--file=-`, or `gh pr|issue create|edit` with `--body-file -`. Git's own
/// options before the subcommand (`-c core.editor=sh`, an alias), an
/// assignment or a wrapper before the program (`GIT_EDITOR=sh git`), and an
/// option that opens an editor (`-e`, `--edit`, `-c`, `--editor`) all
/// make the body something a shell may run, and the body is kept.
fn reads_message_from_stdin(head: &str) -> bool {
    let Some(segment) = shell_command_segments(head).into_iter().last() else {
        return false;
    };
    let words = shell_tokens(segment);
    if effective_command_index(&words) != Some(0) {
        return false;
    }
    let rest = &words[1..];
    let word = |at: usize| rest.get(at).map(String::as_str);
    let fixed = match token_basename(&words[0]).to_ascii_lowercase().as_str() {
        "git" => {
            matches!(word(0), Some("commit" | "tag"))
                || word(0) == Some("notes") && matches!(word(1), Some("add" | "append"))
        }
        "gh" => {
            matches!(word(0), Some("pr" | "issue")) && matches!(word(1), Some("create" | "edit"))
        }
        _ => false,
    };
    let opens_editor = |arg: &String| {
        let long = arg.split('=').next().unwrap_or(arg);
        matches!(long, "--edit" | "--editor" | "--reedit-message")
            || (arg.len() > 1
                && arg.starts_with('-')
                && !arg.starts_with("--")
                && arg[1..].contains(['e', 'c']))
    };
    if !fixed || rest.iter().any(opens_editor) {
        return false;
    }
    let flags = ["-F", "--file", "--body-file", "--notes-file"];
    rest.windows(2)
        .any(|pair| flags.contains(&pair[0].as_str()) && pair[1] == "-")
        || rest
            .iter()
            .any(|arg| flags.iter().any(|flag| *arg == format!("{flag}=-")))
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
    let stripped = without_message_bodies(content);
    let content: &str = &stripped;
    let mut out = Vec::new();
    let segments = shell_command_segments(content);
    for (index, segment) in segments.iter().enumerate() {
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
        let args = &words[at + 1..];
        // GNU's names on macOS (`gcp`, `gmv`, `gln`) are the same programs.
        let found = match name.as_str() {
            "cp" | "gcp" => placed("cp", args),
            "mv" | "gmv" => placed("mv", args),
            "ln" | "gln" => placed("ln", args),
            "rsync" => synced(args),
            "install" | "ginstall" => installed(args),
            "curl" => curl_output(args),
            "wget" => wget_output(args),
            "invoke-webrequest" | "iwr" | "invoke-restmethod" | "irm" => web_request_output(args),
            "git" => git_restored(args),
            _ => None,
        };
        let previous = index.checked_sub(1).map(|before| segments[before]);
        let found = found.or_else(|| redirected_blind(content, &name, segment, args, previous));
        out.extend(found);
    }
    out
}

/// Whether a word is a redirection: `>`, `2>`, `&>`, `2>/dev/null`.
fn is_redirection(word: &str) -> bool {
    let rest = word.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
    rest.starts_with('>') || rest.starts_with('<')
}

/// The words of a command's arguments, read as its options parse them.
#[derive(Debug, Default)]
struct Walked {
    /// The words that are not options nor their values, in order.
    operands: Vec<String>,
    /// Each option that took a value, as written (`-t`, `--output`), and
    /// the value.
    valued: Vec<(String, String)>,
    /// Each option without a value, a short cluster split into its letters
    /// (`-sSL` gives `-s`, `-S`, `-L`).
    flags: Vec<String>,
    /// The files read on standard input (`< file`).
    inputs: Vec<String>,
}

impl Walked {
    fn value(&self, names: &[&str]) -> Option<&str> {
        self.valued
            .iter()
            .rev()
            .find(|(flag, _)| names.contains(&flag.as_str()))
            .map(|(_, value)| value.as_str())
    }

    fn has(&self, names: &[&str]) -> bool {
        self.flags.iter().any(|flag| names.contains(&flag.as_str()))
    }
}

/// Walks arguments as getopt does: `short` the letters that take a value
/// (in the rest of their cluster or the next word), `long` the long options
/// that take the next word when no `=` gives one. Redirections are not
/// arguments; `--` ends the options. Matching is exact for short letters and
/// without regard to case for long names starting with one `-` (PowerShell's
/// `-OutFile`), when `long` lists them so.
fn walk(args: &[String], short: &str, long: &[&str]) -> Walked {
    let mut walked = Walked::default();
    let mut options_over = false;
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        at += 1;
        if !options_over && is_redirection(arg) {
            let rest = arg.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
            let input = rest.starts_with('<') && !rest.starts_with("<<");
            let named = rest.trim_start_matches(['>', '<', '|']).to_string();
            let file = if named.is_empty() {
                at += 1;
                args.get(at - 1).cloned()
            } else {
                Some(named)
            };
            if input {
                walked.inputs.extend(file);
            }
            continue;
        }
        if options_over || !arg.starts_with('-') || arg == "-" {
            walked.operands.push(arg.clone());
            continue;
        }
        if arg == "--" {
            options_over = true;
            continue;
        }
        if let Some(name) = long
            .iter()
            .find(|name| name.eq_ignore_ascii_case(arg) && name.len() > 2)
        {
            if let Some(value) = args.get(at) {
                walked.valued.push((name.to_string(), value.clone()));
                at += 1;
            }
            continue;
        }
        if arg.starts_with("--") {
            match arg.split_once('=') {
                Some((name, value)) => walked.valued.push((name.to_string(), value.to_string())),
                None => walked.flags.push(arg.clone()),
            }
            continue;
        }
        // A short cluster: `-sSLo out`, `-Dm644`, `-qO-`.
        let letters: Vec<char> = arg[1..].chars().collect();
        for (index, letter) in letters.iter().enumerate() {
            if short.contains(*letter) {
                let rest: String = letters[index + 1..].iter().collect();
                let value = if rest.is_empty() {
                    at += 1;
                    args.get(at - 1).cloned()
                } else {
                    Some(rest)
                };
                walked
                    .valued
                    .push((format!("-{letter}"), value.unwrap_or_default()));
                break;
            }
            walked.flags.push(format!("-{letter}"));
        }
    }
    walked
}

/// The last name of a path or an address: `https://x/a/CLAUDE.md?raw=1`
/// gives `CLAUDE.md`, `host:proj/AGENTS.md` gives `AGENTS.md`.
fn last_name(word: &str) -> &str {
    let word = word.trim_matches(|c: char| c == '"' || c == '\'');
    let word = word.split(['?', '#']).next().unwrap_or(word);
    word.trim_end_matches(['/', '\\'])
        .rsplit(['/', '\\', ':'])
        .next()
        .unwrap_or(word)
}

/// The instruction file a copy of `sources` into `target` replaces.
/// `target` is a folder when `is_folder` says so, when it is written as one
/// (`.`, `..`, `~`, a trailing `/`), when more than one source goes into
/// it, or when its last name has no `.` (`cp x/CLAUDE.md proj` writes
/// `proj/CLAUDE.md` when `proj` is a folder, which the line does not say):
/// a folder is the reading that puts the file in an instruction file's place.
fn place(target: String, sources: Vec<String>, is_folder: Option<bool>) -> Option<Overwrite> {
    let written_as_folder = matches!(target.as_str(), "." | ".." | "~")
        || target.ends_with('/')
        || target.ends_with('\\');
    if is_instruction_file(&target) && is_folder != Some(true) && !written_as_folder {
        return Some(Overwrite {
            file: target,
            sources,
        });
    }
    // `cp CLAUDE.md backup`, `mv CLAUDE.md docs`, `cp -r CLAUDE.md AGENTS.md
    // /tmp/bk`: the working folder's own instruction files, copied anywhere,
    // carry no text that was not already there. A folder only guessed at is
    // not read for them; one written as a folder or given by `-t` is.
    let own_files = !sources.is_empty()
        && sources.iter().all(|source| {
            let source = source.trim_matches(|c: char| c == '"' || c == '\'');
            let source = source.strip_prefix("./").unwrap_or(source);
            !source.contains(['/', '\\']) && is_instruction_file(source)
        });
    if is_folder.is_none() && !written_as_folder && own_files {
        return None;
    }
    let folder_like = is_folder.unwrap_or_else(|| {
        written_as_folder || sources.len() > 1 || !last_name(&target).contains('.')
    });
    if !folder_like {
        return None;
    }
    let mut file = None;
    let mut named = Vec::new();
    for source in &sources {
        let joined = format!(
            "{}/{}",
            target.trim_end_matches(['/', '\\']),
            last_name(source)
        );
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

/// The instruction file one `cp`/`mv`/`ln` replaces, from its arguments.
fn placed(program: &str, args: &[String]) -> Option<Overwrite> {
    let walked = walk(args, "tS", &["--target-directory", "--suffix"]);
    let mut operands = walked.operands.clone();
    let no_folder = walked.has(&["-T", "--no-target-directory"]);
    match walked.value(&["-t", "--target-directory"]) {
        Some(folder) => place(folder.to_string(), operands, Some(true)),
        None if operands.len() >= 2 => {
            let target = operands.pop()?;
            place(target, operands, no_folder.then_some(false))
        }
        // `ln -s ../x/CLAUDE.md` makes the link in the working folder.
        None if program == "ln" && operands.len() == 1 => {
            place(".".to_string(), operands, Some(true))
        }
        None => None,
    }
}

/// The instruction file an `rsync` replaces: its last operand is the
/// target, as `cp`'s.
fn synced(args: &[String]) -> Option<Overwrite> {
    let walked = walk(
        args,
        "efBTM",
        &[
            "--rsh",
            "--filter",
            "--exclude",
            "--include",
            "--exclude-from",
            "--include-from",
            "--files-from",
            "--chmod",
            "--chown",
            "--rsync-path",
            "--port",
            "--block-size",
            "--temp-dir",
            "--backup-dir",
            "--suffix",
            "--compare-dest",
            "--copy-dest",
            "--link-dest",
            "--partial-dir",
            "--log-file",
            "--password-file",
            "--timeout",
            "--bwlimit",
            "--remote-option",
            "--max-size",
            "--min-size",
            "--usermap",
            "--groupmap",
        ],
    );
    let mut operands = walked.operands;
    if operands.len() < 2 {
        return None;
    }
    let target = operands.pop()?;
    place(target, operands, None)
}

/// The instruction file an `install` replaces; `install -d` makes folders
/// and copies nothing.
fn installed(args: &[String]) -> Option<Overwrite> {
    let walked = walk(
        args,
        "mogSt",
        &[
            "--mode",
            "--owner",
            "--group",
            "--suffix",
            "--target-directory",
            "--strip-program",
        ],
    );
    if walked.has(&["-d", "--directory"]) {
        return None;
    }
    let mut operands = walked.operands.clone();
    let no_folder = walked.has(&["-T", "--no-target-directory"]);
    match walked.value(&["-t", "--target-directory"]) {
        Some(folder) => place(folder.to_string(), operands, Some(true)),
        None if operands.len() >= 2 => {
            let target = operands.pop()?;
            place(target, operands, no_folder.then_some(false))
        }
        None => None,
    }
}

/// Whether a word is an address a download names.
fn is_address(word: &str) -> bool {
    let word = word.trim_matches(|c: char| c == '"' || c == '\'');
    word.contains("://") || word.starts_with("www.")
}

/// The instruction file a `curl` writes: the file of `-o`, or the
/// address's own name under `-O` (in `--output-dir`).
fn curl_output(args: &[String]) -> Option<Overwrite> {
    let walked = walk(
        args,
        "odHXuAebcFTwxKEmrYyzCPQtUh",
        &[
            "--output",
            "--output-dir",
            "--header",
            "--data",
            "--data-raw",
            "--data-binary",
            "--data-urlencode",
            "--request",
            "--user",
            "--user-agent",
            "--referer",
            "--cookie",
            "--cookie-jar",
            "--form",
            "--upload-file",
            "--write-out",
            "--proxy",
            "--config",
            "--cert",
            "--max-time",
            "--connect-timeout",
            "--retry",
            "--range",
            "--url",
        ],
    );
    let mut addresses: Vec<String> = walked
        .operands
        .iter()
        .filter(|word| is_address(word) || !word.starts_with('-'))
        .cloned()
        .collect();
    addresses.extend(
        walked
            .valued
            .iter()
            .filter(|(flag, _)| flag == "--url")
            .map(|(_, value)| value.clone()),
    );
    for (flag, file) in &walked.valued {
        if (flag == "-o" || flag == "--output") && is_instruction_file(file) {
            return Some(Overwrite {
                file: file.clone(),
                sources: addresses.clone(),
            });
        }
    }
    if walked.has(&["-O", "--remote-name", "--remote-name-all"]) {
        let folder = walked.value(&["--output-dir"]).unwrap_or(".").to_string();
        return place(folder, addresses, Some(true));
    }
    None
}

/// The instruction file a `wget` writes: the file of `-O` (`-` is
/// standard output), or else each address's own name (in `-P`).
fn wget_output(args: &[String]) -> Option<Overwrite> {
    let walked = walk(
        args,
        "OPoaiBtTwQeUlARDIX",
        &[
            "--output-document",
            "--directory-prefix",
            "--output-file",
            "--append-output",
            "--input-file",
            "--tries",
            "--timeout",
            "--wait",
            "--user-agent",
            "--header",
            "--user",
            "--password",
        ],
    );
    let addresses: Vec<String> = walked.operands.clone();
    if let Some(file) = walked.value(&["-O", "--output-document"]) {
        return (file != "-" && is_instruction_file(file)).then(|| Overwrite {
            file: file.to_string(),
            sources: addresses,
        });
    }
    let folder = walked
        .value(&["-P", "--directory-prefix"])
        .unwrap_or(".")
        .to_string();
    place(folder, addresses, Some(true))
}

/// The instruction file PowerShell's `Invoke-WebRequest` writes with
/// `-OutFile`.
fn web_request_output(args: &[String]) -> Option<Overwrite> {
    let walked = walk(
        args,
        "",
        &["-OutFile", "-Uri", "-Method", "-Headers", "-Body"],
    );
    let file = walked.value(&["-OutFile"])?;
    let mut sources = walked.operands.clone();
    sources.extend(walked.value(&["-Uri"]).map(str::to_string));
    is_instruction_file(file).then(|| Overwrite {
        file: file.to_string(),
        sources,
    })
}

/// The instruction file a `git checkout <ref> -- <file>` or `git restore
/// --source <ref> <file>` puts back from another commit: its text is that
/// commit's, not on the line. A restore from the index (no ref) or from the
/// commit checked out (`HEAD`, `@`) puts back the project's own text, and
/// is not read here.
fn git_restored(args: &[String]) -> Option<Overwrite> {
    // Past git's own options to its subcommand.
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        if matches!(
            arg.as_str(),
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace"
        ) {
            at += 2;
        } else if arg.starts_with('-') {
            at += 1;
        } else {
            break;
        }
    }
    let subcommand = args.get(at)?.as_str();
    let rest = &args[at + 1..];
    let (reference, paths) = match subcommand {
        "checkout" => {
            let walked = walk(rest, "bB", &["--orphan", "--conflict"]);
            if walked.value(&["-b", "-B", "--orphan"]).is_some() {
                return None;
            }
            let split = rest.iter().position(|arg| arg == "--");
            match split {
                Some(split) => {
                    let before = walk(&rest[..split], "", &["--conflict"]).operands;
                    let paths: Vec<String> = rest[split + 1..].to_vec();
                    (before.first().cloned()?, paths)
                }
                None => {
                    let mut operands = walked.operands;
                    if operands.len() < 2 {
                        return None;
                    }
                    let reference = operands.remove(0);
                    (reference, operands)
                }
            }
        }
        "restore" => {
            let walked = walk(rest, "s", &["--source"]);
            let reference = walked.value(&["-s", "--source"])?.to_string();
            (reference, walked.operands)
        }
        _ => return None,
    };
    if matches!(reference.as_str(), "HEAD" | "@") {
        return None;
    }
    let file = paths.into_iter().find(|path| is_instruction_file(path))?;
    Some(Overwrite {
        sources: vec![format!("{reference}:{file}")],
        file,
    })
}

/// Programs whose output into a file is text written on the line itself
/// (`echo`, `printf`), or nothing at all (`:`, `true`): the text is read,
/// or there is none.
const TEXT_ON_THE_LINE: &[&str] = &["echo", "printf", "print", ":", "true", "false"];

/// The instruction file any other program's output is redirected into, or a
/// `tee` writes from a pipe or a file: `cat /tmp/x > CLAUDE.md`,
/// `curl -s URL | tee AGENTS.md`. What it writes is not on the line. Text
/// on the line (`echo`, a here-document, a here-string) is read instead.
fn redirected_blind(
    content: &str,
    name: &str,
    segment: &str,
    args: &[String],
    previous: Option<&str>,
) -> Option<Overwrite> {
    // A here-document is text on the line when `cat` or `tee` hands it on;
    // what another program makes of it (`git commit -F - <<'EOF' >
    // CLAUDE.md` writes git's output) is not.
    if TEXT_ON_THE_LINE.contains(&name) || (segment.contains("<<") && matches!(name, "cat" | "tee"))
    {
        return None;
    }
    let walked = walk(args, "", &[]);
    if name == "tee" {
        // `echo X | tee -a GEMINI.md`: the text is on the line, and is read
        // as written. A tee with neither a pipe into it nor a file on its
        // stdin writes nothing a line gave it. A command before it that is
        // not piped (`echo X > /tmp/x; tee -a AGENTS.md < /tmp/x`) feeds it
        // nothing.
        let piped = previous.filter(|previous| piped(content, previous, segment));
        let fed_text = walked.inputs.is_empty()
            && piped.is_some_and(|previous| {
                let words = shell_tokens(previous);
                effective_command_index(&words).is_some_and(|at| {
                    TEXT_ON_THE_LINE
                        .contains(&token_basename(&words[at]).to_ascii_lowercase().as_str())
                })
            });
        if fed_text || (piped.is_none() && walked.inputs.is_empty()) {
            return None;
        }
    }
    let mut sources = walked.operands.clone();
    sources.extend(walked.inputs.iter().cloned());
    let file = if name == "tee" {
        walked
            .operands
            .iter()
            .find(|word| is_instruction_file(word))
            .cloned()
    } else {
        let mut found = None;
        let mut at = 0;
        while let Some(arg) = args.get(at) {
            at += 1;
            let rest = arg.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
            if !rest.starts_with('>') || rest.starts_with(">&") || rest.starts_with(">(") {
                continue;
            }
            let target = rest.trim_start_matches('>').trim_start_matches('|');
            let target = if target.is_empty() {
                at += 1;
                args.get(at - 1).map(String::as_str).unwrap_or("")
            } else {
                target
            };
            if is_instruction_file(target) {
                found = Some(target.to_string());
                break;
            }
        }
        found
    }?;
    if name == "tee" {
        // A tee writes what it is handed: a pipe (judged by what feeds it,
        // which is not on this segment) or a file.
        sources.retain(|source| *source != file);
    }
    Some(Overwrite {
        sources: if sources.is_empty() {
            vec![name.to_string()]
        } else {
            sources
        },
        file,
    })
}

/// Whether `right` reads the output of `left` through a pipe: both are
/// segments of `content`, and only `|` or `|&` stands between them.
fn piped(content: &str, left: &str, right: &str) -> bool {
    let base = content.as_ptr() as usize;
    let (left_at, right_at) = (left.as_ptr() as usize, right.as_ptr() as usize);
    if left_at < base || right_at < left_at + left.len() {
        return false;
    }
    content
        .get(left_at - base + left.len()..right_at - base)
        .is_some_and(|between| matches!(between.trim(), "|" | "|&"))
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

    /// FAILS ON REVERT of the bare-name delimiter, the closing line read as
    /// the shell reads it, and the fixed message readers.
    #[test]
    fn only_a_message_body_that_nothing_can_run_is_left_out() {
        let body = "git commit -F - <<'EOF'\nmsg\nEOF";
        assert_eq!(without_message_bodies(body), "git commit -F - <<'EOF'\nEOF");
        for line in [
            "git commit -F - <<E'OF'\nmsg\nEOF",
            "git commit -F - <<EOF.\nmsg\nEOF",
            "git commit -F - <<'E'OF\nmsg\nEOF",
            "git commit -F - <<'EOF'\nmsg\n EOF",
            "git commit -F - <<'EOF'\nmsg",
            "git commit -F - <<'EOF' > CLAUDE.md\nmsg\nEOF",
            "git commit -F - <<'EOF' | tee CLAUDE.md\nmsg\nEOF",
            "git commit -e -F - <<'EOF'\nmsg\nEOF",
            "git commit -c HEAD -F - <<'EOF'\nmsg\nEOF",
            "GIT_EDITOR=sh git commit -F - <<'EOF'\nmsg\nEOF",
            "git -c core.editor=sh commit -F - <<'EOF'\nmsg\nEOF",
            "git log -F - <<'EOF'\nmsg\nEOF",
            "gh api -F - <<'EOF'\nmsg\nEOF",
            "sh <<'X'\ngit commit -F - <<'EOF'\nX\nmsg\nEOF",
            "cat <<'X' | sh\ngit commit -F - <<'EOF'\nX\nmsg\nEOF",
            "echo \\\ngit commit -F - <<'EOF'\nmsg\nEOF",
        ] {
            assert_eq!(without_message_bodies(line), line, "{line}");
        }
        for line in [
            "git tag -a v1 -F - <<'EOF'\nmsg\nEOF",
            "git notes add -F - <<'EOF'\nmsg\nEOF",
            "gh pr create --title x --body-file - <<\"EOF\"\nmsg\nEOF",
            "gh issue edit 3 --body-file=- <<EOF\nmsg\nEOF",
            "git commit -F - <<-'EOF'\nmsg\n\tEOF",
        ] {
            assert_ne!(without_message_bodies(line), line, "{line}");
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
