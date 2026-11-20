//! An agent's own file tools, screened before they run.
//!
//! Claude Code writes files through `Write`, `Edit`, `MultiEdit` and
//! `NotebookEdit`, not through its shell. A hook wired to `Bash` alone never
//! sees them, so the shell side could refuse `sed -i` on the agent's settings
//! while an `Edit` of the same file went through: the agent could drop the
//! hook that screens it, add an allow rule to the guard's own configuration,
//! or plant a line in a shell startup file, and nothing said so.
//!
//! The same holds for the other agents whose hook runs before their own
//! tools: Gemini CLI writes through `write_file` and `replace`, and Codex CLI
//! through `apply_patch`, whose one argument is a patch that names its files.
//!
//! What is judged is WHERE a call writes, never what it writes, and only
//! against a short list of privileged places:
//!
//! * every place [`crate::threats`] already refuses an MCP write tool
//!   (the guard's configuration and the agent settings that load it, SSH
//!   keys, the sudo rules, cron, boot services, ...);
//! * places in the account's own home that an MCP server is not held to,
//!   because they run as that account and not as anyone more: the shell's
//!   startup files, the user's own services and login items, and the stored
//!   credentials of common tools;
//! * the guard's own program.
//!
//! Everything else, which is every ordinary edit to a project, is allowed
//! without a word and without touching the rule engine, so the hook stays
//! fast on the call an agent makes most.
//!
//! A path is judged as written, after `~` and the working directory are
//! applied and `.` and `..` resolved, and again after the links on the way
//! are followed, so a link made earlier in the project does not step around
//! the list. Then, on Unix, by what it is rather than what it is called: a
//! file that is one of the privileged files (a hard link to it, or the real
//! file a home link such as `~/.bashrc -> dotfiles/bashrc` points at), or that
//! sits in one of the privileged directories reached by another name (a
//! mount or firmlink path to the home), is refused as that file.
//!
//! What a hook that runs before the tool cannot close: the path is judged,
//! then the agent's tool writes it, and a background job that swaps a link
//! into place between the two can win that race. A change the shell makes to
//! a hard link (`>>` into a project file that is the same file) is the shell
//! side's to judge.

use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::threats::{privileged_write_target, ROOT_HOME};

/// Claude Code's tools that change a file, by name.
pub const FILE_TOOLS: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit"];

/// The PreToolUse matcher that sends [`FILE_TOOLS`] to the hook: a plain
/// `|` list, which every Claude Code version reads as that exact set.
pub const FILE_TOOLS_MATCHER: &str = "Write|Edit|MultiEdit|NotebookEdit";

/// Gemini CLI's tools that change a file, by name. Both name their target in
/// `file_path`. Kept apart from [`FILE_TOOLS`], which is also the matcher
/// Claude Code is given: Gemini's hook is written with no matcher at all.
pub const GEMINI_FILE_TOOLS: &[&str] = &["write_file", "replace"];

/// Codex CLI's tool that changes files. It names no path field: its one
/// argument is the text of a patch, and the files are named inside it.
pub const PATCH_TOOL: &str = "apply_patch";

/// Hermes Agent's tool that changes files in place (v0.23.1,
/// `tools/file_tools.py`): in `replace` mode (its default) it names its file
/// in `path`; in `patch` mode it carries a V4A patch in `patch`, and the
/// files are named inside it. Both are read, whatever the mode says.
/// Hermes's `write_file` names its file in `path`, which [`PATH_KEYS`] reads.
pub const HERMES_PATCH_TOOL: &str = "patch";

/// Where a file tool names its target: `file_path` for `Write`, `Edit` and
/// `MultiEdit`, `notebook_path` for `NotebookEdit`. `path` is read too, so a
/// renamed field is still judged rather than skipped.
const PATH_KEYS: &[&str] = &["file_path", "notebook_path", "path"];

/// Where [`PATCH_TOOL`] carries the patch text: `command` in Codex CLI. The
/// other two are read too, so a renamed field is still judged.
const PATCH_TEXT_KEYS: &[&str] = &["command", "input", "patch"];

/// The lines of a patch that name a file it changes.
const PATCH_PATH_MARKERS: &[&str] = &[
    "*** Add File:",
    "*** Update File:",
    "*** Delete File:",
    "*** Move to:",
];

/// How many links are followed before a path is judged as it stands.
const MAX_LINK_STEPS: u8 = 40;

/// Longest path judged. A longer one is not read, and is not passed either:
/// [`privileged_file_write`] answers [`PATH_TOO_LONG`] for it.
const MAX_PATH_BYTES: usize = 4096;

/// What [`privileged_file_write`] says of a path over the cap. Such a path
/// is not known to be privileged: it was not read, and `./` repeated in it
/// can put any file past the cap. The hook treats the call as one it could
/// not read.
pub const PATH_TOO_LONG: &str = "a path too long to be read";

/// One tool call, read for what it writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileToolCall {
    /// Not a tool that changes a file ([`FILE_TOOLS`], [`GEMINI_FILE_TOOLS`],
    /// [`PATCH_TOOL`] or [`HERMES_PATCH_TOOL`]): none of this module's
    /// business.
    NotAFileTool,
    /// A file tool, and every path it names.
    Writes { tool: String, paths: Vec<String> },
    /// A file tool whose target could not be read. The hook is registered for
    /// these tools, so this is a schema change or a broken agent.
    Unreadable(&'static str),
}

/// Read a hook payload as a file tool call.
pub fn file_tool_call(payload: &Value) -> FileToolCall {
    let tool = payload
        .get("tool_name")
        .or_else(|| payload.get("tool"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let input = payload.get("tool_input");
    if tool == PATCH_TOOL {
        return patch_call(input);
    }
    if tool == HERMES_PATCH_TOOL {
        return hermes_patch_call(input);
    }
    if !FILE_TOOLS.contains(&tool) && !GEMINI_FILE_TOOLS.contains(&tool) {
        return FileToolCall::NotAFileTool;
    }
    let paths: Vec<String> = PATH_KEYS
        .iter()
        .filter_map(|key| input.and_then(|input| input.get(*key)))
        .filter_map(Value::as_str)
        .filter(|path| !path.trim().is_empty())
        .map(str::to_string)
        .collect();
    if paths.is_empty() {
        return FileToolCall::Unreadable("a file tool call with no file path");
    }
    FileToolCall::Writes {
        tool: tool.to_string(),
        paths,
    }
}

/// A [`PATCH_TOOL`] call, read for every file its patch names. The patch is
/// never handed on as a shell line: it is text for the patch tool, and what
/// matters about it is where it writes.
///
/// A patch that names no file, or names one with nothing after the marker,
/// could not be read: the tool would still change something, so the call is
/// unreadable and not empty.
fn patch_call(input: Option<&Value>) -> FileToolCall {
    let Some(patch) = patch_text(input) else {
        return FileToolCall::Unreadable("a patch tool call with no patch text");
    };
    let Some(paths) = patch_paths(&patch) else {
        return FileToolCall::Unreadable("a patch that names a file with no path");
    };
    if paths.is_empty() {
        return FileToolCall::Unreadable("a patch that names no file");
    }
    FileToolCall::Writes {
        tool: PATCH_TOOL.to_string(),
        paths,
    }
}

/// A [`HERMES_PATCH_TOOL`] call, read for the file it names in `path` and
/// every file its V4A patch names ([`hermes_patch_paths`]).
fn hermes_patch_call(input: Option<&Value>) -> FileToolCall {
    let mut paths: Vec<String> = Vec::new();
    if let Some(path) = input
        .and_then(|input| input.get("path"))
        .and_then(Value::as_str)
        .filter(|path| !path.trim().is_empty())
    {
        paths.push(path.to_string());
    }
    if let Some(patch) = input
        .and_then(|input| input.get("patch"))
        .and_then(Value::as_str)
    {
        let Some(named) = hermes_patch_paths(patch) else {
            return FileToolCall::Unreadable("a patch that names a file with no path");
        };
        for path in named {
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    if paths.is_empty() {
        return FileToolCall::Unreadable("a patch tool call with no file path");
    }
    FileToolCall::Writes {
        tool: HERMES_PATCH_TOOL.to_string(),
        paths,
    }
}

/// Every file a V4A patch names as Hermes Agent reads one
/// (`tools/patch_parser.py`, v0.23.1): `*** Update File:`, `*** Add File:`,
/// `*** Delete File:`, and `*** Move File: a -> b`, both ends of a move, with
/// any run of blanks between the words and none needed after `***`. A line
/// is read with the blanks around it removed and outside the `Begin`/`End`
/// markers too: one path too many is the safe side. `None` when a marker
/// names nothing.
pub(crate) fn hermes_patch_paths(patch: &str) -> Option<Vec<String>> {
    static MARKERS: std::sync::OnceLock<(regex::Regex, regex::Regex)> = std::sync::OnceLock::new();
    let (moved, named) = MARKERS.get_or_init(|| {
        (
            regex::Regex::new(r"^\*\*\*\s*Move\s+File:\s*(.*?)\s*->\s*(.*)$").expect("move marker"),
            regex::Regex::new(r"^\*\*\*\s*(?:Update|Add|Delete|Move)\s+File:(.*)$")
                .expect("file marker"),
        )
    });
    let mut paths: Vec<String> = Vec::new();
    for line in patch.split('\n') {
        let line = line.trim();
        let found: Vec<&str> = if let Some(caps) = moved.captures(line) {
            vec![caps.get(1)?.as_str(), caps.get(2)?.as_str()]
        } else if let Some(caps) = named.captures(line) {
            vec![caps.get(1)?.as_str()]
        } else {
            continue;
        };
        for path in found {
            let path = path.trim();
            if path.is_empty() {
                return None;
            }
            if !paths.iter().any(|seen| seen == path) {
                paths.push(path.to_string());
            }
        }
    }
    Some(paths)
}

/// The patch text of a [`PATCH_TOOL`] call: one of [`PATCH_TEXT_KEYS`], or
/// the whole input when the tool was handed bare text.
fn patch_text(input: Option<&Value>) -> Option<String> {
    let input = input?;
    let text = match input.as_str() {
        Some(text) => text,
        None => PATCH_TEXT_KEYS
            .iter()
            .find_map(|key| input.get(*key).and_then(Value::as_str))?,
    };
    (!text.trim().is_empty()).then(|| text.to_string())
}

/// Every file a patch names, in the order named, each once. `None` when a
/// marker line names nothing.
///
/// A line is read with the blanks around it removed, as the patch tool reads
/// its markers. That also reads a marker quoted inside the body of a patch
/// as a file: judging one path too many is the safe side.
pub(crate) fn patch_paths(patch: &str) -> Option<Vec<String>> {
    let mut paths: Vec<String> = Vec::new();
    for line in patch.lines() {
        let line = line.trim();
        let named = PATCH_PATH_MARKERS
            .iter()
            .find_map(|marker| line.strip_prefix(marker));
        let Some(path) = named else {
            continue;
        };
        let path = path.trim();
        if path.is_empty() {
            return None;
        }
        if !paths.iter().any(|seen| seen == path) {
            paths.push(path.to_string());
        }
    }
    Some(paths)
}

/// Claude Code's tools that read a file or search files, by name. They
/// never pass through the shell either, so a hook wired to `Bash` and the
/// file-changing tools let `Read` of a private key, or `Grep` over a folder
/// of tokens, run with no screening at all (measured 2026-11-12, 5 of 5).
pub const READ_TOOLS: &[&str] = &["Read", "Grep", "Glob"];

/// The same reads under the names other agents give them, each read in that
/// agent's own source: Gemini CLI's `read_file` (`file_path`),
/// `read_many_files` (`include`), `glob` and `grep_search` (`dir_path`;
/// `search_file_content` before it was renamed), and Hermes Agent's
/// `read_file` (`path`) and `search_files` (`target` `files` or `content`).
/// Their hooks carry no matcher, so these calls reach the guard already.
pub const OTHER_READ_TOOLS: &[&str] = &[
    "read_file",
    "read_many_files",
    "glob",
    "grep_search",
    "search_file_content",
    "search_files",
];

/// The PreToolUse matcher that sends [`READ_TOOLS`] to the hook: a plain
/// `|` list, as [`FILE_TOOLS_MATCHER`] is.
pub const READ_TOOLS_MATCHER: &str = "Read|Grep|Glob";

/// Where a read tool names the folder it searches.
const FOLDER_KEYS: &[&str] = &["path", "dir_path"];

/// The keys of a search call that limit it to the files a glob matches
/// (Claude Code's `Grep` `glob`, Gemini CLI's `grep_search` `include`).
const GLOB_KEYS: [&str; 2] = ["glob", "include"];

/// The pattern of a search of the whole home that looks for a narrow text
/// ([`crate::threats::pattern_is_narrow`]), with no glob that aims at
/// secrets ([`crate::threats::glob_aims_at_secrets`]): said in the line, so
/// the search is judged as its shell twin `grep -r <text> ~` is, a person's
/// call (`review`) when the home holds a key, since grep opens the key and
/// prints from it only a line holding that text. Every other search keeps
/// the empty pattern, and a search of the home with it reads the whole
/// home: the hard refusal. Measured 2026-11-18: a `Grep` of the home for
/// any text was denied in a home that held a login, where the same search
/// in the shell was a `review`.
///
/// Only the home itself, as written (`~`, `$HOME`, its path): a search of a
/// folder the home is in (`/`, `/home`) keeps the empty pattern. The
/// search pattern of a tool is a regular expression, never a fixed string.
fn narrow_search_of_the_home<'a>(
    pattern: Option<&'a str>,
    globs: &[Option<&str>],
    folder: &str,
    context: &WriteContext<'_>,
) -> Option<&'a str> {
    let pattern = pattern.filter(|pattern| crate::threats::pattern_is_narrow(pattern, false))?;
    if globs
        .iter()
        .flatten()
        .any(|glob| crate::threats::glob_aims_at_secrets(glob))
    {
        return None;
    }
    let home = context.home?.to_str()?.trim_end_matches('/');
    let folder = folder.trim_end_matches('/');
    let is_home =
        matches!(folder, "~" | "$HOME" | "${HOME}") || (!home.is_empty() && folder == home);
    is_home.then_some(pattern)
}

/// One tool call, read for what it reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileReadCall {
    /// Not one of [`READ_TOOLS`] or [`OTHER_READ_TOOLS`]: none of this
    /// module's business.
    NotARead,
    /// One of them, as the shell line that reads the same files
    /// ([`file_read_call`]): screened by the rules a shell read is.
    Reads(String),
    /// One of them with no target that can be read. The hook is registered
    /// for these tools, so this is a schema change or a broken agent.
    Unreadable(&'static str),
}

/// What a read tool does, whatever the agent calls it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadKind {
    /// Opens the files it names.
    Files,
    /// Searches the text of every file under a folder.
    Search,
    /// Lists the files under a folder whose names match a pattern.
    Find,
}

fn read_kind(tool: &str, input: Option<&Value>) -> Option<ReadKind> {
    Some(match tool {
        "Read" | "read_file" | "read_many_files" => ReadKind::Files,
        "Grep" | "grep_search" | "search_file_content" => ReadKind::Search,
        "Glob" | "glob" => ReadKind::Find,
        "search_files" => {
            match input
                .and_then(|input| input.get("target"))
                .and_then(Value::as_str)
            {
                Some("files") => ReadKind::Find,
                _ => ReadKind::Search,
            }
        }
        _ => return None,
    })
}

/// [`file_read_call_in`] with the home from the environment (else the
/// account database) and the working directory the payload names.
pub fn file_read_call(payload: &Value) -> FileReadCall {
    let home = home_from(std::env::var_os("HOME"));
    let cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|cwd| cwd.starts_with('/'))
        .map(PathBuf::from);
    let context = WriteContext {
        cwd: cwd.as_deref(),
        home: home.as_deref(),
        guard_program: None,
    };
    file_read_call_in(payload, &context)
}

/// The home a read is judged in: `HOME` when it is set and not empty,
/// else the one the account database names.
fn home_from(variable: Option<std::ffi::OsString>) -> Option<PathBuf> {
    match variable {
        Some(home) if !home.is_empty() => Some(PathBuf::from(home)),
        _ => home_of_this_account(),
    }
}

/// Read a hook payload as a call of one of [`READ_TOOLS`] or
/// [`OTHER_READ_TOOLS`], and say it as the shell line that reads what it
/// reads:
///
/// * a file read is `cat <file>`, every path the call names;
/// * a search over a path is `grep -r '' <path>`, the path the call names,
///   else the folder it runs in (`cwd`), else `.`;
/// * a file search is `find <path> -path <pattern>`, with the same folder.
///
/// What is judged is the files, by the secret rules of the shell: a private
/// key, a tool's stored login, a `.env` outside the project, a hidden folder
/// in the home that holds one. Not the text a search looks for: the pattern
/// is no file, and every text rule of the shell on a search string would
/// refuse a search for the words of a dangerous command. One part of it is
/// kept: the word that makes a search over a broad root a hunt for secrets
/// (`password`, `id_rsa`, see [`crate::threats::credential_hunt_token`]),
/// as `-e <word>`, which the credential hunt reads and the rest of the rules
/// do not. A search limited by `glob` or `type` is judged as a read of the
/// whole path.
///
/// Each path is judged as written and as what it is ([`other_names_of`]): a
/// link to a secret, a hard link to one, and on macOS a spelling in another
/// case are judged as the secret, because the tool opens the secret.
///
/// The empty pattern is grep's first operand, the plainest spelling of the
/// read, so the path is the word the shell rules see as the file.
pub fn file_read_call_in(payload: &Value, context: &WriteContext<'_>) -> FileReadCall {
    let tool = payload
        .get("tool_name")
        .or_else(|| payload.get("tool"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if !READ_TOOLS.contains(&tool) && !OTHER_READ_TOOLS.contains(&tool) {
        return FileReadCall::NotARead;
    }
    let input = payload.get("tool_input");
    let Some(kind) = read_kind(tool, input) else {
        return FileReadCall::NotARead;
    };
    let text = |key: &str| {
        input
            .and_then(|input| input.get(key))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    // The folder a search with no path runs in.
    let folder = || {
        FOLDER_KEYS
            .iter()
            .find_map(|key| text(key))
            .or_else(|| {
                payload
                    .get("cwd")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|cwd| cwd.starts_with('/'))
            })
            .unwrap_or(".")
    };
    // A path as words of the line: as written, then what it also is.
    let words_of = |path: &str| {
        let mut words = vec![shell_path_word(path)];
        words.extend(
            other_names_of(path, context)
                .iter()
                .map(|name| shell_path_word(name)),
        );
        words.join(" ")
    };
    match kind {
        ReadKind::Files => {
            let mut paths: Vec<&str> = Vec::new();
            let listed = input
                .and_then(|input| input.get("include"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|path| !path.is_empty());
            for path in PATH_KEYS
                .iter()
                .chain(&["absolute_path"])
                .filter_map(|key| text(key))
                .chain(listed)
            {
                if !paths.contains(&path) {
                    paths.push(path);
                }
            }
            if paths.is_empty() {
                return FileReadCall::Unreadable("a file read call with no file path");
            }
            let words: Vec<String> = paths.into_iter().map(words_of).collect();
            FileReadCall::Reads(format!("cat {}", words.join(" ")))
        }
        ReadKind::Search => {
            let hunted = text("pattern")
                .and_then(crate::threats::credential_hunt_token)
                .map(|word| format!("-e {word} "))
                .or_else(|| {
                    narrow_search_of_the_home(
                        text("pattern"),
                        &GLOB_KEYS.map(text),
                        folder(),
                        context,
                    )
                    .map(|pattern| format!("-e '{pattern}' "))
                })
                .unwrap_or_else(|| "'' ".to_string());
            FileReadCall::Reads(format!("grep -r {hunted}{}", words_of(folder())))
        }
        ReadKind::Find => {
            let Some(pattern) = text("pattern") else {
                return FileReadCall::Unreadable("a file search call with no pattern");
            };
            FileReadCall::Reads(format!(
                "find {} -path {}",
                words_of(folder()),
                shell_path_word(pattern)
            ))
        }
    }
}

/// The always-secret files in a home, relative to it, that a read is
/// compared with by identity ([`other_names_of`]), beside every file in
/// `~/.ssh`.
pub(crate) const HOME_SECRETS: &[&str] = &[
    ".aws/credentials",
    ".git-credentials",
    ".netrc",
    ".config/gh/hosts.yml",
    ".docker/config.json",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".codex/auth.json",
    ".gemini/oauth_creds.json",
    ".claude/.credentials.json",
    ".hermes/auth.json",
    ".config/gcloud/application_default_credentials.json",
    ".kube/config",
    ".vault-token",
];

/// How many entries of `~/.ssh` a read is compared with.
#[cfg(unix)]
const SSH_ENTRIES: usize = 256;

/// The other names a read tool's `path` has, for the rules that judge a path
/// by its text: the real path once its links are followed, the always-secret
/// file in the home that is the same file (a hard link, or the file a link
/// or another spelling reaches), and on macOS the home-relative path in
/// lowercase when it is in a hidden folder. Only what differs from the path
/// as written is given, and only what exists is compared. A read opens the
/// file a link leads to, the file a hard link is, and on a file system that
/// ignores case the file another spelling names, so each is judged as that
/// file.
pub fn other_names_of(path: &str, context: &WriteContext<'_>) -> Vec<String> {
    // An empty path names no file (`absolute_path` would make it the
    // working directory). A path longer than any the system opens needs no
    // test of its own: following it and asking what it is both fail.
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let Some(absolute) = absolute_path(trimmed, context) else {
        return Vec::new();
    };
    let written = lexical(&absolute);
    let mut names: Vec<String> = Vec::new();
    let mut add = |name: PathBuf| {
        let name = name.to_string_lossy().into_owned();
        if name != written.to_string_lossy() && !names.contains(&name) {
            names.push(name);
        }
    };
    if let Ok(real) = std::fs::canonicalize(&absolute) {
        add(real);
    }
    for secret in same_secret_in_home(&absolute, context) {
        add(secret);
    }
    if cfg!(target_os = "macos") {
        if let Some(lower) = context
            .home
            .and_then(|home| lowercase_hidden_spelling(&written, home))
        {
            add(lower);
        }
    }
    names
}

/// What the file at `path` also is, for the shell's reads: where its links
/// lead, and the always-secret files in `home` it is the same file as
/// ([`same_secrets`]). A path that names no file has no other name.
pub(crate) fn names_of_the_file(path: &Path, home: Option<&Path>) -> Vec<PathBuf> {
    let mut names: Vec<PathBuf> = std::fs::canonicalize(path).into_iter().collect();
    for secret in same_secrets(path, home) {
        if !names.contains(&secret) {
            names.push(secret);
        }
    }
    names
}

/// The always-secret files in the home that `path` is the same file as, by
/// device and inode: every file in `~/.ssh` and the [`HOME_SECRETS`]. None
/// off Unix, where identity is no device and inode pair.
fn same_secret_in_home(path: &Path, context: &WriteContext<'_>) -> Vec<PathBuf> {
    same_secrets(path, context.home)
}

/// [`same_secret_in_home`] with the home given.
fn same_secrets(path: &Path, home: Option<&Path>) -> Vec<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let identity = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
        let (Some(home), Some(target)) = (home, identity(path)) else {
            return Vec::new();
        };
        let ssh = std::fs::read_dir(home.join(".ssh"))
            .into_iter()
            .flatten()
            .flatten()
            .take(SSH_ENTRIES)
            .map(|entry| entry.path());
        ssh.chain(HOME_SECRETS.iter().map(|relative| home.join(relative)))
            .filter(|secret| identity(secret) == Some(target))
            .collect()
    }
    #[cfg(not(unix))]
    {
        let _ = (path, home);
        Vec::new()
    }
}

/// `path` with its part below `home` in lowercase, when that part is in a
/// hidden folder and is spelled with an upper-case letter: on a file system
/// that ignores case, `~/.SSH/id_ed25519` and `~/.Codex/AUTH.json` open
/// `~/.ssh/id_ed25519` and `~/.codex/auth.json`, and the rules know only
/// the lowercase names.
fn lowercase_hidden_spelling(path: &Path, home: &Path) -> Option<PathBuf> {
    let parts = |path: &Path| -> Vec<String> {
        path.components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect()
    };
    let (path_parts, home_parts) = (parts(path), parts(&lexical(home)));
    let rest = path_parts.get(home_parts.len()..)?;
    let same_home = path_parts
        .iter()
        .zip(&home_parts)
        .all(|(a, b)| a.to_lowercase() == b.to_lowercase());
    if !same_home || !rest.first()?.starts_with('.') {
        return None;
    }
    let lower: Vec<String> = rest.iter().map(|part| part.to_lowercase()).collect();
    if lower == rest {
        return None;
    }
    let mut out = home.to_path_buf();
    out.extend(lower);
    Some(out)
}

/// One path as a word of a shell line, so the line names that path and no
/// more: written out when every character is a plain path character, else
/// in single quotes. A leading `~/` stays outside the quotes, where the
/// shell, and the guard, read it as the home; a leading `-` is made a path
/// (`./-x`) so it is no option.
fn shell_path_word(path: &str) -> String {
    let plain = |text: &str| {
        !text.is_empty()
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-./:=@%+,".contains(c))
    };
    let quoted = |text: &str| {
        if plain(text) {
            text.to_string()
        } else {
            format!("'{}'", text.replace('\'', r"'\''"))
        }
    };
    if path == "~" {
        return "~".into();
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return if rest.is_empty() {
            "~/".into()
        } else {
            format!("~/{}", quoted(rest))
        };
    }
    if path.starts_with('-') {
        return quoted(&format!("./{path}"));
    }
    quoted(path)
}

/// Where the call runs, as far as the hook knows it.
#[derive(Debug, Clone, Copy, Default)]
pub struct WriteContext<'a> {
    /// The agent's working directory, for a relative path.
    pub cwd: Option<&'a Path>,
    /// The home of the account the agent runs as.
    pub home: Option<&'a Path>,
    /// The program the guard's hook runs (this binary).
    pub guard_program: Option<&'a Path>,
}

/// A group of places in the account's own home, relative to it, in lowercase.
struct HomeGroup {
    what: &'static str,
    files: &'static [&'static str],
    trees: &'static [&'static str],
}

/// Places in the account's own home whose change runs code later, outside
/// the agent's sight, or hands over a login. Not in the MCP list because an
/// MCP server runs as the same account and could write them itself; the
/// agent's own file tools are the thing being screened here.
const HOME_PLACES: &[HomeGroup] = &[
    HomeGroup {
        what: "your shell's startup files, which run in every new shell",
        files: &[
            ".bashrc",
            ".bash_profile",
            ".bash_login",
            ".bash_logout",
            ".profile",
            ".zshrc",
            ".zprofile",
            ".zlogin",
            ".zlogout",
            ".zshenv",
            ".kshrc",
            ".mkshrc",
            ".cshrc",
            ".tcshrc",
            ".login",
            ".pam_environment",
        ],
        trees: &[".config/fish"],
    },
    // Codex CLI reads its hooks from this file. [`crate::threats`] holds it by
    // name wherever it is, beside Codex's `config.toml`, and that list is
    // asked first. This row holds it under the home, in the same words, for
    // a path that list does not judge (a Windows one).
    HomeGroup {
        what: AGENT_HOOK_SETTINGS,
        files: &[".codex/hooks.json"],
        trees: &[],
    },
    HomeGroup {
        what: "the services, jobs and login items your account starts on its own",
        files: &[],
        trees: &[
            ".config/systemd/user",
            ".local/share/systemd/user",
            ".config/environment.d",
            ".config/autostart",
            "library/launchagents",
        ],
    },
    HomeGroup {
        what: STORED_CREDENTIALS,
        files: &[
            ".aws/credentials",
            ".aws/config",
            ".docker/config.json",
            ".kube/config",
            ".netrc",
            ".npmrc",
            ".pypirc",
            ".cargo/credentials",
            ".cargo/credentials.toml",
            ".config/gh/hosts.yml",
            ".config/hub",
            ".config/git/credentials",
            ".vault-token",
            ".terraform.d/credentials.tfrc.json",
        ],
        trees: &[
            ".azure",
            ".config/gcloud",
            ".password-store",
            ".local/share/keyrings",
            "library/keychains",
        ],
    },
];

const GUARD_PROGRAM: &str = "the guard's own program";

/// What an agent's hook file is, in the words [`crate::threats`] uses for the
/// agent settings it holds by name (a test keeps the two the same).
const AGENT_HOOK_SETTINGS: &str =
    "the guard's own configuration, or the agent settings that load it";

/// What the file at `path` is, when a file tool may not change it: the
/// group's words, to show the person. `None` for every other file, and
/// [`PATH_TOO_LONG`] for a path over the cap, which is not read.
pub fn privileged_file_write(path: &str, context: &WriteContext<'_>) -> Option<&'static str> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() > MAX_PATH_BYTES {
        return Some(PATH_TOO_LONG);
    }
    // With `HOME` unset the account's home still exists; the list in it is
    // judged against the home the account database names.
    let account_home;
    let context = &if context.home.is_none() {
        account_home = home_of_this_account();
        WriteContext {
            home: account_home.as_deref(),
            ..*context
        }
    } else {
        *context
    };
    let Some(absolute) = absolute_path(trimmed, context) else {
        // Relative, with no working directory to place it: only the places
        // that are the same wherever they start can be judged.
        return privileged_write_target(trimmed).map(|target| target.group.what);
    };
    let written = lexical(&absolute);
    if let Some(what) = judge(&written, context) {
        return Some(what);
    }
    // Resolved from the path as given, not its lexical form: after a link,
    // `..` steps out of the link's target, not out of the link's directory,
    // so `proj/link/../.bashrc` can name a file outside the project.
    let real = resolve_links(&absolute);
    if let Some(real) = real.as_ref().filter(|real| **real != written) {
        if let Some(what) = judge(real, context) {
            return Some(what);
        }
    }
    same_as_a_privileged_file(real.as_deref().unwrap_or(&written), context)
}

/// Privileged files in the account's home, relative to it, that
/// [`crate::threats`] holds by name wherever they are (Codex's hooks file and
/// `.zshenv` are in [`HOME_PLACES`] as well). Compared by identity in
/// [`same_as_a_privileged_file`] (Unix only: identity is a device and inode
/// pair), so each is written as the agent writes it: the name of a missing
/// one is compared without case.
#[cfg(unix)]
const HOME_GUARD_FILES: &[&str] = &[
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude.json",
    ".mcp.json",
    ".cursor/mcp.json",
    ".codex/config.toml",
    ".codex/hooks.json",
    // zsh runs it before the hook line Codex starts.
    ".zshenv",
    ".gemini/settings.json",
    // A folder Gemini is told not to trust loads no hook from settings.
    ".gemini/trustedFolders.json",
    ".openclaw/openclaw.json",
    ".config/goose/config.yaml",
    ".hermes/config.yaml",
    ".aider.conf.yml",
    "library/application support/claude/claude_desktop_config.json",
    ".git-credentials",
];

/// Privileged directories in the account's home outside [`HOME_PLACES`].
/// OpenClaw's plugin and hook folders hold the guard that screens its own
/// tools (`innerwarden-guard`) and the hook that records its chats: code the
/// gateway loads, so an agent that could change them could take its own
/// guard off or plant a plugin that rewrites the calls the guard screened.
#[cfg(unix)]
const HOME_GUARD_TREES: &[&str] = &[
    ".config/innerwarden",
    ".ssh",
    ".gnupg",
    ".openclaw/extensions",
    ".openclaw/hooks",
];

/// The account's home from the account database, for a hook run without
/// `HOME`.
#[cfg(unix)]
fn home_of_this_account() -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is to memory owned here and sized as passed; the
    // result is read only when the call says it filled `entry`.
    let status = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        )
    };
    if status != 0 || found.is_null() || entry.pw_dir.is_null() {
        return None;
    }
    // SAFETY: `pw_dir` points into `buffer`, NUL-terminated by the call.
    let dir = unsafe { CStr::from_ptr(entry.pw_dir) };
    let dir = Path::new(std::ffi::OsStr::from_bytes(dir.to_bytes()));
    dir.is_absolute().then(|| dir.to_path_buf())
}

#[cfg(not(unix))]
fn home_of_this_account() -> Option<PathBuf> {
    None
}

/// What `path` is when it is one of the privileged files under another name:
/// the same file (a hard link, or the real file a home link points at), or a
/// file in one of the privileged directories reached by another path. Judged
/// by device and inode, so the spelling does not matter; only what exists is
/// compared, and a missing privileged file is matched by its directory and
/// name.
#[cfg(unix)]
fn same_as_a_privileged_file(path: &Path, context: &WriteContext<'_>) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    let identity = |p: &Path| std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()));
    let target = identity(path);
    let parent = path.parent().and_then(identity);
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase());
    let mut above: Vec<(u64, u64)> = Vec::new();
    let mut directory = path.parent();
    while let Some(at) = directory {
        above.extend(identity(at));
        directory = at.parent();
    }
    let home = context.home?;
    let files = HOME_PLACES
        .iter()
        .flat_map(|group| group.files.iter())
        .chain(HOME_GUARD_FILES);
    for relative in files {
        let relative: &str = relative;
        let place = home.join(relative);
        let same_file = target.is_some() && target == identity(&place);
        let same_slot = parent.is_some()
            && parent == place.parent().and_then(identity)
            && name == relative.rsplit('/').next().map(str::to_lowercase);
        if same_file || same_slot {
            return judge(&place, context);
        }
    }
    let trees = HOME_PLACES
        .iter()
        .flat_map(|group| group.trees.iter())
        .chain(HOME_GUARD_TREES);
    for relative in trees {
        let place = home.join(relative);
        if let Some(tree) = identity(&place) {
            if target == Some(tree) || above.contains(&tree) {
                return judge(&place.join("x"), context);
            }
        }
    }
    let guard = context.guard_program.and_then(identity);
    (guard.is_some() && target == guard).then_some(GUARD_PROGRAM)
}

#[cfg(not(unix))]
fn same_as_a_privileged_file(_: &Path, _: &WriteContext<'_>) -> Option<&'static str> {
    None
}

/// `path` made absolute: `~` from the home, a relative path from the
/// working directory. `None` when the piece it needs is not known.
fn absolute_path(path: &str, context: &WriteContext<'_>) -> Option<PathBuf> {
    if path == "~" {
        return context.home.map(Path::to_path_buf);
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return context.home.map(|home| home.join(rest));
    }
    let path = Path::new(path);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    context.cwd.map(|cwd| cwd.join(path))
}

/// `.` and `..` resolved by name, the way the path reads.
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The file `path` reaches once every link on the way is followed, the part
/// that does not exist yet kept as written. A link whose target does not
/// exist yet is followed too: writing through it creates that target.
fn resolve_links(path: &Path) -> Option<PathBuf> {
    let mut path = path.to_path_buf();
    let mut missing: Vec<std::ffi::OsString> = Vec::new();
    let mut steps = 0u8;
    loop {
        if let Ok(real) = std::fs::canonicalize(&path) {
            let mut out = real;
            for name in missing.iter().rev() {
                out.push(name);
            }
            return Some(out);
        }
        if let Ok(target) = std::fs::read_link(&path) {
            steps += 1;
            if steps > MAX_LINK_STEPS {
                return None;
            }
            path = match path.parent() {
                Some(parent) if target.is_relative() => parent.join(&target),
                _ => target,
            };
            continue;
        }
        missing.push(path.file_name()?.to_os_string());
        if !path.pop() {
            return None;
        }
    }
}

/// [`privileged_file_write`] for one spelling of the path.
fn judge(path: &Path, context: &WriteContext<'_>) -> Option<&'static str> {
    let text = path.to_string_lossy();
    if let Some(target) = privileged_write_target(&text) {
        // A writer that runs as root has its own home under `/root`; its own
        // work there is a project like any other, judged by the home list.
        let own_home = target.group.what == ROOT_HOME
            && homes(context)
                .iter()
                .any(|home| home_relative(path, home).is_some());
        if !own_home {
            return Some(target.group.what);
        }
    }
    for home in homes(context) {
        if let Some(relative) = home_relative(path, &home) {
            if let Some(what) = home_place(&relative) {
                return Some(what);
            }
        }
    }
    if let Some(guard) = context.guard_program {
        let same = |a: &Path, b: &Path| lowercase(a) == lowercase(b);
        if same(path, guard) || std::fs::canonicalize(guard).is_ok_and(|real| same(path, &real)) {
            return Some(GUARD_PROGRAM);
        }
    }
    None
}

/// The home as given and as its links resolve (a home under a linked
/// directory is reached by either name).
fn homes(context: &WriteContext<'_>) -> Vec<PathBuf> {
    let Some(home) = context.home else {
        return Vec::new();
    };
    let given = lexical(home);
    let mut out = vec![given.clone()];
    if let Ok(real) = std::fs::canonicalize(&given) {
        if real != given {
            out.push(real);
        }
    }
    out
}

fn lowercase(path: &Path) -> String {
    path.to_string_lossy().to_lowercase()
}

/// `path` below `home`, as `/`-joined lowercase components; `None` when it
/// is not below it. Lowercase because the macOS file system ignores case.
fn home_relative(path: &Path, home: &Path) -> Option<String> {
    let path = PathBuf::from(lowercase(path));
    let home = PathBuf::from(lowercase(home));
    let rest = path.strip_prefix(&home).ok()?;
    let parts: Vec<String> = rest
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Every file and folder of the [`HOME_PLACES`] groups named `whats`,
/// relative to the home.
pub(crate) fn home_places_of(whats: &'static [&'static str]) -> impl Iterator<Item = &'static str> {
    HOME_PLACES
        .iter()
        .filter(move |group| whats.contains(&group.what))
        .flat_map(|group| group.files.iter().chain(group.trees.iter()).copied())
}

/// What [`HOME_PLACES`] calls the stored credentials.
pub(crate) const STORED_CREDENTIALS: &str = "your stored credentials";

/// The group of [`HOME_PLACES`] a home-relative path is in.
pub(crate) fn home_place(relative: &str) -> Option<&'static str> {
    HOME_PLACES
        .iter()
        .find(|group| {
            group.files.contains(&relative)
                || group.trees.iter().any(|tree| {
                    relative == *tree
                        || relative
                            .strip_prefix(tree)
                            .is_some_and(|rest| rest.starts_with('/'))
                })
        })
        .map(|group| group.what)
}

/// The person-facing reason a file tool call was refused.
pub fn refusal_explanation(tool: &str, path: &str, what: &str) -> String {
    let shown: String = path.trim().chars().take(200).collect();
    format!(
        "{tool} would change `{shown}`, part of {what}. An agent may not change this file \
         with its own tools; if you meant the change, make it yourself"
    )
}

/// The verdict the hook records for a refused file tool call, in the shape
/// of the command verdicts beside it.
pub fn refusal_verdict(tool: &str, path: &str, what: &str) -> Value {
    let explanation = refusal_explanation(tool, path, what);
    serde_json::json!({
        "command": format!("{tool} {}", path.trim()),
        "risk_score": 60,
        "severity": "high",
        "signals": [{
            "signal": "privileged_file_write",
            "score": 60,
            "detail": explanation,
        }],
        "recommendation": "deny",
        "explanation": explanation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn context<'a>(home: &'a Path, cwd: &'a Path) -> WriteContext<'a> {
        WriteContext {
            cwd: Some(cwd),
            home: Some(home),
            guard_program: None,
        }
    }

    #[test]
    fn only_the_file_tools_are_read_as_file_tools() {
        for tool in FILE_TOOLS {
            let key = if *tool == "NotebookEdit" {
                "notebook_path"
            } else {
                "file_path"
            };
            assert_eq!(
                file_tool_call(&json!({"tool_name": tool, "tool_input": {key: "/x/y"}})),
                FileToolCall::Writes {
                    tool: tool.to_string(),
                    paths: vec!["/x/y".into()],
                }
            );
        }
        for tool in [
            "Bash",
            "Read",
            "Grep",
            "WebFetch",
            "write",
            "mcp__fs__write_file",
        ] {
            assert_eq!(
                file_tool_call(&json!({"tool_name": tool, "tool_input": {"file_path": "/x"}})),
                FileToolCall::NotAFileTool,
                "{tool}"
            );
        }
        assert!(matches!(
            file_tool_call(&json!({"tool_name": "Edit", "tool_input": {"content": "x"}})),
            FileToolCall::Unreadable(_)
        ));
        assert!(matches!(
            file_tool_call(&json!({"tool_name": "Write", "tool_input": {"file_path": "  "}})),
            FileToolCall::Unreadable(_)
        ));
    }

    #[test]
    fn the_matcher_names_exactly_the_file_tools() {
        assert_eq!(
            FILE_TOOLS_MATCHER.split('|').collect::<Vec<_>>(),
            FILE_TOOLS
        );
        assert_eq!(
            READ_TOOLS_MATCHER.split('|').collect::<Vec<_>>(),
            READ_TOOLS
        );
    }

    /// Each read tool is said as the shell line that reads the same files,
    /// and nothing else is read as one.
    ///
    /// FAILS ON REVERT of `file_read_call` (every call is `NotARead`, as the
    /// hook took a call with no command before).
    #[test]
    fn a_read_tool_is_said_as_the_shell_read_of_the_same_files() {
        let read = |tool: &str, input: Value| {
            file_read_call(
                &json!({"tool_name": tool, "cwd": "/home/dev/proj", "tool_input": input}),
            )
        };
        for (tool, input, line) in [
            (
                "Read",
                json!({"file_path": "/home/dev/.ssh/id_ed25519"}),
                "cat /home/dev/.ssh/id_ed25519",
            ),
            (
                "Read",
                json!({"file_path": "/home/dev/proj/src/main.rs", "offset": 10, "limit": 40}),
                "cat /home/dev/proj/src/main.rs",
            ),
            (
                "Read",
                json!({"file_path": "~/.codex/auth.json"}),
                "cat ~/.codex/auth.json",
            ),
            (
                "Read",
                json!({"file_path": "/home/dev/My Notes/a.md", "path": "/etc/shadow"}),
                "cat '/home/dev/My Notes/a.md' /etc/shadow",
            ),
            (
                "Read",
                json!({"notebook_path": "/home/dev/proj/a.ipynb"}),
                "cat /home/dev/proj/a.ipynb",
            ),
            (
                "Grep",
                json!({"pattern": "xoxb-", "path": "/home/dev/.hermes", "output_mode": "content"}),
                "grep -r '' /home/dev/.hermes",
            ),
            (
                "Grep",
                json!({"pattern": "docker run --privileged", "glob": "*.md"}),
                "grep -r '' /home/dev/proj",
            ),
            (
                "Glob",
                json!({"pattern": "**/id_rsa", "path": "/"}),
                "find / -path '**/id_rsa'",
            ),
            (
                "Glob",
                json!({"pattern": "src/**/*.rs"}),
                "find /home/dev/proj -path 'src/**/*.rs'",
            ),
        ] {
            assert_eq!(
                read(tool, input.clone()),
                FileReadCall::Reads(line.to_string()),
                "{tool} {input}"
            );
        }
        // No folder at all: the search runs where the hook runs.
        assert_eq!(
            file_read_call(&json!({"tool_name": "Grep", "tool_input": {"pattern": "x"}})),
            FileReadCall::Reads("grep -r '' .".into())
        );
        for tool in [
            "Bash",
            "Write",
            "Edit",
            "read",
            "Read_File",
            "mcp__fs__read_file",
        ] {
            assert_eq!(
                read(
                    tool,
                    json!({"file_path": "/home/dev/.ssh/id_rsa", "pattern": "x"})
                ),
                FileReadCall::NotARead,
                "{tool}"
            );
        }
        for (tool, input) in [
            ("Read", json!({"offset": 1})),
            ("Read", json!({"file_path": "  "})),
            ("Glob", json!({"path": "/home/dev"})),
        ] {
            assert!(
                matches!(read(tool, input.clone()), FileReadCall::Unreadable(_)),
                "{tool} {input}"
            );
        }
    }

    /// The same reads under Gemini CLI's and Hermes Agent's names, with the
    /// fields their own sources give them, are said as the same lines.
    ///
    /// FAILS ON REVERT of `OTHER_READ_TOOLS` (each call is `NotARead`), of
    /// `absolute_path` or `include` in the file arm, of `dir_path` in
    /// `FOLDER_KEYS`, or of the `target` test of `search_files`.
    #[test]
    fn another_agents_read_tool_is_said_as_the_same_shell_read() {
        let read = |tool: &str, input: Value| {
            file_read_call(
                &json!({"tool_name": tool, "cwd": "/home/dev/proj", "tool_input": input}),
            )
        };
        for (tool, input, line) in [
            // Gemini CLI.
            (
                "read_file",
                json!({"file_path": "/home/dev/.ssh/id_ed25519", "start_line": 1}),
                "cat /home/dev/.ssh/id_ed25519",
            ),
            (
                "read_file",
                json!({"absolute_path": "/home/dev/.netrc"}),
                "cat /home/dev/.netrc",
            ),
            (
                "read_many_files",
                json!({"include": ["src/**/*.rs", "/home/dev/.aws/credentials"], "recursive": true}),
                "cat 'src/**/*.rs' /home/dev/.aws/credentials",
            ),
            (
                "glob",
                // A broad root that is no link on any runner: `/home` is one
                // on macOS (it leads to `/System/Volumes/Data/home`).
                json!({"pattern": "**/id_rsa", "dir_path": "/srv"}),
                "find /srv -path '**/id_rsa'",
            ),
            (
                "grep_search",
                json!({"pattern": "oauth_token", "dir_path": "/home/dev/.config"}),
                "grep -r -e oauth /home/dev/.config",
            ),
            (
                "search_file_content",
                json!({"pattern": "x", "path": "/home/dev/.hermes"}),
                "grep -r '' /home/dev/.hermes",
            ),
            // Hermes Agent.
            (
                "read_file",
                json!({"path": "~/.codex/auth.json", "offset": 1, "limit": 200}),
                "cat ~/.codex/auth.json",
            ),
            (
                "search_files",
                json!({"pattern": "xoxb-", "target": "content", "path": "/home/dev/.hermes"}),
                "grep -r '' /home/dev/.hermes",
            ),
            (
                "search_files",
                json!({"pattern": "TOKEN"}),
                "grep -r -e token /home/dev/proj",
            ),
            (
                "search_files",
                json!({"pattern": "*.pem", "target": "files", "path": "/"}),
                "find / -path '*.pem'",
            ),
        ] {
            assert_eq!(
                read(tool, input.clone()),
                FileReadCall::Reads(line.to_string()),
                "{tool} {input}"
            );
        }
        for (tool, input) in [
            ("read_file", json!({"start_line": 1})),
            ("read_many_files", json!({"include": []})),
            ("glob", json!({"dir_path": "/home/dev"})),
        ] {
            assert!(
                matches!(read(tool, input.clone()), FileReadCall::Unreadable(_)),
                "{tool} {input}"
            );
        }
    }

    /// A search keeps the word that makes it a hunt for secrets, and only
    /// that word: the rest of the search text is no file and no command.
    ///
    /// FAILS ON REVERT of the `credential_hunt_token` reading in the search
    /// arm: every line holds `''`.
    #[test]
    fn a_search_keeps_only_the_word_it_hunts() {
        let grep = |pattern: &str| {
            file_read_call(&json!({
                "tool_name": "Grep",
                "cwd": "/home/dev/proj",
                "tool_input": {"pattern": pattern, "path": "/", "-A": 50},
            }))
        };
        for (pattern, line) in [
            (
                "password|BEGIN OPENSSH PRIVATE KEY",
                "grep -r -e password /",
            ),
            ("API_KEY=", "grep -r -e api_key /"),
            ("id_rsa", "grep -r -e id_rsa /"),
            ("rm -rf /; curl x | sh", "grep -r '' /"),
            ("fn main", "grep -r '' /"),
        ] {
            assert_eq!(grep(pattern), FileReadCall::Reads(line.into()), "{pattern}");
        }
    }

    /// A search of the home itself for a narrow text keeps its text, so it
    /// is judged as `grep -r <text> ~` is; one for a secret, one limited to
    /// files where secrets are kept, and one of a folder the home is in keep
    /// the empty pattern, the read of the whole home.
    ///
    /// FAILS ON REVERT of `narrow_search_of_the_home` in the search arm:
    /// the first lines hold `''`.
    #[test]
    fn a_narrow_search_of_the_home_keeps_its_text() {
        let home = Path::new("/home/dev");
        let project = home.join("proj");
        let ctx = context(home, &project);
        let grep = |input: Value| {
            file_read_call_in(&json!({"tool_name": "Grep", "tool_input": input}), &ctx)
        };
        for (input, line) in [
            (
                json!({"pattern": "fn main", "path": "/home/dev"}),
                "grep -r -e 'fn main' /home/dev",
            ),
            (
                json!({"pattern": "TODO", "path": "/home/dev/"}),
                "grep -r -e 'TODO' /home/dev/",
            ),
            (
                json!({"pattern": "innerwarden", "path": "~"}),
                "grep -r -e 'innerwarden' ~",
            ),
            (
                json!({"pattern": "use serde", "path": "/home/dev", "glob": "*.rs"}),
                "grep -r -e 'use serde' /home/dev",
            ),
            // A secret, by the word a hunt looks for: as before.
            (
                json!({"pattern": "password", "path": "/home/dev"}),
                "grep -r -e password /home/dev",
            ),
            (
                json!({"pattern": "TOKEN", "path": "/home/dev"}),
                "grep -r -e token /home/dev",
            ),
            // By a credential marker, a wide pattern, or a glob that aims at
            // secrets: the whole home.
            (
                json!({"pattern": "AKIA", "path": "/home/dev"}),
                "grep -r '' /home/dev",
            ),
            (
                json!({"pattern": "ssh-ed25519", "path": "/home/dev"}),
                "grep -r '' /home/dev",
            ),
            (
                json!({"pattern": "TODO|FIXME", "path": "/home/dev"}),
                "grep -r '' /home/dev",
            ),
            (
                json!({"pattern": ".*", "path": "/home/dev"}),
                "grep -r '' /home/dev",
            ),
            (
                json!({"pattern": "TODO", "path": "/home/dev", "glob": "**/.ssh/*"}),
                "grep -r '' /home/dev",
            ),
            (
                json!({"pattern": "TODO", "path": "/home/dev", "glob": ".aws/**"}),
                "grep -r '' /home/dev",
            ),
            (
                json!({"pattern": "TODO", "path": "/home/dev", "glob": "*.pem"}),
                "grep -r '' /home/dev",
            ),
            (
                json!({"pattern": "TODO", "path": "/home/dev", "glob": "id_*"}),
                "grep -r '' /home/dev",
            ),
            (
                json!({"pattern": "TODO", "path": "/home/dev", "glob": "*credentials*"}),
                "grep -r '' /home/dev",
            ),
            (
                json!({"pattern": "TODO", "path": "/home/dev", "include": "*.env"}),
                "grep -r '' /home/dev",
            ),
            // Not the home itself: as before.
            (json!({"pattern": "fn main", "path": "/"}), "grep -r '' /"),
            (
                json!({"pattern": "fn main", "path": "/home"}),
                "grep -r '' /home",
            ),
            (
                json!({"pattern": "fn main", "path": "/home/dev/.config"}),
                "grep -r '' /home/dev/.config",
            ),
        ] {
            assert_eq!(
                grep(input.clone()),
                FileReadCall::Reads(line.into()),
                "{input}"
            );
        }
    }

    /// A read through a link to a secret, through a hard link to one, or by
    /// a spelling in another case, is said with the secret's own name too.
    ///
    /// FAILS ON REVERT of `other_names_of` in `file_read_call_in` (each line
    /// is the path as written alone), of the `canonicalize` step (the link),
    /// or of `same_secret_in_home` (the hard link).
    #[cfg(unix)]
    #[test]
    fn a_read_names_the_secret_a_link_or_a_hard_link_reaches() {
        let root = tempfile::tempdir().expect("tempdir");
        // Its real path: a temporary folder may sit under a link (`/tmp` on
        // macOS), and the spellings below are then the real ones.
        let root_path = std::fs::canonicalize(root.path()).expect("real tempdir");
        let home = root_path.join("home");
        std::fs::create_dir_all(home.join(".ssh")).expect("ssh");
        let key = home.join(".ssh/id_ed25519");
        std::fs::write(&key, "dummy key\n").expect("key");
        std::fs::create_dir_all(home.join(".docker")).expect("docker");
        std::fs::write(home.join(".docker/config.json"), "{}\n").expect("docker config");
        let elsewhere = root_path.join("tmp");
        std::fs::create_dir_all(&elsewhere).expect("tmp");
        let soft = elsewhere.join("k");
        std::os::unix::fs::symlink(&key, &soft).expect("symlink");
        let hard = elsewhere.join("h");
        std::fs::hard_link(&key, &hard).expect("hard link");
        let hard_docker = elsewhere.join("d");
        std::fs::hard_link(home.join(".docker/config.json"), &hard_docker).expect("hard link");
        let project = home.join("proj");
        std::fs::create_dir_all(&project).expect("project");
        let ctx = context(&home, &project);
        let real_key = std::fs::canonicalize(&key).expect("real key");
        let at = |p: &Path| p.to_string_lossy().into_owned();
        let read = |path: &str| {
            file_read_call_in(
                &json!({"tool_name": "Read", "tool_input": {"file_path": path}}),
                &ctx,
            )
        };
        assert_eq!(
            read(&at(&soft)),
            FileReadCall::Reads(format!("cat {} {}", at(&soft), at(&real_key)))
        );
        assert_eq!(
            read(&at(&hard)),
            FileReadCall::Reads(format!("cat {} {}", at(&hard), at(&key)))
        );
        assert_eq!(
            read(&at(&hard_docker)),
            FileReadCall::Reads(format!(
                "cat {} {}",
                at(&hard_docker),
                at(&home.join(".docker/config.json"))
            ))
        );
        // A link to the folder a search runs in is searched as the folder.
        let soft_folder = elsewhere.join("s");
        std::os::unix::fs::symlink(home.join(".ssh"), &soft_folder).expect("folder link");
        let real_folder = std::fs::canonicalize(home.join(".ssh")).expect("real folder");
        assert_eq!(
            file_read_call_in(
                &json!({"tool_name": "Grep", "tool_input": {"pattern": "x", "path": at(&soft_folder)}}),
                &ctx,
            ),
            FileReadCall::Reads(format!(
                "grep -r '' {} {}",
                at(&soft_folder),
                at(&real_folder)
            ))
        );
        // The twins: the secret by its own name, and an ordinary file, are
        // said as written and nothing more.
        let plain = project.join("main.rs");
        std::fs::write(&plain, "fn main() {}\n").expect("main.rs");
        for path in [&key, &plain] {
            let path = std::fs::canonicalize(path).expect("real path");
            assert_eq!(
                read(&at(&path)),
                FileReadCall::Reads(format!("cat {}", at(&path)))
            );
        }
    }

    /// An empty path names no file, whatever the folder the call runs in
    /// is reached through; and the home is `HOME` unless it is empty.
    /// FAILS ON REVERT of the empty test in `other_names_of` (the working
    /// directory's real path is given), or of the `!` in `home_from`.
    #[cfg(unix)]
    #[test]
    fn an_empty_path_names_nothing_and_the_home_is_homes_unless_empty() {
        let root = tempfile::tempdir().expect("tempdir");
        let real = std::fs::canonicalize(root.path())
            .expect("real")
            .join("real");
        std::fs::create_dir_all(&real).expect("real dir");
        let linked = root.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked).expect("link");
        let ctx = WriteContext {
            cwd: Some(&linked),
            home: Some(&real),
            guard_program: None,
        };
        assert_eq!(other_names_of("", &ctx), Vec::<String>::new());
        assert_eq!(other_names_of("  ", &ctx), Vec::<String>::new());
        assert_eq!(
            other_names_of(".", &ctx),
            vec![real.to_string_lossy().into_owned()]
        );
        assert_eq!(
            home_from(Some("/home/dev".into())),
            Some(PathBuf::from("/home/dev"))
        );
        assert_eq!(home_from(Some("".into())), home_of_this_account());
        assert_eq!(home_from(None), home_of_this_account());
    }

    /// On a file system that ignores case a hidden folder in the home is
    /// also read in lowercase, the spelling the rules know.
    ///
    /// FAILS ON REVERT of `lowercase_hidden_spelling`.
    #[test]
    fn an_upper_case_spelling_in_a_hidden_folder_is_read_in_lowercase() {
        let home = Path::new("/Users/dev");
        for (path, lower) in [
            (
                "/Users/dev/.SSH/id_ed25519",
                Some("/Users/dev/.ssh/id_ed25519"),
            ),
            (
                "/Users/dev/.Codex/AUTH.json",
                Some("/Users/dev/.codex/auth.json"),
            ),
            ("/USERS/DEV/.ssh/ID_RSA", Some("/Users/dev/.ssh/id_rsa")),
            ("/Users/dev/.ssh/id_ed25519", None),
            ("/Users/dev/Projects/App/README.md", None),
            ("/Users/other/.SSH/id_rsa", None),
            ("/Users/dev", None),
        ] {
            assert_eq!(
                lowercase_hidden_spelling(Path::new(path), home),
                lower.map(PathBuf::from),
                "{path}"
            );
        }
    }

    /// A path is one word of the line and no more: a quote, a space, a
    /// substitution or an option inside it stays inside it.
    #[test]
    fn a_path_is_one_word_of_the_line() {
        for (path, word) in [
            ("/home/dev/.netrc", "/home/dev/.netrc"),
            ("~", "~"),
            ("~/", "~/"),
            ("~/.ssh", "~/.ssh"),
            ("~/My Keys/id_rsa", "~/'My Keys/id_rsa'"),
            ("/tmp/a b", "'/tmp/a b'"),
            ("/tmp/it's", r"'/tmp/it'\''s'"),
            ("/tmp/$(id)", "'/tmp/$(id)'"),
            ("/tmp/a;rm -rf ~", "'/tmp/a;rm -rf ~'"),
            ("-rf", "./-rf"),
            ("--help me", "'./--help me'"),
            ("src/**/*.rs", "'src/**/*.rs'"),
        ] {
            assert_eq!(shell_path_word(path), word, "{path}");
        }
    }

    /// The per-agent profiles, the user's and the system's, are the person's:
    /// a file tool writing either one is refused however it is spelled. The
    /// refusal reads the path only, so no level of trust and no profile can
    /// change it.
    ///
    /// FAILS ON REVERT: drop `.config/innerwarden` and `/etc/innerwarden`
    /// from the privileged places and these are allowed.
    #[test]
    fn the_agent_profiles_files_are_refused_to_every_file_tool() {
        let home = Path::new("/home/dev");
        let cwd = Path::new("/home/dev/proj");
        let ctx = context(home, cwd);
        for path in [
            "/home/dev/.config/innerwarden/agent-profiles.toml",
            "~/.config/innerwarden/agent-profiles.toml",
            "../.config/innerwarden/agent-profiles.toml",
            "/home/dev/proj/../.config/innerwarden/./agent-profiles.toml",
            "/etc/innerwarden/agent-profiles.toml",
            "/etc//innerwarden/agent-profiles.toml",
            "/ETC/innerwarden/AGENT-PROFILES.TOML",
        ] {
            assert!(
                privileged_file_write(path, &ctx).is_some(),
                "{path} must be refused"
            );
        }
        let root = context(Path::new("/root"), Path::new("/root/proj"));
        for path in [
            "/root/.config/innerwarden/agent-profiles.toml",
            "/etc/innerwarden/agent-profiles.toml",
        ] {
            assert!(privileged_file_write(path, &root).is_some(), "{path}");
        }
        // A file of the same name in the project is the project's.
        assert_eq!(
            privileged_file_write("/home/dev/proj/agent-profiles.toml", &ctx),
            None
        );
    }

    /// The row's proof: the agent's settings, the guard's configuration, shell
    /// startup files, SSH keys, the account's own services and credential
    /// stores are refused, however the path is spelled.
    ///
    /// FAILS ON REVERT: an empty [`HOME_PLACES`], or `privileged_file_write`
    /// returning `None`, leaves these allowed.
    #[test]
    fn privileged_files_are_refused_however_they_are_spelled() {
        let home = Path::new("/home/dev");
        let cwd = Path::new("/home/dev/proj");
        let ctx = context(home, cwd);
        for (path, what) in [
            (
                "/home/dev/.claude/settings.json",
                "the guard's own configuration",
            ),
            ("~/.claude/settings.json", "the guard's own configuration"),
            ("../.claude/settings.json", "the guard's own configuration"),
            (
                "/home/dev/proj/./src/../../.claude/settings.json",
                "the guard's own configuration",
            ),
            (".claude/settings.json", "the guard's own configuration"),
            (
                ".claude/settings.local.json",
                "the guard's own configuration",
            ),
            (
                "/home/dev/.config/innerwarden/suppress.toml",
                "the guard's own configuration",
            ),
            (
                "/home/dev/.codex/config.toml",
                "the guard's own configuration",
            ),
            (
                "/home/dev/.openclaw/extensions/innerwarden-guard/index.js",
                "the guard's own configuration",
            ),
            (
                "~/.openclaw/extensions/a-new-plugin/index.js",
                "the guard's own configuration",
            ),
            (
                "/home/dev/.openclaw/hooks/innerwarden-attempts/handler.js",
                "the guard's own configuration",
            ),
            ("/home/dev/.ssh/authorized_keys", "SSH"),
            ("/home/dev/.bashrc", "startup files"),
            ("~/.zshrc", "startup files"),
            ("/HOME/DEV/.ZSHRC", "startup files"),
            ("/home/dev/.config/fish/config.fish", "startup files"),
            (
                "/home/dev/.config/systemd/user/x.service",
                "your account starts",
            ),
            (
                "/home/dev/Library/LaunchAgents/com.x.plist",
                "your account starts",
            ),
            ("/home/dev/.aws/credentials", "credentials"),
            ("/home/dev/.docker/config.json", "credentials"),
            ("/home/dev/.npmrc", "credentials"),
            ("/home/dev/.git-credentials", "git credentials"),
            ("/etc/cron.d/job", "schedule"),
            ("/var/spool/cron/crontabs/dev", "schedule"),
            ("/etc/sudoers.d/dev", "sudo"),
        ] {
            let found = privileged_file_write(path, &ctx)
                .unwrap_or_else(|| panic!("{path} must be refused"));
            assert!(found.contains(what), "{path}: {found}");
        }
    }

    /// The guard rule of the row: ordinary project edits are never refused,
    /// including files that share a name with a privileged one but sit in a
    /// project, and the work of an agent that runs as root in its own home.
    #[test]
    fn project_edits_are_never_refused() {
        let home = Path::new("/home/dev");
        let cwd = Path::new("/home/dev/proj");
        let ctx = context(home, cwd);
        for path in [
            "/home/dev/proj/src/main.rs",
            "src/main.rs",
            "./README.md",
            "/home/dev/proj/.npmrc",
            "/home/dev/proj/.profile.example",
            "/home/dev/proj/config/.bashrc",
            "/home/dev/proj/.claude/agents/reviewer.md",
            "/home/dev/proj/.claude/commands/x.md",
            "/home/dev/proj/CLAUDE.md",
            "/home/dev/proj/.env",
            "/home/dev/notes.md",
            "/home/dev/.config/systemd-like/x",
            "/tmp/scratch.txt",
        ] {
            assert_eq!(privileged_file_write(path, &ctx), None, "{path}");
        }
        let root = context(Path::new("/root"), Path::new("/root/proj"));
        assert_eq!(privileged_file_write("/root/proj/src/main.rs", &root), None);
        assert!(privileged_file_write("/root/.bashrc", &root).is_some());
        assert!(privileged_file_write("/root/.claude/settings.json", &root).is_some());
        // Root's home is still root's to an agent that is not root.
        assert_eq!(privileged_file_write("/root/proj/x", &ctx), Some(ROOT_HOME));
    }

    #[test]
    fn the_guards_own_program_is_refused() {
        let ctx = WriteContext {
            cwd: Some(Path::new("/w")),
            home: Some(Path::new("/home/dev")),
            guard_program: Some(Path::new("/opt/tools/innerwarden")),
        };
        assert_eq!(
            privileged_file_write("/opt/tools/innerwarden", &ctx),
            Some(GUARD_PROGRAM)
        );
        assert_eq!(privileged_file_write("/opt/tools/other", &ctx), None);
    }

    /// A link made in the project earlier does not step around the list,
    /// including one whose target does not exist yet.
    ///
    /// FAILS ON REVERT: judge only the path as written and both links pass.
    #[cfg(unix)]
    #[test]
    fn a_link_in_the_project_is_followed_to_what_it_writes() {
        let dir = tempfile::TempDir::new().unwrap();
        let home = dir.path().join("home");
        let proj = home.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(home.join(".claude/settings.json"), "{}").unwrap();
        std::os::unix::fs::symlink(home.join(".claude/settings.json"), proj.join("cfg.json"))
            .unwrap();
        std::os::unix::fs::symlink(home.join(".claude"), proj.join("dot")).unwrap();
        // Dangling: the unit does not exist yet, and writing creates it.
        std::os::unix::fs::symlink(
            home.join(".config/systemd/user/x.service"),
            proj.join("unit"),
        )
        .unwrap();
        // `..` after a link steps out of the link's target: `cfgdir/..` is
        // the home, not the project.
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::os::unix::fs::symlink(home.join(".config"), proj.join("cfgdir")).unwrap();
        let ctx = context(&home, &proj);
        for path in ["cfg.json", "dot/settings.json", "unit", "cfgdir/../.bashrc"] {
            assert!(
                privileged_file_write(path, &ctx).is_some(),
                "{path} must be judged where it writes"
            );
        }
        std::fs::write(proj.join("plain.txt"), "x").unwrap();
        assert_eq!(privileged_file_write("plain.txt", &ctx), None);
    }

    /// The same file under another name is the same file: a hard link made
    /// in the project, the real file a home link points at (dotfiles kept in
    /// a repository), a new file in a privileged directory reached that way,
    /// and a hard link to the guard's own program.
    ///
    /// FAILS ON REVERT: drop `same_as_a_privileged_file` from
    /// `privileged_file_write` and every path here is allowed; read `==` as
    /// `!=` in the test of the folder there and a file in another folder
    /// that only shares its name with a startup file is refused; read `==`
    /// as `!=` in the test of the name and a new file of any other name in
    /// the home is refused.
    #[cfg(unix)]
    #[test]
    fn the_same_file_under_another_name_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let home = dir.path().join("home");
        let proj = home.join("proj");
        let dotfiles = home.join("dotfiles");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::create_dir_all(dotfiles.join("fish")).unwrap();
        std::fs::create_dir_all(home.join(".config")).unwrap();
        std::fs::write(home.join(".claude/settings.json"), "{}").unwrap();
        std::fs::hard_link(home.join(".claude/settings.json"), proj.join("notes.json")).unwrap();
        std::fs::write(dotfiles.join("bashrc"), "").unwrap();
        std::os::unix::fs::symlink(dotfiles.join("bashrc"), home.join(".bashrc")).unwrap();
        std::os::unix::fs::symlink(dotfiles.join("fish"), home.join(".config/fish")).unwrap();
        let tools = dir.path().join("tools");
        std::fs::create_dir_all(&tools).unwrap();
        std::fs::write(tools.join("innerwarden"), "").unwrap();
        std::fs::hard_link(tools.join("innerwarden"), proj.join("helper")).unwrap();
        let guard = tools.join("innerwarden");
        let ctx = WriteContext {
            cwd: Some(&proj),
            home: Some(&home),
            guard_program: Some(&guard),
        };
        for (path, what) in [
            ("notes.json", "the guard's own configuration"),
            ("../dotfiles/bashrc", "startup files"),
            ("../dotfiles/fish/conf.d/new.fish", "startup files"),
            ("helper", GUARD_PROGRAM),
        ] {
            let found = privileged_file_write(path, &ctx)
                .unwrap_or_else(|| panic!("{path} is a privileged file under another name"));
            assert!(found.contains(what), "{path}: {found}");
        }
        // A plain file beside them, and a dotfile that is no link, are not.
        std::fs::write(dotfiles.join("README.md"), "").unwrap();
        std::fs::write(dotfiles.join(".bashrc"), "").unwrap();
        std::fs::write(proj.join("plain.json"), "{}").unwrap();
        for path in [
            "plain.json",
            "../dotfiles/README.md",
            "new.txt",
            "../dotfiles/.bashrc",
            "../todo.txt",
        ] {
            assert_eq!(privileged_file_write(path, &ctx), None, "{path}");
        }
    }

    /// OpenClaw's plugin and hook folders hold the guard that screens its
    /// own tools: reached by another name (the folder a link in the home
    /// leads to), a write into them is refused as a write into them.
    ///
    /// FAILS ON REVERT: take `.openclaw/extensions` and `.openclaw/hooks` out
    /// of `HOME_GUARD_TREES` and both paths are allowed.
    #[cfg(unix)]
    #[test]
    fn openclaws_plugin_folders_are_refused_under_another_name() {
        let dir = tempfile::TempDir::new().unwrap();
        let home = dir.path().join("home");
        let proj = home.join("proj");
        let kept = home.join("kept");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::create_dir_all(home.join(".openclaw")).unwrap();
        std::fs::create_dir_all(kept.join("ext/innerwarden-guard")).unwrap();
        std::fs::create_dir_all(kept.join("hooks/innerwarden-attempts")).unwrap();
        std::os::unix::fs::symlink(kept.join("ext"), home.join(".openclaw/extensions")).unwrap();
        std::os::unix::fs::symlink(kept.join("hooks"), home.join(".openclaw/hooks")).unwrap();
        let ctx = WriteContext {
            cwd: Some(&proj),
            home: Some(&home),
            guard_program: None,
        };
        for path in [
            "../kept/ext/innerwarden-guard/index.js",
            "../kept/hooks/innerwarden-attempts/handler.js",
            "../kept/ext/new-plugin/index.js",
        ] {
            let found = privileged_file_write(path, &ctx)
                .unwrap_or_else(|| panic!("{path} is OpenClaw's plugin folder under another name"));
            assert!(
                found.contains("the guard's own configuration"),
                "{path}: {found}"
            );
        }
        assert_eq!(privileged_file_write("../kept/notes.txt", &ctx), None);
    }

    /// A hook run without `HOME` still knows the account's home, from the
    /// account database, so the home list does not fall away.
    ///
    /// FAILS ON REVERT: without `home_of_this_account` the path below is
    /// judged as an unknown home (allowed) or as root's home, not as a
    /// startup file.
    #[cfg(unix)]
    #[test]
    fn with_no_home_set_the_accounts_own_home_is_used() {
        let Some(home) = home_of_this_account() else {
            return;
        };
        let ctx = WriteContext {
            cwd: Some(Path::new("/")),
            home: None,
            guard_program: None,
        };
        let path = home.join(".bashrc");
        let found = privileged_file_write(&path.to_string_lossy(), &ctx)
            .unwrap_or_else(|| panic!("{} must be refused with HOME unset", path.display()));
        assert!(found.contains("startup files"), "{found}");
    }

    #[test]
    fn a_relative_path_with_no_working_directory_is_judged_as_far_as_it_can_be() {
        let ctx = WriteContext::default();
        assert!(privileged_file_write(".claude/settings.json", &ctx).is_some());
        assert_eq!(privileged_file_write("src/main.rs", &ctx), None);
    }

    #[test]
    fn the_refusal_says_what_and_who_may_change_it() {
        let verdict = refusal_verdict("Edit", "/h/.claude/settings.json", "the x");
        assert_eq!(verdict["recommendation"], "deny");
        assert_eq!(verdict["signals"][0]["signal"], "privileged_file_write");
        let text = verdict["explanation"].as_str().unwrap();
        assert!(text.contains("Edit would change `/h/.claude/settings.json`"));
        assert!(text.contains("make it yourself"));
    }

    /// Gemini CLI's two file tools are read as file tools, by their exact
    /// names, so a write through either is judged by where it lands.
    ///
    /// FAILS ON REVERT: take [`GEMINI_FILE_TOOLS`] out of `file_tool_call`
    /// and both read as `NotAFileTool`, which the hook lets through.
    #[test]
    fn geminis_file_tools_are_read_as_file_tools() {
        assert_eq!(
            file_tool_call(&json!({
                "tool_name": "write_file",
                "tool_input": {"file_path": "/x/y", "content": "z"},
            })),
            FileToolCall::Writes {
                tool: "write_file".into(),
                paths: vec!["/x/y".into()],
            }
        );
        assert_eq!(
            file_tool_call(&json!({
                "tool_name": "replace",
                "tool_input": {
                    "file_path": "notes.md",
                    "instruction": "i",
                    "old_string": "a",
                    "new_string": "b",
                },
            })),
            FileToolCall::Writes {
                tool: "replace".into(),
                paths: vec!["notes.md".into()],
            }
        );
        assert_eq!(
            file_tool_call(&json!({"tool_name": "replace", "tool_input": {"old_string": "a"}})),
            FileToolCall::Unreadable("a file tool call with no file path")
        );
        // An MCP server's tool of the same name is the proxy's to screen.
        assert_eq!(
            file_tool_call(&json!({
                "tool_name": "mcp_fs_write_file",
                "tool_input": {"file_path": "/x"},
            })),
            FileToolCall::NotAFileTool
        );
        let ctx = context(Path::new("/home/dev"), Path::new("/home/dev/proj"));
        assert_eq!(
            privileged_file_write("~/.gemini/settings.json", &ctx),
            Some(AGENT_HOOK_SETTINGS)
        );
    }

    /// A path over the length cap is not read, and is not passed for that:
    /// `./` repeated in it puts any file past the cap. The empty path alone
    /// names nothing.
    ///
    /// FAILS ON REVERT: put `|| trimmed.len() > MAX_PATH_BYTES` back in the
    /// test of the empty path in `privileged_file_write` and the padded path
    /// to Gemini's settings is `None`, which the hook lets through; read `>`
    /// as `>=` in the test of the cap and a path at the cap is not read.
    #[test]
    fn a_path_over_the_cap_is_not_passed_as_ordinary() {
        let ctx = context(Path::new("/home/dev"), Path::new("/home/dev/proj"));
        let padded = format!("/home/dev/{}.gemini/settings.json", "./".repeat(2100));
        assert!(padded.len() > MAX_PATH_BYTES);
        assert_eq!(privileged_file_write(&padded, &ctx), Some(PATH_TOO_LONG));
        // The same file under the cap is read for what it is.
        let short = format!("/home/dev/{}.gemini/settings.json", "./".repeat(20));
        assert_eq!(
            privileged_file_write(&short, &ctx),
            Some(AGENT_HOOK_SETTINGS)
        );
        // A long path to an ordinary file is not read either.
        let ordinary = format!("/home/dev/proj/{}notes.md", "a/".repeat(2100));
        assert_eq!(privileged_file_write(&ordinary, &ctx), Some(PATH_TOO_LONG));
        // At the cap a path is read; one byte past it, it is not.
        let at_cap = format!("/home/dev/proj/{}b", "a/".repeat(2040));
        assert_eq!(at_cap.len(), MAX_PATH_BYTES);
        assert_eq!(privileged_file_write(&at_cap, &ctx), None);
        assert_eq!(
            privileged_file_write(&format!("{at_cap}c"), &ctx),
            Some(PATH_TOO_LONG)
        );
        assert_eq!(privileged_file_write("  ", &ctx), None);
    }

    fn hermes_patch_of(input: serde_json::Value) -> FileToolCall {
        file_tool_call(&json!({"tool_name": "patch", "tool_input": input}))
    }

    /// Hermes Agent's `patch` is read for the file it names in `path` and
    /// for every file its V4A patch names, as loosely as Hermes reads its
    /// markers: no blank after `***`, a run of blanks between the words, and
    /// both ends of a `Move File: a -> b`.
    ///
    /// FAILS ON REVERT: drop the `HERMES_PATCH_TOOL` branch in
    /// `file_tool_call` and every call below is `NotAFileTool`; read the
    /// markers by their exact text and the loose ones name nothing.
    #[test]
    fn hermes_patch_is_read_for_its_path_and_every_file_its_patch_names() {
        let writes = |paths: &[&str]| FileToolCall::Writes {
            tool: "patch".into(),
            paths: paths.iter().map(|p| p.to_string()).collect(),
        };
        assert_eq!(
            hermes_patch_of(json!({"path": "~/.bashrc", "old_string": "a", "new_string": "b"})),
            writes(&["~/.bashrc"])
        );
        let patch = "*** Begin Patch\n***Update File: src/a.rs\n@@\n-a\n+b\n\
                     ***  Add   File:  ~/.hermes/config.yaml \n+x\n\
                     *** Delete File: notes.md\n\
                     *** Move File: src/b.rs -> ~/.ssh/authorized_keys\n*** End Patch";
        assert_eq!(
            hermes_patch_of(json!({"mode": "patch", "patch": patch})),
            writes(&[
                "src/a.rs",
                "~/.hermes/config.yaml",
                "notes.md",
                "src/b.rs",
                "~/.ssh/authorized_keys"
            ])
        );
        assert_eq!(
            hermes_patch_of(json!({"mode": "patch", "patch": "*** Update File:   \n"})),
            FileToolCall::Unreadable("a patch that names a file with no path")
        );
        assert_eq!(
            hermes_patch_of(json!({"mode": "patch"})),
            FileToolCall::Unreadable("a patch tool call with no file path")
        );
        assert_eq!(
            hermes_patch_of(json!({"mode": "patch", "patch": "*** Begin Patch\n*** End Patch"})),
            FileToolCall::Unreadable("a patch tool call with no file path")
        );
    }

    fn patch_call_of(patch: &str) -> FileToolCall {
        file_tool_call(&json!({"tool_name": "apply_patch", "tool_input": {"command": patch}}))
    }

    /// Every file a patch names is read: added, updated, deleted and moved
    /// to, in the order named and each once.
    ///
    /// FAILS ON REVERT: drop any one marker from [`PATCH_PATH_MARKERS`] and
    /// its file is missing from the list, so it is never judged.
    #[test]
    fn a_patch_is_read_for_every_file_it_names() {
        let patch = "*** Begin Patch\n\
                     *** Add File: notes/new.md\n\
                     +hello\n\
                     *** Update File: src/lib.rs\n\
                     *** Move to: src/moved.rs\n\
                     @@\n\
                     -old\n\
                     +new\n\
                     *** Delete File: /abs/gone.txt\n\
                     *** Update File: src/lib.rs\n\
                     @@\n\
                     -a\n\
                     +b\n\
                     *** End Patch\n";
        assert_eq!(
            patch_call_of(patch),
            FileToolCall::Writes {
                tool: "apply_patch".into(),
                paths: vec![
                    "notes/new.md".into(),
                    "src/lib.rs".into(),
                    "src/moved.rs".into(),
                    "/abs/gone.txt".into(),
                ],
            }
        );
        for marker in [
            "*** Add File:",
            "*** Update File:",
            "*** Delete File:",
            "*** Move to:",
        ] {
            // Carriage returns and padding around a marker are the patch
            // tool's to forgive, so they are forgiven here too.
            let patch = format!("*** Begin Patch\r\n  {marker}   a b/c.txt  \r\n*** End Patch\r\n");
            assert_eq!(
                patch_call_of(&patch),
                FileToolCall::Writes {
                    tool: "apply_patch".into(),
                    paths: vec!["a b/c.txt".into()],
                },
                "{marker}"
            );
        }
        // The same text under another field, or handed over bare.
        let patch = "*** Begin Patch\n*** Add File: a.txt\n+x\n*** End Patch";
        for input in [
            json!({"input": patch}),
            json!({"patch": patch}),
            json!(patch),
        ] {
            assert_eq!(
                file_tool_call(&json!({"tool_name": "apply_patch", "tool_input": input})),
                FileToolCall::Writes {
                    tool: "apply_patch".into(),
                    paths: vec!["a.txt".into()],
                }
            );
        }
    }

    /// A patch whose files cannot be read is unreadable, never empty: the
    /// hook refuses an unreadable call in enforce, and an empty list of
    /// paths would have let the patch through unjudged.
    ///
    /// FAILS ON REVERT: return `Writes` with no paths, or `NotAFileTool`,
    /// for any of these and the patch runs unscreened.
    #[test]
    fn a_patch_with_no_readable_path_is_unreadable() {
        assert_eq!(
            patch_call_of("*** Begin Patch\n*** End Patch\n"),
            FileToolCall::Unreadable("a patch that names no file")
        );
        assert_eq!(
            patch_call_of("some text that is not a patch"),
            FileToolCall::Unreadable("a patch that names no file")
        );
        // One marker names nothing: the rest of the list cannot be trusted
        // to be all of it.
        assert_eq!(
            patch_call_of(
                "*** Begin Patch\n*** Update File: a.txt\n*** Add File:   \n+x\n*** End Patch"
            ),
            FileToolCall::Unreadable("a patch that names a file with no path")
        );
        for input in [
            json!({}),
            json!({"command": "  \n"}),
            json!({"command": 7}),
            json!(null),
        ] {
            assert_eq!(
                file_tool_call(&json!({"tool_name": "apply_patch", "tool_input": input})),
                FileToolCall::Unreadable("a patch tool call with no patch text")
            );
        }
        assert_eq!(
            file_tool_call(&json!({"tool_name": "apply_patch"})),
            FileToolCall::Unreadable("a patch tool call with no patch text")
        );
    }

    /// A relative path in a patch is judged from the directory in the
    /// context, as every file tool's path is: `../.zshrc` from a project in
    /// the home is the home's startup file. Only the paths are judged here.
    /// That the hook puts the payload's directory in the context is run in
    /// `crates/cli/tests/hook_file_tools.rs`
    /// (`a_patchs_relative_path_is_judged_from_the_payloads_directory`).
    #[test]
    fn a_patchs_relative_path_is_judged_from_the_calls_directory() {
        let ctx = context(Path::new("/home/dev"), Path::new("/home/dev/proj"));
        let call = patch_call_of(
            "*** Begin Patch\n\
             *** Update File: src/main.rs\n\
             *** Add File: ../.zshrc\n\
             +x\n\
             *** End Patch\n",
        );
        let paths = match call {
            FileToolCall::Writes { paths, .. } => paths,
            other => panic!("the patch names two files: {other:?}"),
        };
        let judged: Vec<Option<&str>> = paths
            .iter()
            .map(|path| privileged_file_write(path, &ctx))
            .collect();
        assert_eq!(
            judged,
            vec![
                None,
                Some("your shell's startup files, which run in every new shell"),
            ]
        );
    }

    /// Codex CLI's hooks file is held in the words of the agent settings
    /// that load the guard, however it is spelled and wherever a `.codex`
    /// folder is, and a file of the same name outside one is the project's.
    ///
    /// FAILS ON REVERT: take `Place::Components(".codex/hooks.json")` out of
    /// `GUARD_SETTINGS` in threats.rs and the hooks file of a `.codex` folder
    /// outside the home is no longer held; drop the `.codex/hooks.json` row
    /// from [`HOME_PLACES`] and `home_place` no longer knows it.
    #[test]
    fn codexs_hooks_file_is_held_like_the_settings_that_load_the_guard() {
        assert_eq!(
            privileged_write_target("/home/dev/.codex/config.toml").map(|target| target.group.what),
            Some(AGENT_HOOK_SETTINGS),
            "the two lists must describe an agent's settings in the same words"
        );
        assert_eq!(
            privileged_write_target("/srv/work/.codex/hooks.json").map(|target| target.group.what),
            Some(AGENT_HOOK_SETTINGS),
            "the list the shell side reads holds the hooks file by name"
        );
        assert_eq!(home_place(".codex/hooks.json"), Some(AGENT_HOOK_SETTINGS));
        let ctx = context(Path::new("/home/dev"), Path::new("/home/dev/proj"));
        for path in [
            "/home/dev/.codex/hooks.json",
            "~/.codex/hooks.json",
            "../.codex/hooks.json",
            "/home/dev/proj/../.codex/./hooks.json",
            "/home/dev/.CODEX/Hooks.json",
        ] {
            assert_eq!(
                privileged_file_write(path, &ctx),
                Some(AGENT_HOOK_SETTINGS),
                "{path}"
            );
        }
        assert_eq!(
            privileged_file_write("/home/dev/proj/hooks.json", &ctx),
            None
        );
        let call =
            patch_call_of("*** Begin Patch\n*** Delete File: ~/.codex/hooks.json\n*** End Patch\n");
        let paths = match call {
            FileToolCall::Writes { paths, .. } => paths,
            other => panic!("the patch names one file: {other:?}"),
        };
        assert_eq!(paths, vec!["~/.codex/hooks.json".to_string()]);
        assert_eq!(
            privileged_file_write(&paths[0], &ctx),
            Some(AGENT_HOOK_SETTINGS)
        );
    }

    /// The file zsh runs before the hook line Codex starts, and Gemini's
    /// record of the folders it trusts, are held in the words of the agent
    /// settings that load the guard, however they are spelled.
    ///
    /// FAILS ON REVERT: take `Place::HomeFile(".zshenv")` out of
    /// `GUARD_SETTINGS` in threats.rs and `~/.zshenv` is held as a shell
    /// startup file only, in those words; take
    /// `Place::Components(".gemini/trustedfolders.json")` out and Gemini's
    /// file is not held at all.
    #[test]
    fn zshenv_and_geminis_trusted_folders_are_held_as_guard_settings() {
        let ctx = context(Path::new("/home/dev"), Path::new("/home/dev/proj"));
        for path in [
            "~/.zshenv",
            "/home/dev/.zshenv",
            "../.zshenv",
            "~/.gemini/trustedFolders.json",
            "/home/dev/.gemini/trustedfolders.json",
            "../.gemini/trustedFolders.json",
        ] {
            assert_eq!(
                privileged_file_write(path, &ctx),
                Some(AGENT_HOOK_SETTINGS),
                "{path}"
            );
        }
        assert_eq!(privileged_file_write("/home/dev/proj/zshenv", &ctx), None);
        // A dotfiles repository's copy is no file zsh reads.
        for path in [
            "/home/dev/dotfiles/.zshenv",
            "~/dotfiles/zsh/.zshenv",
            "roles/zsh/files/.zshenv",
        ] {
            assert_eq!(privileged_file_write(path, &ctx), None, "{path}");
        }
    }

    /// A hard link to Gemini's record of trusted folders, under a name of
    /// its own, is that file.
    ///
    /// FAILS ON REVERT: take `.gemini/trustedFolders.json` out of
    /// `HOME_GUARD_FILES` and the link is a project file.
    #[cfg(unix)]
    #[test]
    fn a_link_to_geminis_trusted_folders_is_that_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let home = dir.path().join("home");
        let proj = home.join("proj");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::create_dir_all(home.join(".gemini")).unwrap();
        std::fs::write(home.join(".gemini/trustedFolders.json"), "{}").unwrap();
        std::fs::hard_link(
            home.join(".gemini/trustedFolders.json"),
            proj.join("folders.json"),
        )
        .unwrap();
        std::fs::write(proj.join("plain.json"), "{}").unwrap();
        let ctx = context(&home, &proj);
        assert_eq!(
            privileged_file_write("folders.json", &ctx),
            Some(AGENT_HOOK_SETTINGS)
        );
        assert_eq!(privileged_file_write("plain.json", &ctx), None);
    }
}
