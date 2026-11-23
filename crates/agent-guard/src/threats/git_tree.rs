//! git commands read on the work tree git itself would use: the one the
//! line names (`--work-tree`, `GIT_WORK_TREE`, `-c core.worktree=`,
//! `--config-env`, `GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>`), else the
//! `core.worktree` of the repository's own config, else the folder that
//! holds its `.git`, found from the folder the command runs in (the agent's
//! working folder, `cd`, `-C`) as git finds it, a repository the line made
//! before (`git init`, `git clone`) counted as found.
//!
//! Measured 2026-11-22 with real git 2.43, each one ran and emptied or reset
//! the guard's folder, or put the default posture in place: `stash -a`,
//! `read-tree -u --reset HEAD` and `checkout-index -a -f` with the guard's
//! folder as the work tree; `git clean -fdx` in a home made a repository by
//! `git init .`, in the same line or before it; an alias of `clean`; a
//! repository whose config points `core.worktree` at the guard's folder;
//! `reset --hard` with the home as the work tree of a clone whose files
//! include the guard's.
//!
//! Where the work tree reaches a place of the guard (is one, is inside one,
//! or holds one: the home or a folder above it), only a verb that leaves the
//! work tree as it is passes (`status`, `log`, `diff`, `show`, `add`,
//! `commit` and the like, [`KEEPS_TREE`]). Every other verb is refused: one
//! that puts back what the repository tracks (`checkout`, `restore`,
//! `reset --hard`, `stash`, `read-tree -u`, `checkout-index`, `rm`,
//! `mv`, `pull`), one that removes what it does not track (`clean`,
//! `stash -u`), and a verb not known here or an alias (from `-c`, from the
//! repository's config or the user's). The one way through is paths that
//! keep the verb out of the guard's places (`checkout -- .bashrc`). What
//! the repository tracks is not read: its index, objects and packs are
//! input an attacker shapes, and reading them in the hook was found to let
//! a line run (a `.git` linked to `/dev/zero`, a pack whose delta grows to
//! gigabytes, each killing the hook).
//!
//! Besides that:
//!
//! * `git config core.worktree <place>` naming a place of the guard or a
//!   folder inside one is refused;
//! * a step of the line that writes a `.git`, a `gitdir` or a
//!   `core.worktree` (a redirection, `ln`, `cp`, `git config
//!   core.worktree`, `git worktree`) leaves the work tree of every git
//!   command after it unknown: a verb that writes is refused;
//! * `push` to a repository on this machine whose work tree reaches a place
//!   of the guard is refused (`receive.denyCurrentBranch=updateInstead`
//!   and the remote's hooks write that work tree).
//!
//! The few files still read (a `.git` file, a repository's config, its
//! `commondir`) are read only when they are regular files, not links, of at
//! most [`READ_BYTES`]; one that cannot be read so leaves the work tree
//! unknown, and a verb that writes is refused.
//!
//! Not read: a folder or a value behind a variable the line does not assign
//! (other than the home), an `include` or `url.<base>.insteadOf` in a
//! repository's config, a repository found more than [`DISCOVERY_DEPTH`]
//! folders up.

use super::{
    collapse_path, effective_command_index, shell_command_segments, shell_tokens, token_basename,
    GIT_GLOBAL_VALUE_OPTIONS, GUARD_FIND_PLACES,
};
use std::path::{Path, PathBuf};

/// What the shell side says of such a line.
pub(super) const GIT_TREE_TAKES_GUARD: &str =
    "runs a git command that writes to a work tree holding the guard's own files \
     (its configuration, the settings that load it, or its program), or points a \
     repository's work tree at them";

/// How many folders a line's git commands are read from (the working folder
/// and each `cd`).
const STARTS: usize = 16;

/// How many repositories a line is read to make.
const CREATED: usize = 16;

/// How many folders up a repository is looked for.
const DISCOVERY_DEPTH: usize = 64;

/// Largest file of a repository read (a `.git` file, a config,
/// `commondir`): larger, it is not read.
const READ_BYTES: u64 = 64 * 1024;

/// Commands that only read the files they name: a `.git` named in one of
/// them, with no redirection, is not written.
const READS_ONLY: &[&str] = &[
    "cat",
    "diff",
    "du",
    "echo",
    "file",
    "grep",
    "head",
    "less",
    "ls",
    "md5sum",
    "more",
    "printf",
    "readlink",
    "realpath",
    "rg",
    "sha1sum",
    "sha256sum",
    "stat",
    "tail",
    "test",
    "tree",
    "wc",
    "[",
];

/// The verbs that leave the work tree as it is: they read it, or write only
/// the index, the references or the objects. A verb read here as writing
/// the tree only through what it is handed (`checkout`, `reset --hard`) is
/// read in [`plan`].
const KEEPS_TREE: &[&str] = &[
    "add",
    "annotate",
    "blame",
    "branch",
    "bundle",
    "cat-file",
    "check-attr",
    "check-ignore",
    "check-mailmap",
    "check-ref-format",
    "cherry",
    "clone",
    "commit",
    "commit-tree",
    "count-objects",
    "describe",
    "diff",
    "diff-files",
    "diff-index",
    "diff-tree",
    "fetch",
    "for-each-ref",
    "fsck",
    "gc",
    "grep",
    "hash-object",
    "help",
    "init",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "merge-base",
    "mktag",
    "mktree",
    "name-rev",
    "notes",
    "prune",
    "push",
    "range-diff",
    "reflog",
    "remote",
    "repack",
    "rev-list",
    "rev-parse",
    "shortlog",
    "show",
    "show-branch",
    "show-ref",
    "status",
    "symbolic-ref",
    "tag",
    "update-index",
    "update-ref",
    "var",
    "verify-commit",
    "verify-pack",
    "verify-tag",
    "version",
    "whatchanged",
    "write-tree",
];

thread_local! {
    /// The folder the command being judged runs in, when the caller knows
    /// it ([`in_command_dir`]).
    static COMMAND_DIR: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `judge` with `dir` as the folder git commands are read from,
/// instead of this process's own: the hook runs where the agent started it,
/// and the agent's command runs in the folder its payload names.
pub(crate) fn in_command_dir<T>(dir: Option<&Path>, judge: impl FnOnce() -> T) -> T {
    struct Restore(Option<PathBuf>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let before = self.0.take();
            COMMAND_DIR.with(|dir| *dir.borrow_mut() = before);
        }
    }
    let dir = dir.filter(|dir| dir.is_absolute()).map(Path::to_path_buf);
    let _restore = Restore(COMMAND_DIR.with(|held| held.replace(dir)));
    judge()
}

/// The folder git commands are read from: the command's, when known, else
/// this process's.
fn command_dir() -> Option<PathBuf> {
    COMMAND_DIR
        .with(|dir| dir.borrow().clone())
        .or_else(|| std::env::current_dir().ok())
}

/// Whether the line runs a git command that writes to a work tree holding
/// the guard's places, or repoints a work tree onto them, read in this
/// process's home and the command's working folder.
pub(super) fn git_takes_guard_place(content: &str) -> bool {
    if !may_take(content) {
        return false;
    }
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from);
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|xdg| !xdg.is_empty())
        .map(PathBuf::from);
    let cwd = command_dir();
    git_takes_guard_place_in(content, home.as_deref(), xdg.as_deref(), cwd.as_deref())
}

/// A cheap test ahead of the reading: the line names git.
fn may_take(content: &str) -> bool {
    content.to_ascii_lowercase().contains("git")
}

/// [`git_takes_guard_place`] with the home, `XDG_CONFIG_HOME` and the
/// working folder given, `GIT_CEILING_DIRECTORIES` read from this
/// process's environment (the agent's, which its commands inherit).
pub(super) fn git_takes_guard_place_in(
    content: &str,
    home: Option<&Path>,
    xdg: Option<&Path>,
    cwd: Option<&Path>,
) -> bool {
    let ceilings = ceiling_directories(std::env::var_os("GIT_CEILING_DIRECTORIES").as_deref());
    git_takes_guard_place_with(content, home, xdg, cwd, &ceilings)
}

/// The folders `GIT_CEILING_DIRECTORIES` names: git does not look for a
/// repository in them or above them (the folder it starts in is still
/// looked at). Entries that are not absolute are left out, as git does.
fn ceiling_directories(value: Option<&std::ffi::OsStr>) -> Vec<PathBuf> {
    let Some(value) = value else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in std::env::split_paths(value).take(STARTS) {
        if !entry.is_absolute() {
            continue;
        }
        let real = std::fs::canonicalize(&entry).ok();
        out.push(entry);
        out.extend(real);
    }
    out
}

/// [`git_takes_guard_place_in`] with the ceiling folders given.
fn git_takes_guard_place_with(
    content: &str,
    home: Option<&Path>,
    xdg: Option<&Path>,
    cwd: Option<&Path>,
    ceilings: &[PathBuf],
) -> bool {
    if !may_take(content) {
        return false;
    }
    let places = guard_places(home, xdg);
    if places.is_empty() {
        return false;
    }
    let mut assigned: Vec<(String, String)> = Vec::new();
    let mut starts: Vec<PathBuf> = cwd.map(Path::to_path_buf).into_iter().collect();
    let mut created: Vec<Repository> = Vec::new();
    // Folders the line makes (`mkdir`): a `cd` into one goes there.
    let mut made_dirs: Vec<PathBuf> = Vec::new();
    // The folders the latest `cd` may have gone to.
    let mut last_cd: Vec<PathBuf> = Vec::new();
    // A step before wrote a `.git`, a `gitdir` or a `core.worktree`.
    let mut tree_unknown = false;
    // A `cd` went to a folder the line does not say: git commands after
    // it run in a folder not known.
    let mut start_unknown = false;
    // The latest `cd` went into a git folder (`cd e/.git`): a step that
    // writes there may rewrite the repository's config.
    let mut inside_git = false;
    let cache = Cache::default();
    for segment in shell_command_segments(content) {
        let segment = mark_empty_words(segment);
        let words: Vec<String> = shell_tokens(&segment).iter().map(|w| unquote(w)).collect();
        for word in &words {
            if let Some((name, value)) = assignment(word) {
                assigned.push((name, value));
            }
        }
        let Some(index) = effective_command_index(&words) else {
            if rewrites_repository(&words, None, &assigned) {
                tree_unknown = true;
            }
            continue;
        };
        let name = token_basename(&words[index]).to_ascii_lowercase();
        let arguments = &words[index + 1..];
        if inside_git
            && !matches!(name.as_str(), "cd" | "pushd" | "popd" | "git")
            && (!super::output_redirect_targets(&words).is_empty()
                || (!READS_ONLY.contains(&name.as_str()) && !arguments.is_empty()))
        {
            tree_unknown = true;
        }
        let line = Line {
            home,
            assigned: &assigned,
            created: &created,
            tree_unknown,
            start_unknown,
            ceilings,
            cache: &cache,
        };
        match name.as_str() {
            "cd" | "pushd" | "popd" => {
                let dir = arguments
                    .iter()
                    .find(|word| !word.starts_with('-') || word.as_str() == "-")
                    .map_or("~", String::as_str);
                let named: Vec<PathBuf> = if name == "popd" || dir == "-" {
                    Vec::new()
                } else {
                    starts
                        .iter()
                        .filter_map(|start| line.resolve(&with_pwd(dir, start), start))
                        .chain(line.resolve(dir, Path::new("/")))
                        .collect()
                };
                if named.is_empty() {
                    start_unknown = true;
                }
                inside_git = named.iter().any(|dir| {
                    dir.components()
                        .any(|part| part.as_os_str().eq_ignore_ascii_case(".git"))
                }) || (named.is_empty() && (inside_git || names_git(dir, &assigned)));
                last_cd.clone_from(&named);
                for dir in named {
                    if starts.len() < STARTS && !starts.contains(&dir) {
                        starts.push(dir);
                    }
                }
            }
            "mkdir" => {
                if let Some(last) = starts.last() {
                    let named: Vec<PathBuf> = arguments
                        .iter()
                        .filter(|word| !word.starts_with('-'))
                        .filter_map(|dir| line.resolve(dir, last))
                        .collect();
                    for dir in named {
                        if made_dirs.len() < STARTS && !made_dirs.contains(&dir) {
                            made_dirs.push(dir);
                        }
                    }
                }
            }
            "git" => {
                if starts
                    .iter()
                    .any(|start| line.git_takes(arguments, start, &places))
                {
                    return true;
                }
                // A repository is made where the latest `cd` went, when
                // that folder is there (or the line made it); a `cd` that
                // may fail leaves every folder before it in doubt.
                let went: Vec<PathBuf> = last_cd
                    .iter()
                    .filter(|dir| dir.is_dir() || made_dirs.contains(dir))
                    .cloned()
                    .collect();
                let from: &[PathBuf] = if last_cd.is_empty() {
                    &starts[..starts.len().min(1)]
                } else if !went.is_empty() {
                    &went
                } else {
                    &starts
                };
                let made: Vec<Repository> = from
                    .iter()
                    .filter_map(|start| line.git_makes(arguments, start))
                    .collect();
                for repository in made {
                    if created.len() < CREATED && !created.contains(&repository) {
                        created.push(repository);
                    }
                }
            }
            _ => {}
        }
        if rewrites_repository(&words, Some(index), &assigned) {
            tree_unknown = true;
        }
    }
    false
}

/// Whether a step of the line writes what tells git where a repository or
/// its work tree is: a `.git` (the folder, a file in it, a `.git` file), a
/// `gitdir` or `core.worktree`. `index` is where the command is in
/// `words`.
fn rewrites_repository(
    words: &[String],
    index: Option<usize>,
    assigned: &[(String, String)],
) -> bool {
    if super::output_redirect_targets(words)
        .iter()
        .any(|target| names_git(target, assigned))
    {
        return true;
    }
    let Some(index) = index else {
        return false;
    };
    let name = token_basename(&words[index]).to_ascii_lowercase();
    let arguments = &words[index + 1..];
    match name.as_str() {
        "cd" | "pushd" | "popd" => false,
        // `git config core.worktree`, and the subcommands that write a
        // `.git` file or a `gitdir` (`worktree add`, `submodule update`).
        "git" => {
            let lower: Vec<String> = arguments
                .iter()
                .map(|word| word.to_ascii_lowercase())
                .collect();
            lower.iter().any(|word| word.contains("core.worktree"))
                || lower.windows(2).any(|pair| match pair[0].as_str() {
                    "worktree" => matches!(pair[1].as_str(), "add" | "move" | "repair"),
                    "submodule" => matches!(
                        pair[1].as_str(),
                        "add" | "update" | "init" | "deinit" | "absorbgitdirs"
                    ),
                    _ => false,
                })
        }
        _ if READS_ONLY.contains(&name.as_str()) => false,
        _ => arguments.iter().any(|word| names_git(word, assigned)),
    }
}

/// Whether `word` names a `.git` (a part of a path, a glob that matches
/// one), or `gitdir` or `core.worktree`, the variables the line
/// assigned read.
fn names_git(word: &str, assigned: &[(String, String)]) -> bool {
    let mut text = word.to_string();
    for _ in 0..4 {
        let Some(at) = text.find('$') else { break };
        let rest = &text[at + 1..];
        let (name, after) = if let Some(braced) = rest.strip_prefix('{') {
            match braced.find('}') {
                Some(end) => (&braced[..end], &braced[end + 1..]),
                None => break,
            }
        } else {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            (&rest[..end], &rest[end..])
        };
        let Some((_, value)) = assigned.iter().rev().find(|(assigned, _)| assigned == name) else {
            break;
        };
        text = format!("{}{value}{after}", &text[..at]);
    }
    let lower = text.to_ascii_lowercase();
    if lower.contains("gitdir") || lower.contains("core.worktree") {
        return true;
    }
    lower
        .split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '/' | '\'' | '"' | '=' | ':' | ',' | '(' | ')' | ';' | '<' | '>' | '|' | '&'
                )
        })
        .any(|part| part == ".git" || (part.starts_with('.') && glob_matches(&part[1..], "git")))
}

/// Whether the shell pattern `pattern` (`*`, `?`, `[...]`) matches
/// `text`. A pattern with none of them is not read as one.
fn glob_matches(pattern: &str, text: &str) -> bool {
    /// One part of a pattern.
    enum Part {
        Any,
        One,
        Set(Vec<char>, bool),
        Char(char),
    }
    if !pattern.contains(['*', '?', '[']) {
        return false;
    }
    let pattern: Vec<char> = pattern.chars().take(64).collect();
    let mut parts: Vec<Part> = Vec::new();
    let mut i = 0usize;
    while i < pattern.len() {
        match pattern[i] {
            // A run of `*` is one `*`.
            '*' => {
                if !matches!(parts.last(), Some(Part::Any)) {
                    parts.push(Part::Any);
                }
                i += 1;
            }
            '?' => {
                parts.push(Part::One);
                i += 1;
            }
            '[' => {
                let Some(end) = pattern[i + 1..].iter().position(|c| *c == ']') else {
                    return false;
                };
                let set = &pattern[i + 1..i + 1 + end];
                let (negated, set) = match set.first() {
                    Some('!' | '^') => (true, &set[1..]),
                    _ => (false, set),
                };
                parts.push(Part::Set(set.to_vec(), negated));
                i += end + 2;
            }
            c => {
                parts.push(Part::Char(c));
                i += 1;
            }
        }
    }
    let in_set = |set: &[char], c: char| {
        let mut j = 0usize;
        while j < set.len() {
            if j + 2 < set.len() && set[j + 1] == '-' {
                if (set[j]..=set[j + 2]).contains(&c) {
                    return true;
                }
                j += 3;
            } else {
                if set[j] == c {
                    return true;
                }
                j += 1;
            }
        }
        false
    };
    // Which prefixes of the text the parts read so far can match: linear
    // in the pattern times the text.
    let text: Vec<char> = text.chars().collect();
    let mut can = vec![false; text.len() + 1];
    can[0] = true;
    for part in &parts {
        let mut next = vec![false; text.len() + 1];
        match part {
            Part::Any => {
                let mut seen = false;
                for (n, cell) in next.iter_mut().enumerate() {
                    seen |= can[n];
                    *cell = seen;
                }
            }
            _ => {
                for n in 0..text.len() {
                    if !can[n] {
                        continue;
                    }
                    let c = text[n];
                    next[n + 1] = match part {
                        Part::One => true,
                        Part::Set(set, negated) => in_set(set, c) != *negated,
                        Part::Char(want) => *want == c,
                        Part::Any => unreachable!(),
                    };
                }
            }
        }
        can = next;
    }
    can[text.len()]
}

/// The guard's places, written out from the home: its folders, the agent
/// settings that load it and its program ([`GUARD_FIND_PLACES`]), and its
/// folder under `XDG_CONFIG_HOME`.
fn guard_places(home: Option<&Path>, xdg: Option<&Path>) -> Vec<String> {
    let mut places = Vec::new();
    for (place, _) in GUARD_FIND_PLACES {
        let path = match place.strip_prefix("~/") {
            Some(rest) => match home {
                Some(home) => home.join(rest),
                None => continue,
            },
            None => PathBuf::from(place),
        };
        push_spellings(&mut places, &path);
    }
    if let Some(xdg) = xdg {
        push_spellings(&mut places, &xdg.join("innerwarden"));
    }
    places
}

/// `path` as written and with its links resolved, lowercase.
fn push_spellings(out: &mut Vec<String>, path: &Path) {
    for spelled in spellings(path) {
        if !out.contains(&spelled) {
            out.push(spelled);
        }
    }
}

fn spellings(path: &Path) -> Vec<String> {
    let written = collapse_path(&path.to_string_lossy()).to_lowercase();
    let mut out = vec![written];
    if let Ok(real) = std::fs::canonicalize(path) {
        let real = collapse_path(&real.to_string_lossy()).to_lowercase();
        if !out.contains(&real) {
            out.push(real);
        }
    }
    out
}

/// Whether `inner` is `outer` or below it, by whole parts.
fn is_within(inner: &str, outer: &str) -> bool {
    let outer = outer.trim_end_matches('/');
    inner == outer
        || outer.is_empty()
        || inner
            .strip_prefix(outer)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Whether `path` is a place of the guard, inside one, or holds one.
fn reaches(path: &Path, places: &[String]) -> bool {
    spellings(path).iter().any(|path| {
        places
            .iter()
            .any(|place| is_within(path, place) || is_within(place, path))
    })
}

/// A word without its quotes.
fn unquote(word: &str) -> String {
    word.chars().filter(|c| !matches!(c, '"' | '\'')).collect()
}

/// `NAME=value`, as a shell assigns it.
fn assignment(word: &str) -> Option<(String, String)> {
    let (name, value) = word.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    ((first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_'))
    .then(|| (name.to_string(), value.to_string()))
}

/// A repository: its git folder and the folder that holds it.
#[derive(Clone, PartialEq, Eq)]
struct Repository {
    git_dir: PathBuf,
    top: PathBuf,
}

/// What a git verb does to the work tree.
enum Plan {
    /// Leaves it as it is.
    Keeps,
    /// Removes what is not tracked, below the paths when it is handed some.
    Untracked(Vec<String>),
    /// Puts in place what the repository tracks, below the paths when it
    /// is handed some.
    Tracked(Vec<String>),
    /// Writes to it in a way not read here.
    Writes,
    /// Writes what the index tracks below another folder
    /// (`checkout-index --prefix`).
    WritesBelow(String),
    /// Points the repository's work tree at a folder (`config core.worktree`).
    Points(String),
}

/// Words of a git verb's arguments: the operands before `--` (the values of
/// `valued` options left out, a lone `-` kept) and the words after it.
fn operands<'w>(rest: &'w [String], valued: &[&str]) -> (Vec<&'w str>, Option<Vec<&'w str>>) {
    let mut before = Vec::new();
    let mut at = 0usize;
    while let Some(word) = rest.get(at) {
        if word == "--" {
            let after = rest[at + 1..].iter().map(String::as_str).collect();
            return (before, Some(after));
        }
        if valued.contains(&word.as_str()) {
            at += 2;
            continue;
        }
        if word == "-" || !word.starts_with('-') {
            before.push(word.as_str());
        }
        at += 1;
    }
    (before, None)
}

/// The value of option `names` (`--source X`, `--source=X`, `-sX` not read).
fn option_value<'w>(rest: &'w [String], names: &[&str]) -> Option<&'w str> {
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        if word == "--" {
            return None;
        }
        if names.contains(&word.as_str()) {
            return words.next().map(String::as_str);
        }
        for name in names.iter().filter(|name| name.starts_with("--")) {
            if let Some(value) = word.strip_prefix(&format!("{name}=")) {
                return Some(value);
            }
        }
    }
    None
}

/// What `git <verb> <rest>` does to the work tree, run in `folder`.
fn plan(verb: &str, rest: &[String], folder: &Path, line: &Line<'_>) -> Plan {
    let before_dashes = rest
        .iter()
        .position(|word| word == "--")
        .map_or(rest, |at| &rest[..at]);
    let has = |names: &[&str]| {
        before_dashes
            .iter()
            .any(|word| names.contains(&word.as_str()))
    };
    let short_has = |letters: &[char]| {
        before_dashes
            .iter()
            .any(|word| word.starts_with('-') && !word.starts_with("--") && word.contains(letters))
    };
    let has_prefix = |prefix: &str| before_dashes.iter().any(|word| word.starts_with(prefix));
    let both = |(before, after): (Vec<&str>, Option<Vec<&str>>)| -> Vec<String> {
        before
            .into_iter()
            .chain(after.unwrap_or_default())
            .map(str::to_string)
            .collect()
    };
    // Paths read from a file or from the input are not known: a path that
    // resolves nowhere keeps the verb whole.
    let unknown_paths = has_prefix("--pathspec-from-file") || has(&["--stdin"]);
    let with_unknown = |mut paths: Vec<String>| {
        if unknown_paths {
            paths.push("$UNKNOWN".to_string());
        }
        paths
    };
    match verb {
        "config" => {
            // `git config [set] core.worktree <value>`.
            let mut words = rest.iter().filter(|word| !word.starts_with('-'));
            while let Some(word) = words.next() {
                if word.eq_ignore_ascii_case("core.worktree") {
                    return match words.next() {
                        Some(value) => Plan::Points(value.clone()),
                        None => Plan::Keeps,
                    };
                }
            }
            Plan::Keeps
        }
        "clean" => {
            if has(&["--dry-run"]) || short_has(&['n']) {
                return Plan::Keeps;
            }
            Plan::Untracked(with_unknown(both(operands(rest, &["-e", "--exclude"]))))
        }
        "stash" => {
            let (words, after) = operands(rest, &["-m", "--message"]);
            let sub = words.first().copied();
            match sub {
                Some("list" | "show" | "create" | "store" | "drop" | "clear") => Plan::Keeps,
                Some("pop" | "apply" | "branch") => Plan::Tracked(Vec::new()),
                None | Some("push" | "save") => {
                    let mut paths: Vec<String> = after
                        .unwrap_or_default()
                        .into_iter()
                        .map(str::to_string)
                        .collect();
                    if sub == Some("push") {
                        paths.extend(words.iter().skip(1).map(|word| word.to_string()));
                    }
                    let paths = with_unknown(paths);
                    if has(&["--include-untracked", "--all"]) || short_has(&['u', 'a']) {
                        Plan::Untracked(paths)
                    } else {
                        Plan::Tracked(paths)
                    }
                }
                Some(_) => Plan::Writes,
            }
        }
        "read-tree" => {
            if !(has(&["-u"]) || short_has(&['u'])) {
                return Plan::Keeps;
            }
            if has_prefix("--prefix") {
                return Plan::Writes;
            }
            Plan::Tracked(Vec::new())
        }
        "checkout-index" => {
            if let Some(prefix) = option_value(rest, &["--prefix"]) {
                return Plan::WritesBelow(prefix.to_string());
            }
            let paths = if has(&["-a", "--all"]) {
                Vec::new()
            } else {
                with_unknown(both(operands(rest, &[])))
            };
            Plan::Tracked(paths)
        }
        "checkout" => {
            let new_branch = has(&["-b", "-B", "--orphan"]) || has_prefix("--orphan=");
            let (before, after) = operands(rest, &["-b", "-B", "--orphan"]);
            if let Some(after) = after {
                let paths = after.into_iter().map(str::to_string).collect();
                return Plan::Tracked(with_unknown(paths));
            }
            let Some(first) = before.first() else {
                // With nothing named and nothing forced, checkout moves no
                // file (`git checkout`, `checkout -b <new>`).
                if !unknown_paths
                    && !has(&["-f", "--force", "-m", "--merge"])
                    && !short_has(&['f', 'm'])
                {
                    return Plan::Keeps;
                }
                return Plan::Tracked(with_unknown(Vec::new()));
            };
            // Without `--`, git reads a name that can be a branch as one,
            // even when a file or a folder has that name too.
            let is_path = !new_branch
                && !could_be_branch(first)
                && line
                    .resolve(first, folder)
                    .is_some_and(|path| path.symlink_metadata().is_ok());
            if is_path {
                let paths = before.iter().map(|word| word.to_string()).collect();
                return Plan::Tracked(with_unknown(paths));
            }
            let paths = before[1..].iter().map(|word| word.to_string()).collect();
            Plan::Tracked(with_unknown(paths))
        }
        "switch" => {
            // `switch -c <new>` with no start point moves no file, as
            // `checkout -b <new>`; `--orphan` empties the tree.
            let creates = has(&["-c", "-C", "--create", "--force-create"])
                || has_prefix("--create=")
                || has_prefix("--force-create=");
            let (before, _) = operands(
                rest,
                &["-c", "-C", "--create", "--force-create", "--orphan"],
            );
            if creates
                && before.is_empty()
                && !has(&[
                    "-f",
                    "--force",
                    "--discard-changes",
                    "-m",
                    "--merge",
                    "--orphan",
                ])
                && !has_prefix("--orphan=")
                && !short_has(&['f', 'm'])
            {
                return Plan::Keeps;
            }
            Plan::Tracked(Vec::new())
        }
        "restore" => {
            let staged = has(&["--staged", "-S"]);
            let worktree = has(&["--worktree", "-W"]);
            if staged && !worktree {
                return Plan::Keeps;
            }
            let paths = both(operands(rest, &["-s", "--source"]));
            Plan::Tracked(with_unknown(paths))
        }
        "reset" => {
            if !has(&["--hard", "--merge", "--keep"]) {
                return Plan::Keeps;
            }
            Plan::Tracked(Vec::new())
        }
        "rm" => {
            if has(&["--cached", "--dry-run"]) || short_has(&['n']) {
                return Plan::Keeps;
            }
            Plan::Tracked(with_unknown(both(operands(rest, &[]))))
        }
        "mv" => {
            if has(&["--dry-run"]) || short_has(&['n']) {
                return Plan::Keeps;
            }
            Plan::Tracked(with_unknown(both(operands(rest, &[]))))
        }
        "pull" => Plan::Tracked(Vec::new()),
        _ if KEEPS_TREE.contains(&verb) => Plan::Keeps,
        _ => Plan::Writes,
    }
}

/// Whether `name` can name a branch (`git check-ref-format`): a word
/// that cannot (`.bashrc`, `a..b`, `x.lock`) is read only as a path.
fn could_be_branch(name: &str) -> bool {
    !name.is_empty()
        && name != "@"
        && !name.starts_with('-')
        && !name.ends_with('/')
        && !name.ends_with('.')
        && !name.contains("..")
        && !name.contains("@{")
        && !name
            .chars()
            .any(|c| c.is_control() || matches!(c, ' ' | '~' | '^' | ':' | '?' | '*' | '[' | '\\'))
        && name
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}

/// The long options of the verbs [`plan`] reads, and their short options
/// that take a value: git takes a long option shortened to a prefix only
/// it starts (`--har` is `--hard`), and a value glued to a short one or
/// a short one inside a group (`-bx`, `-fb x`).
fn verb_options(verb: &str) -> (&'static [&'static str], &'static [char]) {
    match verb {
        "reset" => (
            &[
                "--quiet",
                "--no-quiet",
                "--refresh",
                "--no-refresh",
                "--mixed",
                "--soft",
                "--hard",
                "--merge",
                "--keep",
                "--recurse-submodules",
                "--no-recurse-submodules",
                "--patch",
                "--intent-to-add",
                "--pathspec-from-file",
                "--pathspec-file-nul",
            ],
            &[],
        ),
        "checkout" => (
            &[
                "--quiet",
                "--progress",
                "--no-progress",
                "--force",
                "--merge",
                "--conflict",
                "--detach",
                "--track",
                "--no-track",
                "--guess",
                "--no-guess",
                "--orphan",
                "--ignore-skip-worktree-bits",
                "--ignore-other-worktrees",
                "--ours",
                "--theirs",
                "--patch",
                "--recurse-submodules",
                "--no-recurse-submodules",
                "--overlay",
                "--no-overlay",
                "--pathspec-from-file",
                "--pathspec-file-nul",
            ],
            &['b', 'B'],
        ),
        "switch" => (
            &[
                "--create",
                "--force-create",
                "--guess",
                "--no-guess",
                "--discard-changes",
                "--detach",
                "--track",
                "--no-track",
                "--merge",
                "--conflict",
                "--quiet",
                "--progress",
                "--no-progress",
                "--force",
                "--orphan",
                "--ignore-other-worktrees",
                "--recurse-submodules",
                "--no-recurse-submodules",
            ],
            &['c', 'C'],
        ),
        "restore" => (
            &[
                "--source",
                "--patch",
                "--worktree",
                "--staged",
                "--quiet",
                "--progress",
                "--no-progress",
                "--ours",
                "--theirs",
                "--merge",
                "--conflict",
                "--ignore-unmerged",
                "--ignore-skip-worktree-bits",
                "--recurse-submodules",
                "--no-recurse-submodules",
                "--overlay",
                "--no-overlay",
                "--pathspec-from-file",
                "--pathspec-file-nul",
            ],
            &['s'],
        ),
        "clean" => (
            &[
                "--quiet",
                "--dry-run",
                "--force",
                "--interactive",
                "--exclude",
            ],
            &['e'],
        ),
        "stash" => (
            &[
                "--patch",
                "--staged",
                "--keep-index",
                "--no-keep-index",
                "--include-untracked",
                "--only-untracked",
                "--all",
                "--quiet",
                "--message",
                "--pathspec-from-file",
                "--pathspec-file-nul",
                "--index",
            ],
            &['m'],
        ),
        "rm" => (
            &[
                "--cached",
                "--dry-run",
                "--force",
                "--ignore-unmatch",
                "--quiet",
                "--sparse",
                "--pathspec-from-file",
                "--pathspec-file-nul",
            ],
            &[],
        ),
        "mv" => (&["--dry-run", "--force", "--verbose", "--sparse"], &[]),
        "read-tree" => (
            &[
                "--index-output",
                "--empty",
                "--verbose",
                "--trivial",
                "--aggressive",
                "--reset",
                "--prefix",
                "--exclude-per-directory",
                "--no-sparse-checkout",
                "--recurse-submodules",
                "--no-recurse-submodules",
                "--dry-run",
                "--quiet",
            ],
            &[],
        ),
        "checkout-index" => (
            &[
                "--all",
                "--force",
                "--quiet",
                "--no-create",
                "--index",
                "--stdin",
                "--temp",
                "--prefix",
                "--stage",
                "--ignore-skip-worktree-bits",
            ],
            &[],
        ),
        _ => (&[], &[]),
    }
}

/// `rest` with its options written as git reads them ([`verb_options`]):
/// a long option shortened to a prefix only it starts written out whole,
/// a group of short options split, a value glued to a short option that
/// takes one put in its own word. Words after `--` are kept as they are.
fn normalize_options(verb: &str, rest: &[String]) -> Vec<String> {
    let (long, valued) = verb_options(verb);
    let mut out = Vec::with_capacity(rest.len());
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        if word == "--" {
            out.push(word.clone());
            out.extend(words.by_ref().cloned());
            break;
        }
        if let Some(body) = word.strip_prefix("--") {
            let (name, value) = match body.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (body, None),
            };
            let written = format!("--{name}");
            if !name.is_empty() && !long.contains(&written.as_str()) {
                let mut starts = long.iter().filter(|option| option.starts_with(&written));
                if let (Some(only), None) = (starts.next(), starts.next()) {
                    out.push(match value {
                        Some(value) => format!("{only}={value}"),
                        None => (*only).to_string(),
                    });
                    continue;
                }
            }
            out.push(word.clone());
            continue;
        }
        let Some(group) = word.strip_prefix('-') else {
            out.push(word.clone());
            continue;
        };
        if group.chars().count() < 2 || long.is_empty() {
            out.push(word.clone());
            continue;
        }
        for (at, letter) in group.char_indices() {
            out.push(format!("-{letter}"));
            if valued.contains(&letter) {
                let glued = &group[at + letter.len_utf8()..];
                if !glued.is_empty() {
                    out.push(glued.to_string());
                }
                break;
            }
        }
    }
    out
}

/// What the line has said so far: the home, the variables it assigned,
/// the repositories it made, and whether a step before rewrote where a
/// repository or its work tree is ([`rewrites_repository`]).
struct Line<'a> {
    home: Option<&'a Path>,
    assigned: &'a [(String, String)],
    created: &'a [Repository],
    tree_unknown: bool,
    /// A `cd` before went to a folder not known.
    start_unknown: bool,
    /// `GIT_CEILING_DIRECTORIES`.
    ceilings: &'a [PathBuf],
    cache: &'a Cache,
}

/// A git command as judged: its words, the folder it starts in, whether a
/// step before rewrote the repository or went to a folder not known, and
/// how many repositories the line made before it.
type JudgedKey = (Vec<String>, PathBuf, [bool; 2], usize);

/// What a line has read already, kept for the rest of the line: each
/// folder, file and command is read once, so a line of thousands of git
/// commands costs what its distinct ones cost.
#[derive(Default)]
struct Cache {
    repositories:
        std::cell::RefCell<std::collections::HashMap<PathBuf, Result<Option<Repository>, Unread>>>,
    trees: std::cell::RefCell<std::collections::HashMap<PathBuf, Result<Option<String>, Unread>>>,
    reached: std::cell::RefCell<std::collections::HashMap<PathBuf, bool>>,
    judged: std::cell::RefCell<std::collections::HashMap<JudgedKey, bool>>,
}

/// `segment` with each empty quoted word (`""`, `''`) written as a
/// variable no line assigns: the words of a line drop an empty word, and
/// `git -C "" reset --hard` would read as `git -C reset --hard`.
fn mark_empty_words(segment: &str) -> std::borrow::Cow<'_, str> {
    if !segment.contains("\"\"") && !segment.contains("''") {
        return std::borrow::Cow::Borrowed(segment);
    }
    let chars: Vec<char> = segment.chars().collect();
    let mut out = String::with_capacity(segment.len());
    let mut at = 0usize;
    let mut quote: Option<char> = None;
    while at < chars.len() {
        let c = chars[at];
        let alone = |before: Option<&char>, after: Option<&char>| {
            before.is_none_or(|c| c.is_whitespace()) && after.is_none_or(|c| c.is_whitespace())
        };
        if quote.is_none()
            && matches!(c, '"' | '\'')
            && chars.get(at + 1) == Some(&c)
            && alone(
                at.checked_sub(1).and_then(|b| chars.get(b)),
                chars.get(at + 2),
            )
        {
            out.push_str("$IW_EMPTY_WORD");
            at += 2;
            continue;
        }
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(open), _) if open == c => quote = None,
            (None, '\\') => {
                out.push(c);
                at += 1;
                if let Some(next) = chars.get(at) {
                    out.push(*next);
                }
                at += 1;
                continue;
            }
            _ => {}
        }
        out.push(c);
        at += 1;
    }
    std::borrow::Cow::Owned(out)
}

/// `text` with the shell's working folder (`$PWD`, `$(pwd)`) written
/// out as `start`, the folder the shell is in.
fn with_pwd(text: &str, start: &Path) -> String {
    if !text.contains("PWD") && !text.contains("pwd") {
        return text.to_string();
    }
    let start = start.to_string_lossy();
    text.replace("$(pwd)", &start)
        .replace("`pwd`", &start)
        .replace("${PWD}", &start)
        .replace("$PWD", &start)
}

/// A git command's global options, read.
struct Invocation {
    /// The folder it runs in (`-C`).
    folder: PathBuf,
    /// A `-C` named a folder not known (`-C "$DIR"`, `-C ""`).
    folder_unknown: bool,
    git_dir_text: Option<String>,
    tree_text: Option<String>,
    /// `core.worktree` set for this command only.
    set_tree: Option<String>,
    /// Where the verb is in the arguments.
    verb_at: usize,
}

impl Line<'_> {
    /// Whether `dir` is a folder of `GIT_CEILING_DIRECTORIES`.
    fn is_ceiling(&self, dir: &Path) -> bool {
        !self.ceilings.is_empty()
            && (self.ceilings.iter().any(|ceiling| ceiling == dir)
                || std::fs::canonicalize(dir).is_ok_and(|real| self.ceilings.contains(&real)))
    }

    /// [`reaches`], read once per path for the line.
    fn reaches(&self, path: &Path, places: &[String]) -> bool {
        if let Some(known) = self.cache.reached.borrow().get(path) {
            return *known;
        }
        let reached = reaches(path, places);
        self.cache
            .reached
            .borrow_mut()
            .insert(path.to_path_buf(), reached);
        reached
    }

    /// [`repository_at`], read once per folder for the line.
    fn repository_at(&self, dir: &Path) -> Result<Option<Repository>, Unread> {
        if let Some(known) = self.cache.repositories.borrow().get(dir) {
            return known.clone();
        }
        let found = repository_at(dir);
        self.cache
            .repositories
            .borrow_mut()
            .insert(dir.to_path_buf(), found.clone());
        found
    }

    /// [`core_worktree`], read once per repository for the line.
    fn core_worktree(&self, git_dir: &Path) -> Result<Option<String>, Unread> {
        if let Some(known) = self.cache.trees.borrow().get(git_dir) {
            return known.clone();
        }
        let tree = core_worktree(git_dir);
        self.cache
            .trees
            .borrow_mut()
            .insert(git_dir.to_path_buf(), tree.clone());
        tree
    }

    fn variable(&self, name: &str) -> Option<String> {
        self.assigned
            .iter()
            .rev()
            .find(|(assigned, _)| assigned == name)
            .map(|(_, value)| value.clone())
    }

    /// `text` as a path, read in `base`: `~` and `$HOME` are the home, a
    /// variable the line assigned is its value. `None` when a part of it
    /// is not known.
    fn resolve(&self, text: &str, base: &Path) -> Option<PathBuf> {
        let mut text = unquote(text);
        for _ in 0..4 {
            let Some(at) = text.find('$') else { break };
            let rest = &text[at + 1..];
            let (name, after) = if let Some(braced) = rest.strip_prefix('{') {
                let end = braced.find('}')?;
                (&braced[..end], &braced[end + 1..])
            } else {
                let end = rest
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(rest.len());
                (&rest[..end], &rest[end..])
            };
            let value = match self.variable(name) {
                Some(value) => value,
                None if name == "HOME" => self.home?.to_string_lossy().into_owned(),
                None => return None,
            };
            text = format!("{}{value}{after}", &text[..at]);
        }
        if text.contains(['$', '`']) || text.is_empty() {
            return None;
        }
        if text == "~" || text.starts_with("~/") {
            text = format!("{}{}", self.home?.to_string_lossy(), &text[1..]);
        }
        let path = if text.starts_with('/') {
            PathBuf::from(text)
        } else {
            base.join(text)
        };
        Some(PathBuf::from(collapse_path(&path.to_string_lossy())))
    }

    /// The global options of `git <arguments>` run in `start`.
    fn invocation(&self, arguments: &[String], start: &Path) -> Invocation {
        let mut folder = start.to_path_buf();
        let mut folder_unknown = false;
        let mut git_dir_text = self.variable("GIT_DIR");
        let mut tree_text = self.variable("GIT_WORK_TREE");
        // `core.worktree` set for this command only, read in the
        // repository's folder as git reads it.
        let mut set_tree: Option<String> = None;
        for pair in 0..64usize {
            let Some(key) = self.variable(&format!("GIT_CONFIG_KEY_{pair}")) else {
                break;
            };
            if key.eq_ignore_ascii_case("core.worktree") {
                set_tree = self.variable(&format!("GIT_CONFIG_VALUE_{pair}"));
            }
        }
        let setting = |value: &str, set_tree: &mut Option<String>, by_env: bool| {
            let Some((key, value)) = value.split_once('=') else {
                return;
            };
            if !key.trim().eq_ignore_ascii_case("core.worktree") {
                return;
            }
            *set_tree = if by_env {
                self.variable(value)
            } else {
                Some(value.to_string())
            };
        };
        let mut at = 0usize;
        while let Some(word) = arguments.get(at) {
            let next = arguments.get(at + 1).map(String::as_str);
            match word.as_str() {
                "-C" => {
                    if let Some(value) = next {
                        match self.resolve(&with_pwd(value, start), &folder) {
                            Some(named) => folder = named,
                            None => folder_unknown = true,
                        }
                    }
                    at += 2;
                    continue;
                }
                "--git-dir" => {
                    git_dir_text = next.map(str::to_string);
                    at += 2;
                    continue;
                }
                "--work-tree" => {
                    tree_text = next.map(str::to_string);
                    at += 2;
                    continue;
                }
                "-c" => {
                    if let Some(value) = next {
                        setting(value, &mut set_tree, false);
                    }
                    at += 2;
                    continue;
                }
                "--config-env" => {
                    if let Some(value) = next {
                        setting(value, &mut set_tree, true);
                    }
                    at += 2;
                    continue;
                }
                _ => {}
            }
            if let Some(value) = word.strip_prefix("--git-dir=") {
                git_dir_text = Some(value.to_string());
            } else if let Some(value) = word.strip_prefix("--work-tree=") {
                tree_text = Some(value.to_string());
            } else if let Some(value) = word.strip_prefix("--config-env=") {
                setting(value, &mut set_tree, true);
            } else if GIT_GLOBAL_VALUE_OPTIONS.contains(&word.as_str()) {
                at += 2;
                continue;
            } else if !word.starts_with('-') {
                break;
            }
            at += 1;
        }
        Invocation {
            folder,
            folder_unknown,
            git_dir_text,
            tree_text,
            set_tree,
            verb_at: at,
        }
    }

    /// The repository `git <arguments>` makes, run in `start`: `git init`
    /// or `git clone` with a work tree.
    fn git_makes(&self, arguments: &[String], start: &Path) -> Option<Repository> {
        let invocation = self.invocation(arguments, start);
        if invocation.folder_unknown {
            return None;
        }
        let verb = arguments.get(invocation.verb_at)?.to_ascii_lowercase();
        let rest = &arguments[invocation.verb_at + 1..];
        if rest
            .iter()
            .any(|word| matches!(word.as_str(), "--bare" | "--mirror"))
        {
            return None;
        }
        let folder = &invocation.folder;
        let top = match verb.as_str() {
            "init" => {
                let (named, _) = operands(
                    rest,
                    &[
                        "--template",
                        "--separate-git-dir",
                        "-b",
                        "--initial-branch",
                        "--object-format",
                        "--ref-format",
                        "--shared",
                    ],
                );
                match named.first() {
                    Some(dir) => self.resolve(dir, folder)?,
                    None => folder.clone(),
                }
            }
            "clone" => {
                let (named, after) = operands(
                    rest,
                    &[
                        "-b",
                        "--branch",
                        "-o",
                        "--origin",
                        "-c",
                        "--config",
                        "--depth",
                        "-u",
                        "--upload-pack",
                        "--reference",
                        "--reference-if-able",
                        "--separate-git-dir",
                        "-j",
                        "--jobs",
                        "--filter",
                        "--template",
                        "--shallow-since",
                        "--shallow-exclude",
                        "--server-option",
                        "--bundle-uri",
                        "--ref-format",
                    ],
                );
                let named: Vec<&str> = named.into_iter().chain(after.unwrap_or_default()).collect();
                match named.as_slice() {
                    [_, dir, ..] => self.resolve(dir, folder)?,
                    [url] => {
                        let url = url.trim_end_matches('/');
                        let url = url.strip_suffix("/.git").unwrap_or(url);
                        let name = url.rsplit(['/', ':']).next()?;
                        let name = name.strip_suffix(".git").unwrap_or(name);
                        if name.is_empty() {
                            return None;
                        }
                        folder.join(name)
                    }
                    [] => return None,
                }
            }
            _ => return None,
        };
        Some(Repository {
            git_dir: top.join(".git"),
            top,
        })
    }

    /// Whether `git <arguments>`, run in `start`, writes to a work tree
    /// that holds a place of `places`, or points one at them.
    fn git_takes(&self, arguments: &[String], start: &Path, places: &[String]) -> bool {
        let key = (
            arguments.to_vec(),
            start.to_path_buf(),
            [self.tree_unknown, self.start_unknown],
            self.created.len(),
        );
        if let Some(known) = self.cache.judged.borrow().get(&key) {
            return *known;
        }
        let takes = self.git_takes_once(arguments, start, places);
        self.cache.judged.borrow_mut().insert(key, takes);
        takes
    }

    fn git_takes_once(&self, arguments: &[String], start: &Path, places: &[String]) -> bool {
        let invocation = self.invocation(arguments, start);
        let Some(verb) = arguments.get(invocation.verb_at) else {
            return false;
        };
        let verb = verb.to_ascii_lowercase();
        let rest = &arguments[invocation.verb_at + 1..];
        let folder = &invocation.folder;
        let normalized = normalize_options(&verb, rest);
        let plan = plan(&verb, &normalized, folder, self);
        if matches!(plan, Plan::Keeps) {
            return verb == "push"
                && !invocation.folder_unknown
                && self.pushes_to_guard(rest, &invocation, places);
        }
        // Where the repository and its work tree are was rewritten earlier
        // in the line, or the folder git runs in is not known (a `cd` or a
        // `-C` the line does not say): not known here.
        if self.tree_unknown || self.start_unknown || invocation.folder_unknown {
            return true;
        }

        // The repository: named, made before in the line, or found from the
        // folder up.
        let named_git_dir = invocation
            .git_dir_text
            .as_deref()
            .and_then(|text| self.resolve(text, folder));
        // A repository named by a text not known (`--git-dir="$(...)"`):
        // its work tree is not known either.
        if invocation.git_dir_text.is_some()
            && named_git_dir.is_none()
            && !matches!(plan, Plan::Points(_))
        {
            return true;
        }
        let found = if invocation.git_dir_text.is_none() {
            match self.discover(folder) {
                Ok(found) => found,
                Err(Unread) => return true,
            }
        } else {
            None
        };
        let git_dir = named_git_dir
            .clone()
            .or_else(|| found.as_ref().map(|repository| repository.git_dir.clone()));
        let made = git_dir.as_ref().is_some_and(|git_dir| {
            self.created
                .iter()
                .any(|repository| &repository.git_dir == git_dir)
        });
        // A repository git cannot find: the command fails.
        if !made && !git_dir.as_ref().is_some_and(|git_dir| git_dir.exists()) {
            return invocation.git_dir_text.is_some()
                && named_git_dir.is_none()
                && invocation
                    .tree_text
                    .as_deref()
                    .and_then(|text| self.resolve(text, folder))
                    .is_some_and(|tree| self.reaches(&tree, places))
                && !matches!(plan, Plan::Points(_));
        }
        let config_tree = match git_dir
            .as_deref()
            .map(|git_dir| self.core_worktree(git_dir))
        {
            Some(Err(Unread)) => return true,
            Some(Ok(tree)) => tree,
            None => None,
        };
        // `core.worktree`, relative, is read in the repository's folder.
        let tree = if let Some(text) = &invocation.tree_text {
            self.resolve(text, folder)
        } else if let Some(text) = invocation.set_tree.as_deref().or(config_tree.as_deref()) {
            self.resolve(text, git_dir.as_deref().unwrap_or(folder))
        } else if named_git_dir.is_some() {
            Some(folder.clone())
        } else {
            found.map(|repository| repository.top)
        };
        let Some(tree) = tree else {
            // A work tree not known: a verb that writes is held to it.
            return !matches!(plan, Plan::Points(_));
        };

        // Paths are read in the folder git runs in, or from the top of the
        // work tree when that folder is outside it, as git reads them.
        let paths_base = if folder.starts_with(&tree) {
            folder.clone()
        } else {
            tree.clone()
        };
        let resolve_path = |word: &str| -> Option<PathBuf> {
            if word.contains(['*', '?', '[']) {
                return None;
            }
            if let Some(rest) = word.strip_prefix(":/") {
                return self.resolve(rest, &tree);
            }
            if word.starts_with(':') {
                return None;
            }
            self.resolve(word, &paths_base)
        };
        // Paths that keep the verb out of every place of the guard.
        let kept_out = |paths: &[String]| {
            !paths.is_empty()
                && paths
                    .iter()
                    .all(|word| resolve_path(word).is_some_and(|path| !self.reaches(&path, places)))
        };
        match plan {
            Plan::Keeps => false,
            Plan::Points(value) => {
                let base = git_dir.as_deref().unwrap_or(folder);
                self.resolve(&value, base).is_some_and(|path| {
                    spellings(&path)
                        .iter()
                        .any(|path| places.iter().any(|place| is_within(path, place)))
                })
            }
            Plan::Writes => self.reaches(&tree, places),
            Plan::WritesBelow(prefix) => match self.resolve(&prefix, folder) {
                Some(below) => self.reaches(&below, places),
                None => true,
            },
            Plan::Untracked(paths) => {
                // Run below its top, clean reaches the folder it runs in.
                let scope = if verb == "clean" {
                    paths_base.clone()
                } else {
                    tree.clone()
                };
                self.reaches(&scope, places) && !kept_out(&paths)
            }
            Plan::Tracked(paths) => self.reaches(&tree, places) && !kept_out(&paths),
        }
    }

    /// The repository git finds from `folder` up, a repository the line
    /// made counted. `Err` when a `.git` on the way cannot be read.
    fn discover(&self, folder: &Path) -> Result<Option<Repository>, Unread> {
        for dir in folder.ancestors().take(DISCOVERY_DEPTH) {
            // `GIT_CEILING_DIRECTORIES`: git goes no higher.
            if dir != folder && self.is_ceiling(dir) {
                break;
            }
            if let Some(made) = self.created.iter().find(|made| made.top == dir) {
                return Ok(Some(made.clone()));
            }
            if let Some(repository) = self.repository_at(dir)? {
                return Ok(Some(repository));
            }
        }
        Ok(None)
    }

    /// Whether `git push <rest>` sends to a repository on this machine
    /// whose work tree reaches a place of the guard: the remote's
    /// `receive.denyCurrentBranch=updateInstead` or its hooks write that
    /// work tree. A remote the line names that the repository's config does
    /// not hold is read as a path, as git reads it; with none named, every
    /// remote of the config is read.
    fn pushes_to_guard(&self, rest: &[String], invocation: &Invocation, places: &[String]) -> bool {
        let folder = &invocation.folder;
        let (named, _) = operands(
            rest,
            &["--repo", "-o", "--push-option", "--receive-pack", "--exec"],
        );
        let target = option_value(rest, &["--repo"]).or(named.first().copied());
        let git_dir = match invocation.git_dir_text.as_deref() {
            Some(text) => self.resolve(text, folder),
            None => match self.discover(folder) {
                Ok(found) => found.map(|repository| repository.git_dir),
                Err(Unread) => return true,
            },
        };
        let entries = match git_dir.as_deref().filter(|git_dir| git_dir.is_dir()) {
            Some(git_dir) => match repository_config(git_dir) {
                Ok(entries) => entries,
                Err(Unread) => return true,
            },
            None => Vec::new(),
        };
        let urls_of = |remote: Option<&str>| -> Vec<String> {
            entries
                .iter()
                .filter(|entry| {
                    entry.section == "remote"
                        && matches!(entry.key.as_str(), "url" | "pushurl")
                        && remote.is_none_or(|remote| entry.sub.as_deref() == Some(remote))
                })
                .map(|entry| entry.value.clone())
                .collect()
        };
        let urls = match target {
            Some(target) => {
                let configured = urls_of(Some(target));
                if configured.is_empty() {
                    vec![target.to_string()]
                } else {
                    configured
                }
            }
            None => urls_of(None),
        };
        urls.iter().any(|url| {
            let Some(path) = self.local_path(url, folder) else {
                return false;
            };
            match pushed_tree(&path) {
                Ok(Some(tree)) => self.reaches(&tree, places),
                Ok(None) => false,
                Err(Unread) => true,
            }
        })
    }

    /// The path a remote's URL names on this machine: a path or a
    /// `file://` URL; `None` for one on another host.
    fn local_path(&self, url: &str, folder: &Path) -> Option<PathBuf> {
        let url = url.strip_prefix("file://").unwrap_or(url);
        if url.contains("://") {
            return None;
        }
        if !url.starts_with(['/', '~', '.', '$']) {
            if let Some(colon) = url.find(':') {
                if !url[..colon].contains('/') {
                    return None;
                }
            }
        }
        self.resolve(url, folder)
    }
}

/// A file of a repository that could not be read as a small regular file.
#[derive(Clone)]
struct Unread;

/// The text of `path` when it is a regular file, not a link, of at most
/// [`READ_BYTES`]; `Ok(None)` when it is not there. Opened without
/// following a link and without waiting (a FIFO, a device), then checked
/// on the open file.
fn read_small(path: &Path) -> Result<Option<String>, Unread> {
    use std::io::Read;
    let missing = |error: &std::io::Error| {
        matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
        )
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return Err(Unread),
        Err(error) if missing(&error) => return Ok(None),
        Err(_) => return Err(Unread),
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if missing(&error) => return Ok(None),
        Err(_) => return Err(Unread),
    };
    let meta = file.metadata().map_err(|_| Unread)?;
    if !meta.is_file() || meta.len() > READ_BYTES {
        return Err(Unread);
    }
    let mut bytes = Vec::new();
    file.take(READ_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Unread)?;
    if bytes.len() as u64 > READ_BYTES {
        return Err(Unread);
    }
    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
}

/// The repository whose `.git` is in `dir`: a `.git` folder, or a `.git`
/// file that names one (`gitdir: <path>`).
fn repository_at(dir: &Path) -> Result<Option<Repository>, Unread> {
    #[cfg(test)]
    tests::FOLDERS_READ.with(|read| read.set(read.get() + 1));
    let dot_git = dir.join(".git");
    let Ok(meta) = std::fs::metadata(&dot_git) else {
        // A link to nowhere, or to a loop: git cannot use it either, but
        // it is not read as missing.
        return match std::fs::symlink_metadata(&dot_git) {
            Ok(_) => Err(Unread),
            Err(_) => Ok(None),
        };
    };
    if meta.is_dir() {
        return Ok(Some(Repository {
            git_dir: dot_git,
            top: dir.to_path_buf(),
        }));
    }
    let Some(text) = read_small(&dot_git)? else {
        return Ok(None);
    };
    let Some(named) = text
        .lines()
        .find_map(|line| line.trim().strip_prefix("gitdir:"))
    else {
        return Err(Unread);
    };
    let named = PathBuf::from(named.trim());
    let git_dir = if named.is_absolute() {
        named
    } else {
        dir.join(named)
    };
    Ok(Some(Repository {
        git_dir,
        top: dir.to_path_buf(),
    }))
}

/// The work tree of the repository at `path` (its top, or a git folder),
/// as a push to it would write it: `None` when there is no repository
/// there or it has no work tree (bare).
fn pushed_tree(path: &Path) -> Result<Option<PathBuf>, Unread> {
    let mut with_suffix = path.as_os_str().to_owned();
    with_suffix.push(".git");
    for candidate in [path.to_path_buf(), PathBuf::from(with_suffix)] {
        let (git_dir, top) = match repository_at(&candidate)? {
            Some(repository) => (repository.git_dir, Some(repository.top)),
            None if candidate.join("HEAD").is_file() && candidate.join("objects").is_dir() => {
                (candidate.clone(), None)
            }
            None => continue,
        };
        let entries = repository_config(&git_dir)?;
        if let Some(tree) = single_worktree(&entries)? {
            let tree = PathBuf::from(&tree);
            let tree = if tree.is_absolute() {
                tree
            } else {
                git_dir.join(tree)
            };
            return Ok(Some(PathBuf::from(collapse_path(&tree.to_string_lossy()))));
        }
        if let Some(top) = top {
            return Ok(Some(top));
        }
        let bare = entries
            .iter()
            .rev()
            .find(|entry| entry.section == "core" && entry.sub.is_none() && entry.key == "bare");
        if bare.is_some_and(|entry| entry.value.eq_ignore_ascii_case("true")) {
            return Ok(None);
        }
        return Ok(git_dir.parent().map(Path::to_path_buf));
    }
    Ok(None)
}

/// One setting of a git config: `[section "sub"] key = value`, the section
/// and key lowercase.
struct Entry {
    section: String,
    sub: Option<String>,
    key: String,
    value: String,
}

/// The settings of a config's text, as git writes them (an `include` is
/// not followed).
fn parse_config(text: &str, out: &mut Vec<Entry>) {
    let mut section = String::new();
    let mut sub: Option<String> = None;
    for line in text.lines() {
        let mut body = line.trim();
        if let Some(rest) = body.strip_prefix('[') {
            let Some(end) = rest.find(']') else {
                continue;
            };
            let head = rest[..end].trim();
            let (name, named) = match head.split_once(char::is_whitespace) {
                Some((name, named)) => (name, Some(named.trim().trim_matches('"').to_string())),
                None => match head.split_once('.') {
                    Some((name, named)) => (name, Some(named.to_string())),
                    None => (head, None),
                },
            };
            section = name.to_ascii_lowercase();
            sub = named;
            body = rest[end + 1..].trim();
        }
        if body.is_empty() || body.starts_with(['#', ';']) {
            continue;
        }
        let (key, value) = match body.split_once('=') {
            Some((key, value)) => (key.trim(), value.trim()),
            None => (body, "true"),
        };
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(value);
        out.push(Entry {
            section: section.clone(),
            sub: sub.clone(),
            key: key.to_ascii_lowercase(),
            value: value.to_string(),
        });
    }
}

/// The settings of the repository at `git_dir`: its `config`, the config
/// of the folder its `commondir` names (a linked work tree) and its
/// `config.worktree`.
fn repository_config(git_dir: &Path) -> Result<Vec<Entry>, Unread> {
    let mut entries = Vec::new();
    if let Some(common) = read_small(&git_dir.join("commondir"))? {
        let common = PathBuf::from(common.trim());
        let common = if common.is_absolute() {
            common
        } else {
            git_dir.join(common)
        };
        if let Some(text) = read_small(&common.join("config"))? {
            parse_config(&text, &mut entries);
        }
    }
    for name in ["config", "config.worktree"] {
        if let Some(text) = read_small(&git_dir.join(name))? {
            parse_config(&text, &mut entries);
        }
    }
    Ok(entries)
}

/// The one `core.worktree` the settings hold; `Err` when they hold more
/// than one value (which one git takes is not read here).
fn single_worktree(entries: &[Entry]) -> Result<Option<String>, Unread> {
    let mut values: Vec<&str> = entries
        .iter()
        .filter(|entry| entry.section == "core" && entry.sub.is_none() && entry.key == "worktree")
        .map(|entry| entry.value.as_str())
        .collect();
    values.sort_unstable();
    values.dedup();
    match values.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some((*one).to_string())),
        _ => Err(Unread),
    }
}

/// The `core.worktree` of the repository at `git_dir`, as its config
/// writes it.
fn core_worktree(git_dir: &Path) -> Result<Option<String>, Unread> {
    single_worktree(&repository_config(git_dir)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A home with the guard's folder, a repository `r` and a project.
    fn home() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".config/innerwarden")).unwrap();
        std::fs::create_dir_all(dir.path().join("r/.git")).unwrap();
        std::fs::create_dir_all(dir.path().join("proj/.git")).unwrap();
        std::fs::create_dir_all(dir.path().join("proj/src")).unwrap();
        dir
    }

    fn takes(line: &str, home: &Path, cwd: &Path) -> bool {
        git_takes_guard_place_in(line, Some(home), None, Some(cwd))
    }

    /// FAILS ON REVERT of the `stash` and `read-tree` arms: with the
    /// guard's folder as the work tree, `stash -a` empties it and
    /// `read-tree -u --reset` puts the repository's files in its place.
    #[test]
    fn stash_and_read_tree_on_the_guard_folder_are_refused() {
        let dir = home();
        let h = dir.path();
        for line in [
            "git --git-dir=r/.git --work-tree=$HOME/.config/innerwarden stash -a",
            "git --git-dir=r/.git --work-tree=$HOME/.config/innerwarden stash",
            "git --git-dir=r/.git --work-tree=$HOME/.config/innerwarden read-tree -u --reset HEAD",
            "GIT_DIR=r/.git GIT_WORK_TREE=~/.config/innerwarden git stash push -u",
            "git --git-dir r/.git --work-tree ~/.config/innerwarden reset --hard",
            "git --git-dir=r/.git --work-tree=$HOME/.config/innerwarden checkout main",
        ] {
            assert!(takes(line, h, h), "{line}");
        }
        // Reading it is not taking it.
        for line in [
            "git --git-dir=r/.git --work-tree=$HOME/.config/innerwarden stash list",
            "git --git-dir=r/.git --work-tree=$HOME/.config/innerwarden read-tree HEAD",
            "git --git-dir=r/.git --work-tree=$HOME/.config/innerwarden status",
        ] {
            assert!(!takes(line, h, h), "{line}");
        }
    }

    /// FAILS ON REVERT of the discovery (`discover`) or of the folder
    /// above the guard's counting for `clean`: a home made a repository is
    /// cleaned whole, the guard's folder with it.
    #[test]
    fn clean_of_a_home_made_a_repository_is_refused() {
        let dir = home();
        let h = dir.path();
        std::fs::create_dir_all(h.join(".git")).unwrap();
        assert!(takes("git clean -fdx", h, h));
        assert!(takes("git clean -fd", h, h));
        assert!(takes("git stash -u", h, h));
        assert!(takes("cd ~ && git clean -ffdx", h, &h.join("proj/src")));
        assert!(takes("git clean -fdx .config", h, h));
        // A checkout of a branch on a home made a repository: what it
        // puts back is not read.
        assert!(takes("git checkout main", h, h));
        // Dry runs, and a clean below the home that does not reach it.
        assert!(!takes("git clean -n -dx", h, h));
        assert!(!takes("git clean -fdx", h, &h.join("proj")));
        assert!(!takes("git clean -fdx", h, &h.join("proj/src")));
        assert!(!takes("git -C proj clean -fdx", h, h));
        // A dotfiles repository: one file put back, the status, a reset of
        // the tracked files.
        for line in [
            "git --git-dir=$HOME/.dotfiles --work-tree=$HOME checkout -- .bashrc",
            "git --git-dir=$HOME/.dotfiles --work-tree=$HOME status",
            "git --git-dir=$HOME/.dotfiles --work-tree=$HOME reset --hard",
            "git --git-dir=$HOME/.dotfiles --work-tree=$HOME stash",
            "git restore src/lib.rs",
        ] {
            assert!(!takes(line, h, h), "{line}");
        }
    }

    /// FAILS ON REVERT of `core_worktree`, of the `config` arm or of the
    /// line's own `core.worktree` settings: a repository pointed at the
    /// guard's folder, then cleaned.
    #[test]
    fn a_work_tree_pointed_at_the_guard_folder_is_refused() {
        let dir = home();
        let h = dir.path();
        assert!(takes(
            "git -C r config core.worktree ~/.config/innerwarden",
            h,
            h
        ));
        assert!(takes(
            "git -C r config set core.worktree ../../.config/innerwarden/x",
            h,
            h
        ));
        assert!(takes(
            "GW=$HOME/.config/innerwarden git --config-env=core.worktree=GW -C r clean -fdx",
            h,
            h
        ));
        assert!(takes(
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.worktree GIT_CONFIG_VALUE_0=$HOME/.config/innerwarden git -C r clean -fdx",
            h,
            h
        ));
        assert!(takes(
            "git -c core.worktree=../../.config/innerwarden -C r clean -fdx",
            h,
            h
        ));
        assert!(!takes("git -C r clean -fdx", h, h));
        // A dotfiles setup points the work tree at the home: not refused.
        assert!(!takes("git -C r config core.worktree $HOME", h, h));
        assert!(!takes("git -C r config core.worktree ../proj", h, h));
        std::fs::write(
            h.join("r/.git/config"),
            format!(
                "[core]\n\tbare = false\n\tworktree = {}\n",
                h.join(".config/innerwarden").display()
            ),
        )
        .unwrap();
        assert!(takes("git -C r clean -fdx", h, h));
        assert!(takes("cd r && git reset --hard", h, h));
        assert!(takes("git -c alias.nuke=clean -C r nuke -f", h, h));
        assert!(!takes("git -C r status", h, h));
        assert!(!takes("git -C r clean -n", h, h));
    }

    /// A `.git` file (a linked work tree, a submodule) names the
    /// repository whose config is read.
    #[test]
    fn a_git_file_names_the_repository() {
        let dir = home();
        let h = dir.path();
        std::fs::create_dir_all(h.join("w")).unwrap();
        std::fs::write(h.join("w/.git"), "gitdir: ../r/.git\n").unwrap();
        std::fs::write(
            h.join("r/.git/config"),
            "[core]\nworktree = ../../.config/innerwarden\n",
        )
        .unwrap();
        assert!(takes("git clean -fdx", h, &h.join("w")));
    }

    /// git run for real in `dir`, with no config of the user's.
    #[cfg(unix)]
    fn git(dir: &Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .args([
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.invalid",
                "-c",
                "init.defaultBranch=main",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(dir)
            .env("HOME", dir)
            .env("XDG_CONFIG_HOME", dir.join(".xdg-none"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// A home with the guard's folder holding its posture, and nothing else.
    #[cfg(unix)]
    fn guarded_home() -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join(".config/innerwarden")).unwrap();
        std::fs::write(dir.path().join(".config/innerwarden/posture"), "x\n").unwrap();
        std::fs::write(dir.path().join(".bashrc"), "x\n").unwrap();
        dir
    }

    /// A repository at `dir` with one commit of `files`.
    #[cfg(unix)]
    fn repository_with(dir: &Path, files: &[&str]) {
        std::fs::create_dir_all(dir).unwrap();
        git(dir, &["init", "-q", "."]);
        for name in files {
            let path = dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "y\n").unwrap();
        }
        git(dir, &["add", "-A"]);
        git(dir, &["commit", "-q", "-m", "c"]);
    }

    /// FAILS ON REVERT of the repositories a line makes counting as found:
    /// `git init` and `git clean` in one line, on the home.
    #[cfg(unix)]
    #[test]
    fn a_repository_the_line_makes_is_found() {
        let dir = guarded_home();
        let h = dir.path();
        for line in [
            "git init -q . && git clean -fdx",
            "git init -q && git clean -ffdx",
            "cd ~ && git init . && git stash -a",
            "git init -q ~ ; git -C ~ clean -fdx",
            "git init -q . && git config alias.tidy 'clean -fdx' && git tidy",
        ] {
            assert!(takes(line, h, h), "{line}");
        }
        // A repository made below the home cleans only itself.
        assert!(!takes("git init -q proj && git -C proj clean -fdx", h, h));
        assert!(!takes(
            "mkdir p && cd p && git init -q && git clean -fdx",
            h,
            h
        ));
        // The same, in two calls, with real git.
        git(h, &["init", "-q", "."]);
        assert!(takes("git clean -fdx", h, h));
    }

    /// FAILS ON REVERT of an unknown verb counting as a write: an alias of
    /// `clean` from the repository's config, the user's or the line's.
    #[cfg(unix)]
    #[test]
    fn an_alias_on_a_work_tree_holding_the_guard_is_refused() {
        let dir = guarded_home();
        let h = dir.path();
        git(h, &["init", "-q", "."]);
        git(h, &["config", "alias.tidy", "clean -fdx"]);
        assert!(takes("git tidy", h, h));
        git(h, &["config", "--global", "alias.wipe", "!git clean -fdx"]);
        assert!(takes("git wipe", h, h));
        assert!(takes("git -c alias.t='!git clean -fdx' t", h, h));
        assert!(takes("git -c alias.t=clean t -fdx", h, h));
        // The same alias in a project below the home does not reach it.
        repository_with(&h.join("proj"), &["a.txt"]);
        assert!(!takes("git tidy", h, &h.join("proj")));
        // Reading verbs pass on the home.
        for line in [
            "git status",
            "git log -1",
            "git diff",
            "git ls-files",
            "git show HEAD",
        ] {
            assert!(!takes(line, h, h), "{line}");
        }
    }

    /// FAILS ON REVERT of `checkout-index` read: the index of a repository
    /// put in the guard's folder.
    #[cfg(unix)]
    #[test]
    fn checkout_index_into_the_guard_folder_is_refused() {
        let dir = guarded_home();
        let h = dir.path();
        repository_with(&h.join("r"), &["posture"]);
        for line in [
            "git --git-dir=r/.git --work-tree=$HOME/.config/innerwarden checkout-index -a -f",
            "git --git-dir=r/.git --work-tree=$HOME/.config/innerwarden checkout-index -f posture",
            "git -C r checkout-index -a -f --prefix=$HOME/.config/innerwarden/",
        ] {
            assert!(takes(line, h, h), "{line}");
        }
        // In its own folder it writes its own files.
        assert!(!takes("git -C r checkout-index -a -f", h, h));
    }

    /// A clone whose files include the guard's, its work tree the home. No
    /// line names the guard's folder; what the clone tracks is not read, the
    /// verb that puts it back is refused.
    #[cfg(unix)]
    #[test]
    fn a_clone_tracking_the_guard_folder_put_on_the_home_is_refused() {
        let dir = guarded_home();
        let h = dir.path();
        let source = tempfile::TempDir::new().unwrap();
        let s = source.path().join("s");
        repository_with(&s, &[".config/innerwarden/posture", "README"]);
        let url = s.to_string_lossy().into_owned();
        git(h, &["clone", "-q", &url, "e"]);
        let tracked = [
            "git --git-dir=e/.git --work-tree=$HOME reset --hard",
            "git --git-dir=e/.git --work-tree=$HOME read-tree -u --reset HEAD",
            "git --git-dir=e/.git --work-tree=$HOME checkout -f",
            "git --git-dir=e/.git --work-tree=$HOME checkout -- .",
            "GIT_DIR=e/.git GIT_WORK_TREE=$HOME git stash",
        ];
        for line in tracked {
            assert!(takes(line, h, h), "{line}");
        }
        // Made in the same line.
        let line = format!(
            "git clone -q {url} e2 && git --git-dir=e2/.git --work-tree=$HOME reset --hard"
        );
        assert!(takes(&line, h, h), "{line}");
        // Taken out of the index first: the commit still holds it.
        // (Nothing of the repository is read: refused as before.)
        git(
            h,
            &[
                "--git-dir=e/.git",
                "--work-tree=e",
                "rm",
                "-q",
                "-r",
                "--cached",
                ".config",
            ],
        );
        assert!(takes(tracked[0], h, h));
        // Packed, with deltas.
        git(&h.join("e"), &["gc", "-q", "--aggressive"]);
        assert!(takes(tracked[0], h, h));
        // One file named, outside the guard's places, passes.
        assert!(!takes(
            "git --git-dir=e/.git --work-tree=$HOME checkout -- README",
            h,
            h
        ));
    }

    /// FAILS ON REVERT of the `Tracked` arm read without the repository's
    /// files: a dotfiles repository on the home keeps what reads, records,
    /// or puts back a file named outside the guard's places; a verb that
    /// puts back the whole tree (`reset --hard`, `stash`, `pull`, a
    /// branch) or removes untracked files is refused, whatever the
    /// repository tracks.
    #[cfg(unix)]
    #[test]
    fn a_dotfiles_repository_keeps_working() {
        let dir = guarded_home();
        let h = dir.path();
        git(h, &["init", "-q", "--bare", ".dotfiles"]);
        let d = ["--git-dir=.dotfiles", "--work-tree=."];
        git(h, &[d[0], d[1], "add", ".bashrc"]);
        git(h, &[d[0], d[1], "commit", "-q", "-m", "c"]);
        git(h, &[d[0], d[1], "branch", "other"]);
        for verb in [
            "status",
            "add .bashrc",
            "commit -m x",
            "checkout",
            "checkout -b topic",
            "checkout -- .bashrc",
            "checkout .bashrc",
            "checkout other -- .bashrc",
            "restore .bashrc",
            "restore --staged .bashrc",
            "reset",
            "reset --soft HEAD",
            "stash list",
            "fetch",
            "push",
            "diff",
            "log -1",
        ] {
            let line = format!("git --git-dir=$HOME/.dotfiles --work-tree=$HOME {verb}");
            assert!(!takes(&line, h, h), "{line}");
        }
        for verb in [
            "clean -f",
            "clean -fdx",
            "stash -u",
            "stash --all",
            "merge other",
            "apply x.patch",
            "reset --hard",
            "reset --hard HEAD",
            "stash",
            "stash pop",
            "pull",
            "checkout other",
            "switch main",
            "checkout -f",
            "checkout -m",
            "checkout -- .",
            "rm -r .config",
        ] {
            let line = format!("git --git-dir=$HOME/.dotfiles --work-tree=$HOME {verb}");
            assert!(takes(&line, h, h), "{line}");
        }
    }

    /// FAILS ON REVERT of [`read_small`] (a `.git` or a config read whole,
    /// following a link, from a device or a FIFO): what cannot be read as a
    /// small regular file leaves the work tree unknown, and a verb that
    /// writes is refused, at once.
    #[cfg(unix)]
    #[test]
    fn a_git_file_that_is_not_a_small_regular_file_is_not_read() {
        let dir = guarded_home();
        let h = dir.path();
        std::fs::create_dir_all(h.join("w")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", h.join("w/.git")).unwrap();
        let started = std::time::Instant::now();
        assert!(takes("git -C w checkout -f", h, h));
        assert!(takes("git -C w clean -fdx", h, h));
        assert!(!takes("git -C w status", h, h));
        // A link to a gitdir file is not followed either.
        std::fs::create_dir_all(h.join("v")).unwrap();
        std::fs::write(h.join("gitfile"), "gitdir: ../proj/.git\n").unwrap();
        std::os::unix::fs::symlink(h.join("gitfile"), h.join("v/.git")).unwrap();
        assert!(takes("git -C v reset --hard", h, h));
        // A FIFO as the config: opened without waiting, not read.
        repository_with(&h.join("f"), &["a.txt"]);
        std::fs::remove_file(h.join("f/.git/config")).unwrap();
        let fifo =
            std::ffi::CString::new(h.join("f/.git/config").to_string_lossy().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(takes("git -C f checkout -- a.txt", h, h));
        // A config past the size read.
        repository_with(&h.join("g"), &["a.txt"]);
        let big = format!("[core]\n#{}\n", "x".repeat(READ_BYTES as usize));
        std::fs::write(h.join("g/.git/config"), big).unwrap();
        assert!(takes("git -C g checkout -- a.txt", h, h));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        // A project with its own config, below the home, works as before.
        repository_with(&h.join("proj"), &["a.txt"]);
        assert!(!takes("git -C proj checkout -- a.txt", h, h));
        assert!(!takes("git -C proj reset --hard", h, h));
        assert!(!takes("git -C proj clean -fdx", h, h));
    }

    /// FAILS ON REVERT of [`rewrites_repository`]: a step of the line that
    /// writes a `.git`, a `gitdir` or a `core.worktree` leaves the work
    /// tree of the git commands after it unknown. Each line, run for real,
    /// resets the home to a repository's files.
    #[cfg(unix)]
    #[test]
    fn a_line_that_rewrites_where_the_repository_is_is_refused() {
        let dir = guarded_home();
        let h = dir.path();
        repository_with(&h.join("e"), &["README"]);
        for line in [
            "git -C e config core.worktree $HOME && git -C e reset --hard",
            "git -C e config --unset core.worktree; git -C e checkout -f",
            "printf '[core]\\n\\tworktree = /h\\n' >> e/.git/config && git -C e reset --hard",
            "printf 'gitdir: /h/e/.git' > ~/.git && git -C ~ checkout -f",
            "ln -s $HOME/e/.git ~/.git && git -C ~ reset --hard",
            "ln -s e/.g?t ~/ && git -C ~ reset --hard",
            "D=.git; cp -r e/$D ~/ && git -C ~ reset --hard",
            "cd e && sed -i 's/x/y/' .git/config && git stash",
            "git -C e worktree add ~/x && git -C ~/x checkout -f",
        ] {
            assert!(takes(line, h, h), "{line}");
        }
        // Reading a `.git`, or writing other files, leaves the line as it is.
        repository_with(&h.join("proj"), &["a.txt"]);
        let p = h.join("proj");
        for line in [
            "cat .git/config && git checkout -- a.txt",
            "ls .git && git reset --hard",
            "echo x > notes.txt && git checkout -- a.txt",
            "printf 'target/\\n' >> .gitignore && git stash",
            "git config user.name x && git reset --hard",
            "git worktree remove --force ../wt && git worktree prune",
            "git submodule status && git checkout -- a.txt",
        ] {
            assert!(!takes(line, h, &p), "{line}");
        }
    }

    /// FAILS ON REVERT of [`Line::pushes_to_guard`]: a push to a repository
    /// on this machine whose work tree is the home.
    #[cfg(unix)]
    #[test]
    fn a_push_to_a_repository_on_the_home_is_refused() {
        let dir = guarded_home();
        let h = dir.path();
        git(h, &["init", "-q", "."]);
        git(h, &["add", ".bashrc"]);
        git(h, &["commit", "-q", "-m", "c"]);
        let away = tempfile::TempDir::new().unwrap();
        let c = away.path().join("c");
        let home_url = h.to_string_lossy().into_owned();
        git(away.path(), &["clone", "-q", &home_url, "c"]);
        let c_text = c.to_string_lossy().into_owned();
        for line in [
            format!("git -C {c_text} push origin main"),
            format!("git -C {c_text} push"),
            format!("git -C {c_text} push $HOME main"),
            format!("git -C {c_text} push file://{home_url} main"),
            format!("git -C {c_text} push {home_url}/.git main"),
        ] {
            assert!(takes(&line, h, h), "{line}");
        }
        // A bare repository, a project below the home and a host elsewhere.
        git(h, &["init", "-q", "--bare", "b.git"]);
        repository_with(&h.join("proj"), &["a.txt"]);
        git(
            &c,
            &[
                "remote",
                "set-url",
                "origin",
                "https://example.invalid/r.git",
            ],
        );
        for line in [
            format!("git -C {c_text} push $HOME/b.git main"),
            format!("git -C {c_text} push $HOME/b main"),
            format!("git -C {c_text} push $HOME/proj main"),
            format!("git -C {c_text} push origin main"),
            format!("git -C {c_text} push git@example.invalid:r.git main"),
        ] {
            assert!(!takes(&line, h, h), "{line}");
        }
    }

    /// FAILS ON REVERT of `in_command_dir`: the folder the command runs in
    /// is the one the caller names, not this process's.
    #[test]
    fn the_command_folder_is_the_one_named() {
        let dir = tempfile::TempDir::new().unwrap();
        let seen = in_command_dir(Some(dir.path()), command_dir);
        assert_eq!(seen.as_deref(), Some(dir.path()));
        assert_eq!(command_dir(), std::env::current_dir().ok());
    }

    /// FAILS ON REVERT of the call in `mcp::analyze_command_in`: a
    /// repository named relative to the agent's folder, with the home as
    /// its work tree, is found there.
    #[cfg(unix)]
    #[test]
    fn the_agent_folder_finds_the_repository() {
        let Some(home) = std::env::var_os("HOME").filter(|home| !home.is_empty()) else {
            return;
        };
        let home = PathBuf::from(home);
        let work = tempfile::TempDir::new().unwrap();
        let w = work.path();
        let source = w.join("s");
        repository_with(&source, &[".config/innerwarden/posture"]);
        let url = source.to_string_lossy().into_owned();
        git(w, &["clone", "-q", &url, "e"]);
        let line = "git --git-dir=e/.git --work-tree=$HOME reset --hard";
        let context = crate::mcp::WorkingContext::discover(&w.to_string_lossy(), home.to_str())
            .expect("context");
        let analysis = crate::mcp::analyze_command_in(line, None, Some(&context));
        assert_eq!(analysis.recommendation, "deny", "{analysis:?}");
    }
    thread_local! {
        /// How many folders [`repository_at`] read on this thread.
        pub(super) static FOLDERS_READ: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }

    /// A home made a repository, the guard's folder in it.
    fn home_repository() -> tempfile::TempDir {
        let dir = home();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        dir
    }

    /// FAILS ON REVERT of the ceiling in `discover`: with the eval's empty
    /// place inside a checkout (the cargo target in the repository, as CI
    /// lays it out), the checkout around it counted as a repository holding
    /// the home, and a plain `git worktree add` was refused.
    #[test]
    fn a_ceiling_folder_stops_the_search_for_a_repository() {
        let dir = tempfile::TempDir::new().unwrap();
        let checkout = dir.path().join("checkout");
        let place = checkout.join("target/tmp/place");
        let h = place.join("home");
        let work = place.join("work");
        std::fs::create_dir_all(checkout.join(".git")).unwrap();
        std::fs::create_dir_all(h.join(".config/innerwarden")).unwrap();
        std::fs::create_dir_all(&work).unwrap();
        let line = "git worktree add ../x";
        assert!(git_takes_guard_place_with(
            line,
            Some(&h),
            None,
            Some(&work),
            &[]
        ));
        let ceilings = ceiling_directories(Some(place.as_os_str()));
        assert!(!git_takes_guard_place_with(
            line,
            Some(&h),
            None,
            Some(&work),
            &ceilings
        ));
        // The folder git starts in is still read.
        std::fs::create_dir_all(work.join(".git")).unwrap();
        let ceilings = ceiling_directories(Some(work.as_os_str()));
        assert!(!git_takes_guard_place_with(
            line,
            Some(&h),
            None,
            Some(&work),
            &ceilings
        ));
        // A relative entry is left out, as git leaves it.
        assert!(ceiling_directories(Some(std::ffi::OsStr::new("target"))).is_empty());
    }

    /// FAILS ON REVERT of `normalize_options`: git takes a long option
    /// shortened to a prefix only it starts, and a value glued to a short
    /// option.
    #[test]
    fn shortened_long_options_are_read_whole() {
        let dir = home_repository();
        let h = dir.path();
        std::fs::write(h.join("evil"), "").unwrap();
        for line in [
            "git reset --har",
            "git reset --ha",
            "git reset --kee",
            "git reset --mer",
            "git checkout --forc",
            "git checkout -bx evil",
            "git checkout -fb x evil",
            "git stash push --mes .bashrc",
            "git restore --sou=HEAD .",
            "git clean --forc -d",
        ] {
            assert!(takes(line, h, h), "{line}");
        }
        for line in [
            "git reset --sof",
            "git reset --mix",
            "git checkout -bx",
            "git clean --dry -fd",
            "git restore --stag .config",
        ] {
            assert!(!takes(line, h, h), "{line}");
        }
    }

    /// FAILS ON REVERT of `folder_unknown` and `start_unknown`: a `-C`, a
    /// `cd` or a `--git-dir` the line does not say leaves the work tree
    /// unknown, and a verb that writes is refused. `$PWD` is the folder
    /// the shell is in.
    #[test]
    fn a_folder_the_line_does_not_say_is_not_known() {
        let dir = home_repository();
        let h = dir.path();
        let proj = h.join("proj");
        for line in [
            "git -C \"\" reset --hard",
            "git -C \"$X\" reset --hard",
            "git -C $(echo ~) reset --hard",
            "git --git-dir=\"$(echo .git)\" reset --hard",
            "cd \"$X\" && git reset --hard",
            "cd - && git checkout -f",
            "pushd /tmp && popd && git reset --hard",
        ] {
            assert!(takes(line, h, &proj), "{line}");
        }
        for line in [
            "git -C \"$PWD\" reset --hard",
            "git -C \"$(pwd)\" reset --hard",
            "cd \"$PWD\" && git reset --hard",
            "git -C \"$X\" status",
            "cd \"$X\" && git log",
            "git reset --hard",
        ] {
            assert!(!takes(line, h, &proj), "{line}");
        }
        // `$PWD` is the folder the shell is in: here, the home.
        assert!(takes("git -C \"$PWD\" reset --hard", h, h));
    }

    /// FAILS ON REVERT of the `core.worktree` word and of `inside_git` in
    /// the line's reading: a clone given `core.worktree` and a config
    /// written from inside a `.git` repoint the work tree for the rest of
    /// the line.
    #[test]
    fn a_work_tree_repointed_earlier_in_the_line_is_not_known() {
        let dir = home();
        let h = dir.path();
        let proj = h.join("proj");
        std::fs::create_dir_all(proj.join("e/.git")).unwrap();
        for line in [
            "git clone -c core.worktree=$HOME src x && git -C x reset --hard",
            "git clone --config=core.worktree=$HOME src x && git -C x reset --hard",
            "cd e/.git && printf '[core]\\n\\tworktree = /h\\n' >> config && cd ../.. && git -C e reset --hard",
            "cd e/.git && sed -i s/x/y/ config && cd ../.. && git -C e reset --hard",
        ] {
            assert!(takes(line, h, &proj), "{line}");
        }
        for line in [
            "git clone src x && git -C x reset --hard",
            "cd e/.git && cat config && cd ../.. && git -C e reset --hard",
            "cd e/.git && ls && cd ../.. && git -C e checkout -f",
        ] {
            assert!(!takes(line, h, &proj), "{line}");
        }
    }

    /// FAILS ON REVERT of `could_be_branch` and of the `switch` arm:
    /// without `--`, git reads a name that can be a branch as one even when
    /// a file or folder has that name; `switch -c` with no start point
    /// moves no file.
    #[test]
    fn a_branch_named_as_a_file_is_a_branch() {
        let dir = home_repository();
        let h = dir.path();
        std::fs::create_dir_all(h.join("docs")).unwrap();
        std::fs::write(h.join("evil"), "").unwrap();
        std::fs::write(h.join(".bashrc"), "").unwrap();
        for line in [
            "git branch docs evil && git checkout docs",
            "git checkout evil",
            "git switch -c x evil",
            "git switch --orphan x",
            "git switch -c x -f",
            "git switch main",
        ] {
            assert!(takes(line, h, h), "{line}");
        }
        for line in [
            "git checkout .bashrc",
            "git checkout -- evil",
            "git switch -c x",
            "git switch --create=x",
            "git checkout -b x",
        ] {
            assert!(!takes(line, h, h), "{line}");
        }
    }

    /// FAILS ON REVERT of the pattern reading in `glob_matches` (back to
    /// trying every split) and of the line's `Cache`: thousands of
    /// patterns of stars, and thousands of git commands after many `cd`,
    /// are read in well under the hook's deadline.
    #[test]
    fn a_long_line_costs_what_its_distinct_parts_cost() {
        let dir = home();
        let h = dir.path();
        let proj = h.join("proj");
        let stars = format!(".{}x", "*".repeat(60));
        let words: Vec<String> = (0..4000).map(|_| stars.clone()).collect();
        let line = format!("touch {} ; git status", words.join(" "));
        let started = std::time::Instant::now();
        assert!(!takes(&line, h, &proj));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert!(glob_matches(".*g*i*t", ".git") || glob_matches("*g*i*t", "git"));
        assert!(glob_matches("[!a]i?", "git"));
        assert!(!glob_matches("*x", "git"));
        let mut parts: Vec<String> = (0..16).map(|n| format!("cd d{n}")).collect();
        parts.extend((0..12000).map(|_| "git checkout -- a".to_string()));
        let line = parts.join(" && ");
        FOLDERS_READ.with(|read| read.set(0));
        let started = std::time::Instant::now();
        assert!(!takes(&line, h, &proj));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        // Each folder is read once for the line, not once per command.
        let read = FOLDERS_READ.with(std::cell::Cell::get);
        assert!(read < 2000, "{read} folders read");
    }
}
