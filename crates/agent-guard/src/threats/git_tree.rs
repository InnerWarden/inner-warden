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
//! `commit` and the like, [`KEEPS_TREE`]). Every other verb, a verb not
//! known here and an alias (from `-c`, from the repository's config or the
//! user's) included, is refused, unless:
//!
//! * the paths it is handed keep it out of the guard's places
//!   (`checkout -- .bashrc`), or
//! * it only puts back what the repository tracks (`checkout`, `restore`,
//!   `reset --hard`, `stash`, `read-tree -u`, `checkout-index`, `rm`,
//!   `mv`, `pull`), and neither its index nor the commit it puts back holds
//!   a path of the guard's places. Both are read from the repository's files
//!   ([`objects`]); git is not run.
//!
//! A verb that removes what is not tracked (`clean`, `stash -u`/`-a`)
//! has no such second way: run on a work tree that holds the guard's places,
//! it removes them. `git config core.worktree <place>` naming a place of the
//! guard or a folder inside one is refused.
//!
//! Not read: a folder or a value behind a variable the line does not assign
//! (other than the home), an `include` in a repository's config, a
//! repository found more than [`DISCOVERY_DEPTH`] folders up, and what
//! `pull` brings from its remote.

mod objects;

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

/// Largest repository config read.
const CONFIG_BYTES: u64 = 1 << 20;

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

/// Variables that move what git reads as the repository's index or
/// objects: with one assigned, what the repository tracks is not known.
const STORE_VARIABLES: &[&str] = &[
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
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
/// working folder given.
pub(super) fn git_takes_guard_place_in(
    content: &str,
    home: Option<&Path>,
    xdg: Option<&Path>,
    cwd: Option<&Path>,
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
    for segment in shell_command_segments(content) {
        let words: Vec<String> = shell_tokens(segment).iter().map(|w| unquote(w)).collect();
        for word in &words {
            if let Some((name, value)) = assignment(word) {
                assigned.push((name, value));
            }
        }
        let Some(index) = effective_command_index(&words) else {
            continue;
        };
        let name = token_basename(&words[index]).to_ascii_lowercase();
        let arguments = &words[index + 1..];
        let line = Line {
            home,
            assigned: &assigned,
            created: &created,
        };
        match name.as_str() {
            "cd" | "pushd" => {
                let dir = arguments
                    .iter()
                    .find(|word| !word.starts_with('-'))
                    .map_or("~", String::as_str);
                let named: Vec<PathBuf> = starts
                    .iter()
                    .filter_map(|start| line.resolve(dir, start))
                    .chain(line.resolve(dir, Path::new("/")))
                    .collect();
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
    }
    false
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

/// The guard's places as paths in a work tree at `tree`, lowercase: an
/// empty one when the tree is a place of the guard or inside one.
fn tree_targets(tree: &Path, places: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tree in spellings(tree) {
        let tree = tree.trim_end_matches('/');
        for place in places {
            let target = if is_within(place, tree) {
                place[tree.len()..].trim_start_matches('/').to_string()
            } else if is_within(tree, place) {
                String::new()
            } else {
                continue;
            };
            if !out.contains(&target) {
                out.push(target);
            }
        }
    }
    out
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

/// Where a verb takes what it puts in the work tree from.
enum Source {
    /// The repository's index.
    Index,
    /// The tree of the commit a name points at.
    Rev(String),
}

/// What a git verb does to the work tree.
enum Plan {
    /// Leaves it as it is.
    Keeps,
    /// Removes what is not tracked, below the paths when it is handed some.
    Untracked(Vec<String>),
    /// Puts in place what the sources track, below the paths when it is
    /// handed some.
    Tracked(Vec<String>, Vec<Source>),
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
    let head = || Source::Rev("HEAD".to_string());
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
                Some("pop" | "apply" | "branch") => {
                    let named = match sub {
                        Some("branch") => words.get(2),
                        _ => words.get(1),
                    };
                    let stash = named.map_or("refs/stash", |name| *name).to_string();
                    Plan::Tracked(Vec::new(), vec![Source::Index, head(), Source::Rev(stash)])
                }
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
                        Plan::Tracked(paths, vec![Source::Index, head()])
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
            let (trees, _) = operands(rest, &[]);
            let mut from = vec![Source::Index];
            from.extend(trees.into_iter().map(|tree| Source::Rev(tree.to_string())));
            Plan::Tracked(Vec::new(), from)
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
            Plan::Tracked(paths, vec![Source::Index])
        }
        "checkout" => {
            let new_branch = has(&["-b", "-B", "--orphan"]);
            let (before, after) = operands(rest, &["-b", "-B", "--orphan"]);
            if let Some(after) = after {
                let paths = after.into_iter().map(str::to_string).collect();
                let from = match before.first() {
                    Some(rev) => vec![Source::Rev(rev.to_string())],
                    None => vec![Source::Index],
                };
                return Plan::Tracked(with_unknown(paths), from);
            }
            let Some(first) = before.first() else {
                return Plan::Tracked(with_unknown(Vec::new()), vec![Source::Index, head()]);
            };
            let is_path = !new_branch
                && line
                    .resolve(first, folder)
                    .is_some_and(|path| path.symlink_metadata().is_ok());
            if is_path {
                let paths = before.iter().map(|word| word.to_string()).collect();
                return Plan::Tracked(with_unknown(paths), vec![Source::Index]);
            }
            let paths = before[1..].iter().map(|word| word.to_string()).collect();
            Plan::Tracked(
                with_unknown(paths),
                vec![Source::Index, Source::Rev(first.to_string())],
            )
        }
        "switch" => {
            let (before, _) = operands(
                rest,
                &["-c", "-C", "--orphan", "--create", "--force-create"],
            );
            let from = match before.first() {
                Some(rev) => Source::Rev(rev.to_string()),
                None => head(),
            };
            Plan::Tracked(Vec::new(), vec![Source::Index, from])
        }
        "restore" => {
            let staged = has(&["--staged", "-S"]);
            let worktree = has(&["--worktree", "-W"]);
            if staged && !worktree {
                return Plan::Keeps;
            }
            let mut from = match option_value(rest, &["-s", "--source"]) {
                Some(source) => vec![Source::Rev(source.to_string())],
                None => vec![Source::Index],
            };
            if staged {
                from.push(head());
            }
            let paths = both(operands(rest, &["-s", "--source"]));
            Plan::Tracked(with_unknown(paths), from)
        }
        "reset" => {
            if !has(&["--hard", "--merge", "--keep"]) {
                return Plan::Keeps;
            }
            let (before, _) = operands(rest, &[]);
            let commit = before.first().map_or("HEAD", |commit| *commit);
            Plan::Tracked(
                Vec::new(),
                vec![Source::Index, Source::Rev(commit.to_string())],
            )
        }
        "rm" => {
            if has(&["--cached", "--dry-run"]) || short_has(&['n']) {
                return Plan::Keeps;
            }
            Plan::Tracked(with_unknown(both(operands(rest, &[]))), vec![Source::Index])
        }
        "mv" => {
            if has(&["--dry-run"]) || short_has(&['n']) {
                return Plan::Keeps;
            }
            Plan::Tracked(with_unknown(both(operands(rest, &[]))), vec![Source::Index])
        }
        "pull" => Plan::Tracked(Vec::new(), vec![Source::Index, head()]),
        _ if KEEPS_TREE.contains(&verb) => Plan::Keeps,
        _ => Plan::Writes,
    }
}

/// What the line has said so far: the home, the variables it assigned and
/// the repositories it made.
struct Line<'a> {
    home: Option<&'a Path>,
    assigned: &'a [(String, String)],
    created: &'a [Repository],
}

/// A git command's global options, read.
struct Invocation {
    /// The folder it runs in (`-C`).
    folder: PathBuf,
    git_dir_text: Option<String>,
    tree_text: Option<String>,
    /// `core.worktree` set for this command only.
    set_tree: Option<String>,
    /// Where the verb is in the arguments.
    verb_at: usize,
}

impl Line<'_> {
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

    /// The global options of `git <arguments>` run in `start`; `None` when
    /// the folder it runs in is not known.
    fn invocation(&self, arguments: &[String], start: &Path) -> Option<Invocation> {
        let mut folder = start.to_path_buf();
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
                        folder = self.resolve(value, &folder)?;
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
        Some(Invocation {
            folder,
            git_dir_text,
            tree_text,
            set_tree,
            verb_at: at,
        })
    }

    /// The repository `git <arguments>` makes, run in `start`: `git init`
    /// or `git clone` with a work tree.
    fn git_makes(&self, arguments: &[String], start: &Path) -> Option<Repository> {
        let invocation = self.invocation(arguments, start)?;
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
        let Some(invocation) = self.invocation(arguments, start) else {
            return false;
        };
        let Some(verb) = arguments.get(invocation.verb_at) else {
            return false;
        };
        let verb = verb.to_ascii_lowercase();
        let rest = &arguments[invocation.verb_at + 1..];
        let folder = &invocation.folder;
        let plan = plan(&verb, rest, folder, self);
        if matches!(plan, Plan::Keeps) {
            return false;
        }

        // The repository: named, made before in the line, or found from the
        // folder up.
        let named_git_dir = invocation
            .git_dir_text
            .as_deref()
            .and_then(|text| self.resolve(text, folder));
        let found = if invocation.git_dir_text.is_none() {
            self.discover(folder)
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
                    .is_some_and(|tree| reaches(&tree, places))
                && !matches!(plan, Plan::Points(_));
        }
        let config_tree = git_dir.as_deref().and_then(core_worktree);
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
                    .all(|word| resolve_path(word).is_some_and(|path| !reaches(&path, places)))
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
            Plan::Writes => reaches(&tree, places),
            Plan::WritesBelow(prefix) => match self.resolve(&prefix, folder) {
                Some(below) => reaches(&below, places),
                None => true,
            },
            Plan::Untracked(paths) => {
                // Run below its top, clean reaches the folder it runs in.
                let scope = if verb == "clean" {
                    paths_base.clone()
                } else {
                    tree.clone()
                };
                reaches(&scope, places) && !kept_out(&paths)
            }
            Plan::Tracked(paths, from) => {
                if !reaches(&tree, places) || kept_out(&paths) {
                    return false;
                }
                if made
                    || STORE_VARIABLES
                        .iter()
                        .any(|name| self.variable(name).is_some())
                {
                    return true;
                }
                let Some(repository) = git_dir.as_deref().and_then(objects::Repo::open) else {
                    return true;
                };
                let targets = tree_targets(&tree, places);
                from.iter().any(|source| {
                    let holds = match source {
                        Source::Index => repository.index_holds(&targets),
                        Source::Rev(rev) => repository.rev_holds(rev, &targets),
                    };
                    holds != Some(false)
                })
            }
        }
    }

    /// The repository git finds from `folder` up, a repository the line
    /// made counted: a `.git` folder, or a `.git` file that names one
    /// (`gitdir: <path>`).
    fn discover(&self, folder: &Path) -> Option<Repository> {
        for dir in folder.ancestors().take(DISCOVERY_DEPTH) {
            if let Some(made) = self.created.iter().find(|made| made.top == dir) {
                return Some(made.clone());
            }
            let dot_git = dir.join(".git");
            let Ok(meta) = std::fs::metadata(&dot_git) else {
                continue;
            };
            if meta.is_dir() {
                return Some(Repository {
                    git_dir: dot_git,
                    top: dir.to_path_buf(),
                });
            }
            let text = std::fs::read_to_string(&dot_git).ok()?;
            let named = text
                .lines()
                .find_map(|line| line.trim().strip_prefix("gitdir:"))?;
            let named = PathBuf::from(named.trim());
            let git_dir = if named.is_absolute() {
                named
            } else {
                dir.join(named)
            };
            return Some(Repository {
                git_dir,
                top: dir.to_path_buf(),
            });
        }
        None
    }
}

/// The `core.worktree` of the repository at `git_dir`, as its config
/// writes it.
fn core_worktree(git_dir: &Path) -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open(git_dir.join("config")).ok()?;
    let mut text = String::new();
    file.take(CONFIG_BYTES).read_to_string(&mut text).ok()?;
    let mut in_core = false;
    let mut value = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(section) = line.strip_prefix('[') {
            let name = section.split(']').next().unwrap_or("").trim();
            in_core = name.eq_ignore_ascii_case("core");
            continue;
        }
        if !in_core {
            continue;
        }
        let Some((key, found)) = line.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("worktree") {
            let found = found.trim();
            let found = found
                .strip_prefix('"')
                .and_then(|found| found.strip_suffix('"'))
                .unwrap_or(found);
            value = Some(found.to_string());
        }
    }
    value
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
        // A checkout on a home made a repository whose files cannot be
        // read (this `.git` is an empty folder): what it puts back is not
        // known.
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

    /// FAILS ON REVERT of reading what the repository tracks: a clone whose
    /// files include the guard's, its work tree the home. No line names the
    /// guard's folder.
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

    /// A dotfiles repository that does not track the guard's places keeps
    /// working on the home: put back, reset, stash, pull, a branch; what
    /// removes untracked files does not.
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
            "checkout -- .bashrc",
            "checkout .bashrc",
            "restore .bashrc",
            "reset --hard",
            "reset --hard HEAD",
            "stash",
            "stash pop",
            "pull",
            "checkout other",
            "switch main",
            "diff",
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
        ] {
            let line = format!("git --git-dir=$HOME/.dotfiles --work-tree=$HOME {verb}");
            assert!(takes(&line, h, h), "{line}");
        }
        // Moved by `reset --soft` to a commit that holds the guard's
        // folder, without the index: the commit is read.
        let other = tempfile::TempDir::new().unwrap();
        let s = other.path().join("s");
        repository_with(&s, &[".config/innerwarden/posture"]);
        let url = s.to_string_lossy().into_owned();
        git(h, &[d[0], "fetch", "-q", &url, "main:evil"]);
        assert!(takes(
            "git --git-dir=$HOME/.dotfiles --work-tree=$HOME checkout evil",
            h,
            h
        ));
        git(h, &[d[0], d[1], "reset", "-q", "--soft", "evil"]);
        assert!(takes(
            "git --git-dir=$HOME/.dotfiles --work-tree=$HOME reset --hard",
            h,
            h
        ));
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
}
