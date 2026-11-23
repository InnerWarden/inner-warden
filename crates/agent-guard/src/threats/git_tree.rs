//! git verbs that empty, reset or repoint a work tree, read on the work tree
//! git itself would use: the one the line names (`--work-tree`,
//! `GIT_WORK_TREE`, `-c core.worktree=`, `--config-env`,
//! `GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>`), else the `core.worktree`
//! of the repository's own config, else the folder that holds its `.git`,
//! found from the folder the command runs in (`cd`, `-C`, the working
//! folder) as git finds it.
//!
//! Measured 2026-11-22 with real git, each one ran and emptied or reset the
//! guard's folder: `stash -a` and `read-tree -u --reset HEAD` with the
//! guard's folder as the work tree, `git clean -fdx` in a home made a
//! repository by `git init .`, and `git clean -fdx` in a repository whose
//! config points `core.worktree` at the guard's folder.
//!
//! What is refused:
//!
//! * a verb that removes what is not tracked (`clean` without `-n`,
//!   `stash -u` / `-a`) where what it reaches holds a place of the guard,
//!   or is one: the home, or any folder above the guard's;
//! * a verb that puts the repository's version of the tracked files in place
//!   (`stash`, `read-tree -u`, `checkout`, `switch`, `restore`,
//!   `reset --hard`/`--merge`/`--keep`) where the work tree, or a path it
//!   is handed, is a place of the guard or inside one. A dotfiles
//!   repository with the home as its work tree (`--work-tree=$HOME
//!   checkout -- .bashrc`) is not refused: the guard's files are not
//!   tracked there;
//! * `git config core.worktree <place>` naming a place of the guard or a
//!   folder inside one.
//!
//! Not read: a folder or a value behind a variable the line does not assign
//! (other than the home), an `include` in a repository's config, and a
//! repository found more than [`DISCOVERY_DEPTH`] folders up.

use super::{
    collapse_path, effective_command_index, shell_command_segments, shell_tokens, token_basename,
    GIT_GLOBAL_VALUE_OPTIONS, GUARD_FIND_PLACES,
};
use std::path::{Path, PathBuf};

/// What the shell side says of such a line.
pub(super) const GIT_TREE_TAKES_GUARD: &str =
    "runs a git command that empties or resets a work tree holding the guard's own files \
     (its configuration, the settings that load it, or its program), or points a \
     repository's work tree at them";

/// How many folders a line's git commands are read from (the working folder
/// and each `cd`).
const STARTS: usize = 16;

/// How many folders up a repository is looked for.
const DISCOVERY_DEPTH: usize = 64;

/// Largest repository config read.
const CONFIG_BYTES: u64 = 1 << 20;

/// Whether the line runs a git command that empties, resets or repoints a
/// work tree onto the guard's places, read in this process's home and
/// working folder.
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
    let cwd = std::env::current_dir().ok();
    git_takes_guard_place_in(content, home.as_deref(), xdg.as_deref(), cwd.as_deref())
}

/// A cheap test ahead of the reading: the line names git and one of the
/// verbs read.
fn may_take(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    lower.contains("git")
        && [
            "clean",
            "stash",
            "read-tree",
            "checkout",
            "switch",
            "restore",
            "reset",
            "config",
        ]
        .iter()
        .any(|verb| lower.contains(verb))
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
                for dir in named {
                    if starts.len() < STARTS && !starts.contains(&dir) {
                        starts.push(dir);
                    }
                }
            }
            "git"
                if starts
                    .iter()
                    .any(|start| line.git_takes(arguments, start, &places)) =>
            {
                return true;
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

/// What a git verb does to the paths it reaches.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect {
    /// Removes what is not tracked there.
    Untracked,
    /// Puts the repository's version of what is tracked there in place.
    Tracked,
}

/// What the line has said so far: the home and the variables it assigned.
struct Line<'a> {
    home: Option<&'a Path>,
    assigned: &'a [(String, String)],
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

    /// Whether `git <arguments>`, run in `start`, takes a place of
    /// `places`.
    fn git_takes(&self, arguments: &[String], start: &Path, places: &[String]) -> bool {
        let mut folder = start.to_path_buf();
        let mut git_dir_text = self.variable("GIT_DIR");
        let mut tree_text = self.variable("GIT_WORK_TREE");
        // `core.worktree` set for this command only, read in the
        // repository's folder as git reads it.
        let mut set_tree: Option<String> = None;
        let mut pair = 0usize;
        while pair < 64 {
            let key = self.variable(&format!("GIT_CONFIG_KEY_{pair}"));
            let Some(key) = key else { break };
            if key.eq_ignore_ascii_case("core.worktree") {
                set_tree = self.variable(&format!("GIT_CONFIG_VALUE_{pair}"));
            }
            pair += 1;
        }
        let mut aliases: Vec<(String, String)> = Vec::new();
        let mut setting = |value: &str, set_tree: &mut Option<String>, by_env: bool| {
            let Some((key, value)) = value.split_once('=') else {
                return;
            };
            let key = key.trim().to_ascii_lowercase();
            let value = if by_env {
                match self.variable(value) {
                    Some(value) => value,
                    None => return,
                }
            } else {
                value.to_string()
            };
            if key == "core.worktree" {
                *set_tree = Some(value);
            } else if let Some(name) = key.strip_prefix("alias.") {
                aliases.push((name.to_string(), value));
            }
        };
        let mut at = 0usize;
        while let Some(word) = arguments.get(at) {
            let next = arguments.get(at + 1).map(String::as_str);
            match word.as_str() {
                "-C" => {
                    if let Some(value) = next {
                        match self.resolve(value, &folder) {
                            Some(path) => folder = path,
                            None => return false,
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
        let Some(verb) = arguments.get(at) else {
            return false;
        };
        let mut verb = verb.to_ascii_lowercase();
        let mut rest: Vec<String> = arguments[at + 1..].to_vec();
        for _ in 0..8 {
            let Some((_, value)) = aliases.iter().rev().find(|(name, _)| *name == verb) else {
                break;
            };
            if value.trim_start().starts_with('!') {
                // A shell alias may do anything to the work tree.
                verb = "clean".to_string();
                rest.clear();
                break;
            }
            let mut words = value.split_whitespace().map(str::to_string);
            let Some(first) = words.next() else { break };
            verb = first.to_ascii_lowercase();
            rest = words.chain(rest).collect();
        }

        // The repository: named, or found from the folder up.
        let named_git_dir = git_dir_text
            .as_deref()
            .and_then(|text| self.resolve(text, &folder));
        if git_dir_text.is_some() && named_git_dir.is_none() {
            return false;
        }
        let found = if named_git_dir.is_none() {
            discover(&folder)
        } else {
            None
        };
        let git_dir = named_git_dir
            .clone()
            .or_else(|| found.as_ref().map(|(dir, _)| dir.clone()));
        let config_tree = git_dir.as_deref().and_then(core_worktree);
        // `core.worktree`, relative, is read in the repository's folder.
        let tree = if let Some(text) = &tree_text {
            self.resolve(text, &folder)
        } else if let Some(text) = set_tree.as_deref().or(config_tree.as_deref()) {
            self.resolve(text, git_dir.as_deref().unwrap_or(&folder))
        } else if named_git_dir.is_some() {
            Some(folder.clone())
        } else {
            found.map(|(_, top)| top)
        };

        let paths = |from: &[String], valued: &[&str]| -> Vec<PathBuf> {
            let mut after_dashes = false;
            let mut skip = false;
            let mut out = Vec::new();
            for word in from {
                if skip {
                    skip = false;
                    continue;
                }
                if word == "--" && !after_dashes {
                    after_dashes = true;
                    continue;
                }
                if !after_dashes && valued.contains(&word.as_str()) {
                    skip = true;
                    continue;
                }
                if after_dashes || !word.starts_with('-') {
                    let path = match (word.strip_prefix(":/"), &tree) {
                        (Some(rest), Some(tree)) => self.resolve(rest, tree),
                        _ => self.resolve(word, &folder),
                    };
                    out.extend(path);
                }
            }
            out
        };
        let has = |names: &[&str]| rest.iter().any(|word| names.contains(&word.as_str()));
        let short_has = |letters: &[char]| {
            rest.iter().any(|word| {
                word.starts_with('-') && !word.starts_with("--") && word.contains(letters)
            })
        };

        let (effect, scope): (Effect, Vec<PathBuf>) = match verb.as_str() {
            "clean" => {
                if has(&["--dry-run"]) || short_has(&['n']) {
                    return false;
                }
                let named = paths(&rest, &["-e", "--exclude"]);
                let scope = if !named.is_empty() {
                    named
                } else {
                    match &tree {
                        // Run below its top, clean reaches the folder it runs in.
                        Some(tree) if folder.starts_with(tree) => vec![folder.clone()],
                        Some(tree) => vec![tree.clone()],
                        None => Vec::new(),
                    }
                };
                (Effect::Untracked, scope)
            }
            "stash" => {
                let sub = rest.iter().find(|word| !word.starts_with('-'));
                if sub.is_some_and(|sub| {
                    matches!(
                        sub.as_str(),
                        "list" | "show" | "drop" | "clear" | "create" | "store"
                    )
                }) {
                    return false;
                }
                let untracked = has(&["--include-untracked", "--all"]) || short_has(&['u', 'a']);
                let effect = if untracked {
                    Effect::Untracked
                } else {
                    Effect::Tracked
                };
                (effect, tree.iter().cloned().collect())
            }
            "read-tree" => {
                if !(has(&["-u"]) || short_has(&['u'])) {
                    return false;
                }
                (Effect::Tracked, tree.iter().cloned().collect())
            }
            "checkout" | "switch" => {
                let mut scope: Vec<PathBuf> = tree.iter().cloned().collect();
                scope.extend(paths(&rest, &["-b", "-B", "--orphan", "-c", "-C"]));
                (Effect::Tracked, scope)
            }
            "restore" => (Effect::Tracked, paths(&rest, &["-s", "--source"])),
            "reset" if has(&["--hard", "--merge", "--keep"]) => {
                (Effect::Tracked, tree.iter().cloned().collect())
            }
            "config" => {
                // `git config [set] core.worktree <value>`.
                let mut words = rest.iter().filter(|word| !word.starts_with('-'));
                let mut value = None;
                while let Some(word) = words.next() {
                    if word.eq_ignore_ascii_case("core.worktree") {
                        value = words.next();
                        break;
                    }
                }
                let Some(value) = value else {
                    return false;
                };
                let base = git_dir.as_deref().unwrap_or(&folder);
                (
                    Effect::Tracked,
                    self.resolve(value, base).into_iter().collect(),
                )
            }
            _ => return false,
        };
        scope.iter().any(|path| {
            spellings(path).iter().any(|path| {
                places.iter().any(|place| {
                    is_within(path, place)
                        || (effect == Effect::Untracked && is_within(place, path))
                })
            })
        })
    }
}

/// The repository git finds from `folder` up, and the folder that holds
/// its `.git`: a `.git` folder, or a `.git` file that names one
/// (`gitdir: <path>`).
fn discover(folder: &Path) -> Option<(PathBuf, PathBuf)> {
    for dir in folder.ancestors().take(DISCOVERY_DEPTH) {
        let dot_git = dir.join(".git");
        let Ok(meta) = std::fs::metadata(&dot_git) else {
            continue;
        };
        if meta.is_dir() {
            return Some((dot_git, dir.to_path_buf()));
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
        return Some((git_dir, dir.to_path_buf()));
    }
    None
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
            "git checkout main",
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
}
