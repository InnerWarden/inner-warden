//! The guard's files reached through a path the line does not spell out
//! whole: a pattern (`rm -f /etc/systemd/system/inner*`), a doubled or
//! dotted folder (`/etc//systemd/./system/...`), a name relative to the
//! folder a `cd` of the line went to, or a whole folder that holds one of
//! them (`rm -rf ~/.config/systemd/user`, `find ... -name 'inner*'
//! -delete`).
//!
//! Measured 2026-11-25 on main 542cc8c and on the branch of pull request
//! #441: each of those forms of removing, moving or editing a unit, the
//! configuration or the program of the guard was allowed, while the same
//! path written whole was refused. The targets of `rm`, `unlink`,
//! `rmdir`, `shred`, `truncate`, `mv`, `find` with `-delete` or a
//! removal it runs, and of the editors [`super::guard_takedown`] reads are
//! now resolved first: each part of the path is compared with the guard's
//! own files, a pattern by what it can match ([`super::glob_names`]).
//! Another program's unit in the same folder, and a pattern that cannot
//! match a name of the guard, stay free.

use super::glob_names::could_be;
use super::{effective_command_index, guard_takedown, program_name};
use crate::shell_words::{read_line, Mark, Word};

/// What [`removal_reaches_guard_file`] says.
pub(super) const GUARD_FILE_REACHED: &str = "removes, moves or edits a file of the guard (its \
     configuration, program or unit) through a pattern, a folder that holds it, a name \
     relative to the folder the line runs in or to a cd of the line, or a HOME the line sets";

/// Concrete files and folders of the guard, as an install lays them out, a
/// home written `~`. A path the line names is compared with each of them,
/// part by part.
const GUARD_FILES: &[&str] = &[
    "/usr/local/bin/innerwarden",
    "/usr/bin/innerwarden",
    "/etc/innerwarden",
    "/etc/innerwarden/guard.toml",
    "/etc/innerwarden/agent.toml",
    "/var/lib/innerwarden",
    "/sys/fs/bpf/innerwarden",
    "/usr/local/lib/innerwarden",
    "/run/innerwarden",
    "/etc/systemd/system/innerwarden-agent.service",
    "/etc/systemd/system/innerwarden-sensor.service",
    "/etc/systemd/system/innerwarden-agent.timer",
    "/etc/systemd/system/multi-user.target.wants/innerwarden-agent.service",
    "/etc/systemd/user/innerwarden-agent.service",
    "~/.config/systemd/user/innerwarden-agent.service",
    "~/.config/systemd/user/innerwarden-agent.timer",
    "~/.config/systemd/user/default.target.wants/innerwarden-agent.service",
    "/etc/sudoers.d/innerwarden",
    "/etc/audit/rules.d/innerwarden.rules",
    "/etc/default/grub.d/99-innerwarden.cfg",
    "/library/launchdaemons/com.innerwarden.agent.plist",
    "/usr/local/etc/innerwarden",
    "/usr/local/var/lib/innerwarden",
    "~/.config/innerwarden",
    "~/.config/innerwarden/config.json",
    "~/.local/bin/innerwarden",
    "~/.cargo/bin/innerwarden",
    "~/.local/share/innerwarden",
    "~/.local/state/innerwarden",
];

/// One part of a path between two `/`, with the shell's marks.
#[derive(Clone, Debug)]
struct Part {
    chars: Vec<char>,
    marks: Vec<Mark>,
}

impl Part {
    fn plain(text: &str) -> Self {
        let chars: Vec<char> = text.chars().collect();
        let marks = vec![Mark::Plain; chars.len()];
        Part { chars, marks }
    }

    fn is(&self, text: &str) -> bool {
        self.marks.iter().all(|mark| *mark == Mark::Plain)
            && self
                .chars
                .iter()
                .collect::<String>()
                .eq_ignore_ascii_case(text)
    }

    /// Whether this part can be the name `name`.
    fn can_be(&self, name: &str) -> bool {
        if self.marks.iter().all(|mark| *mark == Mark::Plain) {
            return self
                .chars
                .iter()
                .collect::<String>()
                .eq_ignore_ascii_case(name);
        }
        could_be(&self.chars, &self.marks, name)
    }
}

/// A path, its first part `/` or `~`.
type Path = Vec<Part>;

/// A path with `.`, empty parts and `..` taken out, and a home under
/// `/home`, `/Users` or `/root` written `~`.
fn normalized(parts: Vec<Part>) -> Path {
    let mut out: Path = Vec::new();
    for part in parts {
        if part.chars.is_empty() || part.is(".") {
            continue;
        }
        if part.is("..") {
            if out.len() > 1 {
                out.pop();
            }
            continue;
        }
        out.push(part);
    }
    if out.first().is_some_and(|root| root.is("/")) {
        if out.get(1).is_some_and(|p| p.is("root")) {
            out.splice(0..2, [Part::plain("~")]);
        } else if out.len() >= 3 && out.get(1).is_some_and(|p| p.is("home") || p.is("users")) {
            out.splice(0..3, [Part::plain("~")]);
        }
    }
    out
}

/// The parts of a path as written, `/` that the shell hands as written
/// splitting them.
fn split(chars: &[char], marks: &[Mark]) -> Vec<Part> {
    let mut parts = Vec::new();
    let mut part = Part {
        chars: Vec::new(),
        marks: Vec::new(),
    };
    for (c, mark) in chars.iter().zip(marks) {
        if *c == '/' && *mark == Mark::Plain {
            parts.push(std::mem::replace(
                &mut part,
                Part {
                    chars: Vec::new(),
                    marks: Vec::new(),
                },
            ));
        } else {
            part.chars.push(*c);
            part.marks.push(*mark);
        }
    }
    parts.push(part);
    parts
}

/// The path a word names, from the folder `cwd` the line went to for a
/// relative one. `None` for a word whose path the text does not give: an
/// expansion other than the home, or a relative name with no folder known.
fn resolve(word: &Word, cwd: Option<&Path>) -> Option<Path> {
    resolve_from(word, cwd, &HomeAs::Account)
}

/// What `~` and `$HOME` stand for where a command of the line runs.
#[derive(Clone, Debug)]
enum HomeAs {
    /// The account's home, written `~`.
    Account,
    /// A folder an earlier command of the line gave `HOME` (`export
    /// HOME=/etc`).
    Set(Path),
    /// A value the text does not give (`read HOME`, `HOME=$(mktemp -d)`).
    Unknown,
}

impl HomeAs {
    fn start(&self) -> Option<Path> {
        match self {
            HomeAs::Account => Some(vec![Part::plain("~")]),
            HomeAs::Set(path) => Some(path.clone()),
            HomeAs::Unknown => None,
        }
    }
}

/// [`resolve`], with `~` and `$HOME` standing for `home`.
fn resolve_from(word: &Word, cwd: Option<&Path>, home: &HomeAs) -> Option<Path> {
    let chars: Vec<char> = word.text.chars().collect();
    let marks = &word.marks;
    if chars.is_empty() || marks.len() != chars.len() {
        return None;
    }
    let text: String = chars.iter().collect();
    let (mut start, skip): (Vec<Part>, usize) = if word.open_tildes.first() == Some(&0) {
        let end = chars.iter().position(|c| *c == '/').unwrap_or(chars.len());
        (home.start()?, end)
    } else if let Some(prefix) = ["${HOME}", "$HOME"].iter().find(|p| text.starts_with(**p)) {
        (home.start()?, prefix.chars().count())
    } else if let Some(prefix) = ["${XDG_CONFIG_HOME}", "$XDG_CONFIG_HOME"]
        .iter()
        .find(|p| text.starts_with(**p))
    {
        (
            vec![Part::plain("~"), Part::plain(".config")],
            prefix.chars().count(),
        )
    } else if chars[0] == '/' {
        (vec![Part::plain("/")], 0)
    } else {
        (cwd?.clone(), 0)
    };
    let rest_chars = &chars[skip..];
    let rest_marks = &marks[skip..];
    if rest_chars.first().is_some_and(|c| *c != '/') && skip > 0 {
        // `$HOMEx`, `~user`: no home this reading knows.
        return None;
    }
    if rest_marks.contains(&Mark::Expansion) {
        return None;
    }
    start.extend(split(rest_chars, rest_marks));
    Some(normalized(start))
}

/// Whether `path` can name the guard's file `file` itself.
fn names(path: &Path, file: &[&str]) -> bool {
    path.len() == file.len() && path.iter().zip(file).all(|(part, name)| part.can_be(name))
}

/// Whether `path` can name a folder that holds the guard's file `file`.
fn holds(path: &Path, file: &[&str]) -> bool {
    path.len() < file.len() && path.iter().zip(file).all(|(part, name)| part.can_be(name))
}

/// Each file of the guard as its names, first `/` or `~`.
fn guard_files() -> impl Iterator<Item = Vec<&'static str>> {
    GUARD_FILES
        .iter()
        .map(|file| match file.strip_prefix("~/") {
            Some(rest) => std::iter::once("~").chain(rest.split('/')).collect(),
            None => std::iter::once("/")
                .chain(file.trim_start_matches('/').split('/'))
                .collect(),
        })
}

/// Whether `path` can name something inside the guard's folder `file`
/// (`/etc/innerwarden/rules`): a file or folder of the guard as well.
fn within(path: &Path, file: &[&str]) -> bool {
    path.len() > file.len() && path.iter().zip(file).all(|(part, name)| part.can_be(name))
}

fn names_guard_file(path: &Path) -> bool {
    guard_files().any(|file| names(path, &file) || within(path, &file))
}

fn names_or_holds_guard_file(path: &Path) -> bool {
    guard_files().any(|file| names(path, &file) || holds(path, &file) || within(path, &file))
}

/// The operands of `rm`-like programs, and whether they remove folders whole.
fn removal_operands(program: &str, args: &[Word]) -> Option<(Vec<Word>, bool)> {
    let mut operands = Vec::new();
    let mut recursive = false;
    let mut rest = args.iter();
    let mut options = true;
    while let Some(word) = rest.next() {
        let text = word.text.as_str();
        if options && text == "--" {
            options = false;
        } else if options && text.starts_with("--") {
            recursive |= text == "--recursive";
            if program == "truncate" && (text == "--size" || text == "--reference") {
                rest.next();
            }
            if program == "mv" && text == "--target-directory" {
                rest.next();
            }
        } else if options && text.starts_with('-') && text.len() > 1 {
            recursive |= program == "rm" && text.contains(['r', 'R']);
            if program == "truncate" && (text == "-s" || text == "-r") {
                rest.next();
            }
            if program == "mv" && text == "-t" {
                rest.next();
            }
        } else {
            operands.push(word.clone());
        }
    }
    match program {
        // A move takes a folder whole; what it lands on is replaced only
        // when that is a file of the guard itself (`removal_reaches_guard_file`).
        "mv" => Some((operands, true)),
        "rm" => Some((operands, recursive)),
        "unlink" | "rmdir" | "shred" | "truncate" => Some((operands, false)),
        _ => None,
    }
}

/// The paths `find` starts from, and whether what it finds under them that
/// can be one of the guard's files is removed.
fn find_reaches(args: &[Word], cwd: Option<&Path>, home: &HomeAs) -> bool {
    let first_expression = args
        .iter()
        .position(|word| {
            word.text.starts_with('-') || word.text == "(" || word.text == "!" || word.text == ")"
        })
        .unwrap_or(args.len());
    let (starts, expression) = args.split_at(first_expression);
    let texts: Vec<&str> = expression.iter().map(|word| word.text.as_str()).collect();
    let removes = texts.contains(&"-delete")
        || texts.windows(2).any(|pair| {
            matches!(pair[0], "-exec" | "-execdir" | "-ok" | "-okdir")
                && matches!(
                    program_name(pair[1]).as_str(),
                    "rm" | "unlink" | "shred" | "truncate" | "mv"
                )
        });
    if !removes || texts.contains(&"-empty") {
        return false;
    }
    // Names it keeps (`-name`, `-iname`): all of them, any of them
    // with `-o`, and none read when `!` or `-not` can turn one around.
    let turned = texts.iter().any(|t| matches!(*t, "!" | "-not"));
    let either = texts.iter().any(|t| matches!(*t, "-o" | "-or"));
    let mut kept: Vec<&Word> = Vec::new();
    for (at, text) in texts.iter().enumerate() {
        if matches!(*text, "-name" | "-iname") {
            kept.extend(expression.get(at + 1));
        }
    }
    let starts: Vec<Path> = if starts.is_empty() {
        cwd.into_iter().cloned().collect()
    } else {
        starts
            .iter()
            .filter_map(|word| resolve_from(word, cwd, home))
            .collect()
    };
    starts.iter().any(|start| {
        guard_files().any(|file| {
            (names(start, &file) || holds(start, &file))
                && (turned || kept.is_empty() || {
                    let matches = |name: &&Word| {
                        let chars: Vec<char> = name.text.chars().collect();
                        // The pattern is find's, not the shell's: every
                        // character of it may still be a pattern.
                        let marks: Vec<Mark> = chars
                            .iter()
                            .map(|c| {
                                if "*?[]".contains(*c) {
                                    Mark::Pattern
                                } else {
                                    Mark::Plain
                                }
                            })
                            .collect();
                        let part = Part { chars, marks };
                        // A name the guard's folders share with other
                        // programs (`config.json`) is read from what
                        // the folders hold elsewhere; here only a part
                        // that carries the guard's own name counts.
                        file[start.len().min(file.len() - 1)..]
                            .iter()
                            .any(|below| below.contains("innerwarden") && part.can_be(below))
                    };
                    if either {
                        kept.iter().any(matches)
                    } else {
                        kept.iter().all(matches)
                    }
                })
        })
    })
}

/// Whether a command of the line removes, moves or edits a file of the
/// guard through a pattern, a folder that holds it, or a name relative to a
/// `cd` of the line.
pub(super) fn removal_reaches_guard_file(content: &str) -> bool {
    removal_reaches_guard_file_from(content, None, None)
}

/// [`removal_reaches_guard_file`] for a line run in the folder `cwd` (the
/// one the hook was given, an absolute path), the account's home being
/// `home` when known: a relative name is read from that folder until a
/// `cd` of the line moves it (`rm -rf innerwarden/rules` run in `/etc`).
/// A folder that is not absolute, or none, leaves a relative name unread,
/// as the line alone does.
///
/// The line is read a second time with `~` and `$HOME` standing for the
/// folder a command of the line gave `HOME` (`export HOME=/etc; rm -rf
/// ~/innerwarden`), its names spelled out first
/// ([`super::names_spelled_out`]: `export {HO,}ME=/etc`): either reading
/// that reaches a file of the guard is enough.
pub(super) fn removal_reaches_guard_file_from(
    content: &str,
    cwd: Option<&str>,
    home: Option<&str>,
) -> bool {
    let lower = content.to_ascii_lowercase();
    if ![
        "rm", "mv", "unlink", "shred", "truncate", "find", "sed", "vi", "ex", "ed", "emacs",
        "perl", "ruby", "awk",
    ]
    .iter()
    .any(|word| lower.contains(word))
    {
        return false;
    }
    let start = cwd
        .filter(|cwd| cwd.starts_with('/'))
        .and_then(|cwd| folder_of(cwd, home));
    if walk(content, start.clone(), false) {
        return true;
    }
    // `HOME` named, or a name the shell may spell out of pieces into it.
    if !lower.contains("home") && !content.contains(['{', '\\']) {
        return false;
    }
    let spelled = super::names_spelled_out(content);
    walk(spelled.as_deref().unwrap_or(content), start, true)
}

/// The path of an absolute folder, under `home` written `~`.
fn folder_of(folder: &str, home: Option<&str>) -> Option<Path> {
    let folder = match home
        .map(|home| home.trim_end_matches('/'))
        .filter(|home| !home.is_empty())
        .and_then(|home| folder.strip_prefix(home))
    {
        Some("") => "~".to_string(),
        Some(rest) if rest.starts_with('/') => format!("~{rest}"),
        _ => folder.to_string(),
    };
    let word = read_line(&shell_quoted_path(&folder))
        .commands
        .into_iter()
        .next()?
        .words
        .into_iter()
        .next()?;
    let word = if folder.starts_with('~') {
        Word {
            open_tildes: vec![0],
            ..word
        }
    } else {
        word
    };
    resolve(&word, None)
}

/// A path written so the shell reads it as one plain word: single quoted,
/// a leading `~` left out of the quotes.
fn shell_quoted_path(path: &str) -> String {
    let (tilde, rest) = match path.strip_prefix('~') {
        Some(rest) => ("~", rest),
        None => ("", path),
    };
    if rest.is_empty() {
        return tilde.to_string();
    }
    format!("{tilde}'{}'", rest.replace('\'', "'\\''"))
}

/// One reading of [`removal_reaches_guard_file_from`]: from the folder
/// `start`, following what the line gives `HOME` when `follow_home`.
fn walk(content: &str, start: Option<Path>, follow_home: bool) -> bool {
    let mut place = Place {
        cwd: start,
        home: HomeAs::Account,
        follow_home,
    };
    // A subshell's `cd` ends with it: the folder each open `(` restores
    // at its `)`, read from the segment's text as
    // `relative_execution_in_temp_directory` reads it.
    let mut subshells: Vec<(Option<Path>, HomeAs)> = Vec::new();
    // The commands as the shell reads the whole line (a here-document's
    // body is no command); the segments only say where a subshell opens
    // and closes, and a command of a segment is read when it is the next
    // command of the line.
    let commands = read_line(content).commands;
    let mut next = 0usize;
    for segment in super::shell_command_segments(content) {
        let head = segment.trim_start();
        let lead: String = head
            .chars()
            .take_while(|c| matches!(c, '(' | '{' | ' ' | '\t'))
            .collect();
        let opens = lead.matches('(').count();
        let rest = &head[lead.len()..];
        let tail: String = rest
            .chars()
            .rev()
            .take_while(|c| matches!(c, ')' | '}' | ' ' | '\t' | ';'))
            .collect();
        let closes = tail
            .matches(')')
            .count()
            .saturating_sub(rest.matches('(').count());
        for _ in 0..opens {
            subshells.push((place.cwd.clone(), place.home.clone()));
        }
        for piece in read_line(rest).commands {
            let Some(command) = commands.get(next) else {
                break;
            };
            if command.words != piece.words {
                continue;
            }
            next += 1;
            if command_reaches(command, &mut place) {
                return true;
            }
        }
        for _ in 0..closes {
            if let Some((cwd, home)) = subshells.pop() {
                place.cwd = cwd;
                place.home = home;
            }
        }
    }
    false
}

/// Where a command of the line runs, as [`walk`] reads it.
struct Place {
    cwd: Option<Path>,
    home: HomeAs,
    follow_home: bool,
}

/// What a command that only sets variables, or `export`, `declare`,
/// `typeset`, `readonly` or `local`, gives `HOME`; `read`, `printf -v`
/// and `mapfile` naming it give a value the text does not hold. `None`
/// when the command leaves `HOME` as it is. A `HOME=` in front of a
/// program sets it for that program alone, after the shell has read the
/// program's words.
fn home_given(command: &crate::shell_words::Command, place: &Place) -> Option<HomeAs> {
    let words = &command.words;
    let first = words.first()?;
    let setter = matches!(
        first.text.as_str(),
        "export" | "declare" | "typeset" | "readonly" | "local"
    );
    let assignments: &[Word] = if setter {
        &words[1..]
    } else if words.iter().all(|word| is_assignment(&word.text)) {
        words
    } else {
        if matches!(
            first.text.as_str(),
            "read" | "printf" | "mapfile" | "readarray"
        ) && words[1..].iter().any(|word| word.text == "HOME")
        {
            return Some(HomeAs::Unknown);
        }
        return None;
    };
    let mut given = None;
    for word in assignments {
        let Some(value) = word.text.strip_prefix("HOME=") else {
            continue;
        };
        let at = "HOME=".chars().count();
        let value_word = Word {
            text: value.to_string(),
            marks: word
                .marks
                .get(at..)
                .map(<[Mark]>::to_vec)
                .unwrap_or_default(),
            open_tildes: word
                .open_tildes
                .iter()
                .filter_map(|tilde| tilde.checked_sub(at))
                .collect(),
            ..Word::default()
        };
        given = Some(
            resolve_from(&value_word, place.cwd.as_ref(), &place.home)
                .map_or(HomeAs::Unknown, HomeAs::Set),
        );
    }
    given
}

/// Whether a word is a shell assignment (`NAME=value`).
fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && !name.starts_with(|c: char| c.is_ascii_digit())
            && name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
    })
}

/// One command of [`removal_reaches_guard_file`]: a `cd` moves `cwd`, a
/// removal, move or edit is read against it.
fn command_reaches(command: &crate::shell_words::Command, place: &mut Place) -> bool {
    if place.follow_home {
        if let Some(home) = home_given(command, place) {
            place.home = home;
            return false;
        }
    }
    let home = place.home.clone();
    let cwd = &mut place.cwd;
    let resolve = |word: &Word, cwd: Option<&Path>| resolve_from(word, cwd, &home);
    let texts: Vec<String> = command.words.iter().map(|word| word.text.clone()).collect();
    let Some(at) = effective_command_index(&texts) else {
        return false;
    };
    let program = program_name(&texts[at]);
    let args = &command.words[at + 1..];
    match program.as_str() {
        "cd" | "pushd" => {
            // `cd -` goes back to a folder the line does not say; `cd`
            // alone goes home.
            let target = args
                .iter()
                .find(|word| word.text == "-" || !word.text.starts_with('-'));
            *cwd = match target {
                None => home.start(),
                Some(word) if word.text == "-" => None,
                Some(word) => resolve(word, cwd.as_ref()),
            };
            return false;
        }
        "find" => {
            if find_reaches(args, cwd.as_ref(), &home) {
                return true;
            }
            return false;
        }
        _ => {}
    }
    if let Some((mut operands, whole)) = removal_operands(&program, args) {
        // The last operand of a move is where it lands: a folder that
        // holds a file of the guard (`mv tool /usr/local/bin/`) only
        // gains one; a file of the guard named whole is replaced.
        let destination = if program == "mv"
            && !args
                .iter()
                .any(|w| w.text == "-t" || w.text.starts_with("--target-directory"))
        {
            operands.pop()
        } else {
            None
        };
        let lands_on_guard = destination
            .and_then(|word| resolve(&word, cwd.as_ref()))
            .is_some_and(|path| names_guard_file(&path));
        let reached = lands_on_guard
            || operands
                .iter()
                .filter_map(|word| resolve(word, cwd.as_ref()))
                .any(|path| {
                    if whole {
                        names_or_holds_guard_file(&path)
                    } else {
                        names_guard_file(&path)
                    }
                });
        if reached {
            return true;
        }
        return false;
    }
    let arg_texts: Vec<String> = args.iter().map(|word| word.text.clone()).collect();
    let edited = guard_takedown::files_an_editor_writes(&program, &arg_texts);
    let reached = edited.iter().any(|file| match file {
        guard_takedown::Edited::Operand(index) => args
            .get(*index)
            .and_then(|word| resolve(word, cwd.as_ref()))
            .is_some_and(|path| names_guard_file(&path)),
        guard_takedown::Edited::Named(name) => {
            let word = crate::shell_words::read_line(name)
                .commands
                .into_iter()
                .next()
                .and_then(|command| command.words.into_iter().next());
            word.and_then(|word| resolve(&word, cwd.as_ref()))
                .is_some_and(|path| names_guard_file(&path))
        }
    });
    if reached {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_read_part_by_part() {
        for line in [
            "rm -f /etc/systemd/system/inner*",
            "rm -f /etc//systemd/./system/innerwarden-agent.service",
            "cd /etc/systemd/system && rm -f innerwarden-agent.service",
            "rm -rf ~/.config/systemd/user",
            "find ~/.config/systemd/user -name 'inner*' -delete",
            "rm -f /home/dev/.config/systemd/user/inner*.service",
        ] {
            assert!(removal_reaches_guard_file(line), "{line}");
        }
        for line in [
            "rm -f ~/.config/systemd/user/my*.service",
            "cd ~/.config/systemd/user && rm -f myapp.service",
            "find ~/.config/systemd/user -name 'myapp*' -delete",
            "rm -f src/inner*.rs",
            "find / -name '*.pyc' -delete",
            "rm -f ~/.config/systemd/user/innerwarden-agent.service.bak",
        ] {
            assert!(!removal_reaches_guard_file(line), "{line}");
        }
    }
}
