//! A patch handed to the patch program on a shell line.
//!
//! Codex CLI puts an `apply_patch` program on the path of the shells it
//! starts, and takes a line such as `apply_patch <<'EOF' ... EOF` out of a
//! shell call to apply the patch itself. The files change either way, and
//! what the hook sees is a shell command: its tool name sends it to the shell
//! rules, which know no writer by that name. [`shell_patch`] reads the files
//! such a line names, so the hook judges them the way it judges the patch
//! tool's ([`crate::file_tools`]).
//!
//! What is read: a patch in a here-document (its text is lines of the command
//! itself) and a patch given as the program's one argument. What cannot be
//! read is said to be unreadable, never passed: a patch from a file or a
//! pipe, one the shell rewrites before the program reads it (a `$` or a
//! backtick outside single quotes), the program started by a program this
//! reader does not follow (`xargs`, `find -exec`, a command substitution),
//! and a relative path after a change of directory that cannot be followed.
//!
//! The program's name is read as the shell reads it: quotes and backslashes
//! taken out, and the line's own assignments read into it. A name the shell
//! still fills in when the line runs, in whole or in part, that may come out
//! as the patch program's is a patch whose program cannot be read. A patch
//! written for any program (`cat > p <<'EOF'`, `printf`) is read for the
//! files it names as well, so a patch that is only applied by a later call
//! is judged where it is written.
//!
//! The line is not parsed as the shell parses it. Every line of it is read
//! both as a command and as patch text, and a relative path is read in every
//! folder the line changes to: the reading errs towards more files judged,
//! never fewer.
//!
//! Pure: no I/O.

use crate::file_tools::patch_paths;
use crate::shell_words::{read_line, Mark, Word};
use crate::threats::{
    assignment_readings, effective_command_index, normalize_command, shell_command_segments,
    shell_tokens, token_basename,
};

/// What a shell line does with the patch program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellPatch {
    /// The line hands the patch program nothing.
    NotAPatch,
    /// The files its patch names: each as written, and a relative one in
    /// every folder the line changes to as well.
    Writes(Vec<String>),
    /// The line runs the patch program on a patch that cannot be read here.
    Unreadable(&'static str),
}

/// What a line that may run the patch program has in it, in lowercase. The
/// last is in [`RUN_AS_PROGRAM`].
const MENTIONS: &[&str] = &["apply_patch", "applypatch", "apply-patch"];

/// The names the patch program is run by.
const PROGRAMS: &[&str] = &["apply_patch", "applypatch"];

/// The flag that makes Codex CLI's own binary run as the patch program, with
/// the patch in the word after it.
const RUN_AS_PROGRAM: &str = "--codex-run-as-apply-patch";

/// What the name of a program file ends with on Windows.
const PROGRAM_SUFFIXES: &[&str] = &[".exe", ".bat", ".cmd"];

/// Shells whose `-c` argument is a line of its own.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh"];

/// Programs that run a command given in their own arguments, which this
/// reader does not follow (`find` only with one of [`FIND_RUNS`]). The
/// launchers [`effective_command_index`] reads (`env`, `sudo`, `nice`,
/// `timeout`, `nohup`, `stdbuf`, `setsid`, `command`, `exec`) are followed to
/// the program they start.
const UNFOLLOWED: &[&str] = &["xargs", "parallel", "watch", "chroot", "flock", "find"];

/// The `find` actions that run a command.
const FIND_RUNS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

/// Options that make a launcher look a name up instead of running it
/// (`command -v`, `sudo -l`).
const LOOKUPS: &[&str] = &["-v", "-V", "-l", "--list", "--version", "-h", "--help"];

/// The first line of a patch.
const BEGIN: &str = "*** Begin Patch";

/// How many shells inside shells are read.
const LINES_DEEP: usize = 3;

/// How many folders one line is followed into.
const DIRECTORIES_FOLLOWED: usize = 64;

/// How many files one line's patches may name.
const FILES_READ: usize = 4096;

/// How many lines inside a line (a substitution, a shell given a line,
/// `eval`) are read for a program name the shell fills in. A line that goes
/// deeper is taken for one whose name may be the patch program's.
const FILLED_IN_DEEP: usize = 16;

const NOT_WRITTEN: &str = "a patch run from the shell whose text is not in the command";
const REWRITTEN: &str = "a patch run from the shell that the shell rewrites first";
const NOT_FOLLOWED: &str =
    "a patch program started from the shell by a program whose input is not read here";
const NO_PATH: &str = "a patch that names a file with no path";
const NO_FILE: &str = "a patch that names no file";
const LOST: &str = "a patch run from the shell after a change of directory that cannot be followed";
const TOO_DEEP: &str = "a patch run from the shell inside more shells than are read";
const TOO_MANY: &str = "a patch run from the shell that names more files than are read";

/// The files a shell line's patch names, when the line hands one to the
/// patch program or holds the text of a patch.
pub fn shell_patch(command: &str) -> ShellPatch {
    // The line as written, then with its own assignments read into it: a
    // program word that is a variable is the patch program when the line
    // makes it one (`p=apply_patch; $p`).
    let (readings, settled) = assignment_readings(command);
    let filled_in = command.contains(['$', '`'])
        && readings
            .iter()
            .any(|reading| names_a_program_filled_in(reading, 0));
    match read_patch(command, &readings, settled) {
        ShellPatch::Unreadable(why) => ShellPatch::Unreadable(why),
        // A program the shell names only when the line runs, which may be
        // the patch program: what the line hands it is not judged here.
        _ if filled_in => ShellPatch::Unreadable(REWRITTEN),
        read => read,
    }
}

/// [`shell_patch`] on the line's `readings` ([`assignment_readings`]):
/// `settled` when the last of them is the line's last form.
fn read_patch(command: &str, readings: &[String], settled: bool) -> ShellPatch {
    let envelope = unquoted_text(command).contains(BEGIN);
    // What the shell makes of a `$` it fills in from the line alone
    // (`${x:-apply_patch}`, `$(echo apply_patch)`).
    let rewritten = command
        .contains(['$', '`'])
        .then(|| normalize_command(command));
    let named = |text: &str| mentions(text) || mentions(&unquoted_text(text));
    let mentioned = readings.iter().any(|reading| named(reading.as_str()));
    if !envelope && !mentioned && !rewritten.as_deref().is_some_and(mentions) {
        return ShellPatch::NotAPatch;
    }
    let mut line = Line {
        envelope,
        ..Line::default()
    };
    for reading in readings {
        line.read_whole(reading);
    }
    // Assignments that name one another past what is read leave the
    // program's name unread on a line that names it.
    if !settled && mentioned {
        line.refuse(REWRITTEN);
    }
    // The text of a patch in a here-document is lines of the command. They
    // are read wherever they stand, and once more with the line continuations
    // taken out, as the shell joins them in a body it expands.
    let joined = command.replace("\\\r\n", "").replace("\\\n", "");
    for text in [command, joined.as_str()] {
        match patch_paths(text) {
            Some(paths) => line.name(paths),
            None => line.refuse(NO_PATH),
        }
    }
    if let Some(why) = line.unreadable {
        return ShellPatch::Unreadable(why);
    }
    // A run only the shell's own rewriting shows: what it is given is not
    // read here.
    if !line.runs {
        if let Some(rewritten) = rewritten.filter(|rewritten| rewritten != command) {
            let mut seen = Line::default();
            seen.read_whole(&rewritten);
            if seen.runs || seen.unreadable.is_some() {
                return ShellPatch::Unreadable(REWRITTEN);
            }
        }
    }
    if line.expanded_body && command.contains(['$', '`']) {
        return ShellPatch::Unreadable(REWRITTEN);
    }
    if line.paths.is_empty() {
        return if line.runs {
            ShellPatch::Unreadable(NO_FILE)
        } else {
            ShellPatch::NotAPatch
        };
    }
    let mut writes: Vec<String> = Vec::new();
    for path in &line.paths {
        // A name the shell puts together (`$HOME/.codex/hooks.json` in a
        // here-document it expands) is not the name written here.
        if path.contains(['$', '`']) {
            return ShellPatch::Unreadable(REWRITTEN);
        }
        let mut places = vec![path.clone()];
        if !rooted(path) {
            if line.lost {
                return ShellPatch::Unreadable(LOST);
            }
            places.extend(line.dirs.iter().map(|dir| format!("{dir}/{path}")));
        }
        for place in places {
            if !writes.contains(&place) {
                writes.push(place);
            }
        }
        if writes.len() > FILES_READ {
            return ShellPatch::Unreadable(TOO_MANY);
        }
    }
    ShellPatch::Writes(writes)
}

/// The text names the patch program somewhere.
fn mentions(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    MENTIONS.iter().any(|mention| lowered.contains(mention))
}

/// The text with what the shell takes out of a word taken out: the line
/// continuations, the quotes and the backslashes. `appl''y_patch`,
/// `apply\_patch` and `"appl"y_patch` all run `apply_patch`.
fn unquoted_text(text: &str) -> String {
    text.replace("\\\r\n", "")
        .replace("\\\n", "")
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect()
}

/// The name a word runs, in lowercase and without its folder or a Windows
/// program suffix.
fn program_name(word: &str) -> String {
    let name = token_basename(word).to_ascii_lowercase();
    let stem = PROGRAM_SUFFIXES
        .iter()
        .find_map(|suffix| name.strip_suffix(*suffix))
        .map(str::to_string);
    stem.unwrap_or(name)
}

/// The word runs the patch program: its name, at the start of a backtick
/// substitution too, or the flag that makes Codex's binary run as it.
fn is_program(word: &str) -> bool {
    word == RUN_AS_PROGRAM
        || PROGRAMS.contains(&program_name(word.trim_start_matches('`')).as_str())
}

/// A command of `text`, or of a line inside it (a substitution, a shell
/// given a line, `eval`), runs a program whose name the shell fills in when
/// the line runs and that may come out as the patch program
/// ([`may_be_the_program`]). Read whole and, at the top, line by line as
/// well, as [`Line::read_whole`] reads. Past [`FILLED_IN_DEEP`] lines inside
/// lines, a line that holds a `$` or a backtick is taken for one that does.
fn names_a_program_filled_in(text: &str, depth: usize) -> bool {
    if !text.contains(['$', '`']) {
        return false;
    }
    if depth > FILLED_IN_DEEP {
        return true;
    }
    let mut texts = vec![text];
    if depth == 0 && text.contains('\n') {
        texts.extend(text.lines());
    }
    texts.into_iter().any(|text| {
        let line = read_line(text);
        line.nested
            .iter()
            .any(|inner| names_a_program_filled_in(inner, depth + 1))
            || line
                .commands
                .iter()
                .any(|command| runs_a_program_filled_in(&command.words, depth))
    })
}

/// One command, as its `words`, runs a program whose name the shell fills
/// in and that may be the patch program: as its own program, or as the
/// program a launcher, a shell, `eval`, `xargs` or `find -exec` starts.
fn runs_a_program_filled_in(words: &[Word], depth: usize) -> bool {
    if depth > FILLED_IN_DEEP {
        return true;
    }
    let texts: Vec<String> = words.iter().map(|word| word.text.clone()).collect();
    // Any word from `from` on.
    let later = |from: usize| words.iter().skip(from).any(may_be_the_program);
    let program = effective_command_index(&texts)
        .filter(|at| texts.get(*at).is_some_and(|word| !word.starts_with('-')));
    let Some(at) = program else {
        // A launcher whose options are not read here: a later word may be
        // what it runs, unless the launcher only looks a name up first. A
        // line of assignments alone runs nothing.
        return words.iter().enumerate().any(|(at, word)| {
            !is_assignment(&word.text)
                && may_be_the_program(word)
                && !texts[..at]
                    .iter()
                    .any(|text| LOOKUPS.contains(&text.as_str()))
        });
    };
    let Some(word) = words.get(at) else {
        return false;
    };
    if may_be_the_program(word) {
        return true;
    }
    let name = program_name(&word.text);
    let arguments = &texts[at + 1..];
    match name.as_str() {
        "find" => arguments
            .iter()
            .position(|word| FIND_RUNS.contains(&word.as_str()))
            .is_some_and(|run| later(at + 1 + run)),
        // The command `xargs` runs, read as a command of its own, or any
        // word after an option of its own that is not read here.
        "xargs" => match xargs_command(arguments) {
            Some(command) => runs_a_program_filled_in(&words[at + 1 + command..], depth + 1),
            None => later(at + 1),
        },
        _ => match line_run_by(&name, arguments) {
            Some(inner) => names_a_program_filled_in(&inner, depth + 1),
            None => UNFOLLOWED.contains(&name.as_str()) && later(at + 1),
        },
    }
}

/// The line a shell given one (`-c`), or `eval`, runs, from its arguments.
fn line_run_by(name: &str, arguments: &[String]) -> Option<String> {
    if name == "eval" {
        Some(arguments.join(" "))
    } else if SHELLS.contains(&name) {
        command_string(arguments).map(str::to_string)
    } else {
        None
    }
}

/// The word sets a variable (`NAME=value`) rather than naming a program.
fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        name.chars().enumerate().all(|(at, c)| {
            c == '_' || (c.is_ascii_alphanumeric() && (at > 0 || !c.is_ascii_digit()))
        }) && !name.is_empty()
    })
}

/// One part of a program's name as the shell will make it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Piece {
    /// A character handed over as written, in lowercase.
    Written(char),
    /// Text the shell fills in when the line runs: a variable, a
    /// substitution. It may hold a folder, so the name may start inside it.
    Filled,
    /// A pattern the shell may expand: a glob, a brace list.
    Pattern,
}

/// A program word the shell fills in when the line runs, in whole or in
/// part, that may come out as the patch program: the part filled in names
/// the program, or the text written out beside it is all in the program's
/// name, in its order, around what is filled in. A word with nothing written
/// out of the name (`$EDITOR`, `${TOOL}.exe`) may be any program at all, and
/// is not one.
fn may_be_the_program(word: &Word) -> bool {
    let (chars, marks) = word.last_component();
    if !marks.contains(&Mark::Expansion) {
        return false;
    }
    let text = chars.iter().collect::<String>().to_ascii_lowercase();
    if PROGRAMS.iter().any(|program| text.contains(program)) {
        return true;
    }
    let mut pieces = pieces_of(&chars, &marks);
    // A Windows program suffix written out after it is no part of the name.
    for suffix in PROGRAM_SUFFIXES {
        let tail: Vec<Piece> = suffix.chars().map(Piece::Written).collect();
        if pieces.ends_with(&tail) {
            pieces.truncate(pieces.len() - tail.len());
            break;
        }
    }
    // The name starts at the start of the word, or inside a part filled in.
    (0..pieces.len())
        .filter(|start| *start == 0 || pieces[*start] == Piece::Filled)
        .map(|start| &pieces[start..])
        .filter(|from| from.iter().any(|piece| matches!(piece, Piece::Written(_))))
        .any(|from| PROGRAMS.iter().any(|program| spells(from, program)))
}

/// The pieces of a program's name as written: each character written out,
/// each run of characters filled in, and the whole stretch from the first
/// pattern character to the last as one pattern (a brace list puts any of
/// its members there).
fn pieces_of(chars: &[char], marks: &[Mark]) -> Vec<Piece> {
    let first = marks.iter().position(|mark| *mark == Mark::Pattern);
    let last = marks.iter().rposition(|mark| *mark == Mark::Pattern);
    let mut pieces: Vec<Piece> = Vec::new();
    for (at, (c, mark)) in chars.iter().zip(marks).enumerate() {
        let in_pattern =
            first.is_some_and(|first| at >= first) && last.is_some_and(|last| at <= last);
        let piece = if in_pattern {
            Piece::Pattern
        } else if *mark == Mark::Expansion {
            Piece::Filled
        } else {
            Piece::Written(c.to_ascii_lowercase())
        };
        if matches!(piece, Piece::Written(_)) || pieces.last() != Some(&piece) {
            pieces.push(piece);
        }
    }
    pieces
}

/// The pieces can make `name` exactly: each character written out is the
/// name's next one, and a part filled in or a pattern stands for any run of
/// characters, none included.
fn spells(pieces: &[Piece], name: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    // `reached[n]`: the pieces so far can make the first `n` characters.
    let mut reached = vec![false; name.len() + 1];
    reached[0] = true;
    for piece in pieces {
        match piece {
            Piece::Written(c) => {
                for at in (0..name.len()).rev() {
                    reached[at + 1] = reached[at] && name[at] == *c;
                }
                reached[0] = false;
            }
            Piece::Filled | Piece::Pattern => {
                let mut any = false;
                for slot in reached.iter_mut() {
                    any |= *slot;
                    *slot = any;
                }
            }
        }
    }
    reached[name.len()]
}

/// The patch program is run inside a command substitution, a process
/// substitution or backticks: what it is given there is not read.
fn runs_in_a_substitution(words: &[String]) -> bool {
    words.iter().enumerate().any(|(at, word)| {
        is_program(word)
            && (word.starts_with('`')
                || at
                    .checked_sub(1)
                    .and_then(|before| words.get(before))
                    .is_some_and(|before| before.ends_with(['$', '<', '>'])))
    })
}

/// A launcher whose options are not read here names the patch program after
/// them, and does not only look the name up.
fn launched_unread(words: &[String]) -> bool {
    let Some(at) = words.iter().position(|word| is_program(word)) else {
        return false;
    };
    !words[..at]
        .iter()
        .any(|word| LOOKUPS.contains(&word.as_str()))
}

/// `name` is in [`UNFOLLOWED`], and the command it runs is the patch
/// program.
///
/// `xargs` runs its first word that is no option of its own, so the name
/// later on is an argument of that command (`xargs grep apply_patch`). That
/// command is read past the launchers the guard reads; when it is a shell
/// or `eval`, or an option of `xargs` is not one read here, the name counts.
fn launches(name: &str, arguments: &[String], segment: &str) -> bool {
    let Some(at) = arguments.iter().position(|word| is_program(word)) else {
        return false;
    };
    match name {
        "find" => arguments[..at]
            .iter()
            .any(|word| FIND_RUNS.contains(&word.as_str())),
        "xargs" => {
            // The words with their braces: `shell_tokens` drops a brace, and
            // `-I{}` is how a replacement string is written.
            let words = crate::threats::shell_tokens_with_braces(segment);
            let Some(start) = words.iter().position(|word| program_name(word) == "xargs") else {
                return true;
            };
            let arguments = &words[start + 1..];
            // An option not read here, or one missing its value at the end,
            // leaves no command.
            let Some(command) = xargs_command(arguments) else {
                return true;
            };
            let rest = arguments.get(command..).unwrap_or_default();
            let Some(effective) = effective_command_index(rest) else {
                return true;
            };
            rest.get(effective).is_none_or(|word| {
                let program = program_name(word);
                is_program(word) || SHELLS.contains(&program.as_str()) || program == "eval"
            })
        }
        _ => true,
    }
}

/// Where the command `xargs` runs starts in its `arguments`: the first word
/// that is neither one of its options nor an option's value. `None` when an
/// option is not one read here, and when no word is left for a command.
///
/// One pass over the words, with no count to step: a value is taken by
/// taking the next word, so no change to a step can make the reading run on
/// without end.
fn xargs_command(arguments: &[String]) -> Option<usize> {
    // Options that take a value, attached or in the next word.
    const VALUED: &str = "adEILnPs";
    // Options that take none (`-e`, `-i` and `-l` take one only attached).
    const FLAGS: &str = "0prtxeil";
    const LONG_FLAGS: &[&str] = &[
        "null",
        "no-run-if-empty",
        "verbose",
        "interactive",
        "open-tty",
        "exit",
        "show-limits",
    ];
    let mut words = arguments.iter().enumerate();
    while let Some((at, word)) = words.next() {
        if word == "--" {
            return Some(at + 1);
        }
        if let Some(long) = word.strip_prefix("--") {
            if !(long.contains('=') || LONG_FLAGS.contains(&long)) {
                return None;
            }
            continue;
        }
        let Some(short) = word.strip_prefix('-').filter(|short| !short.is_empty()) else {
            return Some(at);
        };
        let mut letters = short.chars();
        while let Some(letter) = letters.next() {
            if VALUED.contains(letter) {
                // Its value is the rest of the word, or the next word.
                if letters.as_str().is_empty() {
                    words.next();
                }
                break;
            }
            if matches!(letter, 'e' | 'i' | 'l') {
                // Its optional value is the rest of the word.
                break;
            }
            if !FLAGS.contains(letter) {
                return None;
            }
        }
    }
    None
}

/// A path that starts at the root of a file system, a drive or a share. The
/// patch program reads every other one, a `~` one included, from the folder
/// it runs in.
fn rooted(path: &str) -> bool {
    let bytes = path.as_bytes();
    path.starts_with(['/', '\\'])
        || (bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':')
}

/// What is known of one line as it is read.
#[derive(Default)]
struct Line {
    /// A command on it runs the patch program.
    runs: bool,
    /// The files its patches name, each once.
    paths: Vec<String>,
    /// Every folder a `cd` or a `pushd` on it names, in any reading of it.
    /// The text does not say which of them the patch program runs in, so a
    /// relative path is read in each.
    dirs: Vec<String>,
    /// It changes to a folder that cannot be followed.
    lost: bool,
    /// A here-document the shell expands feeds the patch program.
    expanded_body: bool,
    /// It holds the first line of a patch: every word of it is read as patch
    /// text too, whatever program it is handed to.
    envelope: bool,
    /// Why its patch cannot be read, once that is known.
    unreadable: Option<&'static str>,
}

impl Line {
    fn refuse(&mut self, why: &'static str) {
        self.unreadable.get_or_insert(why);
    }

    fn name(&mut self, paths: Vec<String>) {
        for path in paths {
            if self.paths.len() > FILES_READ {
                return self.refuse(TOO_MANY);
            }
            if !self.paths.contains(&path) {
                self.paths.push(path);
            }
        }
    }

    /// Read `text` whole, and each of its lines on its own: the body of a
    /// here-document can leave a quote open over the commands after it. Each
    /// reading follows its own changes of directory from where the line
    /// starts.
    fn read_whole(&mut self, text: &str) {
        self.read(text, 0, &mut Vec::new());
        if text.contains('\n') {
            for one in text.lines() {
                self.read(one, 0, &mut Vec::new());
            }
        }
    }

    /// Read the commands of `text`: the ones that run the patch program, the
    /// ones that change directory, and the shells that are given a line.
    /// `here` holds the folders this reading has changed to so far.
    fn read(&mut self, text: &str, depth: usize, here: &mut Vec<String>) {
        if depth > LINES_DEEP {
            return self.refuse(TOO_DEEP);
        }
        for segment in shell_command_segments(text) {
            let words = shell_tokens(segment);
            if self.envelope {
                self.name_in_words(&words);
            }
            if runs_in_a_substitution(&words) {
                self.refuse(NOT_FOLLOWED);
            }
            let Some(at) = effective_command_index(&words) else {
                // A launcher whose options are not read here.
                if launched_unread(&words) {
                    self.refuse(NOT_FOLLOWED);
                }
                continue;
            };
            let Some(word) = words.get(at) else {
                continue;
            };
            let name = program_name(word);
            let arguments = &words[at + 1..];
            if PROGRAMS.contains(&name.as_str()) {
                self.patch_command(segment, arguments);
            } else if let Some(flag) = arguments.iter().position(|word| word == RUN_AS_PROGRAM) {
                self.patch_command(segment, &arguments[flag + 1..]);
            } else if matches!(name.as_str(), "cd" | "pushd") {
                self.change_directory(arguments, here);
            } else if name.starts_with('-') {
                // A launcher was read up to an option it does not know.
                if launched_unread(&words) {
                    self.refuse(NOT_FOLLOWED);
                }
            } else if UNFOLLOWED.contains(&name.as_str()) {
                if launches(&name, arguments, segment) {
                    self.refuse(NOT_FOLLOWED);
                }
            } else {
                let nested = if name == "eval" {
                    Some(arguments.join(" "))
                } else if SHELLS.contains(&name.as_str()) {
                    command_string(arguments).map(str::to_string)
                } else {
                    None
                };
                if let Some(nested) = nested.filter(|nested| mentions(nested)) {
                    // The shell that starts it reads its text first.
                    if rewrites(segment).words {
                        self.refuse(REWRITTEN);
                    }
                    // It starts in the folder this line is in.
                    self.read(&nested, depth + 1, &mut here.clone());
                }
            }
        }
    }

    /// The words of a line that holds the first line of a patch, read as
    /// patch text: as the shell hands them over, and with each `\n` that a
    /// program such as `printf` turns into a line end.
    fn name_in_words(&mut self, words: &[String]) {
        for word in words.iter().filter(|word| word.contains("*** ")) {
            for text in [word.clone(), word.replace("\\n", "\n")] {
                match patch_paths(&text) {
                    Some(paths) => self.name(paths),
                    None => self.refuse(NO_PATH),
                }
            }
        }
    }

    /// One command that runs the patch program: its patch is a
    /// here-document, whose text the lines of the command hold, or its one
    /// argument.
    fn patch_command(&mut self, segment: &str, arguments: &[String]) {
        self.runs = true;
        let (words, here_document) = given(arguments);
        let rewrites = rewrites(segment);
        if rewrites.words {
            return self.refuse(REWRITTEN);
        }
        match words.as_slice() {
            [] if here_document => self.expanded_body |= rewrites.body,
            [patch] if !here_document && patch.trim_start().starts_with(BEGIN) => {
                match patch_paths(patch) {
                    Some(paths) => self.name(paths),
                    None => self.refuse(NO_PATH),
                }
            }
            // From a file, a pipe or a here-string, or with more words than
            // the program takes.
            _ => self.refuse(NOT_WRITTEN),
        }
    }

    /// One `cd` or `pushd`: the folder it names, read in each folder this
    /// reading changed to before it when it is relative. Joined once: a
    /// second reading of the same line starts again from where it starts.
    fn change_directory(&mut self, arguments: &[String], here: &mut Vec<String>) {
        let (words, _) = given(arguments);
        let dir = words
            .iter()
            .copied()
            .find(|word| *word == "-" || !word.starts_with('-'))
            .unwrap_or("~");
        // `cd -` goes where the shell was before, another account's home is
        // not known here, the shell fills in a `$` or a backtick, and a glob
        // names whatever folders match it.
        let home = dir == "~" || dir.starts_with("~/");
        if dir == "-" || dir.contains(['$', '`', '*', '?', '[']) || (dir.starts_with('~') && !home)
        {
            self.lost = true;
            return;
        }
        let mut named = vec![dir.to_string()];
        if !home && !rooted(dir) {
            named.extend(here.iter().map(|before| format!("{before}/{dir}")));
        }
        for dir in named {
            if !here.contains(&dir) {
                here.push(dir.clone());
            }
            if self.dirs.contains(&dir) {
                continue;
            }
            if self.dirs.len() == DIRECTORIES_FOLLOWED {
                self.lost = true;
                return;
            }
            self.dirs.push(dir);
        }
    }
}

/// The words a command is given, without the redirections that stand among
/// them, and whether one of those is a here-document. An operator that
/// stands alone has its word after it, which is taken with it: one pass over
/// the words, with no count to step.
fn given(arguments: &[String]) -> (Vec<&str>, bool) {
    let mut words = Vec::new();
    let mut here_document = false;
    let mut arguments = arguments.iter();
    while let Some(argument) = arguments.next() {
        let operator = argument.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
        if operator.starts_with(['<', '>']) {
            here_document =
                here_document || (operator.starts_with("<<") && !operator.starts_with("<<<"));
            let target = operator.trim_start_matches(['<', '>', '|', '&']);
            if target.is_empty() || (target == "-" && operator.starts_with("<<")) {
                arguments.next();
            }
        } else {
            words.push(argument.as_str());
        }
    }
    (words, here_document)
}

/// The line a shell is given to run: the word after its `-c`.
fn command_string(arguments: &[String]) -> Option<&str> {
    let flag = arguments.iter().position(|word| {
        word.strip_prefix('-')
            .is_some_and(|flags| !flags.starts_with('-') && flags.contains('c'))
    })?;
    arguments.get(flag + 1).map(String::as_str)
}

/// What the shell rewrites in a command before the program reads it.
#[derive(Default)]
struct Rewrites {
    /// A `$` or a backtick outside single quotes in the command's own words.
    words: bool,
    /// A here-document whose delimiter is not quoted: the shell expands its
    /// body as well.
    body: bool,
}

/// One pass over the bytes: a byte the reading skips (the one after a
/// backslash, the quote of `$'` and `$"`, a here-document's delimiter) is
/// taken from the same iterator, with no count to step, so no change to a
/// step can make the reading run on without end.
fn rewrites(segment: &str) -> Rewrites {
    let mut bytes = segment.bytes().peekable();
    let mut found = Rewrites::default();
    // The quote the text is in: `'`, `"`, or `$` for `$'...'`.
    let mut quote: Option<u8> = None;
    while let Some(byte) = bytes.next() {
        let next = bytes.peek().copied();
        match (quote, byte) {
            (Some(b'\''), b'\'') => quote = None,
            (Some(b'\''), _) => {}
            (Some(b'$'), b'\\') => {
                bytes.next();
            }
            (Some(b'$'), b'\'') => quote = None,
            (Some(b'$'), _) => {}
            (_, b'\\') => {
                bytes.next();
            }
            (Some(_), b'"') => quote = None,
            (None, b'\'') => quote = Some(b'\''),
            (None, b'"') => quote = Some(b'"'),
            (None, b'$') if next == Some(b'\'') => {
                quote = Some(b'$');
                bytes.next();
            }
            (None, b'$') if next == Some(b'"') => {
                quote = Some(b'"');
                bytes.next();
            }
            (_, b'$' | b'`') => found.words = true,
            (None, b'<') if next == Some(b'<') => {
                bytes.next();
                if bytes.peek() == Some(&b'<') {
                    // A here-string: its word is read like any other.
                    continue;
                }
                bytes.next_if_eq(&b'-');
                while bytes.next_if(|b| matches!(b, b' ' | b'\t')).is_some() {}
                // Quoted in any part, the delimiter makes the body text the
                // shell leaves alone.
                let mut quoted = false;
                while let Some(b) = bytes.next_if(|b| !b.is_ascii_whitespace()) {
                    quoted = quoted || matches!(b, b'\'' | b'"' | b'\\');
                }
                if !quoted {
                    found.body = true;
                }
            }
            _ => {}
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The patch of a here-document, with `header` as the line that runs it.
    fn here(header: &str, files: &[&str]) -> String {
        let mut command = format!("{header}\n*** Begin Patch\n");
        for file in files {
            command.push_str(&format!("*** Update File: {file}\n@@\n-a\n+b\n"));
        }
        command.push_str("*** End Patch\nEOF\n");
        command
    }

    fn writes(paths: &[&str]) -> ShellPatch {
        ShellPatch::Writes(paths.iter().map(|path| path.to_string()).collect())
    }

    /// A patch in a here-document is read for the files it names, however
    /// the program is named and the here-document is opened. Its body is
    /// data: a `$` in it changes nothing when the delimiter is quoted.
    ///
    /// FAILS ON REVERT: drop the loop over `[command, joined.as_str()]` in
    /// `shell_patch` and each line names no file, so it is unreadable.
    #[test]
    fn a_patch_in_a_here_document_is_read_for_the_files_it_names() {
        for header in [
            "apply_patch <<'EOF'",
            "apply_patch << 'EOF'",
            "apply_patch <<-'EOF'",
            "apply_patch <<\"EOF\"",
            "apply_patch <<EOF",
            "applypatch <<'EOF'",
            "/tmp/codex/apply_patch <<'EOF'",
            "env LANG=C apply_patch <<'EOF' 2>&1",
            "true && apply_patch <<'EOF'",
            "sudo -n apply_patch <<'EOF'",
        ] {
            assert_eq!(
                shell_patch(&here(header, &["/home/dev/.codex/hooks.json", "src/a.rs"])),
                writes(&["/home/dev/.codex/hooks.json", "src/a.rs"]),
                "{header}"
            );
        }
        let script = "apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: run.sh\n@@\n-echo $HOME\n+echo \"$HOME\"\n*** End Patch\nEOF\n";
        assert_eq!(shell_patch(script), writes(&["run.sh"]));
    }

    /// After a change of directory on the line a relative path is read in
    /// the folder the line went to, and in each of them when it names more
    /// than one. A relative folder is joined once to each folder before it:
    /// the line is read more than once, and no shell reads `app/app`.
    ///
    /// FAILS ON REVERT: drop the `"cd" | "pushd"` arm of `Line::read` and
    /// each patch names its file as written alone; join a relative folder to
    /// `self.dirs` instead of `here` in `Line::change_directory` and the
    /// third line also names `app/app/a.rs` and `/srv/app/app/a.rs`; start
    /// the nested reading with no folder instead of `here.clone()` and the
    /// last loses `/srv/app/a.rs`; read `&&` as `||` in the test of the
    /// folder in `Line::change_directory` and a rooted folder is joined to
    /// the one before it too (`/srv//etc/a.rs`).
    #[test]
    fn a_patch_after_a_change_of_directory_is_read_in_that_folder() {
        assert_eq!(
            shell_patch(&here("cd ~/.codex && apply_patch <<'EOF'", &["hooks.json"])),
            writes(&["hooks.json", "~/.codex/hooks.json"])
        );
        assert_eq!(
            shell_patch(&here(
                "(cd -- '/srv/my app' && apply_patch <<'EOF'",
                &["a.rs", "/etc/b"]
            )),
            writes(&["a.rs", "/srv/my app/a.rs", "/etc/b"])
        );
        assert_eq!(
            shell_patch(&here("cd /srv; pushd app; apply_patch <<'EOF'", &["a.rs"])),
            writes(&["a.rs", "/srv/a.rs", "app/a.rs", "/srv/app/a.rs"])
        );
        assert_eq!(
            shell_patch(&here("cd && apply_patch <<'EOF'", &[".zshrc"])),
            writes(&[".zshrc", "~/.zshrc"])
        );
        // A path rooted on a drive is not placed in the folder the line went
        // to (FAILS ON REVERT: read `>=` as `<` in `rooted`).
        assert_eq!(
            shell_patch(&here(
                "cd /srv && apply_patch <<'EOF'",
                &["C:/Users/me/.codex/hooks.json"]
            )),
            writes(&["C:/Users/me/.codex/hooks.json"])
        );
        // A rooted folder is where the line goes, whatever folder it was in.
        assert_eq!(
            shell_patch(&here(
                "cd /srv && cd /etc && apply_patch <<'EOF'",
                &["a.rs"]
            )),
            writes(&["a.rs", "/srv/a.rs", "/etc/a.rs"])
        );
        // A shell given a line starts in the folder the line went to.
        let nested = "cd /srv && bash -c 'cd app && apply_patch \"*** Begin Patch\n*** Delete File: a.rs\n*** End Patch\"'";
        assert_eq!(
            shell_patch(nested),
            writes(&["a.rs", "/srv/a.rs", "app/a.rs", "/srv/app/a.rs"])
        );
    }

    /// A folder that is a glob names whatever folders match it: a relative
    /// path after it cannot be placed, and a rooted one still can.
    ///
    /// FAILS ON REVERT: take `'*', '?', '['` out of the test for a lost
    /// folder in `Line::change_directory` and each of the first three names
    /// a folder whose name is the glob.
    #[test]
    fn a_change_of_directory_to_a_glob_cannot_be_followed() {
        for header in [
            "cd src/* && apply_patch <<'EOF'",
            "cd /srv/app? && apply_patch <<'EOF'",
            "pushd ~/.c[o]dex && apply_patch <<'EOF'",
        ] {
            assert_eq!(
                shell_patch(&here(header, &["hooks.json"])),
                ShellPatch::Unreadable(LOST),
                "{header}"
            );
        }
        assert_eq!(
            shell_patch(&here("cd src/* && apply_patch <<'EOF'", &["/etc/x"])),
            writes(&["/etc/x"])
        );
    }

    /// A patch given as the program's one argument is read from the word the
    /// shell hands it.
    ///
    /// FAILS ON REVERT: drop the `[patch]` arm of `Line::patch_command` and
    /// each is a patch whose text is not in the command.
    #[test]
    fn a_patch_given_as_an_argument_is_read() {
        let quoted = "apply_patch '*** Begin Patch\n*** Add File: src/new.rs\n+x\n*** End Patch'";
        assert_eq!(shell_patch(quoted), writes(&["src/new.rs"]));
        // `$'...'` holds its line ends as escapes: no line of the command
        // starts with a marker, and the word the shell makes of it does.
        let escaped =
            "apply_patch $'*** Begin Patch\\n*** Delete File: /home/dev/.bashrc\\n*** End Patch'";
        assert_eq!(shell_patch(escaped), writes(&["/home/dev/.bashrc"]));
        let run_as = "codex --codex-run-as-apply-patch $'*** Begin Patch\\n*** Delete File: /home/dev/.zshrc\\n*** End Patch'";
        assert_eq!(shell_patch(run_as), writes(&["/home/dev/.zshrc"]));
    }

    /// The program's name is read as the shell reads it: quotes and
    /// backslashes out, the line's own assignments in, and what the shell
    /// fills in from the line alone. A variable the line does not set is no
    /// patch program.
    ///
    /// FAILS ON REVERT: test only `mentions(reading)` in the gate of
    /// `shell_patch` (no `unquoted_text`) and the first three are not a
    /// patch; read only the line as written (the first of `readings`) and
    /// the fourth and fifth are not; drop the second reading of a
    /// `rewritten` line and the sixth is not. Read `||` as `&&` in the test
    /// of that second reading and a run only the rewriting shows, of a patch
    /// it can read, names the patch's file as if the line ran nothing; have
    /// `mentions` answer yes for every text and a shell line with a `$` and
    /// no patch program in it is unreadable; drop the `!` before the test of
    /// the rewritten line in the gate and a here-document that holds a bare
    /// patch marker, and nothing else of a patch, is read as a patch that
    /// names a file with no path.
    #[test]
    fn a_patch_program_named_through_quotes_or_a_variable_is_read() {
        for command in [
            "appl''y_patch < /tmp/change.patch",
            "apply\\_patch < /tmp/change.patch",
            "\"appl\"y_patch < /tmp/change.patch",
            "p=apply_patch; $p < /tmp/change.patch",
            "a=apply; ${a}_patch < /tmp/change.patch",
        ] {
            assert_eq!(
                shell_patch(command),
                ShellPatch::Unreadable(NOT_WRITTEN),
                "{command}"
            );
        }
        assert_eq!(
            shell_patch("${x:-apply_patch} < /tmp/change.patch"),
            ShellPatch::Unreadable(REWRITTEN)
        );
        // No patch program named and no patch begun: a bare marker in a
        // here-document is text, not a patch with no path.
        assert_eq!(
            shell_patch("cat <<'EOF'\n*** Delete File:\nEOF\n"),
            ShellPatch::NotAPatch
        );
        assert_eq!(
            shell_patch(
                "${x:-apply_patch} '*** Begin Patch\n*** Delete File: /home/dev/.bashrc\n*** End Patch'"
            ),
            ShellPatch::Unreadable(REWRITTEN)
        );
        // Split by quotes, a here-document's patch is read for its files.
        assert_eq!(
            shell_patch(&here(
                "appl''y_patch <<'EOF'",
                &["/home/dev/.codex/hooks.json"]
            )),
            writes(&["/home/dev/.codex/hooks.json"])
        );
        for command in [
            "$APPLY < /tmp/apply_patch.diff",
            "grep -rn 'appl''y_patch' docs/",
            "bash -c \"echo $HOME\"",
        ] {
            assert_eq!(shell_patch(command), ShellPatch::NotAPatch, "{command}");
        }
    }

    /// A patch written for any program is read for the files it names: the
    /// call that writes it is judged as the call that would apply it.
    ///
    /// FAILS ON REVERT: take `envelope` out of the gate of `shell_patch` and
    /// none of these names the patch program, so each is not a patch; drop
    /// the `self.envelope` call of `Line::name_in_words` and the two
    /// `printf` lines name no file; drop the `$` test on a named path and the
    /// last names `$HOME/.codex/hooks.json` as a relative file.
    #[test]
    fn a_patch_written_for_any_program_is_read_for_the_files_it_names() {
        let hooks = "/home/dev/.codex/hooks.json";
        for command in [
            format!(
                "cat > /tmp/p.patch <<'EOF'\n*** Begin Patch\n*** Update File: {hooks}\n@@\n-a\n+b\n*** End Patch\nEOF\n"
            ),
            format!(
                "printf '*** Begin Patch\\n*** Delete File: {hooks}\\n*** End Patch\\n' > /tmp/p.patch"
            ),
            format!(
                "printf '%s\\n' '*** Begin Patch' '*** Delete File: {hooks}' '*** End Patch' > /tmp/p"
            ),
        ] {
            assert_eq!(shell_patch(&command), writes(&[hooks]), "{command}");
        }
        let project = "cat > notes.md <<'EOF'\n*** Begin Patch\n*** Add File: src/new.rs\n+x\n*** End Patch\nEOF\n";
        assert_eq!(shell_patch(project), writes(&["src/new.rs"]));
        let expanded = "cat > /tmp/p <<EOF\n*** Begin Patch\n*** Update File: $HOME/.codex/hooks.json\n@@\n-a\n+b\n*** End Patch\nEOF\n";
        assert_eq!(shell_patch(expanded), ShellPatch::Unreadable(REWRITTEN));
    }

    /// The patch program started by a program this reader does not follow
    /// is unreadable; the same program started by a launcher it reads is
    /// read; a launcher that only looks the name up runs nothing.
    ///
    /// FAILS ON REVERT: drop the `UNFOLLOWED` arm of `Line::read` and the
    /// first two are not a patch; drop the `runs_in_a_substitution` test and
    /// the third and fourth are not; drop the two `launched_unread` tests
    /// and the fifth and sixth are not. Read `||` as `&&` in the test of a
    /// long option in `xargs_command` and `--null` and `--max-args=1` are
    /// options not read here, so a search for the name is unreadable; drop
    /// the shell or `eval` from the last test in `launches` and the patch
    /// program a shell or `eval` runs under `xargs` is not a patch; hand
    /// back the place of `--` itself (or the one before it) for the command
    /// after it and the patch program after `--` is not a patch.
    #[test]
    fn a_patch_program_started_by_a_program_not_followed_is_unreadable() {
        for command in [
            "ls *.patch | xargs -n1 apply_patch",
            "find . -name '*.patch' -exec apply_patch {} \\;",
            "echo $(apply_patch < /tmp/p)",
            "echo `apply_patch < /tmp/p`",
            "sudo --bogus apply_patch < /tmp/p",
            "nice -z apply_patch < /tmp/p",
        ] {
            assert_eq!(
                shell_patch(command),
                ShellPatch::Unreadable(NOT_FOLLOWED),
                "{command}"
            );
        }
        assert_eq!(
            shell_patch("timeout 30 apply_patch < /tmp/p"),
            ShellPatch::Unreadable(NOT_WRITTEN)
        );
        for command in [
            "find . -name apply_patch",
            "sudo grep apply_patch notes.md",
            "xargs grep -l TODO < files.txt",
            "git ls-files | xargs grep -n apply_patch",
            "xargs -0 grep -l apply_patch < files.txt",
            "xargs -I{} grep apply_patch {} < files.txt",
            "xargs -n 1 rg apply_patch < files.txt",
            "git ls-files -z | xargs --null grep -l apply_patch",
            "xargs --max-args=1 grep apply_patch < files.txt",
        ] {
            assert_eq!(shell_patch(command), ShellPatch::NotAPatch, "{command}");
        }
        // The patch program as the command xargs runs, behind a launcher, a
        // shell, or an option not read here, stays unreadable.
        for command in [
            "ls *.patch | xargs -n1 apply_patch",
            "ls *.patch | xargs sudo apply_patch",
            "ls *.patch | xargs --max-args 1 apply_patch",
            "ls *.patch | xargs -Q apply_patch",
            "ls *.patch | xargs bash -c apply_patch",
            "ls *.patch | xargs eval apply_patch",
            "ls *.patch | xargs -- apply_patch",
            "ls *.patch | xargs -n 1 apply_patch",
            // An option with no value at the end: no command, no panic.
            "ls | xargs -a apply_patch -n",
        ] {
            assert_eq!(
                shell_patch(command),
                ShellPatch::Unreadable(NOT_FOLLOWED),
                "{command}"
            );
        }
    }

    /// A shell given a line is read for the line: the patch program in it
    /// and the folder it goes to first.
    ///
    /// FAILS ON REVERT: drop `self.read(&nested, depth + 1, ..)` in
    /// `Line::read` and the folder inside the quoted line is never followed,
    /// so the file is named as written alone; read `&&` as `||` in
    /// `command_string` and `-l` is taken for the flag of the line, so the
    /// second is read without its folder.
    #[test]
    fn a_patch_inside_a_shell_given_a_line_is_read() {
        let nested = "bash -lc 'cd /srv/app && apply_patch \"*** Begin Patch\n*** Delete File: old.rs\n*** End Patch\"'";
        assert_eq!(shell_patch(nested), writes(&["old.rs", "/srv/app/old.rs"]));
        // The line is the word after `-c`, past the shell's other options.
        let after_options = "bash -l -c 'cd /srv/app && apply_patch \"*** Begin Patch\n*** Delete File: old.rs\n*** End Patch\"'";
        assert_eq!(
            shell_patch(after_options),
            writes(&["old.rs", "/srv/app/old.rs"])
        );
    }

    /// A patch the line runs and this reader cannot read is unreadable, with
    /// the reason, and a readable patch beside it does not stand in for it.
    ///
    /// FAILS ON REVERT: drop the last arm of the `match` in
    /// `Line::patch_command` and the first four name no file or, the fourth,
    /// only the file of the patch beside it; drop the `rewrites.words` test
    /// there and the fifth, sixth and seventh give the reason of a patch
    /// whose text is not in the command; drop the `expanded_body` test in
    /// `shell_patch` and the eighth names a file the shell has yet to fill
    /// in (read `|=` as `^=` where `Line::patch_command` notes a body the
    /// shell expands, and the ninth, read once whole and once by its lines,
    /// is read as a body the shell leaves alone; read `&&` as `||` in the
    /// test of an operator that stands alone in `given` and the file the
    /// program is given beside its here-document is taken for the
    /// delimiter, so the tenth names the here-document's file alone)
    /// in; drop the `line.lost` test and the ninth names `notes.md` alone.
    #[test]
    fn a_patch_that_cannot_be_read_is_unreadable() {
        let decoy = here("cat <<'EOF' >/dev/null", &["notes.md"]);
        for (command, why) in [
            ("apply_patch < /tmp/change.patch".to_string(), NOT_WRITTEN),
            (
                "cat /tmp/change.patch | apply_patch".to_string(),
                NOT_WRITTEN,
            ),
            ("apply_patch /tmp/change.patch".to_string(), NOT_WRITTEN),
            (
                format!("apply_patch < /tmp/change.patch\n{decoy}"),
                NOT_WRITTEN,
            ),
            (format!("apply_patch \"$PATCH\"\n{decoy}"), REWRITTEN),
            (
                "apply_patch \"$(cat /tmp/change.patch)\"".to_string(),
                REWRITTEN,
            ),
            ("apply_patch <<<\"$PATCH\"".to_string(), REWRITTEN),
            (here("apply_patch <<EOF", &["$TARGET"]), REWRITTEN),
            (
                here("apply_patch <<'EOF' /tmp/change.patch", &["notes.md"]),
                NOT_WRITTEN,
            ),
            (
                "apply_patch <<EOF\n*** Begin Patch\n*** Update File: run.sh\n@@\n-echo a\n+echo $HOME\n*** End Patch\nEOF\n"
                    .to_string(),
                REWRITTEN,
            ),
            (
                here("cd \"$ROOT\" && apply_patch <<'EOF'", &["notes.md"]),
                LOST,
            ),
            (here("cd - && apply_patch <<'EOF'", &["notes.md"]), LOST),
            ("apply_patch <<'EOF'\nnothing\nEOF\n".to_string(), NO_FILE),
            (
                "apply_patch <<'EOF'\n*** Begin Patch\n*** Update File:\n*** End Patch\nEOF\n"
                    .to_string(),
                NO_PATH,
            ),
            ("bash -lc \"apply_patch '$PATCH'\"".to_string(), REWRITTEN),
        ] {
            assert_eq!(
                shell_patch(&command),
                ShellPatch::Unreadable(why),
                "{command}"
            );
        }
    }

    /// A line that names the patch program and does not run it hands it
    /// nothing.
    ///
    /// FAILS ON REVERT: take the `if line.runs` test off the answer for a
    /// line that names no file in `shell_patch` and each of these that names
    /// the program is unreadable.
    #[test]
    fn a_line_that_only_names_the_patch_program_is_not_a_patch() {
        for command in [
            "ls -la",
            "grep -rn apply_patch docs/",
            "which apply_patch",
            "command -v apply_patch",
            "echo 'use apply_patch to edit'",
            "git log --grep=applypatch",
        ] {
            assert_eq!(shell_patch(command), ShellPatch::NotAPatch, "{command}");
        }
    }

    /// Shells inside shells are read [`LINES_DEEP`] deep, and a line that
    /// goes deeper is unreadable, not read in part.
    ///
    /// FAILS ON REVERT: read `>` as `==` or `>=` in the depth test of
    /// `Line::read` and the line at the depth is unreadable; hand the nested
    /// reading `depth * 1` instead of `depth + 1` and the deeper line is read.
    #[test]
    fn shells_inside_shells_are_read_to_their_depth_and_no_further() {
        let file = "/home/dev/.codex/hooks.json";
        let nested = |evals: usize| {
            here(
                &format!("{}apply_patch <<'EOF'", "eval ".repeat(evals)),
                &[file],
            )
        };
        assert_eq!(shell_patch(&nested(LINES_DEEP)), writes(&[file]));
        assert_eq!(
            shell_patch(&nested(LINES_DEEP + 1)),
            ShellPatch::Unreadable(TOO_DEEP)
        );
    }

    /// A line's patch is read up to [`FILES_READ`] files, counted as named
    /// and again with each relative one in the folder the line went to, and
    /// a line that names more is unreadable, not read in part.
    ///
    /// FAILS ON REVERT: read `>` as `==` or `>=` in `Line::name` (the line is
    /// read more than once, so the bound is met on the second reading) or at
    /// the end of `shell_patch` and the line at the bound is unreadable.
    #[test]
    fn a_line_is_read_up_to_the_files_it_may_name_and_no_further() {
        let files = |count: usize, root: &str| -> Vec<String> {
            (0..count).map(|n| format!("{root}f{n}.rs")).collect()
        };
        let line = |header: &str, files: &[String]| {
            let names: Vec<&str> = files.iter().map(String::as_str).collect();
            shell_patch(&here(header, &names))
        };
        let rooted = files(FILES_READ, "/srv/");
        let names: Vec<&str> = rooted.iter().map(String::as_str).collect();
        assert_eq!(line("apply_patch <<'EOF'", &rooted), writes(&names));
        assert_eq!(
            line("apply_patch <<'EOF'", &files(FILES_READ + 1, "/srv/")),
            ShellPatch::Unreadable(TOO_MANY)
        );
        // Relative after a change of directory: each is two places.
        let relative = files(FILES_READ / 2, "");
        match line("cd /srv && apply_patch <<'EOF'", &relative) {
            ShellPatch::Writes(writes) => assert_eq!(writes.len(), FILES_READ),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            line(
                "cd /srv && apply_patch <<'EOF'",
                &files(FILES_READ / 2 + 1, "")
            ),
            ShellPatch::Unreadable(TOO_MANY)
        );
    }

    /// What the shell rewrites is told from what it leaves alone.
    ///
    /// FAILS ON REVERT: drop the `(Some(b'\''), _)` arm of `rewrites` and a
    /// `$` in single quotes counts; drop the test of the delimiter's quotes
    /// and every here-document is one the shell expands. Drop the
    /// `(Some(b'\''), b'\'')` arm and a single quote never closes, so a `$`
    /// or an open delimiter after one is missed; leave the `-` of `<<-` in
    /// the delimiter's reading and a quoted delimiter after a space is read
    /// as the `-` alone, so its body counts as one the shell expands. Take
    /// the guard off the `$"` arm and the `$` of a translated string counts;
    /// drop the arm that closes `$'...'`, or the one that closes `"..."`, and
    /// what follows the closed quote is read as still inside it.
    #[test]
    fn the_shell_rewrites_what_is_outside_single_quotes() {
        for (segment, words, body) in [
            ("apply_patch <<'EOF'", false, false),
            ("apply_patch <<\\EOF", false, false),
            ("apply_patch <<-\"EOF\"", false, false),
            ("apply_patch <<EOF", false, true),
            ("apply_patch << EOF", false, true),
            ("apply_patch '$x `y`'", false, false),
            ("apply_patch $'a\\'$b'", false, false),
            ("apply_patch \"$x\"", true, false),
            ("apply_patch `cat x`", true, false),
            ("apply_patch \\$x", false, false),
            ("apply_patch <<<$x", true, false),
            ("apply_patch <<- 'EOF'", false, false),
            ("env 'LANG=C' apply_patch <<EOF", false, true),
            ("apply_patch 'a' \"$x\"", true, false),
            ("apply_patch $\"x\"", false, false),
            ("apply_patch $'a' \"$x\"", true, false),
            ("apply_patch \"a\" <<EOF", false, true),
        ] {
            let found = rewrites(segment);
            assert_eq!((found.words, found.body), (words, body), "{segment}");
        }
    }

    /// A program name the shell still fills in when the line runs, in whole
    /// or in part, that may come out as the patch program's: the line is a
    /// patch whose program cannot be read, as the name in a default
    /// (`${x:-apply_patch}`) is, whatever the patch it hands over. The name
    /// may start inside the part filled in (it may hold a folder), is read
    /// in any case, and a Windows suffix written after it is no part of it.
    ///
    /// FAILS ON REVERT: take the `filled_in` arm out of `shell_patch` and
    /// every one of these is not a patch, or the patch it holds is read as
    /// if a plain name ran it; take `*start == 0 ||` out of the starts in
    /// `may_be_the_program` and the line whose written text comes first
    /// passes; drop the suffix loop and the `.exe` line passes; drop the
    /// test of the name inside the part filled in and the two lines that
    /// name it whole pass.
    #[test]
    fn a_patch_program_named_another_way_is_unreadable() {
        let mut commands: Vec<String> = [
            "$(echo apply)_patch < /tmp/change.patch",
            "`echo apply`_patch < /tmp/change.patch",
            "apply$(echo _patch) < /tmp/change.patch",
            "a$(echo pply_pa)tch < /tmp/change.patch",
            "\"$(echo apply)\"_patch < /tmp/change.patch",
            "${A}_patch < /tmp/change.patch",
            "$A\"_patch\" < /tmp/change.patch",
            "${A}ly_patch < /tmp/change.patch",
            "${A}patch < /tmp/change.patch",
            "apply${A} < /tmp/change.patch",
            "x${A}_patch < /tmp/change.patch",
            "/usr/local/bin/${A}_patch < /tmp/change.patch",
            "${A}_PATCH.exe < /tmp/change.patch",
            "${A}_pat{c,x}h < /tmp/change.patch",
            "$(echo apply_patch) < /tmp/change.patch",
            "`printf apply_patch` < /tmp/change.patch",
            "for a in apply; do ${a}_patch < /tmp/change.patch; done",
            "a=foo; a=apply; ${a}_patch < /tmp/change.patch",
            "$(echo apply)_patch '*** Begin Patch\n*** Delete File: /home/dev/.bashrc\n*** End Patch'",
        ]
        .iter()
        .map(|command| command.to_string())
        .collect();
        commands.push(here("${A}_patch <<'EOF'", &["src/a.rs"]));
        commands.push(here("$(echo apply)_patch <<'EOF'", &["src/a.rs"]));
        for command in &commands {
            assert_eq!(
                shell_patch(command),
                ShellPatch::Unreadable(REWRITTEN),
                "{command}"
            );
        }
        // The line's own assignments still name the program in full, and
        // the reason stays the one the plain name gets.
        assert_eq!(
            shell_patch("a=apply; ${a}_patch < /tmp/change.patch"),
            ShellPatch::Unreadable(NOT_WRITTEN)
        );
    }

    /// The same program name filled in by the shell, started by a launcher,
    /// a shell given a line, `eval`, a substitution, `xargs`, `find -exec`
    /// or a program this reader does not follow, is unreadable too, and so
    /// is a line read line by line.
    ///
    /// FAILS ON REVERT: drop the reading of `line.nested` in
    /// `names_a_program_filled_in` and the substitution passes; read only
    /// the line whole there and the line after an open quote passes; drop
    /// the arm for a launcher whose options are not read and the `--bogus`
    /// and `-z` lines pass; drop `line_run_by` and the shell and `eval`
    /// lines pass; drop the `find`, `xargs` or `UNFOLLOWED` arm and its
    /// line passes.
    #[test]
    fn a_patch_program_named_another_way_and_started_another_way_is_unreadable() {
        for command in [
            "env LANG=C ${A}_patch < /tmp/change.patch",
            "sudo -n ${A}_patch < /tmp/change.patch",
            "sudo --bogus ${A}_patch < /tmp/change.patch",
            "nice -z ${A}_patch < /tmp/change.patch",
            "bash -lc '${A}_patch < /tmp/change.patch'",
            "eval '${A}_patch < /tmp/change.patch'",
            "echo $(${A}_patch < /tmp/change.patch)",
            "ls *.patch | xargs -n1 ${A}_patch",
            "ls *.patch | xargs sudo ${A}_patch",
            "ls *.patch | xargs bash -c '${A}_patch'",
            "ls *.patch | xargs --bogus ${A}_patch",
            "find . -name '*.patch' -exec ${A}_patch {} \\;",
            "ls *.patch | parallel ${A}_patch",
            "printf '%s' \"x\n${A}_patch < /tmp/change.patch",
        ] {
            assert_eq!(
                shell_patch(command),
                ShellPatch::Unreadable(REWRITTEN),
                "{command}"
            );
        }
    }

    /// Lines with a program or a file whose name the shell fills in, and
    /// that is not the patch program, keep their reading: a file named like
    /// the program, a script whose name only starts like it, a word filled
    /// in whole, a name looked up, an assignment.
    ///
    /// FAILS ON REVERT: let `may_be_the_program` answer yes for every word
    /// with a part filled in and each of these is unreadable; drop the test
    /// for a written character in the starts there and `$EDITOR` and the
    /// suffix alone are; drop the `LOOKUPS` test and the lookups are; drop
    /// the `is_assignment` test and the assignment is; drop the `FIND_RUNS`
    /// test and the search by name is.
    #[test]
    fn a_word_named_like_the_patch_program_is_no_patch() {
        for command in [
            "$APPLY < /tmp/change.patch",
            "$EDITOR notes.md",
            "${TOOL}.exe < /tmp/change.patch",
            "cat $(echo src)_patch.rs",
            "cat ${DIR}_patch.rs",
            "python3 ${ROOT}/apply_patch.py",
            "./${NAME}_patch.sh",
            "${TOOL}_patcher in.txt",
            "${A}-patch < /tmp/change.patch",
            "\"$(npm bin)/eslint\" .",
            "${PYTHON:-python3} -m pytest -q",
            "$(git rev-parse --show-toplevel)/scripts/apply_patch.sh",
            "OUT=${NAME}_patch; echo $OUT",
            "BRANCH=${USER}_patch git switch -c x",
            "command -v ${A}_patch",
            "sudo -l ${A}_patch",
            "find . -name ${A}_patch",
            "xargs grep ${A}_patch < files.txt",
            "for f in ${A}_patch; do echo $f; done",
            "bash -c 'cat ${DIR}_patch.rs'",
            "echo $(cat ${DIR}_patch.rs)",
        ] {
            assert_eq!(shell_patch(command), ShellPatch::NotAPatch, "{command}");
        }
        // A patch whose program is named in full keeps its reading.
        assert_eq!(
            shell_patch(&here(
                "cd \"$HOME\"/proj; apply_patch <<'EOF'",
                &["/srv/a.rs"]
            )),
            writes(&["/srv/a.rs"])
        );
    }

    /// Lines inside lines are read [`FILLED_IN_DEEP`] deep for a program
    /// name the shell fills in, and a line that goes deeper is taken for
    /// one that may name the patch program.
    ///
    /// FAILS ON REVERT: read `>` as `>=` or `==` in the depth test of
    /// `names_a_program_filled_in` and the `eval` line at the depth is
    /// unreadable; the same in `runs_a_program_filled_in` and the `xargs`
    /// line at the depth is; hand `xargs` its command at the same depth
    /// and the deeper `xargs` line is read to its end, as one that runs an
    /// editor.
    #[test]
    fn lines_inside_lines_are_read_to_their_depth_for_a_name_filled_in() {
        let nested = |evals: usize| format!("{}$EDITOR notes.md", "eval ".repeat(evals));
        assert_eq!(shell_patch(&nested(FILLED_IN_DEEP)), ShellPatch::NotAPatch);
        assert_eq!(
            shell_patch(&nested(FILLED_IN_DEEP + 1)),
            ShellPatch::Unreadable(REWRITTEN)
        );
        // `xargs` run by `xargs` is followed as deep, and no deeper.
        let piped = |times: usize| format!("ls | {}$EDITOR", "xargs ".repeat(times));
        assert_eq!(shell_patch(&piped(FILLED_IN_DEEP)), ShellPatch::NotAPatch);
        assert_eq!(
            shell_patch(&piped(FILLED_IN_DEEP + 1)),
            ShellPatch::Unreadable(REWRITTEN)
        );
        // Substitutions nested far past the depth are answered, and not read
        // to their end.
        let deep = format!("echo {}x{}", "$(echo ".repeat(2000), ")".repeat(2000));
        assert_eq!(shell_patch(&deep), ShellPatch::Unreadable(REWRITTEN));
    }

    /// The pieces of a name spell a program's exactly: each written
    /// character in its place, and a part filled in for any run, none
    /// included.
    ///
    /// FAILS ON REVERT: keep `reached[0]` after a written character in
    /// `spells` and a name that only ends like the program is taken for it;
    /// let a part filled in reach no further than where it starts and a
    /// part that stands for characters spells nothing.
    #[test]
    fn the_pieces_of_a_name_spell_a_program_exactly() {
        let written = |text: &str| text.chars().map(Piece::Written).collect::<Vec<_>>();
        assert!(spells(&written("apply_patch"), "apply_patch"));
        assert!(!spells(&written("xapply_patch"), "apply_patch"));
        assert!(!spells(&written("apply_patc"), "apply_patch"));
        let mut filled = written("app");
        filled.push(Piece::Filled);
        filled.extend(written("patch"));
        assert!(spells(&filled, "apply_patch"));
        assert!(spells(&filled, "applypatch"));
        let mut pattern = vec![Piece::Pattern];
        pattern.extend(written("tch"));
        assert!(spells(&pattern, "apply_patch"));
        assert!(!spells(
            &[Piece::Written('h'), Piece::Filled],
            "apply_patch"
        ));
    }
}
