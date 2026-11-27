//! Where in a simple command a word can be the program that runs.
//!
//! The guard's name is its program only where the shell runs it: the command
//! word, the word a launcher before it runs ([`super::launched_command_index`]:
//! `sudo`, `env`, `nice`, `timeout`, `xargs`, `npx` and the rest it reads),
//! the command `find -exec` and `fd -x` run, the package `cargo run` builds
//! and runs, and the command `ssh` hands the far shell. Anywhere else it is an
//! argument. An argument of a program whose arguments are data
//! ([`DATA_PROGRAMS`]) is a mention: a folder, a file, a test filter, an
//! option's value. An argument of any other program (a script, a function, an
//! interpreter, a program named by an expansion) may still be run by that
//! program, so the reading holds it for review rather than letting it pass.
//!
//! A command whose launcher the reading does not follow, and a program that
//! runs commands from its own words in ways not read here
//! ([`RUNS_ITS_WORDS`], a shell, a builtin that gives a variable a value),
//! keep the reading of every word as a program could be there
//! ([`WordPlace::Any`]).

use crate::shell_words::Word;

/// What a word of a command can be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WordPlace {
    /// The program the shell runs, or the one a launcher before it runs.
    Program,
    /// An argument of a program whose arguments name no program it runs, or
    /// a launcher's own option or value: a mention.
    Data,
    /// An argument of a program the line does not show to be one of those:
    /// that program may run it.
    Unknown,
    /// Not read: any word may be the program, as every word was before.
    Any,
}

/// Programs whose arguments never name a program they run: they read, list,
/// copy, move, hash, pack or fetch the files and names they are given, or
/// print them. A `git`, `rg` or `printf` that runs or sets something of its
/// words is read apart ([`places`]).
const DATA_PROGRAMS: &[&str] = &[
    // Reading and listing.
    "ls",
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "wc",
    "cut",
    "tr",
    "sort",
    "uniq",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "diff",
    "cmp",
    "comm",
    "file",
    "stat",
    "du",
    "df",
    "tree",
    "realpath",
    "readlink",
    "basename",
    "dirname",
    "which",
    "whereis",
    "type",
    "strings",
    "nm",
    "objdump",
    "readelf",
    "otool",
    "ldd",
    "column",
    "nl",
    "fold",
    "paste",
    "join",
    "rev",
    "tac",
    "jq",
    "yq",
    "xxd",
    "od",
    "hexdump",
    "base64",
    "test",
    "[",
    "[[",
    "echo",
    "printf",
    "true",
    "false",
    "cd",
    "pushd",
    "popd",
    "man",
    "date",
    "sleep",
    "env",
    "printenv",
    "id",
    "whoami",
    "uname",
    "hostname",
    // Files changed, copied or packed.
    "cp",
    "mv",
    "rm",
    "rmdir",
    "mkdir",
    "touch",
    "ln",
    "chmod",
    "chown",
    "chgrp",
    "install",
    "tar",
    "zip",
    "unzip",
    "gzip",
    "gunzip",
    "xz",
    "zstd",
    "bzip2",
    "tee",
    "mktemp",
    "truncate",
    "shred",
    "strip",
    "codesign",
    "xattr",
    "scp",
    "rsync",
    // Hashes.
    "sha256sum",
    "sha1sum",
    "sha512sum",
    "md5sum",
    "shasum",
    "md5",
    "b2sum",
    "cksum",
    // Fetches and services, which name the service or the address.
    "curl",
    "wget",
    "systemctl",
    "journalctl",
    "launchctl",
    "service",
    "ps",
    "pgrep",
    "pidof",
    "kill",
    "pkill",
    "killall",
    "lsof",
    // Builds and repositories: what they run is the project's, not a word.
    "cargo",
    "git",
    "gh",
    // A search: what `-exec` or `-x` runs is read apart.
    "find",
    "fd",
    "fdfind",
];

/// Programs that run commands from their own words in ways this reading
/// does not follow (`watch CMD`, `parallel CMD ::: ...`, `docker exec C
/// CMD`, `ip netns exec NS CMD`, `gdb --args CMD`, `su -c CMD`, `eval`),
/// and the builtins that give a variable its value from their words (`for
/// NAME in ...`, `set --`, `alias`, `hash -p`): any of their words may be
/// the program.
const RUNS_ITS_WORDS: &[&str] = &[
    "watch",
    "parallel",
    "sem",
    "rush",
    "gdb",
    "lldb",
    "valgrind",
    "firejail",
    "bwrap",
    "ip",
    "docker",
    "podman",
    "nerdctl",
    "kubectl",
    "oc",
    "su",
    "sg",
    "script",
    "eval",
    "source",
    ".",
    "trap",
    "builtin",
    "entr",
    "hyperfine",
    "for",
    "select",
    "case",
    "set",
    "alias",
    "hash",
    "let",
];

/// The options of `ssh` that take a value, as its option reading has them.
const SSH_VALUED: &str = "BbcDEeFIiJLlmOoPpQRSWw";

/// What a program does with its arguments ([`arguments_of`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Arguments {
    /// It names no program it runs with them: they are mentions.
    Data,
    /// It may run one of them as a program, or give a variable its value
    /// from them.
    Run,
    /// The line does not show which.
    Unknown,
}

/// What `program` (a name, lowercase, no folder) does with `arguments` (the
/// words after it the text shows as written).
pub(super) fn arguments_of(program: &str, arguments: &[&str]) -> Arguments {
    let has = |said: &dyn Fn(&str) -> bool| arguments.iter().any(|word| said(word));
    let runs = match program {
        program
            if super::GUARD_PROGRAMS.contains(&program)
                || super::SHELLS.contains(&program)
                || super::VARIABLE_SETTERS.contains(&program)
                || super::VALUE_READERS.contains(&program)
                || RUNS_ITS_WORDS.contains(&program) =>
        {
            true
        }
        "find" => has(&|w| matches!(w, "-exec" | "-execdir" | "-ok" | "-okdir")),
        "fd" | "fdfind" => has(&|w| matches!(w, "-x" | "-X" | "--exec" | "--exec-batch")),
        "cargo" => arguments
            .iter()
            .find(|w| !(w.starts_with('-') || w.starts_with('+')))
            .is_some_and(|sub| matches!(*sub, "run" | "r")),
        "ssh" => true,
        // `git -c alias.x='!cmd'`, `git bisect run CMD`, `git rebase --exec
        // CMD`, `git submodule foreach CMD` and a configuration it writes
        // run a command from its words.
        "git" => has(&|w| {
            matches!(
                w,
                "-c" | "--config-env"
                    | "config"
                    | "bisect"
                    | "rebase"
                    | "submodule"
                    | "filter-branch"
                    | "difftool"
                    | "mergetool"
            ) || w.starts_with('!')
                || w.starts_with("--exec")
        }),
        // `rg --pre CMD` runs it on every file.
        "rg" => has(&|w| w.starts_with("--pre")),
        // `printf -v NAME` gives a variable its value.
        "printf" => has(&|w| w.starts_with("-v")),
        _ => false,
    };
    if runs {
        Arguments::Run
    } else if DATA_PROGRAMS.contains(&program) {
        Arguments::Data
    } else {
        Arguments::Unknown
    }
}

/// What each word of a simple command can be.
pub(super) fn places(words: &[Word]) -> Vec<WordPlace> {
    let mut places = vec![WordPlace::Any; words.len()];
    fill(words, 0, words.len(), &mut places);
    places
}

/// The places of the command in `words[from..to]`, a command of its own.
/// Left [`WordPlace::Any`] where its launcher is not read.
fn fill(words: &[Word], from: usize, to: usize, places: &mut [WordPlace]) {
    if from >= to {
        return;
    }
    let texts: Vec<String> = words[from..to].iter().map(|w| w.text.clone()).collect();
    let Some(at) = super::launched_command_index(&texts) else {
        return;
    };
    let at = from + at;
    for place in &mut places[from..at] {
        *place = WordPlace::Data;
    }
    places[at] = WordPlace::Program;
    let after = at + 1;
    let set = |places: &mut [WordPlace], place: WordPlace| {
        for each in &mut places[after..to] {
            *each = place;
        }
    };
    let program = &words[at];
    if !program.is_plain() {
        set(places, WordPlace::Unknown);
        return;
    }
    let name = super::program_name(&program.text);
    let shown: Vec<&str> = words[after..to]
        .iter()
        .filter(|w| w.is_plain())
        .map(|w| w.text.as_str())
        .collect();
    match name.as_str() {
        // The file found, run as the program (`find /opt -name x -exec {}
        // monitor \;`, `fd x -x {}`): what names it among the search's own
        // words names the program, so every word is read as before.
        "find" | "fd" | "fdfind" if runs_the_found_file(&words[after..to]) => {}
        "find" => {
            set(places, WordPlace::Data);
            let mut index = after;
            while index < to {
                let word = &words[index];
                index += 1;
                if !(word.is_plain()
                    && matches!(word.text.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir"))
                {
                    continue;
                }
                let end = (index..to)
                    .find(|&j| matches!(words[j].text.as_str(), ";" | "+"))
                    .unwrap_or(to);
                fill(words, index, end, places);
                index = end;
            }
        }
        "fd" | "fdfind" => {
            set(places, WordPlace::Data);
            if let Some(exec) = (after..to).find(|&j| {
                words[j].is_plain()
                    && matches!(
                        words[j].text.as_str(),
                        "-x" | "-X" | "--exec" | "--exec-batch"
                    )
            }) {
                let end = (exec + 1..to).find(|&j| words[j].text == ";").unwrap_or(to);
                fill(words, exec + 1, end, places);
            }
        }
        "cargo" => {
            set(places, WordPlace::Data);
            if arguments_of("cargo", &shown) == Arguments::Run {
                // The package or binary it builds and runs, up to `--`.
                for j in after..to.saturating_sub(1) {
                    if words[j].text == "--" {
                        break;
                    }
                    if matches!(
                        words[j].text.as_str(),
                        "-p" | "--package" | "--bin" | "--example"
                    ) {
                        places[j + 1] = WordPlace::Program;
                    }
                }
            }
        }
        "ssh" => {
            set(places, WordPlace::Data);
            if let Some(start) = ssh_command_start(&words[after..to]) {
                fill(words, after + start, to, places);
            }
        }
        name => set(
            places,
            match arguments_of(name, &shown) {
                Arguments::Data => WordPlace::Data,
                Arguments::Run => WordPlace::Any,
                Arguments::Unknown => WordPlace::Unknown,
            },
        ),
    }
}

/// Whether a search runs the file it finds as the program: the word right
/// after `-exec`, `-execdir`, `-ok`, `-okdir` (`find`) or `-x`, `-X`,
/// `--exec`, `--exec-batch` (`fd`) holds `{}`, or is a word the text does not
/// show.
fn runs_the_found_file(words: &[Word]) -> bool {
    words.windows(2).any(|pair| {
        pair[0].is_plain()
            && matches!(
                pair[0].text.as_str(),
                "-exec" | "-execdir" | "-ok" | "-okdir" | "-x" | "-X" | "--exec" | "--exec-batch"
            )
            && (pair[1].text.contains("{}") || !pair[1].is_plain())
    })
}

/// Where the command `ssh` hands the far shell starts among the words after
/// `ssh`: past its options (an option's value too) and the host. `None` when
/// none is left.
fn ssh_command_start(words: &[Word]) -> Option<usize> {
    let mut options = true;
    let mut index = 0;
    while let Some(word) = words.get(index) {
        let text = word.text.as_str();
        if options && text == "--" {
            options = false;
            index += 1;
            continue;
        }
        if options && text.len() > 1 && text.starts_with('-') {
            index += 1;
            let letters = &text[1..];
            if let Some(at) = letters.find(|c| SSH_VALUED.contains(c)) {
                if letters[at + 1..].is_empty() {
                    index += 1;
                }
            }
            continue;
        }
        // The host.
        return (index + 1 < words.len()).then_some(index + 1);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{places, WordPlace};

    fn read(line: &str) -> Vec<(String, WordPlace)> {
        let line = crate::shell_words::read_line(line);
        let words = &line.commands[0].words;
        words
            .iter()
            .map(|w| w.text.clone())
            .zip(places(words))
            .collect()
    }

    fn place_of(line: &str, word: &str) -> WordPlace {
        read(line)
            .into_iter()
            .find(|(text, _)| text == word)
            .map(|(_, place)| place)
            .unwrap_or_else(|| panic!("{word} not in {line}"))
    }

    #[test]
    fn the_program_is_the_command_word_or_what_a_launcher_runs() {
        for (line, program) in [
            ("innerwarden status", "innerwarden"),
            ("sudo -u root innerwarden status", "innerwarden"),
            ("env A=1 nice -n 5 innerwarden status", "innerwarden"),
            ("timeout 60 innerwarden status", "innerwarden"),
            ("taskset 1 innerwarden status", "innerwarden"),
            ("stdbuf -o0 innerwarden status", "innerwarden"),
            ("xargs -I@ innerwarden status", "innerwarden"),
            (
                "find . -name x -exec innerwarden status {} ;",
                "innerwarden",
            ),
            ("fd x -x innerwarden status", "innerwarden"),
            ("cargo run -p innerwarden -- status", "innerwarden"),
            ("ssh -p 22 -i k h innerwarden status", "innerwarden"),
            ("rtk bypass innerwarden status", "innerwarden"),
            ("rtk -v proxy --skip-env innerwarden status", "innerwarden"),
            ("rtk err innerwarden status", "innerwarden"),
        ] {
            assert_eq!(place_of(line, program), WordPlace::Program, "{line}");
        }
    }

    #[test]
    fn an_argument_of_a_program_whose_arguments_are_data_is_a_mention() {
        for (line, word) in [
            (
                "cargo test -p innerwarden --bin innerwarden x",
                "innerwarden",
            ),
            (
                "ls target/release/innerwarden",
                "target/release/innerwarden",
            ),
            (
                "cp a /usr/local/bin/innerwarden",
                "/usr/local/bin/innerwarden",
            ),
            ("sudo -u innerwarden id", "innerwarden"),
            ("find /usr/local/bin -name innerwarden", "innerwarden"),
            (
                "ssh h ls /usr/local/bin/innerwarden",
                "/usr/local/bin/innerwarden",
            ),
            (
                "git -C /home/u/work/innerwarden log",
                "/home/u/work/innerwarden",
            ),
        ] {
            assert_eq!(place_of(line, word), WordPlace::Data, "{line}");
        }
    }

    #[test]
    fn an_argument_of_a_program_the_line_does_not_know_may_be_run() {
        for (line, word) in [
            ("./run innerwarden x", "innerwarden"),
            ("python3 drive.py innerwarden", "innerwarden"),
            ("$TOOL innerwarden", "innerwarden"),
            ("faketime 0 innerwarden", "innerwarden"),
            // `rtk env` shows the environment: no launcher.
            ("rtk env innerwarden", "innerwarden"),
        ] {
            assert_eq!(place_of(line, word), WordPlace::Unknown, "{line}");
        }
    }

    #[test]
    fn a_program_that_runs_its_words_keeps_every_word_read() {
        for (line, word) in [
            ("watch -n1 innerwarden status", "innerwarden"),
            ("docker exec c innerwarden status", "innerwarden"),
            ("set -- innerwarden status", "innerwarden"),
            ("git bisect run innerwarden status", "innerwarden"),
            ("rg --pre innerwarden x", "innerwarden"),
            ("printf -v c innerwarden", "innerwarden"),
            ("env --split-string x innerwarden", "innerwarden"),
            ("bash innerwarden", "innerwarden"),
            (
                "find /usr/local/bin -name innerwarden -exec {} monitor ;",
                "innerwarden",
            ),
            ("fd innerwarden /opt -x {} monitor", "innerwarden"),
            ("innerwarden contain -- innerwarden", "innerwarden"),
        ] {
            assert!(
                read(line)
                    .iter()
                    .any(|(text, place)| text == word && *place == WordPlace::Any),
                "{line}"
            );
        }
    }
}
