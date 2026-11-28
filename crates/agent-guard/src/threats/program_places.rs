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
        "cargo" => cargo_subcommand(arguments).is_some_and(|sub| matches!(sub, "run" | "r")),
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

/// The options cargo takes before its subcommand that are given a value as
/// the next word (`cargo --color always run`, `cargo -C /src/proj run`). A
/// `+toolchain` and any other option stand alone.
const CARGO_GLOBAL_VALUED: &[&str] = &[
    "--color",
    "-C",
    "--config",
    "--manifest-path",
    "-Z",
    "-j",
    "--jobs",
    "--target-dir",
    "--explain",
];

/// cargo's subcommand among `arguments` (the words after `cargo`): the first
/// word that is neither an option nor the value of one it takes before the
/// subcommand ([`CARGO_GLOBAL_VALUED`]). Taken as the first word that is not
/// an option, `cargo --color always run -p NAME` ran `always`, and the
/// package it builds and runs was read as a mention.
fn cargo_subcommand<'a>(arguments: &[&'a str]) -> Option<&'a str> {
    let mut words = arguments.iter();
    while let Some(word) = words.next() {
        if word.starts_with('+') {
            continue;
        }
        if word.starts_with('-') {
            if CARGO_GLOBAL_VALUED.contains(word) {
                words.next();
            }
            continue;
        }
        return Some(word);
    }
    None
}

/// The options of `cargo run` that name the package or binary it builds and
/// runs.
const CARGO_RUN_PROGRAM_OPTIONS: &[&str] = &["-p", "--package", "--bin", "--example"];

/// Whether `text`, an option of `cargo run`, holds the package or binary it
/// runs glued on (`--bin=NAME`, `--package=NAME`, `-pNAME`, `-qpNAME`): the
/// same as that option and its value as two words.
pub(super) fn cargo_run_program_glued(text: &str) -> Option<&str> {
    if let Some(long) = text.strip_prefix("--") {
        let (option, value) = long.split_once('=')?;
        return (CARGO_RUN_PROGRAM_OPTIONS.contains(&format!("--{option}").as_str())
            && !value.is_empty())
        .then_some(value);
    }
    let letters = text.strip_prefix('-')?;
    // A cluster of short flags, the value glued after `p`. Another option
    // that takes a value (`-j`, `-Z`, `-C`, `-F`) ends the cluster.
    for (at, letter) in letters.char_indices() {
        match letter {
            'p' => {
                let value = &letters[at + 1..];
                return (!value.is_empty()).then_some(value);
            }
            'j' | 'Z' | 'C' | 'F' => return None,
            letter if letter.is_ascii_alphabetic() => {}
            _ => return None,
        }
    }
    None
}

/// Whether `text`, an option of `cargo run`, takes the package or binary it
/// runs as the next word (`-p`, `--bin`, `-qp`).
fn cargo_run_program_option(text: &str) -> bool {
    CARGO_RUN_PROGRAM_OPTIONS.contains(&text)
        || text.strip_prefix('-').is_some_and(|letters| {
            !letters.starts_with('-')
                && letters.ends_with('p')
                && letters.chars().all(|c| c.is_ascii_alphabetic())
                && !letters.contains(['j', 'Z', 'C', 'F'])
        })
}

/// The ssh client's programs: each takes `ssh`'s `-o` options, and so runs
/// the commands some of them name on this host.
pub(super) const SSH_FAMILY: &[&str] = &["ssh", "scp", "sftp", "slogin", "autossh"];

/// The `ssh` settings whose value is a command line run on this host, by a
/// shell, when the client connects: the proxy, the command after the
/// connection (with `PermitLocalCommand`), the known-hosts lookup.
const SSH_LOCAL_COMMAND_KEYS: &[&str] = &["proxycommand", "localcommand", "knownhostscommand"];

/// The command lines an ssh client program (`ssh`, `scp`, `sftp`) runs on
/// this host from its `-o` options, wherever they stand among its words:
/// `-o ProxyCommand=CMD`, `-oProxyCommand=CMD`, `-o "ProxyCommand CMD"`,
/// `LocalCommand` and `KnownHostsCommand` the same, and `-o 'Match exec
/// CMD'`. `program`: the program's name, lowercase, no folder; `arguments`:
/// the words after it.
///
/// Each runs where a program runs: the guard named in it is the guard
/// (`scp -o ProxyCommand="innerwarden $V" x h1:y` ran the guard with a verb
/// the line does not show, held for review as an argument of `scp`).
pub(super) fn ssh_local_commands<'a>(program: &str, arguments: &[&'a str]) -> Vec<&'a str> {
    if !SSH_FAMILY.contains(&program) {
        return Vec::new();
    }
    arguments
        .iter()
        .filter_map(|word| {
            let setting = match word.strip_prefix('-') {
                // `-oSetting`, `-4oSetting`: the value glued after `o`.
                Some(letters) if !letters.starts_with('-') => {
                    let at = letters.find('o')?;
                    letters[..at]
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric())
                        .then(|| &letters[at + 1..])?
                }
                Some(_) => return None,
                None => word,
            };
            ssh_setting_command(setting)
        })
        .collect()
}

/// The remote shell `rsync` runs on this host (`-e CMD`, `-eCMD`, `-avze
/// CMD`, `--rsh=CMD`, `--rsh CMD`): a command line, and an `ssh` in it runs
/// what its own options name. `None` for another program or none given.
pub(super) fn rsync_remote_shell<'a>(program: &str, arguments: &[&'a str]) -> Option<&'a str> {
    if program != "rsync" {
        return None;
    }
    let mut words = arguments.iter();
    while let Some(word) = words.next() {
        if *word == "--" {
            return None;
        }
        if let Some(value) = word.strip_prefix("--rsh=") {
            return Some(value);
        }
        if *word == "--rsh" {
            return words.next().copied();
        }
        let Some(letters) = word.strip_prefix('-').filter(|l| !l.starts_with('-')) else {
            continue;
        };
        if let Some(at) = letters.find('e') {
            if letters[..at].chars().all(|c| c.is_ascii_alphanumeric()) {
                let glued = &letters[at + 1..];
                return if glued.is_empty() {
                    words.next().copied()
                } else {
                    Some(glued)
                };
            }
        }
    }
    None
}

/// [`ssh_local_commands`] of a simple command: the program a launcher in
/// front of it runs too (`sudo scp -o ...`, `timeout 9 sftp -o ...`).
pub(super) fn ssh_local_commands_of(words: &[Word]) -> Vec<String> {
    let texts: Vec<String> = words.iter().map(|w| w.text.clone()).collect();
    let Some(at) = super::launched_command_index(&texts) else {
        return Vec::new();
    };
    let program = super::program_name(&texts[at]);
    let arguments: Vec<&str> = texts[at + 1..].iter().map(String::as_str).collect();
    ssh_local_commands(&program, &arguments)
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// The command line an `ssh` setting written as `Key=value` or `Key value`
/// runs on this host, if it is one of [`SSH_LOCAL_COMMAND_KEYS`] (a value of
/// `none` runs nothing) or a `Match` with an `exec` criterion.
fn ssh_setting_command(setting: &str) -> Option<&str> {
    let setting = setting.trim_start();
    let key_end = setting.find(|c: char| c == '=' || c.is_whitespace())?;
    let key = setting[..key_end].to_ascii_lowercase();
    let value = setting[key_end..]
        .trim_start()
        .strip_prefix('=')
        .unwrap_or(&setting[key_end..])
        .trim();
    if SSH_LOCAL_COMMAND_KEYS.contains(&key.as_str()) {
        return (!value.is_empty() && !value.eq_ignore_ascii_case("none")).then_some(value);
    }
    if key != "match" {
        return None;
    }
    // `Match [!]exec "CMD"` among other criteria: the argument after `exec`,
    // whole when it is quoted.
    let mut rest = value;
    while !rest.is_empty() {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let criterion = rest[..end].trim_start_matches('!');
        rest = rest[end..].trim_start();
        if !criterion.eq_ignore_ascii_case("exec") {
            continue;
        }
        if let Some(quoted) = rest.strip_prefix('"') {
            let close = quoted.find('"').unwrap_or(quoted.len());
            return Some(&quoted[..close]).filter(|command| !command.trim().is_empty());
        }
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        return Some(&rest[..end]).filter(|command| !command.is_empty());
    }
    None
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
            // Each command an `-exec` runs, up to its `;` or `+`. Read by
            // search, not by a counter stepped one by one: a counter that
            // stops stepping would never end the reading.
            let mut from = after;
            while let Some(exec) = (from..to).find(|&j| {
                words[j].is_plain()
                    && matches!(
                        words[j].text.as_str(),
                        "-exec" | "-execdir" | "-ok" | "-okdir"
                    )
            }) {
                let start = exec + 1;
                let end = (start..to)
                    .find(|&j| matches!(words[j].text.as_str(), ";" | "+"))
                    .unwrap_or(to);
                fill(words, start, end, places);
                from = end;
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
                // The package or binary it builds and runs, up to `--`: the
                // word after its option, or the option's own word when the
                // value is glued on (`--bin=NAME`, `-pNAME`).
                for j in after..to {
                    let text = words[j].text.as_str();
                    if text == "--" {
                        break;
                    }
                    if cargo_run_program_glued(text).is_some() {
                        places[j] = WordPlace::Program;
                    } else if cargo_run_program_option(text) && j + 1 < to {
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
    let mut rest = words.iter().enumerate();
    while let Some((index, word)) = rest.next() {
        let text = word.text.as_str();
        if options && text == "--" {
            options = false;
            continue;
        }
        if options && text.len() > 1 && text.starts_with('-') {
            let letters = &text[1..];
            if let Some(at) = letters.find(|c| SSH_VALUED.contains(c)) {
                if letters[at + 1..].is_empty() {
                    // Its value is the next word.
                    rest.next();
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
    use super::{
        arguments_of, cargo_run_program_glued, cargo_run_program_option, cargo_subcommand, places,
        rsync_remote_shell, ssh_command_start, ssh_local_commands, Arguments, WordPlace,
    };

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

    #[test]
    fn cargos_subcommand_is_past_its_own_options_and_their_values() {
        for (words, sub) in [
            (&["run", "-p", "x"][..], Some("run")),
            (&["--color", "always", "run"][..], Some("run")),
            (&["-C", "/src/p", "run"][..], Some("run")),
            (&["+stable", "-j", "4", "test"][..], Some("test")),
            (&["--config", "x=1", "-Z", "u", "r"][..], Some("r")),
            (&["-q", "--locked", "build"][..], Some("build")),
            (&["--color"][..], None),
        ] {
            assert_eq!(cargo_subcommand(words), sub, "{words:?}");
        }
    }

    #[test]
    fn a_package_glued_to_cargo_runs_option_is_read_as_its_value() {
        for (text, value) in [
            ("--bin=innerwarden", Some("innerwarden")),
            ("--package=innerwarden", Some("innerwarden")),
            ("--example=x", Some("x")),
            ("-pinnerwarden", Some("innerwarden")),
            ("-qpinnerwarden", Some("innerwarden")),
            ("-p", None),
            ("--bin=", None),
            ("--profile=dev", None),
            ("-j4", None),
            ("--release", None),
        ] {
            assert_eq!(cargo_run_program_glued(text), value, "{text}");
        }
        for (line, word) in [
            ("cargo run --bin=innerwarden -- x", "--bin=innerwarden"),
            ("cargo run -pinnerwarden -- x", "-pinnerwarden"),
            ("cargo run -qp innerwarden -- x", "innerwarden"),
            ("cargo --color always run -p innerwarden", "innerwarden"),
        ] {
            assert_eq!(place_of(line, word), WordPlace::Program, "{line}");
        }
        assert_eq!(
            place_of("cargo test --bin=innerwarden x", "--bin=innerwarden"),
            WordPlace::Data
        );
    }

    #[test]
    fn an_ssh_clients_option_that_runs_a_command_gives_that_command() {
        for (program, words, commands) in [
            (
                "scp",
                &["-o", "ProxyCommand=iw x", "a", "h:b"][..],
                &["iw x"][..],
            ),
            (
                "scp",
                &["-oProxyCommand=iw x", "a", "h:b"][..],
                &["iw x"][..],
            ),
            ("sftp", &["-4oLocalCommand iw y", "h"][..], &["iw y"][..]),
            (
                "ssh",
                &["-o", "knownhostscommand = iw z", "h"][..],
                &["iw z"][..],
            ),
            (
                "scp",
                &["-o", "Match host h exec \"iw a b\"", "a", "h:b"][..],
                &["iw a b"][..],
            ),
            ("ssh", &["-o", "Match !exec iw", "h"][..], &["iw"][..]),
            ("scp", &["-o", "ProxyCommand=none", "a", "h:b"][..], &[][..]),
            ("scp", &["-o", "ConnectTimeout=5", "a", "h:b"][..], &[][..]),
            ("cp", &["-o", "ProxyCommand=iw x"][..], &[][..]),
        ] {
            assert_eq!(ssh_local_commands(program, words), commands, "{words:?}");
        }
        for (words, shell) in [
            (&["-e", "ssh -p 2", "a", "h:b"][..], Some("ssh -p 2")),
            (&["-avze", "ssh", "a", "h:b"][..], Some("ssh")),
            (&["-essh -q", "a"][..], Some("ssh -q")),
            (&["--rsh=ssh", "a"][..], Some("ssh")),
            (&["--rsh", "ssh", "a"][..], Some("ssh")),
            (&["-av", "a", "h:b"][..], None),
        ] {
            assert_eq!(rsync_remote_shell("rsync", words), shell, "{words:?}");
        }
    }

    /// What each program does with its arguments, for each word that makes
    /// it run one and without it.
    ///
    /// FAILS ON REVERT: take the arm of `find`, `fd` or `ssh` out of
    /// `arguments_of`, or read the words of `git` that run a command as all
    /// of them at once, and the line of that program reads as data.
    #[test]
    fn what_a_program_does_with_its_arguments() {
        for (program, words, expected) in [
            (
                "find",
                &["/opt", "-name", "x", "-exec", "y", ";"][..],
                Arguments::Run,
            ),
            ("find", &["/opt", "-okdir", "y", ";"][..], Arguments::Run),
            ("find", &["/opt", "-name", "x"][..], Arguments::Data),
            ("fd", &["x", "--exec-batch", "y"][..], Arguments::Run),
            ("fdfind", &["x", "-X", "y"][..], Arguments::Run),
            ("fd", &["x", "/opt"][..], Arguments::Data),
            ("ssh", &["h1"][..], Arguments::Run),
            ("git", &["-c", "x=y", "log"][..], Arguments::Run),
            ("git", &["log", "!x"][..], Arguments::Run),
            ("git", &["--exec-path=/x", "log"][..], Arguments::Run),
            ("git", &["log", "--oneline"][..], Arguments::Data),
            ("rg", &["--pre", "x", "y"][..], Arguments::Run),
            ("rg", &["x"][..], Arguments::Data),
            ("printf", &["-v", "x", "y"][..], Arguments::Run),
            ("printf", &["%s", "y"][..], Arguments::Data),
            ("cargo", &["--color", "always", "run"][..], Arguments::Run),
            ("cargo", &["test"][..], Arguments::Data),
            ("./run", &["x"][..], Arguments::Unknown),
            ("innerwarden", &["x"][..], Arguments::Run),
            ("bash", &["x"][..], Arguments::Run),
            ("export", &["X=1"][..], Arguments::Run),
            ("read", &["X"][..], Arguments::Run),
            ("watch", &["x"][..], Arguments::Run),
        ] {
            assert_eq!(
                arguments_of(program, words),
                expected,
                "{program} {words:?}"
            );
        }
    }

    /// Only a cluster of letters ending in `p`, none of them an option that
    /// takes a value of its own, waits for the package as the next word,
    /// and a digit ends a cluster that would glue it on.
    ///
    /// FAILS ON REVERT: answer `cargo_run_program_option` `true`, or join
    /// its conditions with `||`, and a flag or a cluster that is not one
    /// gives the next word as the package; take any character for a letter
    /// in `cargo_run_program_glued` and `-1pX` glues one on.
    #[test]
    fn only_an_option_that_takes_the_package_takes_it() {
        for text in ["-p", "--package", "--bin", "--example", "-qp", "-vqp"] {
            assert!(cargo_run_program_option(text), "{text}");
        }
        for text in ["--release", "-q", "-pq", "--p", "-1p", "-jp", "-Fp", "-"] {
            assert!(!cargo_run_program_option(text), "{text}");
        }
        assert_eq!(cargo_run_program_glued("-1pinnerwarden"), None);
        assert_eq!(cargo_run_program_glued("-jpinnerwarden"), None);
        assert_eq!(cargo_run_program_glued("-Zpx"), None);
    }

    /// An option of `cargo run` that waits for the package as the last word
    /// of the command, a `{}` the search hands the found file to whole or a
    /// value in its place, and a `--` before the host of `ssh`.
    ///
    /// FAILS ON REVERT: let `fill` mark the word past the last one
    /// (`j - 1 < to`, `j + 1 <= to`) and the first line panics; join the two
    /// readings of `runs_the_found_file` with `&&` and the found file run by
    /// a quoted `{}` or a value is read as a search; step back at `--` in
    /// `ssh_command_start` and the `ssh` line panics.
    #[test]
    fn the_edges_of_where_a_program_runs() {
        assert_eq!(place_of("cargo run -p", "-p"), WordPlace::Data);
        assert_eq!(place_of("cargo run --bin", "--bin"), WordPlace::Data);
        for (line, word) in [
            (
                "find /usr/local/bin -name innerwarden -exec '{}' monitor ;",
                "innerwarden",
            ),
            ("fd innerwarden /opt -x $X monitor", "innerwarden"),
        ] {
            assert_eq!(place_of(line, word), WordPlace::Any, "{line}");
        }
        assert_eq!(
            place_of("fd ';' -x innerwarden status", "innerwarden"),
            WordPlace::Program
        );
        assert_eq!(
            place_of("ssh -- h1 innerwarden status", "innerwarden"),
            WordPlace::Program
        );
    }

    /// Where the command `ssh` hands the far shell starts: past its
    /// options, an option's value given apart, `--` and the host; a lone `-`
    /// is no option.
    ///
    /// FAILS ON REVERT: take a lone `-` for an option (`len() >= 1`), or
    /// leave the value of `-p 22` among the words, and the start moves.
    #[test]
    fn where_the_command_ssh_runs_starts() {
        let words = |line: &str| {
            crate::shell_words::read_line(line).commands[0]
                .words
                .clone()
        };
        for (line, start) in [
            ("h1", None),
            ("h1 x", Some(1)),
            ("-p 22 h1 x", Some(3)),
            ("-p22 h1 x", Some(2)),
            ("-4 h1 x", Some(2)),
            ("-- h1 x", Some(2)),
            ("- x", Some(1)),
            ("-o X=1 h1", None),
        ] {
            assert_eq!(ssh_command_start(&words(line)), start, "{line}");
        }
        assert_eq!(
            place_of("ssh - innerwarden status", "innerwarden"),
            WordPlace::Program
        );
    }
}
