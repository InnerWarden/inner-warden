//! The programs that run what they are handed, from the table in
//! `data/programs.toml`, and how what they run is read as shell lines.
//!
//! The table says which names are shells, which run their input or their
//! arguments as code, which read a script on stdin, and which option takes
//! inline code or names a file to run. [`super::is_shell_name`],
//! [`super::is_execution_sink`] and [`super::is_stdin_code_executor`] read
//! it, so a program added there is known to every reading at once.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;

/// How what a program runs is read.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Language {
    Shell,
    Python,
    Node,
    Ruby,
    Perl,
    Php,
    Lua,
    Make,
    Awk,
    Crontab,
}

/// One row of the table.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Program {
    names: Vec<String>,
    pub(crate) language: Language,
    /// A shell: a `-c` line, a script file, or its standard input.
    #[serde(default)]
    pub(crate) shell: bool,
    /// Its input or its arguments become code.
    #[serde(default)]
    pub(crate) sink: bool,
    /// It runs what it reads on stdin as code when given no other.
    #[serde(default)]
    pub(crate) stdin_code: bool,
    /// What it reads on stdin is a script for a shell, run later.
    #[serde(default)]
    pub(crate) stdin_script: bool,
    /// Its arguments are a command the guard reads after it.
    #[serde(default)]
    pub(crate) launcher: bool,
    /// The option that takes code on the command line.
    #[serde(default)]
    pub(crate) inline: Option<String>,
    /// The option that names a file it runs.
    #[serde(default)]
    pub(crate) file_option: Option<String>,
}

#[derive(Deserialize)]
struct Table {
    program: Vec<Program>,
}

/// The table, by name.
fn table() -> &'static HashMap<String, Program> {
    static TABLE: LazyLock<HashMap<String, Program>> = LazyLock::new(|| {
        let table: Table = toml::from_str(include_str!("../../data/programs.toml"))
            .expect("data/programs.toml is the guard's own table");
        let mut by_name = HashMap::new();
        for program in table.program {
            for name in &program.names {
                by_name.insert(name.clone(), program.clone());
            }
        }
        by_name
    });
    &TABLE
}

/// The row of a program, by its name without version (`python` for
/// `python3.12`).
pub(crate) fn program(name: &str) -> Option<&'static Program> {
    table().get(name)
}

/// Whether `name` (without version) is a shell or a language of the table
/// that reads code when it is given none: a shell, or a program with an
/// option for inline code that reads stdin as code (`python`, `node`,
/// `perl`). Started with nothing to run, it waits for input
/// (`crate::interactive`).
pub(crate) fn reads_code_when_given_none(name: &str) -> bool {
    program(name)
        .is_some_and(|row| !row.launcher && (row.shell || (row.stdin_code && row.inline.is_some())))
}

/// Every name of the table with its row, for the tests that hold the
/// readings to it.
#[cfg(test)]
pub(crate) fn every_program() -> impl Iterator<Item = (&'static str, &'static Program)> {
    table()
        .iter()
        .map(|(name, program)| (name.as_str(), program))
}

/// What a program reads on stdin as a script, given its words after its
/// name (unquoted): `at` and `batch` without `-f`, `make -f -`, an `awk`
/// program that calls `system()` or prints to a shell, and `parallel` with
/// no command of its own. Shells are read by their own rules.
pub(crate) fn stdin_script(name: &str, args: &[String]) -> Option<Language> {
    let program = program(name)?;
    if program.shell {
        return None;
    }
    if program.stdin_script {
        let file = program.file_option.as_deref();
        return (!args
            .iter()
            .any(|arg| Some(arg.as_str()) == file || arg.starts_with("-f")))
        .then_some(program.language);
    }
    match program.language {
        Language::Make => make_files(args)
            .iter()
            .any(|file| file == "-" || file == "/dev/stdin")
            .then_some(Language::Make),
        Language::Awk => awk_program(args)
            .is_some_and(|code| awk_runs_its_input(&code))
            .then_some(Language::Shell),
        Language::Shell if name == "parallel" => {
            parallel_reads_commands(args).then_some(Language::Shell)
        }
        Language::Crontab => (args.iter().any(|arg| arg == "-")).then_some(Language::Crontab),
        _ => None,
    }
}

/// The files a program runs, each with how it is read: a shell's or an
/// interpreter's script operand, `source` and `.`, the makefile of
/// `make` (`Makefile` when none is named), the file after `at -f`, a
/// crontab file.
pub(crate) fn file_scripts(name: &str, args: &[String]) -> Vec<(String, Language)> {
    let Some(program) = program(name) else {
        return Vec::new();
    };
    let language = program.language;
    match language {
        Language::Make => {
            let named: Vec<String> = make_files(args)
                .into_iter()
                .filter(|file| file != "-" && file != "/dev/stdin")
                .collect();
            if named.is_empty()
                && !args.iter().any(|arg| {
                    arg.starts_with("-f")
                        || arg.starts_with("--file")
                        || arg.starts_with("--makefile")
                })
            {
                ["GNUmakefile", "makefile", "Makefile"]
                    .iter()
                    .map(|file| ((*file).to_owned(), Language::Make))
                    .collect()
            } else {
                named
                    .into_iter()
                    .map(|file| (file, Language::Make))
                    .collect()
            }
        }
        Language::Crontab => crontab_file(args)
            .map(|file| vec![(file, Language::Crontab)])
            .unwrap_or_default(),
        Language::Awk => Vec::new(),
        _ if program.stdin_script => {
            let file = program.file_option.as_deref().unwrap_or("-f");
            args.iter()
                .position(|arg| arg == file)
                .and_then(|at| args.get(at + 1))
                .map(|path| vec![(path.clone(), Language::Shell)])
                .unwrap_or_default()
        }
        _ if program.launcher
            || (program.sink && program.inline.is_none() && !matches!(name, "source" | ".")) =>
        {
            Vec::new()
        }
        _ if matches!(name, "source" | ".") => args
            .first()
            .map(|path| vec![(path.clone(), Language::Shell)])
            .unwrap_or_default(),
        _ => script_operand(args, program)
            .map(|path| vec![(path, language)])
            .unwrap_or_default(),
    }
}

/// The script operand of a shell or an interpreter: the first operand when
/// no option gave it code inline, a module (`-m`) or stdin (`-s`).
fn script_operand(args: &[String], program: &Program) -> Option<String> {
    let inline = program.inline.as_deref().unwrap_or("-c");
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        if arg == "--" {
            return args
                .get(at + 1)
                .filter(|path| !is_stdin_path(path))
                .cloned();
        }
        if arg == inline || arg == "-m" || arg == "--eval" || arg == "--command" {
            return None;
        }
        if let Some(flags) = arg
            .strip_prefix('-')
            .filter(|flags| !flags.starts_with('-'))
        {
            let letter = inline.trim_start_matches('-');
            if program.shell && (flags.contains(letter) || flags.contains('s')) {
                return None;
            }
            if !program.shell && cluster_takes_code(flags, letter, program.language) {
                return None;
            }
        }
        if matches!(
            arg.as_str(),
            "-o" | "+o"
                | "-O"
                | "+O"
                | "--rcfile"
                | "--init-file"
                | "-W"
                | "-X"
                | "-r"
                | "--require"
                | "-I"
        ) && !(arg == "-r" && program.language == Language::Php)
        {
            at += 2;
            continue;
        }
        if arg.starts_with('-') || arg.starts_with('+') {
            at += 1;
            continue;
        }
        return (!is_stdin_path(arg)).then(|| arg.clone());
    }
    None
}

/// Whether a group of short flags of an interpreter (`-uc`, `-ne`, `-pe`,
/// `-le`) holds the flag that takes code inline (`letter`), or Python's
/// `-m`, wherever it stands in the group: read flag by flag up to the first
/// one that takes the rest of the group as its value (`-W`, `-X`, `-I`,
/// `-M`), so the `c` of `-Wignore::DeprecationWarning` is not read as `-c`.
/// Measured 2026-11-20: `python3 -uc CODE` read `CODE` as the script's
/// path, because only a group that starts with the letter was read.
pub(crate) fn cluster_takes_code(flags: &str, letter: &str, language: Language) -> bool {
    let Some(letter) = letter.chars().next() else {
        return false;
    };
    let (values, more_code): (&str, &str) = match language {
        Language::Python => ("WXQ", "m"),
        Language::Perl => ("IMmxiCdD", "E"),
        Language::Ruby => ("IrCEFxKTW", ""),
        Language::Node => ("r", ""),
        Language::Php => ("cdz", ""),
        Language::Lua => ("l", ""),
        _ => ("", ""),
    };
    let mut chars = flags.chars().peekable();
    while let Some(flag) = chars.next() {
        if flag == letter || more_code.contains(flag) {
            return true;
        }
        if values.contains(flag) {
            return false;
        }
        // Perl's `-l` takes octal digits, `-0` octal or `x` and hex ones.
        if language == Language::Perl && matches!(flag, 'l' | '0') {
            if flag == '0' && chars.next_if_eq(&'x').is_some() {
                while chars.next_if(char::is_ascii_hexdigit).is_some() {}
            }
            while chars.next_if(|digit| ('0'..='7').contains(digit)).is_some() {}
        }
    }
    false
}

/// The file `crontab` installs: its first operand past its options, with
/// the value of `-u USER` and `-T` taken off (`crontab -u alice f`
/// installs `f`, not `alice`).
fn crontab_file(args: &[String]) -> Option<String> {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.as_str() {
            "-u" | "-T" => at += 2,
            "--" => return args.get(at + 1).cloned(),
            _ if arg.starts_with('-') => at += 1,
            _ => return Some(arg.clone()),
        }
    }
    None
}

fn is_stdin_path(path: &str) -> bool {
    matches!(path, "-" | "/dev/stdin" | "/dev/fd/0" | "/proc/self/fd/0")
}

/// The makefiles `make` is told to read: `-f FILE`, `-fFILE`,
/// `--file=FILE`, `--makefile=FILE`.
fn make_files(args: &[String]) -> Vec<String> {
    let mut files = Vec::new();
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        if matches!(arg.as_str(), "-f" | "--file" | "--makefile") {
            if let Some(file) = args.get(at + 1) {
                files.push(file.clone());
            }
            at += 2;
            continue;
        }
        if let Some(file) = ["--file=", "--makefile="]
            .iter()
            .find_map(|prefix| arg.strip_prefix(prefix))
            .or_else(|| arg.strip_prefix("-f").filter(|rest| !rest.is_empty()))
        {
            files.push(file.to_owned());
        }
        at += 1;
    }
    files
}

/// The program text of an `awk` command: the first operand after its
/// options, none when it reads its program from a file (`-f`).
fn awk_program(args: &[String]) -> Option<String> {
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        match arg.as_str() {
            "-f" | "--file" => return None,
            "-F" | "-v" | "--assign" | "--field-separator" => at += 2,
            "--" => return args.get(at + 1).cloned(),
            _ if arg.starts_with('-') && arg.len() > 1 => at += 1,
            _ => return Some(arg.clone()),
        }
    }
    None
}

/// Whether an awk program hands what it reads to a shell: `system(` or a
/// print into a pipe (`print | "sh"`).
fn awk_runs_its_input(code: &str) -> bool {
    code.contains("system(")
        || code.contains("system (")
        || code.contains("| \"")
        || code.contains("|\"")
}

/// Whether `parallel` takes each line of its input as a command: no
/// command among its words (options only), and no `:::` list.
fn parallel_reads_commands(args: &[String]) -> bool {
    const VALUED: &[&str] = &[
        "-j",
        "--jobs",
        "-S",
        "--sshlogin",
        "--joblog",
        "--results",
        "--delay",
        "--timeout",
        "-d",
        "--delimiter",
        "-I",
        "--tmpdir",
        "--load",
        "--memfree",
    ];
    let mut at = 0;
    while let Some(arg) = args.get(at) {
        if arg.starts_with(":::") {
            return false;
        }
        if VALUED.contains(&arg.as_str()) {
            at += 2;
            continue;
        }
        if arg.starts_with('-') {
            at += 1;
            continue;
        }
        return false;
    }
    true
}

/// The language and program a script's first line asks for (`#!/bin/sh`,
/// `#!/usr/bin/env python3`), when the table knows it.
pub(crate) fn shebang(text: &str) -> Option<(Language, String)> {
    let first = text.lines().next()?.strip_prefix("#!")?;
    let mut words = first.split_whitespace();
    let mut program = words.next()?.rsplit('/').next()?.to_owned();
    if program == "env" {
        program = words.find(|word| !word.starts_with('-'))?.to_owned();
    }
    let name = versionless(&program);
    let row = super::runners::program(name)?;
    Some((row.language, program))
}

/// A program's name without the version a binary carries (`python3.12`).
pub(crate) fn versionless(name: &str) -> &str {
    if name == "." {
        name
    } else {
        name.trim_end_matches(|character: char| character.is_ascii_digit() || character == '.')
    }
}

/// What runs in a shell when a program reads `text` as `language`, as lines
/// the guard reads: a shell script is itself; a makefile's recipe lines; a
/// crontab's commands; code in another language is the line that would run
/// it from a quoted here-document (`python3 - <<'IW_CODE'`), so the reader of
/// that language judges it as it judges such a line typed out. PHP keeps
/// `php -r '...'`, which reads code without its tags.
///
/// Written as `python3 -c '...'` before 2026-11-21, every `'` of the code
/// became `'\''`, and the reading of the guard's own words took the pieces
/// between those quotes for words beside a part it could not read: a Python
/// test file a line wrote and ran was refused where the same code typed in a
/// here-document was allowed (benchmark of 2026-11-21).
pub(crate) fn shell_lines(language: Language, text: &str, program: &str) -> Vec<String> {
    match language {
        Language::Shell | Language::Awk => vec![text.to_owned()],
        Language::Make => {
            let recipes: Vec<String> = text
                .lines()
                .filter_map(|line| line.strip_prefix('\t'))
                .map(|line| line.trim_start_matches(['@', '-', '+']).to_owned())
                .filter(|line| !line.trim().is_empty())
                .collect();
            if recipes.is_empty() {
                Vec::new()
            } else {
                vec![recipes.join("\n")]
            }
        }
        Language::Crontab => {
            let commands: Vec<String> = text
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .filter(|line| {
                    // `NAME=value`: a setting of the table, not an entry.
                    !line
                        .split_whitespace()
                        .next()
                        .is_some_and(|first| first.contains('=') && !first.starts_with('@'))
                })
                .filter_map(|line| {
                    let fields = if line.starts_with('@') { 1 } else { 5 };
                    let mut rest = line;
                    for _ in 0..fields {
                        rest = rest.trim_start();
                        let end = rest.find(char::is_whitespace)?;
                        rest = &rest[end..];
                    }
                    Some(rest.trim().to_owned())
                })
                .filter(|command| !command.is_empty())
                .collect();
            if commands.is_empty() {
                Vec::new()
            } else {
                vec![commands.join("\n")]
            }
        }
        _ => {
            let row = program_for(language);
            let program = if program.is_empty() { row.0 } else { program };
            let mut code = text.to_owned();
            if language == Language::Php {
                code = code.replace("<?php", "").replace("?>", "");
            }
            // A first line that names the interpreter is not code.
            if code.starts_with("#!") {
                code = code
                    .split_once('\n')
                    .map(|(_, rest)| rest.to_owned())
                    .unwrap_or_default();
            }
            if language == Language::Php {
                return vec![format!("{program} {} {}", row.1, single_quoted(&code))];
            }
            // The lines of the code are read once: the delimiter grows past
            // every line that would end the here-document early.
            let taken: std::collections::HashSet<&str> = code
                .lines()
                .map(|line| line.trim_start_matches('\t'))
                .collect();
            let mut end = String::from("IW_CODE");
            while taken.contains(end.as_str()) {
                end.push('_');
            }
            vec![format!("{program} - <<'{end}'\n{code}\n{end}")]
        }
    }
}

/// The program and inline option a language's code is run with.
fn program_for(language: Language) -> (&'static str, &'static str) {
    match language {
        Language::Python => ("python3", "-c"),
        Language::Node => ("node", "-e"),
        Language::Ruby => ("ruby", "-e"),
        Language::Perl => ("perl", "-e"),
        Language::Php => ("php", "-r"),
        Language::Lua => ("lua", "-e"),
        _ => ("sh", "-c"),
    }
}

/// `text` as one single-quoted shell word.
fn single_quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// What inline code in `language` writes to `path`: `None` when it names no
/// such file in a string, `Some(None)` when it writes it with text it does
/// not spell out, and `Some(Some(text))` when it does (`open('x.sh','w')
/// .write('...')`, `writeFileSync('x.sh', '...')`, `File.write`,
/// `file_put_contents`, Perl's `open` and `print`).
pub(crate) fn code_written_text(
    language: Language,
    code: &str,
    path: &str,
) -> Option<Option<String>> {
    let bare = path.trim_start_matches("./");
    let named = [
        format!("'{bare}'"),
        format!("\"{bare}\""),
        format!("'./{bare}'"),
        format!("\"./{bare}\""),
    ]
    .iter()
    .any(|quoted| code.contains(quoted.as_str()));
    if !named {
        return None;
    }
    let p = format!(r"(?:\./)?{}", regex::escape(bare));
    // A string in single or double quotes, captured without its quotes.
    let s = r#"(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")"#;
    let q = |inner: &str| format!(r#"(?:'{inner}'|"{inner}")"#);
    let pattern = match language {
        Language::Python => format!(
            r"open\(\s*{}\s*,\s*{}\s*\)\s*(?:\.write\(\s*{s}\s*\)|as\s+\w+\s*:\s*\w+\.write\(\s*{s}\s*\))",
            q(&p),
            q(r"[wa]\+?b?")
        ),
        Language::Node => format!(
            r"(?:writeFileSync|appendFileSync|writeFile|appendFile)\(\s*{}\s*,\s*{s}",
            q(&p)
        ),
        Language::Ruby => format!(r"File\.(?:write|binwrite)\(\s*{}\s*,\s*{s}", q(&p)),
        Language::Php => format!(r"file_put_contents\(\s*{}\s*,\s*{s}", q(&p)),
        Language::Perl => format!(
            r"open\s*\(?\s*(?:my\s+)?\$?\w+\s*,\s*(?:{}\s*,\s*{}|{})\s*\)?\s*(?:or\s+die[^;]*)?;\s*print\s+\{{?\$?\w+\}}?\s+{s}",
            q(">>?"),
            q(&p),
            q(&format!(">>?\\s*{p}"))
        ),
        _ => return Some(None),
    };
    let Ok(regex) = regex::Regex::new(&pattern) else {
        return Some(None);
    };
    let Some(found) = regex.captures(code) else {
        return Some(None);
    };
    let (text, double) = match (found.get(1).or(found.get(3)), found.get(2).or(found.get(4))) {
        (Some(single), _) => (single.as_str(), false),
        (None, Some(double)) => (double.as_str(), true),
        _ => return Some(None),
    };
    // A double-quoted string may expand in Perl, PHP and Ruby (`$x`, `#{}`),
    // and a template literal in Node: what it writes is not spelled out.
    if double
        && matches!(language, Language::Perl | Language::Php | Language::Ruby)
        && text.contains(['$', '#', '@'])
    {
        return Some(None);
    }
    if text.contains('\\') && !text.contains("\\n") && !text.contains("\\t") {
        return Some(None);
    }
    Some(Some(text.replace("\\n", "\n").replace("\\t", "\t")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    /// Every launcher row of the table is one the guard reads through: the
    /// command after it is judged. FAILS ON REVERT of a launcher's reading,
    /// or when a row is added that no reading follows.
    #[test]
    fn every_launcher_in_the_table_is_read_through() {
        let forms: &[(&str, &str)] = &[
            ("env", "env rm -rf ~/.ssh"),
            ("sudo", "sudo rm -rf ~/.ssh"),
            ("doas", "doas rm -rf ~/.ssh"),
            ("nice", "nice -n 5 rm -rf ~/.ssh"),
            ("nohup", "nohup rm -rf ~/.ssh"),
            ("timeout", "timeout 5 rm -rf ~/.ssh"),
            ("setsid", "setsid rm -rf ~/.ssh"),
            ("stdbuf", "stdbuf -oL rm -rf ~/.ssh"),
            ("busybox", "busybox rm -rf ~/.ssh"),
            ("find", "find . -maxdepth 0 -exec rm -rf ~/.ssh \\;"),
            ("watch", "watch rm -rf ~/.ssh"),
            ("su", "su -c 'rm -rf ~/.ssh'"),
            ("systemd-run", "systemd-run rm -rf ~/.ssh"),
        ];
        let launchers: Vec<&str> = every_program()
            .filter(|(_, row)| row.launcher)
            .map(|(name, _)| name)
            .collect();
        for name in &launchers {
            let (_, line) = forms
                .iter()
                .find(|(form, _)| form == name)
                .unwrap_or_else(|| panic!("no form for launcher `{name}`"));
            assert_eq!(
                crate::mcp::analyze_command(line, None).recommendation,
                "deny",
                "{line}"
            );
        }
        assert_eq!(launchers.len(), forms.len());
    }

    #[test]
    fn the_table_reads() {
        for name in [
            "sh", "tcsh", "csh", "ash", "python", "node", "at", "make", "awk", "crontab",
        ] {
            assert!(program(name).is_some(), "{name}");
        }
        assert!(program("tcsh").is_some_and(|row| row.shell && row.sink && row.stdin_code));
        assert!(program("at").is_some_and(|row| !row.sink && row.stdin_script));
    }

    #[test]
    fn what_each_runner_reads_on_stdin() {
        assert_eq!(stdin_script("at", &words("now")), Some(Language::Shell));
        assert_eq!(stdin_script("at", &words("-f job now")), None);
        assert_eq!(stdin_script("batch", &[]), Some(Language::Shell));
        assert_eq!(stdin_script("make", &words("-f -")), Some(Language::Make));
        assert_eq!(stdin_script("make", &words("all")), None);
        assert_eq!(
            stdin_script("awk", &["{system($0)}".to_owned()]),
            Some(Language::Shell)
        );
        assert_eq!(stdin_script("awk", &["{print $1}".to_owned()]), None);
        assert_eq!(
            stdin_script("parallel", &words("-j 4")),
            Some(Language::Shell)
        );
        assert_eq!(stdin_script("parallel", &words("gzip")), None);
        assert_eq!(stdin_script("sh", &[]), None);
    }

    #[test]
    fn the_files_each_runner_runs() {
        assert_eq!(
            file_scripts("sh", &words("x.sh")),
            vec![("x.sh".to_owned(), Language::Shell)]
        );
        assert_eq!(file_scripts("sh", &words("-c x.sh")), vec![]);
        assert_eq!(
            file_scripts("tcsh", &words("-f x.sh")),
            vec![("x.sh".to_owned(), Language::Shell)]
        );
        assert_eq!(
            file_scripts("python", &words("-u x.py a")),
            vec![("x.py".to_owned(), Language::Python)]
        );
        assert_eq!(file_scripts("python", &words("-m http.server")), vec![]);
        assert_eq!(
            file_scripts("source", &words("x.sh")),
            vec![("x.sh".to_owned(), Language::Shell)]
        );
        assert_eq!(
            file_scripts("at", &words("-f j.txt now")),
            vec![("j.txt".to_owned(), Language::Shell)]
        );
        assert_eq!(
            file_scripts("make", &words("-f x.mk")),
            vec![("x.mk".to_owned(), Language::Make)]
        );
        assert_eq!(file_scripts("make", &words("test")).len(), 3);
        assert_eq!(file_scripts("xargs", &words("rm")), vec![]);
    }

    #[test]
    fn code_that_writes_a_file() {
        assert_eq!(
            code_written_text(
                Language::Python,
                "open('x.sh','w').write('rm -rf ~')",
                "x.sh"
            ),
            Some(Some("rm -rf ~".to_owned()))
        );
        assert_eq!(
            code_written_text(
                Language::Node,
                "require('fs').writeFileSync('x.sh', \"id\")",
                "./x.sh"
            ),
            Some(Some("id".to_owned()))
        );
        assert_eq!(
            code_written_text(Language::Php, "file_put_contents('x.sh', $x);", "x.sh"),
            Some(None)
        );
        assert_eq!(code_written_text(Language::Ruby, "puts 1", "x.sh"), None);
    }

    #[test]
    fn a_makefile_and_a_crontab_are_read_for_what_they_run() {
        assert_eq!(
            shell_lines(Language::Make, "all:\n\t@curl -s u | sh\n", ""),
            vec!["curl -s u | sh".to_owned()]
        );
        assert_eq!(
            shell_lines(
                Language::Crontab,
                "MAILTO=x\n* * * * * id\n@reboot rm -rf ~\n",
                ""
            ),
            vec!["id\nrm -rf ~".to_owned()]
        );
        assert_eq!(
            shell_lines(Language::Python, "import os\nos.system('id')", "python3"),
            vec!["python3 - <<'IW_CODE'\nimport os\nos.system('id')\nIW_CODE".to_owned()]
        );
    }

    /// `crontab -u USER FILE` installs FILE, not USER; `-T FILE` only checks
    /// FILE and installs nothing.
    #[test]
    fn the_file_crontab_installs_is_past_the_user() {
        let files = |args: &[String]| file_scripts("crontab", args);
        let crontab = |path: &str| vec![(path.to_owned(), Language::Crontab)];
        assert_eq!(
            files(&["-u".to_owned(), "alice".to_owned(), "c.txt".to_owned()]),
            crontab("c.txt")
        );
        assert_eq!(
            files(&["-ualice".to_owned(), "c.txt".to_owned()]),
            crontab("c.txt")
        );
        assert_eq!(files(&["c.txt".to_owned()]), crontab("c.txt"));
        assert_eq!(files(&["-T".to_owned(), "c.txt".to_owned()]), vec![]);
        assert_eq!(files(&["-l".to_owned()]), vec![]);
    }

    /// The flag that takes code inline is read anywhere in a group of short
    /// flags, up to the first flag that takes the rest as its value.
    #[test]
    fn inline_code_is_read_anywhere_in_a_group_of_flags() {
        assert!(cluster_takes_code("uc", "c", Language::Python));
        assert!(cluster_takes_code("Bc", "c", Language::Python));
        assert!(cluster_takes_code("um", "c", Language::Python));
        assert!(!cluster_takes_code(
            "Wignore::DeprecationWarning",
            "c",
            Language::Python
        ));
        assert!(!cluster_takes_code(
            "Xfrozen_modules=off",
            "c",
            Language::Python
        ));
        assert!(cluster_takes_code("ne", "e", Language::Perl));
        assert!(cluster_takes_code("pe", "e", Language::Perl));
        assert!(cluster_takes_code("le", "e", Language::Perl));
        assert!(cluster_takes_code("lE", "e", Language::Perl));
        assert!(cluster_takes_code("0777ne", "e", Language::Perl));
        assert!(!cluster_takes_code("MLWP::Simple", "e", Language::Perl));
        assert!(!cluster_takes_code("pi.bak", "e", Language::Perl));
        // A script after such a group is not inline code: it is read.
        assert_eq!(
            file_scripts("python", &["-u".to_owned(), "x.py".to_owned()]),
            vec![("x.py".to_owned(), Language::Python)]
        );
        assert_eq!(
            file_scripts("python", &["-uc".to_owned(), "print(1)".to_owned()]),
            vec![]
        );
        assert_eq!(
            file_scripts(
                "perl",
                &["-ne".to_owned(), "print".to_owned(), "f".to_owned()]
            ),
            vec![]
        );
    }
}
