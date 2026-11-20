//! A shell call that opens an interpreter and leaves it waiting for input.
//!
//! Codex CLI runs a command in one call (`exec_command`) and can type into
//! it in the next (`write_stdin`). Its PreToolUse hook runs for the first and
//! never for the second (read in Codex CLI 0.167.2's source:
//! `codex-rs/core/src/tools/handlers/unified_exec/write_stdin.rs` has no
//! `pre_tool_use_payload`). So `bash` alone passes the guard as a harmless
//! word, and every line typed into it afterwards runs unscreened: a call
//! rated deny is not refused, it is only moved into the next call. Hermes
//! Agent does the same with a `terminal` run in the background and
//! `process_manage` `write` or `submit`.
//!
//! The hook payload does not say whether the command gets a terminal (Codex
//! sends `{"command"}` alone), so the guard cannot wait for the second call:
//! in enforce mode the first one is refused when it starts a shell, a
//! language or a database client with no script and no command to run, which
//! is the only reason to start one there. A program given its script or its
//! code (`bash build.sh`, `python3 -c ...`, `psql -c ...`) is judged by the
//! shell rules as before.

use crate::threats::{shell_command_segments, shell_tokens_with_braces};

/// What the guard says when it refuses one.
pub const INTERACTIVE_REFUSAL: &str =
    "starts an interpreter that waits for input; what is typed into it later is not screened";

/// How a program reads code when it is given none on its command line.
#[derive(Clone, Copy)]
enum Waits {
    /// A shell or a language: any operand is its script.
    Script,
    /// A database or service client: operands name what it connects to,
    /// and only these flags hand it the work to do.
    Client(&'static [&'static str]),
    /// SQLite: its first operand is the database, the second the SQL.
    Sqlite,
}

/// The programs that wait for input when started with nothing to run, by
/// name with any version suffix taken off (`python3.12` is `python`).
fn waits_for_input(program: &str) -> Option<Waits> {
    const DB_FLAGS: &[&str] = &[
        "-c",
        "--command",
        "-f",
        "--file",
        "-e",
        "--execute",
        "--eval",
    ];
    Some(match program {
        "sh" | "bash" | "zsh" | "fish" | "dash" | "ksh" | "mksh" | "ash" | "csh" | "tcsh"
        | "nu" | "xonsh" | "elvish" | "pwsh" | "powershell" | "python" | "ipython" | "bpython"
        | "pypy" | "node" | "nodejs" | "deno" | "bun" | "irb" | "pry" | "ruby" | "perl" | "php"
        | "lua" | "luajit" | "julia" | "ghci" | "scala" | "jshell" | "tclsh" | "wish" | "guile"
        | "racket" | "iex" | "erl" | "osascript" | "gdb" | "lldb" => Waits::Script,
        "psql" | "mysql" | "mariadb" | "redis-cli" | "mongosh" | "mongo" | "clickhouse-client"
        | "cqlsh" => Waits::Client(DB_FLAGS),
        "sqlite" => Waits::Sqlite,
        _ => return None,
    })
}

/// The flags that hand a shell or a language its code in place of a script:
/// with one of them, the program does not wait.
const CODE_FLAGS: &[&str] = &["-c", "-e", "-m", "-r", "--eval", "--command", "--exec"];

/// Wrappers that run the program after them.
const WRAPPERS: &[&str] = &[
    "exec", "env", "command", "nohup", "time", "nice", "sudo", "doas",
];

/// PURE. The interpreter a shell line starts with nothing to run, waiting
/// for input, or `None`. A line that feeds it (`bash < build.sh`,
/// `bash <<EOF`) or names its script or code is not one. Each segment of the
/// line is asked, with the wrappers in front of it and the variables it sets
/// taken off.
pub fn interactive_interpreter(command: &str) -> Option<String> {
    shell_command_segments(command)
        .into_iter()
        .find_map(|segment| {
            if segment.contains('<') {
                return None;
            }
            let words = shell_tokens_with_braces(segment);
            let at = program_position(&words)?;
            let program = program_name(&words[at]);
            let waits = waits_for_input(&program)?;
            let rest = &words[at..][1..];
            let given_work = match waits {
                Waits::Script => rest.iter().any(|word| {
                    let flag = word.split('=').next().unwrap_or(word);
                    !word.starts_with('-')
                    || CODE_FLAGS.contains(&flag)
                    // `bash -lc 'x'`: a group of short flags holding `c`.
                    || (!flag.starts_with("--") && flag.contains('c'))
                }),
                Waits::Client(flags) => rest.iter().any(|word| {
                    let flag = word.split('=').next().unwrap_or(word);
                    flags.contains(&flag)
                }),
                Waits::Sqlite => rest.iter().filter(|word| !word.starts_with('-')).count() > 1,
            };
            (!given_work).then_some(program)
        })
}

/// Where the program of a segment's words stands: past the variables it
/// sets and the wrappers in front of it, and past a wrapper's own flags
/// (`sudo -E`, `env -i`). `None` when there is no program.
fn program_position(words: &[String]) -> Option<usize> {
    let mut after_a_prefix = false;
    words.iter().position(|word| {
        let assigns = word
            .split_once('=')
            .is_some_and(|(name, _)| crate::threats::is_shell_name(name));
        if assigns || WRAPPERS.contains(&program_name(word).as_str()) {
            after_a_prefix = true;
            return false;
        }
        !(after_a_prefix && word.starts_with('-'))
    })
}

/// A program's name as it is asked about: its last path part, lowercase,
/// quotes off, and a version suffix taken off (`python3.12`, `pypy3`).
fn program_name(word: &str) -> String {
    let word = word.trim_matches(['\'', '"']);
    let base = word.rsplit('/').next().unwrap_or(word).to_ascii_lowercase();
    let unversioned = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if unversioned.is_empty() {
        base
    } else {
        unversioned.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FAILS ON REVERT of `interactive_interpreter` (answer `None`): each of
    /// these is a shell, a language or a client left waiting for input.
    #[test]
    fn an_interpreter_with_nothing_to_run_waits_for_input() {
        for (line, program) in [
            ("bash", "bash"),
            ("bash -i", "bash"),
            ("bash -l", "bash"),
            ("bash --login", "bash"),
            ("sh -s", "sh"),
            ("/bin/zsh", "zsh"),
            ("fish", "fish"),
            ("dash", "dash"),
            ("python3", "python"),
            ("python3.12 -i", "python"),
            ("python3 -", "python"),
            ("node", "node"),
            ("irb", "irb"),
            ("perl", "perl"),
            ("psql", "psql"),
            ("psql -h db -U app appdb", "psql"),
            ("sqlite3 app.db", "sqlite"),
            ("exec bash", "bash"),
            ("sudo -E bash", "bash"),
            ("env FOO=1 bash -i", "bash"),
            ("cd /tmp && bash", "bash"),
            ("cat | bash", "bash"),
            ("TERM=dumb zsh -l", "zsh"),
        ] {
            assert_eq!(
                interactive_interpreter(line).as_deref(),
                Some(program),
                "{line}"
            );
        }
    }

    /// The twins: the same programs given their script or code, fed from a
    /// file or a here-document, or a program that is no interpreter.
    #[test]
    fn an_interpreter_given_its_work_does_not_wait() {
        for line in [
            "bash script.sh",
            "bash -c 'echo hi'",
            "bash -lc 'make test'",
            "sh -ec 'true'",
            "sh -ec",
            "bash -lc",
            "python3 -c 'print(1)'",
            "python3 -m pytest -q",
            "python3 app.py",
            "node server.js",
            "node -e 'console.log(1)'",
            "ruby -e 'p 1'",
            "perl -e 'print 1'",
            "psql -c 'select 1'",
            "psql -h db -f migrate.sql",
            "mysql --execute='select 1'",
            "sqlite3 app.db 'select 1'",
            "bash < build.sh",
            "bash <<'EOF'\necho hi\nEOF",
            "ls -la",
            "git status",
            "cargo test",
            "npm test",
            "echo bash",
            // Not an assignment: the shell runs `a-b=1` as the program.
            "a-b=1 bash",
        ] {
            assert_eq!(interactive_interpreter(line), None, "{line}");
        }
    }
}
