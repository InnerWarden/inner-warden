//! A file size limit lowered on the agent, or on what will start the guard's
//! hook.
//!
//! A process that writes past its soft `RLIMIT_FSIZE` gets `SIGXFSZ`, whose
//! default action ends it, and the limit is inherited. Measured 2026-11-26
//! with release binaries on a disposable home: with the agent's limit
//! lowered to 1 KiB the hook died by that signal before it answered, a
//! refused command included, and an agent runs a call whose hook gave no
//! answer. The lines that set it up were all allowed or only asked:
//! `prlimit --pid $PPID --fsize=1024`, Python's
//! `resource.prlimit(os.getppid(), resource.RLIMIT_FSIZE, ...)`,
//! `ulimit -f 1`, and `prlimit` on the pid `pgrep` finds for the agent.
//! (The hook now survives such a limit; this keeps the act itself in view.)
//!
//! Read here, in the whole line with its quotes and backslashes dropped (an
//! inline program and a here-document included):
//!
//! - a file size limit lowered for the agent's process (`$PPID`,
//!   `getppid`, a `ppid` read from `ps`), for a program the line names as
//!   an agent or the guard (`pgrep -n claude`, `ulimit -f 1; codex`,
//!   `prlimit --fsize=1 innerwarden hook`): refused;
//! - a file size or core limit lowered for any other process (`prlimit
//!   --pid N`, `resource.prlimit(pid, ...)`), or a file size limit lowered
//!   in the shell itself (`ulimit -f N`), which every program that shell
//!   starts later inherits: held for the person.
//!
//! Raising a limit (`unlimited`), reading one (`ulimit -f`, `prlimit --pid
//! N`), the other limits (`ulimit -n 4096`, `prlimit --nofile=...`,
//! `ulimit -c unlimited`) and a lower limit handed to a program the line
//! starts that is no agent (`prlimit --fsize=10M ./build.sh`) are left
//! alone.

use std::sync::LazyLock;

use regex::Regex;

/// What a refusal says.
pub(crate) const AGENT_FILE_SIZE_LOWERED: &str =
    "lowers the file size limit of the agent or of the guard: \
     the guard's hook it starts is killed by SIGXFSZ at its first write past the limit, and a call \
     whose hook gave no answer runs unscreened";

/// What a hold says.
pub(crate) const PROCESS_LIMIT_LOWERED: &str =
    "lowers the file size or core limit of another process, \
     or the file size limit of the shell for what it starts later";

/// `--fsize` or `--core` with a value (`prlimit`'s long options).
static LONG_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)--(fsize|core)(?:=(\S*)|\s+([0-9$:]\S*))").expect("static long option regex")
});

/// `-f` or `-c` with a value glued or after a space (`prlimit`'s short
/// options), read only on a line that names `prlimit`.
static SHORT_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s)-([fc])(?:=?([0-9$:]\S*)|\s+([0-9$:]\S*))")
        .expect("static short option regex")
});

/// The pid `prlimit` is given: `--pid N`, `--pid=N`, `-p N`, `-pN`.
static PID_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:--pid(?:=|\s+)|(?:^|\s)-p\s*)(\S+)").expect("static pid option regex")
});

/// `ulimit` with its options and the value after them.
static ULIMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bulimit((?:\s+-[A-Za-z]+)+)\s+([^\s;&|)`]+)").expect("static ulimit regex")
});

/// A call that sets a limit in code: Python's `resource.prlimit(pid, RES,
/// ...)` and `resource.setrlimit(RES, ...)`, Perl's `setrlimit(RES, ...)`,
/// the resource by name or by its Linux number (1 is the file size, 4 the
/// core).
static CODE_PRLIMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\bprlimit\s*\(\s*([^,]+?)\s*,\s*(?:[A-Za-z_]\w*\.)?(RLIMIT_FSIZE|RLIMIT_CORE|1|4)\s*[,)]",
    )
    .expect("static code prlimit regex")
});
static CODE_SETRLIMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bsetrlimit\s*\(\s*(?:[A-Za-z_]\w*\.)?(RLIMIT_FSIZE|1)\s*,")
        .expect("static code setrlimit regex")
});

/// The agent's own process named: the parent's pid, read in any language
/// (`$PPID`, `os.getppid()`, `process.ppid`, `ps -o ppid=`).
static PARENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bppid\b|getppid").expect("static parent regex"));

/// A pid that is the process itself (`0`, `$$`, `os.getpid()`).
static OWN_PID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:0|\$\$|\$\{\$\}|(?:os\.)?getpid\(\s*\)|\$\$\$)$")
        .expect("static own pid regex")
});

/// The guard's own program names, besides the agents'.
const GUARD_PROGRAMS: &[&str] = &["innerwarden", "innerwarden-agent-guard", "cursor-agent"];

/// The line with quotes and backslashes dropped, as the shell joins
/// `'pr'limit` and `"--fsize"=1`.
fn joined(command: &str) -> String {
    command
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\'))
        .collect()
}

/// Whether a limit value lowers the limit: any part of `soft:hard` that is
/// not `unlimited` (a number, a variable, a suffix such as `10M`). An
/// empty value is a read.
fn lowers(value: &str) -> bool {
    let value = value.trim_end_matches([';', '&', '|', ')']);
    value.split(':').any(|part| {
        let part = part.trim().to_ascii_lowercase();
        !part.is_empty() && part != "unlimited" && part != "infinity" && part != "-1"
    })
}

/// Whether the line names an agent or the guard as a word (`claude`,
/// `/usr/local/bin/codex`, `innerwarden`), by the program names the guard
/// knows for each agent.
fn names_an_agent(line: &str) -> bool {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/')))
        .filter_map(|word| word.rsplit('/').next())
        .map(str::to_ascii_lowercase)
        .any(|word| {
            GUARD_PROGRAMS.contains(&word.as_str())
                || crate::agents::KNOWN.iter().any(|known| {
                    known.executables.contains(&word.as_str())
                        || known.aliases.iter().any(|alias| *alias == word)
                })
        })
}

/// `alias NAME=prlimit`: the name the line gives `prlimit`.
static PRLIMIT_ALIAS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\balias\s+([A-Za-z0-9_.-]+)=\S*\bprlimit\b").expect("static alias regex")
});

/// What the line lowers, if anything.
#[derive(Default)]
struct Lowered {
    /// A file size limit of a process the line names by pid.
    other_file_size: bool,
    /// A core limit of a process the line names by pid.
    other_core: bool,
    /// A file size limit of the shell or the program itself.
    own_file_size: bool,
    /// A file size limit handed to a program `prlimit` starts.
    started_file_size: bool,
}

/// Whether a word of the segment is `prlimit` (by any path) or a name the
/// line gave it.
fn runs_prlimit(segment: &str, aliases: &[String]) -> bool {
    segment
        .split_whitespace()
        .filter_map(|word| word.rsplit('/').next())
        .any(|word| word == "prlimit" || aliases.iter().any(|alias| alias == word))
}

fn read(line: &str) -> Lowered {
    let mut found = Lowered::default();
    let aliases: Vec<String> = PRLIMIT_ALIAS
        .captures_iter(line)
        .map(|caps| caps[1].to_string())
        .collect();
    for segment in line.split(['\n', ';', '&', '|']) {
        let prlimit = runs_prlimit(segment, &aliases);
        let mut file_size = false;
        let mut core = false;
        for caps in LONG_OPTION.captures_iter(segment) {
            let value = caps.get(2).or(caps.get(3)).map_or("", |m| m.as_str());
            if lowers(value) {
                match caps[1].to_ascii_lowercase().as_str() {
                    "fsize" => file_size = true,
                    _ => core = true,
                }
            }
        }
        if prlimit {
            for caps in SHORT_OPTION.captures_iter(segment) {
                let value = caps.get(2).or(caps.get(3)).map_or("", |m| m.as_str());
                if lowers(value) {
                    match &caps[1] {
                        "f" => file_size = true,
                        _ => core = true,
                    }
                }
            }
        }
        if !(file_size || core) {
            continue;
        }
        let pid = PID_OPTION
            .captures_iter(segment)
            .filter(|caps| prlimit || caps[0].contains("--pid"))
            .map(|caps| caps[1].trim_end_matches(')').to_string())
            .next();
        match pid {
            Some(pid) if OWN_PID.is_match(&pid) => found.own_file_size |= file_size,
            Some(_) => {
                found.other_file_size |= file_size;
                found.other_core |= core;
            }
            None => found.started_file_size |= file_size,
        }
    }
    for caps in ULIMIT.captures_iter(line) {
        if caps[1].contains('f') && lowers(&caps[2]) {
            found.own_file_size = true;
        }
    }
    for caps in CODE_PRLIMIT.captures_iter(line) {
        let file = matches!(&caps[2], "RLIMIT_FSIZE" | "1");
        if OWN_PID.is_match(caps[1].trim()) {
            found.own_file_size |= file;
        } else if file {
            found.other_file_size = true;
        } else {
            found.other_core = true;
        }
    }
    if CODE_SETRLIMIT.is_match(line) {
        found.own_file_size = true;
    }
    found
}

/// The finding for a line that lowers a file size limit of the agent or of
/// what starts the guard's hook (refused, 60), or a file size or core limit
/// of another process or of the shell itself (held, 30).
pub(crate) fn check_limit_lowered(command: &str) -> Option<(&'static str, u32)> {
    let line = joined(command);
    let found = read(&line);
    let file_size = found.other_file_size || found.own_file_size || found.started_file_size;
    if file_size && (PARENT.is_match(&line) || names_an_agent(&line)) {
        return Some((AGENT_FILE_SIZE_LOWERED, 60));
    }
    if found.other_file_size || found.other_core || found.own_file_size {
        return Some((PROCESS_LIMIT_LOWERED, 30));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(line: &str) -> String {
        crate::mcp::analyze_command(line, None).recommendation
    }

    /// The agent's own file size limit lowered, by the lines measured
    /// allowed (or held) on main and their spellings: refused.
    ///
    /// FAILS ON REVERT: without the check in `analyze_command` each of these
    /// is allowed (one held for review); without its exemption in
    /// `mention_only` the Python lines are lowered to a review.
    #[test]
    fn a_file_size_limit_lowered_on_the_agent_is_refused() {
        for line in [
            "prlimit --pid $PPID --fsize=1024",
            "prlimit --pid ${PPID} --fsize 1024",
            "python3 -c 'import resource,os; resource.prlimit(os.getppid(), resource.RLIMIT_FSIZE, (1024, 1024))'",
            "python3 <<'EOF'\nimport os, resource\nresource.prlimit(os.getppid(), resource.RLIMIT_FSIZE, (1024, 1024))\nEOF",
            "prlimit --pid $(pgrep -n claude) --fsize=1024",
            "prlimit --pid \"$(pidof codex)\" --fsize=:2048",
            "\"prl\"'imit' --pid \"$PPID\" \"--fsize=1024\"",
            "/usr/bin/prlimit -p $PPID -f1024",
            "alias pl=prlimit; pl -p $PPID -f1024",
            "perl -MBSD::Resource -e 'setrlimit(RLIMIT_FSIZE, 1024, 1024); exec \"claude\"'",
            "node -e 'require(\"child_process\").execSync(\"prlimit --pid \" + process.ppid + \" --fsize=1024\")'",
            "ulimit -f 1; claude -p hi",
            "ulimit -Sf 0 && exec gemini",
            "pid=$(ps -o ppid= -p $$); prlimit --pid $pid --fsize=1024",
            "python3 -c 'import resource,os; resource.prlimit(os.getppid(), 1, (1, 1))'",
        ] {
            assert_eq!(verdict(line), "deny", "{line}");
            assert_eq!(
                check_limit_lowered(line).map(|(what, _)| what),
                Some(AGENT_FILE_SIZE_LOWERED),
                "{line}"
            );
        }
    }

    /// Another process's limit, or the shell's own file size limit, is held
    /// for the person.
    ///
    /// FAILS ON REVERT: allowed without the check.
    #[test]
    fn another_process_limit_or_the_shells_own_is_held() {
        for line in [
            "ulimit -f 1",
            "ulimit -S -f 100",
            "prlimit --pid 4242 --fsize=1024",
            "prlimit --pid 4242 --core=0",
            "prlimit --pid $$ --fsize=1",
            "python3 -c 'import resource; resource.setrlimit(resource.RLIMIT_FSIZE, (1, 1))'",
            "python3 -c 'import resource; resource.prlimit(4242, resource.RLIMIT_CORE, (0, 0))'",
        ] {
            assert_eq!(verdict(line), "review", "{line}");
            assert_eq!(
                check_limit_lowered(line).map(|(what, _)| what),
                Some(PROCESS_LIMIT_LOWERED),
                "{line}"
            );
        }
    }

    /// Raising a limit, reading one, the other limits and a lower limit for
    /// a program that is no agent stay as they were.
    #[test]
    fn everyday_limit_lines_are_left_alone() {
        for line in [
            "ulimit -n 4096",
            "ulimit -n",
            "ulimit -a",
            "ulimit -c unlimited",
            "ulimit -c 0",
            "ulimit -s unlimited",
            "ulimit -f",
            "ulimit -f unlimited",
            "prlimit --nofile=65536 cargo test",
            "prlimit --pid 1234 --nofile=65536",
            "prlimit --pid $$",
            "prlimit",
            "prlimit --fsize=unlimited make",
            "prlimit --nproc=512 ./run.sh",
            "ulimit -n 65536 && cargo build --release",
            "mkdir -p out && prlimit --nofile=4096 make -j8",
            "mkdir -p out && prlimit --fsize=10M ./build.sh",
            "python3 -c 'import resource; print(resource.getrlimit(resource.RLIMIT_NOFILE))'",
            "python3 -c 'import resource; resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))'",
            "cat /proc/self/limits",
            "tail -f -n 100 logs/app.log",
            "docker run --rm --ulimit nofile=1024:1024 alpine true",
            "ulimit -c unlimited && ./crash_test",
            "git log -p --stat -n 3",
        ] {
            assert_eq!(check_limit_lowered(line), None, "{line}");
            assert_eq!(verdict(line), "allow", "{line}");
        }
    }
}
