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
//! - a file size limit lowered by `prlimit` or code whose target is the
//!   agent: the pid it is given is the agent's (`$PPID`, `getppid`, a
//!   `ppid` read from `ps`, the pid `pgrep` or `pidof` finds for an agent
//!   or the guard, a variable the line gave one of those), or the program
//!   `prlimit` starts is an agent or the guard (`prlimit --fsize=1
//!   innerwarden hook`): refused. An agent, the guard or `ppid` named
//!   anywhere else on the line does not count;
//! - a file size or core limit lowered for any other process (`prlimit
//!   --pid N`, `resource.prlimit(pid, ...)`): held for the person; the
//!   shell's or the program's own (`ulimit -f N`, `setrlimit`, `prlimit
//!   --pid $$`) with no agent started after it: allowed.
//!
//! `ulimit` and `setrlimit` set the limit of the shell or the program
//! itself and of its children: refused only when a command after them on
//! the line starts an agent or the guard's hook (`ulimit -n 3; claude`,
//! `(ulimit -t 0; exec codex)`, `ulimit -n 3 && npx @anthropic-ai/claude-code`),
//! read by its command word. An agent, the guard or `ppid` named in a path,
//! an argument or an option does not count (decided 2026-11-26, after
//! `ulimit -n 256` on a line that only named `codex`, `ppid` or the guard
//! was refused).
//!
//! Raising a limit (`unlimited`), reading one (`ulimit -f`, `prlimit --pid
//! N`), the other limits (`ulimit -n 4096`, `prlimit --nofile=...`,
//! `ulimit -c unlimited`) and a lower limit handed to a program the line
//! starts that is no agent (`prlimit --fsize=10M ./build.sh`) are left
//! alone.
//!
//! The other limits an inherited value can turn against the hook, measured
//! the same way: a CPU limit of 0, an address space of 16 MiB or three open
//! files end it before its first instruction, and low data, open file and
//! stack limits made it refuse every call. The hook now raises what it can
//! (`crates/cli/src/hook_limits.rs`), but not what ends it before it runs,
//! so the guard reads those too:
//!
//! - a CPU time (`--cpu`, `-t`, `RLIMIT_CPU`), address space (`--as`,
//!   `-v`, `RLIMIT_AS`), data (`--data`, `-d`, `RLIMIT_DATA`), open file
//!   (`--nofile`, `-n`, `RLIMIT_NOFILE`) or stack (`--stack`, `-s`,
//!   `RLIMIT_STACK`) limit lowered by `prlimit` or code whose target is the
//!   agent, as above: refused;
//! - lowered means below what an agent and its hook need to run: under 60
//!   seconds of CPU, 256 MiB of memory, 1024 open files, the usual 8 MiB of
//!   stack, or a value the line does not spell (a variable);
//! - for any other process or the shell itself these limits stay allowed,
//!   as everyday tuning (`ulimit -n 4096`, `ulimit -n 256 && npm test`,
//!   `prlimit --pid N --nofile=...`).

use std::sync::LazyLock;

use regex::Regex;

/// What a refusal says.
pub(crate) const AGENT_FILE_SIZE_LOWERED: &str =
    "lowers the file size limit of the agent or of the guard: \
     the guard's hook it starts is killed by SIGXFSZ at its first write past the limit, and a call \
     whose hook gave no answer runs unscreened";

/// What a refusal of another limit says.
pub(crate) const AGENT_LIMIT_LOWERED: &str =
    "lowers the CPU time, memory, open file or stack limit of the agent or of the guard: \
     the guard's hook inherits it and is killed before it runs or cannot screen, and a call \
     whose hook gave no answer runs unscreened";

/// What a hold says.
pub(crate) const PROCESS_LIMIT_LOWERED: &str =
    "lowers the file size or core limit of another process";

/// `--fsize`, `--core` or another limit the hook depends on, with a value
/// (`prlimit`'s long options).
static LONG_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)--(fsize|core|cpu|as|data|nofile|stack)(?:=(\S*)|\s+([0-9$:]\S*))")
        .expect("static long option regex")
});

/// `-f` or `-c` with a value glued or after a space (`prlimit`'s short
/// options), read only on a line that names `prlimit`.
static SHORT_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|\s)-([fctvdns])(?:=?([0-9$:]\S*)|\s+([0-9$:]\S*))")
        .expect("static short option regex")
});

/// The option that gives `prlimit` its pid: `--pid N`, `--pid=N`, `-p N`,
/// `-pN`; the value is read by [`pid_value`].
static PID_OPTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:--pid(?:=|\s+)|(?:^|\s)-p\s*)").expect("static pid option regex")
});

/// `ulimit` with its options and the value after them (`-n 3`, `-n3`).
static ULIMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\bulimit((?:\s+-[A-Za-z]+)+)\s*([^\s;&|)`]+)").expect("static ulimit regex")
});

/// A call that sets a limit in code: Python's `resource.prlimit(pid, RES,
/// ...)` and `resource.setrlimit(RES, ...)`, Perl's `setrlimit(RES, ...)`,
/// the resource by name or by its Linux number, with the soft value that
/// follows it when there is one.
static CODE_PRLIMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\bprlimit\s*\(\s*([^,]+?)\s*,\s*(?:[A-Za-z_]\w*\.)?(RLIMIT_[A-Z]+|[0-9]+)\s*(?:\)|,\s*\(?\s*([^,\s)]*))",
    )
    .expect("static code prlimit regex")
});
static CODE_SETRLIMIT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\bsetrlimit\s*\(\s*(?:[A-Za-z_]\w*\.)?(RLIMIT_[A-Z]+|[0-9]+)\s*,\s*\(?\s*([^,\s)]*)",
    )
    .expect("static code setrlimit regex")
});

/// A limit the guard reads.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Limit {
    FileSize,
    Core,
    Cpu,
    Memory,
    OpenFiles,
    Stack,
}

impl Limit {
    /// By `prlimit`'s long option name or its short letter (`-c` core,
    /// `-d` data, `-f` file size, `-n` open files, `-s` stack, `-t` CPU,
    /// `-v` address space); `ulimit` uses the same letters.
    fn by_option(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "fsize" | "f" => Self::FileSize,
            "core" | "c" => Self::Core,
            "cpu" | "t" => Self::Cpu,
            "as" | "data" | "v" | "d" => Self::Memory,
            "nofile" | "n" => Self::OpenFiles,
            "stack" | "s" => Self::Stack,
            _ => return None,
        })
    }

    /// By the name or Linux number code gives it (`RLIMIT_FSIZE`, `1`).
    fn by_code(name: &str) -> Option<Self> {
        Some(match name {
            "RLIMIT_FSIZE" | "1" => Self::FileSize,
            "RLIMIT_CORE" | "4" => Self::Core,
            "RLIMIT_CPU" | "0" => Self::Cpu,
            "RLIMIT_AS" | "RLIMIT_VMEM" | "RLIMIT_DATA" | "2" | "9" => Self::Memory,
            "RLIMIT_NOFILE" | "RLIMIT_OFILE" | "7" => Self::OpenFiles,
            "RLIMIT_STACK" | "3" => Self::Stack,
            _ => return None,
        })
    }

    /// Below this an agent and its hook do not run as they should: seconds
    /// of CPU, bytes of memory or stack, open files.
    fn floor(self) -> u64 {
        match self {
            Self::Cpu => 60,
            Self::Memory => 256 * 1024 * 1024,
            Self::OpenFiles => 1024,
            Self::Stack => 8 * 1024 * 1024,
            Self::FileSize | Self::Core => 0,
        }
    }

    /// The unit `ulimit` counts this limit in (KiB for memory and stack).
    fn ulimit_unit(self) -> u64 {
        match self {
            Self::Memory | Self::Stack => 1024,
            _ => 1,
        }
    }
}

/// Whether a value of one of the limits the hook depends on (CPU, memory,
/// open files, stack) is below its floor: any part of `soft:hard` that is a
/// number under it once multiplied by `unit` (with a `K`, `M` or `G`
/// suffix), or that is not spelled as a number at all (a variable). An
/// empty value is a read; `unlimited` raises.
fn below_floor(limit: Limit, value: &str, unit: u64) -> bool {
    let value = value.trim_end_matches([';', '&', '|', ')']);
    value.split(':').any(|part| {
        let part = part.trim().to_ascii_lowercase();
        if part.is_empty() || part == "unlimited" || part == "-1" || part.ends_with("infinity") {
            return false;
        }
        let digits = part.trim_end_matches(|c: char| c.is_ascii_alphabetic());
        let scale = match part[digits.len()..].chars().next() {
            None => 1,
            Some('k') => 1024,
            Some('m') => 1024 * 1024,
            Some('g') => 1024 * 1024 * 1024,
            Some(_) => return true,
        };
        match digits.parse::<u64>() {
            Ok(n) => n.saturating_mul(unit).saturating_mul(scale) < limit.floor(),
            Err(_) => true,
        }
    })
}

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

/// What the line lowers, if anything, and for whom.
#[derive(Default)]
struct Lowered {
    /// A file size limit of the agent: `prlimit` or code aimed at its pid,
    /// or `prlimit` starting an agent or the guard.
    agent_file_size: bool,
    /// A CPU, memory, open file or stack limit below its floor, aimed the
    /// same way at the agent.
    agent_hook_limit: bool,
    /// A file size limit of another process the line names by pid.
    other_file_size: bool,
    /// A core limit of another process the line names by pid.
    other_core: bool,
}

/// Whether a word of the segment is `prlimit` (by any path) or a name the
/// line gave it, a word inside code included (`execSync(prlimit ...`).
fn runs_prlimit(segment: &str, aliases: &[String]) -> bool {
    segment
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/')))
        .filter_map(|word| word.rsplit('/').next())
        .any(|word| word == "prlimit" || aliases.iter().any(|alias| alias == word))
}

/// The pid value after `--pid` or `-p`: a whole `$(...)` (`$(pgrep -n
/// claude)`), or the next word; a `+` of code that joins strings
/// (`"--pid " + process.ppid`) is passed over.
fn pid_value(segment: &str, prlimit: bool) -> Option<String> {
    let option = PID_OPTION
        .find_iter(segment)
        .find(|m| prlimit || m.as_str().contains("--pid"))?;
    let rest = segment[option.end()..].trim_start_matches(|c: char| c.is_whitespace() || c == '+');
    if let Some(inner) = rest.strip_prefix("$(") {
        let mut depth = 1usize;
        for (at, c) in inner.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(rest[..at + 3].to_string());
                    }
                }
                _ => {}
            }
        }
        return Some(rest.to_string());
    }
    let word = rest.split_whitespace().next()?;
    Some(word.trim_end_matches(')').to_string())
}

/// `NAME=` given a value on the line: `pid=$(ps -o ppid= -p $$)`.
fn assigned(line: &str, name: &str) -> Option<String> {
    let pattern = format!(r"(?:^|[\s;&|(]){}=(\$\([^)]*\)?|\S+)", regex::escape(name));
    let caps = Regex::new(&pattern).ok()?.captures(line)?;
    Some(caps[1].to_string())
}

/// Whether a pid names the agent: its parent's pid in any language
/// (`$PPID`, `os.getppid()`, `process.ppid`, a `ppid` read from `ps`),
/// the pid `pgrep` or `pidof` finds for an agent or the guard, or a
/// variable the line gave one of those. Only the pid counts: an agent
/// named anywhere else on the line does not.
fn pid_is_agent(pid: &str, line: &str, depth: u8) -> bool {
    if PARENT.is_match(pid) {
        return true;
    }
    if ["pgrep", "pidof", "pstree"]
        .iter()
        .any(|finder| pid.contains(finder))
        && names_an_agent(pid)
    {
        return true;
    }
    let name = pid
        .trim_start_matches('$')
        .trim_start_matches('{')
        .trim_end_matches('}');
    depth < 2
        && pid.starts_with('$')
        && !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && assigned(line, name).is_some_and(|value| pid_is_agent(&value, line, depth + 1))
}

/// Whether `prlimit` without a pid starts an agent or the guard: the first
/// word after its options (and an `env`, `exec`, `nohup`, `command` or
/// `sudo` in front, and `NAME=value`) is one (`prlimit --nofile=3
/// claude`, `prlimit --fsize=1 innerwarden hook`).
fn starts_an_agent(segment: &str, aliases: &[String]) -> bool {
    let words: Vec<&str> = segment.split_whitespace().collect();
    let Some(at) = words.iter().position(|word| {
        let name = word.rsplit(['/', '(']).next().unwrap_or(word);
        name == "prlimit" || aliases.iter().any(|alias| alias == name)
    }) else {
        return false;
    };
    let mut rest = words[at + 1..].iter().peekable();
    while let Some(word) = rest.next() {
        if *word == "--" {
            continue;
        }
        if word.starts_with('-') {
            let glued = word.contains('=') || (!word.starts_with("--") && word.len() > 2);
            if !glued
                && rest.peek().is_some_and(|next| {
                    next.starts_with(|c: char| c.is_ascii_digit() || matches!(c, '$' | ':'))
                })
            {
                rest.next();
            }
            continue;
        }
        let name = word.rsplit('/').next().unwrap_or(word);
        if matches!(name, "env" | "exec" | "nohup" | "command" | "sudo") || word.contains('=') {
            continue;
        }
        return names_an_agent(word);
    }
    false
}

/// Programs that start the next word as the command: the word after them
/// (and after their options and `NAME=value`) is the one that runs.
const RUNNERS: &[&str] = &[
    "exec", "env", "command", "builtin", "nohup", "sudo", "time", "nice", "setsid", "npx", "bunx",
];

/// Whether a command after this point of the line starts an agent or the
/// guard's hook: the command word of a later command (after `(`, `{`,
/// `$(`, a runner such as `exec` or `npx`, and `NAME=value`) is an
/// agent (`claude`, `/usr/local/bin/codex`, `@anthropic-ai/claude-code`)
/// or `innerwarden hook`. A name in a path, an argument or an option
/// (`cd ~/src/codex`, `cargo test -p innerwarden`, `--author=claude`) is
/// no start.
fn later_starts_an_agent(rest: &str) -> bool {
    rest.split(['\n', ';', '&', '|']).any(|command| {
        let mut words = command.split_whitespace().map(|word| {
            word.trim_start_matches(['(', '{', '$', '`'])
                .trim_end_matches([')', '}', '`'])
        });
        while let Some(word) = words.next() {
            if word.is_empty() || word.contains('=') && !word.starts_with('-') {
                continue;
            }
            if word.starts_with('-') {
                continue;
            }
            let name = word.rsplit('/').next().unwrap_or(word).to_ascii_lowercase();
            if RUNNERS.contains(&name.as_str()) {
                continue;
            }
            if name == "innerwarden" || name == "innerwarden-agent-guard" {
                return words.next() == Some("hook");
            }
            return names_an_agent(&name);
        }
        false
    })
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
        let mut hook_limit = false;
        let mut options: Vec<(Limit, &str)> = LONG_OPTION
            .captures_iter(segment)
            .filter_map(|caps| {
                let value = caps.get(2).or(caps.get(3)).map_or("", |m| m.as_str());
                Some((Limit::by_option(&caps[1])?, value))
            })
            .collect();
        if prlimit {
            options.extend(SHORT_OPTION.captures_iter(segment).filter_map(|caps| {
                let value = caps.get(2).or(caps.get(3)).map_or("", |m| m.as_str());
                Some((Limit::by_option(&caps[1])?, value))
            }));
        }
        for (limit, value) in options {
            match limit {
                Limit::FileSize => file_size |= lowers(value),
                Limit::Core => core |= lowers(value),
                // `--data`, `--cpu` and `--stack` are options of many
                // programs (`curl --data`): read only where `prlimit` runs.
                _ if prlimit => hook_limit |= below_floor(limit, value, 1),
                _ => {}
            }
        }
        if !(file_size || core || hook_limit) {
            continue;
        }
        // A program `prlimit` starts comes first: its own options (`claude
        // -p hi`) are no pid of `prlimit`'s.
        if prlimit && starts_an_agent(segment, &aliases) {
            found.agent_file_size |= file_size;
            found.agent_hook_limit |= hook_limit;
            continue;
        }
        match pid_value(segment, prlimit) {
            Some(pid) if OWN_PID.is_match(&pid) => {}
            Some(pid) if pid_is_agent(&pid, line, 0) => {
                found.agent_file_size |= file_size;
                found.agent_hook_limit |= hook_limit;
            }
            Some(_) => {
                found.other_file_size |= file_size;
                found.other_core |= core;
            }
            None => {}
        }
    }
    // `ulimit` and `setrlimit` set the limit of the shell or the program
    // itself and of what it starts: refused only when a command after them
    // on the line starts an agent or the guard's hook, which inherit it
    // (`ulimit -n 3; claude`, `setrlimit(...); exec "claude"`). An agent,
    // the guard or `ppid` named in a path, an argument or an option is no
    // start (`ulimit -n 512 && cargo test -p innerwarden`). Otherwise only
    // they are left alone.
    for caps in ULIMIT.captures_iter(line) {
        let starts = later_starts_an_agent(&line[caps.get(0).map_or(0, |m| m.end())..]);
        let file_size = caps[1].contains('f') && lowers(&caps[2]);
        found.agent_file_size |= file_size && starts;
        if starts {
            for letter in caps[1].chars() {
                if let Some(
                    limit @ (Limit::Cpu | Limit::Memory | Limit::OpenFiles | Limit::Stack),
                ) = Limit::by_option(&letter.to_string())
                {
                    found.agent_hook_limit |= below_floor(limit, &caps[2], limit.ulimit_unit());
                }
            }
        }
    }
    for caps in CODE_SETRLIMIT.captures_iter(line) {
        let starts = later_starts_an_agent(&line[caps.get(0).map_or(0, |m| m.end())..]);
        match Limit::by_code(&caps[1]) {
            Some(Limit::FileSize) if starts => found.agent_file_size = true,
            Some(limit @ (Limit::Cpu | Limit::Memory | Limit::OpenFiles | Limit::Stack))
                if starts =>
            {
                found.agent_hook_limit |= below_floor(limit, &caps[2], 1);
            }
            _ => {}
        }
    }
    for caps in CODE_PRLIMIT.captures_iter(line) {
        let pid = caps[1].trim();
        let value = caps.get(3).map_or("", |m| m.as_str());
        let own = OWN_PID.is_match(pid);
        let agent = !own && pid_is_agent(pid, line, 0);
        match Limit::by_code(&caps[2]) {
            Some(Limit::FileSize) if own => {}
            Some(Limit::FileSize) if agent => found.agent_file_size = true,
            Some(Limit::FileSize) => found.other_file_size = true,
            Some(Limit::Core) if !own => found.other_core = true,
            Some(limit @ (Limit::Cpu | Limit::Memory | Limit::OpenFiles | Limit::Stack))
                if agent =>
            {
                found.agent_hook_limit |= below_floor(limit, value, 1);
            }
            _ => {}
        }
    }
    found
}

/// The finding for a line that lowers a file size limit of the agent or of
/// what starts the guard's hook (refused, 60), its CPU, memory, open file or
/// stack limit below the floor (refused, 60), or a file size or core limit
/// of another process or of the shell itself (held, 30).
pub(crate) fn check_limit_lowered(command: &str) -> Option<(&'static str, u32)> {
    let found = read(&joined(command));
    if found.agent_file_size {
        return Some((AGENT_FILE_SIZE_LOWERED, 60));
    }
    if found.agent_hook_limit {
        return Some((AGENT_LIMIT_LOWERED, 60));
    }
    if found.other_file_size || found.other_core {
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

    /// Another process's file size or core limit is held for the person.
    /// (The shell's own file size limit was held here too until 2026-11-26;
    /// it is allowed now, see
    /// `the_shells_limit_with_an_agent_only_named_is_allowed`.)
    ///
    /// FAILS ON REVERT: allowed without the check.
    #[test]
    fn another_process_limit_or_the_shells_own_is_held() {
        for line in [
            "prlimit --pid 4242 --fsize=1024",
            "prlimit --pid 4242 --core=0",
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

    /// The CPU, memory, open file and stack limits of the agent lowered, by
    /// prlimit (long and short options, quotes, a path, an alias), ulimit
    /// before an agent, and Python, Perl and Node: refused. Each spelling
    /// was allowed before.
    ///
    /// FAILS ON REVERT: without these limits in `read` each is allowed
    /// (the lines with a file size limit aside).
    #[test]
    fn a_hook_limit_lowered_on_the_agent_is_refused() {
        for line in [
            "prlimit --pid $PPID --cpu=0",
            "prlimit --pid $PPID --as=16777216",
            "prlimit --pid $PPID --data=1M",
            "prlimit --pid $PPID --nofile=3",
            "prlimit --pid $PPID --stack=16384",
            "prlimit --pid $(pgrep -n claude) --nofile 3:3",
            "\"prl\"'imit' --pid \"$PPID\" \"--nofile=3\"",
            "/usr/bin/prlimit -p $PPID -n3",
            "alias pl=prlimit; pl -p $PPID -t0",
            "prlimit -p $(pidof codex) -v 16000000",
            "prlimit --nofile=3 claude -p hi",
            "ulimit -n 3; claude -p hi",
            "ulimit -t 0 && exec gemini",
            "ulimit -Sv 16384; codex",
            "ulimit -s 16 && claude",
            "python3 -c 'import resource,os; resource.prlimit(os.getppid(), resource.RLIMIT_NOFILE, (3, 3))'",
            "python3 -c 'import resource,os; resource.prlimit(os.getppid(), resource.RLIMIT_AS, (16 << 20, 16 << 20))'",
            "python3 -c 'import resource,os; resource.prlimit(os.getppid(), 0, (0, 0))'",
            "perl -MBSD::Resource -e 'setrlimit(RLIMIT_NOFILE, 3, 3); exec \"claude\"'",
            "node -e 'require(\"child_process\").execSync(\"prlimit --pid \" + process.ppid + \" --cpu=0\")'",
            "pid=$(ps -o ppid= -p $); prlimit --pid $pid --stack=$S",
        ] {
            assert_eq!(verdict(line), "deny", "{line}");
            assert_eq!(
                check_limit_lowered(line).map(|(what, _)| what),
                Some(AGENT_LIMIT_LOWERED),
                "{line}"
            );
        }
    }

    /// Everyday tuning of these limits, for the shell, another process, a
    /// program that is no agent, or the agent with a value at or above the
    /// floor, and the same option names in other programs: left alone.
    #[test]
    fn everyday_hook_limit_lines_are_left_alone() {
        for line in [
            "ulimit -n 4096",
            "ulimit -n 256 && npm test",
            "ulimit -t 10; ./bench",
            "ulimit -v 1000000",
            "ulimit -s 8192",
            "ulimit -s unlimited; claude",
            "ulimit -n 65536; claude",
            "prlimit --pid 1234 --nofile=65536",
            "prlimit --pid 1234 --nofile=64",
            "prlimit --pid 1234 --cpu=5",
            "prlimit --pid $PPID --nofile=65536",
            "prlimit --pid $PPID --stack=unlimited",
            "prlimit --as=1G claude -p hi",
            "prlimit --nofile=128 ./server",
            "systemctl --user show -p LimitNOFILE my.service",
            "python3 -c 'import resource; resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))'",
            "python3 -c 'import resource; resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))'",
            "python3 -c 'import resource,os; print(resource.prlimit(os.getppid(), resource.RLIMIT_NOFILE))'",
            "curl --data @payload.json http://localhost:8080/claude",
            "stress-ng --cpu 4 --timeout 10s; echo $PPID",
            "pulumi up --stack dev --yes",
            "docker run --cpus 2 --ulimit nofile=1024:1024 alpine true",
        ] {
            assert_eq!(check_limit_lowered(line), None, "{line}");
            assert_eq!(verdict(line), "allow", "{line}");
        }
    }

    /// The shell's own limit lowered and a later command that starts an
    /// agent or the guard's hook, which inherit it: refused, by the command
    /// word (a subshell, `sh -c`, a path, `npx`, glued and split options).
    ///
    /// FAILS ON REVERT: with the shell's own limits never read for the
    /// agent (`later_starts_an_agent` always false) each is allowed or held.
    #[test]
    fn the_shells_limit_before_an_agent_it_starts_is_refused() {
        for line in [
            "ulimit -n 3; claude -p hi",
            "(ulimit -t 0; exec codex)",
            "ulimit -Hv 16384 && /usr/local/bin/claude",
            "sh -c 'ulimit -s 16; exec gemini'",
            "ulimit -f 1 && claude --continue",
            "ulimit -S -n 3; claude",
            "ulimit -n3; claude",
            "ulimit -n 3 && npx @anthropic-ai/claude-code",
            "ulimit -n 3; env FOO=1 codex exec hi",
            "ulimit -t 0; innerwarden hook --agent claude-code",
        ] {
            assert_eq!(verdict(line), "deny", "{line}");
            assert!(
                matches!(
                    check_limit_lowered(line).map(|(what, _)| what),
                    Some(AGENT_FILE_SIZE_LOWERED | AGENT_LIMIT_LOWERED)
                ),
                "{line}"
            );
        }
    }

    /// The shell's own limit with an agent, the guard or `ppid` only named
    /// in a path, an argument or an option, and everyday limits: allowed.
    /// Each was allowed on main and refused by the first two rounds of this
    /// check (it read any mention on the line as the agent).
    ///
    /// FAILS ON REVERT: with the agent read anywhere on the line again,
    /// the first eight are refused.
    #[test]
    fn the_shells_limit_with_an_agent_only_named_is_allowed() {
        for line in [
            "ulimit -n 512 && cargo test -p innerwarden",
            "cd ~/src/codex && ulimit -n 256 && npm test",
            "ulimit -n 256; ps -o pid,ppid,cmd",
            "ulimit -s 4096 && git log --author=claude",
            "ulimit -n 1024 && ls ~/.claude/projects",
            "ulimit -t 30 && pytest tests/test_codex_client.py",
            "ulimit -v 2000000; cat /proc/$PPID/status",
            "ulimit -n 256 && grep -rn gemini src/",
            "ulimit -n 4096",
            "ulimit -c unlimited",
            "ulimit -n 65536 && cargo test",
            "ulimit -t 60; ./slow_test.sh",
            "docker run --ulimit nofile=65536:65536 redis",
            "ulimit -s 16384 && make check",
            "ulimit -n 2048; node server.js",
            "ulimit -Sn 4096 && npm run build",
            "ulimit -n 256 && echo claude",
            "prlimit --pid 4242 --nofile=3 && echo $PPID",
        ] {
            assert_eq!(check_limit_lowered(line), None, "{line}");
            assert_eq!(verdict(line), "allow", "{line}");
        }
    }

    /// The shell's or the program's own file size limit with no agent
    /// started after it: allowed (held for review until 2026-11-26).
    #[test]
    fn the_shells_own_file_size_limit_is_allowed() {
        for line in [
            "ulimit -f 2048 && cargo test -p innerwarden",
            "ulimit -f 1",
            "ulimit -S -f 100",
            "prlimit --pid $$ --fsize=1",
            "python3 -c 'import resource; resource.setrlimit(resource.RLIMIT_FSIZE, (1, 1))'",
        ] {
            assert_eq!(check_limit_lowered(line), None, "{line}");
            assert_eq!(verdict(line), "allow", "{line}");
        }
    }
}
