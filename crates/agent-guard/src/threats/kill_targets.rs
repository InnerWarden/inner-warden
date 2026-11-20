//! Which processes a kill reaches, read from the line.
//!
//! A line stops the guard by any of several forms: a pattern (pkill, pgrep,
//! killall), a name (pidof, systemctl kill), the numbers another program
//! prints (kill $(pgrep ...), pgrep ... | xargs kill, ps ... | grep ... |
//! awk ... | xargs kill, lsof -t -i:PORT, fuser -k). Read by its words, a
//! form whose target holds no word "innerwarden" was let through:
//! pgrep innerwarden | xargs kill, killall iw-guard and pkill -f sensor were
//! allowed (measured 2026-11-20). One rule reads them all: the target each
//! form resolves to is matched against the guard's processes. A target that
//! is one of them is a kill of the guard; one the line does not resolve
//! (kill $PID, kill $(cat app.pid), xargs kill < pids.txt) may be.

use super::{effective_command_index, program_name, GUARD_PROCESS_LINES};
use crate::shell_words::{read_line, Command, Word};

/// Process names of the guard's programs, as pkill without -f, pgrep,
/// pidof and killall match them: the full name and, on Linux, the name
/// cut to the 15 characters the kernel keeps.
const GUARD_PROCESS_NAMES: &[&str] = &[
    "innerwarden",
    "innerwarden-agent",
    "innerwarden-sensor",
    "innerwarden-watchdog",
    "innerwarden-supervisor",
    "innerwarden-ctl",
    "innerwarden-dns-guard",
    "innerwarden-sensor-esf",
    "innerwarden-esf-bridge",
    "iw-guard",
    "iw",
];

/// The port the guard's dashboard and agent answer on.
const GUARD_PORTS: &[&str] = &["8787"];

/// What one kill, or the whole line, does to the guard's processes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum KillReach {
    /// No kill, or every target resolved and none is the guard's.
    Misses,
    /// A kill whose target the line does not resolve.
    Unread,
    /// A target resolved to one of the guard's processes.
    Guard,
}

/// The worst [`KillReach`] of the kills of `line`.
pub(crate) fn kill_reach(line: &str) -> KillReach {
    if !mentions_a_kill(line) {
        return KillReach::Misses;
    }
    reach_of_line(line, 0)
}

/// `segment` is only kills (kill, pkill, killall, behind their launch
/// wrappers), each with every target resolved and none the guard's. The
/// checks of words leave such a segment out: the words `innerwarden` in
/// `kill $(pgrep -f innerwarden-agent-guard)` name a test run, not the
/// guard.
pub(crate) fn resolved_kill_misses(segment: &str) -> bool {
    let read = read_line(segment);
    !read.commands.is_empty()
        && read.commands.iter().all(|command| {
            program_and_words(command).is_some_and(|(program, _)| {
                matches!(program.as_str(), "kill" | "pkill" | "killall")
            })
        })
        && reach_of_line(segment, 0) == KillReach::Misses
}

/// Some word of a kill appears in the text.
fn mentions_a_kill(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("kill") || lower.contains("fuser") || lower.contains("service")
}

fn reach_of_line(line: &str, depth: usize) -> KillReach {
    let read = read_line(line);
    let mut worst = KillReach::Misses;
    for (at, command) in read.commands.iter().enumerate() {
        // The commands that pipe into this one.
        let mut start = at;
        while start > 0 && read.commands[start - 1].piped {
            start -= 1;
        }
        let reach = reach_of_command(command, &read.commands[start..at], depth);
        worst = worst.max(reach);
    }
    if depth < 4 {
        for nested in &read.nested {
            worst = worst.max(reach_of_line(nested, depth + 1));
        }
    }
    worst
}

/// The program a command runs, behind its launch wrappers, and its words
/// from that program on.
fn program_and_words(command: &Command) -> Option<(String, &[Word])> {
    let all: Vec<String> = command.words.iter().map(|word| word.text.clone()).collect();
    let at = effective_command_index(&all)?;
    let word = command.words.get(at)?;
    if !word.is_plain() {
        return None;
    }
    Some((program_name(&word.text), &command.words[at..]))
}

/// What `command` kills, `producers` being the commands that pipe into it.
fn reach_of_command(command: &Command, producers: &[Command], depth: usize) -> KillReach {
    let Some((program, words)) = program_and_words(command) else {
        return KillReach::Misses;
    };
    let args = &words[1..];
    match program.as_str() {
        "kill" => kill_operands(args, depth),
        "pkill" => pattern_targets(args),
        "killall" => killall_targets(args),
        "fuser" if fuser_kills(args) => fuser_targets(args),
        "systemctl" => systemctl_kill(args),
        "service" => service_stop(args),
        "xargs" => xargs_kill(args, producers, command),
        _ => KillReach::Misses,
    }
}

/// kill: each operand a number, a job, or the numbers a substitution
/// prints.
fn kill_operands(args: &[Word], depth: usize) -> KillReach {
    let mut worst = KillReach::Misses;
    let mut options_done = false;
    let mut skip = false;
    // `kill -0` only asks whether the process is there.
    let probe = args.iter().enumerate().any(|(at, word)| {
        let text = word.text.as_str();
        text == "-0"
            || text == "--signal=0"
            || (matches!(text, "-s" | "-n" | "--signal")
                && args.get(at + 1).is_some_and(|value| value.text == "0"))
    });
    if probe {
        return KillReach::Misses;
    }
    for word in args {
        if skip {
            skip = false;
            continue;
        }
        // `$!`: the job this shell last started in the background, on
        // the line (`npm run dev & ...; kill $!`).
        if word.text == "$!" {
            continue;
        }
        if !word.is_plain() {
            worst = worst.max(numbers_of_word(word, depth));
            continue;
        }
        let text = word.text.as_str();
        if !options_done && text == "--" {
            options_done = true;
            continue;
        }
        if !options_done && matches!(text, "-s" | "-n" | "--signal") {
            skip = true;
            continue;
        }
        // A signal, -l, or a negative process group.
        let option = !options_done && text.starts_with('-') && text.len() > 1;
        let number = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
        if option || number || text.starts_with('%') {
            continue;
        }
        worst = worst.max(KillReach::Unread);
    }
    worst
}

/// Whose numbers a word the shell fills in holds: only a whole command
/// substitution is read, quoted or not. A parameter (`$PID`) or text
/// beside the substitution is not.
fn numbers_of_word(word: &Word, depth: usize) -> KillReach {
    let text = word.text.trim();
    let dollar = text.starts_with("$(") && text.ends_with(')') && !text.starts_with("$((");
    let backquoted = text.len() > 1 && text.starts_with('`') && text.ends_with('`');
    if !(dollar || backquoted) || word.substitutions.len() != 1 {
        return KillReach::Unread;
    }
    producer_line(&word.substitutions[0], depth + 1)
}

/// Whose numbers a command line prints.
fn producer_line(line: &str, depth: usize) -> KillReach {
    if depth > 4 {
        return KillReach::Unread;
    }
    let read = read_line(line);
    let Some((last, before)) = read.commands.split_last() else {
        return KillReach::Unread;
    };
    // One pipeline, every command but the last piped on.
    if before.iter().any(|command| !command.piped) || last.piped || !read.nested.is_empty() {
        return KillReach::Unread;
    }
    producer_pipeline(&read.commands)
}

/// Whose numbers a pipeline prints: its first program lists processes
/// (pgrep, pidof, lsof -t, ps with a grep after it), and the ones after it
/// only narrow or reshape the list.
fn producer_pipeline(commands: &[Command]) -> KillReach {
    let Some((first, rest)) = commands.split_first() else {
        return KillReach::Unread;
    };
    let Some((program, words)) = program_and_words(first) else {
        return KillReach::Unread;
    };
    let args = &words[1..];
    let mut filters = rest;
    let source = match program.as_str() {
        "pgrep" => pattern_targets(args),
        "pidof" => pidof_targets(args),
        "lsof" => lsof_targets(args),
        "ps" => {
            // ps lists every process; the first grep after it names which.
            let Some((grep, after)) = filters.split_first() else {
                return ps_by_name(args);
            };
            filters = after;
            match grep_pattern(grep) {
                Some(Some(regex)) => lines_reach(&regex),
                _ => return KillReach::Unread,
            }
        }
        _ => return KillReach::Unread,
    };
    if filters.iter().all(narrows) {
        source
    } else {
        KillReach::Unread
    }
}

/// A command after a list of processes that keeps some of it and changes
/// nothing else of which: head, tail, sort, uniq, cut, tr, grep, or awk
/// printing one field.
fn narrows(command: &Command) -> bool {
    let Some((program, words)) = program_and_words(command) else {
        return false;
    };
    if words.iter().any(|word| !word.is_plain()) {
        return false;
    }
    match program.as_str() {
        "head" | "tail" | "sort" | "uniq" | "cut" | "tr" | "grep" | "egrep" | "fgrep" => true,
        "awk" | "gawk" | "mawk" => words[1..]
            .iter()
            .all(|word| word.text.starts_with('-') || is_print_field(&word.text)),
        _ => false,
    }
}

/// An awk program that prints one field: `{print $2}`.
fn is_print_field(program: &str) -> bool {
    let inner: String = program.chars().filter(|c| !c.is_whitespace()).collect();
    inner
        .strip_prefix("{print$")
        .and_then(|rest| rest.strip_suffix('}'))
        .is_some_and(|field| !field.is_empty() && field.bytes().all(|b| b.is_ascii_digit()))
}

/// The pattern of a grep that keeps the lines it matches, as a regular
/// expression with case ignored: `None` when the command is no grep,
/// `Some(None)` when it is one not read (`-v`, a pattern file, two
/// patterns, a value the line does not show).
fn grep_pattern(command: &Command) -> Option<Option<regex::Regex>> {
    let (program, words) = program_and_words(command)?;
    if !matches!(program.as_str(), "grep" | "egrep" | "fgrep") {
        return None;
    }
    let mut fixed = program == "fgrep";
    let mut patterns = Vec::new();
    for word in &words[1..] {
        if !word.is_plain() || word.text.starts_with("--") {
            return Some(None);
        }
        let text = word.text.as_str();
        if let Some(flags) = text.strip_prefix('-').filter(|flags| !flags.is_empty()) {
            if flags.contains(['v', 'e', 'f']) {
                return Some(None);
            }
            fixed |= flags.contains('F');
            continue;
        }
        patterns.push(text);
    }
    let [pattern] = patterns.as_slice() else {
        return Some(None);
    };
    let source = if fixed {
        regex::escape(pattern)
    } else {
        pattern
            .replace("\\|", "|")
            .replace("\\(", "(")
            .replace("\\)", ")")
    };
    Some(build(&source))
}

fn build(pattern: &str) -> Option<regex::Regex> {
    if pattern.is_empty() {
        return None;
    }
    regex::RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(1 << 20)
        .build()
        .ok()
}

/// A regular expression against the guard's command lines.
fn lines_reach(regex: &regex::Regex) -> KillReach {
    if GUARD_PROCESS_LINES.iter().any(|line| regex.is_match(line)) {
        KillReach::Guard
    } else {
        KillReach::Misses
    }
}

/// A guard process name, whole or cut to 15 characters.
fn name_forms() -> impl Iterator<Item = &'static str> {
    GUARD_PROCESS_NAMES
        .iter()
        .flat_map(|name| [*name, name.get(..15).unwrap_or(name)])
}

/// A regular expression against the guard's process names.
fn names_reach(regex: &regex::Regex) -> KillReach {
    if name_forms().any(|name| regex.is_match(name)) {
        KillReach::Guard
    } else {
        KillReach::Misses
    }
}

/// A name, as written, is one of the guard's processes.
fn is_guard_name(name: &str) -> bool {
    let name = program_name(name);
    name_forms().any(|guard| name == guard)
}

/// pkill or pgrep: one pattern, against names or, with -f, command lines.
/// A pidfile (-F) is resolved by its path alone.
fn pattern_targets(args: &[Word]) -> KillReach {
    let mut full = false;
    let mut patterns: Vec<&Word> = Vec::new();
    let mut options_done = false;
    let mut index = 0usize;
    while let Some(word) = args.get(index) {
        index += 1;
        let text = word.text.as_str();
        if options_done || !word.is_plain() || !text.starts_with('-') || text == "-" {
            patterns.push(word);
            continue;
        }
        match text {
            "--" => options_done = true,
            "--full" => full = true,
            "-F" | "--pidfile" => {
                return args.get(index).map_or(KillReach::Unread, pidfile_reach);
            }
            "-u" | "-U" | "-g" | "-G" | "-P" | "-s" | "-t" | "--euid" | "--uid" | "--group"
            | "--pgroup" | "--parent" | "--session" | "--terminal" | "--signal" | "--ns"
            | "--nslist" | "-q" | "--queue" | "-d" | "--delimiter" => index += 1,
            "--inverse" => return KillReach::Unread,
            "--ignore-case" | "--newest" | "--oldest" | "--exact" | "--echo" | "--count"
            | "--list-full" | "--list-name" | "--lightweight" => {}
            _ if text.starts_with("--pidfile=") => {
                return path_reach(&text["--pidfile=".len()..]);
            }
            _ if text.starts_with("--") => {
                // `--signal=KILL`, `--euid=0`: one word. Any other long
                // option is not read.
                if !text.contains('=') {
                    return KillReach::Unread;
                }
            }
            _ => {
                let flags = &text[1..];
                // A signal: `-9`, `-KILL`, `-SIGTERM`, `-HUP`.
                if flags.bytes().all(|b| b.is_ascii_digit())
                    || (flags.bytes().all(|b| b.is_ascii_uppercase()) && flags.len() >= 3)
                {
                    continue;
                }
                if !flags.bytes().all(|b| b"fienoxcalw".contains(&b)) {
                    return KillReach::Unread;
                }
                full |= flags.contains('f');
            }
        }
    }
    let [pattern] = patterns.as_slice() else {
        return KillReach::Unread;
    };
    if !pattern.is_plain() {
        return KillReach::Unread;
    }
    let Some(regex) = build(&pattern.text) else {
        return KillReach::Unread;
    };
    if full {
        lines_reach(&regex)
    } else {
        names_reach(&regex)
    }
}

/// A pidfile: the guard's when its path names the guard; any other is not
/// read.
fn pidfile_reach(file: &Word) -> KillReach {
    if !file.is_plain() {
        return KillReach::Unread;
    }
    path_reach(&file.text)
}

fn path_reach(path: &str) -> KillReach {
    let lower = path.to_ascii_lowercase();
    if lower.contains("innerwarden") || lower.contains("iw-guard") {
        KillReach::Guard
    } else {
        KillReach::Unread
    }
}

/// pidof NAME...: names, exact.
fn pidof_targets(args: &[Word]) -> KillReach {
    let mut worst = KillReach::Misses;
    let mut names = 0usize;
    let mut skip = false;
    for word in args {
        if skip {
            skip = false;
            continue;
        }
        if !word.is_plain() {
            return KillReach::Unread;
        }
        let text = word.text.as_str();
        if text == "-o" || text == "-d" {
            skip = true;
            continue;
        }
        if text.starts_with('-') {
            continue;
        }
        names += 1;
        if is_guard_name(text) {
            worst = KillReach::Guard;
        }
    }
    if names == 0 {
        KillReach::Unread
    } else {
        worst
    }
}

/// killall NAME... (exact names), or with -r patterns.
fn killall_targets(args: &[Word]) -> KillReach {
    let mut regex = false;
    let mut names: Vec<&Word> = Vec::new();
    let mut skip = false;
    let mut options_done = false;
    for word in args {
        if skip {
            skip = false;
            continue;
        }
        let text = word.text.as_str();
        if options_done || !word.is_plain() || !text.starts_with('-') || text == "-" {
            names.push(word);
            continue;
        }
        match text {
            "--" => options_done = true,
            "--regexp" => regex = true,
            "-u" | "--user" | "-o" | "--older-than" | "-y" | "--younger-than" | "-s"
            | "--signal" | "-n" | "--ns" | "-Z" | "--context" => skip = true,
            _ if text.starts_with("--") => {}
            _ => {
                let flags = &text[1..];
                if flags.bytes().all(|b| b.is_ascii_digit())
                    || flags.bytes().all(|b| b.is_ascii_uppercase())
                {
                    continue;
                }
                regex |= flags.contains('r');
                skip = flags.ends_with(['u', 'o', 'y', 's', 'n', 'Z']);
            }
        }
    }
    if names.is_empty() {
        return KillReach::Unread;
    }
    names
        .iter()
        .map(|name| {
            if !name.is_plain() {
                KillReach::Unread
            } else if regex {
                build(&name.text).map_or(KillReach::Unread, |r| names_reach(&r))
            } else if is_guard_name(&name.text) {
                KillReach::Guard
            } else {
                KillReach::Misses
            }
        })
        .max()
        .unwrap_or(KillReach::Unread)
}

/// lsof -t with -i naming a port: whatever listens there.
fn lsof_targets(args: &[Word]) -> KillReach {
    if args.iter().any(|word| !word.is_plain()) {
        return KillReach::Unread;
    }
    let texts: Vec<&str> = args.iter().map(|word| word.text.as_str()).collect();
    let short = |text: &str| text.starts_with('-') && !text.starts_with("--");
    if !texts.iter().any(|text| short(text) && text.contains('t')) {
        return KillReach::Unread;
    }
    let mut ports = Vec::new();
    for (index, text) in texts.iter().enumerate() {
        if !short(text) {
            continue;
        }
        let Some(at) = text.find('i') else {
            continue;
        };
        let glued = &text[at + 1..];
        let value = if glued.is_empty() {
            texts.get(index + 1).copied().unwrap_or("")
        } else {
            glued
        };
        let Some((_, port)) = value.rsplit_once(':') else {
            return KillReach::Unread;
        };
        ports.push(port);
    }
    if ports.is_empty() {
        return KillReach::Unread;
    }
    port_reach(&ports)
}

fn port_reach(ports: &[&str]) -> KillReach {
    ports
        .iter()
        .map(|port| {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                KillReach::Unread
            } else if GUARD_PORTS.contains(port) {
                KillReach::Guard
            } else {
                KillReach::Misses
            }
        })
        .max()
        .unwrap_or(KillReach::Unread)
}

/// fuser with -k: it kills what it finds.
fn fuser_kills(args: &[Word]) -> bool {
    args.iter().any(|word| {
        let text = word.text.as_str();
        text == "--kill" || (text.starts_with('-') && !text.starts_with("--") && text.contains('k'))
    })
}

/// fuser -k: ports (`N/tcp`) and files.
fn fuser_targets(args: &[Word]) -> KillReach {
    let mut worst = KillReach::Misses;
    let mut any = false;
    for word in args {
        if !word.is_plain() {
            return KillReach::Unread;
        }
        let text = word.text.as_str();
        if text.starts_with('-') {
            continue;
        }
        any = true;
        if let Some((port, "tcp" | "udp")) = text.split_once('/') {
            worst = worst.max(port_reach(&[port]));
            continue;
        }
        let lower = text.to_ascii_lowercase();
        if lower.contains("innerwarden") || lower.contains("iw-guard") {
            worst = KillReach::Guard;
        }
    }
    if any {
        worst
    } else {
        KillReach::Unread
    }
}

/// systemctl kill UNIT...: the guard's units, and the CLI's shortcut name.
fn systemctl_kill(args: &[Word]) -> KillReach {
    let mut operands = args
        .iter()
        .filter(|word| !(word.is_plain() && word.text.starts_with('-')));
    let Some(verb) = operands.next() else {
        return KillReach::Misses;
    };
    if !verb.is_plain() || verb.text != "kill" {
        return KillReach::Misses;
    }
    operands
        .map(|unit| {
            if !unit.is_plain() {
                return KillReach::Unread;
            }
            let name = unit.text.to_ascii_lowercase();
            let name = name.strip_suffix(".service").unwrap_or(&name);
            if name.starts_with("innerwarden") || is_guard_name(name) {
                KillReach::Guard
            } else {
                KillReach::Misses
            }
        })
        .max()
        .unwrap_or(KillReach::Misses)
}

/// service NAME stop: the guard's units by their name. Measured 2026-11-20:
/// `sudo service innerwarden-agent stop` was allowed, the verb after the
/// name.
fn service_stop(args: &[Word]) -> KillReach {
    let [name, verb, ..] = args else {
        return KillReach::Misses;
    };
    if !verb.is_plain() || !matches!(verb.text.as_str(), "stop" | "kill" | "force-stop") {
        return KillReach::Misses;
    }
    if !name.is_plain() {
        return KillReach::Unread;
    }
    let lower = name.text.to_ascii_lowercase();
    if lower.starts_with("innerwarden") || is_guard_name(&lower) {
        KillReach::Guard
    } else {
        KillReach::Misses
    }
}

/// xargs running kill: the numbers come from the commands piped in; from a
/// file (`-a`, `<`) or from nowhere the line shows, they are not read.
fn xargs_kill(args: &[Word], producers: &[Command], command: &Command) -> KillReach {
    let mut index = 0usize;
    let mut from_file = false;
    while let Some(word) = args.get(index) {
        if !word.is_plain() {
            return KillReach::Unread;
        }
        let text = word.text.as_str();
        if !text.starts_with('-') {
            break;
        }
        index += 1;
        if matches!(text, "-I" | "-n" | "-P" | "-L" | "-s" | "-d" | "-E" | "-a") {
            from_file |= text == "-a";
            index += 1;
        }
        from_file |= text.starts_with("--arg-file");
    }
    if !runs_a_kill(&args[index.min(args.len())..]) {
        return KillReach::Misses;
    }
    if from_file || !command.reads.is_empty() || !command.inputs.is_empty() || producers.is_empty()
    {
        return KillReach::Unread;
    }
    producer_pipeline(producers)
}

/// The words xargs runs are a kill, or not read.
fn runs_a_kill(words: &[Word]) -> bool {
    let Some(first) = words.first() else {
        return false;
    };
    if !first.is_plain() {
        return true;
    }
    let mut name = program_name(&first.text);
    if name == "sudo" {
        name = words
            .get(1)
            .map(|word| program_name(&word.text))
            .unwrap_or_default();
    }
    matches!(name.as_str(), "kill" | "pkill" | "killall")
}

/// ps -C NAME: names, exact; any other ps alone lists every process and is
/// not read.
fn ps_by_name(args: &[Word]) -> KillReach {
    let Some(at) = args
        .iter()
        .position(|word| word.is_plain() && word.text == "-C")
    else {
        return KillReach::Unread;
    };
    match args.get(at + 1) {
        Some(names) if names.is_plain() => {
            if names.text.split(',').any(is_guard_name) {
                KillReach::Guard
            } else {
                KillReach::Misses
            }
        }
        _ => KillReach::Unread,
    }
}
