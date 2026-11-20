//! The guard taken down by a line whose words say so, read as the shell
//! hands them to each program, never by how far one word sits from another
//! in the text.
//!
//! Three readings:
//!
//! * the command lines the guard's own processes run with
//!   ([`guard_lines`]), built from what the CLI writes into an agent's hooks
//!   and MCP configuration, so that a `pkill -f` or `pgrep -f` pattern is
//!   matched against them as `pkill` matches it against every process;
//! * a service manager (`systemctl`, `service`, `launchctl`) told to stop,
//!   disable, mask or kill a unit of the guard, its verb and unit read past
//!   a redirection glued to the verb (`stop>&2`, `unload>/dev/null`);
//! * systemd's manager reached over D-Bus (`busctl`, `dbus-send`, `gdbus`,
//!   `qdbus`), asked to stop, kill, restart, freeze, mask or disable a unit of
//!   the guard.

use super::{effective_command_index, program_name, PkillReach, PROTECTED_TARGETS};
use crate::shell_words::{read_line, Command};
use std::ops::Range;
use std::path::Path;
use std::sync::LazyLock;

/// How deep the command lines a line runs from inside it are read.
const NESTED_DEPTH: u8 = 4;

/// One command line a process of the guard runs with, as `pkill -f` reads
/// it (the program's words joined by a space), and the bytes of it the guard
/// wrote. The rest is another program's: the agent's id after `--agent`
/// (the agent's own process carries it too) and the MCP server after the
/// proxy's `--`. A pattern that matches only there aims at that program.
pub(super) struct GuardLine {
    pub(super) text: String,
    shared: Vec<Range<usize>>,
}

impl GuardLine {
    /// Whether a match over `range` aims at the guard's part of the line:
    /// it covers one of the guard's words whole (`proxy`, `hook`, the
    /// program's name), or reaches across the end of one of them (`roxy
    /// --mod`). A letter or two inside a word (`x` of `proxy`) aims at no
    /// program in particular.
    fn aims_at_guard(&self, range: Range<usize>) -> bool {
        let bytes = self.text.as_bytes();
        let owned = |at: usize| !self.shared.iter().any(|shared| shared.contains(&at));
        let range = range.start..range.end.min(bytes.len());
        if range
            .clone()
            .any(|at| owned(at) && matches!(bytes[at], b' ' | b'/'))
        {
            return true;
        }
        let mut start = 0usize;
        for (at, byte) in bytes
            .iter()
            .enumerate()
            .chain(std::iter::once((bytes.len(), &b' ')))
        {
            if matches!(byte, b' ' | b'/') {
                let word = start..at;
                if !word.is_empty()
                    && range.start <= word.start
                    && word.end <= range.end
                    && word.clone().all(owned)
                {
                    return true;
                }
                start = at + 1;
            }
        }
        false
    }
}

/// The install paths the guard's CLI is written under in a hook or an MCP
/// wrapper: the installer's, a package's, a user install and Homebrew's.
const GUARD_PROGRAMS: &[&str] = &[
    "/usr/local/bin/innerwarden",
    "/usr/bin/innerwarden",
    "/home/user/.local/bin/innerwarden",
    "/opt/homebrew/bin/innerwarden",
    "innerwarden",
];

/// MCP servers as agents start them, behind the proxy's `--`: what follows
/// the separator is the server's, and a pattern reaching across the
/// separator from the guard's side needs some server after it.
const SERVER_LINES: &[&[&str]] = &[
    &["npx", "-y", "server"],
    &["uvx", "server"],
    &["node", "server.js"],
    &["python3", "-m", "server"],
    &["docker", "run", "-i", "--rm", "image"],
];

/// The Pro daemons, as the Pro installer's units start them, and the Pro
/// CLI's own MCP proxy. Their units are written by the Pro installer, not by
/// this crate, so they are listed as that installer writes them.
const PRO_LINES: &[&str] = &[
    "/usr/local/bin/innerwarden-sensor --config /etc/innerwarden/config.toml",
    "/usr/local/bin/innerwarden-agent --data-dir /var/lib/innerwarden --config /etc/innerwarden/agent.toml --dashboard",
    "/usr/local/bin/innerwarden-agent --config /etc/innerwarden/agent.toml --dashboard",
    "/usr/bin/innerwarden-agent --dashboard",
    "/usr/local/bin/innerwarden-watchdog",
    "/usr/local/bin/innerwarden-supervisor",
    "/usr/local/bin/innerwarden-ctl",
    "/usr/local/bin/innerwarden-dns-guard --bind 127.0.0.2:53 --events /var/lib/innerwarden/dns_guard-events.jsonl",
    "/usr/local/bin/innerwarden-sensor-esf",
    "/usr/local/bin/innerwarden-esf-bridge",
];

/// Every command line of [`GuardLine`], built once.
pub(super) fn guard_lines() -> &'static [GuardLine] {
    static LINES: LazyLock<Vec<GuardLine>> = LazyLock::new(build_guard_lines);
    &LINES
}

fn build_guard_lines() -> Vec<GuardLine> {
    let mut lines = Vec::new();
    for program in GUARD_PROGRAMS {
        let bin = Path::new(program);
        // The hook lines the CLI writes for each agent and mode, read as the
        // shell reads them down to the program it starts.
        for (block_review, monitor) in [(false, false), (true, false), (false, true)] {
            let mut written = vec![
                crate::hook::hook_command_for(bin, block_review, monitor, None),
                crate::hook::hook_command_for(bin, block_review, monitor, Some("claude-code")),
                crate::agent_hooks::CODEX.command(bin, block_review, monitor),
                crate::agent_hooks::GEMINI.command(bin, block_review, monitor),
                crate::hermes_hook::command(bin, block_review, monitor),
            ];
            for spec in [&crate::agent_hooks::CODEX, &crate::agent_hooks::GEMINI] {
                written.push(crate::hook::hook_command_shaped(
                    bin,
                    block_review,
                    monitor,
                    Some(spec.agent),
                    false,
                ));
            }
            for line in written {
                if let Some(words) = started_program_words(&line) {
                    lines.push(guard_line(&words, None));
                }
            }
        }
        // The MCP wrappers the CLI writes, in each mode, and the layout it
        // still reads as its own (`proxy -- <server>`), around each server.
        for server in SERVER_LINES {
            for monitor in [false, true] {
                let config = serde_json::json!({"mcpServers": {"s": {
                    "command": server[0],
                    "args": server[1..],
                }}});
                let (wrapped, _) = crate::mcp_wire::wrap(config, program, monitor, "claude-code");
                let entry = &wrapped["mcpServers"]["s"];
                let mut words: Vec<String> = Vec::new();
                if let Some(command) = entry["command"].as_str() {
                    words.push(command.to_owned());
                }
                for arg in entry["args"].as_array().into_iter().flatten() {
                    if let Some(arg) = arg.as_str() {
                        words.push(arg.to_owned());
                    }
                }
                lines.push(guard_line(&words, words.iter().position(|w| w == "--")));
            }
            let mut legacy: Vec<String> = vec![(*program).to_owned(), "proxy".into(), "--".into()];
            legacy.extend(server.iter().map(|word| (*word).to_owned()));
            lines.push(guard_line(&legacy, Some(2)));
            let mut pro: Vec<String> = [
                "/usr/local/bin/innerwarden-ctl",
                "agent",
                "proxy",
                "--mode",
                "guard",
                "--",
            ]
            .iter()
            .map(|word| (*word).to_owned())
            .collect();
            pro.extend(server.iter().map(|word| (*word).to_owned()));
            lines.push(guard_line(&pro, Some(5)));
        }
        lines.push(guard_line(
            &[(*program).to_owned(), "dashboard".into()],
            None,
        ));
    }
    for line in PRO_LINES {
        lines.push(GuardLine {
            text: (*line).to_owned(),
            shared: Vec::new(),
        });
    }
    lines
}

/// The words of the program a hook line starts, as the shell starts it:
/// the first command of the line, and for a line that hands a script to
/// `/bin/sh -c` with the guard's path as `$0`, the first command of that
/// script with `$0` read as that path.
fn started_program_words(line: &str) -> Option<Vec<String>> {
    let read = read_line(line);
    let words: Vec<String> = read
        .commands
        .first()?
        .words
        .iter()
        .map(|w| w.text.clone())
        .collect();
    if words.len() >= 4 && words[0].ends_with("/sh") && words[1] == "-c" {
        let script = read_line(&words[2]);
        let inner: Vec<String> = script
            .commands
            .first()?
            .words
            .iter()
            .map(|w| {
                if w.text == "$0" {
                    words[3].clone()
                } else {
                    w.text.clone()
                }
            })
            .collect();
        return Some(inner);
    }
    Some(words)
}

/// A [`GuardLine`] of `words`: the agent id after `--agent` or `--label` is shared,
/// and so is every word after the one at `separator`.
fn guard_line(words: &[String], separator: Option<usize>) -> GuardLine {
    let mut text = String::new();
    let mut shared = Vec::new();
    let mut names_agent = false;
    let mut previous_shared = false;
    for (index, word) in words.iter().enumerate() {
        if index > 0 {
            text.push(' ');
        }
        let start = text.len();
        text.push_str(word);
        let theirs = names_agent || separator.is_some_and(|at| index > at);
        if theirs {
            // The space in front of a shared word is the guard's only when
            // the word before it is.
            let from = if previous_shared { start - 1 } else { start };
            shared.push(from..text.len());
        }
        previous_shared = theirs;
        // The proxy's `--label` names the agent as its `--agent` does.
        names_agent = word == "--agent" || word == "--label";
    }
    GuardLine { text, shared }
}

/// What a `pkill -f` or `pgrep -f` pattern does to the guard's processes:
/// [`PkillReach::NamesGuard`] when it matches one of [`guard_lines`] on
/// bytes the guard wrote, [`PkillReach::Unread`] when it matches one only
/// on another program's part (the agent's id, the MCP server: `pkill -f
/// npx` stops the servers as much as the proxies), and
/// [`PkillReach::Misses`] when it matches none.
pub(super) fn pattern_reach(regex: &regex::Regex) -> PkillReach {
    if names_the_cli(regex.as_str()) {
        return PkillReach::NamesGuard;
    }
    let mut matched = false;
    for line in guard_lines() {
        let text = line.text.as_str();
        let mut from = 0usize;
        // Every place a match starts, each with its leftmost-first length.
        while from <= text.len() {
            let Some(found) = regex.find_at(text, from) else {
                break;
            };
            matched = true;
            if line.aims_at_guard(found.range()) {
                return PkillReach::NamesGuard;
            }
            let mut next = found.start() + 1;
            while next < text.len() && !text.is_char_boundary(next) {
                next += 1;
            }
            from = next;
        }
    }
    if matched {
        PkillReach::Unread
    } else {
        PkillReach::Misses
    }
}

/// Whether `pattern` spells the guard's CLI as a program followed by its
/// words (`innerwarden mcp-proxy`, `innerwarden\\s+hook`): every process
/// of that program is the guard's, whatever subcommand it runs, more than
/// the lines [`guard_lines`] holds. A longer name (`innerwarden-agent-guard`,
/// a crate's test binary) is another program.
fn names_the_cli(pattern: &str) -> bool {
    let lower = pattern.to_ascii_lowercase();
    lower.match_indices("innerwarden").any(|(at, name)| {
        let after = &lower[at + name.len()..];
        after.starts_with(' ') || after.starts_with("\\s")
    })
}

/// The words of `command`, when the shell hands every one of them as written.
fn plain_words(command: &Command) -> Option<Vec<String>> {
    command
        .words
        .iter()
        .map(|word| word.is_plain().then(|| word.text.clone()))
        .collect()
}

/// `text` as one shell word.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// Whether `command` is a `pgrep -f` whose pattern reaches the guard
/// ([`pattern_reach`]).
fn pgrep_reaches_guard(command: &Command) -> bool {
    let Some(words) = plain_words(command) else {
        return false;
    };
    let Some(at) = effective_command_index(&words) else {
        return false;
    };
    if program_name(&words[at]) != "pgrep" {
        return false;
    }
    let segment: Vec<String> = std::iter::once("pkill".to_owned())
        .chain(words[at + 1..].iter().map(|word| quoted(word)))
        .collect();
    super::pkill_reach(&segment.join(" ")) == PkillReach::NamesGuard
}

/// Whether `command` runs `kill` on what it is handed: `kill` itself, or
/// `xargs` starting it.
fn runs_kill(command: &Command) -> bool {
    let words: Vec<String> = command.words.iter().map(|w| w.text.clone()).collect();
    let Some(at) = effective_command_index(&words) else {
        return false;
    };
    match program_name(&words[at]).as_str() {
        "kill" => true,
        "xargs" => words[at + 1..]
            .iter()
            .any(|word| program_name(word) == "kill"),
        _ => false,
    }
}

/// A `pgrep -f` that finds the guard's processes ([`pattern_reach`]) and
/// hands what it prints to `kill`: through a pipe into `kill` or `xargs
/// kill`, or as a substitution in a `kill`'s words.
pub(super) fn pgrep_feeds_a_kill_of_the_guard(text: &str) -> bool {
    feeds_kill(text, 0)
}

fn feeds_kill(text: &str, depth: u8) -> bool {
    if !text.contains("pgrep") {
        return false;
    }
    let line = read_line(text);
    for (index, command) in line.commands.iter().enumerate() {
        if command.piped
            && pgrep_reaches_guard(command)
            && line.commands.get(index + 1).is_some_and(runs_kill)
        {
            return true;
        }
        if runs_kill(command)
            && command
                .words
                .iter()
                .flat_map(|word| &word.substitutions)
                .any(|inner| read_line(inner).commands.iter().any(pgrep_reaches_guard))
        {
            return true;
        }
    }
    depth < NESTED_DEPTH && line.nested.iter().any(|inner| feeds_kill(inner, depth + 1))
}

/// What [`service_lowered`] says when the unit is the guard's.
pub const GUARD_SERVICE_LOWERED: &str =
    "stop, disable, mask or kill an InnerWarden service (its verb and unit read word by word)";

/// What [`service_lowered`] says when the unit is another security control's.
pub const MONITOR_SERVICE_LOWERED: &str = "disable a host security monitor";

/// The options of `systemctl` that take the next word as their value.
const SYSTEMCTL_VALUED: &[&str] = &[
    "-H",
    "--host",
    "-M",
    "--machine",
    "-t",
    "--type",
    "-p",
    "--property",
    "-s",
    "--signal",
    "--root",
    "-n",
    "--lines",
    "-o",
    "--output",
    "--kill-whom",
    "--kill-value",
    "--job-mode",
    "--what",
    "--state",
    "--timestamp",
    "--message",
    "--image",
    "--drop-in",
    "--when",
    "-P",
    "--boot-loader-entry",
    "--reboot-argument",
    "--image-policy",
];

/// The methods of systemd's manager and of its units that take a unit out
/// of service, in lower case: stopped, killed, restarted, frozen, masked or
/// disabled.
const LOWERING_METHODS: &[&str] = &[
    "stopunit",
    "killunit",
    "restartunit",
    "tryrestartunit",
    "reloadorrestartunit",
    "reloadortryrestartunit",
    "freezeunit",
    "maskunitfiles",
    "disableunitfiles",
    "disableunitfileswithflags",
    "disableunitfileswithflagsandinstallinfo",
    "stop",
    "kill",
    "restart",
    "tryrestart",
    "reloadorrestart",
    "reloadortryrestart",
    "freeze",
];

/// The protected target a word names, by the text of its lower case.
fn protected_target(word: &str) -> Option<&'static str> {
    let lower = word.to_ascii_lowercase();
    PROTECTED_TARGETS
        .iter()
        .copied()
        .find(|target| lower.contains(target))
}

fn finding(target: &str) -> &'static str {
    if target == "innerwarden" {
        GUARD_SERVICE_LOWERED
    } else {
        MONITOR_SERVICE_LOWERED
    }
}

/// A service manager or systemd over D-Bus told, word by word, to take a
/// protected service out of service. The words are the shell's, so a
/// redirection glued to the verb is a redirection and the unit is read
/// wherever it stands.
pub(super) fn service_lowered(text: &str) -> Option<&'static str> {
    lowered_in(text, 0)
}

fn lowered_in(text: &str, depth: u8) -> Option<&'static str> {
    let line = read_line(text);
    for command in &line.commands {
        let words: Vec<String> = command.words.iter().map(|w| w.text.clone()).collect();
        let Some(at) = effective_command_index(&words) else {
            continue;
        };
        let rest = &words[at + 1..];
        let hit = match program_name(&words[at]).as_str() {
            "systemctl" => systemctl_lowers(rest),
            "service" => {
                let operands: Vec<&String> = rest.iter().filter(|w| !w.starts_with('-')).collect();
                match operands.as_slice() {
                    [unit, verb, ..] if verb.as_str() == "stop" => protected_target(unit),
                    _ => None,
                }
            }
            "launchctl" => {
                let mut operands = rest.iter().filter(|w| !w.starts_with('-'));
                match operands.next().map(String::as_str) {
                    Some("unload" | "bootout" | "remove" | "stop" | "disable" | "kill") => {
                        operands.find_map(|word| protected_target(word))
                    }
                    _ => None,
                }
            }
            "busctl" | "dbus-send" | "gdbus" | "qdbus" | "qdbus6" => dbus_lowers(rest),
            _ => None,
        };
        if let Some(target) = hit {
            return Some(finding(target));
        }
    }
    if depth < NESTED_DEPTH {
        line.nested
            .iter()
            .find_map(|inner| lowered_in(inner, depth + 1))
    } else {
        None
    }
}

fn systemctl_lowers(rest: &[String]) -> Option<&'static str> {
    let mut operands = Vec::new();
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        if SYSTEMCTL_VALUED.contains(&word.as_str()) {
            words.next();
        } else if !word.starts_with('-') {
            operands.push(word.as_str());
        }
    }
    let (verb, units) = operands.split_first()?;
    if !matches!(*verb, "stop" | "disable" | "mask" | "kill" | "freeze") {
        return None;
    }
    units.iter().find_map(|unit| protected_target(unit))
}

fn dbus_lowers(rest: &[String]) -> Option<&'static str> {
    let systemd = rest
        .iter()
        .any(|word| word.to_ascii_lowercase().contains("freedesktop.systemd1"))
        || rest
            .iter()
            .any(|word| word.contains("/org/freedesktop/systemd1"));
    if !systemd {
        return None;
    }
    let method = rest.iter().any(|word| {
        let lower = word.to_ascii_lowercase();
        let name = lower.rsplit(['.', '=']).next().unwrap_or(&lower);
        LOWERING_METHODS.contains(&name)
    });
    if !method {
        return None;
    }
    rest.iter().find_map(|word| protected_target(word))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reach(pattern: &str) -> PkillReach {
        pattern_reach(
            &regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .unwrap(),
        )
    }

    #[test]
    fn the_lines_are_the_ones_the_cli_writes() {
        let texts: Vec<&str> = guard_lines()
            .iter()
            .map(|line| line.text.as_str())
            .collect();
        assert!(
            texts.contains(&"/usr/local/bin/innerwarden hook --agent claude-code"),
            "{texts:#?}"
        );
        assert!(
            texts.contains(&"/usr/local/bin/innerwarden hook --monitor --agent codex"),
            "{texts:#?}"
        );
        assert!(
            texts.contains(&"/usr/local/bin/innerwarden proxy --label claude-code --agent claude-code --mode guard -- npx -y server"),
            "{texts:#?}"
        );
        assert!(
            texts.contains(&"/usr/local/bin/innerwarden proxy -- npx -y server"),
            "{texts:#?}"
        );
    }

    #[test]
    fn a_pattern_on_the_guards_part_reaches_it_and_one_on_another_programs_does_not() {
        for pattern in [
            "hook --agent claude-code",
            "proxy -- npx",
            "proxy -- ",
            "mode guard --",
            "inner.arden",
            "agent clau",
            "roxy --mod",
            "proxy",
            "innerwarden mcp-proxy",
        ] {
            assert_eq!(reach(pattern), PkillReach::NamesGuard, "{pattern}");
        }
        for pattern in [
            "claude",
            "npx",
            "server",
            "claude-code",
            "node server.js",
            "npx -y server",
            // A letter inside the guard's words (`proxy`, `docker`): no
            // program in particular.
            "x",
        ] {
            assert_eq!(reach(pattern), PkillReach::Unread, "{pattern}");
        }
        for pattern in ["mcp-proxy -- npx", "cargo build", "vite --port"] {
            assert_eq!(reach(pattern), PkillReach::Misses, "{pattern}");
        }
    }
}
