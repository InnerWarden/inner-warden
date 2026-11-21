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

use super::{
    effective_command_index, launched_command_index, program_name, PkillReach, PROTECTED_TARGETS,
};
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
    /// The guard's own message in the line (what the fail-closed hook
    /// prints when the guard gives no answer): ordinary words of English,
    /// whole or in part not a mark of the guard, though a match across
    /// them is.
    prose: Vec<Range<usize>>,
    /// Where the folder of the program ends: the bytes before it are its
    /// install path (`/usr/local/bin/`), words many programs share.
    folder_end: usize,
}

/// The guard's name, as each of its programs and folders carries it.
const GUARD_NAME: &str = "innerwarden";

/// How many bytes of [`GUARD_NAME`] a match covers to touch it: `warden`,
/// `inner`, `den` do; one or two letters (`e`, `ar`) are in too many
/// other names to aim at this one.
const NAME_PIECE: usize = 3;

/// Whether `range` of `text` covers [`NAME_PIECE`] bytes or more of one
/// [`GUARD_NAME`] in it.
fn touches_name(text: &str, range: &Range<usize>) -> bool {
    text.match_indices(GUARD_NAME).any(|(at, name)| {
        let start = range.start.max(at);
        let end = range.end.min(at + name.len());
        end >= start + NAME_PIECE
    })
}

impl GuardLine {
    /// What a match over `range` does to the guard:
    ///
    /// * [`PkillReach::NamesGuard`] when it touches the guard's name
    ///   ([`touches_name`]), or reaches across a space between two of the
    ///   guard's words (`hook --agent`, `roxy --mod`): a pattern written
    ///   for this line;
    /// * [`PkillReach::Broad`] when it covers a whole word the guard wrote
    ///   and nothing more (`proxy`, `hook`, `dashboard`, the `local` or
    ///   `bin` of its folder): the kill takes the guard with other
    ///   programs, and a person decides;
    /// * [`PkillReach::Unread`] for letters inside one word (`x` of
    ///   `proxy`) or another program's part (the agent's id, the server).
    fn reach_of(&self, range: Range<usize>) -> PkillReach {
        let bytes = self.text.as_bytes();
        let range = range.start..range.end.min(bytes.len());
        if touches_name(&self.text, &range) {
            return PkillReach::NamesGuard;
        }
        let owned = |at: usize| !self.shared.iter().any(|shared| shared.contains(&at));
        if range
            .clone()
            .any(|at| owned(at) && at >= self.folder_end && bytes[at] == b' ')
        {
            return PkillReach::NamesGuard;
        }
        // A word that starts in the message is the message's (its last one
        // runs on to the closing quote).
        let prose =
            |word: &Range<usize>| self.prose.iter().any(|prose| prose.contains(&word.start));
        let mut start = 0usize;
        let mut reach = PkillReach::Unread;
        for (at, byte) in bytes
            .iter()
            .enumerate()
            .chain(std::iter::once((bytes.len(), &b' ')))
        {
            if matches!(byte, b' ' | b'/') {
                let word = start..at;
                if !word.is_empty() && word.clone().all(owned) && !prose(&word) {
                    if range.start <= word.start && word.end <= range.end {
                        return PkillReach::Broad;
                    }
                    // A piece of [`NAME_PIECE`] bytes or more of one word of
                    // the program's (`roxy` of `proxy`, `hoo` of `hook`), not
                    // of a folder in a path: written for this word, the kill
                    // takes the guard with whatever else holds it.
                    let spaced = (word.start == 0 || bytes[word.start - 1] == b' ')
                        && (word.end == bytes.len() || bytes[word.end] == b' ');
                    if spaced
                        && word.start >= self.folder_end
                        && word.start <= range.start
                        && range.end <= word.end
                        && range.len() >= NAME_PIECE
                    {
                        reach = PkillReach::Broad;
                    }
                }
                start = at + 1;
            }
        }
        reach
    }
}

/// The install paths the guard's CLI is written under in a hook or an MCP
/// wrapper: the installer's, a package's, a user install and Homebrew's.
/// [`guard_programs`] adds the ones of this machine.
const GUARD_PROGRAMS: &[&str] = &[
    "/usr/local/bin/innerwarden",
    "/usr/bin/innerwarden",
    "/home/user/.local/bin/innerwarden",
    "/opt/homebrew/bin/innerwarden",
    "innerwarden",
];

/// [`GUARD_PROGRAMS`], and where the CLI is on this machine: the binary
/// running now when it is the CLI (the path the CLI wrote into the hooks it
/// installed), and the user installs under this home.
fn guard_programs() -> Vec<String> {
    let mut programs: Vec<String> = GUARD_PROGRAMS.iter().map(|p| (*p).to_owned()).collect();
    if let Ok(home) = std::env::var("HOME") {
        let home = home.trim_end_matches('/');
        if !home.is_empty() {
            for folder in [".local/bin", ".cargo/bin", "bin"] {
                programs.push(format!("{home}/{folder}/innerwarden"));
            }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let name = exe.file_name().and_then(|name| name.to_str());
        if matches!(name, Some("innerwarden" | "innerwarden.exe")) {
            if let Some(path) = exe.to_str() {
                programs.push(path.to_owned());
            }
        }
    }
    programs.sort();
    programs.dedup();
    programs
}

/// The command lines the guard's list held before it was built from what
/// the CLI writes, kept as they were: `innerwarden mcp-proxy -- <server>`
/// is the layout of older wrappers and of the Pro CLI's label, and a pattern
/// written for it stops the guard where that layout still runs.
const LEGACY_LINES: &[&str] = &[
    "/usr/local/bin/innerwarden hook --agent claude-code",
    "/usr/local/bin/innerwarden mcp-proxy -- npx -y server",
    "/usr/local/bin/innerwarden dashboard",
    "/usr/bin/innerwarden hook",
    "/home/user/.local/bin/innerwarden hook",
    "innerwarden",
];

/// The layouts of the MCP wrapper the CLI has written, oldest first, as the
/// options between `proxy` and its `--`: `{mode}` is `guard` or `advisory`,
/// `{agent}` the agent's id (another program's part of the line). A wrapper
/// keeps the options it already had when it is wrapped again, so each
/// layout runs on machines that installed it.
///
/// * 1.0 to 1.5.1: the mode alone (`mcp_wire.rs` of guard-v1.5.1);
/// * 1.0 to 1.5.1, a wrapper a person labelled, kept on a later wrap
///   (`--label`, `--error-response`; the same file's tests);
/// * from 1.5.2: `--label` and `--agent` added before the mode
///   (`mcp_wire::naming`, d98eabd);
/// * an `--agent` with no `--label`, as a wrapper written by hand or by the
///   Pro CLI's label reads before a reconnect adds the label.
///
/// The last one is what [`crate::mcp_wire::wrap`] writes today, which a
/// test holds to.
const WRAPPER_LAYOUTS: &[&[&str]] = &[
    &["--mode", "{mode}"],
    &["--label", "{agent}", "--mode", "{mode}"],
    &["--label", "{agent}", "--error-response", "--mode", "{mode}"],
    &["--agent", "{agent}", "--mode", "{mode}"],
    &[
        "--label", "{agent}", "--agent", "{agent}", "--mode", "{mode}",
    ],
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
    for program in &guard_programs() {
        let program = program.as_str();
        let bin = Path::new(program);
        // The program alone, and its hook with no option.
        lines.push(guard_line(&[program.to_owned()], None));
        lines.push(guard_line(&[program.to_owned(), "hook".into()], None));
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
                // The shell that runs a fail-closed hook is the guard's too:
                // killed, the agent reads no refusal and runs the call. The
                // line Claude Code is given is run by its own `sh -c`.
                let run = if line.starts_with(FAIL_CLOSED_SHELL) {
                    line.clone()
                } else {
                    format!("{FAIL_CLOSED_SHELL} -c {} \"\"", quoted(&line))
                };
                if line.contains("s=$?") {
                    if let Some(shell) = fail_closed_shell_line(&run) {
                        lines.push(shell);
                    }
                }
            }
        }
        // The MCP wrappers the CLI writes, in each mode, and the layout it
        // still reads as its own (`proxy -- <server>`), around each server.
        for (index, server) in SERVER_LINES.iter().enumerate() {
            // Each agent the CLI wires MCP servers for names its wrappers;
            // the first server stands for the rest.
            let mut agents: Vec<&str> = vec!["claude-code"];
            if index == 0 {
                for agent in wired_agents() {
                    if !agents.contains(&agent) {
                        agents.push(agent);
                    }
                }
            }
            for agent in &agents {
                for monitor in [false, true] {
                    let config = serde_json::json!({"mcpServers": {"s": {
                        "command": server[0],
                        "args": server[1..],
                    }}});
                    let (wrapped, _) = crate::mcp_wire::wrap(config, program, monitor, agent);
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
            }
            for subcommand in ["proxy", "mcp-proxy"] {
                let mut legacy: Vec<String> =
                    vec![program.to_owned(), subcommand.into(), "--".into()];
                legacy.extend(server.iter().map(|word| (*word).to_owned()));
                lines.push(guard_line(&legacy, Some(2)));
            }
            // The layouts older CLIs wrote ([`WRAPPER_LAYOUTS`]), in each mode.
            for (layout, agent, mode) in WRAPPER_LAYOUTS.iter().flat_map(|layout| {
                agents.iter().flat_map(move |agent| {
                    ["guard", "advisory"]
                        .into_iter()
                        .map(move |mode| (layout, *agent, mode))
                })
            }) {
                let mut words: Vec<String> = vec![program.to_owned(), "proxy".into()];
                words.extend(
                    layout
                        .iter()
                        .map(|word| word.replace("{mode}", mode).replace("{agent}", agent)),
                );
                let separator = words.len();
                words.push("--".into());
                words.extend(server.iter().map(|word| (*word).to_owned()));
                // `--label` names the agent as `--agent` does (shared by
                // [`guard_line`]); `--error-response` takes no value.
                lines.push(guard_line(&words, Some(separator)));
            }
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
        lines.push(guard_line(&[program.to_owned(), "dashboard".into()], None));
    }
    for line in PRO_LINES {
        let words: Vec<String> = line.split(' ').map(str::to_owned).collect();
        lines.push(guard_line(&words, None));
    }
    for line in LEGACY_LINES {
        let words: Vec<String> = line.split(' ').map(str::to_owned).collect();
        let separator = words.iter().position(|word| word == "--");
        lines.push(guard_line(&words, separator));
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

/// The agents the CLI wires MCP servers for, by the id their wrappers name
/// ([`crate::agents::KNOWN`]).
fn wired_agents() -> Vec<&'static str> {
    crate::agents::KNOWN
        .iter()
        .filter(|known| known.mcp_json.is_some() || known.mcp_toml.is_some())
        .map(|known| known.name)
        .collect()
}

/// The shell that runs a fail-closed hook line.
const FAIL_CLOSED_SHELL: &str = "/bin/sh";

/// The process a fail-closed hook line (`/bin/sh -c '"$0" hook ...; s=$?;
/// ...' "/path/innerwarden"`) starts first, as `pkill -f` reads it: the
/// shell's words joined by a space, the script one of them. The agent's id
/// after `--agent` is another program's part; the message the script
/// prints is the guard's prose ([`GuardLine::prose`]).
fn fail_closed_shell_line(line: &str) -> Option<GuardLine> {
    let read = read_line(line);
    let words: Vec<String> = read
        .commands
        .first()?
        .words
        .iter()
        .map(|w| w.text.clone())
        .collect();
    if words.len() < 4 || !words[0].ends_with("/sh") || words[1] != "-c" {
        return None;
    }
    let text = words.join(" ");
    let pieces: Vec<String> = text.split(' ').map(str::to_owned).collect();
    let mut shell = guard_line(&pieces, None);
    if let Some(open) = shell.text.find("echo \"") {
        let start = open + "echo \"".len();
        if let Some(close) = shell.text[start..].find('"') {
            shell.prose.push(start..start + close);
        }
    }
    Some(shell)
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
    let folder_end = words
        .first()
        .and_then(|program| program.rfind('/'))
        .map_or(0, |slash| slash + 1);
    GuardLine {
        text,
        shared,
        prose: Vec::new(),
        folder_end,
    }
}

/// What a `pkill -f` or `pgrep -f` pattern does to the guard's processes,
/// the strongest of what each match on each of [`guard_lines`] does
/// ([`GuardLine::reach_of`]): [`PkillReach::Misses`] when it matches none.
/// A pattern that matches a line only where the guard's name stands (the
/// line with the name spelled out of reach no longer matches) names it.
pub(super) fn pattern_reach(regex: &regex::Regex) -> PkillReach {
    if names_the_cli(regex.as_str()) {
        return PkillReach::NamesGuard;
    }
    let unnamed = |line: &str| line.replace(GUARD_NAME, "xxxxxxxxxxx");
    let mut reach = PkillReach::Misses;
    for line in guard_lines() {
        let text = line.text.as_str();
        if regex.is_match(text) && !regex.is_match(&unnamed(text)) {
            return PkillReach::NamesGuard;
        }
        let mut from = 0usize;
        // Every place a match starts, each with its leftmost-first length.
        while from <= text.len() {
            let Some(found) = regex.find_at(text, from) else {
                break;
            };
            reach = reach.max(line.reach_of(found.range()));
            if reach == PkillReach::NamesGuard {
                return reach;
            }
            let mut next = found.start() + 1;
            while next < text.len() && !text.is_char_boundary(next) {
                next += 1;
            }
            from = next;
        }
    }
    reach
}

/// The names the kernel keeps for the guard's processes, which `pkill` and
/// `pgrep` without `-f`, `killall` and `pidof` match: each program's file
/// name, and the first 15 bytes of it (`comm`).
fn guard_process_names() -> &'static [String] {
    static NAMES: LazyLock<Vec<String>> = LazyLock::new(|| {
        let mut names: Vec<String> = Vec::new();
        for line in guard_lines() {
            let program = line.text.split(' ').next().unwrap_or_default();
            let name = program.rsplit('/').next().unwrap_or(program);
            if name.contains(GUARD_NAME) {
                names.push(name.to_owned());
                names.push(name.chars().take(15).collect());
            }
        }
        names.sort();
        names.dedup();
        names
    });
    &NAMES
}

/// What a pattern matched against process names (`pkill` or `pgrep`
/// without `-f`, `killall -r`) does to the guard's processes:
/// [`PkillReach::NamesGuard`] when a match touches the guard's name in one
/// of [`guard_process_names`], [`PkillReach::Broad`] when it matches one
/// elsewhere (`agent` of `innerwarden-agent`: the kill takes other
/// programs too, and a person decides).
fn name_reach(regex: &regex::Regex) -> PkillReach {
    let mut reach = PkillReach::Misses;
    for name in guard_process_names() {
        let mut from = 0usize;
        while from <= name.len() {
            let Some(found) = regex.find_at(name, from) else {
                break;
            };
            if touches_name(name, &found.range()) {
                return PkillReach::NamesGuard;
            }
            reach = PkillReach::Broad;
            from = found.start() + 1;
        }
    }
    reach
}

/// Whether `name`, matched whole as `killall` and `pidof` match a name,
/// is one of the guard's processes: its file name, its `comm`, or with a
/// folder its program's path.
fn names_a_guard_process(name: &str, ignore_case: bool) -> bool {
    let same = |a: &str, b: &str| {
        if ignore_case {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        }
    };
    if name.contains('/') {
        // Any folder: a path whose file is one of the guard's programs is
        // the guard, wherever it was installed (`/opt/iw/bin/innerwarden`).
        let file = name.rsplit('/').next().unwrap_or(name);
        return guard_lines()
            .iter()
            .any(|line| same(line.text.split(' ').next().unwrap_or_default(), name))
            || guard_process_names().iter().any(|own| same(own, file));
    }
    guard_process_names().iter().any(|own| same(own, name))
}

/// The readings of a process pattern by each regular expression dialect
/// that may run it: this crate's, the ERE of glibc (`\w`, `\s`, `\b` and
/// their capitals mean what they mean here, any other letter after a
/// backslash is that letter: `\d` is `d`) and the ERE of the BSDs and
/// macOS (every letter after a backslash is that letter). `pkill -f
/// 'innerwar\den'` matches `innerwarden` on Linux and nothing here.
fn dialect_readings(pattern: &str) -> Vec<String> {
    let mut readings = vec![pattern.to_owned()];
    // glibc reads `{,n}` as `{0,n}`; this crate does not compile it.
    if pattern.contains("{,") {
        if let Ok(open) = regex::Regex::new(r"\{,(\d+)\}") {
            let read = open.replace_all(pattern, "{0,$1}").into_owned();
            if read != pattern {
                readings.extend(dialect_readings(&read));
            }
        }
    }
    if !pattern.contains('\\') {
        return readings;
    }
    for keeps in ["wWsSbB", ""] {
        let mut out = String::with_capacity(pattern.len());
        let mut chars = pattern.chars();
        while let Some(character) = chars.next() {
            if character != '\\' {
                out.push(character);
                continue;
            }
            match chars.next() {
                Some(letter) if letter.is_ascii_alphabetic() && !keeps.contains(letter) => {
                    out.push(letter);
                }
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        }
        if !readings.contains(&out) {
            readings.push(out);
        }
    }
    readings
}

/// What a `pkill` or `pgrep` pattern does to the guard's processes, in the
/// strongest of its [`dialect_readings`], case ignored: matched against the
/// command lines with `-f` ([`pattern_reach`]), against the names without
/// ([`name_reach`]). A pattern that names a path whose file is one of the
/// guard's programs, in any folder ([`names_a_guard_path`]), names the
/// guard. [`PkillReach::Broad`] when no reading compiles: what the program
/// makes of it is not known, and a person decides.
pub(super) fn reach_of_pattern(pattern: &str, full: bool) -> PkillReach {
    if names_a_guard_path(pattern) {
        return PkillReach::NamesGuard;
    }
    let mut reach: Option<PkillReach> = None;
    for reading in dialect_readings(pattern) {
        let Ok(regex) = regex::RegexBuilder::new(&reading)
            .case_insensitive(true)
            .size_limit(1 << 20)
            .build()
        else {
            continue;
        };
        let this = if full {
            pattern_reach(&regex)
        } else {
            name_reach(&regex)
        };
        reach = Some(reach.map_or(this, |before| before.max(this)));
    }
    reach.unwrap_or(PkillReach::Broad)
}

/// Whether `pattern` spells a path whose file is one of the guard's
/// programs (`/opt/iw/bin/innerwarden`, `~/bin/innerwarden-agent`), in a
/// folder the guard's lines do not list: every process of that program is
/// the guard's.
fn names_a_guard_path(pattern: &str) -> bool {
    pattern
        .split(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '~')))
        .filter(|token| token.contains('/'))
        .any(|token| {
            let file = token.rsplit('/').next().unwrap_or(token);
            !file.is_empty() && names_a_guard_process(file, true)
        })
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

/// What the processes `command` lists do to the guard, when it is a
/// `pgrep` (its pattern read as `pkill` reads it, [`super::pkill_reach`])
/// or a `pidof` (each name matched whole, [`names_a_guard_process`]),
/// behind any launcher the shell reads (`env`, `command`, `exec`, `sudo`).
fn listed_reach(command: &Command) -> PkillReach {
    let Some(words) = plain_words(command) else {
        return PkillReach::Unread;
    };
    let Some(at) = launched_command_index(&words) else {
        return PkillReach::Unread;
    };
    match program_name(&words[at]).as_str() {
        "pgrep" => {
            let segment: Vec<String> = std::iter::once("pkill".to_owned())
                .chain(words[at + 1..].iter().map(|word| quoted(word)))
                .collect();
            super::pkill_reach(&segment.join(" "))
        }
        "pidof" => {
            let mut reach = PkillReach::Misses;
            let mut rest = words[at + 1..].iter();
            while let Some(word) = rest.next() {
                if word == "-o" || word == "--omit-pid" {
                    rest.next();
                } else if !word.starts_with('-') && names_a_guard_process(word, false) {
                    reach = PkillReach::NamesGuard;
                }
            }
            reach
        }
        _ => PkillReach::Misses,
    }
}

/// Whether `command` runs `kill` on what it is handed: `kill` itself, or
/// `xargs` starting it, behind any launcher the shell reads.
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

/// What a `pgrep` or `pidof` that finds the guard's processes
/// ([`listed_reach`]) does when it hands what it prints to `kill`: through
/// a pipe into `kill` or `xargs kill`, or as a substitution in a `kill`'s
/// words. The strongest such hand-over of the line.
pub(super) fn pgrep_feeds_a_kill_of_the_guard(text: &str) -> PkillReach {
    if !text.contains("pgrep") && !text.contains("pidof") {
        return PkillReach::Misses;
    }
    feeds_kill(text, 0)
}

fn feeds_kill(text: &str, depth: u8) -> PkillReach {
    let line = read_line(text);
    let mut reach = PkillReach::Misses;
    for (index, command) in line.commands.iter().enumerate() {
        if command.piped && line.commands.get(index + 1).is_some_and(runs_kill) {
            reach = reach.max(listed_reach(command));
        }
        if runs_kill(command) {
            for inner in command.words.iter().flat_map(|word| &word.substitutions) {
                for listed in &read_line(inner).commands {
                    reach = reach.max(listed_reach(listed));
                }
            }
        }
    }
    if depth < NESTED_DEPTH {
        for inner in &line.nested {
            reach = reach.max(feeds_kill(inner, depth + 1));
        }
    }
    // What a list misses or reads less surely kills nothing of the guard.
    if reach < PkillReach::Broad {
        PkillReach::Misses
    } else {
        reach
    }
}

/// The options of `killall` (psmisc, and the BSDs' and macOS's) that take
/// the next word as their value.
const KILLALL_VALUED: &[&str] = &[
    "-s",
    "--signal",
    "-u",
    "--user",
    "-y",
    "--younger-than",
    "-o",
    "--older-than",
    "-n",
    "--ns",
    "-Z",
    "--context",
    "-t",
    "-c",
];

/// What a `killall` of the line does to the guard's processes: each name
/// matched whole ([`names_a_guard_process`]), or with `-r` (psmisc) or `-m`
/// (the BSDs, macOS) read as a pattern over the names ([`name_reach`], in
/// every dialect). Behind any launcher the shell reads.
pub(super) fn killall_reach(text: &str) -> PkillReach {
    if !text.contains("killall") {
        return PkillReach::Misses;
    }
    killall_in(text, 0)
}

fn killall_in(text: &str, depth: u8) -> PkillReach {
    let line = read_line(text);
    let mut reach = PkillReach::Misses;
    for command in &line.commands {
        let words: Vec<String> = command.words.iter().map(|w| w.text.clone()).collect();
        let Some(at) = launched_command_index(&words) else {
            continue;
        };
        if program_name(&words[at]) != "killall" {
            continue;
        }
        let mut pattern = false;
        let mut ignore_case = false;
        let mut names = Vec::new();
        let mut rest = words[at + 1..].iter();
        let mut options_done = false;
        while let Some(word) = rest.next() {
            if options_done || !word.starts_with('-') || word == "-" {
                names.push(word.as_str());
                continue;
            }
            match word.as_str() {
                "--" => options_done = true,
                "--regexp" => pattern = true,
                "--ignore-case" => ignore_case = true,
                valued if KILLALL_VALUED.contains(&valued) => {
                    rest.next();
                }
                long if long.starts_with("--") => {}
                short => {
                    let flags = &short[1..];
                    // A signal: `-9`, `-KILL`, `-SIGTERM`.
                    if flags.bytes().all(|b| b.is_ascii_digit())
                        || (flags.len() >= 3 && flags.bytes().all(|b| b.is_ascii_uppercase()))
                    {
                        continue;
                    }
                    pattern |= flags.contains('r') || flags.contains('m');
                    ignore_case |= flags.contains('I');
                }
            }
        }
        for name in names {
            let this = if pattern {
                reach_of_pattern(name, false)
            } else if names_a_guard_process(name, ignore_case) {
                PkillReach::NamesGuard
            } else {
                PkillReach::Misses
            };
            reach = reach.max(this);
        }
    }
    if depth < NESTED_DEPTH {
        for inner in &line.nested {
            reach = reach.max(killall_in(inner, depth + 1));
        }
    }
    if reach < PkillReach::Broad {
        PkillReach::Misses
    } else {
        reach
    }
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
    units
        .iter()
        .find_map(|unit| protected_target(unit).or_else(|| glob_target(unit)))
}

/// The units of the guard, as its installers name them.
const GUARD_UNITS: &[&str] = &[
    "innerwarden",
    "innerwarden-sensor",
    "innerwarden-agent",
    "innerwarden-watchdog",
    "innerwarden-supervisor",
    "innerwarden-dns-guard",
];

/// The protected target a unit pattern reaches: systemd expands a glob in
/// `stop`, `disable`, `mask` and `kill` over the units it knows, so the
/// pattern is matched (as `fnmatch` matches it) against the guard's units
/// and each [`PROTECTED_TARGETS`] name, with and without `.service`. A
/// pattern that cannot be read (an unclosed `[`) is taken as reaching the
/// guard.
fn glob_target(unit: &str) -> Option<&'static str> {
    if !unit.contains(['*', '?', '[']) {
        return None;
    }
    let Some(tokens) = glob_tokens(unit.as_bytes()) else {
        return Some("innerwarden");
    };
    let names = GUARD_UNITS
        .iter()
        .map(|unit| (*unit, "innerwarden"))
        .chain(PROTECTED_TARGETS.iter().map(|target| (*target, *target)));
    for (name, target) in names {
        for full in [name.to_owned(), format!("{name}.service")] {
            if glob_matches(&tokens, full.as_bytes()) {
                return Some(target);
            }
        }
    }
    None
}

/// One part of a glob pattern.
enum GlobToken {
    /// `*`: any run of bytes.
    Any,
    /// `?`: one byte.
    One,
    /// A byte as written, or after a backslash.
    Byte(u8),
    /// A bracket expression: its byte ranges, and whether it is negated.
    Set(Vec<(u8, u8)>, bool),
}

/// `pattern` as [`GlobToken`]s; none when a bracket is never closed or a
/// backslash ends it.
fn glob_tokens(pattern: &[u8]) -> Option<Vec<GlobToken>> {
    let mut tokens = Vec::new();
    let mut at = 0usize;
    while at < pattern.len() {
        match pattern[at] {
            b'*' => tokens.push(GlobToken::Any),
            b'?' => tokens.push(GlobToken::One),
            b'\\' => {
                at += 1;
                tokens.push(GlobToken::Byte(*pattern.get(at)?));
            }
            b'[' => {
                at += 1;
                let negated = matches!(pattern.get(at), Some(b'!' | b'^'));
                if negated {
                    at += 1;
                }
                let mut ranges = Vec::new();
                let mut first = true;
                loop {
                    let byte = *pattern.get(at)?;
                    if byte == b']' && !first {
                        break;
                    }
                    first = false;
                    if byte == b'[' && pattern.get(at + 1) == Some(&b':') {
                        // A class (`[:alpha:]`): every letter, digit and mark
                        // it may hold, read as any byte.
                        let close = pattern[at + 2..].windows(2).position(|w| w == b":]")?;
                        at += close + 4;
                        ranges.push((0u8, u8::MAX));
                        continue;
                    }
                    if pattern.get(at + 1) == Some(&b'-')
                        && pattern.get(at + 2).is_some_and(|end| *end != b']')
                    {
                        ranges.push((byte, pattern[at + 2]));
                        at += 3;
                    } else {
                        ranges.push((byte, byte));
                        at += 1;
                    }
                }
                tokens.push(GlobToken::Set(ranges, negated));
            }
            byte => tokens.push(GlobToken::Byte(byte)),
        }
        at += 1;
    }
    Some(tokens)
}

/// Whether `tokens` match all of `name`, by the table of which prefix of
/// the pattern matches which prefix of the name.
fn glob_matches(tokens: &[GlobToken], name: &[u8]) -> bool {
    let mut row = vec![false; name.len() + 1];
    row[0] = true;
    for token in tokens {
        let mut next = vec![false; name.len() + 1];
        for at in 0..=name.len() {
            next[at] = match token {
                GlobToken::Any => row[at] || (at > 0 && next[at - 1]),
                _ if at == 0 => false,
                GlobToken::One => row[at - 1],
                GlobToken::Byte(byte) => row[at - 1] && name[at - 1] == *byte,
                GlobToken::Set(ranges, negated) => {
                    let byte = name[at - 1];
                    let inside = ranges
                        .iter()
                        .any(|(low, high)| (*low..=*high).contains(&byte));
                    row[at - 1] && inside != *negated
                }
            };
        }
        row = next;
    }
    row[name.len()]
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
            "innerwarden mcp-proxy",
            // A piece of the name, or the legacy proxy layout.
            "warden",
            "inner",
            "innerwar",
            "den",
            "mcp-proxy -- npx",
        ] {
            assert_eq!(reach(pattern), PkillReach::NamesGuard, "{pattern}");
        }
        // A whole word of the guard's, its name untouched: the kill takes
        // the guard with others, a person decides.
        for pattern in [
            "proxy",
            "hook",
            "dashboard",
            "guard",
            "local",
            "/usr/local/bin",
        ] {
            assert_eq!(reach(pattern), PkillReach::Broad, "{pattern}");
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
        for pattern in ["innerwarden-docs-server", "cargo build", "vite --port"] {
            assert_eq!(reach(pattern), PkillReach::Misses, "{pattern}");
        }
    }

    /// The newest of [`WRAPPER_LAYOUTS`] is what [`crate::mcp_wire::wrap`]
    /// writes today, for every agent it wires and in each mode: a new
    /// layout is added to the history, not written over it.
    #[test]
    fn the_newest_wrapper_layout_is_the_one_the_cli_writes() {
        let newest = WRAPPER_LAYOUTS.last().unwrap();
        for agent in wired_agents() {
            for (monitor, mode) in [(false, "guard"), (true, "advisory")] {
                let config = serde_json::json!({"mcpServers": {"s": {
                    "command": "npx", "args": ["-y", "server"],
                }}});
                let (wrapped, _) = crate::mcp_wire::wrap(config, "/x/innerwarden", monitor, agent);
                let args: Vec<String> = wrapped["mcpServers"]["s"]["args"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|arg| arg.as_str().unwrap().to_owned())
                    .collect();
                let separator = args.iter().position(|arg| arg == "--").unwrap();
                let expected: Vec<String> = newest
                    .iter()
                    .map(|word| word.replace("{mode}", mode).replace("{agent}", agent))
                    .collect();
                assert_eq!(args[0], "proxy", "{args:?}");
                assert_eq!(args[1..separator], expected[..], "{agent}: {args:?}");
            }
        }
    }

    /// A kill pattern across the words of every layout, past the program,
    /// names the guard; the agent's id alone does not.
    #[test]
    fn every_wrapper_layout_is_matched() {
        for layout in WRAPPER_LAYOUTS {
            let words: Vec<String> = layout
                .iter()
                .map(|word| {
                    word.replace("{mode}", "advisory")
                        .replace("{agent}", "codex")
                })
                .collect();
            let pattern = regex::escape(&format!("proxy {} --", words.join(" ")));
            assert_eq!(reach(&pattern), PkillReach::NamesGuard, "{pattern}");
        }
        assert_eq!(reach("codex"), PkillReach::Unread);
    }

    /// The shell of a fail-closed hook: its words are the guard's, the
    /// agent's id is the agent's, and the words of its message alone are
    /// no mark of the guard.
    #[test]
    fn the_fail_closed_shell_is_a_line_of_the_guards() {
        assert!(guard_lines()
            .iter()
            .any(|line| line.text.starts_with("/bin/sh -c \"$0\" hook")));
        for pattern in ["without an answer", "--agent codex; s=", "esac; echo"] {
            assert_eq!(
                reach(&regex::escape(pattern)),
                PkillReach::NamesGuard,
                "{pattern}"
            );
        }
        for pattern in ["program", "settings", "answer"] {
            let found = reach(pattern);
            assert!(found < PkillReach::Broad, "{pattern}: {found:?}");
        }
    }

    #[test]
    fn every_dialect_that_may_run_a_pattern_is_read() {
        // `\d` is a digit here and `d` in glibc's and the BSDs' ERE.
        assert_eq!(
            reach_of_pattern(r"innerwar\den", true),
            PkillReach::NamesGuard
        );
        assert_eq!(
            reach_of_pattern(r"inner\warden", true),
            PkillReach::NamesGuard
        );
        assert_eq!(
            reach_of_pattern(r"node\s+server\.js", true),
            PkillReach::Unread
        );
        assert_eq!(reach_of_pattern(r"cargo\d", true), PkillReach::Misses);
    }

    #[test]
    fn process_names_are_matched_as_pkill_and_killall_match_them() {
        assert_eq!(reach_of_pattern("warden", false), PkillReach::NamesGuard);
        assert_eq!(reach_of_pattern("agent", false), PkillReach::Broad);
        assert_eq!(reach_of_pattern("node", false), PkillReach::Misses);
        assert!(names_a_guard_process("innerwarden", false));
        assert!(names_a_guard_process("innerwarden-sen", false));
        assert!(names_a_guard_process("/usr/local/bin/innerwarden", false));
        assert!(names_a_guard_process("INNERWARDEN", true));
        assert!(!names_a_guard_process("INNERWARDEN", false));
        assert!(!names_a_guard_process("innerwarden-docs-server", false));
    }

    #[test]
    fn a_unit_glob_is_matched_against_the_guards_units() {
        for unit in [
            "innerwar*",
            "*warden*",
            "inner?arden-agent",
            "innerwarden-[a-z]*",
            "*",
        ] {
            assert_eq!(glob_target(unit), Some("innerwarden"), "{unit}");
        }
        // Not read: closes.
        assert_eq!(glob_target("inner[warden"), Some("innerwarden"));
        assert_eq!(glob_target("fal*"), Some("falco"));
        for unit in ["nginx*", "php*-fpm", "user@*.service"] {
            assert_eq!(glob_target(unit), None, "{unit}");
        }
    }
}
