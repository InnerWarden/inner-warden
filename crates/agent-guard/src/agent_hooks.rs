//! The blocking hook for the agents that keep it outside Claude Code's
//! settings: Codex CLI, Gemini CLI and Cursor.
//!
//! Both run a command before a tool call and refuse the call when the command
//! exits 2 with text on stderr, which is what `innerwarden hook` answers. So
//! the hook is the one Claude Code runs, and only the wiring differs:
//!
//! | agent  | file                      | event        | timeout in   |
//! |--------|---------------------------|--------------|--------------|
//! | Codex  | `~/.codex/hooks.json`     | `PreToolUse` | seconds      |
//! | Gemini | `~/.gemini/settings.json` | `BeforeTool` | milliseconds |
//! | Cursor | `~/.cursor/hooks.json`    | `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile` | seconds |
//! | Antigravity | `~/.gemini/config/hooks.json` | `PreToolUse` under the hook name `innerwarden` | seconds |
//!
//! Antigravity's file maps a hook's name to its events, so the guard's group
//! sits under its own name instead of under `hooks`, and Antigravity reads a
//! JSON `decision` on stdout ([`crate::antigravity_hook`]).
//!
//! Cursor's file lists the hooks flat under each event (no group, no
//! matcher), carries `version: 1` and a `failClosed` switch per entry, and
//! Cursor reads a JSON `permission` on stdout ([`crate::cursor_hook`]).
//!
//! The entry carries no matcher, so every tool call reaches the hook and the
//! guard lets through what it does not screen. It carries an explicit timeout,
//! longer than the guard's own longest wait: both agents run the tool when a
//! hook times out, so the guard has to answer first.
//!
//! An entry in the file is not a hook that runs. Codex skips a hook it does
//! not trust ([`crate::codex_trust`]), and both agents have switches that turn
//! hooks off without a word. [`state`] reads all of that and says "on" only
//! when nothing it can read says otherwise.
//!
//! These agents keep their MCP proxy as well: the hook screens the agent's own
//! shell and file tools, the proxy screens the calls to its MCP servers.

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Map, Value};
use toml_edit::DocumentMut;

use crate::codex_trust::{self, GrantError, Place, Skip, Trust};
use crate::{agents_ops, file_update, hook};

/// The name Gemini lists the hook under, and the name a person disables it by.
const GEMINI_HOOK_NAME: &str = "innerwarden";

/// Where Codex keeps the trust it gave a hook, relative to the home directory.
const CODEX_CONFIG: &str = ".codex/config.toml";

/// The one step that turns on a Codex hook this crate could not get trusted.
const TRUST_STEP: &str = "Run `/hooks` inside Codex and trust the innerwarden hook";

/// The one step for a hook the person switched off in Codex.
const SWITCH_ON_STEP: &str = "Switch it back on with `/hooks` inside Codex";

/// The one step when Codex keeps its settings in a folder other than the one
/// the hook was written in.
const OTHER_HOME_STEP: &str =
    "Start Codex without CODEX_HOME, then run `innerwarden agents connect codex` again";

/// The one step when Codex does not list the hook and no file read here says
/// why.
const NOT_LISTED_STEP: &str = "Update Codex, make sure hooks are not switched off, then run \
                               `innerwarden agents connect codex` again";

/// The variable that moves the folder Codex keeps its settings in.
const CODEX_HOME_VAR: &str = "CODEX_HOME";

/// The agent a hook is wired into. What differs between the two is the unit
/// of the timeout and where trust and the off switches live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host {
    Codex,
    Gemini,
    Cursor,
    Antigravity,
}

/// Where one agent keeps its hook, and what the entry written there holds.
#[derive(Debug, PartialEq, Eq)]
pub struct HookSpec {
    /// The agent's name in the listing, and the id the hook line carries.
    pub agent: &'static str,
    /// The agent's name in a sentence.
    pub product: &'static str,
    pub host: Host,
    /// The file that holds the hook, relative to the home directory.
    pub file: &'static str,
    /// The event the hook is listed under, and the name the listing gives it.
    pub event: &'static str,
    /// Further events the same entry is listed under (Cursor's), each of
    /// which must hold it for the hook to be on.
    pub more_events: &'static [&'static str],
    /// How long the agent waits for the hook, in the agent's own unit:
    /// seconds for Codex, milliseconds for Gemini.
    pub timeout: u64,
    /// The file that holds the agent's MCP servers, relative to the home
    /// directory. A row found through any other file is not this agent.
    pub mcp_config: &'static str,
    /// The agent's own tools that change files, as it names them.
    pub file_tools: &'static str,
    /// The line that says how the behaviour stated here was measured.
    pub measured: &'static str,
    /// The oldest release that runs this hook as written, and why, in the
    /// words that follow "Needs ". Read in the agent's own source at its
    /// release tags, not measured on those releases.
    pub minimum: &'static str,
}

/// Codex CLI. The timeout is in seconds.
pub static CODEX: HookSpec = HookSpec {
    agent: "codex",
    product: "Codex",
    host: Host::Codex,
    file: ".codex/hooks.json",
    event: "PreToolUse",
    more_events: &[],
    timeout: 60,
    mcp_config: CODEX_CONFIG,
    file_tools: "`apply_patch`",
    measured: "Measured on Linux with Codex CLI 0.170.0 and on macOS with Codex CLI 0.167.2.",
    minimum: "Codex CLI 0.166.0 or later. Codex runs a PreToolUse hook for its shell and \
              `apply_patch` from 0.124.0 and asks for trust from 0.129.0, but before 0.166.0 \
              the folder it sends is the session's, not the command's, so a command run in \
              another folder is judged in the wrong one.",
};

/// Gemini CLI. The timeout is in milliseconds.
pub static GEMINI: HookSpec = HookSpec {
    agent: "gemini",
    product: "Gemini",
    host: Host::Gemini,
    file: ".gemini/settings.json",
    event: "BeforeTool",
    more_events: &[],
    timeout: 60_000,
    mcp_config: ".gemini/settings.json",
    file_tools: "`write_file` and `replace`",
    measured: "Judged only by its payload, not on a running Gemini, which needs a Google login.",
    minimum: "Gemini CLI 0.26.0 or later: before it, Gemini runs no hook unless \
              `hooks.enabled` is set. From 0.30.0 Gemini refuses a tool call on any hook exit \
              but 0 and 1, so on Linux and macOS the monitor line turns every other end of \
              the guard into 1.",
};

/// Cursor. The timeout is in seconds. Read in Cursor's hooks documentation
/// (cursor.com/docs/agent/hooks, as published on 2026-11-20), not measured
/// on a running Cursor.
pub static CURSOR: HookSpec = HookSpec {
    agent: "cursor",
    product: "Cursor",
    host: Host::Cursor,
    file: ".cursor/hooks.json",
    event: crate::cursor_hook::SHELL_EVENT,
    more_events: &[
        crate::cursor_hook::MCP_EVENT,
        crate::cursor_hook::READ_EVENT,
    ],
    timeout: 60,
    mcp_config: ".cursor/mcp.json",
    file_tools: "",
    measured: "Judged only by the payloads Cursor's hooks documentation gives \
               (cursor.com/docs/agent/hooks, read on 2026-11-20), not on a running Cursor.",
    minimum: "a Cursor that runs hooks from ~/.cursor/hooks.json with `failClosed` \
              (its hooks documentation of 2026-11; the version that added `failClosed` is \
              not named there). On a Cursor without it, a guard that cannot answer still \
              refuses in enforce mode on Linux and macOS, where the line ends in exit 2.",
};

/// The Antigravity CLI. The timeout is in seconds. Read in Antigravity's
/// hooks documentation (antigravity.google/docs/hooks, as published on
/// 2026-11-21), not measured on a running `agy`. It has no MCP config here:
/// where the CLI keeps its MCP servers is not confirmed, so no proxy is
/// wired for it.
pub static ANTIGRAVITY: HookSpec = HookSpec {
    agent: crate::antigravity_hook::AGENT,
    product: "Antigravity",
    host: Host::Antigravity,
    file: crate::antigravity_hook::FILE,
    event: crate::antigravity_hook::EVENT,
    more_events: &[],
    timeout: 60,
    mcp_config: "",
    file_tools: "`write_to_file`, `replace_file_content` and `multi_replace_file_content`",
    measured: "Judged only by the payloads Antigravity's hooks documentation gives \
               (antigravity.google/docs/hooks, read on 2026-11-21), not on a running \
               Antigravity CLI, which needs a Google login.",
    minimum: "an Antigravity CLI that runs hooks from ~/.gemini/config/hooks.json (its hooks \
              documentation of 2026-11; it names no version).",
};

/// The hook wiring for the agent the listing calls `agent`, when it has one.
pub fn spec_for(agent: &str) -> Option<&'static HookSpec> {
    [&CODEX, &GEMINI, &CURSOR, &ANTIGRAVITY]
        .into_iter()
        .find(|spec| spec.agent == agent)
}

/// How long the guard gives itself to answer before it refuses the call in
/// enforce mode: the hook's own deadline (`hook_net::DEADLINE` in the CLI,
/// which a test there holds to this). A second opinion the operator turned on
/// moves it by the bound of that wait.
pub const GUARD_DEADLINE_SECS: u64 = 10;

/// What happens to a tool call when the innerwarden program a hook names is
/// gone, killed or ends without an answer, for an agent named `product`.
///
/// On Linux and macOS the enforcing line is the fail-closed script
/// ([`hook::hook_command_shaped`]), and the monitor line never refuses: plain
/// for Codex, the fail-open script for Gemini. On Windows every line is
/// plain. How the agent reads the line's end was read in its source and run
/// under `sh` with a stand-in guard, not measured on a running agent, and
/// the line says so.
fn fail_closed_gap(product: &str) -> String {
    if cfg!(unix) {
        format!(
            "If the innerwarden program the hook names is moved, removed or killed, {product} \
             refuses every tool call in enforce mode and runs it unscreened in monitor mode \
             (read in {product}'s source and run under sh with a stand-in guard, not measured \
             on a running {product})."
        )
    } else {
        format!(
            "If the innerwarden program the hook names is moved, removed or killed, {product} \
             runs the tool: on Windows the hook line is the program alone."
        )
    }
}

impl HookSpec {
    /// Every event the entry is listed under: [`HookSpec::event`] first.
    pub fn events(&self) -> impl Iterator<Item = &'static str> {
        std::iter::once(self.event).chain(self.more_events.iter().copied())
    }

    /// The file that holds the hook, under `home`.
    pub fn path(&self, home: &Path) -> PathBuf {
        home.join(self.file)
    }

    /// The key at the top of the file the events sit under: `hooks`, or for
    /// Antigravity, whose file maps a hook's name to its events, the guard's
    /// own name.
    fn container(&self) -> &'static str {
        match self.host {
            Host::Antigravity => crate::antigravity_hook::HOOK_NAME,
            Host::Codex | Host::Gemini | Host::Cursor => "hooks",
        }
    }

    /// Whether the agent has an MCP config the proxy is wired through.
    pub fn has_mcp_config(&self) -> bool {
        !self.mcp_config.is_empty()
    }

    /// The hook line: the program, `hook`, the mode flag and this agent's id.
    ///
    /// Nothing in it changes from one release to the next for one install
    /// path. Codex's trust covers the line and the timeout, so a line that
    /// moved with a version would switch the hook off at every upgrade.
    pub fn command(&self, guard_bin: &Path, block_review: bool, monitor: bool) -> String {
        hook::hook_command_shaped(
            guard_bin,
            block_review,
            monitor,
            Some(self.agent),
            cfg!(unix),
        )
    }

    /// How long the agent waits for the hook before it runs the tool.
    pub fn wait(&self) -> Duration {
        match self.host {
            Host::Codex | Host::Cursor | Host::Antigravity => Duration::from_secs(self.timeout),
            Host::Gemini => Duration::from_millis(self.timeout),
        }
    }

    /// The one group `agents connect` writes under the event: a command hook
    /// with a timeout and no matcher. For Cursor it is the hook itself, flat
    /// in the event's list, with `failClosed` on in enforce mode and off in
    /// monitor, which never refuses.
    fn entry(&self, command: &str) -> Value {
        if self.host == Host::Cursor {
            let monitor = hook::read_hook_line(&json!({ "command": command }))
                .is_some_and(|line| line.monitor);
            return json!({
                "command": command,
                "timeout": self.timeout,
                "failClosed": !monitor,
            });
        }
        let mut hook = Map::new();
        hook.insert("type".to_string(), Value::from("command"));
        if self.host == Host::Antigravity {
            // `""` matches every tool (its hooks documentation). With no
            // matcher at all what it runs for is not documented.
            hook.insert("command".to_string(), Value::from(command));
            hook.insert("timeout".to_string(), Value::from(self.timeout));
            return json!({ "matcher": "", "hooks": [Value::Object(hook)] });
        }
        if self.host == Host::Gemini {
            hook.insert("name".to_string(), Value::from(GEMINI_HOOK_NAME));
        }
        hook.insert("command".to_string(), Value::from(command));
        hook.insert("timeout".to_string(), Value::from(self.timeout));
        json!({ "hooks": [Value::Object(hook)] })
    }

    /// What the hook and the proxy screen between them, in the words that
    /// follow "screened before they run: ".
    pub fn screened(&self) -> String {
        // Gemini's read tools are judged as the shell read of the same files
        // (`file_tools::OTHER_READ_TOOLS`). Codex reads through its shell.
        let reads = match self.host {
            Host::Gemini => {
                ", reads of secrets through `read_file`, `read_many_files`, `glob` and \
                 `grep_search`"
            }
            Host::Codex => "",
            Host::Cursor => return crate::cursor_hook::screened(),
            Host::Antigravity => return crate::antigravity_hook::screened(),
        };
        format!(
            "shell commands, changes to privileged files through {}{reads}, and calls to MCP \
             servers behind the proxy. Its other tools are not screened.",
            self.file_tools
        )
    }

    /// What is screened for this agent and what is not, in the words
    /// `agents connect` prints. Each line is one measured fact.
    pub fn coverage(&self) -> Vec<String> {
        let mut lines = vec![format!("Screened before they run: {}", self.screened())];
        lines.extend(self.gaps());
        lines
    }

    /// What a hook that is on still leaves unscreened, and when the agent
    /// stops running it. Each line is one measured fact.
    pub fn gaps(&self) -> Vec<String> {
        let mut lines = Vec::new();
        match self.host {
            Host::Codex => {
                lines.push(
                    "Not screened: `write_stdin` and `tool_search`. Codex does not run the hook \
                     for them, so a shell started in one call can be given any command through \
                     `write_stdin`, unscreened. In enforce mode a shell call that starts a \
                     shell, a language or a database client with nothing to run (`bash`, \
                     `python3`, `psql`) is refused for that reason; one started any other way \
                     that reads its input (`cat | sh`, a program of its own) is not seen."
                        .to_string(),
                );
                lines.push(
                    "Codex runs the hook only while it trusts it. A changed hook line, \
                     `enabled = false`, `hooks = false` under [features] or \
                     `codex --disable hooks` switch it off without a word."
                        .to_string(),
                );
                lines.push(
                    "The hook is written in ~/.codex. A Codex started with CODEX_HOME set to \
                     another folder reads its hooks there and does not run this one."
                        .to_string(),
                );
                lines.push(fail_closed_gap(self.product));
                lines.push(
                    "Codex starts the hook line with your login shell (`$SHELL -lc`, else \
                     `/bin/sh -lc`), which runs its startup files before the guard: zsh \
                     ~/.zshenv, ~/.zprofile and ~/.zlogin, bash the first of ~/.bash_profile, \
                     ~/.bash_login and ~/.profile, sh ~/.profile. A line in one can end the \
                     hook before the guard answers. A shell change to ~/.zshenv is refused; \
                     a change to the others is refused through `apply_patch` and only flagged \
                     through the shell. A ZDOTDIR set in your environment moves zsh's files, \
                     and the guard does not read ZDOTDIR."
                        .to_string(),
                );
                lines.push(
                    "Inline interpreter code that rewrites ~/.codex/hooks.json or \
                     ~/.codex/config.toml is refused by its text; code that builds the file's \
                     name from pieces is not seen."
                        .to_string(),
                );
            }
            Host::Gemini => lines.push(
                "Gemini skips the hook in a folder it does not trust, and when user or project \
                 settings switch hooks off or disable this one. Project settings are not read \
                 here."
                    .to_string(),
            ),
            Host::Cursor => {
                lines.extend(crate::cursor_hook::gaps());
                lines.push(format!("Needs {}", self.minimum));
                lines.push(self.measured.to_string());
                return lines;
            }
            Host::Antigravity => {
                lines.extend(crate::antigravity_hook::gaps());
                lines.push(format!(
                    "The guard answers within {GUARD_DEADLINE_SECS} seconds (more only while it \
                     waits on a second opinion you turned on), with a deny in enforce mode when \
                     it runs out of time. Antigravity gives the hook {} seconds (the entry's \
                     `timeout`).",
                    self.wait().as_secs()
                ));
                lines.push(format!("Needs {}", self.minimum));
                lines.push(self.measured.to_string());
                return lines;
            }
        }
        if self.host == Host::Gemini {
            lines.push(fail_closed_gap(self.product));
        }
        lines.push(format!(
            "The guard answers within {} seconds (more only while it waits on a second opinion \
             you turned on) or refuses the call in enforce mode. If {} stops the hook at its \
             own limit of {} seconds, or the hook's shell is killed, {} runs the tool.",
            GUARD_DEADLINE_SECS,
            self.product,
            self.wait().as_secs(),
            self.product
        ));
        lines.push(format!("Needs {}", self.minimum));
        lines.push(self.measured.to_string());
        lines
    }
}

/// One InnerWarden hook found under the event, with where it sits.
struct Found {
    /// The event it is listed under.
    event: &'static str,
    group: usize,
    index: usize,
    line: hook::HookLine,
    /// The command exactly as the file holds it.
    command: String,
    /// The timeout the file holds, when it holds a whole number.
    timeout: Option<u64>,
}

/// Every InnerWarden hook under the spec's events, in file order. In
/// Cursor's flat lists each hook is its own group, at index 0.
fn found(settings: &Value, spec: &HookSpec) -> Vec<Found> {
    let mut out = Vec::new();
    for event in spec.events() {
        let Some(groups) = settings
            .get(spec.container())
            .and_then(|hooks| hooks.get(event))
            .and_then(Value::as_array)
        else {
            continue;
        };
        found_in(groups, spec, event, &mut out);
    }
    out
}

/// [`found`] for one event's list.
fn found_in(groups: &[Value], spec: &HookSpec, event: &'static str, out: &mut Vec<Found>) {
    for (group, entry) in groups.iter().enumerate() {
        let flat;
        let list: &[Value] = if spec.host == Host::Cursor {
            flat = [entry.clone()];
            &flat
        } else {
            match entry.get("hooks").and_then(Value::as_array) {
                Some(list) => list,
                None => continue,
            }
        };
        for (index, hook) in list.iter().enumerate() {
            let Some(line) = hook::read_hook_line(hook) else {
                continue;
            };
            out.push(Found {
                event,
                group,
                index,
                line,
                command: hook
                    .get("command")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                timeout: hook.get("timeout").and_then(Value::as_u64),
            });
        }
    }
}

/// Whether a group holds a hook of ours, and whether it holds nothing else
/// (read only of a group that holds one of ours).
fn ours_in(group: &Value) -> (bool, bool) {
    let Some(list) = group.get("hooks").and_then(Value::as_array) else {
        return (false, false);
    };
    let ours = list
        .iter()
        .filter(|hook| hook::read_hook_line(hook).is_some())
        .count();
    (ours > 0, ours == list.len())
}

/// How much of a hook's command a message shows.
const SHOWN_COMMAND_CHARS: usize = 60;

/// A hook's command as a short piece of one line: control characters become
/// spaces and a long command is cut.
fn shown(command: &str) -> String {
    let plain: String = command
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    match plain.char_indices().nth(SHOWN_COMMAND_CHARS) {
        Some((cut, _)) => format!("{}...", &plain[..cut]),
        None => plain,
    }
}

/// The program a hook's command starts, as the person wrote it: its first
/// word, or the quoted text it starts with. The rest of the command is never
/// shown. A note under `agents connect` or `disconnect` that held the
/// person's own words could read as a failure of the run (`echo "audit
/// failed: x"`), so a program whose name says `failed:` is not shown either.
fn program_of(command: &str) -> Option<String> {
    let command = command.trim_start();
    let word = match command.chars().next() {
        Some(quote @ ('"' | '\'')) => command[1..].split(quote).next().unwrap_or(""),
        _ => command.split_whitespace().next().unwrap_or(""),
    };
    (!word.is_empty() && !word.contains("failed:")).then(|| shown(word))
}

/// The person's own hooks under the spec's event, in file order: where each
/// sits, and the words that name it in a message: the program it starts, or
/// its place when that cannot be shown.
fn theirs_at(settings: &Value, spec: &HookSpec) -> Vec<((usize, usize), String)> {
    let Some(groups) = settings
        .get(spec.container())
        .and_then(|hooks| hooks.get(spec.event))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (group, entry) in groups.iter().enumerate() {
        let Some(list) = entry.get("hooks").and_then(Value::as_array) else {
            continue;
        };
        for (index, hook) in list.iter().enumerate() {
            if hook::read_hook_line(hook).is_some() {
                continue;
            }
            let name = match hook.get("command").and_then(Value::as_str) {
                Some(command) => match program_of(command) {
                    Some(program) => format!("`{program}`"),
                    None => format!("the one at group {}, hook {}", group + 1, index + 1),
                },
                None => "one with no command".to_string(),
            };
            out.push(((group, index), name));
        }
    }
    out
}

/// PURE: the person's own Codex hooks that sit at another place in `after`
/// than in `before`, in file order, each by the words that name it.
///
/// Codex keys its trust by place. A hook of the person's that moved has no
/// trust at its new place, and Codex skips it without a word. Taking a hook
/// of ours out of the file moves every hook listed behind it. Gemini keeps no
/// trust by place, so nothing is named for it.
///
/// Both settings hold the same hooks of the person's in the same order: the
/// writes of this module take out hooks of ours and nothing else.
pub fn moved(before: &Value, after: &Value, spec: &HookSpec) -> Vec<String> {
    if spec.host != Host::Codex {
        return Vec::new();
    }
    let was = theirs_at(before, spec);
    let now = theirs_at(after, spec);
    was.iter()
        .zip(&now)
        .filter(|((old, _), (new, _))| old != new)
        .map(|(_, (_, name))| name.clone())
        .collect()
}

/// What to say when hooks of the person's moved ([`moved`]): which ones, and
/// the step that makes Codex run them again. `None` when none moved. Their
/// records of trust are left alone: trust is the person's to give.
pub fn moved_note(spec: &HookSpec, moved: &[String]) -> Option<String> {
    let (count, them, are) = match moved.len() {
        0 => return None,
        1 => ("A".to_string(), "it", "it is"),
        more => (more.to_string(), "them", "they are"),
    };
    Some(format!(
        "{count} {} hook{} of your own moved to a new place in ~/{}: {}. {} trusts a hook \
         by its place and skips {them} until {are} trusted there. Run `/hooks` inside {} and \
         trust {them} again.",
        spec.event,
        if moved.len() == 1 { "" } else { "s" },
        spec.file,
        moved.join(", "),
        spec.product,
        spec.product,
    ))
}

/// A group with no hook in it. Codex counts it when it numbers the groups
/// (measured on Codex CLI 0.167.2: behind `{"hooks": []}` the next hook is
/// listed at group 1), and runs nothing for it. It holds a place that a hook
/// of ours left, so the person's hooks behind it keep theirs.
fn empty_group() -> Value {
    json!({"hooks": []})
}

/// Take the empty groups ([`empty_group`]) off the end of the list. Nothing
/// sits behind them, so no hook changes its place.
fn trim_empty_groups(groups: &mut Vec<Value>) {
    while groups.last() == Some(&empty_group()) {
        groups.pop();
    }
}

/// PURE: take every hook of ours out of Codex's file, leaving the person's
/// hooks at the places Codex trusts them by. A group that held only hooks of
/// ours becomes an empty group ([`empty_group`]) instead of going, so the
/// groups behind it are not renumbered. Returns the settings and how many
/// hooks came out.
///
/// A hook of ours that shares a group with the person's still moves the
/// person's hooks behind it inside that group: a group cannot hold an empty
/// hook. [`moved`] names those.
fn vacate(mut settings: Value, event: &str) -> (Value, usize) {
    let Some(groups) = settings
        .get_mut("hooks")
        .and_then(|hooks| hooks.get_mut(event))
        .and_then(Value::as_array_mut)
    else {
        return (settings, 0);
    };
    let mut removed = 0usize;
    for group in groups.iter_mut() {
        let Some(list) = group.get_mut("hooks").and_then(Value::as_array_mut) else {
            continue;
        };
        let before = list.len();
        list.retain(|hook| hook::read_hook_line(hook).is_none());
        let gone = before - list.len();
        removed += gone;
        if gone > 0 && list.is_empty() {
            *group = empty_group();
        }
    }
    if removed > 0 {
        trim_empty_groups(groups);
    }
    (settings, removed)
}

/// PURE: put the hook into the agent's settings, leaving one entry of ours.
///
/// A group that holds only our hook is replaced where it sits, so a re-run
/// moves nothing: Codex keys its trust by position, the person's hooks
/// included. Our hook inside a group it shares with another is taken out of
/// that group, because the group's matcher is the person's and ours has none.
/// In Codex's file a second group of ours becomes an empty group, and with no
/// group of ours to replace the entry takes the first empty group a
/// disconnect left ([`vacate`]): either way no hook of the person's changes
/// its place. Otherwise the entry goes at the end, behind every hook that is
/// already there. Every other key, group and hook stays as it was.
pub fn merge(settings: Value, spec: &HookSpec, command: &str) -> Result<Value, String> {
    if spec.host == Host::Cursor {
        return merge_flat(settings, spec, command);
    }
    let mut settings = match settings {
        Value::Null => json!({}),
        other => other,
    };
    let root = settings
        .as_object_mut()
        .ok_or("its top level is not a JSON object")?;
    let container = spec.container();
    let hooks = root
        .entry(container)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| format!("`{container}` is not a JSON object"))?;
    // Antigravity skips a hook whose `enabled` is false. A person who runs
    // `agents connect` asks for the guard to run: the switch comes out.
    if spec.host == Host::Antigravity && hooks.get("enabled") == Some(&Value::Bool(false)) {
        hooks.remove("enabled");
    }
    let groups = hooks
        .entry(spec.event)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| format!("`{container}.{}` is not a list", spec.event))?;
    let entry = spec.entry(command);
    let keep_places = spec.host == Host::Codex;
    let mut placed = false;
    groups.retain_mut(|group| {
        let (any, all) = ours_in(group);
        if !any {
            return true;
        }
        if all && !placed {
            *group = entry.clone();
            placed = true;
            return true;
        }
        if all && keep_places {
            *group = empty_group();
            return true;
        }
        match group.get_mut("hooks").and_then(Value::as_array_mut) {
            Some(list) => {
                list.retain(|hook| hook::read_hook_line(hook).is_none());
                !list.is_empty()
            }
            None => true,
        }
    });
    if !placed && keep_places {
        if let Some(empty) = groups.iter_mut().find(|group| **group == empty_group()) {
            *empty = entry.clone();
            placed = true;
        }
    }
    if !placed {
        groups.push(entry);
    }
    if keep_places {
        trim_empty_groups(groups);
    }
    Ok(settings)
}

/// Why Cursor's hooks file under `home` no longer holds the guard as
/// `agents connect cursor` wrote it, when it still holds some of it: an
/// event without the entry, an entry changed (`failClosed` turned off, another
/// timeout, another mode), a `version` Cursor does not read, or a file that
/// is no longer JSON. `None` when it is whole, and when no entry of ours is
/// left at all.
///
/// The hook asks this on every Cursor call it is started for, because
/// Cursor's file edits are not screened (it has no hook before an edit): an
/// agent can take one event's entry out of the file with an edit, and the
/// entries left behind are the guard's only chance to see it. With every
/// entry gone Cursor starts no hook of ours, so there is no call to refuse.
/// The program is not looked at here: it is the one asking.
pub fn cursor_wiring_lost(home: &Path) -> Option<String> {
    let binary = std::env::current_exe().ok();
    cursor_wiring_lost_for(home, binary.as_deref(), std::env::var_os("PATH").as_deref())
}

/// [`cursor_wiring_lost`], with this program (`binary`, when it is known)
/// and the `PATH` a bare program name is looked up on handed in.
fn cursor_wiring_lost_for(
    home: &Path,
    binary: Option<&Path>,
    path_env: Option<&OsStr>,
) -> Option<String> {
    let file = CURSOR.path(home);
    let events = CURSOR.events().collect::<Vec<_>>().join(", ");
    let state = state_with(home, &CURSOR, |_| hook::ProgramFact::Executable);
    let state = match binary {
        Some(binary) => cursor_runs_this(home, state, binary, path_env),
        None => state,
    };
    match state {
        HookState::Off(reason @ Reason::OtherProgram { .. }) => {
            Some(format!("{}: {}", file.display(), reason.why(&CURSOR)))
        }
        HookState::Off(Reason::Altered) => Some(format!(
            "{} no longer lists the InnerWarden entry, as `innerwarden agents connect cursor` \
             wrote it, under each of {events}",
            file.display()
        )),
        HookState::Unreadable => Some(format!(
            "{} can no longer be read as Cursor's hooks",
            file.display()
        )),
        _ => None,
    }
}

/// Whether Cursor reads hooks from a file with this `version`: a positive
/// whole number, as its documentation requires.
fn cursor_version_ok(settings: &Value) -> bool {
    settings
        .get("version")
        .and_then(Value::as_u64)
        .is_some_and(|version| version > 0)
}

/// PURE: [`merge`] for Cursor's flat lists. Under each event every hook of
/// ours comes out and one entry goes where the first of them was, else at
/// the end: no hook of the person's moves, and a re-run writes nothing. A
/// `version` Cursor would not read becomes 1. Every other key and hook stays
/// as it was.
fn merge_flat(settings: Value, spec: &HookSpec, command: &str) -> Result<Value, String> {
    let mut settings = match settings {
        Value::Null => json!({}),
        other => other,
    };
    let version_ok = cursor_version_ok(&settings);
    let root = settings
        .as_object_mut()
        .ok_or("its top level is not a JSON object")?;
    if !version_ok {
        root.insert("version".to_string(), json!(1));
    }
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or("`hooks` is not a JSON object")?;
    let entry = spec.entry(command);
    for event in spec.events() {
        let list = hooks
            .entry(event)
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or_else(|| format!("`hooks.{event}` is not a list"))?;
        let first = list
            .iter()
            .position(|hook| hook::read_hook_line(hook).is_some());
        list.retain(|hook| hook::read_hook_line(hook).is_none());
        match first {
            Some(at) => list.insert(at, entry.clone()),
            None => list.push(entry.clone()),
        }
    }
    Ok(settings)
}

/// PURE: take every hook of ours out of Cursor's flat lists. A list that
/// held only hooks of ours goes; every other key and hook stays.
fn vacate_flat(mut settings: Value, spec: &HookSpec) -> (Value, usize) {
    let Some(hooks) = settings.get_mut("hooks").and_then(Value::as_object_mut) else {
        return (settings, 0);
    };
    let mut removed = 0usize;
    for event in spec.events() {
        let Some(list) = hooks.get_mut(event).and_then(Value::as_array_mut) else {
            continue;
        };
        let before = list.len();
        list.retain(|hook| hook::read_hook_line(hook).is_none());
        let gone = before - list.len();
        removed += gone;
        if gone > 0 && list.is_empty() {
            hooks.remove(event);
        }
    }
    (settings, removed)
}

/// PURE: take every hook of ours out of Antigravity's file. Under the
/// guard's own name a group left with no hook goes, an event left with no
/// group goes, and the name goes once no event is left under it. Every other
/// name, and what the person added under ours, stays.
fn vacate_named(mut settings: Value, spec: &HookSpec) -> (Value, usize) {
    let container = spec.container();
    let Some(hooks) = settings.get_mut(container).and_then(Value::as_object_mut) else {
        return (settings, 0);
    };
    let mut removed = 0usize;
    if let Some(groups) = hooks.get_mut(spec.event).and_then(Value::as_array_mut) {
        groups.retain_mut(|group| {
            let Some(list) = group.get_mut("hooks").and_then(Value::as_array_mut) else {
                return true;
            };
            let before = list.len();
            list.retain(|hook| hook::read_hook_line(hook).is_none());
            removed += before - list.len();
            before == list.len() || !list.is_empty()
        });
        if groups.is_empty() && removed > 0 {
            hooks.remove(spec.event);
        }
    }
    let events_left = hooks.keys().any(|key| key != "enabled");
    if removed > 0 && !events_left {
        if let Some(root) = settings.as_object_mut() {
            root.remove(container);
        }
    }
    (settings, removed)
}

/// What to write for Antigravity's file going from `settings` (read from
/// `before`) to `merged`: `Some(body)`, or `None` to remove the file.
///
/// Only the guard's member changes, so it is taken out and put back as text
/// ([`crate::antigravity_hook::splice_in`]): every byte of the person's
/// stays where it was, and a disconnect gives back the file a connect found,
/// to the byte, while our member is still the text connect wrote. A file
/// connect created is removed by the disconnect that empties it, and so is
/// one that was blank or held only `{}` before (they read the same, and
/// Antigravity reads no hook from any of them): those do not come back.
/// Whenever the text is not what this wrote (the file was reformatted), or
/// the result does not read as `merged`, the file is written whole in the
/// person's key order, as for the other agents: then not to the byte.
fn antigravity_body(
    before: Option<&[u8]>,
    settings: &Value,
    merged: &Value,
) -> Result<Option<String>, String> {
    use crate::antigravity_hook::{fresh_file, splice_in, splice_out, HOOK_NAME};
    let whole = || crate::json_order::pretty_in_order(before, merged).map(Some);
    let text = match before.map(std::str::from_utf8) {
        None => None,
        Some(Ok(text)) if text.trim().is_empty() => None,
        Some(Ok(text)) => Some(text),
        Some(Err(_)) => return whole(),
    };
    let reads_as = |body: &str, want: &Value| {
        serde_json::from_str::<Value>(body).is_ok_and(|read| &read == want)
    };
    let without = |value: &Value| {
        let mut value = value.clone();
        if let Some(root) = value.as_object_mut() {
            root.remove(HOOK_NAME);
        }
        value
    };
    let old = settings.get(HOOK_NAME);
    // The file as it would be without our member, to the byte.
    let base = match (text, old) {
        (None, _) => None,
        (Some(text), None) => Some(text.to_string()),
        (Some(text), Some(old)) => match splice_out(text, old) {
            Some(base) => Some(base),
            None => return whole(),
        },
    };
    let rest = without(settings);
    if base.as_deref().is_some_and(|base| !reads_as(base, &rest)) || without(merged) != rest {
        return whole();
    }
    match merged.get(HOOK_NAME) {
        None => match (text, old) {
            (Some(text), Some(old)) if fresh_file(old).as_deref() == Some(text) => Ok(None),
            _ => match base {
                Some(base) => Ok(Some(base)),
                None => whole(),
            },
        },
        Some(new) => {
            let body = match base {
                Some(base) => splice_in(&base, new),
                None => fresh_file(new),
            };
            match body {
                Some(body) if reads_as(&body, merged) => Ok(Some(body)),
                _ => whole(),
            }
        }
    }
}

/// Antigravity's hooks file must be a file of its own, not a link. Its
/// connect and disconnect write by text and remove the file a disconnect
/// empties: through a link that would be another file's bytes, or the file
/// the link points to removed. The read already refuses a link (it opens
/// without following one, "too many levels of symbolic links"); this says
/// so in words, with what to do, before anything is read or written.
fn refuse_a_link(path: &Path, spec: &HookSpec) -> Result<(), String> {
    if spec.host != Host::Antigravity {
        return Ok(());
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => Err(format!(
            "{} is a link; InnerWarden does not write {}'s hooks through one. Put the file it \
             points to in its place, then run this again",
            path.display(),
            spec.product
        )),
        _ => Ok(()),
    }
}

/// Write `body` to `path` (or remove the file, for `None`), refused when
/// the file changed since it was read as `before`.
fn commit(path: &Path, before: Option<&[u8]>, body: Option<String>) -> Result<(), String> {
    match (body, before) {
        (Some(body), _) => file_update::replace_if_unchanged(path, before, body.as_bytes()),
        (None, Some(before)) => file_update::remove_if_unchanged(path, before),
        (None, None) => Ok(()),
    }
}

/// Read the settings file as JSON. A missing or blank file is `Null`: there
/// is nothing in it to keep.
fn parse(path: &Path, bytes: Option<&[u8]>) -> Result<Value, String> {
    let Some(bytes) = bytes else {
        return Ok(Value::Null);
    };
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(bytes)
        .map_err(|error| format!("{} is not valid JSON: {error}", path.display()))
}

/// Write the hook into the agent's file under `home`. Returns whether the
/// file changed: a second run with the same mode writes nothing.
///
/// A file that is there and cannot be read as settings is an error and is left
/// alone. The write is refused when the file changed since it was read.
pub fn install(
    home: &Path,
    spec: &HookSpec,
    guard_bin: &Path,
    block_review: bool,
    monitor: bool,
) -> Result<bool, String> {
    install_noting_moved(home, spec, guard_bin, block_review, monitor).map(|(wrote, _)| wrote)
}

/// [`install`], which also names the hooks of the person's that the write
/// moved ([`moved`]).
fn install_noting_moved(
    home: &Path,
    spec: &HookSpec,
    guard_bin: &Path,
    block_review: bool,
    monitor: bool,
) -> Result<(bool, Vec<String>), String> {
    let path = spec.path(home);
    refuse_a_link(&path, spec)?;
    let before = file_update::read_config(&path)?;
    let settings = parse(&path, before.as_deref())?;
    let command = spec.command(guard_bin, block_review, monitor);
    let merged = merge(settings.clone(), spec, &command)
        .map_err(|why| format!("{}: {why}", path.display()))?;
    if merged == settings {
        return Ok((false, Vec::new()));
    }
    let body = match spec.host {
        Host::Antigravity => antigravity_body(before.as_deref(), &settings, &merged)?,
        _ => Some(crate::json_order::pretty_in_order(
            before.as_deref(),
            &merged,
        )?),
    };
    commit(&path, before.as_deref(), body)?;
    Ok((true, moved(&settings, &merged, spec)))
}

/// Take every InnerWarden hook out of the agent's file under `home`, and the
/// trust Codex held for it. Returns how many hooks were removed. A missing
/// file, or one with no hook of ours, is 0 and nothing is written.
pub fn uninstall(home: &Path, spec: &HookSpec) -> Result<usize, String> {
    uninstall_noting_moved(home, spec).map(|(removed, _)| removed)
}

/// [`uninstall`], which also names the hooks of the person's that the removal
/// moved ([`moved`]).
pub fn uninstall_noting_moved(
    home: &Path,
    spec: &HookSpec,
) -> Result<(usize, Vec<String>), String> {
    let path = spec.path(home);
    refuse_a_link(&path, spec)?;
    let before = file_update::read_config(&path)?;
    let settings = parse(&path, before.as_deref())?;
    let ours = found(&settings, spec);
    // Codex trusts a hook by its place, so its file keeps the places.
    let (cleaned, removed) = match spec.host {
        Host::Codex => vacate(settings.clone(), spec.event),
        Host::Gemini => hook::remove_iwguard_hooks_for_event(settings.clone(), spec.event),
        Host::Cursor => vacate_flat(settings.clone(), spec),
        Host::Antigravity => vacate_named(settings.clone(), spec),
    };
    if removed == 0 {
        return Ok((0, Vec::new()));
    }
    let body = match spec.host {
        Host::Antigravity => antigravity_body(before.as_deref(), &settings, &cleaned)?,
        _ => Some(crate::json_order::pretty_in_order(
            before.as_deref(),
            &cleaned,
        )?),
    };
    commit(&path, before.as_deref(), body)?;
    if spec.host == Host::Codex {
        forget_trust(home, &path, &ours);
    }
    Ok((removed, moved(&settings, &cleaned, spec)))
}

/// Remove the records of trust for hooks that were just removed. Best effort:
/// a record left behind names a hook that is gone, and trusts nothing.
fn forget_trust(home: &Path, file: &Path, removed: &[Found]) {
    let config_path = home.join(CODEX_CONFIG);
    let Ok(Some(before)) = file_update::read_config(&config_path) else {
        return;
    };
    let Some(mut config) = std::str::from_utf8(&before)
        .ok()
        .and_then(|text| text.parse::<DocumentMut>().ok())
    else {
        return;
    };
    let mut changed = false;
    for hook in removed {
        let Some(timeout) = hook.timeout else {
            continue;
        };
        changed |= codex_trust::forget(
            &mut config,
            Place {
                file,
                group: hook.group,
                index: hook.index,
                command: &hook.command,
                timeout,
            },
        );
    }
    if changed {
        let _ = file_update::replace_if_unchanged(
            &config_path,
            Some(&before),
            config.to_string().as_bytes(),
        );
    }
}

/// A Codex or Gemini hook that would outlive the binary it runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeftBehind {
    pub spec: &'static HookSpec,
    /// The file was read and holds the hook. `false` for a file that could
    /// not be read as settings: nothing there rules the hook out.
    pub seen: bool,
}

/// The Codex and Gemini hooks under `home` that still run `binary`. Asked by
/// `uninstall` when its disconnect failed, before the binary goes: Gemini
/// refuses every tool call while its hook names a program that is gone.
///
/// A file that cannot be opened is listed, and so is one that is not valid
/// settings when its text holds an InnerWarden hook line. Neither rules the
/// hook out: which copy such a line runs cannot be told from the text.
pub fn left_behind(home: &Path, binary: &Path) -> Vec<LeftBehind> {
    [&CODEX, &GEMINI, &CURSOR, &ANTIGRAVITY]
        .into_iter()
        .filter_map(|spec| {
            let seen = still_runs(&spec.path(home), spec, binary)?;
            Some(LeftBehind { spec, seen })
        })
        .collect()
}

/// `Some(true)` when the file holds an InnerWarden hook whose program is
/// `binary`, `Some(false)` when the file does not read well enough to rule
/// one out, `None` when it holds none.
fn still_runs(path: &Path, spec: &HookSpec, binary: &Path) -> Option<bool> {
    let bytes = match file_update::read_config(path) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return None,
        Err(_) => return Some(false),
    };
    match parse(path, Some(bytes.as_slice())) {
        Ok(settings) => found(&settings, spec)
            .iter()
            .any(|hook| is_program(&hook.line.program, binary))
            .then_some(true),
        Err(_) => holds_a_hook_line(&bytes).then_some(false),
    }
}

/// Whether a hook's program is `binary`, as written or once both are
/// resolved: a link to the binary runs it.
fn is_program(program: &str, binary: &Path) -> bool {
    let program = Path::new(program);
    program == binary
        || matches!(
            (program.canonicalize(), binary.canonicalize()),
            (Ok(program), Ok(binary)) if program == binary
        )
}

/// Whether text that is not valid settings holds a hook line as
/// [`HookSpec::command`] writes it: the program in quotes, which the JSON
/// string escapes, then `hook`; or the fail-closed script, which starts the
/// guard as its quoted `$0`, then `hook`.
fn holds_a_hook_line(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    ["innerwarden", "innerwarden.exe", "iw", "iw.exe", "'\\\"$0"]
        .iter()
        .any(|name| text.contains(&format!("{name}\\\" hook")))
}

/// What `uninstall` says when it stops for [`left_behind`]: that it stopped,
/// then for each hook the file, what the hook costs once the binary is gone,
/// and the step.
pub fn left_behind_lines(left: &[LeftBehind]) -> Vec<String> {
    let mut lines = vec![
        "disconnect reported a problem, and a hook would outlive the binary.".to_string(),
        "The configuration and the binary were left in place.".to_string(),
    ];
    for hook in left {
        let spec = hook.spec;
        lines.push(if hook.seen {
            format!(
                "~/{} still holds a {} hook that runs this binary.",
                spec.file, spec.event
            )
        } else {
            format!(
                "~/{} could not be read, and a {} hook in it may still run this binary.",
                spec.file, spec.event
            )
        });
        lines.push(
            match spec.host {
                Host::Codex => {
                    "Codex would start a hook whose program is gone before every tool call: \
                     in enforce mode it refuses every call, in monitor mode it runs them \
                     unscreened."
                }
                Host::Gemini => {
                    "Gemini would start a hook whose program is gone before every tool call: \
                     in enforce mode it refuses every call, in monitor mode it runs them \
                     unscreened on Linux and macOS and refuses them on Windows."
                }
                Host::Cursor => {
                    "Cursor would start a hook whose program is gone before every shell \
                     command, MCP call and file read of its agent: in enforce mode \
                     (`failClosed`) it refuses every one, in monitor mode it runs them \
                     unscreened."
                }
                Host::Antigravity => {
                    "Antigravity would start a hook whose program is gone before every tool \
                     call: in enforce mode the hook line answers each with a deny on Linux and \
                     macOS; in monitor mode, and on Windows, what Antigravity does with it is \
                     not measured."
                }
            }
            .to_string(),
        );
        lines.push(format!(
            "Take the innerwarden hook out of that file, or run `innerwarden agents \
             disconnect {}` once the file can be read and written.",
            spec.agent
        ));
    }
    lines
}

/// Where an agent's hook stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookState {
    /// No InnerWarden hook in the agent's file, or no file.
    Absent,
    /// The file is there and could not be read as settings.
    Unreadable,
    /// The agent runs it, as far as anything readable from here says.
    On { monitor: bool, block_review: bool },
    /// It is in the file, and the agent does not run it as installed.
    Off(Reason),
}

impl HookState {
    /// The hook screens this agent's tool calls.
    pub fn is_on(&self) -> bool {
        matches!(self, Self::On { .. })
    }

    /// A hook of ours is in the file, whether or not the agent runs it.
    pub fn installed(&self) -> bool {
        matches!(self, Self::On { .. } | Self::Off(_))
    }
}

/// Why a hook that is in the file is not reported on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// It is not the entry `agents connect` writes: a matcher, another
    /// timeout, another agent's id, a second copy, or a group it shares.
    Altered,
    /// The program it runs is not there. `clause` says so; `refuses` says the
    /// agent refuses every tool call while it is gone, as Gemini does with
    /// any hook line and Claude Code and Codex do with the fail-closed one.
    Broken { clause: String, refuses: bool },
    /// The program it runs could not be looked at. `clause` says so;
    /// `refuses` as for [`Reason::Broken`], if the program does not start.
    Unchecked { clause: String, refuses: bool },
    /// Codex's config says Codex skips it.
    Codex(Skip),
    /// `CODEX_HOME` names another folder, so a Codex started from here does
    /// not read the file the hook is in. Holds that folder.
    CodexElsewhere(PathBuf),
    /// Gemini's settings switch every hook off.
    GeminiHooksOff,
    /// Gemini's settings disable this hook by name.
    GeminiHookDisabled,
    /// Antigravity's file sets the guard's `enabled` to false.
    AntigravityDisabled,
    /// Cursor's entries are the shape `agents connect` writes, and run
    /// another program than this innerwarden: an edit of the file (Cursor
    /// screens none) can point them anywhere. Holds that program and this
    /// one.
    OtherProgram { program: String, ours: String },
}

impl Reason {
    /// Why the hook is not on, to follow "installed, but ".
    fn why(&self, spec: &HookSpec) -> String {
        match self {
            Self::Altered => format!(
                "it is not the entry `agents connect` writes, so {} may not run it for every tool",
                spec.product
            ),
            Self::Broken { clause, .. } | Self::Unchecked { clause, .. } => clause.clone(),
            Self::Codex(skip) => format!("Codex skips it: {}", skip.words()),
            Self::CodexElsewhere(folder) => format!(
                "Codex does not read it: {CODEX_HOME_VAR} is set to {}",
                folder.display()
            ),
            Self::GeminiHooksOff => {
                "Gemini skips it: hooks are switched off (`hooksConfig.enabled` is false)"
                    .to_string()
            }
            Self::GeminiHookDisabled => {
                "Gemini skips it: it is listed under `hooksConfig.disabled`".to_string()
            }
            Self::OtherProgram { program, ours } => format!(
                "it runs another program ({program}), not this innerwarden ({ours}), so no call \
                 of {} reaches the guard",
                spec.product
            ),
            Self::AntigravityDisabled => format!(
                "Antigravity skips it: its `enabled` is false in ~/{}",
                spec.file
            ),
        }
    }

    /// The one step that turns the hook on.
    fn step(&self, spec: &HookSpec) -> String {
        match self {
            Self::Altered
            | Self::AntigravityDisabled
            | Self::OtherProgram { .. }
            | Self::Broken { .. }
            | Self::Unchecked { .. }
            | Self::Codex(Skip::NotTrusted | Skip::Changed) => {
                format!("Run: innerwarden agents connect {}", spec.agent)
            }
            Self::Codex(Skip::SwitchedOff) => SWITCH_ON_STEP.to_string(),
            Self::CodexElsewhere(_) => OTHER_HOME_STEP.to_string(),
            Self::Codex(Skip::HooksOff) => {
                "Take `hooks = false` and `codex_hooks = false` out of [features] in \
                 ~/.codex/config.toml"
                    .to_string()
            }
            Self::GeminiHooksOff => "Set it to true in ~/.gemini/settings.json".to_string(),
            Self::GeminiHookDisabled => {
                "Take it out of that list in ~/.gemini/settings.json".to_string()
            }
        }
    }
}

/// The mode a hook line runs in, as the listing spells it.
fn mode_word(monitor: bool) -> &'static str {
    if monitor {
        "monitor"
    } else {
        "enforce"
    }
}

/// The one step for a settings file that could not be read. The file comes
/// first: `agents connect` writes nothing into a file it cannot read.
fn unreadable_step(spec: &HookSpec) -> String {
    format!(
        "Fix ~/{} or move it aside, then run `innerwarden agents connect {}`",
        spec.file, spec.agent
    )
}

/// One line that says where the hook stands and, when it is not on, the one
/// step that turns it on. The word "on" is printed for [`HookState::On`] only.
pub fn state_line(spec: &HookSpec, state: &HookState) -> String {
    match state {
        HookState::Absent => format!(
            "{} hook: not installed. Run: innerwarden agents connect {}",
            spec.event, spec.agent
        ),
        HookState::Unreadable => format!(
            "{} hook: unknown, ~/{} could not be read. {}",
            spec.event,
            spec.file,
            unreadable_step(spec)
        ),
        HookState::On { monitor, .. } => {
            format!("{} hook: on ({})", spec.event, mode_word(*monitor))
        }
        HookState::Off(reason) => format!(
            "{} hook: installed, but {}. {}",
            spec.event,
            reason.why(spec),
            reason.step(spec)
        ),
    }
}

/// A hook that does not screen, in the two parts `status` prints: what is
/// wrong, to follow "Its ", and the one thing to try. `None` for a hook that
/// is on.
pub fn not_on(spec: &HookSpec, state: &HookState) -> Option<(String, String)> {
    let connect = format!("innerwarden agents connect {}", spec.agent);
    match state {
        HookState::On { .. } => None,
        // Cursor's file edits are not screened: an edit can take every entry
        // out at once, and the guard never runs again to see it.
        HookState::Absent if spec.host == Host::Cursor => Some((
            format!(
                "hooks are not in ~/{} (removed, or never connected; an edit of that file \
                 by the agent can take them out, since Cursor screens no edit)",
                spec.file
            ),
            connect,
        )),
        HookState::Absent => Some((format!("{} hook is not installed", spec.event), connect)),
        HookState::Unreadable => Some((
            format!(
                "{} hook is unknown: ~/{} could not be read",
                spec.event, spec.file
            ),
            unreadable_step(spec),
        )),
        HookState::Off(reason) => {
            let step = reason.step(spec);
            Some((
                format!("{} hook is installed, but {}", spec.event, reason.why(spec)),
                step.strip_prefix("Run: ").unwrap_or(&step).to_string(),
            ))
        }
    }
}

/// What a hook whose program is the trouble does to the agent's tool calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stall {
    /// The program is not there: the agent refuses every tool call.
    Refuses,
    /// The program could not be looked at: the agent refuses every tool call
    /// if it does not start.
    MayRefuse,
}

/// Whether the agent refuses its tool calls while the hook stands as `state`.
///
/// Read from each agent's hook runner: Gemini CLI (0.30.0 and later) refuses
/// a call when its hook exits with any code but 0 and 1 and says something,
/// as a shell does for a program that is not there; Claude Code and Codex run
/// the tool, unless the line is the fail-closed one, which turns the shell's
/// 127 into a refusal. The entry carries no matcher, so every tool call is
/// refused.
pub fn stall(_spec: &HookSpec, state: &HookState) -> Option<Stall> {
    match state {
        HookState::Off(Reason::Broken { refuses: true, .. }) => Some(Stall::Refuses),
        HookState::Off(Reason::Unchecked { refuses: true, .. }) => Some(Stall::MayRefuse),
        _ => None,
    }
}

/// Codex's config under `home`, `None` when it is missing or does not parse.
fn codex_config(home: &Path) -> Option<DocumentMut> {
    let bytes = file_update::read_config(&home.join(CODEX_CONFIG)).ok()??;
    std::str::from_utf8(&bytes).ok()?.parse().ok()
}

/// Read where the agent's hook stands under `home`. Nothing is started and
/// nothing is written. `path_env` is the `PATH` a bare program name is looked
/// up on.
pub fn state(home: &Path, spec: &HookSpec, path_env: Option<&OsStr>) -> HookState {
    let state = state_with(home, spec, |program| {
        agents_ops::program_fact(program, path_env)
    });
    let state = where_codex_reads(home, spec, state);
    match std::env::current_exe() {
        Ok(binary) if spec.host == Host::Cursor => cursor_runs_this(home, state, &binary, path_env),
        _ => state,
    }
}

/// Cursor's `state`, once the program its entries run is compared with
/// `binary` (this innerwarden), as written or resolved (a link to it runs
/// it, a bare name is looked up on `path_env`). Cursor's file edits are not
/// screened, so an edit can keep every entry in the shape `agents connect`
/// writes and point it at another program, and that program then answers
/// every call: the guard never runs to see it. `status` and `agents` are
/// where it shows. A state that is not installed, or already altered, stays
/// what it was.
fn cursor_runs_this(
    home: &Path,
    state: HookState,
    binary: &Path,
    path_env: Option<&OsStr>,
) -> HookState {
    if !state.installed() || state == HookState::Off(Reason::Altered) {
        return state;
    }
    let path = CURSOR.path(home);
    let Ok(Some(bytes)) = file_update::read_config(&path) else {
        return state;
    };
    let Ok(settings) = parse(&path, Some(bytes.as_slice())) else {
        return state;
    };
    let Some(first) = found(&settings, &CURSOR).into_iter().next() else {
        return state;
    };
    if guard_programs(home, binary)
        .iter()
        .any(|ours| runs_binary(&first.line.program, Path::new(ours), path_env))
    {
        return state;
    }
    HookState::Off(Reason::OtherProgram {
        program: first.line.program,
        ours: binary.display().to_string(),
    })
}

/// The programs this machine runs as its guard: `binary` (the one asking)
/// and every program Claude Code's, Codex's and Gemini's hooks of ours run.
/// `status` may be started from another copy of the guard than the one
/// `agents connect` wired (an npm install beside a package, say): a Cursor
/// hook that runs any of them is ours. Cursor's own files are not counted:
/// its agent can edit them unscreened.
fn guard_programs(home: &Path, binary: &Path) -> Vec<String> {
    let mut programs = vec![binary.display().to_string()];
    let claude = home.join(".claude/settings.json");
    if let Some(settings) = file_update::read_config(&claude)
        .ok()
        .flatten()
        .and_then(|body| serde_json::from_slice::<Value>(&body).ok())
    {
        programs.extend(hook::effective_iwguard_hook_programs(&settings));
    }
    for spec in [&CODEX, &GEMINI, &ANTIGRAVITY] {
        let path = spec.path(home);
        if let Ok(settings) = parse(
            &path,
            file_update::read_config(&path).ok().flatten().as_deref(),
        ) {
            programs.extend(
                found(&settings, spec)
                    .into_iter()
                    .map(|hook| hook.line.program),
            );
        }
    }
    programs
}

/// Whether a hook line's `program` is `binary`: as written, through a link,
/// or, for a bare name, the first file of that name on `path_env`.
fn runs_binary(program: &str, binary: &Path, path_env: Option<&OsStr>) -> bool {
    if Path::new(program).components().count() > 1 {
        return is_program(program, binary);
    }
    path_env
        .map(std::env::split_paths)
        .into_iter()
        .flatten()
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
        .is_some_and(|found| is_program(&found.to_string_lossy(), binary))
}

/// `state`, once the folder Codex reads is taken into account.
///
/// The hook and its trust are read under `<home>/.codex`. With `CODEX_HOME`
/// naming another folder, a Codex started from this environment opens that
/// one, so a hook that reads "on" here runs for no call. Asked only for the
/// home this process runs under, as [`codex_to_ask`] is: the variable says
/// nothing about another home.
fn where_codex_reads(home: &Path, spec: &HookSpec, state: HookState) -> HookState {
    if spec.host != Host::Codex || codex_to_ask(home).is_none() {
        return state;
    }
    read_elsewhere(home, std::env::var_os(CODEX_HOME_VAR).as_deref(), state)
}

/// A hook that is in the file is off when `codex_home` (the value of
/// `CODEX_HOME`) names a folder other than `<home>/.codex`. A hook that is
/// not in the file stays what it was: there is nothing to switch off.
fn read_elsewhere(home: &Path, codex_home: Option<&OsStr>, state: HookState) -> HookState {
    match other_codex_home(home, codex_home) {
        Some(folder) if state.installed() => HookState::Off(Reason::CodexElsewhere(folder)),
        _ => state,
    }
}

/// The folder `codex_home` names, when it is not `<home>/.codex` under either
/// spelling. Unset and empty are both "not set".
fn other_codex_home(home: &Path, codex_home: Option<&OsStr>) -> Option<PathBuf> {
    let named = PathBuf::from(codex_home.filter(|value| !value.is_empty())?);
    let ours = home.join(".codex");
    let same = named == ours
        || matches!(
            (named.canonicalize(), ours.canonicalize()),
            (Ok(named), Ok(ours)) if named == ours
        );
    (!same).then_some(named)
}

/// [`state`], with the look at the hook's program handed in.
fn state_with(home: &Path, spec: &HookSpec, fact: impl Fn(&str) -> hook::ProgramFact) -> HookState {
    let path = spec.path(home);
    let settings = match file_update::read_config(&path) {
        Ok(bytes) => match parse(&path, bytes.as_deref()) {
            Ok(Value::Null) => return HookState::Absent,
            Ok(settings) => settings,
            Err(_) => return HookState::Unreadable,
        },
        Err(_) => return HookState::Unreadable,
    };
    let config = match spec.host {
        Host::Codex => codex_config(home),
        Host::Gemini | Host::Cursor | Host::Antigravity => None,
    };
    judge(&settings, spec, &path, config.as_ref(), fact)
}

/// PURE: where the hook stands, from the agent's settings, Codex's config and
/// what the caller found when it looked for the hook's program.
///
/// Every doubt is "off". A hook reported off that runs costs one more
/// `agents connect`. A hook reported on that the agent skips costs every tool
/// call it was meant to screen. That is also why a program that could not be
/// looked at is not "on" here, where for Claude Code's hook it is: these two
/// agents give no other sign that a hook was skipped.
fn judge(
    settings: &Value,
    spec: &HookSpec,
    file: &Path,
    codex_config: Option<&DocumentMut>,
    fact: impl Fn(&str) -> hook::ProgramFact,
) -> HookState {
    let ours = found(settings, spec);
    if spec.host == Host::Cursor {
        return judge_flat(settings, spec, &ours, fact);
    }
    let [only] = ours.as_slice() else {
        return if ours.is_empty() {
            HookState::Absent
        } else {
            HookState::Off(Reason::Altered)
        };
    };
    // The entry `agents connect` writes for this program and mode. Anything
    // else in the group (a matcher, another timeout, a second hook) changes
    // which calls reach the guard or how long it is given.
    let command = spec.command(
        Path::new(&only.line.program),
        only.line.block_review,
        only.line.monitor,
    );
    if current(&settings[spec.container()][spec.event][only.group]) != spec.entry(&command) {
        return HookState::Off(Reason::Altered);
    }
    // Gemini reads its switches before it starts a hook. One that is set
    // decides, whatever the hook's program is: a hook Gemini skips is never
    // started, so its program cannot hold a call up.
    let switched_off = match spec.host {
        Host::Gemini => gemini_switch(settings, &command),
        Host::Antigravity => (settings[spec.container()].get("enabled")
            == Some(&Value::Bool(false)))
        .then_some(Reason::AntigravityDisabled),
        Host::Codex | Host::Cursor => None,
    };
    if let Some(reason) = switched_off {
        return HookState::Off(reason);
    }
    // A program that does not start is a refusal through the fail-closed
    // line, and on Gemini through a plain line too (a monitor line on
    // Windows): Gemini refuses on any exit but 0 and 1. Gemini's fail-open
    // monitor line turns every other end into 1.
    let refuses = only.line.fail_closed || (spec.host == Host::Gemini && !only.line.fail_open);
    match hook::judge_hook_program(&only.line.program, fact(&only.line.program)) {
        hook::HookProgram::Runs => {}
        hook::HookProgram::Broken { problem, .. } => {
            return HookState::Off(Reason::Broken {
                clause: problem,
                refuses,
            })
        }
        hook::HookProgram::Unknown { why, .. } => {
            return HookState::Off(Reason::Unchecked {
                clause: why,
                refuses,
            })
        }
    }
    let skipped = match spec.host {
        Host::Codex => {
            let place = Place {
                file,
                group: only.group,
                index: only.index,
                // The line as the file holds it: Codex trusts the bytes it
                // read, and a 1.6.15 line differs from `command` in its tail.
                command: &only.command,
                timeout: spec.timeout,
            };
            match codex_trust::offline(codex_config, place) {
                Trust::Trusted => None,
                Trust::Skipped(skip) => Some(Reason::Codex(skip)),
            }
        }
        Host::Gemini | Host::Cursor | Host::Antigravity => None,
    };
    match skipped {
        Some(reason) => HookState::Off(reason),
        None => HookState::On {
            monitor: only.line.monitor,
            block_review: only.line.block_review,
        },
    }
}

/// PURE: a group (or Cursor's flat entry) with every hook line in it given
/// today's fail-closed tail ([`hook::with_current_tail`]): a line an earlier
/// version wrote is the entry `agents connect` writes, as long as nothing
/// else in it changed.
fn current(entry: &Value) -> Value {
    fn mend(hook: &mut Value) {
        if let Some(line) = hook.get("command").and_then(Value::as_str) {
            if let std::borrow::Cow::Owned(line) = hook::with_current_tail(line) {
                hook["command"] = Value::String(line);
            }
        }
    }
    let mut entry = entry.clone();
    match entry.get_mut("hooks").and_then(Value::as_array_mut) {
        Some(list) => list.iter_mut().for_each(mend),
        None => mend(&mut entry),
    }
    entry
}

/// PURE: [`judge`] for Cursor. The hook is on only when each of its events
/// lists exactly the entry `agents connect` writes, all for one program and
/// mode, in a file whose `version` Cursor reads, and the program is there.
/// One event without it leaves that kind of call unscreened, so it is not
/// on. Every doubt is "off", as for the others.
fn judge_flat(
    settings: &Value,
    spec: &HookSpec,
    ours: &[Found],
    fact: impl Fn(&str) -> hook::ProgramFact,
) -> HookState {
    let Some(first) = ours.first() else {
        return HookState::Absent;
    };
    let command = spec.command(
        Path::new(&first.line.program),
        first.line.block_review,
        first.line.monitor,
    );
    let expected = spec.entry(&command);
    let each_once = spec.events().all(|event| {
        let mine: Vec<&Found> = ours.iter().filter(|hook| hook.event == event).collect();
        matches!(mine.as_slice(), [only] if current(&settings["hooks"][event][only.group]) == expected)
    });
    if !each_once || !cursor_version_ok(settings) {
        return HookState::Off(Reason::Altered);
    }
    // The enforcing entry carries `failClosed`: Cursor refuses the call when
    // the program does not start. The monitor entry never refuses.
    let refuses = !first.line.monitor;
    match hook::judge_hook_program(&first.line.program, fact(&first.line.program)) {
        hook::HookProgram::Runs => HookState::On {
            monitor: first.line.monitor,
            block_review: first.line.block_review,
        },
        hook::HookProgram::Broken { problem, .. } => HookState::Off(Reason::Broken {
            clause: problem,
            refuses,
        }),
        hook::HookProgram::Unknown { why, .. } => HookState::Off(Reason::Unchecked {
            clause: why,
            refuses,
        }),
    }
}

/// The switch in Gemini's own settings file that turns the hook off, if one
/// is set. A switch in a project's settings is not in this file.
fn gemini_switch(settings: &Value, command: &str) -> Option<Reason> {
    let config = settings.get("hooksConfig")?;
    if config.get("enabled").and_then(Value::as_bool) == Some(false) {
        return Some(Reason::GeminiHooksOff);
    }
    config
        .get("disabled")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_str)
        .any(|name| name == GEMINI_HOOK_NAME || name == command)
        .then_some(Reason::GeminiHookDisabled)
}

/// The Codex to ask for trust when the hook is wired under `home`, `None`
/// when there is none to ask.
///
/// The Codex this process can start serves the home this process runs under.
/// When `home` is another one, that Codex reads other files: it does not list
/// the hook written here and could only say no.
pub fn codex_to_ask(home: &Path) -> Option<Vec<OsString>> {
    let own = hook::home_dir().ok()?;
    let same = own == home
        || matches!(
            (own.canonicalize(), home.canonicalize()),
            (Ok(own), Ok(home)) if own == home
        );
    same.then(|| vec![OsString::from("codex")])
}

/// How `agents connect` left the hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The agent runs it. `changed` when it did not before this run.
    Active { changed: bool },
    /// It is in the file and the agent does not run it. `why` finishes "it is
    /// NOT active: " and `step` is the one thing left for the person to do.
    NotActive { why: String, step: String },
}

/// Install the hook under `home` and establish whether the agent runs it.
///
/// For Codex, `codex` is the program to ask for trust ([`codex_to_ask`]).
/// The person ran `agents connect`, and that is the consent Codex's trust
/// stands for, so Codex is asked on every run: a mode change rewrites the
/// hook line, and Codex stops trusting a line that changed.
pub fn connect(
    home: &Path,
    spec: &HookSpec,
    guard_bin: &Path,
    block_review: bool,
    monitor: bool,
    codex: Option<&[OsString]>,
) -> Result<Outcome, String> {
    connect_noting_write(home, spec, guard_bin, block_review, monitor, codex)
        .map(|connected| connected.outcome)
}

/// What a connect did, beside how it left the hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connected {
    pub outcome: Outcome,
    /// The hooks of the person's that the write moved ([`moved`]).
    pub moved: Vec<String>,
}

impl Connected {
    /// What `agents connect` says under the hook's line, beside the coverage:
    /// hooks of the person's that moved.
    pub fn notes(&self, spec: &HookSpec) -> Vec<String> {
        moved_note(spec, &self.moved).into_iter().collect()
    }
}

/// Why a hook is not active when the program asked said it trusts the hook
/// and Codex's config holds no record of that trust for this line.
const YES_NOT_IN_CONFIG: &str = "the `codex` program answered that it trusts the hook, but \
     ~/.codex/config.toml holds no record of that trust for this hook line";

/// [`connect`], which also says what the run did to the agent's file
/// ([`Connected`]).
pub fn connect_noting_write(
    home: &Path,
    spec: &HookSpec,
    guard_bin: &Path,
    block_review: bool,
    monitor: bool,
    codex: Option<&[OsString]>,
) -> Result<Connected, String> {
    // The line names the program the caller installs as. Whether that program
    // is there is a question for `status`, as it is for Claude Code's hook.
    let there = |_: &str| hook::ProgramFact::Executable;
    let was_on = state_with(home, spec, there).is_on();
    let (wrote, moved) = install_noting_moved(home, spec, guard_bin, block_review, monitor)?;
    let asked = match (spec.host, codex) {
        (Host::Codex, Some(codex)) => Some(codex_trust::grant(
            codex,
            home,
            &spec.path(home),
            &spec.command(guard_bin, block_review, monitor),
            codex_trust::GRANT_WAIT,
        )),
        _ => None,
    };
    // What the program asked says is not the proof: it is the first `codex`
    // on the PATH, and any program placed in front of the real one answers in
    // its place. The proof is the record in Codex's own config and the folder
    // `CODEX_HOME` names, read here as `status` reads them.
    let now = where_codex_reads(home, spec, state_with(home, spec, there));
    Ok(Connected {
        outcome: settle(spec, wrote || !was_on, asked, &now),
        moved,
    })
}

/// Whether Codex was reached and gave an answer, as against not being there
/// to ask.
fn answered(error: GrantError) -> bool {
    !matches!(
        error,
        GrantError::NotStarted | GrantError::NoAnswer | GrantError::Stopped
    )
}

/// The one step after Codex answered and the hook is still not on.
///
/// A hook Codex does not list is not on its `/hooks` screen, so trusting it
/// there is no step. When the files say why Codex leaves it out, the step is
/// theirs.
fn grant_step(spec: &HookSpec, error: GrantError, state: &HookState) -> String {
    match (error, state) {
        (GrantError::SwitchedOff, _) => SWITCH_ON_STEP.to_string(),
        (GrantError::OtherHome, _) => OTHER_HOME_STEP.to_string(),
        (
            GrantError::NotListed,
            HookState::Off(
                reason @ (Reason::Codex(Skip::HooksOff | Skip::SwitchedOff)
                | Reason::CodexElsewhere(_)),
            ),
        ) => reason.step(spec),
        (GrantError::NotListed, _) => NOT_LISTED_STEP.to_string(),
        _ => TRUST_STEP.to_string(),
    }
}

/// PURE: the outcome of a connect, from what Codex answered (when it was
/// asked) and what the files say afterwards.
///
/// Codex's own "no" stands whatever the files say. A "yes" never outranks
/// them: the program asked is whichever `codex` comes first on the PATH, and
/// a hook reported active that Codex skips costs every tool call it was meant
/// to screen. A later Codex that records trust another way makes this "not
/// active" for a hook that runs, never the reverse. When Codex could not be
/// asked, the files decide too.
fn settle(
    spec: &HookSpec,
    changed: bool,
    asked: Option<Result<(), GrantError>>,
    state: &HookState,
) -> Outcome {
    if let Some(Err(error)) = asked {
        if answered(error) {
            return Outcome::NotActive {
                why: error.words().to_string(),
                step: grant_step(spec, error, state),
            };
        }
    }
    match state {
        HookState::On { .. } => Outcome::Active { changed },
        HookState::Off(Reason::Codex(Skip::NotTrusted | Skip::Changed))
            if asked == Some(Ok(())) =>
        {
            Outcome::NotActive {
                why: YES_NOT_IN_CONFIG.to_string(),
                step: TRUST_STEP.to_string(),
            }
        }
        // Not trusted, and connect is the command that was just run: the step
        // left is the one inside Codex.
        HookState::Off(reason @ Reason::Codex(Skip::NotTrusted | Skip::Changed)) => {
            Outcome::NotActive {
                why: match asked {
                    Some(Err(error)) => error.words().to_string(),
                    _ => reason.why(spec),
                },
                step: TRUST_STEP.to_string(),
            }
        }
        HookState::Off(reason) => Outcome::NotActive {
            why: reason.why(spec),
            step: reason.step(spec),
        },
        HookState::Absent | HookState::Unreadable => Outcome::NotActive {
            why: format!("~/{} could not be read back", spec.file),
            step: format!("Run: innerwarden agents connect {}", spec.agent),
        },
    }
}

/// The line `agents connect` prints for the hook of the agent listed as
/// `name`. A hook the agent does not run is never printed as connected.
pub fn connect_line(
    name: &str,
    spec: &HookSpec,
    outcome: &Outcome,
    block_review: bool,
    monitor: bool,
) -> String {
    match outcome {
        Outcome::Active { changed: true } => {
            let mode = if monitor {
                ", monitor (records, never blocks)"
            } else if block_review {
                ", strict"
            } else {
                ""
            };
            format!("  {name} - connected ({} hook{mode})", spec.event)
        }
        Outcome::Active { changed: false } => format!(
            "  {name} - already guarded ({} hook, {})",
            spec.event,
            mode_word(monitor)
        ),
        Outcome::NotActive { why, step } => format!(
            "  {name} - its {} hook is installed, but it is NOT active: {why}. {step}",
            spec.event
        ),
    }
}

/// What `agents connect` says under the agent's lines: what is screened and
/// what is not once the hook runs, or what is left screened while it does not.
pub fn connect_notes(spec: &HookSpec, outcome: &Outcome) -> Vec<String> {
    match outcome {
        Outcome::Active { .. } => spec.coverage(),
        Outcome::NotActive { .. } if !spec.has_mcp_config() => vec![format!(
            "Until the hook is active, none of {}'s tool calls are screened.",
            spec.product
        )],
        Outcome::NotActive { .. } => vec![format!(
            "Until the hook is active, only calls to MCP servers behind the proxy are screened. \
             {}'s shell commands and file changes run unscreened.",
            spec.product
        )],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIN: &str = "/opt/iw/innerwarden";

    /// The prompt line is Claude Code's alone: no agent wired here (Cursor,
    /// Codex, Gemini) is wired on a prompt event, and no line written for
    /// one carries the prompt flag, in any mode.
    #[test]
    fn no_agent_wired_here_gets_the_prompt_line() {
        for spec in [&CODEX, &GEMINI, &CURSOR] {
            assert!(
                spec.events()
                    .all(|event| event != crate::user_prompt::PROMPT_EVENT),
                "{}",
                spec.agent
            );
            for (block_review, monitor) in [(false, false), (true, false), (false, true)] {
                let line = spec.command(Path::new(BIN), block_review, monitor);
                assert!(
                    !line.contains(crate::user_prompt::PROMPT_LINE_FLAG),
                    "{}: {line}",
                    spec.agent
                );
            }
        }
    }
    /// The enforcing lines as `agents connect` writes them on this system:
    /// the fail-closed script on Linux and macOS.
    static CODEX_LINE: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| CODEX.command(Path::new(BIN), false, false));
    const CODEX_MONITOR: &str = "\"/opt/iw/innerwarden\" hook --monitor --agent codex";
    static GEMINI_LINE: std::sync::LazyLock<String> =
        std::sync::LazyLock::new(|| GEMINI.command(Path::new(BIN), false, false));

    fn write(home: &Path, rel: &str, body: &str) {
        let path = home.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn read(home: &Path, rel: &str) -> Value {
        serde_json::from_str(&std::fs::read_to_string(home.join(rel)).unwrap()).unwrap()
    }

    fn runs(_: &str) -> hook::ProgramFact {
        hook::ProgramFact::Executable
    }

    fn codex_entry(command: &str) -> Value {
        json!({"hooks": [{"type": "command", "command": command, "timeout": 60}]})
    }

    fn gemini_entry(command: &str) -> Value {
        json!({"hooks": [{
            "type": "command",
            "name": "innerwarden",
            "command": command,
            "timeout": 60000
        }]})
    }

    /// A hook of the person's, under a matcher of theirs.
    fn theirs() -> Value {
        json!({
            "matcher": "write_file",
            "hooks": [{"type": "command", "command": "/opt/audit/before"}]
        })
    }

    /// Codex's config with the hook at `group` in `file` trusted for
    /// `command`. The key is a literal string, so a Windows path stays as it
    /// is.
    fn trusting(file: &Path, group: usize, command: &str) -> String {
        format!(
            "[hooks.state.'{}:pre_tool_use:{group}:0']\ntrusted_hash = \"{}\"\n",
            file.display(),
            codex_trust::hook_hash(command, 60)
        )
    }

    fn config(body: &str) -> DocumentMut {
        body.parse().expect("test config parses")
    }

    /// Judge Codex settings that live in `/home/me/.codex/hooks.json`.
    fn judged_codex(settings: &Value, config_body: Option<&str>) -> HookState {
        let config = config_body.map(config);
        judge(
            settings,
            &CODEX,
            Path::new("/home/me/.codex/hooks.json"),
            config.as_ref(),
            runs,
        )
    }

    fn judged_gemini(settings: &Value) -> HookState {
        judge(
            settings,
            &GEMINI,
            Path::new("/home/me/.gemini/settings.json"),
            None,
            runs,
        )
    }

    fn trusted_codex() -> String {
        trusting(Path::new("/home/me/.codex/hooks.json"), 0, &CODEX_LINE)
    }

    #[test]
    fn the_two_agents_are_found_by_their_listing_names() {
        assert_eq!(spec_for("codex"), Some(&CODEX));
        assert_eq!(spec_for("gemini"), Some(&GEMINI));
        assert_eq!(spec_for("claude-code"), None);
        assert_eq!(spec_for("codex-cli"), None);
    }

    /// The whole entry is pinned: a matcher, a missing timeout or a timeout in
    /// the other agent's unit all change this value.
    #[test]
    fn the_entry_has_no_matcher_and_a_timeout_in_the_agents_unit() {
        assert_eq!(
            merge(Value::Null, &CODEX, &CODEX_LINE).unwrap(),
            json!({"hooks": {"PreToolUse": [{"hooks": [{
                "type": "command",
                "command": &*CODEX_LINE,
                "timeout": 60
            }]}]}})
        );
        assert_eq!(
            merge(Value::Null, &GEMINI, &GEMINI_LINE).unwrap(),
            json!({"hooks": {"BeforeTool": [{"hooks": [{
                "type": "command",
                "name": "innerwarden",
                "command": &*GEMINI_LINE,
                "timeout": 60000
            }]}]}})
        );
    }

    /// Codex counts seconds and Gemini milliseconds: both wait one minute.
    #[test]
    fn each_agent_waits_a_minute_in_its_own_unit() {
        assert_eq!(CODEX.timeout, 60);
        assert_eq!(GEMINI.timeout, 60_000);
        assert_eq!(CODEX.wait(), Duration::from_secs(60));
        assert_eq!(GEMINI.wait(), Duration::from_secs(60));
    }

    #[test]
    fn the_hook_line_is_the_program_the_mode_and_the_agent() {
        let bin = Path::new(BIN);
        assert_eq!(
            CODEX.command(bin, false, false),
            hook::hook_command_shaped(bin, false, false, Some("codex"), cfg!(unix))
        );
        assert_eq!(CODEX.command(bin, false, true), CODEX_MONITOR);
        assert_eq!(
            GEMINI.command(bin, true, false),
            hook::hook_command_shaped(bin, true, false, Some("gemini"), cfg!(unix))
        );
        assert_eq!(
            hook::hook_command_shaped(bin, true, false, Some("gemini"), false),
            "\"/opt/iw/innerwarden\" hook --block-review --agent gemini"
        );
    }

    #[test]
    fn install_keeps_every_hook_and_setting_of_the_persons() {
        let home = tempfile::TempDir::new().unwrap();
        let after_tool = json!({"hooks": [{"type": "command", "command": "/opt/audit/after"}]});
        let before = json!({
            "theme": "dark",
            "hooks": {"BeforeTool": [theirs()], "AfterTool": [after_tool.clone()]},
            "mcpServers": {"fs": {"command": "npx"}}
        });
        write(home.path(), GEMINI.file, &before.to_string());

        assert_eq!(
            install(home.path(), &GEMINI, Path::new(BIN), false, false),
            Ok(true)
        );
        assert_eq!(
            read(home.path(), GEMINI.file),
            json!({
                "theme": "dark",
                "hooks": {
                    "BeforeTool": [theirs(), gemini_entry(&GEMINI_LINE)],
                    "AfterTool": [after_tool]
                },
                "mcpServers": {"fs": {"command": "npx"}}
            })
        );

        // And it comes out again, leaving the file as the person had it.
        assert_eq!(uninstall(home.path(), &GEMINI), Ok(1));
        assert_eq!(read(home.path(), GEMINI.file), before);
        assert_eq!(uninstall(home.path(), &GEMINI), Ok(0));
    }

    #[test]
    fn install_creates_the_file_and_a_second_run_writes_nothing() {
        let home = tempfile::TempDir::new().unwrap();
        assert_eq!(
            install(home.path(), &CODEX, Path::new(BIN), false, false),
            Ok(true)
        );
        let written = std::fs::read(home.path().join(CODEX.file)).unwrap();
        assert_eq!(
            read(home.path(), CODEX.file),
            json!({"hooks": {"PreToolUse": [codex_entry(&CODEX_LINE)]}})
        );
        assert_eq!(
            install(home.path(), &CODEX, Path::new(BIN), false, false),
            Ok(false)
        );
        assert_eq!(
            std::fs::read(home.path().join(CODEX.file)).unwrap(),
            written
        );
    }

    /// A mode change rewrites the entry where it sits. The person's hook
    /// behind it keeps its position, and so the trust Codex keyed to it.
    #[test]
    fn a_reinstall_replaces_the_entry_in_place() {
        let settings = json!({"hooks": {"PreToolUse": [codex_entry(CODEX_MONITOR), theirs()]}});
        assert_eq!(
            merge(settings, &CODEX, &CODEX_LINE).unwrap(),
            json!({"hooks": {"PreToolUse": [codex_entry(&CODEX_LINE), theirs()]}})
        );
    }

    /// Ours inside a group of the person's is taken out of it, a second copy
    /// goes, and one entry is left.
    #[test]
    fn a_merge_leaves_one_entry_of_ours() {
        let ours = json!({"type": "command", "command": CODEX_MONITOR});
        let their_hook = json!({"type": "command", "command": "/opt/audit/before"});
        let settings = json!({"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [their_hook.clone(), ours.clone()]},
            {"matcher": "Bash", "hooks": [ours.clone()]},
            {"hooks": [ours]}
        ]}});
        assert_eq!(
            merge(settings, &CODEX, &CODEX_LINE).unwrap(),
            json!({"hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [their_hook]},
                codex_entry(&CODEX_LINE)
            ]}})
        );
    }

    /// A hook of the person's listed behind ours moves up when ours comes
    /// out, and is named. One listed in front of ours stays where it was and
    /// is not named.
    ///
    /// FAILS ON REVERT: take the `filter` line out of `moved` and the hook
    /// that stayed in its place is named as well.
    #[test]
    fn a_hook_of_the_persons_that_moved_is_named_and_one_that_stayed_is_not() {
        let behind = json!({"hooks": [{"type": "command", "command": "/opt/audit/behind"}]});
        let before = json!({"hooks": {"PreToolUse": [
            theirs(),
            codex_entry(&CODEX_LINE),
            behind.clone()
        ]}});
        let (after, removed) = hook::remove_iwguard_hooks_for_event(before.clone(), CODEX.event);
        assert_eq!(removed, 1);
        assert_eq!(after, json!({"hooks": {"PreToolUse": [theirs(), behind]}}));
        assert_eq!(
            moved(&before, &after, &CODEX),
            vec!["`/opt/audit/behind`".to_string()]
        );
        assert_eq!(moved(&before, &before, &CODEX), Vec::<String>::new());
    }

    /// An install that takes our hook out of a group it shares moves the
    /// person's hook listed behind it in that group, and it is named. A
    /// second group of ours becomes an empty group, so the groups behind it
    /// keep their places and nothing is named. A run that writes nothing
    /// names nothing.
    ///
    /// FAILS ON REVERT: end `install_noting_moved` with
    /// `Ok((true, Vec::new()))` in place of its last line and no hook is named.
    /// Take the `all && keep_places` arm out of `merge` and the second group
    /// of ours is dropped, which moves `/opt/audit/last`.
    #[test]
    fn an_install_names_the_hooks_it_moved_inside_a_group_and_behind_one() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = Path::new(BIN);
        let ours = json!({"type": "command", "command": CODEX_MONITOR});
        let first = json!({"type": "command", "command": "/opt/audit/first"});
        let second = json!({"type": "command", "command": "/opt/audit/second"});
        let last = json!({"hooks": [{"type": "command", "command": "/opt/audit/last"}]});

        let shared = json!({"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [first, ours.clone(), second]}
        ]}});
        write(home.path(), CODEX.file, &shared.to_string());
        assert_eq!(
            install_noting_moved(home.path(), &CODEX, bin, false, false),
            Ok((true, vec!["`/opt/audit/second`".to_string()]))
        );
        assert_eq!(
            install_noting_moved(home.path(), &CODEX, bin, false, false),
            Ok((false, Vec::new()))
        );

        let twice = json!({"hooks": {"PreToolUse": [
            {"hooks": [ours.clone()]},
            {"hooks": [ours]},
            last.clone()
        ]}});
        write(home.path(), CODEX.file, &twice.to_string());
        assert_eq!(
            install_noting_moved(home.path(), &CODEX, bin, false, false),
            Ok((true, Vec::new()))
        );
        assert_eq!(
            read(home.path(), CODEX.file),
            json!({"hooks": {"PreToolUse": [codex_entry(&CODEX_LINE), {"hooks": []}, last]}})
        );
    }

    /// A disconnect leaves an empty group where our hook was, so the person's
    /// hooks behind it keep their places. The next connect writes our hook
    /// back into that group, and still moves nothing. Gemini keeps no trust
    /// by place: its file keeps no empty group.
    ///
    /// FAILS ON REVERT: take the `find` over empty groups out of `merge`
    /// and the reconnect leaves the empty group and puts ours at the end.
    /// Uninstall Codex's hook with `remove_iwguard_hooks_for_event` and
    /// `/opt/audit/before` moves up to group 0.
    #[test]
    fn our_place_is_kept_empty_and_taken_again_in_codexs_file() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = Path::new(BIN);
        write(
            home.path(),
            CODEX.file,
            &json!({"hooks": {"PreToolUse": [codex_entry(&CODEX_LINE), theirs()]}}).to_string(),
        );
        assert_eq!(
            uninstall_noting_moved(home.path(), &CODEX),
            Ok((1, Vec::new()))
        );
        assert_eq!(
            read(home.path(), CODEX.file),
            json!({"hooks": {"PreToolUse": [{"hooks": []}, theirs()]}})
        );
        assert_eq!(
            install_noting_moved(home.path(), &CODEX, bin, false, false),
            Ok((true, Vec::new()))
        );
        assert_eq!(
            read(home.path(), CODEX.file),
            json!({"hooks": {"PreToolUse": [codex_entry(&CODEX_LINE), theirs()]}})
        );
        // Ours last: nothing sits behind it, and no empty group is left.
        write(
            home.path(),
            CODEX.file,
            &json!({"hooks": {"PreToolUse": [theirs(), codex_entry(&CODEX_LINE)]}}).to_string(),
        );
        assert_eq!(
            uninstall_noting_moved(home.path(), &CODEX),
            Ok((1, Vec::new()))
        );
        assert_eq!(
            read(home.path(), CODEX.file),
            json!({"hooks": {"PreToolUse": [theirs()]}})
        );

        write(
            home.path(),
            GEMINI.file,
            &json!({"hooks": {"BeforeTool": [gemini_entry(&GEMINI_LINE), theirs()]}}).to_string(),
        );
        assert_eq!(uninstall(home.path(), &GEMINI), Ok(1));
        assert_eq!(
            read(home.path(), GEMINI.file),
            json!({"hooks": {"BeforeTool": [theirs()]}})
        );
    }

    /// PURE: only hooks of ours come out, a group that held only ours stays
    /// as an empty group while something sits behind it, and empty groups at
    /// the end go.
    #[test]
    fn vacate_keeps_every_place_in_front_of_the_last_hook_of_the_persons() {
        let behind = json!({"hooks": [{"type": "command", "command": "/opt/audit/behind"}]});
        let ours = json!({"type": "command", "command": CODEX_LINE.as_str()});
        let settings = json!({"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [ours.clone()]},
            theirs(),
            {"hooks": [ours.clone()]},
            behind.clone(),
            {"hooks": [ours]}
        ]}});
        let (after, removed) = vacate(settings.clone(), CODEX.event);
        assert_eq!(removed, 3);
        assert_eq!(
            after,
            json!({"hooks": {"PreToolUse": [{"hooks": []}, theirs(), {"hooks": []}, behind]}})
        );
        assert_eq!(moved(&settings, &after, &CODEX), Vec::<String>::new());
        // Nothing of ours: nothing changes, an empty group of the person's
        // at the end included.
        let none = json!({"hooks": {"PreToolUse": [theirs(), {"hooks": []}]}});
        assert_eq!(vacate(none.clone(), CODEX.event), (none, 0));
    }

    /// Gemini keeps no trust by place, so a hook of the person's that moved
    /// in its file is not named.
    ///
    /// FAILS ON REVERT: take the `spec.host != Host::Codex` return out of
    /// `moved` and Gemini's hook is named.
    #[test]
    fn a_hook_that_moved_in_geminis_file_is_not_named() {
        let before = json!({"hooks": {"BeforeTool": [gemini_entry(&GEMINI_LINE), theirs()]}});
        let after = json!({"hooks": {"BeforeTool": [theirs()]}});
        assert_eq!(moved(&before, &after, &GEMINI), Vec::<String>::new());
    }

    /// The note names each hook that moved and the step inside Codex, in one
    /// line, and there is no note when nothing moved.
    ///
    /// FAILS ON REVERT: take the `0 => return None` arm out of `moved_note`
    /// and a run that moved nothing prints a note about no hook.
    #[test]
    fn the_note_names_the_hooks_that_moved_and_the_step_to_trust_them() {
        assert_eq!(moved_note(&CODEX, &[]), None);
        assert_eq!(
            moved_note(&CODEX, &["`/opt/audit/before`".to_string()]).as_deref(),
            Some(
                "A PreToolUse hook of your own moved to a new place in ~/.codex/hooks.json: \
                 `/opt/audit/before`. Codex trusts a hook by its place and skips it until it \
                 is trusted there. Run `/hooks` inside Codex and trust it again."
            )
        );
        assert_eq!(
            moved_note(
                &CODEX,
                &[
                    "`/opt/audit/before`".to_string(),
                    "one with no command".to_string()
                ]
            )
            .as_deref(),
            Some(
                "2 PreToolUse hooks of your own moved to a new place in ~/.codex/hooks.json: \
                 `/opt/audit/before`, one with no command. Codex trusts a hook by its place \
                 and skips them until they are trusted there. Run `/hooks` inside Codex and \
                 trust them again."
            )
        );
    }

    /// A command is shown on one line and cut when it is long: the note it
    /// goes into is one line.
    ///
    /// FAILS ON REVERT: take the `.map(...)` line out of `shown` and the line
    /// break inside a command is printed.
    #[test]
    fn a_hooks_command_is_shown_on_one_line_and_cut_when_long() {
        assert_eq!(shown("/opt/audit/before"), "/opt/audit/before");
        assert_eq!(shown("sh -c 'a\nb'\t"), "sh -c 'a b' ");
        let long = "x".repeat(SHOWN_COMMAND_CHARS + 5);
        assert_eq!(
            shown(&long),
            format!("{}...", "x".repeat(SHOWN_COMMAND_CHARS))
        );
        assert_eq!(
            shown(&"x".repeat(SHOWN_COMMAND_CHARS)),
            "x".repeat(SHOWN_COMMAND_CHARS)
        );
        // A hook with no command is still named.
        let settings = json!({"hooks": {"PreToolUse": [{"hooks": [{"type": "prompt"}]}]}});
        assert_eq!(
            theirs_at(&settings, &CODEX),
            vec![((0, 0), "one with no command".to_string())]
        );
    }

    /// A hook of the person's is named by the program it starts, never by
    /// the rest of its command: a note that held `failed:` would read as a
    /// failed run to `agents connect` and `disconnect`. A program that says
    /// `failed:` itself, or no program at all, is named by its place.
    ///
    /// FAILS ON REVERT: name a hook by `shown(command)` in `theirs_at` and
    /// the first two hold the whole command, `failed:` in the first; drop
    /// the `failed:` test in `program_of` and the third holds it.
    #[test]
    fn a_persons_hook_is_named_by_its_program_only() {
        let hook = |command: &str| json!({"hooks": [{"type": "command", "command": command}]});
        let settings = json!({"hooks": {"PreToolUse": [
            hook("echo \"audit failed: x\""),
            hook("\"/opt/my tools/audit\" --before"),
            hook("/opt/failed:/audit --before"),
            hook("   "),
        ]}});
        let named: Vec<String> = theirs_at(&settings, &CODEX)
            .into_iter()
            .map(|(_, name)| name)
            .collect();
        assert_eq!(
            named,
            vec![
                "`echo`",
                "`/opt/my tools/audit`",
                "the one at group 3, hook 1",
                "the one at group 4, hook 1",
            ]
        );
        assert!(named.iter().all(|name| !name.contains("failed:")));
    }

    #[test]
    fn install_refuses_settings_it_cannot_merge_into_and_leaves_them() {
        let home = tempfile::TempDir::new().unwrap();
        let path = home.path().join(CODEX.file);
        for (body, why) in [
            ("[]", "its top level is not a JSON object"),
            ("{\"hooks\": []}", "`hooks` is not a JSON object"),
            (
                "{\"hooks\": {\"PreToolUse\": {}}}",
                "`hooks.PreToolUse` is not a list",
            ),
        ] {
            write(home.path(), CODEX.file, body);
            assert_eq!(
                install(home.path(), &CODEX, Path::new(BIN), false, false),
                Err(format!("{}: {why}", path.display())),
                "{body}"
            );
            assert_eq!(std::fs::read_to_string(&path).unwrap(), body);
        }
        // Not JSON at all: refused, and left.
        write(home.path(), CODEX.file, "{ // mine\n}");
        assert!(install(home.path(), &CODEX, Path::new(BIN), false, false).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ // mine\n}");
        assert!(uninstall(home.path(), &CODEX).is_err());
        assert_eq!(state(home.path(), &CODEX, None), HookState::Unreadable);
    }

    #[test]
    fn uninstall_forgets_the_trust_codex_held_for_the_hook() {
        let home = tempfile::TempDir::new().unwrap();
        let file = home.path().join(CODEX.file);
        write(
            home.path(),
            CODEX.file,
            &json!({"hooks": {"PreToolUse": [theirs(), codex_entry(&CODEX_LINE)]}}).to_string(),
        );
        let their_key = format!("{}:pre_tool_use:0:0", file.display());
        write(
            home.path(),
            CODEX_CONFIG,
            &format!(
                "model = \"gpt\"\n\n[hooks.state.'{their_key}']\ntrusted_hash = \"sha256:00\"\n\n{}",
                trusting(&file, 1, &CODEX_LINE)
            ),
        );

        assert_eq!(uninstall(home.path(), &CODEX), Ok(1));
        assert_eq!(
            read(home.path(), CODEX.file),
            json!({"hooks": {"PreToolUse": [theirs()]}})
        );
        let config = config(&std::fs::read_to_string(home.path().join(CODEX_CONFIG)).unwrap());
        let keys: Vec<String> = config["hooks"]["state"]
            .as_table_like()
            .expect("the state table stays")
            .iter()
            .map(|(key, _)| key.to_string())
            .collect();
        assert_eq!(keys, vec![their_key]);
        assert_eq!(config["model"].as_str(), Some("gpt"));
    }

    /// Every hook of ours that is taken out takes its record of trust with
    /// it, however many there were.
    ///
    /// FAILS ON REVERT: read `changed |=` as `changed ^=` in `forget_trust`
    /// and the second record forgotten cancels the first: the config is not
    /// written, and both records stay.
    #[test]
    fn uninstall_forgets_the_trust_of_every_hook_of_ours_it_takes_out() {
        let home = tempfile::TempDir::new().unwrap();
        let file = home.path().join(CODEX.file);
        write(
            home.path(),
            CODEX.file,
            &json!({"hooks": {"PreToolUse": [
                codex_entry(&CODEX_LINE),
                theirs(),
                codex_entry(&CODEX_LINE)
            ]}})
            .to_string(),
        );
        let their_key = format!("{}:pre_tool_use:1:0", file.display());
        write(
            home.path(),
            CODEX_CONFIG,
            &format!(
                "{}\n[hooks.state.'{their_key}']\ntrusted_hash = \"sha256:00\"\n\n{}",
                trusting(&file, 0, &CODEX_LINE),
                trusting(&file, 2, &CODEX_LINE)
            ),
        );

        assert_eq!(uninstall(home.path(), &CODEX), Ok(2));
        let config = config(&std::fs::read_to_string(home.path().join(CODEX_CONFIG)).unwrap());
        let keys: Vec<String> = config["hooks"]["state"]
            .as_table_like()
            .expect("the state table stays")
            .iter()
            .map(|(key, _)| key.to_string())
            .collect();
        assert_eq!(keys, vec![their_key]);
    }

    /// A group of the person's with no hook in it is theirs, and stays where
    /// it is when ours is written.
    ///
    /// FAILS ON REVERT: read the first `ours > 0` in `ours_in` as
    /// `ours >= 0` and the empty group is taken for one of ours, emptied of
    /// nothing, and dropped.
    #[test]
    fn a_group_of_theirs_with_no_hook_in_it_stays() {
        let empty = json!({"matcher": "Bash", "hooks": []});
        let settings = json!({"hooks": {"PreToolUse": [empty.clone()]}});
        assert_eq!(
            merge(settings, &CODEX, &CODEX_LINE).unwrap(),
            json!({"hooks": {"PreToolUse": [empty, codex_entry(&CODEX_LINE)]}})
        );
    }

    /// Taking our hook out of Codex's file leaves the person's hook listed
    /// behind it at its place, so the record of trust Codex holds for it,
    /// which this leaves alone, still names it. Nothing moved and nothing is
    /// named.
    ///
    /// FAILS ON REVERT: uninstall Codex's hook with
    /// `remove_iwguard_hooks_for_event` again and `/opt/audit/before` moves
    /// to group 0, away from its record.
    #[test]
    fn uninstall_keeps_the_persons_hook_at_the_place_of_its_record() {
        let home = tempfile::TempDir::new().unwrap();
        let file = home.path().join(CODEX.file);
        write(
            home.path(),
            CODEX.file,
            &json!({"hooks": {"PreToolUse": [codex_entry(&CODEX_LINE), theirs()]}}).to_string(),
        );
        let their_key = format!("{}:pre_tool_use:1:0", file.display());
        write(
            home.path(),
            CODEX_CONFIG,
            &format!(
                "[hooks.state.'{their_key}']\ntrusted_hash = \"sha256:00\"\n\n{}",
                trusting(&file, 0, &CODEX_LINE)
            ),
        );

        assert_eq!(
            uninstall_noting_moved(home.path(), &CODEX),
            Ok((1, Vec::new()))
        );
        assert_eq!(
            read(home.path(), CODEX.file),
            json!({"hooks": {"PreToolUse": [{"hooks": []}, theirs()]}})
        );
        let config = config(&std::fs::read_to_string(home.path().join(CODEX_CONFIG)).unwrap());
        let held = config["hooks"]["state"]
            .as_table_like()
            .expect("the state table stays");
        let records: Vec<(String, Option<&str>)> = held
            .iter()
            .map(|(key, record)| {
                (
                    key.to_string(),
                    record.get("trusted_hash").and_then(toml_edit::Item::as_str),
                )
            })
            .collect();
        assert_eq!(records, vec![(their_key, Some("sha256:00"))]);
        // A hook in front of ours does not move, and nothing is named.
        write(
            home.path(),
            CODEX.file,
            &json!({"hooks": {"PreToolUse": [theirs(), codex_entry(&CODEX_LINE)]}}).to_string(),
        );
        assert_eq!(
            uninstall_noting_moved(home.path(), &CODEX),
            Ok((1, Vec::new()))
        );
    }

    /// What stops an uninstall whose disconnect failed: a hook that still
    /// runs the binary about to go. A file that reads is judged by the
    /// program its hook names. A file that is not valid settings is judged by
    /// its text, whatever copy the line names.
    ///
    /// FAILS ON REVERT: answer `None` from the `Err(_)` arm of the `parse`
    /// match in `still_runs` and the Gemini file that was cut short is not
    /// listed. Take the `$0` form out of `holds_a_hook_line` and the cut
    /// fail-closed line is not found either (Linux and macOS write that one).
    #[test]
    fn a_hook_that_still_runs_the_binary_is_found_whether_or_not_its_file_reads() {
        let home = tempfile::TempDir::new().unwrap();
        assert!(left_behind(home.path(), Path::new(BIN)).is_empty());

        write(
            home.path(),
            CODEX.file,
            &json!({"hooks": {"PreToolUse": [codex_entry(&CODEX_LINE)]}}).to_string(),
        );
        // The same kind of file, cut short: not valid JSON, the line still in it.
        let whole = json!({"hooks": {"BeforeTool": [gemini_entry(&GEMINI_LINE)]}}).to_string();
        write(home.path(), GEMINI.file, &whole[..whole.len() - 1]);
        assert_eq!(
            left_behind(home.path(), Path::new(BIN)),
            vec![
                LeftBehind {
                    spec: &CODEX,
                    seen: true
                },
                LeftBehind {
                    spec: &GEMINI,
                    seen: false
                },
            ]
        );
        // A hook that reads and names another copy does not run this binary.
        assert_eq!(
            left_behind(home.path(), Path::new("/usr/local/bin/innerwarden")),
            vec![LeftBehind {
                spec: &GEMINI,
                seen: false
            }]
        );

        // The plain line, cut short, is found as well.
        let plain = hook::hook_command_shaped(Path::new(BIN), false, false, Some("gemini"), false);
        let whole = json!({"hooks": {"BeforeTool": [gemini_entry(&plain)]}}).to_string();
        write(home.path(), GEMINI.file, &whole[..whole.len() - 1]);
        assert_eq!(
            left_behind(home.path(), Path::new("/usr/local/bin/innerwarden")),
            vec![LeftBehind {
                spec: &GEMINI,
                seen: false
            }]
        );

        // Text that is not settings and holds no hook line rules nothing in.
        write(home.path(), GEMINI.file, "{\"hooks\": ");
        write(
            home.path(),
            CODEX.file,
            &json!({"hooks": {"PreToolUse": [theirs()]}}).to_string(),
        );
        assert!(left_behind(home.path(), Path::new(BIN)).is_empty());
    }

    /// The hook may name the binary through a link, and `uninstall` holds the
    /// binary's path with every link resolved.
    ///
    /// FAILS ON REVERT: take the `matches!` over the two resolved paths out
    /// of `is_program` and the hook that names the link is not found.
    #[cfg(unix)]
    #[test]
    fn a_hook_that_names_the_binary_through_a_link_still_runs_it() {
        let home = tempfile::TempDir::new().unwrap();
        write(home.path(), "opt/innerwarden", "");
        let real = home.path().join("opt/innerwarden").canonicalize().unwrap();
        let link = home.path().join("bin/innerwarden");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let command = format!("\"{}\" hook --agent gemini", link.display());
        write(
            home.path(),
            GEMINI.file,
            &json!({"hooks": {"BeforeTool": [gemini_entry(&command)]}}).to_string(),
        );

        assert_eq!(
            left_behind(home.path(), &real),
            vec![LeftBehind {
                spec: &GEMINI,
                seen: true
            }]
        );
    }

    /// The words `uninstall` stops on: that it stopped, the file, what the
    /// hook costs once its program is gone, and the step. A file that was not
    /// read is said to be unread, not to hold the hook.
    ///
    /// FAILS ON REVERT: push the `still holds` sentence whatever `seen` says
    /// and the unread Gemini file is reported as read.
    #[test]
    fn the_stop_names_each_file_what_the_hook_costs_and_the_step() {
        assert_eq!(
            left_behind_lines(&[
                LeftBehind {
                    spec: &CODEX,
                    seen: true
                },
                LeftBehind {
                    spec: &GEMINI,
                    seen: false
                },
            ]),
            vec![
                "disconnect reported a problem, and a hook would outlive the binary.",
                "The configuration and the binary were left in place.",
                "~/.codex/hooks.json still holds a PreToolUse hook that runs this binary.",
                "Codex would start a hook whose program is gone before every tool call: in \
                 enforce mode it refuses every call, in monitor mode it runs them unscreened.",
                "Take the innerwarden hook out of that file, or run `innerwarden agents \
                 disconnect codex` once the file can be read and written.",
                "~/.gemini/settings.json could not be read, and a BeforeTool hook in it may \
                 still run this binary.",
                "Gemini would start a hook whose program is gone before every tool call: in \
                 enforce mode it refuses every call, in monitor mode it runs them unscreened on \
                 Linux and macOS and refuses them on Windows.",
                "Take the innerwarden hook out of that file, or run `innerwarden agents \
                 disconnect gemini` once the file can be read and written.",
            ]
        );
    }

    /// The row's proof for Codex: the hook `agents connect` writes in
    /// enforce mode is the fail-closed line, so with its program gone Codex
    /// refuses every tool call, and `status` says so; in monitor mode the
    /// line is plain and the calls run unscreened.
    ///
    /// FAILS ON REVERT: compute `refuses` in `judge` from the host alone and
    /// the Codex hook in enforce mode reads as one that lets calls through.
    #[cfg(unix)]
    #[test]
    fn a_codex_hook_whose_program_is_gone_refuses_in_enforce_and_not_in_monitor() {
        let home = tempfile::TempDir::new().unwrap();
        let gone = home.path().join("gone/innerwarden");
        install(home.path(), &CODEX, &gone, false, false).unwrap();
        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(CODEX.path(home.path())).unwrap())
                .unwrap();
        let line = hook::read_hook_line(&written["hooks"]["PreToolUse"][0]["hooks"][0]).unwrap();
        assert!(line.fail_closed, "{written}");
        let enforce = state(home.path(), &CODEX, None);
        assert_eq!(stall(&CODEX, &enforce), Some(Stall::Refuses), "{enforce:?}");

        install(home.path(), &CODEX, &gone, false, true).unwrap();
        let monitor = state(home.path(), &CODEX, None);
        assert!(
            matches!(
                monitor,
                HookState::Off(Reason::Broken { refuses: false, .. })
            ),
            "{monitor:?}"
        );
        assert_eq!(stall(&CODEX, &monitor), None);
    }

    #[test]
    fn a_file_with_no_hook_of_ours_is_absent() {
        assert_eq!(judged_codex(&json!({}), None), HookState::Absent);
        assert_eq!(
            judged_codex(&json!({"hooks": {"PreToolUse": [theirs()]}}), None),
            HookState::Absent
        );
        // Ours under another event is not a hook that runs before a tool.
        assert_eq!(
            judged_codex(
                &json!({"hooks": {"PostToolUse": [codex_entry(&CODEX_LINE)]}}),
                Some(&trusted_codex())
            ),
            HookState::Absent
        );
        let home = tempfile::TempDir::new().unwrap();
        assert_eq!(state(home.path(), &CODEX, None), HookState::Absent);
        write(home.path(), CODEX.file, "\n");
        assert_eq!(state(home.path(), &CODEX, None), HookState::Absent);
    }

    #[test]
    fn a_codex_hook_is_on_only_with_trust_for_this_line() {
        let settings = merge(Value::Null, &CODEX, &CODEX_LINE).unwrap();
        assert_eq!(
            judged_codex(&settings, Some(&trusted_codex())),
            HookState::On {
                monitor: false,
                block_review: false
            }
        );
        assert_eq!(
            judged_codex(&settings, None),
            HookState::Off(Reason::Codex(Skip::NotTrusted))
        );
        assert_eq!(
            judged_codex(&settings, Some("model = \"gpt\"\n")),
            HookState::Off(Reason::Codex(Skip::NotTrusted))
        );
        // Trust given to the monitor line is trust for another hook.
        let for_monitor = trusting(Path::new("/home/me/.codex/hooks.json"), 0, CODEX_MONITOR);
        assert_eq!(
            judged_codex(&settings, Some(&for_monitor)),
            HookState::Off(Reason::Codex(Skip::Changed))
        );
        assert_eq!(
            judged_codex(
                &settings,
                Some(&format!("{}enabled = false\n", trusted_codex()))
            ),
            HookState::Off(Reason::Codex(Skip::SwitchedOff))
        );
        assert_eq!(
            judged_codex(
                &settings,
                Some(&format!("[features]\nhooks = false\n\n{}", trusted_codex()))
            ),
            HookState::Off(Reason::Codex(Skip::HooksOff))
        );
    }

    /// Trust is keyed by position: the record for group 0 says nothing of a
    /// hook that sits in group 1.
    #[test]
    fn codex_trust_is_read_for_the_place_the_hook_sits_in() {
        let settings = json!({"hooks": {"PreToolUse": [theirs(), codex_entry(&CODEX_LINE)]}});
        assert_eq!(
            judged_codex(&settings, Some(&trusted_codex())),
            HookState::Off(Reason::Codex(Skip::NotTrusted))
        );
        let second = trusting(Path::new("/home/me/.codex/hooks.json"), 1, &CODEX_LINE);
        assert_eq!(
            judged_codex(&settings, Some(&second)),
            HookState::On {
                monitor: false,
                block_review: false
            }
        );
    }

    #[test]
    fn the_mode_of_a_hook_that_is_on_is_read_from_its_line() {
        let monitor = merge(
            Value::Null,
            &GEMINI,
            &GEMINI.command(Path::new(BIN), false, true),
        );
        assert_eq!(
            judged_gemini(&monitor.unwrap()),
            HookState::On {
                monitor: true,
                block_review: false
            }
        );
        let strict = merge(
            Value::Null,
            &GEMINI,
            &GEMINI.command(Path::new(BIN), true, false),
        );
        assert_eq!(
            judged_gemini(&strict.unwrap()),
            HookState::On {
                monitor: false,
                block_review: true
            }
        );
    }

    /// Each of these still holds a hook line of ours, and none is the entry
    /// that sends every tool call to the guard with a minute to answer.
    #[test]
    fn an_entry_connect_would_not_write_is_not_on() {
        let hook =
            |timeout: u64| json!({"type": "command", "command": &*CODEX_LINE, "timeout": timeout});
        let bare = json!({"type": "command", "command": &*CODEX_LINE});
        let other_agent = json!({
            "type": "command",
            "command": "\"/opt/iw/innerwarden\" hook --agent gemini",
            "timeout": 60
        });
        let their_hook = json!({"type": "command", "command": "/opt/audit/before"});
        for (what, groups) in [
            (
                "a matcher",
                json!([{"matcher": "Bash", "hooks": [hook(60)]}]),
            ),
            ("a shorter timeout", json!([{"hooks": [hook(5)]}])),
            ("no timeout", json!([{"hooks": [bare]}])),
            ("another agent's id", json!([{"hooks": [other_agent]}])),
            ("a shared group", json!([{"hooks": [hook(60), their_hook]}])),
            (
                "a second copy",
                json!([codex_entry(&CODEX_LINE), codex_entry(&CODEX_LINE)]),
            ),
        ] {
            assert_eq!(
                judged_codex(
                    &json!({"hooks": {"PreToolUse": groups}}),
                    Some(&trusted_codex())
                ),
                HookState::Off(Reason::Altered),
                "{what}"
            );
        }
    }

    #[test]
    fn a_hook_whose_program_is_not_there_is_not_on() {
        let settings = merge(Value::Null, &GEMINI, &GEMINI_LINE).unwrap();
        let judged = |fact: hook::ProgramFact| {
            judge(
                &settings,
                &GEMINI,
                Path::new("/home/me/.gemini/settings.json"),
                None,
                move |_: &str| fact,
            )
        };
        assert_eq!(
            judged(hook::ProgramFact::Missing),
            HookState::Off(Reason::Broken {
                clause: "its hook runs /opt/iw/innerwarden, which does not exist".to_string(),
                refuses: true,
            })
        );
        assert_eq!(
            judged(hook::ProgramFact::Unreadable),
            HookState::Off(Reason::Unchecked {
                clause: "its hook runs /opt/iw/innerwarden, and I could not look to see if it \
                         is there"
                    .to_string(),
                refuses: true,
            })
        );
        assert_eq!(
            judged(hook::ProgramFact::Executable),
            HookState::On {
                monitor: false,
                block_review: false
            }
        );
        // The same look, through the filesystem: nothing is at that path.
        let home = tempfile::TempDir::new().unwrap();
        let gone = home.path().join("gone/innerwarden");
        install(home.path(), &GEMINI, &gone, false, false).unwrap();
        assert_eq!(
            state(home.path(), &GEMINI, None),
            HookState::Off(Reason::Broken {
                clause: format!("its hook runs {}, which does not exist", gone.display()),
                refuses: true,
            })
        );
    }

    /// Gemini's monitor line is the fail-open script on Linux and macOS: a
    /// program that is gone ends it with 1, and Gemini runs the call. So the
    /// state says the hook is broken without saying Gemini refuses calls.
    ///
    /// FAILS ON REVERT of `!only.line.fail_open` in `judge`: the monitor
    /// hook reads as one that refuses every call.
    #[cfg(unix)]
    #[test]
    fn a_gemini_monitor_hook_whose_program_is_gone_does_not_refuse() {
        let home = tempfile::TempDir::new().unwrap();
        let gone = home.path().join("gone/innerwarden");
        install(home.path(), &GEMINI, &gone, false, true).unwrap();
        let state = state(home.path(), &GEMINI, None);
        assert_eq!(
            state,
            HookState::Off(Reason::Broken {
                clause: format!("its hook runs {}, which does not exist", gone.display()),
                refuses: false,
            })
        );
        assert_eq!(stall(&GEMINI, &state), None);
    }

    #[test]
    fn geminis_own_switches_turn_the_hook_off() {
        let with = |hooks_config: Value| {
            let mut settings = merge(Value::Null, &GEMINI, &GEMINI_LINE).unwrap();
            settings["hooksConfig"] = hooks_config;
            judged_gemini(&settings)
        };
        let on = HookState::On {
            monitor: false,
            block_review: false,
        };
        assert_eq!(
            with(json!({"enabled": false})),
            HookState::Off(Reason::GeminiHooksOff)
        );
        assert_eq!(
            with(json!({"disabled": ["innerwarden"]})),
            HookState::Off(Reason::GeminiHookDisabled)
        );
        assert_eq!(
            with(json!({"disabled": [&*GEMINI_LINE]})),
            HookState::Off(Reason::GeminiHookDisabled)
        );
        assert_eq!(with(json!({"enabled": true, "disabled": ["lint"]})), on);
        assert_eq!(with(json!({})), on);
    }

    /// A Gemini hook whose program is gone holds every tool call up, and so
    /// does a fail-closed Codex one; a plain Codex line does not. A hook
    /// Gemini's switch turns off is never started, so the switch is what is
    /// reported, whatever the program is.
    ///
    /// FAILS ON REVERT: move the `gemini_switch` look in `judge` back under
    /// the look at the program and the switched-off hook reads `Broken`, which
    /// `stall` answers with a refusal Gemini does not make.
    #[test]
    fn a_missing_program_stalls_gemini_only_while_gemini_starts_the_hook() {
        let broken = |refuses| {
            HookState::Off(Reason::Broken {
                clause: "its hook runs /x, which does not exist".to_string(),
                refuses,
            })
        };
        let unchecked = |refuses| {
            HookState::Off(Reason::Unchecked {
                clause: "its hook runs /x, and I could not look to see if it is there".to_string(),
                refuses,
            })
        };
        assert_eq!(stall(&GEMINI, &broken(true)), Some(Stall::Refuses));
        assert_eq!(stall(&GEMINI, &unchecked(true)), Some(Stall::MayRefuse));
        assert_eq!(stall(&CODEX, &broken(true)), Some(Stall::Refuses));
        assert_eq!(stall(&CODEX, &broken(false)), None);
        assert_eq!(stall(&CODEX, &unchecked(false)), None);
        assert_eq!(
            stall(&GEMINI, &HookState::Off(Reason::GeminiHooksOff)),
            None
        );
        assert_eq!(stall(&GEMINI, &HookState::Absent), None);

        let mut settings = merge(Value::Null, &GEMINI, &GEMINI_LINE).unwrap();
        settings["hooksConfig"] = json!({"enabled": false});
        let switched_off = judge(
            &settings,
            &GEMINI,
            Path::new("/home/me/.gemini/settings.json"),
            None,
            |_: &str| hook::ProgramFact::Missing,
        );
        assert_eq!(switched_off, HookState::Off(Reason::GeminiHooksOff));
        assert_eq!(stall(&GEMINI, &switched_off), None);
    }

    /// The exact words. "on" is in the line of a hook that is on and in no
    /// other.
    #[test]
    fn the_state_line_says_on_only_for_a_hook_that_is_on() {
        let on = HookState::On {
            monitor: true,
            block_review: false,
        };
        assert_eq!(state_line(&CODEX, &on), "PreToolUse hook: on (monitor)");
        assert_eq!(
            state_line(
                &GEMINI,
                &HookState::On {
                    monitor: false,
                    block_review: false
                }
            ),
            "BeforeTool hook: on (enforce)"
        );
        assert_eq!(
            state_line(&CODEX, &HookState::Absent),
            "PreToolUse hook: not installed. Run: innerwarden agents connect codex"
        );
        // A file that cannot be read comes first: connect refuses to write
        // into it, so "run connect" alone is a step that cannot work.
        assert_eq!(
            state_line(&GEMINI, &HookState::Unreadable),
            "BeforeTool hook: unknown, ~/.gemini/settings.json could not be read. Fix \
             ~/.gemini/settings.json or move it aside, then run `innerwarden agents connect \
             gemini`"
        );
        for (reason, line) in [
            (
                Reason::Codex(Skip::NotTrusted),
                "PreToolUse hook: installed, but Codex skips it: it is not trusted yet. \
                 Run: innerwarden agents connect codex",
            ),
            (
                Reason::Codex(Skip::Changed),
                "PreToolUse hook: installed, but Codex skips it: it changed after it was \
                 trusted. Run: innerwarden agents connect codex",
            ),
            (
                Reason::Codex(Skip::SwitchedOff),
                "PreToolUse hook: installed, but Codex skips it: it is switched off \
                 (`enabled = false`). Switch it back on with `/hooks` inside Codex",
            ),
            (
                Reason::Codex(Skip::HooksOff),
                "PreToolUse hook: installed, but Codex skips it: hooks are switched off under \
                 [features]. Take `hooks = false` and `codex_hooks = false` out of [features] \
                 in ~/.codex/config.toml",
            ),
            (
                Reason::Altered,
                "PreToolUse hook: installed, but it is not the entry `agents connect` writes, \
                 so Codex may not run it for every tool. Run: innerwarden agents connect codex",
            ),
            (
                Reason::Broken {
                    clause: "its hook runs /x, which does not exist".to_string(),
                    refuses: false,
                },
                "PreToolUse hook: installed, but its hook runs /x, which does not exist. \
                 Run: innerwarden agents connect codex",
            ),
        ] {
            assert_eq!(state_line(&CODEX, &HookState::Off(reason)), line);
        }
        assert_eq!(
            state_line(&GEMINI, &HookState::Off(Reason::GeminiHooksOff)),
            "BeforeTool hook: installed, but Gemini skips it: hooks are switched off \
             (`hooksConfig.enabled` is false). Set it to true in ~/.gemini/settings.json"
        );
        assert_eq!(
            state_line(&GEMINI, &HookState::Off(Reason::GeminiHookDisabled)),
            "BeforeTool hook: installed, but Gemini skips it: it is listed under \
             `hooksConfig.disabled`. Take it out of that list in ~/.gemini/settings.json"
        );
    }

    fn not_active(why: &str, step: &str) -> Outcome {
        Outcome::NotActive {
            why: why.to_string(),
            step: step.to_string(),
        }
    }

    const ON: HookState = HookState::On {
        monitor: false,
        block_review: false,
    };

    /// Codex was reached and said no: no reading of the files turns that into
    /// a hook that is on.
    #[test]
    fn a_no_from_codex_is_not_active_whatever_the_files_say() {
        for (error, why, step) in [
            (
                GrantError::NotTrusted,
                "Codex still does not trust it",
                TRUST_STEP,
            ),
            (GrantError::Refused, "Codex refused the request", TRUST_STEP),
            (
                GrantError::NotListed,
                "Codex does not list the hook",
                "Update Codex, make sure hooks are not switched off, then run `innerwarden \
                 agents connect codex` again",
            ),
            (
                GrantError::SwitchedOff,
                "it is switched off in Codex",
                SWITCH_ON_STEP,
            ),
            (
                GrantError::OtherHome,
                "Codex keeps its settings in another folder",
                "Start Codex without CODEX_HOME, then run `innerwarden agents connect codex` again",
            ),
        ] {
            assert_eq!(
                settle(&CODEX, true, Some(Err(error)), &ON),
                not_active(why, step),
                "{error:?}"
            );
        }
    }

    /// A hook Codex does not list is not on its `/hooks` screen, so the step
    /// is never to trust it there. When the files say why Codex leaves it
    /// out, the step is the one they give.
    ///
    /// FAILS ON REVERT: take the two `GrantError::NotListed` arms out of
    /// `grant_step` and every step here is the one inside `/hooks`.
    #[test]
    fn a_hook_codex_does_not_list_is_never_sent_to_the_hooks_screen() {
        for (state, step) in [
            (
                HookState::Off(Reason::Codex(Skip::HooksOff)),
                "Take `hooks = false` and `codex_hooks = false` out of [features] in \
                 ~/.codex/config.toml",
            ),
            (
                HookState::Off(Reason::Codex(Skip::SwitchedOff)),
                SWITCH_ON_STEP,
            ),
            (
                HookState::Off(Reason::CodexElsewhere(PathBuf::from("/work/codex-home"))),
                OTHER_HOME_STEP,
            ),
            (
                HookState::Off(Reason::Codex(Skip::NotTrusted)),
                NOT_LISTED_STEP,
            ),
            (ON, NOT_LISTED_STEP),
        ] {
            let settled = settle(&CODEX, true, Some(Err(GrantError::NotListed)), &state);
            assert_eq!(
                settled,
                not_active("Codex does not list the hook", step),
                "{state:?}"
            );
            assert_ne!(step, TRUST_STEP, "{state:?}");
        }
        // A hook Codex lists and does not trust keeps the step inside Codex.
        assert_eq!(
            settle(
                &CODEX,
                true,
                Some(Err(GrantError::NotTrusted)),
                &HookState::Off(Reason::Codex(Skip::HooksOff))
            ),
            not_active("Codex still does not trust it", TRUST_STEP)
        );
    }

    /// The notes under the hook's line name the hooks of the person's that
    /// moved, and nothing else: there is no "yes" from Codex to report beside
    /// the files any more.
    #[test]
    fn the_notes_are_the_hooks_that_moved() {
        let connected = |moved: Vec<String>| Connected {
            outcome: Outcome::Active { changed: true },
            moved,
        };
        assert_eq!(connected(Vec::new()).notes(&CODEX), Vec::<String>::new());
        let one = connected(vec!["`/opt/audit/before`".to_string()]).notes(&CODEX);
        assert_eq!(one.len(), 1);
        assert!(
            one[0].starts_with("A PreToolUse hook of your own moved"),
            "{one:?}"
        );
    }

    /// Codex was not there to ask: the files decide, and a hook they do not
    /// show as trusted is not active, with the step inside Codex.
    #[test]
    fn with_no_codex_to_ask_the_files_decide() {
        let untrusted = HookState::Off(Reason::Codex(Skip::NotTrusted));
        for error in [
            GrantError::NotStarted,
            GrantError::NoAnswer,
            GrantError::Stopped,
        ] {
            assert_eq!(
                settle(&CODEX, false, Some(Err(error)), &ON),
                Outcome::Active { changed: false },
                "{error:?}"
            );
            assert_eq!(
                settle(&CODEX, true, Some(Err(error)), &untrusted),
                not_active(error.words(), TRUST_STEP),
                "{error:?}"
            );
        }
        assert_eq!(
            settle(&CODEX, true, None, &untrusted),
            not_active("Codex skips it: it is not trusted yet", TRUST_STEP)
        );
        assert_eq!(
            settle(&CODEX, true, None, &ON),
            Outcome::Active { changed: true }
        );
    }

    /// The program asked says it trusts and runs the hook, and Codex's config
    /// holds no record of that trust for this line: the hook is not active.
    /// The program asked is the first `codex` on the PATH, and another one
    /// placed in front of Codex answers in its place. A switch its answer does
    /// not cover still decides too.
    ///
    /// FAILS ON REVERT: answer `Outcome::Active { changed }` again in the
    /// `asked == Some(Ok(()))` arm of `settle`, and a yes from any program
    /// called `codex` reports a hook Codex skips as active.
    #[test]
    fn a_yes_from_the_program_asked_never_outranks_codexs_config() {
        for skip in [Skip::NotTrusted, Skip::Changed] {
            assert_eq!(
                settle(
                    &CODEX,
                    true,
                    Some(Ok(())),
                    &HookState::Off(Reason::Codex(skip))
                ),
                not_active(YES_NOT_IN_CONFIG, TRUST_STEP),
                "{skip:?}"
            );
        }
        assert_eq!(
            settle(&CODEX, true, Some(Ok(())), &ON),
            Outcome::Active { changed: true }
        );
        assert_eq!(
            settle(
                &CODEX,
                true,
                Some(Ok(())),
                &HookState::Off(Reason::Codex(Skip::HooksOff))
            ),
            not_active(
                "Codex skips it: hooks are switched off under [features]",
                "Take `hooks = false` and `codex_hooks = false` out of [features] in \
                 ~/.codex/config.toml"
            )
        );
        assert_eq!(
            settle(&GEMINI, true, None, &HookState::Off(Reason::GeminiHooksOff)),
            not_active(
                "Gemini skips it: hooks are switched off (`hooksConfig.enabled` is false)",
                "Set it to true in ~/.gemini/settings.json"
            )
        );
    }

    #[test]
    fn connecting_gemini_leaves_a_hook_that_is_on() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = Path::new(BIN);
        assert_eq!(
            connect(home.path(), &GEMINI, bin, false, true, None),
            Ok(Outcome::Active { changed: true })
        );
        assert_eq!(
            read(home.path(), GEMINI.file),
            json!({"hooks": {"BeforeTool": [gemini_entry(&GEMINI.command(bin, false, true))]}})
        );
        assert_eq!(
            connect(home.path(), &GEMINI, bin, false, true, None),
            Ok(Outcome::Active { changed: false })
        );
        // The other mode is a change.
        assert_eq!(
            connect(home.path(), &GEMINI, bin, false, false, None),
            Ok(Outcome::Active { changed: true })
        );
        assert_eq!(uninstall(home.path(), &GEMINI), Ok(1));
        assert_eq!(state(home.path(), &GEMINI, None), HookState::Absent);
    }

    /// The hook is written and Codex has not been asked: it is in the file,
    /// and it is not reported active.
    #[test]
    fn connecting_codex_without_its_trust_is_not_active() {
        let home = tempfile::TempDir::new().unwrap();
        assert_eq!(
            connect(home.path(), &CODEX, Path::new(BIN), false, false, None),
            Ok(not_active(
                "Codex skips it: it is not trusted yet",
                TRUST_STEP
            ))
        );
        assert_eq!(
            read(home.path(), CODEX.file),
            json!({"hooks": {"PreToolUse": [codex_entry(&CODEX_LINE)]}})
        );
    }

    #[test]
    fn connecting_codex_that_trusts_this_line_is_active() {
        let home = tempfile::TempDir::new().unwrap();
        let file = home.path().join(CODEX.file);
        write(home.path(), CODEX_CONFIG, &trusting(&file, 0, &CODEX_LINE));
        assert_eq!(
            connect(home.path(), &CODEX, Path::new(BIN), false, false, None),
            Ok(Outcome::Active { changed: true })
        );
        assert_eq!(
            connect(home.path(), &CODEX, Path::new(BIN), false, false, None),
            Ok(Outcome::Active { changed: false })
        );
        // The monitor line is another line: the trust does not carry over.
        assert_eq!(
            connect(home.path(), &CODEX, Path::new(BIN), false, true, None),
            Ok(not_active(
                "Codex skips it: it changed after it was trusted",
                TRUST_STEP
            ))
        );
    }

    /// A Codex that cannot be started is a Codex that could not be asked.
    #[test]
    fn connecting_codex_with_no_codex_program_is_not_active() {
        let home = tempfile::TempDir::new().unwrap();
        let missing = [OsString::from(home.path().join("no-such-codex"))];
        assert_eq!(
            connect(
                home.path(),
                &CODEX,
                Path::new(BIN),
                false,
                false,
                Some(&missing)
            ),
            Ok(not_active(
                "the `codex` program could not be started",
                TRUST_STEP
            ))
        );
    }

    /// `connect` against a stand-in for `codex app-server`
    /// ([`codex_trust::FAKE_APP_SERVER`]), run through `/bin/sh`.
    #[cfg(unix)]
    mod asking_codex {
        use super::*;

        /// The key Codex gives the hook `connect` writes into an empty file.
        fn key(home: &Path) -> String {
            format!("{}:pre_tool_use:0:0", CODEX.path(home).display())
        }

        /// The folder of a stand-in that serves the Codex folder under
        /// `home`. Its n-th listing shows the monitor hook `connect` writes
        /// there, in the n-th of `statuses`.
        fn stand_in(home: &Path, statuses: &[&str]) -> tempfile::TempDir {
            let dir = tempfile::TempDir::new().unwrap();
            let file = CODEX.path(home);
            std::fs::write(dir.path().join("codex.sh"), codex_trust::FAKE_APP_SERVER).unwrap();
            std::fs::write(
                dir.path().join("home"),
                file.parent().unwrap().display().to_string(),
            )
            .unwrap();
            for (n, status) in statuses.iter().enumerate() {
                let listing = json!({
                    "data": [{
                        "cwd": "/",
                        "hooks": [{
                            "key": key(home),
                            "eventName": "preToolUse",
                            "handlerType": "command",
                            "command": CODEX.command(Path::new(BIN), false, true),
                            "sourcePath": file.display().to_string(),
                            "enabled": true,
                            "currentHash": "sha256:feed",
                            "trustStatus": status,
                        }],
                        "warnings": [],
                        "errors": [],
                    }]
                });
                std::fs::write(
                    dir.path().join(format!("list{}", n + 1)),
                    listing.to_string(),
                )
                .unwrap();
            }
            dir
        }

        /// The words that start the stand-in in `dir`.
        fn codex(dir: &tempfile::TempDir) -> [OsString; 3] {
            [
                OsString::from("/bin/sh"),
                dir.path().join("codex.sh").into_os_string(),
                dir.path().as_os_str().to_os_string(),
            ]
        }

        /// The write request the stand-in received, when it received one.
        fn asked(dir: &tempfile::TempDir) -> Option<Value> {
            std::fs::read(dir.path().join("asked"))
                .ok()
                .map(|line| serde_json::from_slice(&line).expect("the request is JSON"))
        }

        /// Codex is asked about the line `connect` has just written, in the
        /// file it wrote it in, under the home it was given, and writes its
        /// record of trust into its config: the hook is active.
        ///
        /// FAILS ON REVERT: swap `home` and `&spec.path(home)` in the
        /// `codex_trust::grant` call of `connect_noting_write` (Codex is asked
        /// about the folder above the home and answers that it serves another
        /// one), or swap `block_review` and `monitor` in the line built for
        /// that call (Codex lists no hook with that line).
        #[test]
        fn connect_has_codex_trust_the_line_and_the_file_it_wrote() {
            let home = tempfile::TempDir::new().unwrap();
            let fake = stand_in(home.path(), &["untrusted", "trusted"]);
            std::fs::write(
                fake.path().join("config"),
                trusting(&CODEX.path(home.path()), 0, CODEX_MONITOR),
            )
            .unwrap();
            assert_eq!(
                connect(
                    home.path(),
                    &CODEX,
                    Path::new(BIN),
                    false,
                    true,
                    Some(&codex(&fake))
                ),
                Ok(Outcome::Active { changed: true })
            );
            assert_eq!(
                read(home.path(), CODEX.file),
                json!({"hooks": {"PreToolUse": [codex_entry(CODEX_MONITOR)]}})
            );
            assert_eq!(
                asked(&fake).map(|request| request["params"]["edits"][0]["keyPath"].clone()),
                Some(json!(format!(
                    "hooks.state.\"{}\".trusted_hash",
                    key(home.path())
                )))
            );
        }

        /// A program called `codex` in front of the real one answers that it
        /// trusts the hook and writes nothing. Codex's config holds no record
        /// for the line, Codex skips the hook, and connect says it is not
        /// active (measured on the binary before this check: "connected").
        ///
        /// FAILS ON REVERT: settle on the state read before the exchange is
        /// trusted, or answer `Active` for a yes in `settle`, and the hook
        /// is reported active.
        #[test]
        fn a_yes_that_leaves_no_record_in_codexs_config_is_not_active() {
            let home = tempfile::TempDir::new().unwrap();
            let fake = stand_in(home.path(), &["trusted"]);
            assert_eq!(
                connect(
                    home.path(),
                    &CODEX,
                    Path::new(BIN),
                    false,
                    true,
                    Some(&codex(&fake))
                ),
                Ok(not_active(YES_NOT_IN_CONFIG, TRUST_STEP))
            );
            assert!(!home.path().join(CODEX_CONFIG).exists());
            // A record for another line is not this one's trust either.
            write(
                home.path(),
                CODEX_CONFIG,
                &trusting(&CODEX.path(home.path()), 0, &CODEX_LINE),
            );
            let fake = stand_in(home.path(), &["trusted"]);
            assert_eq!(
                connect(
                    home.path(),
                    &CODEX,
                    Path::new(BIN),
                    false,
                    true,
                    Some(&codex(&fake))
                ),
                Ok(not_active(YES_NOT_IN_CONFIG, TRUST_STEP))
            );
        }

        /// The files read here say the hook is trusted, and the Codex that
        /// was asked says it is not: its no stands.
        ///
        /// FAILS ON REVERT: pass `None` where `asked` goes in the `settle`
        /// call of `connect_noting_write` and the trust in the config file
        /// makes the second connect active.
        #[test]
        fn a_no_from_the_codex_that_was_asked_outranks_the_files() {
            let home = tempfile::TempDir::new().unwrap();
            let file = CODEX.path(home.path());
            write(
                home.path(),
                CODEX_CONFIG,
                &trusting(&file, 0, CODEX_MONITOR),
            );
            // With no Codex to ask, the files decide, and they say yes.
            assert_eq!(
                connect(home.path(), &CODEX, Path::new(BIN), false, true, None),
                Ok(Outcome::Active { changed: true })
            );
            let fake = stand_in(home.path(), &["untrusted", "untrusted"]);
            assert_eq!(
                connect(
                    home.path(),
                    &CODEX,
                    Path::new(BIN),
                    false,
                    true,
                    Some(&codex(&fake))
                ),
                Ok(not_active("Codex still does not trust it", TRUST_STEP))
            );
            assert!(asked(&fake).is_some());
        }
    }

    #[test]
    fn the_connect_line_never_says_connected_for_a_hook_that_is_not_active() {
        let active = Outcome::Active { changed: true };
        assert_eq!(
            connect_line("codex", &CODEX, &active, false, true),
            "  codex - connected (PreToolUse hook, monitor (records, never blocks))"
        );
        assert_eq!(
            connect_line("gemini", &GEMINI, &active, true, false),
            "  gemini - connected (BeforeTool hook, strict)"
        );
        assert_eq!(
            connect_line("gemini", &GEMINI, &active, false, false),
            "  gemini - connected (BeforeTool hook)"
        );
        assert_eq!(
            connect_line(
                "codex",
                &CODEX,
                &Outcome::Active { changed: false },
                false,
                false
            ),
            "  codex - already guarded (PreToolUse hook, enforce)"
        );
        assert_eq!(
            connect_line(
                "codex",
                &CODEX,
                &not_active("Codex did not answer in time", TRUST_STEP),
                false,
                false
            ),
            "  codex - its PreToolUse hook is installed, but it is NOT active: Codex did not \
             answer in time. Run `/hooks` inside Codex and trust the innerwarden hook"
        );
    }

    /// Codex is asked for the home this process runs under and for no other:
    /// a test's home, or another account's, is not the one its Codex serves.
    /// The home named through a link to it is the same home.
    ///
    /// FAILS ON REVERT: read `||` as `&&` in `codex_to_ask` and the home
    /// named through a link is another one, so Codex is not asked.
    #[test]
    fn codex_is_asked_only_for_the_home_this_process_runs_under() {
        let elsewhere = tempfile::TempDir::new().unwrap();
        assert_eq!(codex_to_ask(elsewhere.path()), None);
        if let Ok(own) = hook::home_dir() {
            assert_eq!(codex_to_ask(&own), Some(vec![OsString::from("codex")]));
            #[cfg(unix)]
            if own.is_dir() {
                let link = elsewhere.path().join("home");
                std::os::unix::fs::symlink(&own, &link).unwrap();
                assert_eq!(codex_to_ask(&link), Some(vec![OsString::from("codex")]));
            }
        }
    }

    /// `CODEX_HOME` moves the folder Codex reads. Unset, empty, and the
    /// folder the hook is written in all leave the hook where Codex looks.
    /// Any other folder switches off a hook that is in the file, and leaves
    /// alone a file with no hook of ours to switch off.
    ///
    /// FAILS ON REVERT: take the `Some(folder) if state.installed()` arm out
    /// of `read_elsewhere` and the hook under another `CODEX_HOME` reads "on".
    #[test]
    fn a_codex_home_that_is_another_folder_switches_the_hook_off() {
        let home = tempfile::TempDir::new().unwrap();
        let ours = home.path().join(".codex");
        let other = home.path().join("elsewhere");
        let on = HookState::On {
            monitor: false,
            block_review: false,
        };

        assert_eq!(other_codex_home(home.path(), None), None);
        assert_eq!(other_codex_home(home.path(), Some(OsStr::new(""))), None);
        assert_eq!(other_codex_home(home.path(), Some(ours.as_os_str())), None);
        assert_eq!(
            other_codex_home(home.path(), Some(other.as_os_str())),
            Some(other.clone())
        );

        assert_eq!(read_elsewhere(home.path(), None, on.clone()), on);
        assert_eq!(
            read_elsewhere(home.path(), Some(ours.as_os_str()), on.clone()),
            on
        );
        assert_eq!(
            read_elsewhere(home.path(), Some(other.as_os_str()), on),
            HookState::Off(Reason::CodexElsewhere(other.clone()))
        );
        assert_eq!(
            read_elsewhere(
                home.path(),
                Some(other.as_os_str()),
                HookState::Off(Reason::Codex(Skip::NotTrusted))
            ),
            HookState::Off(Reason::CodexElsewhere(other.clone()))
        );
        for unwritten in [HookState::Absent, HookState::Unreadable] {
            assert_eq!(
                read_elsewhere(home.path(), Some(other.as_os_str()), unwritten.clone()),
                unwritten
            );
        }
    }

    /// A `CODEX_HOME` that reaches `<home>/.codex` through a link names the
    /// folder the hook is in.
    ///
    /// FAILS ON REVERT: take the `canonicalize` comparison out of
    /// `other_codex_home` and the link reads as another folder.
    #[cfg(unix)]
    #[test]
    fn a_codex_home_that_links_to_the_same_folder_is_the_same_folder() {
        let home = tempfile::TempDir::new().unwrap();
        let ours = home.path().join(".codex");
        std::fs::create_dir(&ours).unwrap();
        let link = home.path().join("codex-link");
        std::os::unix::fs::symlink(&ours, &link).unwrap();
        assert_eq!(other_codex_home(home.path(), Some(link.as_os_str())), None);
    }

    /// The line names the other folder and gives the step the live grant
    /// gives when Codex itself reports another home.
    ///
    /// FAILS ON REVERT: give `Reason::CodexElsewhere` any other step in
    /// `Reason::step` and the two no longer say one thing.
    #[test]
    fn a_hook_codex_reads_elsewhere_names_the_folder_and_the_step() {
        let state = HookState::Off(Reason::CodexElsewhere(PathBuf::from("/work/codex-home")));
        assert_eq!(
            state_line(&CODEX, &state),
            "PreToolUse hook: installed, but Codex does not read it: CODEX_HOME is set to \
             /work/codex-home. Start Codex without CODEX_HOME, then run `innerwarden agents \
             connect codex` again"
        );
        assert_eq!(
            not_on(&CODEX, &state),
            Some((
                "PreToolUse hook is installed, but Codex does not read it: CODEX_HOME is set \
                 to /work/codex-home"
                    .to_string(),
                grant_step(&CODEX, GrantError::OtherHome, &state),
            ))
        );
        assert_eq!(
            settle(&CODEX, true, None, &state),
            not_active(
                "Codex does not read it: CODEX_HOME is set to /work/codex-home",
                &grant_step(&CODEX, GrantError::OtherHome, &state)
            )
        );
    }

    /// The words `agents connect` and `status` print, whole.
    #[test]
    fn the_coverage_names_what_each_agent_leaves_unscreened() {
        let gone = |product: &str| {
            if cfg!(unix) {
                format!(
                    "If the innerwarden program the hook names is moved, removed or killed, \
                     {product} refuses every tool call in enforce mode and runs it unscreened \
                     in monitor mode (read in {product}'s source and run under sh with a \
                     stand-in guard, not measured on a running {product})."
                )
            } else {
                format!(
                    "If the innerwarden program the hook names is moved, removed or killed, \
                     {product} runs the tool: on Windows the hook line is the program alone."
                )
            }
        };
        assert_eq!(
            CODEX.coverage(),
            vec![
                "Screened before they run: shell commands, changes to privileged files through \
                 `apply_patch`, and calls to MCP servers behind the proxy. Its other tools are \
                 not screened."
                    .to_string(),
                "Not screened: `write_stdin` and `tool_search`. Codex does not run the hook for \
                 them, so a shell started in one call can be given any command through \
                 `write_stdin`, unscreened. In enforce mode a shell call that starts a shell, a \
                 language or a database client with nothing to run (`bash`, `python3`, `psql`) \
                 is refused for that reason; one started any other way that reads its input \
                 (`cat | sh`, a program of its own) is not seen."
                    .to_string(),
                "Codex runs the hook only while it trusts it. A changed hook line, \
                 `enabled = false`, `hooks = false` under [features] or `codex --disable hooks` \
                 switch it off without a word."
                    .to_string(),
                "The hook is written in ~/.codex. A Codex started with CODEX_HOME set to \
                 another folder reads its hooks there and does not run this one."
                    .to_string(),
                gone("Codex"),
                "Codex starts the hook line with your login shell (`$SHELL -lc`, else \
                 `/bin/sh -lc`), which runs its startup files before the guard: zsh ~/.zshenv, \
                 ~/.zprofile and ~/.zlogin, bash the first of ~/.bash_profile, ~/.bash_login \
                 and ~/.profile, sh ~/.profile. A line in one can end the hook before the guard \
                 answers. A shell change to ~/.zshenv is refused; a change to the others is \
                 refused through `apply_patch` and only flagged through the shell. A ZDOTDIR \
                 set in your environment moves zsh's files, and the guard does not read \
                 ZDOTDIR."
                    .to_string(),
                "Inline interpreter code that rewrites ~/.codex/hooks.json or \
                 ~/.codex/config.toml is refused by its text; code that builds the file's name \
                 from pieces is not seen."
                    .to_string(),
                "The guard answers within 10 seconds (more only while it waits on a second \
                 opinion you turned on) or refuses the call in enforce mode. If Codex stops the \
                 hook at its own limit of 60 seconds, or the hook's shell is killed, Codex runs \
                 the tool."
                    .to_string(),
                "Needs Codex CLI 0.166.0 or later. Codex runs a PreToolUse hook for its shell \
                 and `apply_patch` from 0.124.0 and asks for trust from 0.129.0, but before \
                 0.166.0 the folder it sends is the session's, not the command's, so a command \
                 run in another folder is judged in the wrong one."
                    .to_string(),
                "Measured on Linux with Codex CLI 0.170.0 and on macOS with Codex CLI 0.167.2."
                    .to_string(),
            ]
        );
        assert_eq!(
            GEMINI.coverage(),
            vec![
                "Screened before they run: shell commands, changes to privileged files through \
                 `write_file` and `replace`, reads of secrets through `read_file`, \
                 `read_many_files`, `glob` and `grep_search`, and calls to MCP servers behind \
                 the proxy. Its other tools are not screened."
                    .to_string(),
                "Gemini skips the hook in a folder it does not trust, and when user or project \
                 settings switch hooks off or disable this one. Project settings are not read \
                 here."
                    .to_string(),
                gone("Gemini"),
                "The guard answers within 10 seconds (more only while it waits on a second \
                 opinion you turned on) or refuses the call in enforce mode. If Gemini stops \
                 the hook at its own limit of 60 seconds, or the hook's shell is killed, Gemini \
                 runs the tool."
                    .to_string(),
                "Needs Gemini CLI 0.26.0 or later: before it, Gemini runs no hook unless \
                 `hooks.enabled` is set. From 0.30.0 Gemini refuses a tool call on any hook exit \
                 but 0 and 1, so on Linux and macOS the monitor line turns every other end of \
                 the guard into 1."
                    .to_string(),
                "Judged only by its payload, not on a running Gemini, which needs a Google login."
                    .to_string(),
            ]
        );
    }

    /// `status` prints the two halves apart: the first line of the coverage
    /// is the screened half, and every line after it is a gap.
    #[test]
    fn the_coverage_is_what_is_screened_and_then_every_gap() {
        assert_eq!(
            CODEX.screened(),
            "shell commands, changes to privileged files through `apply_patch`, and calls to MCP \
             servers behind the proxy. Its other tools are not screened."
        );
        assert_eq!(
            GEMINI.screened(),
            "shell commands, changes to privileged files through `write_file` and `replace`, \
             reads of secrets through `read_file`, `read_many_files`, `glob` and `grep_search`, \
             and calls to MCP servers behind the proxy. Its other tools are not screened."
        );
        for spec in [&CODEX, &GEMINI] {
            let coverage = spec.coverage();
            assert_eq!(
                coverage[0],
                format!("Screened before they run: {}", spec.screened())
            );
            assert_eq!(coverage[1..], spec.gaps()[..]);
        }
        assert_eq!(CODEX.gaps().len(), 9);
        assert_eq!(GEMINI.gaps().len(), 5);
    }

    /// Under a hook that is active: the whole coverage. Under one that is
    /// not: one line that says the shell and the file tools run unscreened,
    /// and nothing that reads as coverage.
    #[test]
    fn the_notes_under_connect_follow_whether_the_hook_is_active() {
        assert_eq!(
            connect_notes(&CODEX, &Outcome::Active { changed: true }),
            CODEX.coverage()
        );
        assert_eq!(
            connect_notes(&GEMINI, &Outcome::Active { changed: false }),
            GEMINI.coverage()
        );
        assert_eq!(
            connect_notes(
                &CODEX,
                &not_active("Codex did not answer in time", TRUST_STEP)
            ),
            vec![
                "Until the hook is active, only calls to MCP servers behind the proxy are \
                 screened. Codex's shell commands and file changes run unscreened."
                    .to_string()
            ]
        );
    }

    /// What `status` says of a hook that does not screen, and the one thing
    /// to try: a command with no "Run: " in front, or the step in words.
    #[test]
    fn a_hook_that_is_not_on_is_told_with_one_thing_to_try() {
        let told = |what: &str, next: &str| Some((what.to_string(), next.to_string()));
        assert_eq!(not_on(&CODEX, &ON), None);
        assert_eq!(
            not_on(&CODEX, &HookState::Absent),
            told(
                "PreToolUse hook is not installed",
                "innerwarden agents connect codex"
            )
        );
        assert_eq!(
            not_on(&GEMINI, &HookState::Unreadable),
            told(
                "BeforeTool hook is unknown: ~/.gemini/settings.json could not be read",
                "Fix ~/.gemini/settings.json or move it aside, then run `innerwarden agents \
                 connect gemini`"
            )
        );
        assert_eq!(
            not_on(&CODEX, &HookState::Off(Reason::Codex(Skip::NotTrusted))),
            told(
                "PreToolUse hook is installed, but Codex skips it: it is not trusted yet",
                "innerwarden agents connect codex"
            )
        );
        assert_eq!(
            not_on(&CODEX, &HookState::Off(Reason::Codex(Skip::SwitchedOff))),
            told(
                "PreToolUse hook is installed, but Codex skips it: it is switched off \
                 (`enabled = false`)",
                "Switch it back on with `/hooks` inside Codex"
            )
        );
        assert_eq!(
            not_on(&GEMINI, &HookState::Off(Reason::GeminiHookDisabled)),
            told(
                "BeforeTool hook is installed, but Gemini skips it: it is listed under \
                 `hooksConfig.disabled`",
                "Take it out of that list in ~/.gemini/settings.json"
            )
        );
    }

    /// A Codex hook 1.6.15 wrote, whose refusal does not name Cursor's file
    /// yet, is the entry `agents connect` writes: on when Codex trusts the
    /// line the file holds, and skipped when Codex only trusts today's line
    /// (Codex trusts the bytes it read).
    ///
    /// FAILS ON REVERT of `current` in `judge` (the old line is "altered"),
    /// or of the file's own line in the trust check (a trusted old line is
    /// reported skipped).
    #[cfg(unix)]
    #[test]
    fn a_1615_line_is_judged_as_todays() {
        let old = CODEX_LINE.replacen(hook::FAIL_CLOSED_TAIL, hook::FAIL_CLOSED_TAIL_1615, 1);
        assert_ne!(old, *CODEX_LINE);
        let settings = json!({"hooks": {"PreToolUse": [codex_entry(&old)]}});
        let file = Path::new("/home/me/.codex/hooks.json");
        assert_eq!(
            judged_codex(&settings, Some(&trusting(file, 0, &old))),
            HookState::On {
                monitor: false,
                block_review: false
            }
        );
        assert!(matches!(
            judged_codex(&settings, Some(&trusting(file, 0, &CODEX_LINE))),
            HookState::Off(Reason::Codex(_))
        ));
    }

    /// Entries of the shape connect writes that run another program are
    /// "another program", named with this one; a link to this program, and
    /// the program itself, are this one; a state that is not installed or is
    /// already altered stays as it was.
    #[cfg(unix)]
    #[test]
    fn a_cursor_hook_that_runs_another_program_is_said() {
        let home = tempfile::TempDir::new().unwrap();
        let home = home.path();
        let real = home.join("bin/innerwarden");
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        std::fs::write(&real, "").unwrap();
        let link = home.join("bin/iw-link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let on = HookState::On {
            monitor: false,
            block_review: false,
        };
        let wire = |program: &Path| {
            let line = CURSOR.command(program, false, false);
            write(
                home,
                CURSOR.file,
                &merge(json!(null), &CURSOR, &line).unwrap().to_string(),
            );
        };

        wire(Path::new(BIN));
        let said = cursor_runs_this(home, on.clone(), &real, None);
        let HookState::Off(reason @ Reason::OtherProgram { .. }) = &said else {
            panic!("{said:?}");
        };
        let why = reason.why(&CURSOR);
        assert!(
            why.contains(BIN) && why.contains(&real.display().to_string()),
            "{why}"
        );
        assert!(not_on(&CURSOR, &said).is_some());

        wire(&real);
        assert_eq!(cursor_runs_this(home, on.clone(), &real, None), on);
        wire(&link);
        assert_eq!(
            cursor_runs_this(home, on.clone(), &real, None),
            on,
            "a link to it"
        );
        // A program Codex's hook of ours runs is the guard too: status may be
        // started from another copy than the one connect wired.
        write(
            home,
            CODEX.file,
            &json!({"hooks": {"PreToolUse": [codex_entry(&CODEX_LINE)]}}).to_string(),
        );
        wire(Path::new(BIN));
        assert_eq!(
            cursor_runs_this(home, on.clone(), &real, None),
            on,
            "Codex's program"
        );
        std::fs::remove_file(home.join(CODEX.file)).unwrap();
        let altered = HookState::Off(Reason::Altered);
        assert_eq!(
            cursor_runs_this(home, altered.clone(), &real, None),
            altered
        );
        assert_eq!(
            cursor_runs_this(home, HookState::Absent, &real, None),
            HookState::Absent
        );
    }

    /// A bare program name is the first file of that name on PATH.
    #[cfg(unix)]
    #[test]
    fn a_bare_program_name_is_looked_up_on_path() {
        let dir = tempfile::TempDir::new().unwrap();
        let real = dir.path().join("innerwarden");
        std::fs::write(&real, "").unwrap();
        let path = std::ffi::OsString::from(dir.path());
        assert!(runs_binary("innerwarden", &real, Some(&path)));
        assert!(!runs_binary("innerwarden", &real, None));
        assert!(!runs_binary("other", &real, Some(&path)));
    }

    /// Status says Cursor's hooks are gone from the file, and that an edit
    /// of the agent's can take them out.
    #[test]
    fn cursor_hooks_not_in_the_file_are_said_as_such() {
        let (what, next) = not_on(&CURSOR, &HookState::Absent).unwrap();
        assert!(what.contains("not in ~/.cursor/hooks.json"), "{what}");
        assert!(what.contains("edit"), "{what}");
        assert_eq!(next, "innerwarden agents connect cursor");
    }

    fn cursor_file() -> Value {
        let line = CURSOR.command(Path::new(BIN), false, false);
        merge(json!(null), &CURSOR, &line).unwrap()
    }

    /// The hook refuses while Cursor's file has lost part of the guard: one
    /// event's entry taken out, `failClosed` turned off, a file that is not
    /// JSON. A whole file, and a file with nothing of ours left, are not
    /// refused here (Cursor runs no hook of ours from the second).
    #[test]
    fn cursor_wiring_lost_is_said_until_it_is_put_back() {
        let home = tempfile::TempDir::new().unwrap();
        let home = home.path();
        let lost = |home: &Path| cursor_wiring_lost_for(home, Some(Path::new(BIN)), None);
        assert_eq!(lost(home), None, "no file");
        let whole = cursor_file();
        write(home, CURSOR.file, &whole.to_string());
        assert_eq!(lost(home), None, "whole");

        let mut no_read = whole.clone();
        no_read["hooks"]
            .as_object_mut()
            .unwrap()
            .remove(crate::cursor_hook::READ_EVENT);
        write(home, CURSOR.file, &no_read.to_string());
        let why = lost(home).expect("an event without the entry");
        assert!(why.contains(".cursor/hooks.json"), "{why}");
        assert!(why.contains(crate::cursor_hook::READ_EVENT), "{why}");

        let mut open = whole.clone();
        open["hooks"][crate::cursor_hook::MCP_EVENT][0]["failClosed"] = json!(false);
        write(home, CURSOR.file, &open.to_string());
        assert!(lost(home).is_some(), "failClosed off");

        write(home, CURSOR.file, "{ not json");
        assert!(lost(home).is_some(), "unreadable");

        write(
            home,
            CURSOR.file,
            &json!({"version": 1, "hooks": {}}).to_string(),
        );
        assert_eq!(lost(home), None, "nothing of ours left");

        write(home, CURSOR.file, &whole.to_string());
        assert_eq!(lost(home), None, "put back");

        // The whole file, for another program than this one.
        let elsewhere = cursor_wiring_lost_for(home, Some(Path::new("/usr/local/bin/iw")), None)
            .expect("another program");
        assert!(elsewhere.contains("another program"), "{elsewhere}");
    }

    /// Connect and disconnect keep the person's keys in their order in
    /// Cursor's and Gemini's files: only the hook goes in or out.
    ///
    /// FAILS ON REVERT of `json_order::pretty_in_order` in `install` and
    /// `uninstall`: the keys come back sorted.
    #[test]
    fn connect_keeps_the_order_of_the_persons_keys() {
        let home = tempfile::TempDir::new().unwrap();
        let home = home.path();
        let cursor = r#"{"version":1,"zeta":true,"hooks":{"stop":[{"command":"./after.sh"}],"afterFileEdit":[{"command":"./fmt.sh"}]},"alpha":2}"#;
        let gemini = r#"{"theme":"dark","model":{"name":"x"},"auth":{"type":"y"}}"#;
        write(home, CURSOR.file, cursor);
        write(home, GEMINI.file, gemini);
        for spec in [&CURSOR, &GEMINI] {
            assert!(install(home, spec, Path::new(BIN), false, false).unwrap());
        }
        let text = std::fs::read_to_string(home.join(CURSOR.file)).unwrap();
        let at = |key: &str| {
            text.find(&format!("\"{key}\""))
                .unwrap_or_else(|| panic!("{key} in {text}"))
        };
        assert!(
            at("version") < at("zeta") && at("zeta") < at("hooks") && at("hooks") < at("alpha"),
            "{text}"
        );
        assert!(
            at("stop") < at("afterFileEdit")
                && at("afterFileEdit") < at(crate::cursor_hook::SHELL_EVENT),
            "{text}"
        );
        let text = std::fs::read_to_string(home.join(GEMINI.file)).unwrap();
        let at = |key: &str| {
            text.find(&format!("\"{key}\""))
                .unwrap_or_else(|| panic!("{key} in {text}"))
        };
        assert!(
            at("theme") < at("model") && at("model") < at("auth") && at("auth") < at("hooks"),
            "{text}"
        );

        assert!(uninstall(home, &CURSOR).unwrap() > 0);
        let text = std::fs::read_to_string(home.join(CURSOR.file)).unwrap();
        let at = |key: &str| {
            text.find(&format!("\"{key}\""))
                .unwrap_or_else(|| panic!("{key} in {text}"))
        };
        assert!(
            at("version") < at("zeta") && at("zeta") < at("hooks") && at("hooks") < at("alpha"),
            "{text}"
        );
        assert!(at("stop") < at("afterFileEdit"), "{text}");
    }
}

/// The Antigravity CLI's wiring: the guard's own name in its hooks file, a
/// disconnect that gives back the file it found to the byte, and the switch
/// that turns the hook off.
#[cfg(test)]
mod antigravity_tests {
    use super::*;

    const BIN: &str = "/opt/iw/innerwarden";

    fn runs(_: &str) -> hook::ProgramFact {
        hook::ProgramFact::Executable
    }

    fn file(home: &Path) -> PathBuf {
        ANTIGRAVITY.path(home)
    }

    fn put(home: &Path, body: &str) {
        let path = file(home);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn bytes(home: &Path) -> String {
        std::fs::read_to_string(file(home)).unwrap()
    }

    fn state_of(home: &Path) -> HookState {
        state_with(home, &ANTIGRAVITY, runs)
    }

    /// A hooks file as a person keeps it: four spaces, a hook of their own
    /// under another name, keys in their order.
    const THEIRS: &str = "{\n    \"my-linter\": {\n        \"PostToolUse\": [\n            {\n                \"matcher\": \"write_to_file\",\n                \"hooks\": [{\"command\": \"./lint.sh\"}]\n            }\n        ]\n    },\n    \"enabled-gate\": {\"enabled\": false, \"PreToolUse\": []}\n}\n";

    /// Connect writes one group under the guard's own name, matching every
    /// tool, and touches no byte of the person's; the hook is on; a second
    /// connect writes nothing; disconnect gives back the file it found, to
    /// the byte.
    ///
    /// FAILS ON REVERT: write the file whole (`pretty_in_order`) instead of
    /// `antigravity_body`, and the person's four-space file comes back in two.
    #[test]
    fn connect_adds_only_our_name_and_disconnect_gives_the_bytes_back() {
        let home = tempfile::TempDir::new().unwrap();
        put(home.path(), THEIRS);
        assert!(install(home.path(), &ANTIGRAVITY, Path::new(BIN), false, false).unwrap());
        let written = bytes(home.path());
        assert!(
            written.starts_with(THEIRS.trim_end().trim_end_matches('}').trim_end()),
            "the person's bytes stay first, as they were: {written}"
        );
        let value: Value = serde_json::from_str(&written).unwrap();
        let command = ANTIGRAVITY.command(Path::new(BIN), false, false);
        assert_eq!(
            value[crate::antigravity_hook::HOOK_NAME],
            json!({"PreToolUse": [{
                "matcher": "",
                "hooks": [{"type": "command", "command": command, "timeout": 60}],
            }]})
        );
        assert_eq!(
            state_of(home.path()),
            HookState::On {
                monitor: false,
                block_review: false
            }
        );
        assert!(!install(home.path(), &ANTIGRAVITY, Path::new(BIN), false, false).unwrap());
        assert_eq!(
            bytes(home.path()),
            written,
            "a second connect writes nothing"
        );

        assert_eq!(uninstall(home.path(), &ANTIGRAVITY).unwrap(), 1);
        assert_eq!(bytes(home.path()), THEIRS);
        assert_eq!(state_of(home.path()), HookState::Absent);
        assert_eq!(uninstall(home.path(), &ANTIGRAVITY).unwrap(), 0);
    }

    /// A mode switch rewrites our member and nothing else, and the
    /// disconnect after it still gives back the file it first found.
    #[test]
    fn a_mode_switch_and_then_a_disconnect_give_the_bytes_back() {
        let home = tempfile::TempDir::new().unwrap();
        put(home.path(), "{\"a\":1}");
        install(home.path(), &ANTIGRAVITY, Path::new(BIN), false, false).unwrap();
        assert!(install(home.path(), &ANTIGRAVITY, Path::new(BIN), false, true).unwrap());
        assert_eq!(
            state_of(home.path()),
            HookState::On {
                monitor: true,
                block_review: false
            }
        );
        assert!(bytes(home.path()).starts_with("{\"a\":1,\n  \"innerwarden\""));
        uninstall(home.path(), &ANTIGRAVITY).unwrap();
        assert_eq!(bytes(home.path()), "{\"a\":1}");
    }

    /// With no file, connect creates one that holds only our name, and the
    /// disconnect that empties it removes it.
    #[test]
    fn a_file_connect_created_goes_with_the_disconnect() {
        let home = tempfile::TempDir::new().unwrap();
        install(home.path(), &ANTIGRAVITY, Path::new(BIN), false, false).unwrap();
        assert!(file(home.path()).is_file());
        assert_eq!(uninstall(home.path(), &ANTIGRAVITY).unwrap(), 1);
        assert!(!file(home.path()).exists());
    }

    /// A hooks file that is a link is refused by connect and by disconnect,
    /// in words that say so: nothing is written through it and the file it
    /// points to stays.
    ///
    /// FAILS ON REVERT: drop `refuse_a_link`, and the refusal is the read's
    /// "too many levels of symbolic links", which does not say what to do.
    #[cfg(unix)]
    #[test]
    fn a_hooks_file_that_is_a_link_is_refused() {
        let home = tempfile::TempDir::new().unwrap();
        let elsewhere = home.path().join("dotfiles-hooks.json");
        std::fs::write(&elsewhere, "{}\n").unwrap();
        let path = file(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        let refused = uninstall(home.path(), &ANTIGRAVITY).expect_err("disconnect through a link");
        assert!(refused.contains("is a link"), "{refused}");
        let refused = install(home.path(), &ANTIGRAVITY, Path::new(BIN), false, false)
            .expect_err("connect through a link");
        assert!(refused.contains("is a link"), "{refused}");
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "{}\n");

        // Our entry already behind the link (a link made after the connect).
        std::fs::remove_file(&path).unwrap();
        install(home.path(), &ANTIGRAVITY, Path::new(BIN), false, false).unwrap();
        std::fs::rename(&path, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        let held = std::fs::read_to_string(&elsewhere).unwrap();
        let refused = uninstall(home.path(), &ANTIGRAVITY).expect_err("disconnect through a link");
        assert!(refused.contains("is a link"), "{refused}");
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), held);
        assert!(std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    /// A file the person reformatted after the connect is still put right:
    /// our name comes out, everything else reads as it did.
    #[test]
    fn a_reformatted_file_is_still_disconnected() {
        let home = tempfile::TempDir::new().unwrap();
        put(home.path(), THEIRS);
        install(home.path(), &ANTIGRAVITY, Path::new(BIN), false, false).unwrap();
        let value: Value = serde_json::from_str(&bytes(home.path())).unwrap();
        put(home.path(), &value.to_string());
        assert_eq!(uninstall(home.path(), &ANTIGRAVITY).unwrap(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(&bytes(home.path())).unwrap(),
            serde_json::from_str::<Value>(THEIRS).unwrap()
        );
    }

    /// `enabled: false` under our name is a hook Antigravity skips: off,
    /// with the reason; a connect takes the switch out and it is on again.
    /// A hook the person put under our name stays through the disconnect.
    ///
    /// FAILS ON REVERT: drop the Antigravity arm of `switched_off` in
    /// `judge`, and a hook Antigravity skips reads as on.
    #[test]
    fn enabled_false_is_off_and_connect_turns_it_back_on() {
        let home = tempfile::TempDir::new().unwrap();
        install(home.path(), &ANTIGRAVITY, Path::new(BIN), false, false).unwrap();
        let mut value: Value = serde_json::from_str(&bytes(home.path())).unwrap();
        value["innerwarden"]["enabled"] = json!(false);
        value["innerwarden"]["Stop"] = json!([{"command": "./mine.sh"}]);
        put(home.path(), &value.to_string());
        assert_eq!(
            state_of(home.path()),
            HookState::Off(Reason::AntigravityDisabled)
        );
        let line = state_line(&ANTIGRAVITY, &state_of(home.path()));
        assert!(
            line.contains("enabled") && line.contains("agents connect antigravity"),
            "{line}"
        );

        install(home.path(), &ANTIGRAVITY, Path::new(BIN), false, false).unwrap();
        assert!(state_of(home.path()).is_on());
        uninstall(home.path(), &ANTIGRAVITY).unwrap();
        let left: Value = serde_json::from_str(&bytes(home.path())).unwrap();
        assert_eq!(
            left,
            json!({"innerwarden": {"Stop": [{"command": "./mine.sh"}]}})
        );
    }

    /// A group of ours with a matcher of someone else's, or a second copy,
    /// is not the entry connect writes: off, so `status` says so.
    #[test]
    fn an_altered_entry_is_off() {
        let home = tempfile::TempDir::new().unwrap();
        install(home.path(), &ANTIGRAVITY, Path::new(BIN), false, false).unwrap();
        let mut value: Value = serde_json::from_str(&bytes(home.path())).unwrap();
        value["innerwarden"]["PreToolUse"][0]["matcher"] = json!("view_file");
        put(home.path(), &value.to_string());
        assert_eq!(state_of(home.path()), HookState::Off(Reason::Altered));
    }

    /// The enforcing line is the script that answers with a deny of its own
    /// when the guard does not; the monitor line is the guard alone. Both are
    /// read back as ours, in their mode, for this agent.
    #[test]
    fn the_lines_are_read_back_as_ours() {
        let enforce = ANTIGRAVITY.command(Path::new(BIN), false, false);
        if cfg!(unix) {
            assert!(
                enforce.starts_with("/bin/sh -c '\"$0\" hook --agent antigravity; s=$?"),
                "{enforce}"
            );
            assert!(enforce.contains("decision"), "{enforce}");
        }
        let monitor = ANTIGRAVITY.command(Path::new(BIN), false, true);
        assert_eq!(
            monitor,
            "\"/opt/iw/innerwarden\" hook --monitor --agent antigravity"
        );
        for (line, is_monitor) in [(enforce, false), (monitor, true)] {
            let read = hook::read_hook_line(&json!({ "command": line })).expect("ours");
            assert_eq!(read.monitor, is_monitor);
            assert_eq!(read.agent.as_deref(), Some("antigravity"));
            assert_eq!(read.program, BIN);
        }
    }
}
