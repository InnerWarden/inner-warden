//! `innerwarden install claude-code` - wire the guardrail into Claude Code as a
//! fail-closed PreToolUse hook on `Bash` and on its file tools
//! (`Write|Edit|MultiEdit|NotebookEdit`, see [`crate::file_tools`]), in ONE
//! command, offline.
//!
//! Unlike the Linux `innerwarden agent install-hook` (which POSTs to a running
//! agent over HTTPS via a bash+python3+curl script), this points the hook
//! straight at `innerwarden hook` - the in-process adapter that reads Claude's tool
//! call on stdin, runs the check-command engine locally, and blocks (exit 2) on a
//! dangerous verdict. No agent, no HTTP, no python3: just the binary. So the same
//! one command works on Windows, macOS, and Linux.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

/// Resolve the user home directory cross-platform (`USERPROFILE` on Windows,
/// `HOME` elsewhere).
pub fn home_dir() -> Result<PathBuf, String> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(var)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{var} is not set; pass --settings explicitly"))
}

/// What was installed, for the caller's report.
#[derive(Debug)]
pub struct Report {
    pub settings_path: PathBuf,
    pub hook_command: String,
    pub block_review: bool,
    /// Monitor (observe-only) mode: the hook records every screened command into
    /// the graph but NEVER blocks. Gives the live dashboard/narrative without the
    /// guardrail denying day-to-day dev commands. Overrides `block_review`.
    pub monitor: bool,
    /// Whether Claude Code actually looks installed here (a `claude` binary on
    /// PATH, or a pre-existing `~/.claude`). When false the caller says so
    /// honestly instead of claiming the hook is "wired into Claude Code".
    pub claude_code_detected: bool,
}

pub(crate) enum AutomaticHookInstall {
    Installed(Report),
    SkippedExisting,
}

/// True when a `claude` executable is on PATH (Linux/macOS/Windows names).
fn claude_on_path() -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths).any(|dir| {
                dir.join("claude").is_file()
                    || dir.join("claude.cmd").is_file()
                    || dir.join("claude.exe").is_file()
            })
        })
        .unwrap_or(false)
}

/// True when `~/.claude` is a MEANINGFUL sign of Claude Code, not just an empty
/// leftover directory: it holds `settings.json` or has at least one entry. An
/// empty `~/.claude` (which other tools, or a re-run, can leave behind) does not
/// count, so the install message stays honest.
fn claude_dir_configured(home: &Path) -> bool {
    let dir = home.join(".claude");
    if dir.join("settings.json").exists() {
        return true;
    }
    fs::read_dir(&dir)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

/// Decide whether Claude Code looks present: a `claude` on PATH (`on_path`), or a
/// meaningful `~/.claude` (`dir_configured`). Both signals are injected so this is
/// pure and deterministic in tests regardless of the machine.
fn detect_claude_code(on_path: bool, dir_configured: bool) -> bool {
    on_path || dir_configured
}

/// Idempotently install one InnerWarden hook that covers `PreToolUse:Bash`.
/// Existing keys and unrelated hooks are preserved. A previous InnerWarden hook
/// under a matcher that certainly includes Bash is replaced in place (and
/// accidental duplicates are collapsed), so switching monitor/enforce never
/// leaves an older enforcing hook active beside the new one.
/// Idempotently install the `PostToolUse` half of the guard.
///
/// PreToolUse alone can only ever see the command. That is why the two-step
/// attack worked: a value that arrived inside a file the agent READ is
/// indistinguishable, at the moment of the next command, from one the operator
/// typed. This hook is what carries tool RESULTS in, so the next command can be
/// judged on where its arguments came from.
///
/// The matcher is `*` on purpose. The dangerous result is as likely to come
/// from a web page, an MCP response or a grep as from a file read, and
/// enumerating tool names here would leave the gap exactly where the next agent
/// adds a tool.
///
/// This hook can never refuse anything: by the time it runs the tool has
/// already run. It is pure observation, so unlike the PreToolUse merge there is
/// no matcher-coverage or block-mode reasoning to get wrong.
pub fn merge_posttooluse_hook(mut settings: Value, hook_command: &str) -> Value {
    if !settings.is_object() {
        settings = json!({});
    }
    let obj = settings.as_object_mut().expect("object");
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let post = hooks
        .as_object_mut()
        .expect("object")
        .entry("PostToolUse")
        .or_insert_with(|| json!([]));
    if !post.is_array() {
        *post = json!([]);
    }
    let arr = post.as_array_mut().expect("array");

    // Drop any previous InnerWarden PostToolUse hook wherever it sits, so a
    // reinstall with a new binary path does not leave the old one behind. An
    // entry whose hook list becomes empty is removed with it; operator hooks in
    // the same entry are untouched.
    // The fields InnerWarden does not own on the first such hook (the
    // `timeout` `install` or the operator set) are kept on the new one, as
    // the PreToolUse merge keeps them: a rewrite dropped them.
    let mut kept: Option<serde_json::Map<String, Value>> = None;
    arr.retain_mut(|entry| {
        let Some(list) = entry.get_mut("hooks").and_then(Value::as_array_mut) else {
            return true;
        };
        let was_empty = list.is_empty();
        list.retain(|hook| {
            if !is_iwguard_hook(hook) {
                return true;
            }
            if kept.is_none() {
                kept = hook.as_object().cloned();
            }
            false
        });
        was_empty || !list.is_empty()
    });

    let mut hook = kept.unwrap_or_default();
    hook.insert("type".into(), json!("command"));
    hook.insert("command".into(), json!(hook_command));
    arr.push(json!({
        "matcher": "*",
        "hooks": [ Value::Object(hook) ]
    }));
    settings
}

pub fn merge_pretooluse_bash_hook(mut settings: Value, hook_command: &str) -> Value {
    if !settings.is_object() {
        settings = json!({});
    }
    let obj = settings.as_object_mut().expect("object");
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let pre = hooks
        .as_object_mut()
        .expect("object")
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));
    if !pre.is_array() {
        *pre = json!([]);
    }
    let arr = pre.as_array_mut().expect("array");
    let replacement = json!({
        "matcher": "Bash",
        "hooks": [ { "type": "command", "command": hook_command } ]
    });
    let replacement_hook = replacement["hooks"][0].clone();
    let replacing_innerwarden = is_iwguard_hook(&replacement_hook);
    let mut installed = false;
    arr.retain_mut(|entry| {
        // The file-tools and read-tools entries are the other halves of the
        // same wiring, kept by `merge_pretooluse_file_hook` and
        // `merge_pretooluse_read_hook`; collapsing their hook as a duplicate
        // would make every reinstall rewrite the file.
        if is_file_tools_entry(entry) || is_read_tools_entry(entry) {
            return true;
        }
        let is_bash_entry = bash_matcher_coverage(entry) == BashMatcherCoverage::Includes;
        let Some(hooks) = entry.get_mut("hooks").and_then(Value::as_array_mut) else {
            return true;
        };
        let was_empty = hooks.is_empty();
        hooks.retain_mut(|hook| {
            let same_command = hook.get("command").and_then(Value::as_str) == Some(hook_command);
            let matches = same_command || (replacing_innerwarden && is_iwguard_hook(hook));
            if !matches {
                return true;
            }
            if !installed && is_bash_entry {
                // Change only the fields InnerWarden owns. Operator fields on
                // our hook (for example Claude's `timeout`) survive a mode flip.
                if let Some(object) = hook.as_object_mut() {
                    object.insert("type".into(), json!("command"));
                    object.insert("command".into(), json!(hook_command));
                } else {
                    *hook = replacement_hook.clone();
                }
                installed = true;
                true
            } else {
                // Collapse duplicate InnerWarden hooks. When the old hook lives
                // under a non-Bash matcher, remove just that hook and install a
                // canonical Bash entry below without affecting its neighbours.
                false
            }
        });
        // Empty operator-owned entries can be meaningful to Claude. Only drop
        // an entry that became empty because its InnerWarden hook was removed.
        was_empty || !hooks.is_empty()
    });
    if !installed {
        // Preserve unrelated entries. A canonical entry is appended when the
        // previous InnerWarden hook used a different matcher or did not exist.
        arr.push(replacement);
    }
    settings
}

/// The longest an InnerWarden hook takes to answer or refuse, in seconds:
/// the hook's own limit on the clock (`hook_net::WALL_CAP`, 25 s) plus the
/// one wait it may add on purpose, a second opinion's 20 s. Past it the hook
/// has ended itself, refusing the call in enforce.
pub const HOOK_LONGEST_SECS: u64 = 45;

/// The `timeout` `install` writes on each InnerWarden hook line for Claude
/// Code, in seconds. Without one Claude Code waits 600 s for a hook, and a
/// hook it stops waiting for is a non-blocking error: the call runs. So it
/// is above [`HOOK_LONGEST_SECS`], where the hook's own refusal always comes
/// first. Measured on 2026-11-19 (4 cores): a hook answers in 0.19 s at the
/// median and 0.38 s at most with nothing else running, 1.6 s at most during
/// a `cargo build` (load 10), with about 40 ms of its own CPU.
pub const HOOK_TIMEOUT_SECS: u64 = 50;

// The hook's own refusal comes before Claude Code stops waiting, and the
// wait stays well under Claude Code's 600 s default.
const _: () = assert!(HOOK_LONGEST_SECS < HOOK_TIMEOUT_SECS && HOOK_TIMEOUT_SECS < 600);

/// PURE: every InnerWarden hook line, before or after a tool runs, with a
/// `timeout` of [`HOOK_TIMEOUT_SECS`] where it has none. A `timeout` already
/// on a line (the operator's) is kept as it is; nothing else changes.
pub fn with_hook_timeouts(mut settings: Value) -> Value {
    for event in ["PreToolUse", "PostToolUse"] {
        let Some(entries) = settings
            .get_mut("hooks")
            .and_then(|hooks| hooks.get_mut(event))
            .and_then(Value::as_array_mut)
        else {
            continue;
        };
        for hook in entries
            .iter_mut()
            .filter_map(|entry| entry.get_mut("hooks").and_then(Value::as_array_mut))
            .flatten()
        {
            if !is_iwguard_hook(hook) {
                continue;
            }
            if let Some(object) = hook.as_object_mut() {
                object
                    .entry("timeout")
                    .or_insert_with(|| json!(HOOK_TIMEOUT_SECS));
            }
        }
    }
    settings
}

/// What Claude Code's settings say of how long it waits for the InnerWarden
/// hook that screens Bash: `None` when there is no such hook, `Some(None)`
/// when it names no `timeout` (Claude Code then waits 600 s), else the
/// seconds. Of several such lines, the shortest wait.
pub fn iwguard_bash_hook_timeout(settings: &Value) -> Option<Option<u64>> {
    let waits: Vec<Option<u64>> = settings
        .get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| bash_matcher_coverage(entry) == BashMatcherCoverage::Includes)
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter(|hook| is_iwguard_hook(hook))
        .map(|hook| {
            hook.get("timeout").and_then(|t| {
                t.as_u64()
                    .or_else(|| t.as_f64().filter(|s| *s >= 0.0).map(|s| s.ceil() as u64))
            })
        })
        .collect();
    if waits.is_empty() {
        return None;
    }
    Some(waits.iter().flatten().min().copied())
}

/// Idempotently install the hook on the agent's own file tools
/// (`Write|Edit|MultiEdit|NotebookEdit`, see [`crate::file_tools`]).
///
/// Its own `PreToolUse` entry with an exact matcher, so it never widens the
/// tools an operator hook in a shared entry is run for. The InnerWarden hook
/// already in that entry is updated in place (an operator's `timeout` on it
/// survives) and duplicates there are collapsed. When an InnerWarden hook
/// with this same command already runs for every file tool (under `*`, say),
/// nothing is added: the agent would run the same check twice.
pub fn merge_pretooluse_file_hook(settings: Value, hook_command: &str) -> Value {
    merge_pretooluse_tools_hook(
        settings,
        hook_command,
        crate::file_tools::FILE_TOOLS_MATCHER,
        crate::file_tools::FILE_TOOLS,
    )
}

/// Idempotently install the hook on the agent's own read tools
/// (`Read|Grep|Glob`, see [`crate::file_tools::file_read_call`]), as
/// [`merge_pretooluse_file_hook`] does for the file-changing ones: its own
/// entry, an exact matcher, the same command and mode.
pub fn merge_pretooluse_read_hook(settings: Value, hook_command: &str) -> Value {
    merge_pretooluse_tools_hook(
        settings,
        hook_command,
        crate::file_tools::READ_TOOLS_MATCHER,
        crate::file_tools::READ_TOOLS,
    )
}

/// [`merge_pretooluse_file_hook`] and [`merge_pretooluse_read_hook`]: the
/// entry whose matcher is exactly `matcher`, for `tools`.
fn merge_pretooluse_tools_hook(
    mut settings: Value,
    hook_command: &str,
    matcher: &str,
    tools: &[&str],
) -> Value {
    if !settings.is_object() {
        settings = json!({});
    }
    let obj = settings.as_object_mut().expect("object");
    let hooks = obj.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let pre = hooks
        .as_object_mut()
        .expect("object")
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));
    if !pre.is_array() {
        *pre = json!([]);
    }
    let arr = pre.as_array_mut().expect("array");
    let replacement_hook = json!({ "type": "command", "command": hook_command });
    let replacing_innerwarden = is_iwguard_hook(&replacement_hook);
    let mut installed = false;
    arr.retain_mut(|entry| {
        if entry.get("matcher").and_then(Value::as_str) != Some(matcher) {
            return true;
        }
        let Some(hooks) = entry.get_mut("hooks").and_then(Value::as_array_mut) else {
            return true;
        };
        let was_empty = hooks.is_empty();
        hooks.retain_mut(|hook| {
            let same_command = hook.get("command").and_then(Value::as_str) == Some(hook_command);
            if !(same_command || (replacing_innerwarden && is_iwguard_hook(hook))) {
                return true;
            }
            if installed {
                return false;
            }
            if let Some(object) = hook.as_object_mut() {
                object.insert("type".into(), json!("command"));
                object.insert("command".into(), json!(hook_command));
            } else {
                *hook = replacement_hook.clone();
            }
            installed = true;
            true
        });
        was_empty || !hooks.is_empty()
    });
    let covered_elsewhere = arr.iter().any(|entry| {
        covers_every_tool(entry, tools)
            && entry
                .get("hooks")
                .and_then(Value::as_array)
                .is_some_and(|hooks| {
                    hooks.iter().any(|hook| {
                        hook.get("command").and_then(Value::as_str) == Some(hook_command)
                    })
                })
    });
    if !installed && !covered_elsewhere {
        arr.push(json!({
            "matcher": matcher,
            "hooks": [replacement_hook],
        }));
    }
    settings
}

/// The entry [`merge_pretooluse_file_hook`] owns: its matcher is exactly
/// [`crate::file_tools::FILE_TOOLS_MATCHER`].
fn is_file_tools_entry(entry: &Value) -> bool {
    entry.get("matcher").and_then(Value::as_str) == Some(crate::file_tools::FILE_TOOLS_MATCHER)
}

/// The entry [`merge_pretooluse_read_hook`] owns: its matcher is exactly
/// [`crate::file_tools::READ_TOOLS_MATCHER`].
fn is_read_tools_entry(entry: &Value) -> bool {
    entry.get("matcher").and_then(Value::as_str) == Some(crate::file_tools::READ_TOOLS_MATCHER)
}

/// Whether an entry's matcher certainly sends every one of `tools` to its
/// hooks.
fn covers_every_tool(entry: &Value, tools: &[&str]) -> bool {
    tools
        .iter()
        .all(|tool| tool_matcher_coverage(entry, tool) == BashMatcherCoverage::Includes)
}

/// Whether a recognised InnerWarden hook is run for the agent's own file
/// tools (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`), so a write to a
/// privileged file is judged before it happens. False on wiring written
/// before this existed, which judges shell commands only, and on a file hook
/// that only records (`--monitor`) beside a shell hook that refuses: there
/// the file changes are not judged the way the shell commands are.
pub fn iwguard_judges_file_tools(settings: &Value) -> bool {
    iwguard_judges_tools(settings, crate::file_tools::FILE_TOOLS)
}

/// [`iwguard_judges_file_tools`] for the agent's read tools (`Read`,
/// `Grep`, `Glob`), so a read of a secret is judged before it happens.
/// False on wiring written before reads were judged.
pub fn iwguard_judges_read_tools(settings: &Value) -> bool {
    iwguard_judges_tools(settings, crate::file_tools::READ_TOOLS)
}

/// Whether a recognised InnerWarden hook runs for every one of `tools`, in
/// a mode as strong as the shell hook's ([`iwguard_judges_file_tools`]).
fn iwguard_judges_tools(settings: &Value, tools: &[&str]) -> bool {
    let mode = settings
        .get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| covers_every_tool(entry, tools))
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter_map(iwguard_hook_mode)
        .max();
    match (mode, strongest_effective_iwguard_hook_mode(settings)) {
        (None, _) => false,
        (Some(HookProtection::Monitor), Some(shell)) => shell == HookProtection::Monitor,
        (Some(_), _) => true,
    }
}

/// Whether automatic setup can merge without repairing or discarding malformed
/// operator-owned structure. Explicit install remains permissive so a user can
/// intentionally repair a broken file; the background watcher is fail-closed.
pub fn is_automatic_merge_safe(settings: &Value) -> bool {
    let Some(root) = settings.as_object() else {
        return false;
    };
    let Some(hooks) = root.get("hooks") else {
        return true;
    };
    let Some(hooks) = hooks.as_object() else {
        return false;
    };
    let Some(pretool) = hooks.get("PreToolUse") else {
        return true;
    };
    let Some(entries) = pretool.as_array() else {
        return false;
    };
    entries.iter().all(|entry| {
        let Some(entry) = entry.as_object() else {
            return false;
        };
        if entry
            .get("matcher")
            .is_some_and(|matcher| !matcher.is_string())
        {
            return false;
        }
        entry
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|handlers| handlers.iter().all(Value::is_object))
    })
}

/// The shell command Claude Code runs for the hook: the quoted innerwarden path plus
/// `hook` (and `--block-review` when requested). Quoting handles a path with
/// spaces (e.g. `C:\Users\Some Name\...`).
pub fn hook_command(iw_guard: &Path, block_review: bool, monitor: bool) -> String {
    hook_command_for(iw_guard, block_review, monitor, None)
}

/// [`hook_command`], naming the agent the hook serves (`--agent <id>`), so
/// every decision it records says which agent asked. The id is written only
/// when it is a plain agent id; anything else is left out rather than quoted.
///
/// This is Claude Code's line. On Linux and macOS an enforcing one ends in
/// [`FAIL_CLOSED`]; Codex CLI and Gemini CLI get [`hook_command_shaped`].
pub fn hook_command_for(
    iw_guard: &Path,
    block_review: bool,
    monitor: bool,
    agent: Option<&str>,
) -> String {
    let words = hook_words(block_review, monitor, agent);
    // A hook that refuses closes when it cannot run: see [`FAIL_CLOSED`].
    let closed = if !monitor && cfg!(unix) {
        FAIL_CLOSED
    } else {
        ""
    };
    format!("\"{}\" hook{words}{closed}", iw_guard.display())
}

/// The shell that runs the fail-closed hook line. Named by its full path: the
/// line must not depend on the agent's `PATH`, and every Linux and macOS
/// system has it.
const FAIL_CLOSED_SHELL: &str = "/bin/sh";

/// How the fail-closed line names the guard inside its script: the shell's
/// `$0`, which is the guard's path, handed to the shell as its own argument.
/// The path is then quoted once, by the agent's shell, exactly as in the plain
/// line, and never inside the script.
const FAIL_CLOSED_PROGRAM: &str = "\"$0\"";

/// What the fail-closed line runs after the guard. The guard answers 0 (run
/// it) or 2 (refuse it) in enforce. Any other end means it did not answer: the
/// shell could not find or start it (127, 126), it died on a signal (128 and
/// up, `SIGKILL` included, which no process can answer), or it failed some
/// other way. Every agent this line is written for refuses on 2 with a reason
/// on stderr, and runs the tool on most of the rest, so the rest becomes 2
/// with a reason. There is no `'` and no `\` in it, so it reads the same in
/// every shell an agent may start the line with (`sh`, `bash`, `zsh`, `fish`).
///
/// The refusal names the way out, because the agent cannot take it: every
/// call it would make to mend the hook is refused too. A person who removed
/// the program without `innerwarden uninstall` puts it back, or takes the
/// hook out of the agent's settings by hand.
const FAIL_CLOSED_TAIL: &str = "; s=$?; case $s in 0|2) exit $s;; esac; echo \"InnerWarden \
hook: the innerwarden program ended without an answer (exit $s); refusing this tool call rather \
than letting it run unscreened. To stop this, put the innerwarden program back, or remove the \
innerwarden hook from the agent settings by hand (~/.claude/settings.json, ~/.codex/hooks.json \
or ~/.gemini/settings.json).\" >&2; exit 2";

/// What the Gemini monitor line runs after the guard ([`FAIL_CLOSED_TAIL`]
/// turned the other way): every end but 0 becomes 1, with a note. Gemini CLI
/// 0.30.0 and later refuse a tool call on any exit but 0 and 1, so a plain
/// monitor line whose program is gone (127), cannot start (126) or is killed
/// held every call up: a mode that never refuses refused everything. 1 is
/// Gemini's "warn, run the tool". No `'` and no `\`, as in the other tail.
const FAIL_OPEN_TAIL: &str = "; s=$?; case $s in 0) exit 0;; esac; echo \"InnerWarden \
hook: the innerwarden program ended without an answer (exit $s); this tool call was NOT \
screened (monitor mode never blocks).\" >&2; exit 1";

/// The agent whose monitor line is the fail-open script: the one agent that
/// refuses a call on an exit a plain monitor line can end with.
const FAIL_OPEN_AGENT: &str = "gemini";

/// PURE: the hook line for Codex CLI, Gemini CLI and Hermes Agent, with its
/// shape chosen by the caller. Codex starts a hook line with the person's
/// login shell (`$SHELL -lc`), which may be one that cannot read the
/// [`FAIL_CLOSED`] tail (fish), and a line that shell cannot parse runs no
/// guard at all; so these lines name `/bin/sh` themselves.
///
/// `fail_closed` wraps an enforcing line in a small shell script that turns
/// every end of the guard other than its own answer into a refusal
/// ([`FAIL_CLOSED_TAIL`]). Without it the line is the guard alone, and a guard
/// that is missing, cannot start or is killed lets the call run on Claude Code
/// and Codex: they treat an exit other than 2 as "carry on". A monitor line
/// never refuses anything, whatever happens to the guard: it stays plain,
/// except Gemini's, which the same flag wraps in the script that turns every
/// end other than 0 into 1 ([`FAIL_OPEN_TAIL`]), because Gemini refuses on
/// the others. On Windows the line stays plain, because the agents start it
/// with `cmd` or PowerShell, where there is no `/bin/sh`.
pub fn hook_command_shaped(
    iw_guard: &Path,
    block_review: bool,
    monitor: bool,
    agent: Option<&str>,
    fail_closed: bool,
) -> String {
    let words = hook_words(block_review, monitor, agent);
    let tail = match (monitor, agent) {
        (false, _) => FAIL_CLOSED_TAIL,
        (true, Some(FAIL_OPEN_AGENT)) => FAIL_OPEN_TAIL,
        (true, _) => "",
    };
    if fail_closed && !tail.is_empty() {
        format!(
            "{FAIL_CLOSED_SHELL} -c '{FAIL_CLOSED_PROGRAM} hook{words}{tail}' \"{}\"",
            iw_guard.display()
        )
    } else {
        format!("\"{}\" hook{words}", iw_guard.display())
    }
}

/// The words after `hook` in a line of ours: the mode flag, then
/// `--agent <id>`.
fn hook_words(block_review: bool, monitor: bool, agent: Option<&str>) -> String {
    // `monitor` wins: it records every command but never blocks, so a dev gets the
    // live graph without the guardrail denying day-to-day work.
    let flag = if monitor {
        " --monitor"
    } else if block_review {
        " --block-review"
    } else {
        ""
    };
    let agent = agent
        .filter(|agent| is_agent_id(agent))
        .map(|agent| format!(" --agent {agent}"))
        .unwrap_or_default();
    format!("{flag}{agent}")
}

/// Written after a hook that refuses (enforce, `--block-review`), never after
/// one in monitor, which never acts.
///
/// Claude Code refuses a call only on exit 2; any other failure of the hook is
/// "non-blocking" and the call runs. So a hook whose binary is gone (127),
/// cannot be executed (126) or was killed (128 + signal) let every call run
/// unscreened, silently. The shell Claude Code runs the hook line in turns
/// exactly those three into 2 and leaves every other code as it was: 0 still
/// allows, 2 still refuses.
///
/// A hook that times out is not covered: Claude Code may end the shell that
/// runs this line when its hook timeout fires, and then the tail never runs.
/// Only the three failures of the binary above are closed.
///
/// Unix only: on Windows the line may not reach a POSIX shell, and a line the
/// shell cannot parse would leave every call unscreened, which is worse.
/// Recognition ([`hook_command_words`]) accepts this exact text on every
/// platform, so uninstall and repair keep finding the line.
pub const FAIL_CLOSED: &str = " || { s=$?; [ $s -ge 126 ] && exit 2; exit $s; }";

/// A plain agent id (`claude-code`): lowercase letters, digits, `-` and `_`.
pub fn is_agent_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// The agent an existing InnerWarden hook names: `None` when there is no
/// recognised hook at all, `Some(None)` when there is one that names no
/// agent. Rewriting a hook keeps this exactly as it was: a hook written
/// before `--agent` existed is correct as it stands, and must never be
/// rewritten just to add an identity.
fn existing_agent_flag(settings: &Value) -> Option<Option<String>> {
    let hooks: Vec<&Value> = settings
        .get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .collect();
    hooks
        .into_iter()
        .find_map(iwguard_hook_parts)
        .map(|(_, agent)| agent)
}

/// For a hook that names no agent, the mode flag `agents connect claude-code`
/// needs to rewrite it in the mode it already has (` --monitor`, ` --strict`,
/// or nothing for enforce): run by hand, that adds the agent's name and
/// changes nothing else. `None` when there is no hook, when it already names
/// its agent, or when its entries disagree on a mode (a reconnect would pick
/// one, which is not "nothing else").
pub fn unnamed_hook_reconnect_flag(settings: &Value) -> Option<&'static str> {
    if existing_agent_flag(settings) != Some(None) {
        return None;
    }
    let modes: Vec<HookProtection> = settings
        .get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| bash_matcher_coverage(entry) == BashMatcherCoverage::Includes)
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter_map(iwguard_hook_mode)
        .collect();
    let first = *modes.first()?;
    if modes.iter().any(|mode| *mode != first) {
        return None;
    }
    Some(match first {
        HookProtection::Monitor => " --monitor",
        HookProtection::Enforce => "",
        HookProtection::BlockReview => " --strict",
    })
}

/// Core installer with the home directory injected, so it is unit-testable
/// against a temp dir without touching the real home. `iw_guard` is the path to
/// this binary that the hook will invoke.
pub fn install_hook(
    home: &Path,
    agent: &str,
    settings: Option<&str>,
    iw_guard: &Path,
    block_review: bool,
    monitor: bool,
) -> Result<Report, String> {
    match install_hook_with_link_policy(
        home,
        agent,
        settings,
        iw_guard,
        block_review,
        monitor,
        false,
    )? {
        AutomaticHookInstall::Installed(report) => Ok(report),
        AutomaticHookInstall::SkippedExisting => {
            Err("existing InnerWarden hook was unexpectedly skipped".into())
        }
    }
}

pub(crate) fn install_hook_no_symlinks(
    home: &Path,
    agent: &str,
    settings: Option<&str>,
    iw_guard: &Path,
    block_review: bool,
    monitor: bool,
) -> Result<AutomaticHookInstall, String> {
    install_hook_with_link_policy(home, agent, settings, iw_guard, block_review, monitor, true)
}

fn install_hook_with_link_policy(
    home: &Path,
    agent: &str,
    settings: Option<&str>,
    iw_guard: &Path,
    block_review: bool,
    monitor: bool,
    reject_symlinks: bool,
) -> Result<AutomaticHookInstall, String> {
    // An agent this build has never heard of is a typo; one it knows but which
    // has no settings hook gets ROUTED to the mechanism that does cover it,
    // never a bare refusal. The old message said "only 'claude-code' is
    // supported today", which on a host running anything else read as
    // "InnerWarden cannot protect this" and was false.
    let target = crate::hook_targets::by_id(agent).ok_or_else(|| {
        format!(
            "unknown agent '{agent}'. Known: {}",
            crate::hook_targets::known_ids()
        )
    })?;
    let agent = target.id;
    if agent != "claude-code" {
        return Err(format!(
            "{} does not expose a hook this can install into.\n  {}",
            target.display,
            crate::hook_targets::guidance(target)
        ));
    }

    // Detect Claude Code BEFORE we create `~/.claude` (else we'd see our own dir).
    let claude_code_detected = detect_claude_code(claude_on_path(), claude_dir_configured(home));

    let settings_path = match settings {
        Some(p) => PathBuf::from(p),
        None => home.join(".claude/settings.json"),
    };
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }

    let source = if reject_symlinks {
        crate::file_update::read_config_no_symlinks(home, &settings_path)?
    } else {
        crate::file_update::read_config(&settings_path)?
    };
    let (existing, expected): (Value, Option<Vec<u8>>) = match source {
        Some(source) if source.iter().all(u8::is_ascii_whitespace) => (json!({}), Some(source)),
        Some(source) => {
            let value = serde_json::from_slice(&source)
                .map_err(|_| format!("{} is not valid JSON", settings_path.display()))?;
            (value, Some(source))
        }
        None => (json!({}), None),
    };
    if reject_symlinks && !is_automatic_merge_safe(&existing) {
        return Err(format!(
            "automatic setup refuses the invalid hook structure in {}",
            settings_path.display()
        ));
    }
    // Claude matchers may be JavaScript regular expressions. Rust cannot prove
    // arbitrary JS-regex coverage without changing semantics. If a recognised
    // InnerWarden hook uses such a matcher, background setup leaves the file
    // untouched rather than potentially replacing effective enforcement with a
    // monitor hook. An explicit install remains available to canonicalize it.
    if reject_symlinks && has_ambiguous_iwguard_matcher(&existing) {
        return Ok(AutomaticHookInstall::SkippedExisting);
    }
    let requested_mode = HookProtection::from_flags(block_review, monitor);
    // Background reconciliation must never turn an effective, manually
    // configured Bash enforce hook into monitor mode. It may canonicalize
    // aliases/path and collapse duplicates, but wiring under another matcher is
    // not active command protection and must not promote monitor-only setup.
    let effective_mode = if reject_symlinks {
        strongest_effective_iwguard_hook_mode(&existing)
            .map_or(requested_mode, |current| current.max(requested_mode))
    } else {
        requested_mode
    };
    let (block_review, monitor) = effective_mode.flags();
    // A NEW connection names its agent, and an existing hook that names one
    // keeps it. A hook that names NONE (written before hooks named their
    // agent) is left alone by background setup, which never churns a correct
    // hook; a person who runs `install` or `agents connect` by hand gets the
    // name added, which is the one way such a hook ever gains it.
    let agent_flag = match existing_agent_flag(&existing) {
        Some(Some(named)) => Some(named),
        Some(None) if reject_symlinks => None,
        _ => Some(agent.to_string()),
    };
    let cmd = hook_command_for(iw_guard, block_review, monitor, agent_flag.as_deref());
    // Background setup writes only a command it will recognise as its own
    // afterwards. One it would not (a binary path reading
    // `innerwarden (deleted)` after an in-place upgrade on Linux, or a renamed
    // build) cannot replace the existing hook, so the merge APPENDS it beside
    // the valid one, and nothing could ever repair or remove it again. An
    // explicit `install` keeps its old latitude: a person asked for it.
    if reject_symlinks && !is_iwguard_hook(&json!({ "type": "command", "command": cmd })) {
        return Err(format!(
            "automatic setup refuses to write `{cmd}`: it would not recognise that \
             command as its own, so it would sit beside the existing hook instead of \
             replacing it"
        ));
    }
    // Background setup keeps the mode of EVERY half it rewrites, not only the
    // Bash one: an enforcing `Write|Edit` or `Read|Grep|Glob` hook with no
    // enforcing Bash hook beside it was rewritten to the Bash half's mode,
    // monitor, and a monitor half beside an enforcing Bash hook was raised.
    // A half that is not there yet takes the Bash half's mode, as before.
    let half_command = |matcher: &str| -> String {
        match exact_matcher_iwguard_mode(&existing, matcher).filter(|_| reject_symlinks) {
            Some(mode) => {
                let mode = mode.max(requested_mode);
                let (block_review, monitor) = mode.flags();
                hook_command_for(iw_guard, block_review, monitor, agent_flag.as_deref())
            }
            None => cmd.clone(),
        }
    };
    let merged = merge_pretooluse_bash_hook(existing.clone(), &cmd);
    // The file-tools half: the same binary, on the agent's own
    // `Write`/`Edit` tools, which never pass through the shell.
    let merged =
        merge_pretooluse_file_hook(merged, &half_command(crate::file_tools::FILE_TOOLS_MATCHER));
    // The read half: `Read`, `Grep` and `Glob`, judged by the secret rules
    // of the shell, with the same binary.
    let merged =
        merge_pretooluse_read_hook(merged, &half_command(crate::file_tools::READ_TOOLS_MATCHER));
    // The observation half. Written with the SAME binary and the same mode
    // flags, because a PostToolUse hook that points at a different build is a
    // seam that drifts silently: it would keep feeding a store the screening
    // half no longer reads.
    //
    // Its mode follows the same rule as the other halves: a PostToolUse line
    // already there keeps its own mode, never weaker than asked, and only a
    // missing one takes the Bash half's. Writing the Bash half's mode on it
    // turned an enforcing line into `--monitor` when no Bash hook enforced.
    let post_command = match posttooluse_iwguard_mode(&existing).filter(|_| reject_symlinks) {
        Some(mode) => {
            let (block_review, monitor) = mode.max(requested_mode).flags();
            hook_command_for(iw_guard, block_review, monitor, agent_flag.as_deref())
        }
        None => cmd.clone(),
    };
    let merged = merge_posttooluse_hook(merged, &post_command);
    // Claude Code waits 600 s for a hook that names no `timeout`; every line
    // of ours gets [`HOOK_TIMEOUT_SECS`] unless the operator set one. Only an
    // explicit install or connect writes it: background setup keeps every
    // line it does not have to change exactly as it was, and `status` says
    // when the line has none.
    let merged = if reject_symlinks {
        merged
    } else {
        with_hook_timeouts(merged)
    };
    // Automatic setup must not treat any recognised legacy hook as proof that
    // the requested wiring is already correct. Reconcile aliases, duplicate
    // entries and mode/path drift first; skip only an exact semantic no-op.
    if reject_symlinks && merged == existing {
        return Ok(AutomaticHookInstall::SkippedExisting);
    }
    let body = serde_json::to_string_pretty(&merged).map_err(|e| e.to_string())? + "\n";
    if reject_symlinks {
        crate::file_update::replace_if_unchanged_no_symlinks(
            home,
            &settings_path,
            expected.as_deref(),
            body.as_bytes(),
        )?;
    } else {
        crate::file_update::replace_if_unchanged(
            &settings_path,
            expected.as_deref(),
            body.as_bytes(),
        )?;
    }

    Ok(AutomaticHookInstall::Installed(Report {
        settings_path,
        hook_command: cmd,
        block_review,
        monitor,
        claude_code_detected,
    }))
}

/// Split the deliberately small command grammar emitted by [`hook_command`].
///
/// This is not a general shell parser. Refusing shell composition, redirects and
/// unknown flags is intentional: detection is also used by uninstall, so a
/// command that merely mentions InnerWarden must remain operator-owned.
fn hook_command_words(command: &str) -> Option<Vec<String>> {
    // The one piece of shell the grammar knows: the exact [`FAIL_CLOSED`]
    // tail [`hook_command_for`] writes. Any other composition stays refused.
    let command = command.trim();
    plain_hook_command_words(command.strip_suffix(FAIL_CLOSED).unwrap_or(command))
}

/// The grammar of every release before [`FAIL_CLOSED`]: no shell at all.
///
/// Kept apart because it is the rollback limit. A binary from before the
/// tail reads a line that carries it as an operator's command, not as its
/// own: going back to it, `install` adds a second hook beside this one and
/// `uninstall` leaves this one in place, still refusing. Remove the hooks
/// with this binary (`innerwarden uninstall`) before installing an older one.
fn plain_hook_command_words(command: &str) -> Option<Vec<String>> {
    let mut chars = command.trim().chars().peekable();
    let mut words = Vec::new();

    while chars.peek().is_some() {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&first) = chars.peek() else {
            break;
        };

        let mut word = String::new();
        if first == '"' || first == '\'' {
            let quote = chars.next().expect("peeked quote");
            let mut closed = false;
            for ch in chars.by_ref() {
                if ch == quote {
                    closed = true;
                    break;
                }
                word.push(ch);
            }
            if !closed || chars.peek().is_some_and(|c| !c.is_whitespace()) {
                return None;
            }
        } else {
            while chars.peek().is_some_and(|c| !c.is_whitespace()) {
                word.push(chars.next().expect("peeked command character"));
            }
        }
        if word.is_empty() {
            return None;
        }
        words.push(word);
    }

    Some(words)
}

/// How a line of ours runs the guard ([`hook_command_shaped`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineShape {
    /// The guard alone.
    Plain,
    /// Inside the script that refuses when the guard does not answer.
    FailClosed,
    /// Inside the script that lets the call run, with a note, when the guard
    /// does not answer (Gemini's monitor line).
    FailOpen,
}

/// The guard's own words in a hook line, the program first: the line split by
/// [`hook_command_words`], or, for the scripted lines [`hook_command_shaped`]
/// writes, the words its script hands the guard, with the program its `$0`
/// names. The second value says which shape it was.
///
/// A scripted line is read by its exact shape and nothing wider: the shell by
/// its full path, `-c`, a script that starts with the guard as `$0` and ends
/// with [`FAIL_CLOSED_TAIL`] or [`FAIL_OPEN_TAIL`] to the letter, and the
/// program as the one word after it. Uninstall and repair find this line by
/// it, and a script of the person's own that merely runs the guard must stay
/// theirs.
fn guard_words(command: &str) -> Option<(Vec<String>, LineShape)> {
    let words = hook_command_words(command)?;
    let [shell, dash_c, script, program] = words.as_slice() else {
        return Some((words, LineShape::Plain));
    };
    if shell != FAIL_CLOSED_SHELL || dash_c != "-c" {
        return Some((words, LineShape::Plain));
    }
    let guard = script.strip_prefix(FAIL_CLOSED_PROGRAM)?;
    let (guard, shape) = match guard.strip_suffix(FAIL_CLOSED_TAIL) {
        Some(guard) => (guard, LineShape::FailClosed),
        None => (guard.strip_suffix(FAIL_OPEN_TAIL)?, LineShape::FailOpen),
    };
    if !guard.starts_with(' ') {
        return None;
    }
    let mut inner = vec![program.clone()];
    inner.extend(hook_command_words(guard)?);
    Some((inner, shape))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum HookProtection {
    Monitor,
    Enforce,
    BlockReview,
}

impl HookProtection {
    fn from_flags(block_review: bool, monitor: bool) -> Self {
        if monitor {
            Self::Monitor
        } else if block_review {
            Self::BlockReview
        } else {
            Self::Enforce
        }
    }

    fn flags(self) -> (bool, bool) {
        match self {
            Self::Monitor => (false, true),
            Self::Enforce => (false, false),
            Self::BlockReview => (true, false),
        }
    }
}

fn is_innerwarden_executable(executable: &str) -> bool {
    let components: Vec<String> = executable
        .split(['/', '\\'])
        .filter(|component| !component.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    let basename = components.last().map(String::as_str).unwrap_or(executable);
    let stem = [".exe", ".cmd", ".bat"]
        .iter()
        .find_map(|suffix| basename.strip_suffix(suffix))
        .unwrap_or(basename);
    if stem == "innerwarden" {
        return true;
    }
    if stem != "iw" || components.len() < 3 {
        return false;
    }

    // `iw` is also the standard Linux wireless utility. Treat it as our alias
    // only at the locations InnerWarden itself creates or Cargo uses for a
    // development binary; `/usr/sbin/iw` and `/opt/other/iw` remain untouched.
    let parent = components.len() - 2;
    (components[parent - 1] == ".local" && components[parent] == "bin")
        || (matches!(components[parent].as_str(), "debug" | "release")
            && components[..parent]
                .iter()
                .any(|component| component == "target"))
}

/// True when a hook directly executes a known InnerWarden binary basename with
/// the `hook` subcommand. Exact basenames recognise installed binaries, legacy
/// aliases and development paths such as `target/debug/iw`, without claiming
/// the unrelated system `iw` utility, a neighbouring executable like
/// `innerwarden-helper`, or a shell command that only mentions InnerWarden.
fn iwguard_hook_mode(hook: &Value) -> Option<HookProtection> {
    iwguard_hook_parts(hook).map(|(mode, _)| mode)
}

/// The mode an InnerWarden hook runs in, and the agent it names.
///
/// The grammar is the one [`hook_command_for`] writes and nothing wider:
/// `<innerwarden> hook`, then at most one mode flag, then at most one
/// `--agent <id>`, alone or inside the fail-closed script ([`guard_words`]). A repeated flag, an unknown word or an agent id that is not
/// a plain id means the line is not ours, exactly as before `--agent` existed:
/// uninstall and repair must never claim an operator's own command.
fn iwguard_hook_parts(hook: &Value) -> Option<(HookProtection, Option<String>)> {
    let line = parse_guard_line(hook.get("command").and_then(Value::as_str)?)?;
    Some((line.mode, line.agent))
}

/// One line of ours, read apart by [`parse_guard_line`].
struct GuardLine {
    program: String,
    mode: HookProtection,
    agent: Option<String>,
    shape: LineShape,
}

/// PURE: read a hook command as a line of ours, plain or fail-closed
/// ([`guard_words`]), by the grammar [`iwguard_hook_parts`] states.
fn parse_guard_line(command: &str) -> Option<GuardLine> {
    let (words, shape) = guard_words(command)?;
    parse_guard_words(&words, shape)
}

/// [`iwguard_hook_parts`] once the command is split into words.
#[cfg(test)]
fn hook_parts_of_words(words: &[String]) -> Option<(HookProtection, Option<String>)> {
    parse_guard_words(words, LineShape::Plain).map(|line| (line.mode, line.agent))
}

/// [`parse_guard_line`] once the command is split into words.
fn parse_guard_words(words: &[String], shape: LineShape) -> Option<GuardLine> {
    let (executable, rest) = words.split_first()?;
    let (subcommand, flags) = rest.split_first()?;
    if !is_innerwarden_executable(executable) || subcommand != "hook" {
        return None;
    }
    let (mode_flag, agent_flags) = match flags.first().map(String::as_str) {
        Some("--monitor" | "--block-review") => (flags.first(), &flags[1..]),
        _ => (None, flags),
    };
    let mode = match mode_flag.map(String::as_str) {
        None => HookProtection::Enforce,
        Some("--monitor") => HookProtection::Monitor,
        Some(_) => HookProtection::BlockReview,
    };
    let agent = match agent_flags {
        [] => None,
        [flag, agent] if flag == "--agent" && is_agent_id(agent) => Some(agent.clone()),
        _ => return None,
    };
    // Each script belongs to its mode: a monitor line that refuses, or an
    // enforcing one that lets a call through, is no line this module writes.
    let monitor = mode == HookProtection::Monitor;
    match shape {
        LineShape::FailClosed if monitor => return None,
        LineShape::FailOpen if !monitor => return None,
        _ => {}
    }
    Some(GuardLine {
        program: executable.clone(),
        mode,
        agent,
        shape,
    })
}

fn is_iwguard_hook(hook: &Value) -> bool {
    iwguard_hook_mode(hook).is_some()
}

/// One hook command this module calls its own, read apart.
///
/// For the agents whose hook lives outside Claude Code's settings
/// ([`crate::agent_hooks`]): they recognise, judge and remove their entry by
/// the same grammar, so a line is "ours" in one place only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookLine {
    /// The program the hook runs, quotes removed.
    pub program: String,
    /// `--monitor`: records, never blocks.
    pub monitor: bool,
    /// `--block-review`: also blocks `review`.
    pub block_review: bool,
    /// The agent the line names with `--agent`, when it names one.
    pub agent: Option<String>,
    /// The line is the fail-closed script ([`hook_command_shaped`]): a guard
    /// that does not answer refuses the call.
    pub fail_closed: bool,
    /// The line is the fail-open script (Gemini's monitor line): a guard
    /// that does not answer ends the line with 1, and the call runs.
    pub fail_open: bool,
}

/// Read one hook object as an InnerWarden hook line, `None` when its command
/// is not one [`hook_command_for`] writes.
pub fn read_hook_line(hook: &Value) -> Option<HookLine> {
    let line = parse_guard_line(hook.get("command").and_then(Value::as_str)?)?;
    let (block_review, monitor) = line.mode.flags();
    Some(HookLine {
        program: line.program,
        monitor,
        block_review,
        agent: line.agent,
        fail_closed: line.shape == LineShape::FailClosed,
        fail_open: line.shape == LineShape::FailOpen,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BashMatcherCoverage {
    Includes,
    Excludes,
    Ambiguous,
}

/// Classify Claude Code's matcher grammar without evaluating arbitrary
/// JavaScript regular expressions. Empty, omitted and `*` match every tool.
/// A whitespace-free `|` list is compatible with both the legacy regex grammar
/// and Claude Code's newer exact-set grammar. Commas and whitespace only gained
/// exact-list semantics in 2.1.191, so they remain ambiguous unless the runtime
/// version is known. Everything else on the JS-regex path is ambiguous too.
fn bash_matcher_coverage(entry: &Value) -> BashMatcherCoverage {
    tool_matcher_coverage(entry, "Bash")
}

/// [`bash_matcher_coverage`] for any one tool name.
fn tool_matcher_coverage(entry: &Value, tool: &str) -> BashMatcherCoverage {
    let Some(matcher) = entry.get("matcher") else {
        return BashMatcherCoverage::Includes;
    };
    let Some(matcher) = matcher.as_str() else {
        return BashMatcherCoverage::Ambiguous;
    };
    if matcher.is_empty() || matcher == "*" {
        return BashMatcherCoverage::Includes;
    }
    let cross_version_exact_set = matcher
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '|'));
    if !cross_version_exact_set || matcher.split('|').any(str::is_empty) {
        return BashMatcherCoverage::Ambiguous;
    }
    if matcher.split('|').any(|candidate| candidate == tool) {
        BashMatcherCoverage::Includes
    } else {
        BashMatcherCoverage::Excludes
    }
}

fn has_ambiguous_iwguard_matcher(settings: &Value) -> bool {
    settings
        .get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|entry| {
            bash_matcher_coverage(entry) == BashMatcherCoverage::Ambiguous
                && is_iwguard_hook_entry(entry)
        })
}

/// Strongest recognised InnerWarden mode under a matcher that certainly covers
/// Bash. Wiring under an excluding or ambiguous matcher is not authority to
/// enable enforcement during monitor-only automatic setup.
fn strongest_effective_iwguard_hook_mode(settings: &Value) -> Option<HookProtection> {
    settings
        .get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| bash_matcher_coverage(entry) == BashMatcherCoverage::Includes)
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter_map(iwguard_hook_mode)
        .max()
}

/// Strongest recognised InnerWarden mode in the `PreToolUse` entries whose
/// matcher is exactly `matcher`: the entries [`merge_pretooluse_tools_hook`]
/// rewrites in place.
fn exact_matcher_iwguard_mode(settings: &Value, matcher: &str) -> Option<HookProtection> {
    settings
        .get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| entry.get("matcher").and_then(Value::as_str) == Some(matcher))
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter_map(iwguard_hook_mode)
        .max()
}

/// Strongest recognised InnerWarden mode among the `PostToolUse` hooks,
/// under any matcher: [`merge_posttooluse_hook`] replaces ours wherever it
/// sits.
fn posttooluse_iwguard_mode(settings: &Value) -> Option<HookProtection> {
    settings
        .get("hooks")
        .and_then(|hooks| hooks.get("PostToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter_map(iwguard_hook_mode)
        .max()
}

fn is_iwguard_hook_entry(entry: &Value) -> bool {
    entry
        .get("hooks")
        .and_then(|h| h.as_array())
        .map(|hs| hs.iter().any(is_iwguard_hook))
        .unwrap_or(false)
}

/// Effective protection mode represented by recognised hooks under a
/// `PreToolUse` matcher that certainly includes Bash. Block-review is an
/// enforcing mode for dashboard posture; mixed means duplicate effective hooks
/// disagree on monitor/enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveHookMode {
    Monitor,
    Enforce,
    Mixed,
}

pub fn effective_iwguard_hook_mode(settings: &Value) -> Option<EffectiveHookMode> {
    let protections = settings
        .get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| bash_matcher_coverage(entry) == BashMatcherCoverage::Includes)
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter_map(iwguard_hook_mode);
    let mut monitor = false;
    let mut enforce = false;
    for protection in protections {
        if protection == HookProtection::Monitor {
            monitor = true;
        } else {
            enforce = true;
        }
    }
    match (monitor, enforce) {
        (true, true) => Some(EffectiveHookMode::Mixed),
        (true, false) => Some(EffectiveHookMode::Monitor),
        (false, true) => Some(EffectiveHookMode::Enforce),
        (false, false) => None,
    }
}

/// True when the settings object carries any recognised InnerWarden PreToolUse
/// wiring, including a legacy hook under the wrong matcher. This is intentionally
/// broader than [`has_iwguard_hook`]: callers use it to find wiring that needs
/// repair or removal, never to claim that Bash execution is protected.
pub fn has_iwguard_wiring(settings: &Value) -> bool {
    settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(Value::as_array)
        .is_some_and(|entries| entries.iter().any(is_iwguard_hook_entry))
}

/// True only when a recognised InnerWarden hook is effective for Claude Code's
/// `PreToolUse:Bash` surface. Excluding and ambiguous matchers remain wiring
/// evidence, but are never presented as active command protection.
pub fn has_iwguard_hook(settings: &Value) -> bool {
    effective_iwguard_hook_mode(settings).is_some()
}

/// What the caller found when it looked for the program a hook runs.
///
/// Handed in, never looked up here, so [`judge_hook_program`] is testable
/// without a filesystem or a `PATH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramFact {
    /// There, a regular file, and executable.
    Executable,
    /// There, but not an executable regular file.
    NotExecutable,
    /// Not there: no such path, or a bare name no `PATH` directory holds.
    Missing,
    /// The look itself failed, for example a permission error on the way.
    Unreadable,
}

/// Whether the program an InnerWarden hook runs is there for the agent to
/// start.
///
/// A recognised hook was all "guarded" used to mean, and a hook is only text.
/// Claude Code runs the command, the exec fails, it reports a non-blocking hook
/// error, and the tool call goes ahead unscreened. A Mac sat like that for
/// weeks, pointing at a `target/release` build that had been cleaned, while
/// `status` said `[on]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookProgram {
    /// It is there and executable, so the agent can start it.
    Runs,
    /// It is not, so the hook fails and nothing is screened. `problem` is a
    /// clause naming the program, for a sentence about the agent.
    Broken { program: String, problem: String },
    /// Could not be established either way. Never reported as broken.
    Unknown { program: String, why: String },
}

/// PURE: judge one hook program from what the caller found when it looked.
///
/// A bare name (no directory) is found through `PATH`, the way the agent's
/// shell finds it. A path relative to a directory is relative to wherever the
/// agent was started, which is not knowable from here, so it stays unknown
/// whatever the caller found.
pub fn judge_hook_program(program: &str, fact: ProgramFact) -> HookProgram {
    let bare = !program.contains(['/', '\\']);
    if !bare && !Path::new(program).is_absolute() {
        return HookProgram::Unknown {
            program: program.to_string(),
            why: format!(
                "its hook runs {program}, a path relative to wherever the agent starts, \
                 so I cannot check it from here"
            ),
        };
    }
    // A bare name is found on the PATH of the agent that runs the hook, which
    // is not this process's PATH and cannot be read from here. Found here (on
    // this PATH or in a usual place), the agent may still resolve another, so
    // an OK could be false: "could not tell". Found nowhere here, the agent
    // will likely not find it either: that is off, the same alarm as a path
    // that does not exist.
    if bare {
        return match fact {
            ProgramFact::Missing | ProgramFact::NotExecutable => HookProgram::Broken {
                program: program.to_string(),
                problem: format!(
                    "its hook runs `{program}`, which is not on PATH: {BARE_NOT_FOUND}"
                ),
            },
            ProgramFact::Executable | ProgramFact::Unreadable => HookProgram::Unknown {
                program: program.to_string(),
                why: bare_name_why(program),
            },
        };
    }
    let problem = match fact {
        ProgramFact::Executable => return HookProgram::Runs,
        ProgramFact::Unreadable => {
            return HookProgram::Unknown {
                program: program.to_string(),
                why: format!("its hook runs {program}, and I could not look to see if it is there"),
            }
        }
        ProgramFact::Missing => format!("its hook runs {program}, which does not exist"),
        ProgramFact::NotExecutable => {
            format!("its hook runs {program}, which is not an executable file")
        }
    };
    HookProgram::Broken {
        program: program.to_string(),
        problem,
    }
}

/// Why a hook that names its program bare cannot be judged from here.
pub const BARE_NAME: &str = "could not tell: bare name, resolved on the agent's PATH";

/// Why a bare name found nowhere here is off.
pub const BARE_NOT_FOUND: &str =
    "not found on this shell's PATH or the usual places; the agent will likely not find it either";

fn bare_name_why(program: &str) -> String {
    format!("{BARE_NAME}: its hook runs `{program}`")
}

/// The clue a caller adds to a bare name's `why`: where it was found here
/// (`Some`: this PATH or a usual place), or that the look failed (`None`).
/// Only a clue: the agent resolves the name on a PATH of its own.
pub fn bare_name_clue(found_here: Option<&Path>) -> String {
    match found_here {
        Some(path) => format!(
            "; found here at {}, the agent may resolve another",
            path.display()
        ),
        None => "; I could not look for it here".to_string(),
    }
}

/// A hook line that names the guard's binary and its `hook` verb but is not
/// in the grammar [`hook_command_for`] writes: something else comes first
/// (`env X=1 /p/innerwarden hook`, `sh -c '/p/innerwarden hook'`), or a path
/// holds a space and no quotes. Never the guard's own line, so never touched
/// by install or uninstall; `status` names it so it cannot vanish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedHook {
    /// The command exactly as the settings file holds it.
    pub command: String,
    /// The word that names the guard's binary, quotes removed.
    pub program: String,
    /// Under `PreToolUse` with a matcher that certainly includes Bash.
    pub screens_bash: bool,
}

/// The word in `command` that names the guard's binary right before `hook`,
/// read loosely: words split on whitespace and shell punctuation, quotes
/// dropped. Only for naming a line in `status`; never to claim it as ours.
fn wrapped_guard_program(command: &str) -> Option<String> {
    let words: Vec<&str> = command
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '`'))
        .map(|word| word.trim_matches(|c| c == '"' || c == '\''))
        .filter(|word| !word.is_empty())
        .collect();
    words
        .windows(2)
        .find(|pair| is_innerwarden_executable(pair[0]) && pair[1] == "hook")
        .map(|pair| pair[0].to_string())
}

/// Every hook line, under any event and matcher, that names the guard but is
/// not one [`is_iwguard_hook`] reads as ours, in file order.
pub fn wrapped_iwguard_hooks(settings: &Value) -> Vec<WrappedHook> {
    let Some(events) = settings.get("hooks").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (event, entries) in events {
        for entry in entries.as_array().into_iter().flatten() {
            let screens_bash = event == "PreToolUse"
                && bash_matcher_coverage(entry) == BashMatcherCoverage::Includes;
            for hook in entry
                .get("hooks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if is_iwguard_hook(hook) {
                    continue;
                }
                let Some(command) = hook.get("command").and_then(Value::as_str) else {
                    continue;
                };
                if let Some(program) = wrapped_guard_program(command) {
                    out.push(WrappedHook {
                        command: command.to_string(),
                        program,
                        screens_bash,
                    });
                }
            }
        }
    }
    out
}

/// PURE: judge a [`WrappedHook`] from what the caller found when it looked
/// for the binary it names. Never `Runs`: what comes before the binary (an
/// `env`, a `sh -c`, a split path) decides what actually starts, so the line
/// is "could not tell", with the line in the words. Only a binary that is
/// certainly gone (an absolute path that does not exist or is not
/// executable) is the same alarm as the guard's own line: nothing it names
/// can start.
pub fn judge_wrapped_hook(hook: &WrappedHook, fact: ProgramFact) -> HookProgram {
    let program = hook.program.as_str();
    let line = &hook.command;
    if Path::new(program).is_absolute() {
        let gone = match fact {
            ProgramFact::Missing => Some("which does not exist"),
            ProgramFact::NotExecutable => Some("which is not an executable file"),
            ProgramFact::Executable | ProgramFact::Unreadable => None,
        };
        if let Some(gone) = gone {
            return HookProgram::Broken {
                program: program.to_string(),
                problem: format!("its hook line `{line}` runs {program}, {gone}"),
            };
        }
    }
    HookProgram::Unknown {
        program: program.to_string(),
        why: format!(
            "could not tell: its hook line `{line}` names {program} but does not start with \
             it, so I cannot say what that line runs"
        ),
    }
}

/// The program each InnerWarden hook effective under `PreToolUse:Bash` runs,
/// quotes removed, in file order.
///
/// Read with the same small grammar detection uses, so a program is only ever
/// taken from a command this module already calls its own.
pub fn effective_iwguard_hook_programs(settings: &Value) -> Vec<String> {
    settings
        .get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| bash_matcher_coverage(entry) == BashMatcherCoverage::Includes)
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter_map(|hook| hook.get("command").and_then(Value::as_str))
        .filter_map(parse_guard_line)
        .map(|line| line.program)
        .collect()
}

/// The words of each InnerWarden hook Claude Code runs before `tool`
/// (`Bash`, `Read`, `Write`, ...), quotes removed, in file order: the
/// hooks under a `PreToolUse` matcher that certainly includes the tool.
/// Empty when no hook of ours is wired for it.
///
/// Read with the same small grammar detection uses, so a hook is only ever
/// taken from a command this module already calls its own. `innerwarden
/// demo` runs these, as written, to show what each one answers.
pub fn iwguard_hook_commands_for_tool(settings: &Value, tool: &str) -> Vec<Vec<String>> {
    settings
        .get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|entry| tool_matcher_coverage(entry, tool) == BashMatcherCoverage::Includes)
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter(|hook| is_iwguard_hook(hook))
        .filter_map(|hook| hook.get("command").and_then(Value::as_str))
        .filter_map(hook_command_words)
        .filter(|words| !words.is_empty())
        .collect()
}

/// PURE: can the InnerWarden hooks that screen Bash actually start? `None`
/// when there are none.
///
/// Claude Code runs every matching hook, so ONE that runs is enough for the
/// command to be screened. Short of that, one that could not be checked makes
/// the answer unknown rather than broken: "could not tell" is never "off".
pub fn judge_iwguard_hooks(
    settings: &Value,
    fact: impl Fn(&str) -> ProgramFact,
) -> Option<HookProgram> {
    let verdicts: Vec<HookProgram> = effective_iwguard_hook_programs(settings)
        .iter()
        .map(|program| judge_hook_program(program, fact(program)))
        .collect();
    if verdicts.is_empty() {
        return None;
    }
    if verdicts.contains(&HookProgram::Runs) {
        return Some(HookProgram::Runs);
    }
    verdicts
        .iter()
        .find(|verdict| matches!(verdict, HookProgram::Unknown { .. }))
        .or_else(|| verdicts.first())
        .cloned()
}

/// One group of InnerWarden hooks (an event and a matcher) whose program
/// cannot start, so the tools it is wired for go unscreened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnscreenedHooks {
    /// The tools that go unscreened, for a sentence: `Write/Edit` for a
    /// `PreToolUse` matcher, `PostToolUse (every tool)` for a result hook.
    pub tools: String,
    /// A clause naming the program, as in [`HookProgram::Broken`].
    pub problem: String,
}

/// The tool names a matcher lists, for a sentence. `None` for an entry that
/// covers every tool.
fn matcher_label(entry: &Value) -> String {
    match entry.get("matcher").and_then(Value::as_str) {
        None | Some("" | "*") => "every tool".to_string(),
        Some(matcher) => matcher.split('|').collect::<Vec<_>>().join("/"),
    }
}

/// PURE: the groups of InnerWarden hooks, beyond the one that screens Bash,
/// whose program cannot start: `Write|Edit|MultiEdit|NotebookEdit`,
/// `Read|Grep|Glob`, `PostToolUse`, or any other event and matcher.
///
/// [`judge_iwguard_hooks`] only asks whether Bash is screened, so a Bash hook
/// that runs beside a file-tool or result hook pointing at a deleted binary
/// read as fully guarded, while Claude Code ran those hooks as non-blocking
/// errors and let the calls through.
///
/// The rule per group is the one [`judge_iwguard_hooks`] uses: one hook in
/// the group that runs is enough, and one that could not be checked keeps the
/// group out of this list ("could not tell" is never "off"). A group is also
/// left out when a hook of ours that runs, in the same event, covers every
/// tool. Operator hooks are never judged.
pub fn unscreened_iwguard_hooks(
    settings: &Value,
    fact: impl Fn(&str) -> ProgramFact,
) -> Vec<UnscreenedHooks> {
    let Some(events) = settings.get("hooks").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out: Vec<UnscreenedHooks> = Vec::new();
    // `PreToolUse` first: a call that is never judged before it runs is the
    // larger gap, so it leads the sentence.
    let mut ordered: Vec<(&String, &Value)> = events.iter().collect();
    ordered.sort_by_key(|(event, _)| event.as_str() != "PreToolUse");
    for (event, entries) in ordered {
        let Some(entries) = entries.as_array() else {
            continue;
        };
        // (label, verdicts) per matcher, in file order.
        let mut groups: Vec<(String, Vec<HookProgram>)> = Vec::new();
        let mut every_tool_runs = false;
        for entry in entries {
            let label = matcher_label(entry);
            let verdicts: Vec<HookProgram> = entry
                .get("hooks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(|hook| is_iwguard_hook(hook))
                .filter_map(|hook| hook.get("command").and_then(Value::as_str))
                .filter_map(hook_command_words)
                .filter_map(|words| words.into_iter().next())
                .map(|program| judge_hook_program(&program, fact(&program)))
                .collect();
            if verdicts.is_empty() {
                continue;
            }
            if label == "every tool" && verdicts.contains(&HookProgram::Runs) {
                every_tool_runs = true;
            }
            match groups.iter_mut().find(|(l, _)| *l == label) {
                Some((_, all)) => all.extend(verdicts),
                None => groups.push((label, verdicts)),
            }
        }
        if every_tool_runs {
            continue;
        }
        for (label, verdicts) in groups {
            if verdicts
                .iter()
                .any(|v| !matches!(v, HookProgram::Broken { .. }))
            {
                continue;
            }
            // The Bash group is judged by `judge_iwguard_hooks`; a broken one
            // already makes the whole agent off, said elsewhere.
            if event == "PreToolUse" && label == "Bash" {
                continue;
            }
            let Some(HookProgram::Broken { problem, .. }) = verdicts.into_iter().next() else {
                continue;
            };
            let tools = if event == "PreToolUse" {
                label
            } else {
                format!("{event} ({label})")
            };
            out.push(UnscreenedHooks { tools, problem });
        }
    }
    out
}

/// PURE: one sentence for [`unscreened_iwguard_hooks`], `None` when it is
/// empty: `Write/Edit not screened, PostToolUse (every tool) not screened:
/// its hook runs /x/innerwarden, which does not exist`.
pub fn unscreened_hooks_sentence(groups: &[UnscreenedHooks]) -> Option<String> {
    if groups.is_empty() {
        return None;
    }
    let mut problems: Vec<&str> = Vec::new();
    for g in groups {
        if !problems.contains(&g.problem.as_str()) {
            problems.push(&g.problem);
        }
    }
    let tools: Vec<String> = groups
        .iter()
        .map(|g| format!("{} not screened", g.tools))
        .collect();
    Some(format!("{}: {}", tools.join(", "), problems.join("; ")))
}

/// PURE: the `(block_review, monitor)` flags of the mode these hooks already
/// have (the strongest, as [`install_mode_flag`] keeps it), `None` where no
/// hook of ours screens Bash. A rewrite that asked for no mode keeps this one,
/// so it never lowers an enforcing hook to monitor.
pub fn kept_hook_flags(settings: &Value) -> Option<(bool, bool)> {
    strongest_effective_iwguard_hook_mode(settings).map(|mode| match mode {
        HookProtection::Monitor => (false, true),
        HookProtection::Enforce => (false, false),
        HookProtection::BlockReview => (true, false),
    })
}

/// PURE: the `install` flag that rewrites these hooks in the mode they already
/// have, so the remedy for a broken hook never changes what it does. Mixed
/// wiring keeps its strongest half, as automatic repair does.
pub fn install_mode_flag(settings: &Value) -> &'static str {
    match strongest_effective_iwguard_hook_mode(settings) {
        Some(HookProtection::Monitor) => " --monitor",
        Some(HookProtection::BlockReview) => " --block-review",
        Some(HookProtection::Enforce) | None => "",
    }
}

/// Whether automatic setup would make a semantic change to existing hook
/// wiring. The preview uses the same strongest-mode rule as the automatic
/// installer: aliases, path drift, an exact excluding matcher and duplicates are
/// repaired, while an effective Bash enforce/block-review posture is never
/// downgraded to monitor. Ambiguous JavaScript-regex matchers are left untouched.
pub fn needs_iwguard_hook_reconciliation(
    settings: &Value,
    iw_guard: &Path,
    block_review: bool,
    monitor: bool,
) -> bool {
    if has_ambiguous_iwguard_matcher(settings) {
        return false;
    }
    let requested_mode = HookProtection::from_flags(block_review, monitor);
    let effective_mode = strongest_effective_iwguard_hook_mode(settings)
        .map_or(requested_mode, |current| current.max(requested_mode));
    let (block_review, monitor) = effective_mode.flags();
    // The agent the existing hook names, kept as it is: a hook with no
    // `--agent` is correct wiring, never drift to repair.
    let agent = existing_agent_flag(settings).flatten();
    let command = hook_command_for(iw_guard, block_review, monitor, agent.as_deref());
    // The file-tools and read-tools hooks are part of the wiring: an install
    // from before they existed is brought up to them, in the mode it already
    // has.
    merge_pretooluse_read_hook(
        merge_pretooluse_file_hook(
            merge_pretooluse_bash_hook(settings.clone(), &command),
            &command,
        ),
        &command,
    ) != *settings
}

/// Remove every innerwarden PreToolUse Bash hook entry from a settings object,
/// preserving all other keys, hook types, and unrelated PreToolUse entries.
/// Returns `(new_settings, removed_count)`. Idempotent: a second call removes 0.
pub fn remove_iwguard_pretooluse_hook(settings: Value) -> (Value, usize) {
    remove_iwguard_hooks_for_event(settings, "PreToolUse")
}

/// Remove every InnerWarden hook under one event (`PreToolUse`, `PostToolUse`,
/// Gemini's `BeforeTool`), preserving every other hook, entry and key. An
/// entry whose hook list becomes empty goes with it. Returns the new settings
/// and how many hooks were removed. Idempotent: a second call removes 0.
pub fn remove_iwguard_hooks_for_event(mut settings: Value, event: &str) -> (Value, usize) {
    let Some(pre) = settings
        .get_mut("hooks")
        .and_then(|h| h.get_mut(event))
        .and_then(|p| p.as_array_mut())
    else {
        return (settings, 0);
    };
    let mut removed = 0usize;
    pre.retain_mut(|entry| {
        let Some(hooks) = entry.get_mut("hooks").and_then(Value::as_array_mut) else {
            return true;
        };
        let before = hooks.len();
        hooks.retain(|hook| !is_iwguard_hook(hook));
        removed += before - hooks.len();
        !hooks.is_empty()
    });
    (settings, removed)
}

/// Core uninstaller with the home directory injected (unit-testable). Reads the
/// settings, strips innerwarden's PreToolUse hooks and the PostToolUse hook
/// installed with them, and writes back only if something changed. A
/// missing/empty settings file means nothing to remove (0), not an error, so
/// `uninstall` is always safe to run.
/// Whether Claude Code's settings under `home` still hold a PreToolUse hook
/// of ours whose program is `binary`: `Some(true)` when they do,
/// `Some(false)` when the file cannot be read or parsed and its text holds
/// a hook line of ours (which copy it runs cannot be told), `None` when
/// there is none. Asked by `uninstall` before the binary goes: an enforcing
/// line is the fail-closed script, and with its program gone Claude Code
/// refuses every tool call, the one that would mend the file included.
pub fn claude_code_hook_still_runs(home: &Path, binary: &Path) -> Option<bool> {
    let path = home.join(".claude/settings.json");
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return Some(false),
    };
    let text = String::from_utf8_lossy(&bytes);
    let Ok(settings) = serde_json::from_slice::<Value>(&bytes) else {
        let lower = text.to_ascii_lowercase();
        return (lower.contains("innerwarden") && lower.contains("hook")).then_some(false);
    };
    let runs = settings
        .get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("hooks").and_then(Value::as_array))
        .flatten()
        .filter_map(read_hook_line)
        .any(|line| {
            let program = Path::new(&line.program);
            program == binary
                || matches!(
                    (program.canonicalize(), binary.canonicalize()),
                    (Ok(program), Ok(binary)) if program == binary
                )
        });
    runs.then_some(true)
}

/// What `uninstall` says when it stops for [`claude_code_hook_still_runs`].
pub fn claude_code_left_behind_lines(seen: bool) -> Vec<String> {
    vec![
        if seen {
            "~/.claude/settings.json still holds a PreToolUse hook that runs this binary."
                .to_string()
        } else {
            "~/.claude/settings.json could not be read, and a PreToolUse hook in it may still \
             run this binary."
                .to_string()
        },
        "Claude Code would start a hook whose program is gone before every tool call: in \
         enforce mode it refuses every call, the one that would fix the file included."
            .to_string(),
        "Make ~/.claude and its settings.json writable and run `innerwarden uninstall` \
         again, or take the innerwarden entries out of `hooks.PreToolUse` in that file."
            .to_string(),
    ]
}

pub fn uninstall_hook(
    home: &Path,
    agent: &str,
    settings: Option<&str>,
) -> Result<(PathBuf, usize), String> {
    if agent != "claude-code" {
        return Err(format!(
            "unsupported agent '{agent}' (only 'claude-code' is supported today)"
        ));
    }
    let settings_path = match settings {
        Some(p) => PathBuf::from(p),
        None => home.join(".claude/settings.json"),
    };
    let (existing, source): (Value, Vec<u8>) = match fs::read(&settings_path) {
        Ok(source) if source.iter().all(u8::is_ascii_whitespace) => {
            return Ok((settings_path, 0));
        }
        Ok(source) => {
            let value = serde_json::from_slice(&source)
                .map_err(|_| format!("{} is not valid JSON", settings_path.display()))?;
            (value, source)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((settings_path, 0));
        }
        Err(error) => {
            return Err(format!("reading {}: {error}", settings_path.display()));
        }
    };
    let (cleaned, removed) = remove_iwguard_pretooluse_hook(existing);
    // The observation half goes with the screening half. Left behind, it kept
    // running the guard's binary after every tool call of an agent the person
    // had disconnected, and failed on each one once the binary was removed.
    let (cleaned, observed) = remove_iwguard_hooks_for_event(cleaned, "PostToolUse");
    let removed = removed + observed;
    if removed > 0 {
        let body = serde_json::to_string_pretty(&cleaned).map_err(|e| e.to_string())? + "\n";
        crate::file_update::replace_if_unchanged(&settings_path, Some(&source), body.as_bytes())?;
    }
    Ok((settings_path, removed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tail [`hook_command_for`] writes after a refusing hook on this
    /// platform: [`FAIL_CLOSED`] on unix, nothing elsewhere.
    const CLOSED: &str = if cfg!(unix) { FAIL_CLOSED } else { "" };

    /// `innerwarden demo` sends each call only to the hooks Claude Code would
    /// run for that tool: ours, under a matcher that includes it, never an
    /// operator's hook beside it.
    ///
    /// FAILS ON REVERT: drop the matcher filter and the Bash hook is listed
    /// for `Read`; drop the ownership filter and the operator's hook is run.
    #[test]
    fn hook_commands_for_a_tool_are_ours_under_its_matcher() {
        let settings = json!({"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [
                {"type": "command", "command": "\"/p/innerwarden\" hook --agent claude-code"},
                {"type": "command", "command": "/usr/local/bin/my-own-check"}
            ]},
            {"matcher": "Read|Grep|Glob", "hooks": [
                {"type": "command", "command": "\"/p/innerwarden\" hook --monitor"}
            ]}
        ]}});
        assert_eq!(
            iwguard_hook_commands_for_tool(&settings, "Bash"),
            vec![vec![
                "/p/innerwarden".to_string(),
                "hook".into(),
                "--agent".into(),
                "claude-code".into()
            ]]
        );
        assert_eq!(
            iwguard_hook_commands_for_tool(&settings, "Read"),
            vec![vec![
                "/p/innerwarden".to_string(),
                "hook".into(),
                "--monitor".into()
            ]]
        );
        assert!(iwguard_hook_commands_for_tool(&settings, "Write").is_empty());
        assert!(iwguard_hook_commands_for_tool(&json!({}), "Bash").is_empty());
    }

    #[test]
    fn merge_into_empty_adds_bash_hook() {
        let out = merge_pretooluse_bash_hook(json!({}), "\"/p/innerwarden\" hook");
        let entry = &out["hooks"]["PreToolUse"][0];
        assert_eq!(entry["matcher"], "Bash");
        assert_eq!(entry["hooks"][0]["type"], "command");
        assert_eq!(entry["hooks"][0]["command"], "\"/p/innerwarden\" hook");
    }

    /// The file-tools half: its own entry, exact matcher, same command.
    #[test]
    fn install_wires_the_file_tools_with_the_same_command() {
        let home = tempfile::TempDir::new().unwrap();
        let report = install_hook(
            home.path(),
            "claude-code",
            None,
            Path::new("/p/innerwarden"),
            false,
            false,
        )
        .unwrap();
        let settings: Value =
            serde_json::from_slice(&fs::read(&report.settings_path).unwrap()).unwrap();
        let pre = settings["hooks"]["PreToolUse"].as_array().unwrap();
        let file_entry = pre
            .iter()
            .find(|entry| entry["matcher"] == crate::file_tools::FILE_TOOLS_MATCHER)
            .expect("a file-tools entry");
        assert_eq!(
            file_entry["hooks"][0]["command"],
            json!(report.hook_command)
        );
        assert!(iwguard_judges_file_tools(&settings));
        // Still exactly one effective Bash hook, in the mode asked for.
        assert_eq!(
            effective_iwguard_hook_mode(&settings),
            Some(EffectiveHookMode::Enforce)
        );
        // Re-running changes nothing.
        let again = install_hook(
            home.path(),
            "claude-code",
            None,
            Path::new("/p/innerwarden"),
            false,
            false,
        )
        .unwrap();
        let after: Value =
            serde_json::from_slice(&fs::read(&again.settings_path).unwrap()).unwrap();
        assert_eq!(after, settings);
    }

    /// A mode flip rewrites both halves; operator hooks and operator fields
    /// on our hook survive; a second merge is a no-op.
    #[test]
    fn the_file_hook_merge_is_idempotent_and_follows_the_mode() {
        let settings = json!({"hooks": {"PreToolUse": [
            { "matcher": "Write|Edit|MultiEdit|NotebookEdit", "hooks": [
                { "type": "command", "command": "/operator/lint.sh" },
                { "type": "command", "command": "\"/opt/innerwarden\" hook --monitor", "timeout": 9 },
                { "type": "command", "command": "\"/old/innerwarden\" hook" }
            ]}
        ]}});
        let cmd = "\"/opt/innerwarden\" hook";
        let once = merge_pretooluse_file_hook(settings, cmd);
        let twice = merge_pretooluse_file_hook(once.clone(), cmd);
        assert_eq!(once, twice);
        let hooks = once["hooks"]["PreToolUse"][0]["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 2, "operator hook plus one of ours: {hooks:?}");
        assert_eq!(hooks[0]["command"], "/operator/lint.sh");
        assert_eq!(hooks[1]["command"], cmd);
        assert_eq!(hooks[1]["timeout"], 9);
        assert_eq!(once["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        // The Bash merge leaves the file entry alone.
        let both = merge_pretooluse_bash_hook(once.clone(), cmd);
        assert_eq!(
            merge_pretooluse_file_hook(both.clone(), cmd),
            both,
            "bash then file merge is stable"
        );
        assert_eq!(
            both["hooks"]["PreToolUse"][0],
            once["hooks"]["PreToolUse"][0]
        );
    }

    /// A hook already run for every tool (`*`) judges the file tools too, so
    /// no second entry is added.
    #[test]
    fn a_hook_under_star_already_judges_the_file_tools() {
        let cmd = "\"/opt/innerwarden\" hook";
        let settings = json!({"hooks": {"PreToolUse": [
            { "matcher": "*", "hooks": [ { "type": "command", "command": cmd } ] }
        ]}});
        assert!(iwguard_judges_file_tools(&settings));
        let merged = merge_pretooluse_file_hook(settings.clone(), cmd);
        assert_eq!(merged, settings);
    }

    /// The upgrade path: wiring written before the file tools were judged
    /// needs reconciliation, in the mode it already has; after it, it does not.
    ///
    /// FAILS ON REVERT: leave the file merge out of
    /// `needs_iwguard_hook_reconciliation` and an old install is never brought
    /// up to it.
    #[test]
    fn bash_only_wiring_is_brought_up_to_the_file_tools_in_its_own_mode() {
        let iw = Path::new("/opt/innerwarden");
        let old = json!({"hooks": {"PreToolUse": [
            { "matcher": "Bash", "hooks": [
                { "type": "command", "command": "\"/opt/innerwarden\" hook --agent claude-code" }
            ]}
        ]}});
        assert!(!iwguard_judges_file_tools(&old));
        assert!(needs_iwguard_hook_reconciliation(&old, iw, false, true));
        let home = tempfile::TempDir::new().unwrap();
        let path = home.path().join(".claude/settings.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&old).unwrap()).unwrap();
        // Background setup asks for monitor; the enforce hook keeps enforce.
        let result =
            install_hook_no_symlinks(home.path(), "claude-code", None, iw, false, true).unwrap();
        assert!(matches!(result, AutomaticHookInstall::Installed(_)));
        let new: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(iwguard_judges_file_tools(&new));
        assert!(!new.to_string().contains("--monitor"), "{new}");
        assert!(!needs_iwguard_hook_reconciliation(&new, iw, false, true));
    }

    /// A file hook that only records beside a shell hook that refuses is not
    /// reported as judging the file tools; one in the same mode is.
    ///
    /// FAILS ON REVERT: count any InnerWarden file hook, whatever its mode,
    /// and the record-only half reads as judged.
    #[test]
    fn a_record_only_file_hook_beside_an_enforcing_one_is_not_judging() {
        let wiring = |bash: &str, file: &str| {
            json!({"hooks": {"PreToolUse": [
                { "matcher": "Bash", "hooks": [
                    { "type": "command", "command": format!("\"/opt/innerwarden\" hook{bash}") }
                ]},
                { "matcher": crate::file_tools::FILE_TOOLS_MATCHER, "hooks": [
                    { "type": "command", "command": format!("\"/opt/innerwarden\" hook{file}") }
                ]}
            ]}})
        };
        assert!(!iwguard_judges_file_tools(&wiring("", " --monitor")));
        assert!(!iwguard_judges_file_tools(&wiring(
            " --block-review",
            " --monitor"
        )));
        assert!(iwguard_judges_file_tools(&wiring("", "")));
        assert!(iwguard_judges_file_tools(&wiring(
            " --monitor",
            " --monitor"
        )));
        assert!(iwguard_judges_file_tools(&wiring(" --monitor", "")));
    }

    /// The read half is reported on its own: wiring with the shell and file
    /// entries and no read entry does not judge reads, and a record-only
    /// read entry beside an enforcing shell hook does not either.
    ///
    /// FAILS ON REVERT: answer `iwguard_judges_read_tools` with the file
    /// tools' list and the first wiring reads as judging reads.
    #[test]
    fn the_read_half_is_judged_only_where_its_entry_is() {
        let entry = |matcher: &str, flags: &str| {
            json!({ "matcher": matcher, "hooks": [
                { "type": "command", "command": format!("\"/opt/innerwarden\" hook{flags}") }
            ]})
        };
        let without_reads = json!({"hooks": {"PreToolUse": [
            entry("Bash", ""),
            entry(crate::file_tools::FILE_TOOLS_MATCHER, ""),
        ]}});
        assert!(iwguard_judges_file_tools(&without_reads));
        assert!(!iwguard_judges_read_tools(&without_reads));
        let with_reads = json!({"hooks": {"PreToolUse": [
            entry("Bash", ""),
            entry(crate::file_tools::FILE_TOOLS_MATCHER, ""),
            entry(crate::file_tools::READ_TOOLS_MATCHER, ""),
        ]}});
        assert!(iwguard_judges_read_tools(&with_reads));
        let record_only = json!({"hooks": {"PreToolUse": [
            entry("Bash", ""),
            entry(crate::file_tools::READ_TOOLS_MATCHER, " --monitor"),
        ]}});
        assert!(!iwguard_judges_read_tools(&record_only));
    }

    /// Uninstall takes the file-tools half away with the rest.
    #[test]
    fn uninstall_removes_the_file_tools_hook_too() {
        let home = tempfile::TempDir::new().unwrap();
        install_hook(
            home.path(),
            "claude-code",
            None,
            Path::new("/p/innerwarden"),
            false,
            false,
        )
        .unwrap();
        uninstall_hook(home.path(), "claude-code", None).unwrap();
        let settings: Value =
            serde_json::from_slice(&fs::read(home.path().join(".claude/settings.json")).unwrap())
                .unwrap();
        assert!(!iwguard_judges_file_tools(&settings));
        assert!(!has_iwguard_wiring(&settings));
    }

    /// The read-tools half: its own entry, exact matcher, the same command
    /// and mode as the shell hook; the Bash and file merges leave it alone;
    /// an install from before it is brought up to it in its own mode; and
    /// uninstall takes it away.
    ///
    /// FAILS ON REVERT: leave `merge_pretooluse_read_hook` out of
    /// `install_hook_with_link_policy` or out of `needs_iwguard_hook_reconciliation`, or
    /// let the Bash merge collapse its hook, and an assertion here fails.
    #[test]
    fn the_read_tools_are_wired_with_the_same_command_and_mode() {
        let iw = Path::new("/opt/innerwarden");
        let read_entry = |settings: &Value| {
            settings["hooks"]["PreToolUse"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|entry| entry["matcher"] == crate::file_tools::READ_TOOLS_MATCHER)
                .cloned()
                .collect::<Vec<_>>()
        };
        for (block_review, monitor) in [(false, false), (true, false), (false, true)] {
            let home = tempfile::TempDir::new().unwrap();
            let report =
                install_hook(home.path(), "claude-code", None, iw, block_review, monitor).unwrap();
            let settings: Value =
                serde_json::from_slice(&fs::read(&report.settings_path).unwrap()).unwrap();
            let entries = read_entry(&settings);
            assert_eq!(entries.len(), 1, "{settings}");
            assert_eq!(entries[0]["hooks"].as_array().unwrap().len(), 1);
            // The line the Bash entry holds: in enforce, the fail-closed
            // script; in monitor, the program alone.
            let bash_line = settings["hooks"]["PreToolUse"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["matcher"] == "Bash")
                .map(|entry| entry["hooks"][0]["command"].clone())
                .unwrap();
            assert_eq!(entries[0]["hooks"][0]["command"], bash_line);
            // The Bash and file merges, run again, leave it as it is.
            let cmd = bash_line.as_str().unwrap();
            assert_eq!(
                merge_pretooluse_file_hook(merge_pretooluse_bash_hook(settings.clone(), cmd), cmd),
                settings
            );
            assert_eq!(merge_pretooluse_read_hook(settings.clone(), cmd), settings);
            uninstall_hook(home.path(), "claude-code", None).unwrap();
            let after: Value = serde_json::from_slice(
                &fs::read(home.path().join(".claude/settings.json")).unwrap(),
            )
            .unwrap();
            assert!(read_entry(&after).is_empty(), "{after}");
            assert!(!has_iwguard_wiring(&after), "{after}");
        }

        // Wiring from before the read tools: the Bash and file halves only.
        let old = json!({"hooks": {"PreToolUse": [
            { "matcher": "Bash", "hooks": [
                { "type": "command", "command": "\"/opt/innerwarden\" hook --agent claude-code" }
            ]},
            { "matcher": crate::file_tools::FILE_TOOLS_MATCHER, "hooks": [
                { "type": "command", "command": "\"/opt/innerwarden\" hook --agent claude-code" }
            ]}
        ]}});
        assert!(needs_iwguard_hook_reconciliation(&old, iw, false, true));
        let home = tempfile::TempDir::new().unwrap();
        let path = home.path().join(".claude/settings.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, serde_json::to_string_pretty(&old).unwrap()).unwrap();
        // Background setup asks for monitor; the enforce hook keeps enforce.
        let result =
            install_hook_no_symlinks(home.path(), "claude-code", None, iw, false, true).unwrap();
        assert!(matches!(result, AutomaticHookInstall::Installed(_)));
        let new: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let entries = read_entry(&new);
        assert_eq!(entries.len(), 1, "{new}");
        // Brought up in enforce, so as the fail-closed line, as the Bash and
        // file entries are repaired to it.
        assert_eq!(
            entries[0]["hooks"][0]["command"],
            format!("\"/opt/innerwarden\" hook --agent claude-code{CLOSED}")
        );
        assert!(!needs_iwguard_hook_reconciliation(&new, iw, false, true));

        // A hook already run for every tool (`*`) reads them too: nothing added.
        let cmd = "\"/opt/innerwarden\" hook";
        let star = json!({"hooks": {"PreToolUse": [
            { "matcher": "*", "hooks": [ { "type": "command", "command": cmd } ] }
        ]}});
        assert_eq!(merge_pretooluse_read_hook(star.clone(), cmd), star);
    }

    #[test]
    fn merge_is_idempotent() {
        let once = merge_pretooluse_bash_hook(json!({}), "cmd");
        let twice = merge_pretooluse_bash_hook(once.clone(), "cmd");
        assert_eq!(twice["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        assert_eq!(once, twice);
    }

    #[test]
    fn merge_replaces_the_previous_innerwarden_mode_and_collapses_duplicates() {
        let settings = json!({
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Write", "hooks": [
                        { "type": "command", "command": "/other.sh" }
                    ]},
                    { "matcher": "Bash", "hooks": [
                        { "type": "command", "command": "\"/opt/innerwarden\" hook" }
                    ]},
                    { "matcher": "Bash", "hooks": [
                        { "type": "command", "command": "\"/old/innerwarden\" hook --block-review" }
                    ]}
                ]
            }
        });

        let monitor = merge_pretooluse_bash_hook(settings, "\"/opt/innerwarden\" hook --monitor");
        let pre = monitor["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2, "one unrelated hook plus one InnerWarden hook");
        assert_eq!(
            pre.iter()
                .filter(|entry| is_iwguard_hook_entry(entry))
                .count(),
            1
        );
        assert!(pre.iter().any(|entry| {
            entry["hooks"][0]["command"] == "\"/opt/innerwarden\" hook --monitor"
        }));

        let enforce = merge_pretooluse_bash_hook(monitor, "\"/opt/innerwarden\" hook");
        let pre = enforce["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2);
        assert!(pre
            .iter()
            .any(|entry| { entry["hooks"][0]["command"] == "\"/opt/innerwarden\" hook" }));
        assert!(!enforce.to_string().contains("--monitor"));
    }

    #[test]
    fn hook_detection_accepts_exact_aliases_and_development_paths() {
        for command in [
            "\"/home/dev/.local/bin/iw\" hook",
            "\"/usr/local/bin/innerwarden\" hook --monitor",
            "'/work/innerwarden/target/release/innerwarden' hook --block-review",
            "\"/work/innerwarden/target/debug/iw\" hook",
            r#""C:\work\innerwarden\target\debug\innerwarden.exe" hook --monitor"#,
            "INNERWARDEN.CMD hook",
        ] {
            let hook = json!({"type": "command", "command": command});
            assert!(is_iwguard_hook(&hook), "expected alias match: {command}");
        }
    }

    #[test]
    fn hook_detection_does_not_claim_unrelated_shell_commands() {
        for command in [
            "innerwarden-helper hook",
            "/opt/not-innerwarden hook",
            "echo innerwarden hook",
            "innerwarden hook-other",
            "innerwarden hook --unrelated",
            "innerwarden hook --monitor --block-review",
            "innerwarden hook && /operator/hook",
            "\"innerwarden\"hook",
            "\"innerwarden hook\"",
            "/opt/iwrite hook",
            "/opt/other/iw hook",
            "/usr/sbin/iw hook",
        ] {
            let hook = json!({"type": "command", "command": command});
            assert!(
                !is_iwguard_hook(&hook),
                "must preserve unrelated command: {command}"
            );
        }
    }

    #[test]
    fn automatic_reconciliation_preserves_only_the_strongest_effective_bash_mode() {
        let mixed = json!({"hooks":{"PreToolUse":[
            {"matcher":"Bash","hooks":[
                {"type":"command","command":"/old/innerwarden hook --monitor"},
                {"type":"command","command":"/old/innerwarden hook"}
            ]},
            {"matcher":"Bash","hooks":[
                {"type":"command","command":"/old/innerwarden hook --block-review"}
            ]}
        ]}});
        assert_eq!(
            strongest_effective_iwguard_hook_mode(&mixed),
            Some(HookProtection::BlockReview)
        );
        assert_eq!(
            strongest_effective_iwguard_hook_mode(&json!({"hooks":{"PreToolUse":[{
                "matcher":"Write",
                "hooks":[{"command":"/old/innerwarden hook --block-review"}]
            }]}})),
            None,
            "a misplaced hook is not effective Bash protection"
        );
        assert_eq!(
            HookProtection::Enforce.max(HookProtection::Monitor),
            HookProtection::Enforce,
            "automatic monitor setup must not downgrade enforce"
        );
    }

    #[test]
    fn matcher_coverage_is_cross_version_safe_and_fail_closed() {
        for entry in [
            json!({}),
            json!({"matcher": ""}),
            json!({"matcher": "*"}),
            json!({"matcher": "Bash"}),
            json!({"matcher": "Bash|Write"}),
        ] {
            assert_eq!(
                bash_matcher_coverage(&entry),
                BashMatcherCoverage::Includes,
                "matcher must certainly include Bash: {entry}"
            );
        }
        for entry in [
            json!({"matcher": "Write"}),
            json!({"matcher": "Edit|Write"}),
        ] {
            assert_eq!(
                bash_matcher_coverage(&entry),
                BashMatcherCoverage::Excludes,
                "matcher must certainly exclude Bash: {entry}"
            );
        }
        for entry in [
            json!({"matcher": "^Bash$"}),
            json!({"matcher": "Bash.*"}),
            json!({"matcher": "Write | Bash"}),
            json!({"matcher": "Edit, Bash"}),
            json!({"matcher": "Edit, Write"}),
            json!({"matcher": " Bash "}),
            json!({"matcher": ["Bash"]}),
        ] {
            assert_eq!(
                bash_matcher_coverage(&entry),
                BashMatcherCoverage::Ambiguous,
                "JS-regex or invalid matcher must remain ambiguous: {entry}"
            );
        }
    }

    #[test]
    fn match_all_and_exact_list_hooks_are_effective_bash_protection() {
        for matcher in [None, Some(""), Some("*"), Some("Bash|Write")] {
            let mut entry = json!({"hooks":[{
                "type":"command",
                "command":"/old/innerwarden hook --block-review"
            }]});
            if let Some(matcher) = matcher {
                entry["matcher"] = json!(matcher);
            }
            let settings = json!({"hooks":{"PreToolUse":[entry]}});
            assert_eq!(
                strongest_effective_iwguard_hook_mode(&settings),
                Some(HookProtection::BlockReview),
                "effective enforcement must be preserved for matcher {matcher:?}"
            );
            assert_eq!(
                effective_iwguard_hook_mode(&settings),
                Some(EffectiveHookMode::Enforce)
            );
            assert!(has_iwguard_hook(&settings));
        }
    }

    #[test]
    fn automatic_setup_skips_ambiguous_js_regex_without_rewriting_enforcement() {
        let home = tempfile::TempDir::new().unwrap();
        let settings_path = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
        let original = serde_json::to_vec_pretty(&json!({
            "hooks":{"PreToolUse":[{
                "matcher":"^Bash$",
                "hooks":[{
                    "type":"command",
                    "command":"/old/innerwarden hook --block-review"
                }]
            }]}
        }))
        .unwrap();
        std::fs::write(&settings_path, &original).unwrap();

        let result = install_hook_no_symlinks(
            home.path(),
            "claude-code",
            None,
            Path::new("/current/innerwarden"),
            false,
            true,
        )
        .unwrap();
        assert!(matches!(result, AutomaticHookInstall::SkippedExisting));
        assert_eq!(std::fs::read(&settings_path).unwrap(), original);

        let value: Value = serde_json::from_slice(&original).unwrap();
        assert!(has_iwguard_wiring(&value));
        assert!(!has_iwguard_hook(&value));
        assert!(!needs_iwguard_hook_reconciliation(
            &value,
            Path::new("/current/innerwarden"),
            false,
            true,
        ));
    }

    #[test]
    fn merge_reconciles_all_aliases_without_losing_operator_fields_or_hooks() {
        let settings = json!({
            "hooks": {"PreToolUse": [
                {"matcher": "Bash", "operator_entry": true, "hooks": [
                    {"type": "command", "command": "/operator/before", "timeout": 3},
                    {"type": "command", "command": "\"/repo/target/debug/iw\" hook --block-review", "timeout": 17, "operator_note": "keep"}
                ]},
                {"matcher": "Bash", "hooks": [
                    {"type": "command", "command": "\"/repo/target/release/innerwarden\" hook"},
                    {"type": "command", "command": "/operator/after"}
                ]},
                {"matcher": "Write", "hooks": [
                    {"type": "command", "command": "innerwarden hook --monitor"},
                    {"type": "command", "command": "/operator/write"}
                ]}
            ]}
        });

        let out = merge_pretooluse_bash_hook(
            settings,
            "\"/repo/target/release/innerwarden\" hook --monitor",
        );
        let entries = out["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| is_iwguard_hook_entry(entry))
                .count(),
            1
        );
        let installed = entries
            .iter()
            .flat_map(|entry| entry["hooks"].as_array().unwrap())
            .find(|hook| is_iwguard_hook(hook))
            .unwrap();
        assert_eq!(
            installed["command"],
            "\"/repo/target/release/innerwarden\" hook --monitor"
        );
        assert_eq!(installed["timeout"], 17);
        assert_eq!(installed["operator_note"], "keep");
        assert!(entries.iter().any(|entry| entry["operator_entry"] == true));
        for operator_command in ["/operator/before", "/operator/after", "/operator/write"] {
            assert!(out.to_string().contains(operator_command));
        }
    }

    #[test]
    fn merge_preserves_existing_settings_and_hooks() {
        let existing = json!({
            "model": "sonnet",
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Write", "hooks": [ { "type": "command", "command": "/other.sh" } ] }
                ],
                "PostToolUse": [ { "matcher": "Bash", "hooks": [] } ]
            }
        });
        let out = merge_pretooluse_bash_hook(existing, "cmd");
        assert_eq!(out["model"], "sonnet");
        assert!(out["hooks"]["PostToolUse"].is_array());
        let pre = out["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2);
        assert!(pre.iter().any(|e| e["matcher"] == "Write"));
        assert!(pre.iter().any(|e| e["hooks"][0]["command"] == "cmd"));
    }

    #[test]
    fn merge_preserves_operator_owned_empty_hook_entries() {
        let existing = json!({"hooks":{"PreToolUse":[
            {"matcher":"Write","hooks":[]}
        ]}});
        let out = merge_pretooluse_bash_hook(existing, "cmd");
        let entries = out["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], json!({"matcher":"Write","hooks":[]}));
    }

    #[test]
    fn mode_switch_preserves_unrelated_hooks_sharing_the_same_entry() {
        let settings = json!({"hooks":{"PreToolUse":[{
            "matcher":"Bash",
            "hooks":[
                {"type":"command","command":"/before.sh","timeout":7},
                {"type":"command","command":"\"/opt/innerwarden\" hook","timeout":12},
                {"type":"command","command":"/after.sh"}
            ]
        }]}});
        let out = merge_pretooluse_bash_hook(settings, "\"/opt/innerwarden\" hook --monitor");
        let hooks = out["hooks"]["PreToolUse"][0]["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 3);
        assert_eq!(hooks[0]["command"], "/before.sh");
        assert_eq!(hooks[0]["timeout"], 7);
        assert_eq!(hooks[1]["command"], "\"/opt/innerwarden\" hook --monitor");
        assert_eq!(hooks[1]["timeout"], 12);
        assert_eq!(hooks[2]["command"], "/after.sh");
    }

    #[test]
    fn merge_repairs_non_object_settings() {
        let out = merge_pretooluse_bash_hook(json!([1, 2, 3]), "cmd");
        assert!(out["hooks"]["PreToolUse"].is_array());
    }

    #[test]
    fn automatic_merge_accepts_only_non_destructive_settings_shapes() {
        assert!(is_automatic_merge_safe(&json!({})));
        assert!(is_automatic_merge_safe(&json!({"hooks": {}})));
        assert!(is_automatic_merge_safe(
            &json!({"hooks": {"PreToolUse": []}})
        ));
        assert!(is_automatic_merge_safe(&json!({"hooks": {"PreToolUse": [{
            "matcher": "Bash|Write",
            "hooks": []
        }]}})));
        assert!(!is_automatic_merge_safe(&json!([1, 2, 3])));
        assert!(!is_automatic_merge_safe(&json!({"hooks": "custom"})));
        assert!(!is_automatic_merge_safe(
            &json!({"hooks": {"PreToolUse": "custom"}})
        ));
        for malformed in [
            json!({"hooks": {"PreToolUse": ["custom"]}}),
            json!({"hooks": {"PreToolUse": [{"matcher": ["Bash"], "hooks": []}]}}),
            json!({"hooks": {"PreToolUse": [{"matcher": "Bash"}]}}),
            json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": {}}]}}),
            json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": ["custom"]}]}}),
        ] {
            assert!(
                !is_automatic_merge_safe(&malformed),
                "automatic merge must reject malformed nested structure: {malformed}"
            );
        }
    }

    /// NEW-20261112-hook-missing-binary-fails-open. The line an enforcing hook
    /// runs in, run by `sh -c` the way Claude Code runs it: a binary that is
    /// gone, cannot run or dies refuses (2) in enforce; in monitor the same
    /// failure stays a non-blocking error, because monitor never acts. Every
    /// code the binary itself returns passes through unchanged.
    ///
    /// Run under `sh` and, where it exists, `bash`: macOS `/bin/sh` is bash,
    /// which execs a lone command in place of itself, so a monitor line whose
    /// binary is killed takes the shell down with the same signal instead of
    /// returning 128 + n. Both read as the same failure here.
    #[cfg(unix)]
    #[test]
    fn a_refusing_hook_that_cannot_run_refuses_and_monitor_never_acts() {
        use std::os::unix::process::ExitStatusExt;
        let shells: Vec<&str> = ["sh", "/bin/bash"]
            .into_iter()
            .filter(|s| *s == "sh" || Path::new(s).exists())
            .collect();
        for shell in shells {
            refusing_hook_cases(shell, |status: std::process::ExitStatus| {
                status.code().or(status.signal().map(|n| 128 + n))
            });
        }
    }

    #[cfg(unix)]
    fn refusing_hook_cases(shell: &str, code: impl Fn(std::process::ExitStatus) -> Option<i32>) {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let bin = dir.path().join("innerwarden");
        let run = |line: &str| {
            code(
                std::process::Command::new(shell)
                    .args(["-c", line])
                    .stdin(std::process::Stdio::null())
                    .status()
                    .unwrap(),
            )
        };
        let script = |body: &str, mode: u32| {
            fs::write(&bin, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&bin, fs::Permissions::from_mode(mode)).unwrap();
        };
        let enforce = hook_command_for(&bin, false, false, Some("claude-code"));
        let review = hook_command_for(&bin, true, false, Some("claude-code"));
        let monitor = hook_command_for(&bin, false, true, Some("claude-code"));
        assert!(!monitor.contains(FAIL_CLOSED), "{monitor}");

        // Gone: 127 from the shell. Before this, Claude Code ran the call.
        assert_eq!(run(&enforce), Some(2));
        assert_eq!(run(&review), Some(2));
        assert_eq!(run(&monitor), Some(127));
        // Not executable: 126.
        script("exit 0", 0o644);
        assert_eq!(run(&enforce), Some(2));
        assert_eq!(run(&monitor), Some(126));
        // Killed by a signal: 128 + n.
        script("kill -KILL $$", 0o755);
        assert_eq!(run(&enforce), Some(2));
        assert_eq!(run(&monitor), Some(137));
        // The binary's own answers are untouched.
        for code in [0, 1, 2] {
            script(&format!("exit {code}"), 0o755);
            assert_eq!(run(&enforce), Some(code));
            assert_eq!(run(&monitor), Some(code));
        }
    }

    /// The wrapped line stays ours, so uninstall and repair find it; anything
    /// else after it, or a tail that is not exactly ours, is not.
    #[test]
    fn the_fail_closed_tail_is_recognised_and_nothing_wider_is() {
        for (command, mode) in [
            (
                format!("\"/x/innerwarden\" hook --agent claude-code{FAIL_CLOSED}"),
                HookProtection::Enforce,
            ),
            (
                format!("\"/x/innerwarden\" hook --block-review{FAIL_CLOSED}"),
                HookProtection::BlockReview,
            ),
            // Never written, but still ours: repair rewrites it to plain monitor.
            (
                format!("\"/x/innerwarden\" hook --monitor{FAIL_CLOSED}"),
                HookProtection::Monitor,
            ),
        ] {
            assert_eq!(
                iwguard_hook_mode(&json!({ "command": command })),
                Some(mode),
                "{command}"
            );
        }
        for command in [
            format!("\"/x/innerwarden\" hook{FAIL_CLOSED}; rm -rf /"),
            format!("\"/x/innerwarden\" hook{FAIL_CLOSED}{FAIL_CLOSED}"),
            "\"/x/innerwarden\" hook || exit 2".to_string(),
            "\"/x/innerwarden\" hook || { s=$?; [ $s -ge 1 ] && exit 2; exit $s; }".to_string(),
        ] {
            assert_eq!(
                iwguard_hook_mode(&json!({ "command": command })),
                None,
                "{command}"
            );
        }
        // An enforce hook written before the tail is drift: repair adds it.
        let plain = "\"/x/innerwarden\" hook --agent claude-code";
        let settings = json!({"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": plain}]},
            {"matcher": crate::file_tools::FILE_TOOLS_MATCHER,
             "hooks": [{"type": "command", "command": plain}]},
            {"matcher": crate::file_tools::READ_TOOLS_MATCHER,
             "hooks": [{"type": "command", "command": plain}]}
        ]}});
        assert_eq!(
            needs_iwguard_hook_reconciliation(&settings, Path::new("/x/innerwarden"), false, true),
            cfg!(unix)
        );
        // And the wrapped one is removed by uninstall like any other.
        let wrapped = json!({"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command",
              "command": format!("{plain}{FAIL_CLOSED}")}]}
        ]}});
        assert_eq!(remove_iwguard_pretooluse_hook(wrapped).1, 1);
    }

    /// The rollback limit: the grammar of every release before the tail does
    /// not read a line that carries it as ours, so an older binary neither
    /// replaces nor removes it. Documented in the README ("Rolling back").
    #[test]
    fn a_binary_from_before_the_tail_does_not_know_the_line() {
        let plain = "\"/x/innerwarden\" hook --agent claude-code";
        // What a release before the tail recognised: the plain grammar, then
        // the same reading of the words.
        let before_the_tail = |command: &str| {
            plain_hook_command_words(command).and_then(|words| hook_parts_of_words(&words))
        };
        let wrapped = format!("{plain}{FAIL_CLOSED}");
        assert!(before_the_tail(plain).is_some());
        assert_eq!(
            before_the_tail(&wrapped),
            None,
            "an older binary reads it as foreign"
        );
        assert!(iwguard_hook_mode(&json!({ "command": wrapped })).is_some());
    }

    /// Background setup keeps the mode of each half it rewrites: an enforcing
    /// file or read hook with no enforcing Bash hook stays enforcing, and a
    /// monitor half beside an enforcing Bash hook stays monitor.
    #[test]
    fn automatic_setup_keeps_the_mode_of_every_half() {
        let iw = Path::new("/opt/innerwarden");
        let enforce = format!("\"/opt/innerwarden\" hook --agent claude-code{CLOSED}");
        let monitor = "\"/opt/innerwarden\" hook --monitor --agent claude-code".to_string();
        let entry = |matcher: &str, command: &str| json!({"matcher": matcher, "hooks": [{"type": "command", "command": command}]});
        let commands = |v: &Value, matcher: &str| -> Vec<String> {
            v["hooks"]["PreToolUse"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|e| e["matcher"] == matcher)
                .flat_map(|e| e["hooks"].as_array().unwrap().clone())
                .map(|h| h["command"].as_str().unwrap().to_string())
                .collect()
        };
        let file = crate::file_tools::FILE_TOOLS_MATCHER;
        let read = crate::file_tools::READ_TOOLS_MATCHER;
        for (wired, want_bash, want_file, want_read) in [
            // Write|Edit in enforce, no Bash line: the file half stays enforce,
            // the new halves take the monitor automatic setup asks for.
            (
                json!({"hooks": {"PreToolUse": [entry(file, &enforce)]}}),
                &monitor,
                &enforce,
                &monitor,
            ),
            // Write|Edit and Read in enforce, Bash in monitor.
            (
                json!({"hooks": {"PreToolUse": [
                    entry("Bash", &monitor), entry(file, &enforce), entry(read, &enforce)]}}),
                &monitor,
                &enforce,
                &enforce,
            ),
            // The other way: a monitor read half beside an enforcing Bash hook.
            (
                json!({"hooks": {"PreToolUse": [
                    entry("Bash", &enforce), entry(file, &enforce), entry(read, &monitor)]}}),
                &enforce,
                &enforce,
                &monitor,
            ),
        ] {
            let home = tempfile::TempDir::new().unwrap();
            let path = home.path().join(".claude/settings.json");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, serde_json::to_vec_pretty(&wired).unwrap()).unwrap();
            install_hook_no_symlinks(home.path(), "claude-code", None, iw, false, true).unwrap();
            let now: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(commands(&now, "Bash"), vec![want_bash.clone()], "{wired}");
            assert_eq!(commands(&now, file), vec![want_file.clone()], "{wired}");
            assert_eq!(commands(&now, read), vec![want_read.clone()], "{wired}");
            // And a second pass changes nothing.
            let body = fs::read(&path).unwrap();
            install_hook_no_symlinks(home.path(), "claude-code", None, iw, false, true).unwrap();
            assert_eq!(fs::read(&path).unwrap(), body, "{wired}");
        }
    }

    /// The PostToolUse half follows the same rule: an enforcing line there
    /// with no enforcing Bash hook stays enforcing, a monitor one beside an
    /// enforcing Bash hook stays monitor, and a missing one takes the Bash
    /// half's mode.
    #[test]
    fn automatic_setup_keeps_the_mode_of_the_posttooluse_half() {
        let iw = Path::new("/opt/innerwarden");
        let enforce = format!("\"/opt/innerwarden\" hook --agent claude-code{CLOSED}");
        let monitor = "\"/opt/innerwarden\" hook --monitor --agent claude-code".to_string();
        let entry = |matcher: &str, command: &str| json!({"matcher": matcher, "hooks": [{"type": "command", "command": command}]});
        let post_commands = |v: &Value| -> Vec<String> {
            v["hooks"]["PostToolUse"]
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|e| e["hooks"].as_array().unwrap().clone())
                .map(|h| h["command"].as_str().unwrap().to_string())
                .collect()
        };
        for (wired, want_post) in [
            // PostToolUse in enforce, no Bash line.
            (
                json!({"hooks": {"PostToolUse": [entry("*", &enforce)]}}),
                &enforce,
            ),
            // PostToolUse in enforce, Bash in monitor.
            (
                json!({"hooks": {"PreToolUse": [entry("Bash", &monitor)],
                                 "PostToolUse": [entry("*", &enforce)]}}),
                &enforce,
            ),
            // A monitor PostToolUse line beside an enforcing Bash hook.
            (
                json!({"hooks": {"PreToolUse": [entry("Bash", &enforce)],
                                 "PostToolUse": [entry("*", &monitor)]}}),
                &monitor,
            ),
            // No PostToolUse line yet: it takes the Bash half's mode.
            (
                json!({"hooks": {"PreToolUse": [entry("Bash", &enforce)]}}),
                &enforce,
            ),
        ] {
            let home = tempfile::TempDir::new().unwrap();
            let path = home.path().join(".claude/settings.json");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, serde_json::to_vec_pretty(&wired).unwrap()).unwrap();
            install_hook_no_symlinks(home.path(), "claude-code", None, iw, false, true).unwrap();
            let now: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(post_commands(&now), vec![want_post.clone()], "{wired}");
            // And a second pass changes nothing.
            let body = fs::read(&path).unwrap();
            install_hook_no_symlinks(home.path(), "claude-code", None, iw, false, true).unwrap();
            assert_eq!(fs::read(&path).unwrap(), body, "{wired}");
        }
    }

    #[test]
    fn hook_command_quotes_path_and_wires_block_review() {
        let c = hook_command(Path::new("/usr/local/bin/innerwarden"), false, false);
        assert_eq!(c, format!("\"/usr/local/bin/innerwarden\" hook{CLOSED}"));
        let c2 = hook_command(Path::new("/x/innerwarden"), true, false);
        assert_eq!(
            c2,
            format!("\"/x/innerwarden\" hook --block-review{CLOSED}")
        );
        // monitor wins over block_review (records, never blocks).
        let c3 = hook_command(Path::new("/x/innerwarden"), true, true);
        assert_eq!(c3, "\"/x/innerwarden\" hook --monitor");
        let c4 = hook_command(Path::new("/x/innerwarden"), false, true);
        assert_eq!(c4, "\"/x/innerwarden\" hook --monitor");
        assert_eq!(
            hook_command(Path::new("/x/innerwarden"), true, false),
            hook_command_shaped(Path::new("/x/innerwarden"), true, false, None, cfg!(unix))
        );
    }

    #[test]
    fn a_hook_that_names_its_agent_is_still_recognised_in_every_mode() {
        for (command, mode, agent) in [
            (
                "\"/x/innerwarden\" hook --agent claude-code",
                HookProtection::Enforce,
                Some("claude-code"),
            ),
            (
                "\"/x/innerwarden\" hook --monitor --agent claude-code",
                HookProtection::Monitor,
                Some("claude-code"),
            ),
            (
                "\"/x/innerwarden\" hook --block-review --agent claude-code",
                HookProtection::BlockReview,
                Some("claude-code"),
            ),
            (
                "\"/x/innerwarden\" hook --monitor",
                HookProtection::Monitor,
                None,
            ),
        ] {
            let hook = json!({"command": command});
            assert_eq!(
                iwguard_hook_parts(&hook),
                Some((mode, agent.map(str::to_string))),
                "{command}"
            );
        }
        // Anything wider than the grammar the installer writes is not ours.
        for command in [
            "\"/x/innerwarden\" hook --agent",
            "\"/x/innerwarden\" hook --agent Claude",
            "\"/x/innerwarden\" hook --agent claude-code --monitor",
            "\"/x/innerwarden\" hook --monitor --monitor",
            "\"/x/innerwarden\" hook --agent a --agent b",
            "\"/x/innerwarden\" hook --agent claude-code; rm -rf /",
        ] {
            assert_eq!(
                iwguard_hook_parts(&json!({"command": command})),
                None,
                "{command}"
            );
        }
        assert_eq!(
            hook_command_for(
                Path::new("/x/innerwarden"),
                false,
                true,
                Some("claude-code")
            ),
            "\"/x/innerwarden\" hook --monitor --agent claude-code"
        );
        // An id that is not a plain id is left out, never quoted in.
        assert_eq!(
            hook_command_for(Path::new("/x/innerwarden"), false, false, Some("x; rm")),
            format!("\"/x/innerwarden\" hook{CLOSED}")
        );
        assert_eq!(
            hook_command_for(Path::new("/x/innerwarden"), false, false, Some("x; rm")),
            hook_command_for(Path::new("/x/innerwarden"), false, false, None)
        );
    }

    /// A hook written before `--agent` existed is CORRECT wiring. Adding the
    /// flag must never turn every existing install into drift that the
    /// background reconciler then rewrites.
    #[test]
    fn a_hook_without_agent_flag_is_not_drift() {
        let iw = Path::new("/opt/innerwarden");
        for command in [
            "\"/opt/innerwarden\" hook --monitor",
            "\"/opt/innerwarden\" hook --monitor --agent claude-code",
        ] {
            let settings = json!({"hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": command}]},
                {"matcher": crate::file_tools::FILE_TOOLS_MATCHER,
                 "hooks": [{"type": "command", "command": command}]},
                {"matcher": crate::file_tools::READ_TOOLS_MATCHER,
                 "hooks": [{"type": "command", "command": command}]}
            ]}});
            assert!(
                !needs_iwguard_hook_reconciliation(&settings, iw, false, true),
                "{command}"
            );
            // Without the file-tools and read-tools halves it needs work, and
            // the work adds them without renaming the Bash hook.
            let bash_only = json!({"hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}
            ]}});
            assert!(needs_iwguard_hook_reconciliation(
                &bash_only, iw, false, true
            ));
            let repaired = merge_pretooluse_read_hook(
                merge_pretooluse_file_hook(
                    merge_pretooluse_bash_hook(bash_only.clone(), command),
                    command,
                ),
                command,
            );
            assert_eq!(
                repaired["hooks"]["PreToolUse"][0],
                bash_only["hooks"]["PreToolUse"][0]
            );
            assert!(iwguard_judges_file_tools(&repaired));
        }
        // Path drift is still drift, and its repair keeps the hook as it was.
        let old_path = json!({"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "\"/old/innerwarden\" hook --monitor"}]}
        ]}});
        assert!(needs_iwguard_hook_reconciliation(
            &old_path, iw, false, true
        ));
    }

    #[test]
    fn a_hand_run_install_names_an_unnamed_hook_and_background_setup_does_not() {
        let unnamed = r#"{"hooks":{"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"\"/opt/innerwarden\" hook --monitor"}]}],"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"\"/opt/innerwarden\" hook --monitor"}]},{"matcher":"Write|Edit|MultiEdit|NotebookEdit","hooks":[{"type":"command","command":"\"/opt/innerwarden\" hook --monitor"}]},{"matcher":"Read|Grep|Glob","hooks":[{"type":"command","command":"\"/opt/innerwarden\" hook --monitor"}]}]}}"#;
        // By hand: the name is added, in the mode asked for.
        let home = tempfile::TempDir::new().unwrap();
        let settings = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(&settings, unnamed).unwrap();
        install_hook(
            home.path(),
            "claude-code",
            None,
            Path::new("/opt/innerwarden"),
            false,
            true,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "\"/opt/innerwarden\" hook --monitor --agent claude-code"
        );
        assert_eq!(unnamed_hook_reconnect_flag(&v), None, "it is named now");

        // In the background: a correct hook is never rewritten to add a name.
        let home = tempfile::TempDir::new().unwrap();
        let settings = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(&settings, unnamed).unwrap();
        let result = install_hook_no_symlinks(
            home.path(),
            "claude-code",
            None,
            Path::new("/opt/innerwarden"),
            false,
            true,
        )
        .unwrap();
        assert!(matches!(result, AutomaticHookInstall::SkippedExisting));
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), unnamed);
    }

    #[test]
    fn a_hook_that_names_its_agent_keeps_the_name_on_reinstall() {
        let home = tempfile::TempDir::new().unwrap();
        let settings = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(
            &settings,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"\"/opt/innerwarden\" hook --monitor --agent claude-code"}]}]}}"#,
        )
        .unwrap();
        install_hook(
            home.path(),
            "claude-code",
            None,
            Path::new("/opt/innerwarden"),
            false,
            false,
        )
        .unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            format!("\"/opt/innerwarden\" hook --agent claude-code{CLOSED}"),
            "switching mode rewrites the mode and keeps the name"
        );
    }

    #[test]
    fn the_reconnect_flag_keeps_the_hooks_own_mode() {
        let hook = |command: &str| json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}]}});
        assert_eq!(
            unnamed_hook_reconnect_flag(&hook("\"/opt/innerwarden\" hook --monitor")),
            Some(" --monitor")
        );
        assert_eq!(
            unnamed_hook_reconnect_flag(&hook("\"/opt/innerwarden\" hook")),
            Some("")
        );
        assert_eq!(
            unnamed_hook_reconnect_flag(&hook("\"/opt/innerwarden\" hook --block-review")),
            Some(" --strict")
        );
        assert_eq!(unnamed_hook_reconnect_flag(&json!({})), None);
        let mixed = json!({"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "\"/opt/innerwarden\" hook --monitor"}]},
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "\"/opt/innerwarden\" hook"}]},
        ]}});
        assert_eq!(unnamed_hook_reconnect_flag(&mixed), None);
    }

    #[test]
    fn install_hook_writes_and_merges_settings() {
        let home = tempfile::TempDir::new().unwrap();
        let settings = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(&settings, r#"{"model":"sonnet"}"#).unwrap();

        let iw = Path::new("/opt/innerwarden");
        install_hook(home.path(), "claude-code", None, iw, true, false).unwrap();

        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["model"], "sonnet", "unrelated key preserved");
        // A new connection names the agent it serves.
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            format!("\"/opt/innerwarden\" hook --block-review --agent claude-code{CLOSED}")
        );

        // Idempotent: the Bash hook, the file-tools hook and the read-tools
        // hook, once each.
        install_hook(home.path(), "claude-code", None, iw, true, false).unwrap();
        let v2: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v2["hooks"]["PreToolUse"].as_array().unwrap().len(), 3);
    }

    /// `install` writes a `timeout` of [`HOOK_TIMEOUT_SECS`] on every line of
    /// ours (Bash, file tools, read tools, results), above the longest the
    /// hook takes, keeps an operator's own `timeout` and leaves the
    /// operator's hooks alone. Background setup writes none, and keeps each
    /// half's mode as before.
    ///
    /// FAILS ON REVERT: drop `with_hook_timeouts` from the install and the
    /// lines name no timeout, so Claude Code waits 600 s on a hook.
    #[test]
    fn install_writes_a_timeout_above_the_longest_the_hook_takes() {
        let home = tempfile::TempDir::new().unwrap();
        let settings = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(
            &settings,
            serde_json::to_string(&json!({"hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [
                    {"type": "command", "command": "/operator/lint.sh"},
                    {"type": "command", "command": "\"/old/innerwarden\" hook --monitor", "timeout": 9}
                ]},
                {"matcher": crate::file_tools::FILE_TOOLS_MATCHER, "hooks": [
                    {"type": "command", "command": "\"/old/innerwarden\" hook"}
                ]}
            ]}}))
            .unwrap(),
        )
        .unwrap();
        let iw = Path::new("/opt/innerwarden");
        // Background setup adds no timeout to a line, and keeps each half's
        // mode: the file-tools half enforced before and still does.
        install_hook_no_symlinks(home.path(), "claude-code", None, iw, false, true).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(
            exact_matcher_iwguard_mode(&v, crate::file_tools::FILE_TOOLS_MATCHER),
            Some(HookProtection::Enforce)
        );
        assert!(
            !serde_json::to_string(&v)
                .unwrap()
                .contains(&format!("\"timeout\":{HOOK_TIMEOUT_SECS}")),
            "{v}"
        );
        // An explicit install writes it on every line of ours.
        install_hook(home.path(), "claude-code", None, iw, false, true).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        let mut ours = 0;
        for event in ["PreToolUse", "PostToolUse"] {
            for entry in v["hooks"][event].as_array().unwrap() {
                for hook in entry["hooks"].as_array().unwrap() {
                    let command = hook["command"].as_str().unwrap();
                    if command == "/operator/lint.sh" {
                        assert!(hook.get("timeout").is_none(), "{hook}");
                        continue;
                    }
                    ours += 1;
                    let want = if entry["matcher"] == "Bash" {
                        9
                    } else {
                        HOOK_TIMEOUT_SECS
                    };
                    assert_eq!(hook["timeout"], want, "{event} {hook}");
                }
            }
        }
        assert_eq!(ours, 4, "{v}");
        assert_eq!(iwguard_bash_hook_timeout(&v), Some(Some(9)));
        // A second background run finds nothing to change.
        let before = std::fs::read_to_string(&settings).unwrap();
        install_hook_no_symlinks(home.path(), "claude-code", None, iw, false, true).unwrap();
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), before);
    }

    /// What the settings say of the wait for the Bash hook: none of ours,
    /// ours with no timeout, or the shortest of ours.
    #[test]
    fn the_bash_hooks_timeout_is_read_back() {
        assert_eq!(iwguard_bash_hook_timeout(&json!({})), None);
        let line = |timeout: Option<Value>| {
            let mut hook = json!({"type": "command", "command": "\"/opt/innerwarden\" hook"});
            if let Some(t) = timeout {
                hook["timeout"] = t;
            }
            hook
        };
        let one = |hooks: Vec<Value>| json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": hooks}]}});
        assert_eq!(
            iwguard_bash_hook_timeout(&one(vec![line(None)])),
            Some(None)
        );
        assert_eq!(
            iwguard_bash_hook_timeout(&one(vec![line(Some(json!(50))), line(Some(json!(7.5)))])),
            Some(Some(8))
        );
        // An operator's hook is not ours.
        assert_eq!(
            iwguard_bash_hook_timeout(&one(vec![
                json!({"type": "command", "command": "/x", "timeout": 3})
            ])),
            None
        );
    }

    #[test]
    fn install_hook_accepts_claude_aliases_without_changing_agent_identity() {
        let home = tempfile::TempDir::new().unwrap();
        let iw = Path::new("/opt/innerwarden");
        let report = install_hook(home.path(), "claude-code", None, iw, false, false).unwrap();
        let expected = std::fs::read(&report.settings_path).unwrap();
        for alias in ["claude", " CLAUDE ", "Claude Code", "CLAUDE-CODE"] {
            let alias_home = tempfile::TempDir::new().unwrap();
            let report = install_hook(alias_home.path(), alias, None, iw, false, false).unwrap();
            assert_eq!(std::fs::read(&report.settings_path).unwrap(), expected);
            assert!(report.hook_command.contains(" --agent claude-code"));

            install_hook(alias_home.path(), "claude-code", None, iw, false, false).unwrap();
            assert_eq!(std::fs::read(&report.settings_path).unwrap(), expected);
        }
    }

    #[test]
    fn install_hook_aliases_print_the_same_guidance_without_writing() {
        let home = tempfile::TempDir::new().unwrap();
        let iw = Path::new("/opt/innerwarden");
        for (alias, id) in [
            ("codex", "codex-cli"),
            ("openai-codex", "codex-cli"),
            ("gemini", "gemini-cli"),
            (" CODEX ", "codex-cli"),
            (" GEMINI ", "gemini-cli"),
        ] {
            assert_eq!(
                install_hook(home.path(), alias, None, iw, false, false).unwrap_err(),
                install_hook(home.path(), id, None, iw, false, false).unwrap_err()
            );
        }
        assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
    }

    #[test]
    fn detect_claude_code_logic() {
        // on PATH -> detected regardless of the dir signal
        assert!(detect_claude_code(true, false));
        assert!(detect_claude_code(true, true));
        // not on PATH, no meaningful dir -> honestly not detected
        assert!(!detect_claude_code(false, false));
        // not on PATH but a configured ~/.claude -> detected
        assert!(detect_claude_code(false, true));
    }

    #[test]
    fn claude_dir_configured_ignores_empty_dir() {
        // no ~/.claude at all -> not configured
        let fresh = tempfile::TempDir::new().unwrap();
        assert!(!claude_dir_configured(fresh.path()));
        // empty ~/.claude (a leftover) -> NOT counted, stays honest
        let empty = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(empty.path().join(".claude")).unwrap();
        assert!(!claude_dir_configured(empty.path()));
        // ~/.claude with settings.json -> configured
        let with_settings = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(with_settings.path().join(".claude")).unwrap();
        std::fs::write(with_settings.path().join(".claude/settings.json"), "{}").unwrap();
        assert!(claude_dir_configured(with_settings.path()));
        // ~/.claude with some other content -> configured
        let with_content = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(with_content.path().join(".claude/projects")).unwrap();
        assert!(claude_dir_configured(with_content.path()));
    }

    #[test]
    fn install_hook_respects_explicit_settings_path() {
        let home = tempfile::TempDir::new().unwrap();
        let custom = home.path().join("custom/place/settings.json");
        let r = install_hook(
            home.path(),
            "claude-code",
            Some(custom.to_str().unwrap()),
            Path::new("/x/innerwarden"),
            false,
            false,
        )
        .unwrap();
        assert!(custom.exists());
        assert_eq!(r.settings_path, custom);
        assert!(!r.block_review);
        assert!(!r.monitor);
    }

    #[test]
    fn install_hook_monitor_writes_monitor_flag() {
        let home = tempfile::TempDir::new().unwrap();
        let settings = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        let r = install_hook(
            home.path(),
            "claude-code",
            None,
            Path::new("/opt/innerwarden"),
            true, // block_review set, but monitor must win
            true,
        )
        .unwrap();
        assert!(r.monitor);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "\"/opt/innerwarden\" hook --monitor --agent claude-code"
        );
    }

    /// REGRESSION ANCHOR. A KNOWN agent without a hook surface must be routed to
    /// the mechanism that covers it, not refused. The old message said "only
    /// 'claude-code' is supported today", which on a host running Cursor read as
    /// "InnerWarden cannot protect this" and was false: the MCP proxy covers it.
    ///
    /// FAILS ON REVERT: restore the blanket refusal and the guidance check trips.
    #[test]
    fn a_known_agent_without_a_hook_is_routed_not_refused() {
        let home = tempfile::TempDir::new().unwrap();
        let err =
            install_hook(home.path(), "cursor", None, Path::new("/x"), false, false).unwrap_err();
        assert!(err.contains("Cursor"), "must name the agent: {err}");
        assert!(
            err.contains("innerwarden agents connect"),
            "must name the AUTOMATIC mechanism that covers it: {err}"
        );
        assert!(
            !err.contains("only 'claude-code'"),
            "must not claim the product supports one agent: {err}"
        );
    }

    /// An agent nobody has heard of is a typo, and the error should list what is
    /// accepted rather than only what is not.
    #[test]
    fn an_unknown_agent_lists_what_is_accepted() {
        let home = tempfile::TempDir::new().unwrap();
        let err = install_hook(
            home.path(),
            "not-an-agent",
            None,
            Path::new("/x"),
            false,
            false,
        )
        .unwrap_err();
        assert!(err.contains("unknown agent"));
        assert!(err.contains("claude-code") && err.contains("openclaw"));
    }

    /// OpenClaw has no hook surface, and must be routed to the MCP path that
    /// does cover it rather than refused.
    #[test]
    fn openclaw_is_routed_to_its_mcp_path() {
        let home = tempfile::TempDir::new().unwrap();
        let err =
            install_hook(home.path(), "openclaw", None, Path::new("/x"), false, false).unwrap_err();
        assert!(err.contains("OpenClaw"));
        assert!(
            err.contains("innerwarden agents connect openclaw"),
            "must name the automatic mechanism that covers it: {err}"
        );
        assert!(
            err.contains("plugin") && err.contains("its own tools"),
            "and must say what screens its own tools: {err}"
        );
    }

    #[test]
    fn has_iwguard_hook_detects_connected_state() {
        assert!(!has_iwguard_hook(&json!({})));
        assert!(!has_iwguard_hook(&json!({"hooks": {"PreToolUse": []}})));
        let other = json!({"hooks": {"PreToolUse": [
            {"matcher":"Bash","hooks":[{"type":"command","command":"/other.sh"}]}
        ]}});
        assert!(!has_iwguard_hook(&other));
        let wired = merge_pretooluse_bash_hook(json!({}), "\"/x/innerwarden\" hook");
        assert!(has_iwguard_hook(&wired));
    }

    #[test]
    fn wiring_is_distinct_from_an_effective_bash_hook_and_can_be_reconciled() {
        let misplaced = json!({"hooks":{"PreToolUse":[{
            "matcher":"Write",
            "hooks":[{
                "type":"command",
                "command":"\"/old/innerwarden\" hook --block-review"
            }]
        }]}});
        assert!(has_iwguard_wiring(&misplaced));
        assert!(!has_iwguard_hook(&misplaced));
        assert_eq!(effective_iwguard_hook_mode(&misplaced), None);
        assert!(needs_iwguard_hook_reconciliation(
            &misplaced,
            Path::new("/current/innerwarden"),
            false,
            true,
        ));

        let canonical = json!({"hooks":{"PreToolUse":[{
            "matcher":"Bash",
            "hooks":[{
                "type":"command",
                "command":"\"/current/innerwarden\" hook --monitor"
            }]
        }, {
            "matcher": crate::file_tools::FILE_TOOLS_MATCHER,
            "hooks":[{
                "type":"command",
                "command":"\"/current/innerwarden\" hook --monitor"
            }]
        }, {
            "matcher": crate::file_tools::READ_TOOLS_MATCHER,
            "hooks":[{
                "type":"command",
                "command":"\"/current/innerwarden\" hook --monitor"
            }]
        }]}});
        assert!(has_iwguard_wiring(&canonical));
        assert!(has_iwguard_hook(&canonical));
        assert_eq!(
            effective_iwguard_hook_mode(&canonical),
            Some(EffectiveHookMode::Monitor)
        );
        assert!(!needs_iwguard_hook_reconciliation(
            &canonical,
            Path::new("/current/innerwarden"),
            false,
            true,
        ));
    }

    #[test]
    fn automatic_install_repairs_duplicates_without_downgrading_mode_before_skipping() {
        let home = tempfile::TempDir::new().unwrap();
        let settings_path = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
        let settings = json!({
            "model": "sonnet",
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [
                        {"type": "command", "command": "/operator/before"},
                        {"type": "command", "command": "\"/old/target/debug/iw\" hook --block-review", "timeout": 21, "operator_note": "keep"}
                    ]},
                    {"matcher": "Bash", "hooks": [
                        {"type": "command", "command": "\"/old/target/release/innerwarden\" hook --monitor"},
                        {"type": "command", "command": "/operator/after"}
                    ]},
                    {"matcher": "Write", "hooks": [
                        {"type": "command", "command": "innerwarden hook"},
                        {"type": "command", "command": "/operator/write"}
                    ]}
                ],
                "PostToolUse": [{"matcher": "Bash", "hooks": []}]
            }
        });
        std::fs::write(
            &settings_path,
            serde_json::to_string_pretty(&settings).unwrap(),
        )
        .unwrap();

        let first = install_hook_no_symlinks(
            home.path(),
            "claude-code",
            None,
            Path::new("/current/target/release/innerwarden"),
            false,
            true,
        )
        .unwrap();
        assert!(matches!(first, AutomaticHookInstall::Installed(_)));

        let repaired: Value =
            serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
        let entries = repaired["hooks"]["PreToolUse"].as_array().unwrap();
        // One Bash hook, plus the file-tools and read-tools halves beside it.
        assert_eq!(
            entries
                .iter()
                .filter(|entry| is_iwguard_hook_entry(entry)
                    && !is_file_tools_entry(entry)
                    && !is_read_tools_entry(entry))
                .count(),
            1
        );
        assert!(iwguard_judges_file_tools(&repaired));
        let installed = entries
            .iter()
            .flat_map(|entry| entry["hooks"].as_array().unwrap())
            .find(|hook| is_iwguard_hook(hook))
            .unwrap();
        assert_eq!(
            installed["command"],
            format!("\"/current/target/release/innerwarden\" hook --block-review{CLOSED}")
        );
        assert_eq!(installed["timeout"], 21);
        assert_eq!(installed["operator_note"], "keep");
        assert_eq!(repaired["model"], "sonnet");
        assert!(repaired["hooks"]["PostToolUse"].is_array());
        for operator_command in ["/operator/before", "/operator/after", "/operator/write"] {
            assert!(repaired.to_string().contains(operator_command));
        }

        let before_second_run = std::fs::read(&settings_path).unwrap();
        let second = install_hook_no_symlinks(
            home.path(),
            "claude-code",
            None,
            Path::new("/current/target/release/innerwarden"),
            false,
            true,
        )
        .unwrap();
        assert!(matches!(second, AutomaticHookInstall::SkippedExisting));
        assert_eq!(std::fs::read(&settings_path).unwrap(), before_second_run);
    }

    #[test]
    fn automatic_install_repairs_wrong_matcher_only_wiring_in_monitor_mode() {
        let home = tempfile::TempDir::new().unwrap();
        let settings_path = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
        std::fs::write(
            &settings_path,
            serde_json::to_vec_pretty(&json!({
                "hooks": {"PreToolUse": [{
                    "matcher": "Write",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "\"/old/innerwarden\" hook --block-review"
                        },
                        {"type": "command", "command": "/operator/write"}
                    ]
                }]}
            }))
            .unwrap(),
        )
        .unwrap();

        let result = install_hook_no_symlinks(
            home.path(),
            "claude-code",
            None,
            Path::new("/current/innerwarden"),
            false,
            true,
        )
        .unwrap();
        let AutomaticHookInstall::Installed(report) = result else {
            panic!("wrong-matcher wiring must be repaired");
        };
        assert!(report.monitor);
        assert!(!report.block_review);

        let repaired: Value =
            serde_json::from_slice(&std::fs::read(&settings_path).unwrap()).unwrap();
        assert_eq!(
            effective_iwguard_hook_mode(&repaired),
            Some(EffectiveHookMode::Monitor)
        );
        assert!(repaired.to_string().contains("/operator/write"));
        assert!(!repaired.to_string().contains("--block-review"));
    }

    #[test]
    fn remove_strips_only_iwguard_hook_and_is_idempotent() {
        let settings = json!({
            "model": "sonnet",
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Write", "hooks": [ { "type": "command", "command": "/other.sh" } ] },
                    { "matcher": "Bash", "hooks": [ { "type": "command", "command": "\"/usr/local/bin/innerwarden\" hook --block-review" } ] }
                ]
            }
        });
        let (cleaned, removed) = remove_iwguard_pretooluse_hook(settings);
        assert_eq!(removed, 1);
        assert_eq!(cleaned["model"], "sonnet", "unrelated key preserved");
        let pre = cleaned["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0]["matcher"], "Write", "unrelated hook preserved");
        // idempotent: a second removal takes nothing.
        let (again, removed2) = remove_iwguard_pretooluse_hook(cleaned);
        assert_eq!(removed2, 0);
        assert_eq!(again["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn remove_handles_all_aliases_but_preserves_near_matches() {
        let settings = json!({"hooks":{"PreToolUse":[{
            "matcher":"Bash",
            "hooks":[
                {"type":"command","command":"\"/home/dev/.local/bin/iw\" hook"},
                {"type":"command","command":"\"/repo/target/debug/innerwarden\" hook --monitor"},
                {"type":"command","command":"\"/repo/target/release/innerwarden\" hook --block-review"},
                {"type":"command","command":r#""C:\repo\target\debug\iw.exe" hook"#},
                {"type":"command","command":"innerwarden-helper hook"},
                {"type":"command","command":"echo innerwarden hook"},
                {"type":"command","command":"innerwarden hook && /operator/after"}
            ]
        }]}});

        let (out, removed) = remove_iwguard_pretooluse_hook(settings);
        assert_eq!(removed, 4);
        let hooks = out["hooks"]["PreToolUse"][0]["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 3);
        assert_eq!(hooks[0]["command"], "innerwarden-helper hook");
        assert_eq!(hooks[1]["command"], "echo innerwarden hook");
        assert_eq!(hooks[2]["command"], "innerwarden hook && /operator/after");
    }

    #[test]
    fn remove_preserves_unrelated_hooks_sharing_the_same_entry() {
        let settings = json!({"hooks":{"PreToolUse":[{
            "matcher":"Bash",
            "hooks":[
                {"type":"command","command":"/before.sh"},
                {"type":"command","command":"\"/opt/innerwarden\" hook --monitor"},
                {"type":"command","command":"/after.sh"}
            ]
        }]}});
        let (out, removed) = remove_iwguard_pretooluse_hook(settings);
        assert_eq!(removed, 1);
        let hooks = out["hooks"]["PreToolUse"][0]["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[0]["command"], "/before.sh");
        assert_eq!(hooks[1]["command"], "/after.sh");
    }

    #[test]
    fn remove_on_settings_without_hooks_is_a_noop() {
        let (out, removed) = remove_iwguard_pretooluse_hook(json!({"model": "x"}));
        assert_eq!(removed, 0);
        assert_eq!(out["model"], "x");
    }

    #[test]
    fn install_then_uninstall_round_trips() {
        let home = tempfile::TempDir::new().unwrap();
        let iw = Path::new("/opt/innerwarden");
        install_hook(home.path(), "claude-code", None, iw, false, false).unwrap();
        let settings = home.path().join(".claude/settings.json");
        assert!(std::fs::read_to_string(&settings)
            .unwrap()
            .contains("innerwarden"));

        let (path, removed) = uninstall_hook(home.path(), "claude-code", None).unwrap();
        assert_eq!(path, settings);
        assert_eq!(
            removed, 4,
            "the Bash hook, the file-tools hook, the read-tools hook and the PostToolUse hook"
        );
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["hooks"]["PreToolUse"].as_array().unwrap().len(), 0);
        assert_eq!(v["hooks"]["PostToolUse"].as_array().unwrap().len(), 0);

        // running uninstall again removes nothing and does not error.
        let (_, removed2) = uninstall_hook(home.path(), "claude-code", None).unwrap();
        assert_eq!(removed2, 0);
    }

    #[test]
    fn hook_installed_as_innerwarden_is_detected_and_removed() {
        // The rename ships/installs the binary as `innerwarden`. A hook wired by
        // that binary must be recognised for idempotent reinstall and clean
        // uninstall (else every reinstall stacks a duplicate hook).
        let home = tempfile::TempDir::new().unwrap();
        let bin = Path::new("/home/dev/.local/bin/innerwarden");
        install_hook(home.path(), "claude-code", None, bin, false, false).unwrap();
        let settings = home.path().join(".claude/settings.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert!(
            has_iwguard_hook(&v),
            "an innerwarden-installed hook must be detected"
        );
        // reinstall is idempotent (no duplicate entry).
        install_hook(home.path(), "claude-code", None, bin, false, false).unwrap();
        let v2: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(
            v2["hooks"]["PreToolUse"].as_array().unwrap().len(),
            3,
            "reinstall must not stack a second hook (Bash, file-tools and read-tools entries)"
        );
        // uninstall finds and removes all four: Bash, file tools, read tools,
        // PostToolUse.
        let (_, removed) = uninstall_hook(home.path(), "claude-code", None).unwrap();
        assert_eq!(removed, 4);
    }

    /// Uninstall takes out the PostToolUse hook it installed and nothing else
    /// under that event: the person's own hook there stays as it was.
    #[test]
    fn uninstall_removes_its_posttooluse_hook_and_keeps_the_persons() {
        let home = tempfile::TempDir::new().unwrap();
        let settings = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        let theirs = json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "/opt/audit/log-result"}]
        });
        std::fs::write(
            &settings,
            serde_json::to_string(&json!({"hooks": {"PostToolUse": [theirs.clone()]}})).unwrap(),
        )
        .unwrap();
        install_hook(
            home.path(),
            "claude-code",
            None,
            Path::new("/opt/innerwarden"),
            false,
            false,
        )
        .unwrap();

        let (_, removed) = uninstall_hook(home.path(), "claude-code", None).unwrap();
        assert_eq!(removed, 4);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["hooks"]["PostToolUse"], json!([theirs]));
        assert_eq!(v["hooks"]["PreToolUse"], json!([]));
    }

    #[test]
    fn a_hook_line_is_read_apart_and_a_foreign_one_is_not_ours() {
        let line = |command: &str| read_hook_line(&json!({"type": "command", "command": command}));
        assert_eq!(
            line("\"/opt/iw/innerwarden\" hook --monitor --agent codex"),
            Some(HookLine {
                program: "/opt/iw/innerwarden".to_string(),
                monitor: true,
                block_review: false,
                agent: Some("codex".to_string()),
                fail_closed: false,
                fail_open: false,
            })
        );
        assert_eq!(
            line("innerwarden hook --block-review"),
            Some(HookLine {
                program: "innerwarden".to_string(),
                monitor: false,
                block_review: true,
                agent: None,
                fail_closed: false,
                fail_open: false,
            })
        );
        assert_eq!(line("/opt/audit/innerwarden-helper hook"), None);
        assert_eq!(line("innerwarden hook; rm -rf x"), None);
    }

    const GUARD: &str = "/opt/iw/innerwarden";

    /// An enforcing line is the fail-closed script, and it reads back as the
    /// same program, mode and agent: uninstall, repair and `status` find it as
    /// they find the plain one. A monitor line stays plain whatever is asked.
    ///
    /// FAILS ON REVERT: make `hook_command_shaped` ignore `fail_closed` and
    /// the enforcing lines are plain, so they start with the quoted program.
    #[test]
    fn an_enforcing_line_is_the_fail_closed_script_and_reads_back_as_ours() {
        for (block_review, agent) in [
            (false, Some("codex")),
            (true, Some("gemini")),
            (false, None),
        ] {
            let command = hook_command_shaped(Path::new(GUARD), block_review, false, agent, true);
            assert!(command.starts_with("/bin/sh -c '\"$0\" hook"), "{command}");
            assert!(
                command.ends_with("exit 2' \"/opt/iw/innerwarden\""),
                "{command}"
            );
            assert_eq!(
                read_hook_line(&json!({"type": "command", "command": command})),
                Some(HookLine {
                    program: GUARD.to_string(),
                    monitor: false,
                    block_review,
                    agent: agent.map(str::to_string),
                    fail_closed: true,
                    fail_open: false,
                }),
                "{command}"
            );
        }
        let monitor = hook_command_shaped(Path::new(GUARD), false, true, Some("codex"), true);
        assert_eq!(
            monitor,
            "\"/opt/iw/innerwarden\" hook --monitor --agent codex"
        );
        let plain = hook_command_shaped(Path::new(GUARD), false, false, Some("codex"), false);
        assert_eq!(plain, "\"/opt/iw/innerwarden\" hook --agent codex");
        assert_eq!(
            hook_command_for(Path::new(GUARD), false, false, Some("codex")),
            hook_command_shaped(Path::new(GUARD), false, false, Some("codex"), cfg!(unix))
        );
    }

    /// Gemini's monitor line is the fail-open script, and it reads back as
    /// ours, in monitor mode, neither fail-closed nor plain. Every other
    /// monitor line stays plain. A script whose tail does not belong to its
    /// mode is not ours.
    ///
    /// FAILS ON REVERT of the `FAIL_OPEN_AGENT` arm in `hook_command_shaped`
    /// (Gemini's monitor line is plain), or of the `FAIL_OPEN_TAIL` arm in
    /// `guard_words` (the line is not read back as ours).
    #[test]
    fn geminis_monitor_line_is_the_fail_open_script_and_reads_back_as_ours() {
        let command = hook_command_shaped(Path::new(GUARD), false, true, Some("gemini"), true);
        assert!(
            command.starts_with("/bin/sh -c '\"$0\" hook --monitor --agent gemini"),
            "{command}"
        );
        assert!(
            command.ends_with("exit 1' \"/opt/iw/innerwarden\""),
            "{command}"
        );
        assert_eq!(
            read_hook_line(&json!({"type": "command", "command": command})),
            Some(HookLine {
                program: GUARD.to_string(),
                monitor: true,
                block_review: false,
                agent: Some("gemini".to_string()),
                fail_closed: false,
                fail_open: true,
            })
        );
        for agent in [Some("codex"), Some("claude-code"), None] {
            let plain = hook_command_shaped(Path::new(GUARD), false, true, agent, true);
            assert!(
                plain.starts_with("\"/opt/iw/innerwarden\" hook --monitor"),
                "{plain}"
            );
        }
        let plain = hook_command_shaped(Path::new(GUARD), false, true, Some("gemini"), false);
        assert_eq!(
            plain,
            "\"/opt/iw/innerwarden\" hook --monitor --agent gemini"
        );
        // A tail that is not its mode's: an enforcing line that lets the call
        // run, a monitor line that refuses.
        let enforce = hook_command_shaped(Path::new(GUARD), false, false, Some("gemini"), true);
        let line = |command: &str| read_hook_line(&json!({"type": "command", "command": command}));
        assert!(line(&enforce).is_some());
        assert_eq!(
            line(&enforce.replacen(FAIL_CLOSED_TAIL, FAIL_OPEN_TAIL, 1)),
            None
        );
        assert_eq!(
            line(&command.replacen(FAIL_OPEN_TAIL, FAIL_CLOSED_TAIL, 1)),
            None
        );
    }

    /// Run the way Gemini runs it, the fail-open monitor line ends with 1
    /// and a note on stderr when the guard is missing, cannot start or is
    /// killed (Gemini 0.30.0 and later refuse on any exit but 0 and 1), and
    /// passes the guard's own 0 through.
    ///
    /// FAILS ON REVERT of `FAIL_OPEN_TAIL` in `hook_command_shaped`: the
    /// missing guard's 127 comes back, which Gemini reads as a refusal.
    #[cfg(unix)]
    #[test]
    fn geminis_monitor_line_lets_the_call_run_when_the_guard_does_not_answer() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let monitor = |guard: &Path| hook_command_shaped(guard, false, true, Some("gemini"), true);
        let runs = |(code, stderr): (Option<i32>, String)| {
            assert_eq!(code, Some(1), "{stderr}");
            assert!(stderr.contains("NOT screened"), "{stderr}");
        };
        runs(run_line(
            &monitor(&dir.path().join("gone/innerwarden")),
            "{}",
        ));
        let guard = stand_in(dir.path(), "exit 0");
        std::fs::set_permissions(&guard, std::fs::Permissions::from_mode(0o644)).unwrap();
        runs(run_line(&monitor(&guard), "{}"));
        let killed = stand_in(dir.path(), "kill -9 $$");
        runs(run_line(&monitor(&killed), "{}"));
        let answers = stand_in(dir.path(), "cat >/dev/null; exit 0");
        let (code, stderr) = run_line(&monitor(&answers), "{}");
        assert_eq!(code, Some(0), "{stderr}");
        assert!(stderr.is_empty(), "{stderr}");
    }

    /// Whether Claude Code's settings still run this binary, read apart:
    /// a hook of ours naming this program, another program, no file, a file
    /// that is no settings with or without a hook line in it, and a path
    /// that cannot be read. And the words uninstall says when it stops.
    ///
    /// FAILS ON REVERT of any test in `claude_code_hook_still_runs`, or of
    /// the lines in `claude_code_left_behind_lines`.
    #[test]
    fn a_claude_code_hook_that_runs_this_binary_is_found() {
        let home = tempfile::TempDir::new().unwrap();
        let gone = Path::new("/opt/iw-not-here/innerwarden");
        assert_eq!(claude_code_hook_still_runs(home.path(), gone), None);
        let settings = home.path().join(".claude/settings.json");
        fs::create_dir_all(settings.parent().unwrap()).unwrap();
        let wired = json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": hook_command_for(gone, false, false, Some("claude-code"))}
        ]}]}});
        fs::write(&settings, wired.to_string()).unwrap();
        assert_eq!(claude_code_hook_still_runs(home.path(), gone), Some(true));
        assert_eq!(
            claude_code_hook_still_runs(home.path(), Path::new("/usr/bin/innerwarden")),
            None
        );
        fs::write(
            &settings,
            "{\"hooks\": {\"PreToolUse\": [\"innerwarden\" hook",
        )
        .unwrap();
        assert_eq!(claude_code_hook_still_runs(home.path(), gone), Some(false));
        fs::write(&settings, "not json").unwrap();
        assert_eq!(claude_code_hook_still_runs(home.path(), gone), None);
        fs::write(&settings, "{\"note\": \"innerwarden\"").unwrap();
        assert_eq!(claude_code_hook_still_runs(home.path(), gone), None);
        // A link to the binary runs it.
        let real = home.path().join("bin/innerwarden");
        fs::create_dir_all(real.parent().unwrap()).unwrap();
        fs::write(&real, "#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            let link = home.path().join("link/innerwarden");
            fs::create_dir_all(link.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(&real, &link).unwrap();
            let linked = json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "command", "command": hook_command_for(&link, false, false, Some("claude-code"))}
            ]}]}});
            fs::write(&settings, linked.to_string()).unwrap();
            assert_eq!(claude_code_hook_still_runs(home.path(), &real), Some(true));
        }
        fs::remove_file(&settings).unwrap();
        fs::create_dir_all(&settings).unwrap();
        assert_eq!(claude_code_hook_still_runs(home.path(), gone), Some(false));
        assert_eq!(
            claude_code_left_behind_lines(true)[0],
            "~/.claude/settings.json still holds a PreToolUse hook that runs this binary."
        );
        assert_eq!(
            claude_code_left_behind_lines(false)[0],
            "~/.claude/settings.json could not be read, and a PreToolUse hook in it may still \
             run this binary."
        );
        assert_eq!(claude_code_left_behind_lines(true).len(), 3);
        assert!(claude_code_left_behind_lines(true)[1].contains("refuses every call"));
        assert!(claude_code_left_behind_lines(true)[2].contains("innerwarden uninstall"));
    }

    /// The Read|Grep|Glob entry is written with the same line as the shell
    /// entry: in enforce, the fail-closed script, so a guard that is gone
    /// refuses a read of a secret rather than letting it run; in monitor,
    /// plain. An install from before reads were judged is brought up to it.
    ///
    /// FAILS ON REVERT of the read merge in `install_hook_with_link_policy`
    /// or in `needs_iwguard_hook_reconciliation` (no read entry), or with the
    /// read entry written with the plain line.
    #[cfg(unix)]
    #[test]
    fn the_read_entry_is_fail_closed_in_enforce() {
        let home = tempfile::TempDir::new().unwrap();
        let bin = Path::new("/opt/iw/innerwarden");
        install_hook(home.path(), "claude-code", None, bin, false, false).unwrap();
        let settings = home.path().join(".claude/settings.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        let read_entry = |v: &Value| {
            v["hooks"]["PreToolUse"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["matcher"] == crate::file_tools::READ_TOOLS_MATCHER)
                .map(|entry| entry["hooks"][0]["command"].as_str().unwrap().to_string())
        };
        let enforcing = read_entry(&v).expect("a read entry");
        assert_eq!(
            enforcing,
            hook_command_for(bin, false, false, Some("claude-code"))
        );
        assert!(
            enforcing.starts_with("/bin/sh -c '\"$0\" hook"),
            "{enforcing}"
        );
        // An install from before the read entry is brought up to it, fail-closed.
        let old = json!({"hooks": {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command",
                "command": hook_command_for(bin, false, false, Some("claude-code"))}]},
            {"matcher": crate::file_tools::FILE_TOOLS_MATCHER, "hooks": [{"type": "command",
                "command": hook_command_for(bin, false, false, Some("claude-code"))}]}
        ]}});
        assert!(needs_iwguard_hook_reconciliation(&old, bin, false, false));
        std::fs::write(&settings, serde_json::to_string_pretty(&old).unwrap()).unwrap();
        install_hook(home.path(), "claude-code", None, bin, false, false).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(read_entry(&v), Some(enforcing));
        // Monitor never refuses: the read entry is plain there.
        let home = tempfile::TempDir::new().unwrap();
        install_hook(home.path(), "claude-code", None, bin, false, true).unwrap();
        let v: Value = serde_json::from_str(
            &std::fs::read_to_string(home.path().join(".claude/settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read_entry(&v).as_deref(),
            Some("\"/opt/iw/innerwarden\" hook --monitor --agent claude-code")
        );
    }

    /// A script is ours only to the letter: another shell, another tail,
    /// another first word, a program that is not the guard, or one word more
    /// is the person's own command, and uninstall leaves it alone.
    ///
    /// FAILS ON REVERT: read the script by `contains("hook")` instead of its
    /// exact prefix and tail and the altered scripts are claimed.
    #[test]
    fn a_script_that_is_not_ours_to_the_letter_is_left_alone() {
        let ours = hook_command_shaped(Path::new(GUARD), false, false, Some("codex"), true);
        let line = |command: &str| read_hook_line(&json!({"type": "command", "command": command}));
        assert!(line(&ours).is_some());
        let altered = [
            ours.replacen("/bin/sh", "/usr/bin/sh", 1),
            ours.replacen("/bin/sh", "bash", 1),
            ours.replacen(" -c ", " -ec ", 1),
            ours.replacen("exit 2'", "exit 1'", 1),
            ours.replacen("0|2)", "0|1|2)", 1),
            ours.replacen("'\"$0\" hook", "'$0 hook", 1),
            ours.replacen("'\"$0\" hook", "'\"$0\" hook; rm -rf ~;", 1),
            ours.replacen("\"/opt/iw/innerwarden\"", "\"/opt/audit/check\"", 1),
            format!("{ours} extra"),
            ours.replacen("--agent codex", "--agent codex --monitor", 1),
        ];
        for command in &altered {
            assert_eq!(line(command), None, "{command}");
        }
    }

    /// Run `line` the way an agent runs a hook, `sh -c <line>`, with
    /// `payload` on stdin: the exit code and stderr.
    #[cfg(unix)]
    fn run_line(line: &str, payload: &str) -> (Option<i32>, String) {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg(line)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start the agent's shell");
        // A shell that cannot find the guard ends before it reads, and the
        // pipe is closed first; the agent reads the answer all the same.
        match child
            .stdin
            .take()
            .expect("stdin")
            .write_all(payload.as_bytes())
        {
            Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => {
                panic!("write the payload: {error}")
            }
            _ => {}
        }
        let out = child.wait_with_output().expect("wait for the hook");
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// A stand-in guard at `dir/innerwarden` that runs `body` as a script.
    #[cfg(unix)]
    fn stand_in(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("innerwarden");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// The row's proof: run the way an agent runs it, the fail-closed line
    /// refuses with a reason on stderr when the guard is missing, cannot be
    /// started, dies on a signal (`SIGKILL` included) or ends any way but its
    /// own answer, and passes the guard's own 0 and 2 through untouched, with
    /// the payload on its stdin. The plain line, and the monitor line, let
    /// the missing guard's 127 through, which Claude Code and Codex read as
    /// "run the tool".
    ///
    /// FAILS ON REVERT: make `hook_command_shaped` ignore `fail_closed` and
    /// every refusal below is 127, 126, 137, 139 or 1.
    #[cfg(unix)]
    #[test]
    fn the_fail_closed_line_refuses_whenever_the_guard_does_not_answer() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let enforce = |guard: &Path| hook_command_shaped(guard, false, false, Some("codex"), true);
        let refused = |(code, stderr): (Option<i32>, String)| {
            assert_eq!(code, Some(2), "{stderr}");
            assert!(
                stderr
                    .contains("InnerWarden hook: the innerwarden program ended without an answer"),
                "a refusal must say why: {stderr}"
            );
            // The agent cannot mend the hook (each call it makes is refused),
            // so the refusal names the way out for the person.
            assert!(
                stderr.contains(
                    "To stop this, put the innerwarden program back, or remove the innerwarden \
                     hook from the agent settings by hand (~/.claude/settings.json, \
                     ~/.codex/hooks.json or ~/.gemini/settings.json)."
                ),
                "a refusal must name the way out: {stderr}"
            );
        };

        let missing = dir.path().join("gone/innerwarden");
        refused(run_line(&enforce(&missing), "{}"));
        let (code, _) = run_line(
            &hook_command_shaped(&missing, false, false, Some("codex"), false),
            "{}",
        );
        assert_eq!(
            code,
            Some(127),
            "the plain line lets a missing guard through"
        );
        let (code, _) = run_line(
            &hook_command_shaped(&missing, false, true, Some("codex"), true),
            "{}",
        );
        assert_eq!(code, Some(127), "monitor never acts, so it is not wrapped");

        let guard = stand_in(dir.path(), "exit 0");
        std::fs::set_permissions(&guard, std::fs::Permissions::from_mode(0o644)).unwrap();
        refused(run_line(&enforce(&guard), "{}"));

        let killed = stand_in(dir.path(), "kill -9 $$");
        refused(run_line(&enforce(&killed), "{}"));
        let crashed = stand_in(dir.path(), "kill -SEGV $$");
        refused(run_line(&enforce(&crashed), "{}"));
        let failed = stand_in(dir.path(), "exit 1");
        refused(run_line(&enforce(&failed), "{}"));

        let seen = dir.path().join("seen");
        let allows = stand_in(dir.path(), &format!("cat > '{}'; exit 0", seen.display()));
        assert_eq!(
            run_line(&enforce(&allows), "{\"tool_name\":\"Bash\"}"),
            (Some(0), String::new())
        );
        assert_eq!(
            std::fs::read_to_string(&seen).unwrap(),
            "{\"tool_name\":\"Bash\"}",
            "the guard reads the agent's payload through the script"
        );
        let denies = stand_in(
            dir.path(),
            "echo 'InnerWarden blocked this command' >&2; exit 2",
        );
        assert_eq!(
            run_line(&enforce(&denies), "{}"),
            (Some(2), "InnerWarden blocked this command\n".to_string()),
            "the guard's own refusal and reason pass through as they are"
        );
    }

    /// A Claude Code hook written before the fail-closed line is repaired to
    /// it: the plain enforcing line lets every call through when its program
    /// goes, so it is drift, as a moved program is. Its PostToolUse half stays
    /// plain (the tool has run; there is nothing to refuse), and a monitor
    /// hook is left as it is.
    ///
    /// FAILS ON REVERT: write the plain line in `hook_command_for` and the old
    /// hook reads as no drift.
    #[cfg(unix)]
    #[test]
    fn a_plain_enforcing_claude_hook_is_drift_and_is_repaired_to_the_fail_closed_line() {
        let home = tempfile::tempdir().unwrap();
        let bin = Path::new(GUARD);
        let plain = hook_command_shaped(bin, false, false, Some("claude-code"), false);
        let old = merge_posttooluse_hook(
            merge_pretooluse_file_hook(merge_pretooluse_bash_hook(json!({}), &plain), &plain),
            &plain,
        );
        assert!(needs_iwguard_hook_reconciliation(&old, bin, false, false));
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        let settings = home.path().join(".claude/settings.json");
        std::fs::write(&settings, serde_json::to_string(&old).unwrap()).unwrap();
        install_hook(home.path(), "claude-code", None, bin, false, false).unwrap();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        let wrapped = hook_command_for(bin, false, false, Some("claude-code"));
        for entry in v["hooks"]["PreToolUse"].as_array().unwrap() {
            assert_eq!(entry["hooks"][0]["command"], json!(wrapped));
        }
        assert_eq!(
            v["hooks"]["PostToolUse"][0]["hooks"][0]["command"],
            json!(plain)
        );
        assert!(!needs_iwguard_hook_reconciliation(&v, bin, false, false));
        assert_eq!(effective_iwguard_hook_programs(&v), vec![GUARD.to_string()]);
        let (_, removed) = uninstall_hook(home.path(), "claude-code", None).unwrap();
        assert_eq!(removed, 4, "uninstall finds the fail-closed lines");

        let monitor = hook_command_for(bin, false, true, Some("claude-code"));
        let watched = merge_pretooluse_read_hook(
            merge_pretooluse_file_hook(merge_pretooluse_bash_hook(json!({}), &monitor), &monitor),
            &monitor,
        );
        assert!(!needs_iwguard_hook_reconciliation(
            &watched, bin, false, true
        ));
    }

    #[test]
    fn removal_by_event_touches_that_event_only() {
        let ours = json!({"type": "command", "command": "innerwarden hook --agent gemini"});
        let theirs = json!({"type": "command", "command": "/opt/audit/before"});
        let settings = json!({
            "hooks": {
                "BeforeTool": [{"hooks": [theirs.clone(), ours.clone()]}, {"hooks": [ours.clone()]}],
                "AfterTool": [{"hooks": [ours.clone()]}]
            }
        });
        let (out, removed) = remove_iwguard_hooks_for_event(settings, "BeforeTool");
        assert_eq!(removed, 2);
        assert_eq!(
            out,
            json!({
                "hooks": {
                    "BeforeTool": [{"hooks": [theirs]}],
                    "AfterTool": [{"hooks": [ours]}]
                }
            })
        );
    }

    #[test]
    fn uninstall_missing_settings_is_safe() {
        let home = tempfile::TempDir::new().unwrap();
        let (_, removed) = uninstall_hook(home.path(), "claude-code", None).unwrap();
        assert_eq!(
            removed, 0,
            "no settings file -> nothing to remove, no error"
        );
    }

    #[test]
    fn uninstall_rejects_unknown_agent() {
        let home = tempfile::TempDir::new().unwrap();
        let err = uninstall_hook(home.path(), "cursor", None).unwrap_err();
        assert!(err.contains("unsupported agent"));
    }
}

#[cfg(test)]
mod posttooluse_tests {
    use super::*;

    /// The observation half must be written, and written ONCE however many
    /// times the install runs.
    ///
    /// FAILS ON REVERT: drop the `merge_posttooluse_hook` call from
    /// `install_hook_with_link_policy` and no PostToolUse entry exists, so the
    /// two-step defence is present in the binary and never invoked.
    #[test]
    fn the_observation_hook_is_written_once_and_stays_once() {
        let once = merge_posttooluse_hook(json!({}), "\"/p/innerwarden\" hook");
        let entries = once["hooks"]["PostToolUse"].as_array().expect("array");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0]["matcher"], "*",
            "a result can come from any tool"
        );

        let twice = merge_posttooluse_hook(once.clone(), "\"/p/innerwarden\" hook");
        assert_eq!(twice, once, "installing twice must not duplicate the hook");
    }

    /// A reinstall from a NEW path replaces the old entry rather than leaving
    /// two, which would feed the store from a binary the screening half no
    /// longer is.
    #[test]
    fn a_reinstall_from_a_new_path_replaces_rather_than_accumulates() {
        let first = merge_posttooluse_hook(json!({}), "\"/old/innerwarden\" hook");
        let second = merge_posttooluse_hook(first, "\"/new/innerwarden\" hook --block-review");
        let entries = second["hooks"]["PostToolUse"].as_array().expect("array");
        assert_eq!(entries.len(), 1, "exactly one InnerWarden observation hook");
        let cmd = entries[0]["hooks"][0]["command"].as_str().unwrap_or("");
        assert!(cmd.contains("/new/innerwarden"), "{cmd}");
        assert!(!cmd.contains("/old/innerwarden"), "{cmd}");
    }

    /// Operator hooks in the same file are not ours to remove.
    #[test]
    fn an_operators_own_posttooluse_hook_survives() {
        let existing = json!({
            "hooks": {"PostToolUse": [
                {"matcher": "Write", "hooks": [{"type": "command", "command": "/operator/audit"}]}
            ]}
        });
        let merged = merge_posttooluse_hook(existing, "\"/p/innerwarden\" hook");
        let entries = merged["hooks"]["PostToolUse"].as_array().expect("array");
        let commands: Vec<&str> = entries
            .iter()
            .flat_map(|e| e["hooks"].as_array().cloned().unwrap_or_default())
            .filter_map(|h| h["command"].as_str().map(str::to_string))
            .map(|s| Box::leak(s.into_boxed_str()) as &str)
            .collect();
        assert!(
            commands.iter().any(|c| c.contains("/operator/audit")),
            "the operator's hook must survive: {commands:?}"
        );
        assert!(commands.iter().any(|c| c.contains("/p/innerwarden")));
    }
}

/// Whether a hook's program is there to run: the judgement `status`, `agents`
/// and the dashboard share. Every fact is handed in, so nothing here reads the
/// real filesystem or `PATH`.
#[cfg(test)]
mod hook_program_tests {
    use super::*;

    /// The exact settings measured on a real Mac: the hook named a
    /// `target/release` build that `cargo clean` had removed, and `status` said
    /// `[on] Wired into 1: claude-code.` for weeks.
    fn measured(command: &str) -> Value {
        json!({"hooks": {"PreToolUse": [{
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": command}]
        }]}})
    }

    /// An absolute program path on this platform. `/x` is not absolute on
    /// Windows, where this suite also runs.
    fn abs(dir: &str) -> String {
        if cfg!(windows) {
            format!(r"C:\{dir}\innerwarden.exe")
        } else {
            format!("/{dir}/innerwarden")
        }
    }

    fn gone() -> String {
        format!(
            "\"{}\" hook --monitor --agent claude-code",
            abs("nonexistent/target/release")
        )
    }

    #[test]
    fn a_hook_whose_program_is_gone_does_not_run_and_says_which_path() {
        let verdict = judge_iwguard_hooks(&measured(&gone()), |_| ProgramFact::Missing);
        let expected = abs("nonexistent/target/release");
        match verdict {
            Some(HookProgram::Broken { program, problem }) => {
                assert_eq!(program, expected);
                assert_eq!(
                    problem,
                    format!("its hook runs {expected}, which does not exist")
                );
            }
            other => panic!("a hook that cannot start screens nothing: {other:?}"),
        }
    }

    #[test]
    fn a_hook_whose_program_is_there_and_executable_runs() {
        let asked = std::cell::RefCell::new(Vec::new());
        let verdict = judge_iwguard_hooks(&measured(&gone()), |program| {
            asked.borrow_mut().push(program.to_string());
            ProgramFact::Executable
        });
        assert_eq!(verdict, Some(HookProgram::Runs));
        // The fact asked for is the program with its quotes removed, not the
        // whole command line and not the quoted word.
        assert_eq!(asked.into_inner(), vec![abs("nonexistent/target/release")]);
    }

    #[test]
    fn a_hook_whose_program_is_not_executable_does_not_run() {
        let program = abs("opt/iw");
        match judge_hook_program(&program, ProgramFact::NotExecutable) {
            HookProgram::Broken { problem, .. } => assert_eq!(
                problem,
                format!("its hook runs {program}, which is not an executable file")
            ),
            other => panic!("a file nobody can execute screens nothing: {other:?}"),
        }
    }

    /// A bare name is found on the agent's own PATH, which this process cannot
    /// see. Found here, the answer is "could not tell", never an OK that could
    /// be false. Found nowhere here (this PATH and the usual places), it is
    /// off. An unquoted command is read by the same grammar as a quoted one.
    ///
    /// FAILS ON REVERT: let a bare name take the lookup's answer again and
    /// `Executable` reads `Runs`.
    #[test]
    fn a_bare_program_found_here_could_not_be_told_and_one_found_nowhere_is_off() {
        let settings = measured("innerwarden hook --agent claude-code");
        assert_eq!(
            effective_iwguard_hook_programs(&settings),
            vec!["innerwarden".to_string()]
        );
        for fact in [ProgramFact::Executable, ProgramFact::Unreadable] {
            match judge_iwguard_hooks(&settings, |_| fact) {
                Some(HookProgram::Unknown { program, why }) => {
                    assert_eq!(program, "innerwarden");
                    assert!(why.starts_with(BARE_NAME), "{fact:?}: {why}");
                }
                other => panic!("{fact:?}: found here is not the agent's answer: {other:?}"),
            }
        }
        // Found nowhere here (PATH and the usual places): off, as before.
        for fact in [ProgramFact::Missing, ProgramFact::NotExecutable] {
            match judge_iwguard_hooks(&settings, |_| fact) {
                Some(HookProgram::Broken { program, problem }) => {
                    assert_eq!(program, "innerwarden");
                    assert!(
                        problem.starts_with("its hook runs `innerwarden`, which is not on PATH"),
                        "{problem}"
                    );
                    assert!(problem.ends_with(BARE_NOT_FOUND), "{problem}");
                }
                other => panic!("{fact:?}: a name found nowhere cannot start: {other:?}"),
            }
        }
    }

    /// The installer's line (an absolute path in quotes) keeps its verdicts:
    /// the bare-name rule and the hand-written lines change nothing for it.
    #[test]
    fn the_installers_quoted_absolute_line_keeps_its_verdicts() {
        let program = abs("opt/iw bin");
        let settings = measured(&format!("\"{program}\" hook --agent claude-code"));
        assert_eq!(
            judge_iwguard_hooks(&settings, |_| ProgramFact::Executable),
            Some(HookProgram::Runs)
        );
        assert!(matches!(
            judge_iwguard_hooks(&settings, |_| ProgramFact::Missing),
            Some(HookProgram::Broken { .. })
        ));
        assert!(wrapped_iwguard_hooks(&settings).is_empty());
        // The line the installer writes, fail-closed tail included.
        let written = hook_command_for(Path::new(&program), false, false, Some("claude-code"));
        assert!(wrapped_iwguard_hooks(&measured(&written)).is_empty());
    }

    fn one_wrapped(command: &str) -> WrappedHook {
        let found = wrapped_iwguard_hooks(&measured(command));
        assert_eq!(found.len(), 1, "{command}: {found:?}");
        assert!(found[0].screens_bash);
        assert_eq!(found[0].command, command);
        found[0].clone()
    }

    fn unknown_naming_the_line(verdict: HookProgram, command: &str) {
        match verdict {
            HookProgram::Unknown { why, .. } => {
                assert!(why.starts_with("could not tell"), "{why}");
                assert!(why.contains(command), "the line itself is named: {why}");
            }
            other => panic!("{command}: a hand-written line is could not tell: {other:?}"),
        }
    }

    /// `env X=1 /p/innerwarden hook`: not the guard's line, so it used to be
    /// skipped in silence. Now it is found, with the binary it names.
    ///
    /// FAILS ON REVERT: drop `wrapped_iwguard_hooks` (or let it skip a line
    /// whose first word is not the guard) and nothing is found.
    #[test]
    fn a_line_with_env_in_front_is_could_not_tell_with_the_line() {
        let program = abs("opt/iw");
        let command = format!("env IW_X=1 {program} hook --agent claude-code");
        assert!(!is_iwguard_hook(&json!({"command": command})));
        let wrapped = one_wrapped(&command);
        assert_eq!(wrapped.program, program);
        unknown_naming_the_line(
            judge_wrapped_hook(&wrapped, ProgramFact::Executable),
            &command,
        );
    }

    /// A path with a space and no quotes: the shell splits it, so what starts
    /// is not knowable from the text.
    #[test]
    fn a_path_with_a_space_and_no_quotes_is_could_not_tell_with_the_line() {
        let command = if cfg!(windows) {
            r"C:\my tools\innerwarden.exe hook".to_string()
        } else {
            "/home/my user/bin/innerwarden hook".to_string()
        };
        let wrapped = one_wrapped(&command);
        for fact in [ProgramFact::Missing, ProgramFact::Executable] {
            unknown_naming_the_line(judge_wrapped_hook(&wrapped, fact), &command);
        }
    }

    /// `sh -c '/p/innerwarden hook'`: the binary is inside the quoted script.
    #[test]
    fn a_line_through_sh_c_is_could_not_tell_with_the_line() {
        let program = abs("opt/iw");
        let command = format!("sh -c '{program} hook --monitor'");
        let wrapped = one_wrapped(&command);
        assert_eq!(wrapped.program, program);
        unknown_naming_the_line(
            judge_wrapped_hook(&wrapped, ProgramFact::Executable),
            &command,
        );
    }

    /// A hand-written line whose binary is gone is the same alarm as the
    /// guard's own line: nothing it names can start.
    ///
    /// FAILS ON REVERT: make `judge_wrapped_hook` always "could not tell"
    /// and the gone binary reads unknown.
    #[test]
    fn a_hand_written_line_whose_binary_is_gone_is_broken() {
        let program = abs("gone/target/release");
        let command = format!("env IW_X=1 {program} hook");
        let wrapped = one_wrapped(&command);
        match judge_wrapped_hook(&wrapped, ProgramFact::Missing) {
            HookProgram::Broken {
                program: named,
                problem,
            } => {
                assert_eq!(named, program);
                assert!(problem.contains(&command), "{problem}");
                assert!(problem.ends_with("which does not exist"), "{problem}");
            }
            other => panic!("a gone binary is the same alarm: {other:?}"),
        }
    }

    /// Lines that do not name the guard's binary with `hook` stay the
    /// operator's: nothing is reported for them.
    #[test]
    fn a_line_that_only_mentions_the_guard_is_not_named() {
        for command in [
            "/operator/check.sh",
            "/usr/sbin/iw dev wlan0 hook",
            "innerwarden-helper hook",
        ] {
            assert!(
                wrapped_iwguard_hooks(&measured(command)).is_empty(),
                "{command}"
            );
        }
    }

    #[test]
    fn an_unquoted_absolute_program_is_read_the_same_way() {
        let settings = measured("/usr/local/bin/innerwarden hook --monitor");
        assert_eq!(
            effective_iwguard_hook_programs(&settings),
            vec!["/usr/local/bin/innerwarden".to_string()]
        );
    }

    /// "Could not tell" is never "off": neither a failed look nor a path
    /// relative to wherever the agent starts may be reported as broken.
    #[test]
    fn a_program_that_could_not_be_checked_is_unknown_not_broken() {
        assert!(matches!(
            judge_hook_program(&abs("opt/iw"), ProgramFact::Unreadable),
            HookProgram::Unknown { .. }
        ));
        // Relative to the agent's own working directory: unknowable from here,
        // whatever a lookup from this process happened to find.
        for fact in [ProgramFact::Missing, ProgramFact::Executable] {
            match judge_hook_program("target/release/innerwarden", fact) {
                HookProgram::Unknown { why, .. } => {
                    assert!(
                        why.contains("relative to wherever the agent starts"),
                        "{why}"
                    )
                }
                other => panic!("a relative path cannot be judged from here: {other:?}"),
            }
        }
    }

    /// Only hooks that screen Bash are judged, and only commands this module
    /// already calls its own: an operator's script or a hook under another
    /// matcher is never mistaken for the guard.
    #[test]
    fn only_the_guards_own_bash_hooks_are_judged() {
        let settings = json!({"hooks": {"PreToolUse": [
            {"matcher": "Write", "hooks": [{"type": "command", "command": "\"/gone/innerwarden\" hook"}]},
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "/operator/check.sh"}]}
        ]}});
        assert!(effective_iwguard_hook_programs(&settings).is_empty());
        assert_eq!(
            judge_iwguard_hooks(&settings, |_| ProgramFact::Missing),
            None
        );
    }

    /// Claude Code runs every matching hook, so one that starts still screens.
    #[test]
    fn one_hook_that_runs_is_enough() {
        let here = abs("here");
        let settings = json!({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": format!("\"{}\" hook", abs("gone"))},
            {"type": "command", "command": format!("\"{here}\" hook")}
        ]}]}});
        let verdict = judge_iwguard_hooks(&settings, |program| {
            if program == here {
                ProgramFact::Executable
            } else {
                ProgramFact::Missing
            }
        });
        assert_eq!(verdict, Some(HookProgram::Runs));
    }

    /// The remedy must not quietly change what the hook does.
    #[test]
    fn the_repair_keeps_the_mode_the_hook_has() {
        assert_eq!(install_mode_flag(&measured(&gone())), " --monitor");
        assert_eq!(
            install_mode_flag(&measured("\"/x/innerwarden\" hook --block-review")),
            " --block-review"
        );
        assert_eq!(install_mode_flag(&measured("\"/x/innerwarden\" hook")), "");
    }
}

/// What background setup may write into Claude Code's settings.
#[cfg(test)]
mod automatic_write_tests {
    use super::*;

    /// A command automatic setup would not recognise as its own is refused,
    /// never appended beside the valid hook. Measured before this: a binary
    /// path reading `innerwarden (deleted)` (Linux, after an in-place upgrade)
    /// left the old hook in place and added a second entry naming a file that
    /// does not exist, in both PreToolUse and PostToolUse.
    ///
    /// FAILS ON REVERT: drop the refusal and the file gains a second
    /// PreToolUse entry.
    #[test]
    fn automatic_setup_never_appends_a_command_it_would_not_recognise() {
        let home = tempfile::TempDir::new().unwrap();
        let settings = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        let valid = merge_pretooluse_bash_hook(
            json!({}),
            "\"/usr/local/bin/innerwarden\" hook --monitor --agent claude-code",
        );
        std::fs::write(&settings, serde_json::to_vec_pretty(&valid).unwrap()).unwrap();
        let before = std::fs::read(&settings).unwrap();

        let refused = install_hook_no_symlinks(
            home.path(),
            "claude-code",
            None,
            Path::new("/usr/local/bin/innerwarden (deleted)"),
            false,
            true,
        );
        match refused {
            Err(error) => assert!(
                error.contains("would not recognise that command as its own"),
                "{error}"
            ),
            Ok(_) => panic!("an unrecognisable command must not be written"),
        }
        assert_eq!(std::fs::read(&settings).unwrap(), before);
    }

    /// Live gate of Active Defence 0.17.4, G2: the flags of the mode the
    /// hooks already have, so a rewrite that asked for none keeps it; `None`
    /// where no hook of ours screens Bash. FAILS ON REVERT of any arm.
    #[test]
    fn the_kept_flags_are_the_mode_the_hook_already_has() {
        let with = |command: &str| {
            json!({ "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [
                { "type": "command", "command": command }
            ] } ] } })
        };
        assert_eq!(
            kept_hook_flags(&with("innerwarden hook --agent claude-code")),
            Some((false, false))
        );
        assert_eq!(
            kept_hook_flags(&with("innerwarden hook --monitor --agent claude-code")),
            Some((false, true))
        );
        assert_eq!(
            kept_hook_flags(&with("innerwarden hook --block-review --agent claude-code")),
            Some((true, false))
        );
        assert_eq!(kept_hook_flags(&json!({})), None);
        assert_eq!(kept_hook_flags(&with("their-own-audit.sh")), None);
    }
}

/// Every InnerWarden hook a wired agent has is judged, not only the one that
/// screens Bash. Measured 2026-11-18 on a lab host: three hooks (Bash, the
/// file tools, `PostToolUse`) pointed at a build directory that was gone, and
/// Claude Code ran each as a non-blocking error. With only the file-tool and
/// result hooks gone, `status` said `[on]`.
#[cfg(test)]
mod unscreened_hook_tests {
    use super::*;

    /// An absolute program path on this platform: `/x` is not absolute on
    /// Windows, where this suite also runs.
    fn abs(dir: &str) -> String {
        if cfg!(windows) {
            format!(r"C:\{dir}\innerwarden.exe")
        } else {
            format!("/{dir}/innerwarden")
        }
    }

    fn cmd(program: &str) -> String {
        format!(
            "{} hook --agent claude-code",
            serde_json::to_string(program).unwrap()
        )
    }

    /// The settings the installer writes, each hook with its own program.
    fn wired(bash: &str, files: &str, reads: &str, post: &str) -> Value {
        json!({"hooks": {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": bash}]},
                {"matcher": "Write|Edit|MultiEdit|NotebookEdit",
                 "hooks": [{"type": "command", "command": files}]},
                {"matcher": "Read|Grep|Glob", "hooks": [{"type": "command", "command": reads}]}
            ],
            "PostToolUse": [
                {"matcher": "*", "hooks": [{"type": "command", "command": post}]}
            ]
        }})
    }

    /// Only the `ok` directory holds a program; everything else is missing.
    fn fact(program: &str) -> ProgramFact {
        if program == abs("ok") {
            ProgramFact::Executable
        } else {
            ProgramFact::Missing
        }
    }

    fn tools(settings: &Value) -> Vec<String> {
        unscreened_iwguard_hooks(settings, fact)
            .into_iter()
            .map(|g| g.tools)
            .collect()
    }

    /// FAILS ON REVERT of #190: every hook gone is the whole agent off.
    #[test]
    fn every_hook_gone_is_off() {
        let dead = cmd(&abs("gone"));
        let settings = wired(&dead, &dead, &dead, &dead);
        assert!(matches!(
            judge_iwguard_hooks(&settings, fact),
            Some(HookProgram::Broken { .. })
        ));
    }

    #[test]
    fn every_hook_that_runs_is_on_with_nothing_unscreened() {
        let ok = cmd(&abs("ok"));
        let settings = wired(&ok, &ok, &ok, &ok);
        assert_eq!(
            judge_iwguard_hooks(&settings, fact),
            Some(HookProgram::Runs)
        );
        assert!(tools(&settings).is_empty());
    }

    /// FAILS ON REVERT: without this judgement Bash alone decided, and the
    /// file tools went unscreened under `[on]`.
    #[test]
    fn bash_runs_but_the_file_tools_hook_is_gone() {
        let (ok, dead) = (cmd(&abs("ok")), cmd(&abs("gone")));
        let settings = wired(&ok, &dead, &ok, &ok);
        assert_eq!(
            judge_iwguard_hooks(&settings, fact),
            Some(HookProgram::Runs)
        );
        let groups = unscreened_iwguard_hooks(&settings, fact);
        assert_eq!(groups.len(), 1, "{groups:?}");
        assert_eq!(groups[0].tools, "Write/Edit/MultiEdit/NotebookEdit");
        assert!(groups[0].problem.contains(&abs("gone")), "{groups:?}");
        assert!(groups[0].problem.contains("does not exist"), "{groups:?}");
    }

    #[test]
    fn only_the_result_hook_is_gone() {
        let (ok, dead) = (cmd(&abs("ok")), cmd(&abs("gone")));
        assert_eq!(
            tools(&wired(&ok, &ok, &ok, &dead)),
            vec!["PostToolUse (every tool)"]
        );
    }

    #[test]
    fn the_read_tools_hook_is_gone() {
        let (ok, dead) = (cmd(&abs("ok")), cmd(&abs("gone")));
        assert_eq!(tools(&wired(&ok, &ok, &dead, &ok)), vec!["Read/Grep/Glob"]);
    }

    /// The order the sentence reads: before-the-call gaps first.
    #[test]
    fn the_file_tools_and_the_result_hook_gone_are_both_named() {
        let (ok, dead) = (cmd(&abs("ok")), cmd(&abs("gone")));
        let groups = unscreened_iwguard_hooks(&wired(&ok, &dead, &ok, &dead), fact);
        let sentence = unscreened_hooks_sentence(&groups).unwrap();
        assert_eq!(
            sentence,
            format!(
                "Write/Edit/MultiEdit/NotebookEdit not screened, PostToolUse (every tool) \
                 not screened: its hook runs {}, which does not exist",
                abs("gone")
            )
        );
        assert_eq!(unscreened_hooks_sentence(&[]), None);
    }

    /// A quoted path, spaces and all, is read whole; so is one without quotes.
    #[test]
    fn a_quoted_path_is_read_whole() {
        let ok = cmd(&abs("ok"));
        let spaced = abs("dir with space");
        let quoted = format!("\"{spaced}\" hook --agent claude-code");
        let groups = unscreened_iwguard_hooks(&wired(&ok, &quoted, &ok, &ok), fact);
        assert_eq!(groups.len(), 1, "{groups:?}");
        assert!(
            groups[0].problem.contains(&format!("runs {spaced},")),
            "{groups:?}"
        );
        let bare = format!("{} hook --agent claude-code", abs("gone"));
        assert_eq!(
            tools(&wired(&ok, &bare, &ok, &ok)),
            vec!["Write/Edit/MultiEdit/NotebookEdit"]
        );
    }

    /// An operator's own hook is never judged, gone or not.
    #[test]
    fn another_tools_hook_is_ignored() {
        let ok = cmd(&abs("ok"));
        let theirs = format!(
            "{} check",
            serde_json::to_string(&abs("gone").replace("innerwarden", "their-audit")).unwrap()
        );
        assert!(tools(&wired(&ok, &theirs, &theirs, &theirs)).is_empty());
    }

    /// "Could not tell" is never "off": a path relative to wherever the
    /// agent starts cannot be checked from here.
    #[test]
    fn a_hook_that_could_not_be_checked_is_not_reported() {
        let ok = cmd(&abs("ok"));
        let relative = "target/release/innerwarden hook --agent claude-code";
        assert!(tools(&wired(&ok, relative, &ok, relative)).is_empty());
    }

    /// One hook of ours that runs for every tool screens the file tools too.
    #[test]
    fn a_running_hook_for_every_tool_covers_a_gone_one() {
        let (ok, dead) = (cmd(&abs("ok")), cmd(&abs("gone")));
        let mut settings = wired(&ok, &dead, &ok, &ok);
        settings["hooks"]["PreToolUse"]
            .as_array_mut()
            .unwrap()
            .push(json!({"matcher": "*", "hooks": [{"type": "command", "command": ok}]}));
        assert!(tools(&settings).is_empty());
    }
}
