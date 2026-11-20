//! The blocking hook for Hermes Agent.
//!
//! Hermes runs the shell hooks it reads from `~/.hermes/config.yaml` before
//! every tool call. `agents connect hermes` writes one there:
//!
//! ```yaml
//! hooks:
//!   pre_tool_call:
//!     - command: '"/usr/local/bin/innerwarden" hook --agent hermes'
//!       fail_closed: true
//!       timeout: 60
//! ```
//!
//! Read in Hermes Agent's own source (`agent/shell_hooks.py` and
//! `hermes_cli/plugins_dispatch.py` at v0.22.5 and v0.23.1), and measured
//! through Hermes Agent v0.23.1's own hook runner (`hermes hooks test`), not
//! in a full chat:
//!
//! - The command is split into words and started without a shell, with the
//!   call as JSON on stdin (`tool_name`, `tool_input`, `session_id`, `cwd`).
//! - Exit 2 refuses the call, with stderr as the reason. Without
//!   `fail_closed` every other end of the hook runs the call: a program that
//!   is not there, a timeout, any other exit. With `fail_closed: true` each of
//!   those refuses it. So enforce writes `fail_closed: true`, and monitor
//!   writes `false`: monitor never refuses anything. The line is the guard
//!   alone; the shell script the other agents get ([`hook::hook_command_shaped`])
//!   is not needed here.
//! - Hermes gives a `pre_tool_call` hook 30 seconds
//!   (`plugins.hook_callback_timeout`) and refuses one that has not finished.
//! - Hermes runs a hook only once its event and command are approved in
//!   `~/.hermes/shell-hooks-allowlist.json` (or every hook is accepted by
//!   `hooks_auto_accept`, `HERMES_ACCEPT_HOOKS` or `--accept-hooks`).
//!   `agents connect hermes` is the person's approval, and it records it there
//!   the way Hermes's own prompt does. Disconnect takes it out.
//! - `HERMES_SAFE_MODE=1` and Hermes's safe worker run no hook at all, and
//!   `HERMES_HOME` moves the folder Hermes reads.
//!
//! The person's `config.yaml` is theirs, comments and layout included, so it
//! is never re-serialised. The entry goes in as text, at a place read from the
//! file, and the result is parsed back: everything that is not the guard's
//! entry must read exactly as before, or nothing is written and the person is
//! given the entry to add by hand.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use serde_yaml::Value as Yaml;

use crate::{agents_ops, file_update, hook};

/// The agent's id in the listing and on the hook line.
pub const AGENT: &str = "hermes";

/// The file Hermes reads its hooks from, relative to the home directory.
pub const CONFIG: &str = ".hermes/config.yaml";

/// Where Hermes keeps the hooks a person approved, relative to the home.
pub const ALLOWLIST: &str = ".hermes/shell-hooks-allowlist.json";

/// The event the hook is listed under.
pub const EVENT: &str = "pre_tool_call";

/// The hook's own timeout, in seconds: Hermes's default. The plugin layer
/// refuses a `pre_tool_call` hook still running at 30 s first.
pub const TIMEOUT_SECS: u64 = 60;

/// The comment above a `hooks:` block this module adds to a file that had
/// none, so disconnect can take the whole block out again.
const MARK: &str = "# Added by `innerwarden agents connect hermes`; \
                    `innerwarden agents disconnect hermes` takes it out.";

/// The hook line: the guard alone, as Hermes splits it into words.
pub fn command(guard_bin: &Path, block_review: bool, monitor: bool) -> String {
    hook::hook_command_shaped(guard_bin, block_review, monitor, Some(AGENT), false)
}

/// The file that holds the hook, under `home`.
pub fn config_path(home: &Path) -> PathBuf {
    home.join(CONFIG)
}

/// A YAML single-quoted scalar: the only escape is `''` for `'`.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// The guard's entry as lines of YAML, its `-` at `indent`.
fn item(indent: &str, command: &str, monitor: bool) -> String {
    format!(
        "{indent}- command: {}\n{indent}  fail_closed: {}\n{indent}  timeout: {TIMEOUT_SECS}\n",
        quoted(command),
        !monitor
    )
}

/// The entry, as the person adds it by hand when the file cannot be edited
/// here without touching something else.
pub fn manual_entry(command: &str, monitor: bool) -> String {
    format!("hooks:\n  {EVENT}:\n{}", item("    ", command, monitor))
}

/// Parse the file's text. Blank is `Null`; anything but a mapping at the top
/// is an error, as Hermes would not read hooks from it either.
fn parse(text: &str) -> Result<Yaml, String> {
    if text.trim().is_empty() {
        return Ok(Yaml::Null);
    }
    let value: Yaml = serde_yaml::from_str(text).map_err(|error| error.to_string())?;
    match value {
        Yaml::Mapping(_) | Yaml::Null => Ok(value),
        _ => Err("its top level is not a mapping".to_string()),
    }
}

/// The guard's line an entry runs, when the entry is one of ours.
fn ours(entry: &Yaml) -> Option<hook::HookLine> {
    let command = entry.get("command")?.as_str()?;
    hook::read_hook_line(&json!({"type": "command", "command": command}))
}

/// The entries under `hooks.pre_tool_call`, when that is a list.
fn entries(config: &Yaml) -> Vec<&Yaml> {
    config
        .get("hooks")
        .and_then(|hooks| hooks.get(EVENT))
        .and_then(Yaml::as_sequence)
        .map(|list| list.iter().collect())
        .unwrap_or_default()
}

/// PURE: the settings with every entry of ours taken out, and the
/// `pre_tool_call` list and the `hooks` mapping taken out once nothing is
/// left in them. Two files that differ only by the guard's entry, and by the
/// scaffolding it needs, read the same here.
fn theirs(config: &Yaml) -> Yaml {
    let mut config = config.clone();
    let Some(root) = config.as_mapping_mut() else {
        return config;
    };
    let hooks_key = Yaml::from("hooks");
    let mut drop_hooks = false;
    if let Some(hooks) = root.get_mut(&hooks_key).and_then(Yaml::as_mapping_mut) {
        let event = Yaml::from(EVENT);
        let mut drop_event = false;
        match hooks.get_mut(&event) {
            Some(Yaml::Sequence(list)) => {
                list.retain(|entry| ours(entry).is_none());
                drop_event = list.is_empty();
            }
            Some(Yaml::Null) => drop_event = true,
            _ => {}
        }
        if drop_event {
            hooks.remove(&event);
        }
        drop_hooks = hooks.is_empty();
    }
    if drop_hooks || root.get(&hooks_key) == Some(&Yaml::Null) {
        root.remove(&hooks_key);
    }
    if root.is_empty() {
        return Yaml::Null;
    }
    config
}

/// The lines of `text`, each with its line ending.
fn lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// A line that holds nothing YAML reads: blank, or a comment.
fn is_quiet(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
}

/// Whether `line` is the key `key:` at `indent`, with nothing after it but a
/// comment: the start of a block.
fn is_block_key(line: &str, indent: usize, key: &str) -> bool {
    if indent_of(line) != indent {
        return false;
    }
    let Some(rest) = line.trim_start_matches(' ').strip_prefix(key) else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(':') else {
        return false;
    };
    let rest = rest.trim();
    rest.is_empty() || rest.starts_with('#')
}

/// The guard's entries taken out as text: the block [`MARK`] heads, or each
/// item whose `- command:` line runs the guard, with the lines under it. An
/// entry in another shape stays; the callers parse the result to find out.
fn without_ours(text: &str) -> String {
    let all = lines(text);
    let mut kept: Vec<&str> = Vec::with_capacity(all.len());
    // Lines still to drop after the one that started an entry of ours. One
    // pass over the lines, so no count here can make it run on.
    let mut drop = 0usize;
    for (at, line) in all.iter().copied().enumerate() {
        if drop > 0 {
            drop -= 1;
            continue;
        }
        if line.trim_end() == MARK
            && all.get(at + 1).map(|l| l.trim_end()) == Some("hooks:")
            && all.get(at + 2).is_some_and(|l| is_block_key(l, 2, EVENT))
        {
            // The whole block this module added, when nothing else has
            // been put in it since: an entry of ours and nothing after.
            let body: Vec<&str> = all[at + 3..]
                .iter()
                .take_while(|l| indent_of(l) >= 4 && !is_quiet(l))
                .copied()
                .collect();
            let block = body.concat();
            if parse(&format!("x:\n{block}"))
                .ok()
                .and_then(|v| v.get("x").and_then(Yaml::as_sequence).cloned())
                .is_some_and(|list| !list.is_empty() && list.iter().all(|e| ours(e).is_some()))
            {
                if kept.last().is_some_and(|l| l.trim().is_empty()) {
                    kept.pop();
                }
                drop = 2 + body.len();
                continue;
            }
        }
        if let Some(value) = line.trim_start_matches(' ').strip_prefix("- command:") {
            let runs_guard = serde_yaml::from_str::<Yaml>(value.trim())
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .is_some_and(|command| {
                    hook::read_hook_line(&json!({"type": "command", "command": command})).is_some()
                });
            if runs_guard {
                let dash = indent_of(line);
                drop = all[at + 1..]
                    .iter()
                    .take_while(|l| indent_of(l) > dash && !l.trim().is_empty())
                    .count();
                // A `pre_tool_call:` left with nothing under it goes too:
                // it was there for this entry, and Hermes reads it as no hook.
                let next = all[at + 1 + drop..]
                    .iter()
                    .find(|l| !is_quiet(l))
                    .map(|l| indent_of(l));
                if let Some(key) = kept.last().filter(|l| !l.trim_start().starts_with('-')) {
                    let key_indent = indent_of(key);
                    if is_block_key(key, key_indent, EVENT)
                        && key_indent < dash
                        && next.is_none_or(|n| n <= key_indent)
                    {
                        kept.pop();
                    }
                }
                continue;
            }
        }
        kept.push(line);
    }
    kept.concat()
}

/// Where in `text` the guard's entry goes, and the text that goes there.
/// `None` when the file's `hooks:` is not a block this can add to (a flow
/// mapping, a list written inline): the person adds the entry by hand.
fn placed(text: &str, config: &Yaml, command: &str, monitor: bool) -> Option<String> {
    let all = lines(text);
    let Some(hooks) = config.get("hooks") else {
        // No `hooks:` at all: a block of its own at the end.
        let mut out = text.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(MARK);
        out.push('\n');
        out.push_str(&manual_entry(command, monitor));
        return Some(out);
    };
    if !matches!(hooks, Yaml::Mapping(_) | Yaml::Null) {
        return None;
    }
    let hooks_at = all.iter().position(|l| is_block_key(l, 0, "hooks"))?;
    // How far the keys under `hooks:` are indented: as the first of them is,
    // or two spaces when there is none.
    let child = all[hooks_at + 1..]
        .iter()
        .find(|l| !is_quiet(l))
        .map(|l| indent_of(l))
        .filter(|&n| n > 0)
        .unwrap_or(2);
    let mut out: Vec<String> = all.iter().map(|l| l.to_string()).collect();
    let (at, entry) = match hooks.get(EVENT) {
        None => {
            let pad = " ".repeat(child);
            let entry = format!(
                "{pad}{EVENT}:\n{}",
                item(&format!("{pad}  "), command, monitor)
            );
            (hooks_at + 1, entry)
        }
        Some(Yaml::Sequence(_) | Yaml::Null) => {
            // The first `pre_tool_call:` at the indentation of the keys under
            // `hooks:` is the one under it: every line of the block comes
            // before the next key at the top, and a value inside the block
            // is indented further than its keys.
            let event_at = hooks_at
                + 1
                + all[hooks_at + 1..]
                    .iter()
                    .position(|l| is_block_key(l, child, EVENT))?;
            // An item goes where the first item is, or two spaces in.
            let dash = all[event_at + 1..]
                .iter()
                .find(|l| !is_quiet(l))
                .filter(|l| l.trim_start_matches(' ').starts_with("- "))
                .map(|l| indent_of(l))
                .filter(|&n| n >= child)
                .unwrap_or(child + 2);
            (event_at + 1, item(&" ".repeat(dash), command, monitor))
        }
        Some(_) => return None,
    };
    if !out[at - 1].ends_with('\n') {
        out[at - 1].push('\n');
    }
    out.insert(at, entry);
    Some(out.concat())
}

/// PURE: the file's text with the guard's entry in it, in the mode asked for,
/// and no other change: no entry of ours but this one, and every other key,
/// entry and value reading as before. An error says why it could not be
/// placed; the entry to add by hand is [`manual_entry`].
pub fn merged(text: &str, command: &str, monitor: bool) -> Result<String, String> {
    let before = parse(text).map_err(|why| format!("it is not valid YAML: {why}"))?;
    // Hermes's YAML reader applies `<<` merge keys and the one read here does
    // not: a `hooks:` written here could hide hooks the file merges in, and
    // nothing below would see it.
    let merge_key = Yaml::from("<<");
    let merges = |value: Option<&Yaml>| {
        value
            .and_then(Yaml::as_mapping)
            .is_some_and(|map| map.contains_key(&merge_key))
    };
    if merges(Some(&before)) || merges(before.get("hooks")) {
        return Err("it merges keys in with `<<`, and the entry could hide them".to_string());
    }
    let cleaned = without_ours(text);
    let after_removal = parse(&cleaned).map_err(|why| format!("it could not be edited: {why}"))?;
    if theirs(&after_removal) != theirs(&before)
        || !entries(&after_removal).iter().all(|e| ours(e).is_none())
    {
        return Err("an entry of the guard's is there in a shape it cannot take out".to_string());
    }
    let out = placed(&cleaned, &after_removal, command, monitor)
        .ok_or_else(|| "its `hooks:` is not a block the entry can be added to".to_string())?;
    let after = parse(&out).map_err(|why| format!("the entry could not be placed: {why}"))?;
    let mine: Vec<&Yaml> = entries(&after)
        .into_iter()
        .filter(|e| ours(e).is_some())
        .collect();
    let expected: Yaml = serde_yaml::from_str(&item("", command, monitor))
        .ok()
        .and_then(|v: Yaml| v.as_sequence().and_then(|l| l.first().cloned()))
        .ok_or("the entry could not be written")?;
    if theirs(&after) != theirs(&before) || mine != [&expected] {
        return Err("the entry could not be placed without changing anything else".to_string());
    }
    Ok(out)
}

/// PURE: the file's text with every entry of the guard's taken out, and
/// nothing else changed. `Ok(None)` when there was none.
pub fn removed(text: &str) -> Result<Option<String>, String> {
    let before = parse(text).map_err(|why| format!("it is not valid YAML: {why}"))?;
    if entries(&before).iter().all(|e| ours(e).is_none()) {
        return Ok(None);
    }
    let out = without_ours(text);
    let after = parse(&out).map_err(|why| format!("it could not be edited: {why}"))?;
    if theirs(&after) != theirs(&before) || entries(&after).iter().any(|e| ours(e).is_some()) {
        return Err(
            "the guard's entry is there in a shape it cannot take out; remove it from \
             `hooks.pre_tool_call` by hand"
                .to_string(),
        );
    }
    Ok(Some(out))
}

/// PURE: Hermes's allowlist with the guard's approval in it for `command`
/// and no older approval of a guard line for the event. Every other approval
/// and key stays as it was. `approved_at` and `script_mtime_at_approval` are
/// what Hermes's own prompt records.
pub fn approved(
    allowlist: Option<&[u8]>,
    command: &str,
    approved_at: &str,
    script_mtime: Option<&str>,
) -> Result<Value, String> {
    let mut list = match allowlist {
        None => json!({"approvals": []}),
        Some(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => json!({"approvals": []}),
        Some(bytes) => serde_json::from_slice(bytes).map_err(|error| error.to_string())?,
    };
    let approvals = list
        .as_object_mut()
        .ok_or("its top level is not a JSON object")?
        .entry("approvals")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or("`approvals` is not a list")?;
    approvals.retain(|entry| !is_guard_approval(entry));
    approvals.push(json!({
        "event": EVENT,
        "command": command,
        "approved_at": approved_at,
        "script_mtime_at_approval": script_mtime,
    }));
    Ok(list)
}

/// PURE: the allowlist with every approval of a guard line for the event
/// taken out. `None` when there was none.
pub fn unapproved(allowlist: &[u8]) -> Result<Option<Value>, String> {
    let mut list: Value = serde_json::from_slice(allowlist).map_err(|error| error.to_string())?;
    let Some(approvals) = list.get_mut("approvals").and_then(Value::as_array_mut) else {
        return Ok(None);
    };
    let before = approvals.len();
    approvals.retain(|entry| !is_guard_approval(entry));
    Ok((approvals.len() != before).then_some(list))
}

fn is_guard_approval(entry: &Value) -> bool {
    entry.get("event").and_then(Value::as_str) == Some(EVENT)
        && entry
            .get("command")
            .and_then(Value::as_str)
            .is_some_and(|command| {
                hook::read_hook_line(&json!({"type": "command", "command": command})).is_some()
            })
}

/// Whether the allowlist approves `command` for the event.
fn is_approved(allowlist: &Value, command: &str) -> bool {
    allowlist
        .get("approvals")
        .and_then(Value::as_array)
        .is_some_and(|list| {
            list.iter().any(|entry| {
                entry.get("event").and_then(Value::as_str) == Some(EVENT)
                    && entry.get("command").and_then(Value::as_str) == Some(command)
            })
        })
}

/// Whether the config accepts every hook without an approval
/// (`hooks_auto_accept`), as Hermes reads that key.
fn accepts_every_hook(config: &Yaml) -> bool {
    match config.get("hooks_auto_accept") {
        Some(Yaml::Bool(on)) => *on,
        Some(Yaml::String(text)) => {
            matches!(
                text.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        }
        _ => false,
    }
}

fn now_iso() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.6fZ")
        .to_string()
}

/// The modification time Hermes records for the program a command names.
fn mtime_iso(program: &Path) -> Option<String> {
    let modified = std::fs::metadata(program).ok()?.modified().ok()?;
    let at: chrono::DateTime<chrono::Utc> = modified.into();
    Some(at.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
}

fn read_text(path: &Path) -> Result<Option<String>, String> {
    match file_update::read_config(path)? {
        None => Ok(None),
        Some(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| format!("{} is not UTF-8 text", path.display())),
    }
}

/// Write the hook into `~/.hermes/config.yaml` and its approval into the
/// allowlist, under `home`. Returns whether anything changed. The config
/// comes first; an allowlist that cannot be read is left alone, and the hook
/// then reads as not approved.
pub fn install(
    home: &Path,
    guard_bin: &Path,
    block_review: bool,
    monitor: bool,
) -> Result<bool, String> {
    let path = config_path(home);
    let command = command(guard_bin, block_review, monitor);
    let before = read_text(&path)?;
    let text = before.clone().unwrap_or_default();
    let merged = merged(&text, &command, monitor).map_err(|why| {
        format!(
            "{} was left as it is: {why}. Add this under it by hand:\n{}",
            path.display(),
            manual_entry(&command, monitor)
        )
    })?;
    let mut changed = false;
    if merged != text {
        file_update::replace_if_unchanged(
            &path,
            before.as_deref().map(str::as_bytes),
            merged.as_bytes(),
        )?;
        changed = true;
    }
    let list_path = home.join(ALLOWLIST);
    let list_before = file_update::read_config(&list_path)?;
    let already = list_before
        .as_deref()
        .and_then(|bytes| serde_json::from_slice::<Value>(bytes).ok())
        .is_some_and(|list| {
            is_approved(&list, &command)
                && list["approvals"]
                    .as_array()
                    .is_some_and(|all| all.iter().filter(|e| is_guard_approval(e)).count() == 1)
        });
    if !already {
        let list = approved(
            list_before.as_deref(),
            &command,
            &now_iso(),
            mtime_iso(guard_bin).as_deref(),
        )
        .map_err(|why| format!("{}: {why}", list_path.display()))?;
        let mut body = serde_json::to_string_pretty(&list).map_err(|e| e.to_string())?;
        body.push('\n');
        file_update::replace_if_unchanged(&list_path, list_before.as_deref(), body.as_bytes())?;
        changed = true;
    }
    Ok(changed)
}

/// Take the guard's entry out of the config and its approval out of the
/// allowlist, under `home`. Returns how many entries left the config.
pub fn uninstall(home: &Path) -> Result<usize, String> {
    let path = config_path(home);
    let mut removed_entries = 0;
    if let Some(text) = read_text(&path)? {
        let count = parse(&text)
            .map(|config| {
                entries(&config)
                    .iter()
                    .filter(|e| ours(e).is_some())
                    .count()
            })
            .unwrap_or(0);
        if let Some(out) = removed(&text).map_err(|why| format!("{}: {why}", path.display()))? {
            file_update::replace_if_unchanged(&path, Some(text.as_bytes()), out.as_bytes())?;
            removed_entries = count;
        }
    }
    let list_path = home.join(ALLOWLIST);
    if let Some(bytes) = file_update::read_config(&list_path)? {
        if let Ok(Some(list)) = unapproved(&bytes) {
            let mut body = serde_json::to_string_pretty(&list).map_err(|e| e.to_string())?;
            body.push('\n');
            file_update::replace_if_unchanged(&list_path, Some(&bytes), body.as_bytes())?;
        }
    }
    Ok(removed_entries)
}

/// Where the Hermes hook stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// No entry of the guard's in the config, or no config.
    Absent,
    /// The config is there and could not be read.
    Unreadable,
    /// Hermes runs it, as far as anything readable from here says.
    On { monitor: bool, block_review: bool },
    /// It is in the config, and Hermes does not run it as written.
    Off(Off),
}

/// Why an entry that is in the config is not reported on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Off {
    /// Not the entry `agents connect` writes: another `fail_closed`, a
    /// matcher, another timeout, a second copy.
    Altered,
    /// Not approved in the allowlist, and the config does not accept every
    /// hook: Hermes skips it.
    NotApproved,
    /// The program it runs is not there. Holds the clause; `refuses` says
    /// Hermes refuses every call meanwhile (`fail_closed` in enforce).
    Broken { clause: String, refuses: bool },
    /// The program could not be looked at. Holds the clause.
    Unchecked { clause: String, refuses: bool },
}

impl State {
    pub fn is_on(&self) -> bool {
        matches!(self, Self::On { .. })
    }

    pub fn installed(&self) -> bool {
        matches!(self, Self::On { .. } | Self::Off(_))
    }
}

/// Read where the hook stands under `home`. `path_env` is the `PATH` a bare
/// program name is looked up on. Nothing is started and nothing is written.
pub fn state(home: &Path, path_env: Option<&OsStr>) -> State {
    let text = match read_text(&config_path(home)) {
        Ok(Some(text)) => text,
        Ok(None) => return State::Absent,
        Err(_) => return State::Unreadable,
    };
    let Ok(config) = parse(&text) else {
        return State::Unreadable;
    };
    let allowlist = file_update::read_config(&home.join(ALLOWLIST))
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    judge(&config, allowlist.as_ref(), |program| {
        agents_ops::program_fact(program, path_env)
    })
}

/// PURE: where the hook stands, from the config, the allowlist and what the
/// caller found when it looked for the program. Every doubt is "off", as for
/// Codex and Gemini: Hermes gives no other sign that it skipped a hook.
fn judge(
    config: &Yaml,
    allowlist: Option<&Value>,
    fact: impl Fn(&str) -> hook::ProgramFact,
) -> State {
    let mine: Vec<(&Yaml, hook::HookLine)> = entries(config)
        .into_iter()
        .filter_map(|entry| ours(entry).map(|line| (entry, line)))
        .collect();
    let [(entry, line)] = mine.as_slice() else {
        return if mine.is_empty() {
            State::Absent
        } else {
            State::Off(Off::Altered)
        };
    };
    let command = command(Path::new(&line.program), line.block_review, line.monitor);
    let expected: Option<Yaml> = serde_yaml::from_str::<Yaml>(&item("", &command, line.monitor))
        .ok()
        .and_then(|v| v.as_sequence().and_then(|l| l.first().cloned()));
    if expected.as_ref() != Some(*entry) || line.agent.as_deref() != Some(AGENT) {
        return State::Off(Off::Altered);
    }
    let refuses = !line.monitor;
    match hook::judge_hook_program(&line.program, fact(&line.program)) {
        hook::HookProgram::Runs => {}
        hook::HookProgram::Broken { problem, .. } => {
            return State::Off(Off::Broken {
                clause: problem,
                refuses,
            })
        }
        hook::HookProgram::Unknown { why, .. } => {
            return State::Off(Off::Unchecked {
                clause: why,
                refuses,
            })
        }
    }
    if !accepts_every_hook(config) && !allowlist.is_some_and(|list| is_approved(list, &command)) {
        return State::Off(Off::NotApproved);
    }
    State::On {
        monitor: line.monitor,
        block_review: line.block_review,
    }
}

/// One line that says where the hook stands and, when it is not on, the one
/// step that turns it on.
pub fn state_line(state: &State) -> String {
    let connect = "Run: innerwarden agents connect hermes";
    match state {
        State::Absent => format!("{EVENT} hook: not installed. {connect}"),
        State::Unreadable => format!(
            "{EVENT} hook: unknown, ~/{CONFIG} could not be read. Fix ~/{CONFIG}, then run \
             `innerwarden agents connect hermes`"
        ),
        State::On { monitor, .. } => format!(
            "{EVENT} hook: on ({})",
            if *monitor { "monitor" } else { "enforce" }
        ),
        State::Off(Off::Altered) => format!(
            "{EVENT} hook: installed, but it is not the entry `agents connect` writes, so \
             Hermes may not run it, or may run the call when the guard cannot answer. {connect}"
        ),
        State::Off(Off::NotApproved) => format!(
            "{EVENT} hook: installed, but Hermes skips it: it is not approved in \
             ~/{ALLOWLIST}. {connect}"
        ),
        State::Off(Off::Broken { clause, refuses } | Off::Unchecked { clause, refuses }) => {
            let effect = if *refuses {
                ", and Hermes refuses every tool call until it is there"
            } else {
                ""
            };
            format!("{EVENT} hook: installed, but {clause}{effect}. {connect}")
        }
    }
}

/// Where a hook that is not on stands, to follow "Its " in `status`. `None`
/// for a hook that is on.
pub fn not_on(state: &State) -> Option<String> {
    Some(match state {
        State::On { .. } => return None,
        State::Absent => format!("{EVENT} hook is not installed"),
        State::Unreadable => format!("{EVENT} hook is unknown: ~/{CONFIG} could not be read"),
        State::Off(Off::Altered) => {
            format!("{EVENT} hook is installed, but it is not the entry `agents connect` writes")
        }
        State::Off(Off::NotApproved) => format!(
            "{EVENT} hook is installed, but Hermes skips it: it is not approved in ~/{ALLOWLIST}"
        ),
        State::Off(Off::Broken { clause, .. } | Off::Unchecked { clause, .. }) => {
            format!("{EVENT} hook is installed, but {clause}")
        }
    })
}

/// What is screened for Hermes and what is not, in the words `agents
/// connect` prints. Each line is one fact read in Hermes's source.
pub fn coverage() -> Vec<String> {
    let mut lines = vec![format!("Screened before they run: {}", screened())];
    lines.extend(gaps());
    lines
}

/// What the hook screens, in the words that follow "screened before they
/// run: ".
pub fn screened() -> String {
    "`terminal` commands (in the `workdir` they name), the Python `execute_code` runs (as \
     `python3 -c`), text `process_manage` types into a running process (as a shell line), \
     changes to privileged files through `write_file` and `patch`, and reads of secrets \
     through `read_file` and `search_files`. Its other tools (the browser, its MCP servers \
     and the rest) are not screened."
        .to_string()
}

/// What a hook that is on still leaves out, and when Hermes stops running
/// it. Each line is one fact read in Hermes's source.
pub fn gaps() -> Vec<String> {
    vec![
        format!(
            "Hermes runs the hook only while it is approved in ~/{ALLOWLIST}; connect records \
             that approval. `hermes hooks revoke`, a changed hook line, HERMES_SAFE_MODE=1, \
             Hermes's safe worker or a HERMES_HOME set to another folder switch it off without \
             a word."
        ),
        "Hermes keeps the folder a `terminal` command changes to for its next command, and \
         sends the folder Hermes was started in: a later command or file change that names a \
         relative path is judged in that folder, not where it runs."
            .to_string(),
        "With a container or remote `terminal` backend (Docker, SSH and the like) the \
         command runs there, and the guard judges it as if it ran on this host."
            .to_string(),
        "`execute_code` keeps one Python kernel across calls, and each call is judged on its \
         own: a name set in one call and used in the next is not followed. In enforce mode a \
         `terminal` command that starts a shell, a language or a database client with nothing \
         to run is refused, so a process left waiting cannot be typed into past the guard."
            .to_string(),
        "In enforce mode the entry carries `fail_closed: true`: a guard that is missing, \
         cannot start, is killed, times out or ends without its answer refuses the call. In \
         monitor mode it is false, and such a call runs."
            .to_string(),
        "Hermes gives the hook 30 seconds (`plugins.hook_callback_timeout`) and refuses a call \
         whose hook has not finished. The guard refuses on its own at 10 seconds."
            .to_string(),
        "Needs Hermes Agent v0.22.5 or later: `fail_closed` exists from v0.20.1, and what is \
         stated here was read in v0.22.5 and v0.23.1."
            .to_string(),
        "Measured through Hermes Agent v0.23.1's own hook runner (`hermes hooks test`), not in a full chat.".to_string(),
    ]
}

/// The tool that runs Python in Hermes's own kernel.
pub const EXECUTE_CODE_TOOL: &str = "execute_code";

/// The tool that types into a process a `terminal` call left running:
/// `process_manage` in Hermes Agent v0.22.5 and v0.23.1.
pub const PROCESS_TOOL: &str = "process_manage";

/// PURE. The shell line a Hermes call that runs code outside `terminal` is
/// judged as, read in Hermes Agent v0.23.1's source:
///
/// * `execute_code` (`{"code"}`) runs its Python as given, so it is judged
///   as `python3 -c '<code>'`, which the shell rules read as inline code;
/// * `process_manage` with `write` or `submit` (`{"action", "data"}`) types
///   `data` into a process a background `terminal` call started, which is
///   a shell when the process is one, so `data` is judged as a shell line.
///
/// `None` for any other call, and for `process_manage` that only polls,
/// waits, lists or kills. `Err` for one of these two with nothing in it: the
/// hook is run for them, so that is a schema change.
pub fn shell_line_of(payload: &Value) -> Option<Result<String, &'static str>> {
    let tool = payload.get("tool_name").and_then(Value::as_str)?;
    let input = payload.get("tool_input");
    let text = |key: &str| {
        input
            .and_then(|input| input.get(key))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
    };
    match tool {
        EXECUTE_CODE_TOOL => Some(
            text("code")
                .map(|code| format!("python3 -c {}", shell_quoted(code)))
                .ok_or("an execute_code call with no code"),
        ),
        PROCESS_TOOL => {
            let action = input
                .and_then(|input| input.get("action"))
                .and_then(Value::as_str)?;
            if !matches!(action, "write" | "submit") {
                return None;
            }
            Some(
                text("data")
                    .map(str::to_string)
                    .ok_or("a process_manage write with no data"),
            )
        }
        _ => None,
    }
}

/// `code` as one shell word that reads back as exactly `code`: in double
/// quotes when nothing in it means anything there (no `"`, `$`, backquote,
/// backslash or `!`), else in single quotes, with each `'` written `'\''`.
/// Double quotes first because that reads back most plainly.
fn shell_quoted(code: &str) -> String {
    if !code.contains(['"', '$', '`', '\\', '!']) {
        format!("\"{code}\"")
    } else {
        format!("'{}'", code.replace('\'', r"'\''"))
    }
}

/// Whether `~/.hermes/config.yaml` under `home` holds an entry that runs
/// `binary`: `Some(true)` when it does, `Some(false)` when the file does not
/// read well enough to rule one out, `None` when it holds none. Asked by
/// `uninstall` before the binary goes: Hermes refuses every tool call while a
/// fail-closed entry names a program that is gone.
pub fn still_runs(home: &Path, binary: &Path) -> Option<bool> {
    let text = match read_text(&config_path(home)) {
        Ok(Some(text)) => text,
        Ok(None) => return None,
        Err(_) => return Some(false),
    };
    match parse(&text) {
        Ok(config) => entries(&config)
            .into_iter()
            .filter_map(ours)
            .any(|line| {
                let program = Path::new(&line.program);
                program == binary
                    || matches!(
                        (program.canonicalize(), binary.canonicalize()),
                        (Ok(program), Ok(binary)) if program == binary
                    )
            })
            .then_some(true),
        Err(_) => text.contains("innerwarden\" hook").then_some(false),
    }
}

/// What `uninstall` says of a Hermes entry it stopped for ([`still_runs`]):
/// the file, what the entry costs once the binary is gone, and the step.
/// `seen` is false for a file that could not be read as YAML.
pub fn left_behind_lines(seen: bool) -> Vec<String> {
    vec![
        if seen {
            format!("~/{CONFIG} still holds a {EVENT} hook that runs this binary.")
        } else {
            format!(
                "~/{CONFIG} could not be read, and a {EVENT} hook in it may still run this binary."
            )
        },
        "Hermes refuses every tool call while a fail-closed hook names a program that is gone."
            .to_string(),
        format!(
            "Take the innerwarden entry out of `hooks.{EVENT}` in that file, or run \
             `innerwarden agents disconnect {AGENT}` once the file can be read and written."
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIN: &str = "/opt/iw/innerwarden";

    fn line(monitor: bool) -> String {
        command(Path::new(BIN), false, monitor)
    }

    fn approved_list(command: &str) -> Value {
        approved(None, command, "2026-11-13T00:00:00.000000Z", None).unwrap()
    }

    /// The line is the guard alone, naming Hermes: Hermes splits it into
    /// words and starts it without a shell, and `fail_closed` refuses what
    /// the script does for the other agents.
    #[test]
    fn the_line_is_the_guard_alone_and_names_hermes() {
        assert_eq!(line(false), "\"/opt/iw/innerwarden\" hook --agent hermes");
        assert_eq!(
            line(true),
            "\"/opt/iw/innerwarden\" hook --monitor --agent hermes"
        );
    }

    /// A file with no `hooks:` gets a block of its own at the end, marked,
    /// and every comment and key of the person's stays as it was, to the
    /// byte. Enforce writes `fail_closed: true`, monitor `false`. A second
    /// run changes nothing, and a run in the other mode replaces the entry.
    ///
    /// FAILS ON REVERT: write `fail_closed: true` whatever the mode, and the
    /// monitor entry refuses calls when the guard is gone.
    #[test]
    fn a_file_without_hooks_gets_the_marked_block_and_keeps_every_byte() {
        let person =
            "# my settings\nmodel:\n  default: gpt-5.6   # fast\nterminal:\n  backend: local\n";
        let out = merged(person, &line(false), false).unwrap();
        assert!(out.starts_with(person), "{out}");
        assert_eq!(
            &out[person.len()..],
            format!(
                "\n{MARK}\nhooks:\n  pre_tool_call:\n    - command: '\"/opt/iw/innerwarden\" hook \
                 --agent hermes'\n      fail_closed: true\n      timeout: 60\n"
            )
        );
        assert_eq!(merged(&out, &line(false), false).unwrap(), out);
        let watched = merged(&out, &line(true), true).unwrap();
        assert!(watched.contains("hook --monitor --agent hermes'\n      fail_closed: false\n"));
        assert_eq!(watched.matches("- command:").count(), 1, "{watched}");
        assert_eq!(removed(&out).unwrap().unwrap(), person);
        assert_eq!(removed(&watched).unwrap().unwrap(), person);
        assert_eq!(removed(person).unwrap(), None);
        assert_eq!(
            merged("", &line(false), false).unwrap(),
            format!("{MARK}\n{}", manual_entry(&line(false), false))
        );
    }

    /// A file that has hooks of the person's gets the entry beside them, at
    /// the indentation they use, and their hooks, comments and order stay.
    /// Disconnect takes out only the guard's entry.
    #[test]
    fn the_entry_goes_beside_the_persons_own_hooks() {
        let person = "hooks:\n    # audit everything\n    pre_tool_call:\n      - command: ~/.hermes/agent-hooks/audit.sh\n        matcher: terminal\n    post_tool_call:\n      - command: ~/.hermes/agent-hooks/log.sh\nmodel: x\n";
        let out = merged(person, &line(false), false).unwrap();
        let config = parse(&out).unwrap();
        let listed = entries(&config);
        assert_eq!(listed.len(), 2, "{out}");
        assert!(ours(listed[0]).is_some(), "{out}");
        assert_eq!(
            listed[1]["command"],
            Yaml::from("~/.hermes/agent-hooks/audit.sh")
        );
        assert!(out.contains("    # audit everything\n"));
        assert_eq!(removed(&out).unwrap().unwrap(), person);

        let no_event = "hooks:\n  post_tool_call:\n    - command: /x/log.sh\n";
        let out = merged(no_event, &line(false), false).unwrap();
        assert_eq!(entries(&parse(&out).unwrap()).len(), 1, "{out}");
        assert_eq!(
            theirs(&parse(&out).unwrap()),
            theirs(&parse(no_event).unwrap())
        );
        assert_eq!(removed(&out).unwrap().unwrap(), no_event);
    }

    /// A `hooks:` written inline, or a file that is not YAML, is never
    /// rewritten: the person is given the entry to add by hand.
    ///
    /// FAILS ON REVERT: drop the check of `theirs` in `merged` and the `|+`
    /// scalar gains a line.
    #[test]
    fn a_file_it_cannot_edit_exactly_is_left_alone() {
        for text in [
            // The blank line the block is set apart by would join this
            // scalar, which keeps its trailing lines (`|+`).
            "notes: |+\n  text\n",
            // Hermes reads `<<`, so a `hooks:` of the guard's would hide the
            // hooks merged in from `base`.
            "base: &b\n  hooks:\n    pre_tool_call:\n      - command: /x/a.sh\n<<: *b\n",
            "hooks:\n  <<: {pre_tool_call: [{command: /x/a.sh}]}\n",
            "hooks: {post_tool_call: [{command: /x/log.sh}]}\n",
            "hooks:\n  pre_tool_call: [{command: /x/a.sh}]\n",
            "model: [unclosed\n",
            "- a\n- b\n",
        ] {
            assert!(merged(text, &line(false), false).is_err(), "{text}");
        }
    }

    /// An entry of the guard's in a shape the text edit cannot find (a flow
    /// mapping) is never left beside a second one: the file is left alone
    /// and the person is told why.
    ///
    /// FAILS ON REVERT: turn the `||` of the check after `without_ours` in
    /// `merged` into `&&` and the reason is the later, vaguer one.
    #[test]
    fn an_entry_of_ours_it_cannot_take_out_stops_the_edit() {
        let flow = format!(
            "hooks:\n  pre_tool_call:\n    - {{command: {}, fail_closed: true, timeout: 60}}\n",
            quoted(&line(false))
        );
        assert_eq!(
            merged(&flow, &line(true), true),
            Err("an entry of the guard's is there in a shape it cannot take out".to_string())
        );
        assert!(removed(&flow).is_err());
    }

    /// A `hooks:` with nothing under it, last in a file with no newline at
    /// its end, takes the entry on lines of their own.
    ///
    /// FAILS ON REVERT: look at `out[at]` instead of `out[at - 1]` for the
    /// missing newline in `placed`, and the edit reads past the end.
    #[test]
    fn an_empty_hooks_key_at_the_end_of_the_file_takes_the_entry() {
        let out = merged("model: x\nhooks:", &line(false), false).unwrap();
        assert_eq!(
            out,
            format!(
                "model: x\nhooks:\n  pre_tool_call:\n{}",
                item("    ", &line(false), false)
            )
        );
        assert_eq!(removed(&out).unwrap().unwrap(), "model: x\nhooks:\n");
    }

    /// `is_on` is said of a hook Hermes runs only, `installed` of one that is
    /// in the config whether it runs or not.
    #[test]
    fn on_and_installed_say_what_they_name() {
        let on = State::On {
            monitor: false,
            block_review: false,
        };
        let skipped = State::Off(Off::NotApproved);
        assert!(on.is_on() && on.installed());
        assert!(!skipped.is_on() && skipped.installed());
        assert!(!State::Absent.is_on() && !State::Absent.installed());
        assert!(!State::Unreadable.is_on() && !State::Unreadable.installed());
    }

    /// The person's own command that only mentions the guard is not the
    /// guard's entry, and disconnect leaves it.
    #[test]
    fn a_persons_entry_that_mentions_the_guard_is_theirs() {
        let person =
            "hooks:\n  pre_tool_call:\n    - command: '/opt/audit/wrap.sh innerwarden hook'\n";
        assert_eq!(removed(person).unwrap(), None);
        let out = merged(person, &line(false), false).unwrap();
        assert_eq!(entries(&parse(&out).unwrap()).len(), 2);
    }

    /// The approval is the one Hermes's own prompt records, any older
    /// approval of a guard line goes, and the person's own stay.
    #[test]
    fn the_approval_replaces_older_guard_approvals_and_keeps_the_persons() {
        let before = json!({"approvals": [
            {"event": "pre_tool_call", "command": "/x/audit.sh", "approved_at": "a"},
            {"event": "pre_tool_call", "command": "\"/old/innerwarden\" hook --agent hermes"},
        ], "note": "kept"});
        let after = approved(
            Some(before.to_string().as_bytes()),
            &line(false),
            "2026-11-13T10:00:00.000000Z",
            Some("2026-11-01T00:00:00.000000Z"),
        )
        .unwrap();
        assert_eq!(
            after,
            json!({"approvals": [
                {"event": "pre_tool_call", "command": "/x/audit.sh", "approved_at": "a"},
                {"event": "pre_tool_call", "command": line(false),
                 "approved_at": "2026-11-13T10:00:00.000000Z",
                 "script_mtime_at_approval": "2026-11-01T00:00:00.000000Z"},
            ], "note": "kept"})
        );
        let back = unapproved(after.to_string().as_bytes()).unwrap().unwrap();
        assert_eq!(
            back,
            json!({"approvals": [
                {"event": "pre_tool_call", "command": "/x/audit.sh", "approved_at": "a"},
            ], "note": "kept"})
        );
        assert_eq!(unapproved(back.to_string().as_bytes()).unwrap(), None);
        assert!(approved(Some(b"[1]"), &line(false), "t", None).is_err());
    }

    fn judged(text: &str, allowlist: Option<&Value>, fact: hook::ProgramFact) -> State {
        judge(&parse(text).unwrap(), allowlist, move |_: &str| fact)
    }

    /// On only with the exact entry, an approval for its exact line (or a
    /// config that accepts every hook) and a program that is there. A program
    /// that is gone is said to hold every call up in enforce, not in monitor.
    ///
    /// FAILS ON REVERT: skip the allowlist look in `judge` and a hook Hermes
    /// skips reads "on".
    #[test]
    fn the_hook_is_on_only_when_hermes_runs_it() {
        let enforce = merged("", &line(false), false).unwrap();
        let ok = hook::ProgramFact::Executable;
        let list = approved_list(&line(false));
        assert_eq!(
            judged(&enforce, Some(&list), ok),
            State::On {
                monitor: false,
                block_review: false
            }
        );
        assert_eq!(judged(&enforce, None, ok), State::Off(Off::NotApproved));
        assert_eq!(
            judged(&enforce, Some(&approved_list(&line(true))), ok),
            State::Off(Off::NotApproved)
        );
        let auto = format!("hooks_auto_accept: true\n{enforce}");
        assert!(judged(&auto, None, ok).is_on());
        assert_eq!(
            judged(&enforce, Some(&list), hook::ProgramFact::Missing),
            State::Off(Off::Broken {
                clause: "its hook runs /opt/iw/innerwarden, which does not exist".to_string(),
                refuses: true
            })
        );
        let monitor = merged("", &line(true), true).unwrap();
        assert!(matches!(
            judged(
                &monitor,
                Some(&approved_list(&line(true))),
                hook::ProgramFact::Missing
            ),
            State::Off(Off::Broken { refuses: false, .. })
        ));
        // An entry that would let the call run when the guard cannot answer
        // is not the entry connect writes.
        let open = enforce.replace("fail_closed: true", "fail_closed: false");
        assert_eq!(judged(&open, Some(&list), ok), State::Off(Off::Altered));
        let matched = enforce.replace(
            "      timeout: 60\n",
            "      timeout: 60\n      matcher: terminal\n",
        );
        assert_eq!(judged(&matched, Some(&list), ok), State::Off(Off::Altered));
        assert_eq!(judged("model: x\n", Some(&list), ok), State::Absent);
    }

    /// Connect writes the config and the approval, a second connect writes
    /// nothing, and disconnect takes both out and leaves the person's own.
    #[test]
    fn install_and_uninstall_write_the_config_and_the_approval() {
        let home = tempfile::TempDir::new().unwrap();
        let dir = home.path().join(".hermes");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.yaml"), "model:\n  default: x\n").unwrap();
        let bin = Path::new(BIN);
        assert!(install(home.path(), bin, false, false).unwrap());
        assert!(!install(home.path(), bin, false, false).unwrap());
        let list: Value =
            serde_json::from_slice(&std::fs::read(home.path().join(ALLOWLIST)).unwrap()).unwrap();
        assert!(is_approved(&list, &line(false)));
        assert_eq!(
            judge(
                &parse(&std::fs::read_to_string(config_path(home.path())).unwrap()).unwrap(),
                Some(&list),
                |_| hook::ProgramFact::Executable
            ),
            State::On {
                monitor: false,
                block_review: false
            }
        );
        assert_eq!(still_runs(home.path(), bin), Some(true));
        assert_eq!(
            still_runs(home.path(), Path::new("/elsewhere/innerwarden")),
            None
        );
        assert_eq!(uninstall(home.path()).unwrap(), 1);
        assert_eq!(
            std::fs::read_to_string(config_path(home.path())).unwrap(),
            "model:\n  default: x\n"
        );
        let list: Value =
            serde_json::from_slice(&std::fs::read(home.path().join(ALLOWLIST)).unwrap()).unwrap();
        assert_eq!(list, json!({"approvals": []}));
        assert_eq!(uninstall(home.path()).unwrap(), 0);
        assert_eq!(still_runs(home.path(), bin), None);
    }

    #[test]
    fn the_state_line_says_the_step_and_what_a_gone_program_costs() {
        assert_eq!(
            state_line(&State::Off(Off::Broken {
                clause: "its hook runs /x, which does not exist".to_string(),
                refuses: true
            })),
            "pre_tool_call hook: installed, but its hook runs /x, which does not exist, and \
             Hermes refuses every tool call until it is there. Run: innerwarden agents connect \
             hermes"
        );
        assert_eq!(
            state_line(&State::On {
                monitor: true,
                block_review: false
            }),
            "pre_tool_call hook: on (monitor)"
        );
    }

    /// A key the person writes after the marked block stays where it is, and
    /// the block goes whole.
    ///
    /// FAILS ON REVERT: read the marked block's body by `||` instead of `&&`
    /// in `without_ours` and the key after it is taken out with the block.
    #[test]
    fn a_key_after_the_marked_block_stays_and_the_block_goes_whole() {
        let connected = merged("model: x\n", &line(false), false).unwrap();
        let later = format!("{connected}other: 1\n");
        assert_eq!(removed(&later).unwrap().unwrap(), "model: x\nother: 1\n");
    }

    /// The entry goes at the indentation of the person's own items, which
    /// YAML lets sit under the key's own column or further in, past a
    /// comment.
    ///
    /// FAILS ON REVERT: start the look for the first item at the key itself
    /// (`event_at * 1`), or take the first comment for it (`find(is_quiet)`),
    /// and the entry lands at another indentation and the file no longer
    /// reads as it did.
    #[test]
    fn the_entry_takes_the_indentation_of_the_persons_items() {
        for person in [
            "hooks:\n  pre_tool_call:\n  - command: /x/a.sh\n",
            "hooks:\n  pre_tool_call:\n      # mine\n      - command: /x/a.sh\n",
            // A blank line and a comment before the first key under `hooks:`
            // do not set its indentation.
            "hooks:\n\n    # mine\n    post_tool_call:\n      - command: /x/log.sh\n",
        ] {
            let out = merged(person, &line(false), false).unwrap();
            let listed = entries(&parse(&out).unwrap()).len();
            let theirs = entries(&parse(person).unwrap()).len();
            assert_eq!(listed, theirs + 1, "{out}");
            assert_eq!(removed(&out).unwrap().unwrap(), person);
        }
    }

    /// A second connect with the guard somewhere else approves the new line
    /// and drops the old approval, and the approval records the program's
    /// modification time, as Hermes's own prompt does.
    ///
    /// FAILS ON REVERT: count the allowlist as up to date when it approves
    /// this line OR holds one guard approval (`||` in `install`), and the new
    /// line is never approved; answer `None` from `mtime_iso` and the time is
    /// not recorded.
    #[cfg(unix)]
    #[test]
    fn a_connect_from_another_place_approves_the_new_line_only() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".hermes")).unwrap();
        let old = home.path().join("old/innerwarden");
        let new = home.path().join("new/innerwarden");
        for bin in [&old, &new] {
            std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
            std::fs::write(bin, "#!/bin/sh\n").unwrap();
        }
        install(home.path(), &old, false, false).unwrap();
        install(home.path(), &new, false, false).unwrap();
        let list: Value =
            serde_json::from_slice(&std::fs::read(home.path().join(ALLOWLIST)).unwrap()).unwrap();
        let approvals = list["approvals"].as_array().unwrap();
        assert_eq!(approvals.len(), 1, "{list}");
        assert_eq!(approvals[0]["command"], json!(command(&new, false, false)));
        // Both times as Hermes writes them: UTC, microseconds, `Z`, and the
        // program's own time no later than the approval's.
        let shape = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$").unwrap();
        let approved_at = approvals[0]["approved_at"].as_str().unwrap();
        let mtime = approvals[0]["script_mtime_at_approval"].as_str().unwrap();
        assert!(shape.is_match(approved_at), "{approved_at}");
        assert!(shape.is_match(mtime), "{mtime}");
        assert!(mtime <= approved_at, "{mtime} {approved_at}");
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        assert!(approved_at.starts_with(&today), "{approved_at}");
    }

    /// A blank allowlist is an empty one, and a `hooks:` with nothing under
    /// it, followed by another key, takes the entry under `hooks:`.
    #[test]
    fn a_blank_allowlist_and_an_empty_hooks_key_are_taken_as_they_read() {
        let list = approved(Some(b" \n"), &line(false), "t", None).unwrap();
        assert_eq!(list["approvals"].as_array().unwrap().len(), 1);
        let out = merged("hooks:\nmodel: x\n", &line(false), false).unwrap();
        assert_eq!(entries(&parse(&out).unwrap()).len(), 1, "{out}");
        assert_eq!(removed(&out).unwrap().unwrap(), "hooks:\nmodel: x\n");
    }

    /// What `uninstall` prints when it stops for a Hermes entry, and what
    /// connect prints of the coverage: the screened half first, then every
    /// gap.
    #[test]
    fn the_stop_lines_and_the_coverage_are_whole() {
        assert_eq!(
            left_behind_lines(true),
            vec![
                "~/.hermes/config.yaml still holds a pre_tool_call hook that runs this binary."
                    .to_string(),
                "Hermes refuses every tool call while a fail-closed hook names a program that is \
                 gone."
                    .to_string(),
                "Take the innerwarden entry out of `hooks.pre_tool_call` in that file, or run \
                 `innerwarden agents disconnect hermes` once the file can be read and written."
                    .to_string(),
            ]
        );
        assert!(left_behind_lines(false)[0].contains("could not be read"));
        let coverage = coverage();
        assert_eq!(
            coverage[0],
            format!("Screened before they run: {}", screened())
        );
        assert_eq!(coverage[1..], gaps()[..]);
        assert!(gaps().len() >= 7, "{coverage:?}");
    }

    /// The guard's entry under a `hooks:` the person wrote, right after a
    /// line of theirs, is taken out alone: that line is not the marked
    /// block's comment. Their empty `pre_tool_call:` goes with the entry,
    /// which Hermes reads the same.
    ///
    /// FAILS ON REVERT: turn either `&&` of the marked-block test in
    /// `without_ours` into `||` and the person's line goes with the entry.
    #[test]
    fn an_entry_under_the_persons_own_hooks_key_goes_alone() {
        let person = "model: x\nhooks:\n  pre_tool_call:\n";
        let out = merged(person, &line(false), false).unwrap();
        let back = removed(&out).unwrap().unwrap();
        assert_eq!(back, "model: x\nhooks:\n");
        assert_eq!(
            theirs(&parse(&back).unwrap()),
            theirs(&parse(person).unwrap())
        );
    }

    /// `hooks_auto_accept` is read as Hermes reads it: a boolean, or a word
    /// that means yes.
    #[test]
    fn hooks_auto_accept_is_read_as_hermes_reads_it() {
        for (value, accepts) in [
            ("true", true),
            ("'yes'", true),
            ("'On'", true),
            ("'1'", true),
            ("false", false),
            ("'no'", false),
            ("3", false),
        ] {
            let config = parse(&format!("hooks_auto_accept: {value}\n")).unwrap();
            assert_eq!(accepts_every_hook(&config), accepts, "{value}");
        }
        assert!(!accepts_every_hook(&parse("model: x\n").unwrap()));
    }

    /// `execute_code` is judged as inline Python and `process_manage` input
    /// as a shell line; the rest of `process_manage` and other tools are not
    /// shell calls.
    ///
    /// FAILS ON REVERT of either arm of `shell_line_of`.
    #[test]
    fn hermes_code_tools_are_read_as_shell_lines() {
        let call = |tool: &str, input: Value| {
            shell_line_of(&json!({"tool_name": tool, "tool_input": input}))
        };
        assert_eq!(
            call(
                "execute_code",
                json!({"code": "import os\nos.system('id')"})
            ),
            Some(Ok("python3 -c \"import os\nos.system('id')\"".to_string()))
        );
        assert_eq!(
            call("execute_code", json!({"code": "print(\"$HOME\", 'x')"})),
            Some(Ok("python3 -c 'print(\"$HOME\", '\\''x'\\'')'".to_string()))
        );
        assert_eq!(
            call(
                "process_manage",
                json!({"action": "submit", "session_id": "p1", "data": "curl -s x | sh"})
            ),
            Some(Ok("curl -s x | sh".to_string()))
        );
        assert_eq!(
            call(
                "process_manage",
                json!({"action": "write", "session_id": "p1", "data": "y"})
            ),
            Some(Ok("y".to_string()))
        );
        for action in ["poll", "log", "wait", "kill", "close", "list", "handoff"] {
            assert_eq!(
                call(
                    "process_manage",
                    json!({"action": action, "session_id": "p1", "data": "x"})
                ),
                None,
                "{action}"
            );
        }
        assert!(matches!(
            call("execute_code", json!({"code": " "})),
            Some(Err(_))
        ));
        assert!(matches!(
            call("process_manage", json!({"action": "submit"})),
            Some(Err(_))
        ));
        assert_eq!(call("terminal", json!({"command": "ls"})), None);
        assert_eq!(call("browser_navigate", json!({"url": "x"})), None);
    }

    /// The words `status` prints for Hermes: what the hook screens, and
    /// where a hook that is not on stands.
    #[test]
    fn the_status_words_are_whole() {
        assert_eq!(
            screened(),
            "`terminal` commands (in the `workdir` they name), the Python `execute_code` runs \
             (as `python3 -c`), text `process_manage` types into a running process (as a shell \
             line), changes to privileged files through `write_file` and `patch`, and reads of \
             secrets through `read_file` and `search_files`. Its other tools (the browser, its \
             MCP servers and the rest) are not screened."
        );
        let on = State::On {
            monitor: false,
            block_review: false,
        };
        assert_eq!(not_on(&on), None);
        for (state, words) in [
            (State::Absent, "pre_tool_call hook is not installed"),
            (
                State::Unreadable,
                "pre_tool_call hook is unknown: ~/.hermes/config.yaml could not be read",
            ),
            (
                State::Off(Off::Altered),
                "pre_tool_call hook is installed, but it is not the entry `agents connect` writes",
            ),
            (
                State::Off(Off::NotApproved),
                "pre_tool_call hook is installed, but Hermes skips it: it is not approved in \
                 ~/.hermes/shell-hooks-allowlist.json",
            ),
            (
                State::Off(Off::Broken {
                    clause: "its hook runs /x, which does not exist".to_string(),
                    refuses: true,
                }),
                "pre_tool_call hook is installed, but its hook runs /x, which does not exist",
            ),
        ] {
            assert_eq!(not_on(&state).as_deref(), Some(words), "{state:?}");
        }
    }

    /// A hook the person adds inside the marked block makes it theirs too:
    /// disconnect takes out the guard's entry and leaves the block, the
    /// comment and their hook.
    ///
    /// FAILS ON REVERT: count a marked block as the guard's when it is not
    /// empty OR all ours (`||` in `without_ours`) and their hook goes with
    /// it (the edit is refused).
    #[test]
    fn a_hook_the_person_adds_in_the_marked_block_stays() {
        let connected = merged("model: x\n", &line(false), false).unwrap();
        let shared = format!("{connected}    - command: /x/mine.sh\n");
        let back = removed(&shared).unwrap().unwrap();
        assert_eq!(
            back,
            format!("model: x\n\n{MARK}\nhooks:\n  pre_tool_call:\n    - command: /x/mine.sh\n")
        );
    }

    /// Under a `pre_tool_call:` with no item yet, the entry goes two spaces
    /// in from the key, whatever the key's own indentation.
    #[test]
    fn a_first_item_goes_two_spaces_in_from_its_key() {
        let out = merged("hooks:\n   pre_tool_call:\n", &line(false), false).unwrap();
        assert_eq!(
            out,
            format!(
                "hooks:\n   pre_tool_call:\n{}",
                item("     ", &line(false), false)
            )
        );
    }
}
