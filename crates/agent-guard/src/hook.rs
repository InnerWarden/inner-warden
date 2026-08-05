//! `innerwarden install claude-code` - wire the guardrail into Claude Code as a
//! fail-closed PreToolUse:Bash hook, in ONE command, offline.
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
    // `monitor` wins: it records every command but never blocks, so a dev gets the
    // live graph without the guardrail denying day-to-day work.
    let flag = if monitor {
        " --monitor"
    } else if block_review {
        " --block-review"
    } else {
        ""
    };
    format!("\"{}\" hook{flag}", iw_guard.display())
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
    if agent != "claude-code" {
        if let Some(target) = crate::hook_targets::by_id(agent) {
            return Err(format!(
                "{} does not expose a hook this can install into.\n  {}",
                target.display,
                crate::hook_targets::guidance(target)
            ));
        }
        return Err(format!(
            "unknown agent '{agent}'. Known: {}",
            crate::hook_targets::known_ids()
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
    let cmd = hook_command(iw_guard, block_review, monitor);
    let merged = merge_pretooluse_bash_hook(existing.clone(), &cmd);
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
    hook.get("command")
        .and_then(Value::as_str)
        .and_then(hook_command_words)
        .and_then(|words| match words.as_slice() {
            [executable, subcommand]
                if is_innerwarden_executable(executable) && subcommand == "hook" =>
            {
                Some(HookProtection::Enforce)
            }
            [executable, subcommand, flag]
                if is_innerwarden_executable(executable) && subcommand == "hook" =>
            {
                match flag.as_str() {
                    "--monitor" => Some(HookProtection::Monitor),
                    "--block-review" => Some(HookProtection::BlockReview),
                    _ => None,
                }
            }
            _ => None,
        })
}

fn is_iwguard_hook(hook: &Value) -> bool {
    iwguard_hook_mode(hook).is_some()
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
    if matcher.split('|').any(|candidate| candidate == "Bash") {
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
    let command = hook_command(iw_guard, block_review, monitor);
    merge_pretooluse_bash_hook(settings.clone(), &command) != *settings
}

/// Remove every innerwarden PreToolUse Bash hook entry from a settings object,
/// preserving all other keys, hook types, and unrelated PreToolUse entries.
/// Returns `(new_settings, removed_count)`. Idempotent: a second call removes 0.
pub fn remove_iwguard_pretooluse_hook(mut settings: Value) -> (Value, usize) {
    let Some(pre) = settings
        .get_mut("hooks")
        .and_then(|h| h.get_mut("PreToolUse"))
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
/// settings, strips innerwarden's PreToolUse hook, and writes back only if something
/// changed. A missing/empty settings file means nothing to remove (0), not an
/// error, so `uninstall` is always safe to run.
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
    if removed > 0 {
        let body = serde_json::to_string_pretty(&cleaned).map_err(|e| e.to_string())? + "\n";
        crate::file_update::replace_if_unchanged(&settings_path, Some(&source), body.as_bytes())?;
    }
    Ok((settings_path, removed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_into_empty_adds_bash_hook() {
        let out = merge_pretooluse_bash_hook(json!({}), "\"/p/innerwarden\" hook");
        let entry = &out["hooks"]["PreToolUse"][0];
        assert_eq!(entry["matcher"], "Bash");
        assert_eq!(entry["hooks"][0]["type"], "command");
        assert_eq!(entry["hooks"][0]["command"], "\"/p/innerwarden\" hook");
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

    #[test]
    fn hook_command_quotes_path_and_wires_block_review() {
        let c = hook_command(Path::new("/usr/local/bin/innerwarden"), false, false);
        assert_eq!(c, "\"/usr/local/bin/innerwarden\" hook");
        let c2 = hook_command(Path::new("/x/innerwarden"), true, false);
        assert_eq!(c2, "\"/x/innerwarden\" hook --block-review");
        // monitor wins over block_review (records, never blocks).
        let c3 = hook_command(Path::new("/x/innerwarden"), true, true);
        assert_eq!(c3, "\"/x/innerwarden\" hook --monitor");
        let c4 = hook_command(Path::new("/x/innerwarden"), false, true);
        assert_eq!(c4, "\"/x/innerwarden\" hook --monitor");
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
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "\"/opt/innerwarden\" hook --block-review"
        );

        // Idempotent.
        install_hook(home.path(), "claude-code", None, iw, true, false).unwrap();
        let v2: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v2["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
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
            "\"/opt/innerwarden\" hook --monitor"
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
            err.contains("relays"),
            "and must explain why a hook is not the mechanism: {err}"
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
            "\"/current/target/release/innerwarden\" hook --block-review"
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
        assert_eq!(removed, 1);
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(v["hooks"]["PreToolUse"].as_array().unwrap().len(), 0);

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
            1,
            "reinstall must not stack a second hook"
        );
        // uninstall finds and removes it.
        let (_, removed) = uninstall_hook(home.path(), "claude-code", None).unwrap();
        assert_eq!(removed, 1);
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
