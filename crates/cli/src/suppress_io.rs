//! Thin I/O for user suppression: read/write the config and run `innerwarden allow` /
//! `innerwarden mute`. All decision logic lives in the pure, tested `suppress` module.
//! Excluded from the coverage floor like the other adapters.

use serde_json::Value;

use crate::suppress::{apply, SuppressConfig};

/// The suppression config path: env `IW_SUPPRESS_CONFIG`, else
/// `~/.config/innerwarden/suppress.toml`.
fn config_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("IW_SUPPRESS_CONFIG") {
        if !p.trim().is_empty() {
            return Some(std::path::PathBuf::from(p));
        }
    }
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .map(|h| std::path::PathBuf::from(h).join(".config/innerwarden/suppress.toml"))
}

fn load() -> SuppressConfig {
    config_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| SuppressConfig::from_toml(&s))
        .unwrap_or_default()
}

/// Write the config, and report what changed to the guard event stream.
///
/// The reporting lives HERE, not in the `cmd_*` handlers, so it cannot be
/// forgotten by a future subcommand: every mutation reaches disk through this
/// function, so every mutation is recorded. Turning a guard off is a security
/// event; it was previously the only thing the guard did silently.
fn save(cfg: &SuppressConfig) -> Result<(), String> {
    let path =
        config_path().ok_or("cannot resolve a config path (set IW_SUPPRESS_CONFIG or HOME)")?;
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let before = load();
    std::fs::write(&path, cfg.to_toml()).map_err(|e| format!("writing {}: {e}", path.display()))?;
    for (action, pattern) in suppression_delta(&before, cfg) {
        crate::graph_io::record_suppression_change(action, &pattern, counts(cfg));
    }
    Ok(())
}

fn counts(cfg: &SuppressConfig) -> (usize, usize, usize) {
    (
        cfg.allow.len(),
        cfg.mute_rules.len(),
        cfg.mute_categories.len(),
    )
}

/// Every add and removal between two configs, as `(action, pattern)`.
///
/// Removals are reported too: narrowing a suppression is not dangerous, but an
/// event stream that shows only the additions cannot be used to reconstruct what
/// was actually in force at a given moment.
fn suppression_delta(
    before: &SuppressConfig,
    after: &SuppressConfig,
) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let pairs: [(&str, &Vec<String>, &Vec<String>); 3] = [
        ("allow", &before.allow, &after.allow),
        ("mute_rule", &before.mute_rules, &after.mute_rules),
        (
            "mute_category",
            &before.mute_categories,
            &after.mute_categories,
        ),
    ];
    for (label, old, new) in pairs {
        for added in new.iter().filter(|v| !old.contains(v)) {
            out.push((
                match label {
                    "allow" => "allow_added",
                    "mute_rule" => "mute_rule_added",
                    _ => "mute_category_added",
                },
                added.clone(),
            ));
        }
        for removed in old.iter().filter(|v| !new.contains(v)) {
            out.push((
                match label {
                    "allow" => "allow_removed",
                    "mute_rule" => "mute_rule_removed",
                    _ => "mute_category_removed",
                },
                removed.clone(),
            ));
        }
    }
    out
}

/// Apply user suppression to a rules verdict (best-effort). Returns an overriding
/// verdict when the command is allowed/muted, else `None`.
pub fn consider(command: &str, verdict: &Value) -> Option<Value> {
    apply(command, verdict, &load())
}

/// `innerwarden allow [<glob> | --list | --remove <glob>]` - force-allow a command
/// pattern the user trusts (the "stop bugging me about this" list).
pub fn cmd_allow(rest: &[String]) -> std::process::ExitCode {
    let mut cfg = load();
    match rest.first().map(String::as_str) {
        None | Some("--list") => {
            if cfg.allow.is_empty() {
                println!("innerwarden allow - no command patterns allowed. Add one: innerwarden allow \"<glob>\"");
            } else {
                println!("innerwarden allow - force-allowed command patterns:");
                for p in &cfg.allow {
                    println!("  {p}");
                }
            }
            std::process::ExitCode::SUCCESS
        }
        Some("--remove") => {
            let Some(pat) = rest.get(1) else {
                eprintln!("innerwarden allow --remove: needs a pattern");
                return std::process::ExitCode::from(2);
            };
            let before = cfg.allow.len();
            cfg.allow.retain(|p| p != pat);
            if cfg.allow.len() == before {
                println!("innerwarden allow - no such pattern: {pat}");
                return std::process::ExitCode::SUCCESS;
            }
            persist_or_fail(&cfg, &format!("removed allow: {pat}"))
        }
        Some(_) => {
            // Join so a multi-word pattern given without quotes still works.
            let pat = rest.join(" ");
            if cfg.allow.iter().any(|p| p == &pat) {
                println!("innerwarden allow - already allowed: {pat}");
                return std::process::ExitCode::SUCCESS;
            }
            cfg.allow.push(pat.clone());
            persist_or_fail(&cfg, &format!("commands matching \"{pat}\" now allowed"))
        }
    }
}

/// `innerwarden mute [<rule-id|category> | --list | --remove <x>]` - stop a specific
/// ATR rule or category from counting against a command.
pub fn cmd_mute(rest: &[String]) -> std::process::ExitCode {
    let mut cfg = load();
    let is_rule = |s: &str| s.to_ascii_uppercase().starts_with("ATR-");
    match rest.first().map(String::as_str) {
        None | Some("--list") => {
            if cfg.mute_rules.is_empty() && cfg.mute_categories.is_empty() {
                println!(
                    "innerwarden mute - nothing muted. Add: innerwarden mute <ATR-rule-id | category>"
                );
            } else {
                println!("innerwarden mute - muted:");
                for r in &cfg.mute_rules {
                    println!("  rule     {r}");
                }
                for c in &cfg.mute_categories {
                    println!("  category {c}");
                }
            }
            std::process::ExitCode::SUCCESS
        }
        Some("--remove") => {
            let Some(x) = rest.get(1) else {
                eprintln!("innerwarden mute --remove: needs a rule id or category");
                return std::process::ExitCode::from(2);
            };
            cfg.mute_rules.retain(|r| r != x);
            cfg.mute_categories.retain(|c| c != x);
            persist_or_fail(&cfg, &format!("unmuted: {x}"))
        }
        Some(x) => {
            let target = if is_rule(x) {
                &mut cfg.mute_rules
            } else {
                &mut cfg.mute_categories
            };
            if target.iter().any(|e| e == x) {
                println!("innerwarden mute - already muted: {x}");
                return std::process::ExitCode::SUCCESS;
            }
            target.push(x.to_string());
            persist_or_fail(&cfg, &format!("muted: {x}"))
        }
    }
}

fn persist_or_fail(cfg: &SuppressConfig, ok_msg: &str) -> std::process::ExitCode {
    match save(cfg) {
        Ok(()) => {
            println!("innerwarden - {ok_msg}");
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("innerwarden: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(allow: &[&str], rules: &[&str], cats: &[&str]) -> SuppressConfig {
        SuppressConfig {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            mute_rules: rules.iter().map(|s| s.to_string()).collect(),
            mute_categories: cats.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Turning a guard off is a security event. This is the one the guard used to
    /// perform in silence: `guard.blocked` recorded every refusal and nothing
    /// recorded the refusals being switched off.
    #[test]
    fn adding_an_allow_is_reported() {
        let delta = suppression_delta(&cfg(&[], &[], &[]), &cfg(&["rm -rf *"], &[], &[]));
        assert_eq!(delta, vec![("allow_added", "rm -rf *".to_string())]);
    }

    #[test]
    fn every_kind_of_suppression_is_reported() {
        let delta = suppression_delta(
            &cfg(&[], &[], &[]),
            &cfg(&["a"], &["ATR-001"], &["exfiltration"]),
        );
        let actions: Vec<&str> = delta.iter().map(|(a, _)| *a).collect();
        assert_eq!(
            actions,
            vec!["allow_added", "mute_rule_added", "mute_category_added"]
        );
    }

    /// Removals are recorded too. An event stream carrying only additions cannot
    /// reconstruct what was in force at a given moment.
    #[test]
    fn removing_a_suppression_is_reported() {
        let delta = suppression_delta(&cfg(&["a", "b"], &[], &[]), &cfg(&["a"], &[], &[]));
        assert_eq!(delta, vec![("allow_removed", "b".to_string())]);
    }

    /// `innerwarden allow --list` writes nothing, so it must report nothing: a
    /// stream that fires on reads trains its reader to ignore it.
    #[test]
    fn an_unchanged_config_reports_nothing() {
        let same = cfg(&["a"], &["ATR-001"], &["x"]);
        assert!(suppression_delta(&same, &same).is_empty());
    }

    #[test]
    fn counts_travel_with_the_event_so_a_reader_sees_the_resulting_posture() {
        assert_eq!(counts(&cfg(&["a", "b"], &["ATR-1"], &[])), (2, 1, 0));
    }
}
