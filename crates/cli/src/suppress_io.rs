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

fn save(cfg: &SuppressConfig) -> Result<(), String> {
    let path =
        config_path().ok_or("cannot resolve a config path (set IW_SUPPRESS_CONFIG or HOME)")?;
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&path, cfg.to_toml()).map_err(|e| format!("writing {}: {e}", path.display()))
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
