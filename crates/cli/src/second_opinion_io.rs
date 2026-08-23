//! Thin I/O boundary for the LLM second opinion (config read + HTTP POST).
//!
//! All the decision logic lives in the pure, unit-tested `second_opinion` module;
//! this file only reads the optional config and POSTs to the user's endpoint. It
//! is excluded from the coverage floor like the other thin adapters.

use serde_json::Value;

use crate::second_opinion::{
    apply_second_opinion, build_body, needs_second_opinion, parse_reply, LlmConfig,
};

// ---- I/O boundary (config read + HTTP POST). Excluded from the coverage floor
// like the other thin adapters; the decision logic above is what is unit-tested.

/// The optional LLM config path: env `IW_LLM_CONFIG`, else
/// `~/.config/innerwarden/llm.toml` (beside the notify + graph config).
fn config_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("IW_LLM_CONFIG") {
        if !p.trim().is_empty() {
            return Some(std::path::PathBuf::from(p));
        }
    }
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.trim().is_empty())
        .map(|h| std::path::PathBuf::from(h).join(".config/innerwarden/llm.toml"))
}

fn load_config() -> Option<LlmConfig> {
    let s = std::fs::read_to_string(config_path()?).ok()?;
    LlmConfig::from_toml(&s)
}

/// Whether a usable second-opinion endpoint is already configured. Requires a
/// VALID http(s) URL, so a broken config where the API key was pasted into the URL
/// field (`url = "sk-..."`) counts as NOT configured and a re-run of `setup` fixes
/// it instead of reporting "already set".
pub fn is_configured() -> bool {
    load_config().map(|c| c.has_valid_url()).unwrap_or(false)
}

/// Whether the configured endpoint currently has a usable API key (env or file).
/// Used by the wizard: a configured-but-keyless endpoint should let the user paste
/// the key on a re-run instead of silently reporting "already set".
pub fn has_key() -> bool {
    load_config()
        .map(|c| {
            c.resolve_key(|k| std::env::var(k).ok(), read_key_file)
                .is_some()
        })
        .unwrap_or(false)
}

/// POST the classification request to the user's endpoint. Best-effort: any error
/// (no key, network, bad status) returns `None` so the caller keeps the `review`.
fn call_llm(cfg: &LlmConfig, command: &str) -> Option<Value> {
    // The command LEAVES THE HOST here (off-box to the user's LLM endpoint). Redact
    // secrets first so a screened command that embeds a credential never reaches the
    // model; the redacted form keeps the dangerous SHAPE, so the verdict is unaffected.
    let command = innerwarden_agent_guard::redact::redact_secrets(command).text;
    let body = build_body(&cfg.model, &command);
    let mut req = crate::http_io::agent_with_timeout(std::time::Duration::from_secs(20))
        .post(&cfg.url)
        .header("Content-Type", "application/json");
    // Key precedence: the named env var (zero key-at-rest) first, then the 0600
    // key file the wizard / `llm set-key` wrote. Resolved off-thread of the config.
    if let Some(key) = cfg.resolve_key(|k| std::env::var(k).ok(), read_key_file) {
        req = if cfg.is_azure() {
            req.header("api-key", &key)
        } else {
            req.header("Authorization", &format!("Bearer {key}"))
        };
    }
    let resp = req.send_json(body).ok()?;
    resp.into_body().read_json::<Value>().ok()
}

/// Expand a leading `~/` to `$HOME`, then read the file (trimmed by the caller).
/// Used to resolve `api_key_file`. Returns `None` on any error (missing/unreadable).
fn read_key_file(path: &str) -> Option<String> {
    let expanded = if let Some(rest) = path.strip_prefix("~/") {
        match std::env::var("HOME") {
            Ok(home) => format!("{home}/{rest}"),
            Err(_) => path.to_string(),
        }
    } else {
        path.to_string()
    };
    std::fs::read_to_string(expanded).ok()
}

/// The default key-file path the wizard / `set-key` writes: a 0600 file beside the
/// llm config (`~/.config/innerwarden/llm-key`). The config stores this PATH, never
/// the key. Returns `None` when no HOME (and no `IW_LLM_CONFIG` dir) is resolvable.
pub fn default_key_path() -> Option<std::path::PathBuf> {
    config_path().and_then(|c| c.parent().map(|d| d.join("llm-key")))
}

/// True on platforms where `store_key` can enforce owner-only (0600) permissions
/// at create time (unix). On others the key file inherits the default ACL and the
/// user must restrict it themselves - the messaging stays honest about that.
pub const KEY_PERMS_ENFORCED: bool = cfg!(unix);

/// Write `key` to the default key file, OWNER-READABLE ONLY, and return its
/// absolute path (to store in `api_key_file`). The secret is created with 0600
/// FROM THE START (never a world-readable window), a pre-existing file/symlink is
/// removed first so a planted link cannot be followed, and any partial write is
/// unlinked so a secret is never left at loose perms. Creates + tightens the parent
/// dir to 0700 (best-effort). 0600 is enforced on unix; see `KEY_PERMS_ENFORCED`.
pub fn store_key(key: &str) -> std::io::Result<std::path::PathBuf> {
    let path = default_key_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot resolve a key-file path (set IW_LLM_CONFIG or HOME)",
        )
    })?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Best-effort: keep the config dir owner-only too.
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    // Drop any pre-existing file/symlink so O_EXCL below cannot follow a planted
    // link (and so a stale 0644 file is never reused).
    let _ = std::fs::remove_file(&path);

    let write = || -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            // O_CREAT|O_EXCL|O_WRONLY, mode 0600 - owner-only from the first byte.
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            f.write_all(format!("{}\n", key.trim()).as_bytes())?;
            f.flush()
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&path, format!("{}\n", key.trim()))
        }
    };
    if let Err(e) = write() {
        // Never leave a secret behind at unknown perms if anything failed.
        let _ = std::fs::remove_file(&path);
        return Err(e);
    }
    Ok(path)
}

/// A one-shot validation of the configured endpoint: send a trivial classification
/// request and report what happened, so the wizard can tell the user the key +
/// model + URL actually WORK instead of a silent "configured". `Ok` = the endpoint
/// answered (2xx); `Err(msg)` carries a human reason (bad key, model not found,
/// unreachable). Best-effort: a slow endpoint just times out into an Err.
pub fn verify_endpoint(cfg: &LlmConfig) -> Result<(), String> {
    let body = build_body(&cfg.model, "echo hello");
    let mut req = crate::http_io::agent_with_timeout(std::time::Duration::from_secs(12))
        .post(&cfg.url)
        .header("Content-Type", "application/json");
    if let Some(key) = cfg.resolve_key(|k| std::env::var(k).ok(), read_key_file) {
        req = if cfg.is_azure() {
            req.header("api-key", &key)
        } else {
            req.header("Authorization", &format!("Bearer {key}"))
        };
    }
    match req.send_json(body) {
        Ok(_) => Ok(()),
        // Matched on the STATUS rather than on ureq's variants: the enum grew
        // from two arms to ten in ureq 3, and an exhaustive list would keep
        // compiling while quietly losing cases.
        Err(e) => match crate::http_io::status_of(&e) {
            Some(401) | Some(403) => {
                Err("the API key was rejected (401/403) - check the key".into())
            }
            Some(404) => Err(format!(
                "model / deployment \"{}\" not found (404) - check the model name",
                cfg.model
            )),
            Some(code) => Err(format!("endpoint returned HTTP {code}")),
            None => Err(format!("could not reach {} ({e})", cfg.url)),
        },
    }
}

/// The full second-opinion flow: only for `review`, only when the user configured
/// an endpoint. Returns an overriding verdict (`decided_by = llm`) or `None` to
/// keep the rules verdict (which then escalates to a human via notify).
pub fn consider(command: &str, rules_verdict: &Value) -> Option<Value> {
    // No configured endpoint = never escalate (the common case; zero cost, fast).
    let cfg = load_config()?;
    // Escalate only when it is worth the spend: an ambiguous command with real
    // harm potential (review + risk >= the configured floor).
    if !needs_second_opinion(rules_verdict, cfg.effective_min_risk()) {
        return None;
    }
    let resp = call_llm(&cfg, command)?;
    let (verdict, why) = parse_reply(&resp)?;
    Some(apply_second_opinion(rules_verdict, &verdict, &why))
}

/// Persist the llm config to `config_path()`. Shared by `set`, `set-key`, and the
/// setup wizard so there is one writer. Returns the path or an error string.
pub fn write_config(cfg: &LlmConfig) -> Result<std::path::PathBuf, String> {
    let path = config_path()
        .ok_or_else(|| "cannot resolve a config path (set IW_LLM_CONFIG or HOME)".to_string())?;
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let body = toml::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    std::fs::write(&path, body).map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    Ok(path)
}

/// A one-line, secret-free description of where the API key comes from, honouring
/// the env-first precedence. Never prints the key itself.
fn key_status(c: &LlmConfig) -> String {
    if let Some(e) = &c.api_key_env {
        let ok = std::env::var(e)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        return format!("env var {e} ({})", if ok { "set" } else { "MISSING" });
    }
    if let Some(f) = &c.api_key_file {
        let ok = read_key_file(f)
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        return format!("file {f} ({})", if ok { "present" } else { "MISSING" });
    }
    "none (local endpoint, or run `innerwarden llm set-key`)".to_string()
}

/// Read the API key for `set-key`: from stdin when piped or `--stdin`, else a
/// HIDDEN terminal prompt (never echoed, never in shell history).
fn read_key_input(rest: &[String]) -> String {
    let piped =
        rest.iter().any(|a| a == "--stdin") || !std::io::IsTerminal::is_terminal(&std::io::stdin());
    if piped {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut std::io::stdin(), &mut s);
        s.trim().to_string()
    } else {
        dialoguer::Password::new()
            .with_prompt("  Paste your API key (hidden)")
            .allow_empty_password(true)
            .interact()
            .unwrap_or_default()
    }
}

/// `innerwarden llm [set --url U --model M [--provider azure] [--key-env NAME]
/// [--key-file PATH] | set-key [--stdin] | status]` - configure or show the
/// optional second-opinion endpoint. Thin I/O.
pub fn cmd(rest: &[String]) -> std::process::ExitCode {
    match rest.first().map(String::as_str) {
        Some("set") => {
            let mut cfg = load_config().unwrap_or_default();
            let mut it = rest[1..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--url" => cfg.url = it.next().cloned().unwrap_or_default(),
                    "--model" => cfg.model = it.next().cloned().unwrap_or_default(),
                    "--provider" => cfg.provider = it.next().cloned().unwrap_or_default(),
                    "--key-env" => cfg.api_key_env = it.next().cloned(),
                    "--key-file" => cfg.api_key_file = it.next().cloned(),
                    "--min-risk" => cfg.min_risk = it.next().and_then(|v| v.parse().ok()),
                    other => {
                        eprintln!("innerwarden llm set: unknown flag `{other}`");
                        return std::process::ExitCode::from(2);
                    }
                }
            }
            if cfg.url.trim().is_empty() || cfg.model.trim().is_empty() {
                eprintln!("innerwarden llm set: --url and --model are required");
                return std::process::ExitCode::from(2);
            }
            match write_config(&cfg) {
                Ok(_) => {
                    println!("innerwarden llm - saved. A second opinion from {} ({}) is used ONLY for an ambiguous command with risk >= {} (deny/allow are never escalated).", cfg.model, cfg.url, cfg.effective_min_risk());
                    if cfg.api_key_env.is_none() && cfg.api_key_file.is_none() {
                        println!("  note: no API key set (fine for a local endpoint like Ollama; a cloud API needs one - run `innerwarden llm set-key`).");
                    }
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("innerwarden llm set: {e}");
                    std::process::ExitCode::from(1)
                }
            }
        }
        Some("set-key") => {
            let Some(mut cfg) = load_config() else {
                eprintln!("innerwarden llm set-key: configure the endpoint first - `innerwarden llm set --url <URL> --model <M>` (or run `innerwarden setup`).");
                return std::process::ExitCode::from(2);
            };
            let key = read_key_input(rest);
            if key.trim().is_empty() {
                eprintln!("innerwarden llm set-key: no key provided");
                return std::process::ExitCode::from(2);
            }
            let path = match store_key(&key) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("innerwarden llm set-key: {e}");
                    return std::process::ExitCode::from(1);
                }
            };
            cfg.api_key_file = Some(path.display().to_string());
            match write_config(&cfg) {
                Ok(_) => {
                    let perms = if KEY_PERMS_ENFORCED {
                        "0600 - only you can read it"
                    } else {
                        "on disk - restrict its file permissions yourself on this OS"
                    };
                    println!(
                        "innerwarden llm - key stored ({perms}) at {} and referenced by the config; the key is never printed. A second opinion now fires on ambiguous commands.",
                        path.display()
                    );
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("innerwarden llm set-key: {e}");
                    std::process::ExitCode::from(1)
                }
            }
        }
        _ => {
            match load_config() {
                Some(c) => {
                    println!("innerwarden llm - configured: {} via {}\n  api key: {}\n  escalates only: review + risk >= {} (deny/allow never escalate)", c.model, c.url, key_status(&c), c.effective_min_risk());
                }
                None => println!(
                    "innerwarden llm - not configured. Ambiguous commands escalate to a human.\n  set one: innerwarden llm set --url <chat-completions-URL> --model <name> [--provider azure], then innerwarden llm set-key"
                ),
            }
            std::process::ExitCode::SUCCESS
        }
    }
}
