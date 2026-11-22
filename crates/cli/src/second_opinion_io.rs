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

/// Where the LLM config is read from, and whether it is the account's own.
struct ConfigAt {
    path: std::path::PathBuf,
    /// The account's own `llm.toml` (under the home the account database
    /// gives, [`crate::graph_io::config_home`]), not one the override names.
    /// Only the account's own may name an environment variable to send as the
    /// key: an override is chosen by whoever starts the process, an AI agent
    /// included, and one naming `AWS_SECRET_ACCESS_KEY` sent it to its url.
    account: bool,
}

/// The optional LLM config: env `IW_LLM_CONFIG` (the tests, and the jail,
/// which points it at `/dev/null`), else `.config/innerwarden/llm.toml` in
/// the account's own home. Never `HOME`: `HOME=<dir> innerwarden check ...`
/// read the `llm.toml` in `<dir>` and sent the key file it named to the url
/// it named.
fn config_at() -> Option<ConfigAt> {
    if let Ok(p) = std::env::var("IW_LLM_CONFIG") {
        if !p.trim().is_empty() {
            return Some(ConfigAt {
                path: std::path::PathBuf::from(p),
                account: false,
            });
        }
    }
    crate::graph_io::account_config_dir().map(|dir| ConfigAt {
        path: dir.join("llm.toml"),
        account: true,
    })
}

fn config_path() -> Option<std::path::PathBuf> {
    config_at().map(|at| at.path)
}

/// The key for `cfg`, read as the config's place allows: the environment
/// variable it names only when it is the account's own config, the key file
/// only from inside the config's folder ([`read_key_file`]).
fn resolve_key(cfg: &LlmConfig) -> Option<String> {
    let at = config_at()?;
    cfg.resolve_key(
        |name| {
            if at.account {
                std::env::var(name).ok()
            } else {
                None
            }
        },
        |path| read_key_file(path, &at.path).ok(),
    )
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

/// The provider of a usable second-opinion endpoint ("openai" when the config
/// names none), or `None` when none is configured. The name only: never the
/// URL, the model or anything about the key.
pub(crate) fn provider() -> Option<String> {
    load_config()
        .filter(|config| config.has_valid_url())
        .map(|config| {
            let provider = config.provider.trim();
            if provider.is_empty() {
                "openai".to_string()
            } else {
                provider.to_ascii_lowercase()
            }
        })
}

/// Whether the configured endpoint currently has a usable API key (env or file).
/// Used by the wizard: a configured-but-keyless endpoint should let the user paste
/// the key on a re-run instead of silently reporting "already set".
pub fn has_key() -> bool {
    load_config()
        .map(|c| resolve_key(&c).is_some())
        .unwrap_or(false)
}

/// How long the user's endpoint has to answer one classification request.
/// The hook's deadline moves by this much for that one wait, so the timeout an
/// agent is given for the hook has to be longer than the two together.
pub(crate) const LLM_ANSWER_BOUND: std::time::Duration = std::time::Duration::from_secs(20);

/// POST the classification request to the user's endpoint. Best-effort: any error
/// (no key, network, bad status) returns `None` so the caller keeps the `review`.
fn call_llm(cfg: &LlmConfig, command: &str) -> Option<Value> {
    // The command LEAVES THE HOST here (off-box to the user's LLM endpoint). Redact
    // secrets first so a screened command that embeds a credential never reaches the
    // model; the redacted form keeps the dangerous SHAPE, so the verdict is unaffected.
    let command = innerwarden_agent_guard::redact::redact_secrets(command).text;
    let body = build_body(&cfg.model, &command);
    // The hook's deadline does not count a wait this call bounds itself, up
    // to one model's answer a run, counted by the time really waited. With
    // nothing left the call keeps its review rather than be refused by the
    // deadline while it waits; with less than the bound left, that is the
    // timeout.
    let timeout = crate::hook_net::grant_wait(LLM_ANSWER_BOUND)?;
    let started = std::time::Instant::now();
    let reply = (|| {
        let mut req = crate::http_io::agent_with_timeout(timeout)
            .post(&cfg.url)
            .header("Content-Type", "application/json");
        // Key precedence: the named env var (zero key-at-rest) first, then the 0600
        // key file the wizard / `llm set-key` wrote. Resolved off-thread of the config.
        if let Some(key) = resolve_key(cfg) {
            req = if cfg.is_azure() {
                req.header("api-key", &key)
            } else {
                req.header("Authorization", &format!("Bearer {key}"))
            };
        }
        let resp = req.send_json(body).ok()?;
        resp.into_body().read_json::<Value>().ok()
    })();
    crate::hook_net::waited(timeout, started.elapsed());
    reply
}

/// Read `api_key_file` (trimmed by the caller), or say why not. A leading
/// `~/` is the account's own home ([`crate::graph_io::config_home`]), never
/// `HOME`; a relative path is from the config's folder.
///
/// Only a key the person stored beside the config is read: a regular file
/// inside the folder of `config`, not a symbolic link and, on Unix, with no
/// other name (a hard link to a private key elsewhere is that key). Anything
/// else is refused: a config naming `~/.ssh/id_ed25519` sent that file as
/// `Authorization: Bearer` to the url it named.
fn read_key_file(path: &str, config: &std::path::Path) -> Result<String, String> {
    use std::io::Read;
    let folder = match config.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    let named = match path.strip_prefix("~/") {
        Some(rest) => crate::graph_io::config_home()
            .ok_or("this account has no home to expand ~/ in")?
            .join(rest),
        None => std::path::PathBuf::from(path),
    };
    let named = if named.is_relative() {
        folder.join(named)
    } else {
        named
    };
    let real_folder =
        std::fs::canonicalize(&folder).map_err(|_| "the config's folder is missing".to_string())?;
    let real = std::fs::canonicalize(&named).map_err(|_| "missing".to_string())?;
    if !real.starts_with(&real_folder) {
        return Err(format!(
            "outside the config's folder {}",
            real_folder.display()
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&named)
        .map_err(|_| "unreadable, or a symbolic link".to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err("a hard link: the file has another name".into());
        }
    }
    let mut key = String::new();
    file.read_to_string(&mut key).map_err(|e| e.to_string())?;
    Ok(key)
}

/// The default key-file path the wizard / `set-key` writes: a 0600 file beside the
/// llm config (`~/.config/innerwarden/llm-key`). The config stores this PATH, never
/// the key. Returns `None` when the account has no home (and no `IW_LLM_CONFIG`).
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
            "cannot resolve a key-file path (this account has no home; set IW_LLM_CONFIG)",
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
    if let Some(key) = resolve_key(cfg) {
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
    let path = config_path().ok_or_else(|| {
        "cannot resolve a config path (this account has no home; set IW_LLM_CONFIG)".to_string()
    })?;
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
    let at = config_at();
    let account = at.as_ref().is_some_and(|at| at.account);
    let mut said = Vec::new();
    if let Some(e) = &c.api_key_env {
        if !account {
            said.push(format!(
                "env var {e} (not read: only the llm.toml in your account's home may name one)"
            ));
        } else {
            let ok = std::env::var(e)
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
            if ok {
                return format!("env var {e} (set)");
            }
            said.push(format!("env var {e} (MISSING)"));
        }
    }
    if let Some(f) = &c.api_key_file {
        let read = match &at {
            Some(at) => read_key_file(f, &at.path),
            None => Err("no config path".into()),
        };
        said.push(match read {
            Ok(v) if !v.trim().is_empty() => format!("file {f} (present)"),
            Ok(_) => format!("file {f} (MISSING: empty)"),
            Err(why) => format!("file {f} (not read: {why})"),
        });
    }
    if said.is_empty() {
        return "none (local endpoint, or run `innerwarden llm set-key`)".to_string();
    }
    said.join("; ")
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

/// `llm` takes subcommands, not flags; a leading flag is refused by name
/// instead of falling through to the status view (#223).
fn parse_llm_flags(rest: &[String]) -> Result<(), String> {
    match rest.first() {
        Some(a) if a.starts_with('-') => Err(format!(
            "unknown flag `{a}` for `llm`; use a subcommand (set, set-key, status)"
        )),
        _ => Ok(()),
    }
}

/// `innerwarden llm [set --url U --model M [--provider azure] [--key-env NAME]
/// [--key-file PATH] | set-key [--stdin] | status]` - configure or show the
/// optional second-opinion endpoint. Thin I/O.
pub fn cmd(rest: &[String]) -> std::process::ExitCode {
    if let Err(msg) = parse_llm_flags(rest) {
        eprintln!("innerwarden llm: {msg}");
        return std::process::ExitCode::from(2);
    }
    match rest.first().map(String::as_str) {
        Some("set") => {
            let mut cfg = load_config().unwrap_or_default();
            let mut key_file_given = false;
            let mut it = rest[1..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--url" => cfg.url = it.next().cloned().unwrap_or_default(),
                    "--model" => cfg.model = it.next().cloned().unwrap_or_default(),
                    "--provider" => cfg.provider = it.next().cloned().unwrap_or_default(),
                    "--key-env" => cfg.api_key_env = it.next().cloned(),
                    "--key-file" => {
                        cfg.api_key_file = it.next().cloned();
                        key_file_given = true;
                    }
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
            if let (true, Some(file), Some(config)) =
                (key_file_given, cfg.api_key_file.as_deref(), config_path())
            {
                if let Err(why) = read_key_file(file, &config) {
                    eprintln!("innerwarden llm set: --key-file {file} is not read: {why}. Only a key stored beside the config is sent; run `innerwarden llm set-key` to store it there.");
                    return std::process::ExitCode::from(2);
                }
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

#[cfg(test)]
mod flag_parse_tests {
    use super::*;

    #[test]
    fn llm_without_a_leading_flag_is_fine() {
        let none: Vec<String> = vec![];
        assert!(parse_llm_flags(&none).is_ok());
        let set = vec![
            "set".to_string(),
            "--url".to_string(),
            "http://x".to_string(),
        ];
        assert!(parse_llm_flags(&set).is_ok());
    }

    #[test]
    fn llm_refuses_a_leading_flag_by_name() {
        let bogus = vec!["--bogus".to_string()];
        let err = parse_llm_flags(&bogus).unwrap_err();
        assert!(
            err.contains("`--bogus`") && err.contains("subcommand") && err.contains("status"),
            "{err}"
        );
    }
}
