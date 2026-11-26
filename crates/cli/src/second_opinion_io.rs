//! Thin I/O boundary for the LLM second opinion (config read + HTTP POST).
//!
//! All the decision logic lives in the pure, unit-tested `second_opinion` module;
//! this file only reads the optional config and POSTs to the user's endpoint. It
//! is excluded from the coverage floor like the other thin adapters.

use serde_json::Value;

use crate::second_opinion::{
    apply_second_opinion, ask_at_once_or_again, build_body, needs_second_opinion, parse_reply,
    retry_after, Asked, LlmConfig,
};

// ---- I/O boundary (config read + HTTP POST). Excluded from the coverage floor
// like the other thin adapters; the decision logic above is what is unit-tested.

/// The override `IW_LLM_CONFIG` names, when it is honoured: `/dev/null`
/// (no second opinion, what the jail hands its hook) in every build, any
/// path in a debug build (the tests). A release build reads no other: the
/// hook runs with the AI agent's environment, and an `llm.toml` it named
/// sent every command the hook reviews to the url it named
/// ([`crate::graph_io::override_from_env`]).
fn override_path() -> Option<std::path::PathBuf> {
    crate::graph_io::override_from_env("IW_LLM_CONFIG")
}

/// The optional LLM config: the override `IW_LLM_CONFIG`, else
/// `.config/innerwarden/llm.toml` in the account's own home. Never `HOME`:
/// `HOME=<dir> innerwarden check ...` read the `llm.toml` in `<dir>` and sent
/// the key file it named to the url it named.
fn config_path() -> Option<std::path::PathBuf> {
    override_path()
        .or_else(|| crate::graph_io::account_config_dir().map(|dir| dir.join("llm.toml")))
}

/// The line `llm status` adds when `IW_LLM_CONFIG` is set and not read (a
/// release build, any value but `/dev/null`), so the person is not left
/// wondering why the config they named is not the one shown.
fn ignored_override_line() -> Option<&'static str> {
    let named = std::env::var("IW_LLM_CONFIG").ok()?;
    let named = named.trim();
    if named.is_empty()
        || crate::graph_io::honoured_override(
            Some(named),
            crate::graph_io::caller_overrides_honoured(),
        )
        .is_some()
    {
        return None;
    }
    Some("  not read: IW_LLM_CONFIG (a release build reads the second opinion's config only from your account's home, and the variable only as /dev/null, which turns it off: the hook runs with the AI agent's environment)")
}

/// Why a config the override names carries no key, said where a key is
/// asked of one.
const OVERRIDE_HAS_NO_KEY: &str = "IW_LLM_CONFIG names this config, and a config an override names never carries an API key: only the llm.toml in your account's home does";

/// Where the config in hand came from, and so where its key may come from.
enum Source {
    /// The account's own folder, opened once: `llm.toml` and the key file are
    /// both read through this one handle, by plain name, so the folder cannot
    /// be swapped between the two reads. The folder itself may be a link
    /// (dotfiles kept with stow).
    #[cfg(unix)]
    Account(std::fs::File),
    #[cfg(not(unix))]
    Account(std::path::PathBuf),
    /// The override `IW_LLM_CONFIG`: chosen by whoever starts the process, an
    /// AI agent included, so it never carries a key. An override naming
    /// `~/.config/innerwarden/llm-key` sent the account's stored key to the
    /// url it named.
    Override,
}

/// The config, with where it came from.
struct Loaded {
    cfg: LlmConfig,
    source: Source,
}

/// The account's own config folder, opened once ([`Source::Account`]).
fn open_account() -> Option<Source> {
    let dir = crate::graph_io::account_config_dir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&dir)
            .ok()
            .map(Source::Account)
    }
    #[cfg(not(unix))]
    {
        dir.is_dir().then_some(Source::Account(dir))
    }
}

/// Where a key may come from now: the override, or the account's folder.
fn open_source() -> Option<Source> {
    if override_path().is_some() {
        return Some(Source::Override);
    }
    open_account()
}

/// The most a config or key file is read to: both are a few lines.
const MOST_READ: u64 = 64 * 1024;

/// Read `name`, a plain name, from the account's folder [`Source::Account`]:
/// a regular file, not a symbolic link, and with `single` no other name (a
/// hard link to a private key elsewhere is that key). Opened without
/// blocking, so a FIFO planted as the key never holds `check` or the hook.
fn read_in(source: &Source, name: &str, single: bool) -> Result<String, String> {
    use std::io::Read;
    let file = match source {
        Source::Override => return Err(OVERRIDE_HAS_NO_KEY.to_string()),
        #[cfg(unix)]
        Source::Account(dir) => {
            use std::os::fd::{AsRawFd, FromRawFd};
            let c_name = std::ffi::CString::new(name).map_err(|_| "a name with a NUL byte")?;
            // SAFETY: `dir` is an open directory owned here, `c_name` is a
            // NUL-terminated string that outlives the call.
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = std::io::Error::last_os_error();
                return Err(match error.raw_os_error() {
                    Some(libc::ELOOP) => "a symbolic link".to_string(),
                    Some(libc::ENOENT) => "missing".to_string(),
                    _ => format!("unreadable ({error})"),
                });
            }
            // SAFETY: `fd` was just opened here and is owned by nothing else.
            unsafe { std::fs::File::from_raw_fd(fd) }
        }
        #[cfg(not(unix))]
        Source::Account(dir) => {
            let path = dir.join(name);
            let link = std::fs::symlink_metadata(&path).map_err(|_| "missing".to_string())?;
            if link.file_type().is_symlink() {
                return Err("a symbolic link".into());
            }
            std::fs::File::open(&path).map_err(|e| format!("unreadable ({e})"))?
        }
    };
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("not a regular file (a FIFO or a device is never read)".into());
    }
    #[cfg(unix)]
    if single {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err("a hard link: the file has another name".into());
        }
    }
    #[cfg(not(unix))]
    let _ = single;
    let mut text = String::new();
    file.take(MOST_READ)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    Ok(text)
}

/// Read the file an override names. Opened without blocking (a FIFO is read
/// as empty), and `/dev/null`, the jail's, is an empty config.
fn read_override(path: &std::path::Path) -> Option<String> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut text = String::new();
    options
        .open(path)
        .ok()?
        .take(MOST_READ)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// The config, and where it came from. The account's `llm.toml` is read
/// through the folder handle its key is read through later.
fn load() -> Option<Loaded> {
    load_or_why().ok()
}

/// [`load`], with why the account's `llm.toml` is not read when it is
/// there: `Err(None)` when there is none (or the override names an empty
/// one, as the jail's `/dev/null` is), `Err(Some(why))` when it is there
/// and not read. An `llm.toml` that is itself a symbolic link (dotfiles
/// stowed file by file) was "not configured" in `llm status`, with no word
/// of why.
fn load_or_why() -> Result<Loaded, Option<String>> {
    if let Some(path) = override_path() {
        let cfg = read_override(&path)
            .and_then(|text| LlmConfig::from_toml(&text))
            .ok_or(None)?;
        return Ok(Loaded {
            cfg,
            source: Source::Override,
        });
    }
    let source = open_account().ok_or(None)?;
    let named = || {
        crate::graph_io::account_config_dir()
            .map(|dir| dir.join("llm.toml").display().to_string())
            .unwrap_or_else(|| "llm.toml".to_string())
    };
    let text = match read_in(&source, "llm.toml", false) {
        Ok(text) => text,
        Err(why) if why == "missing" => return Err(None),
        Err(why) if why == "a symbolic link" => {
            return Err(Some(format!(
                "{} is not read: it is a symbolic link, and the file itself is never followed (the folder may be one); keep a plain file there",
                named()
            )))
        }
        Err(why) => return Err(Some(format!("{} is not read: {why}", named()))),
    };
    let cfg = LlmConfig::from_toml(&text).ok_or_else(|| {
        Some(format!(
            "{} is not read: it is not a config with a url and a model",
            named()
        ))
    })?;
    Ok(Loaded { cfg, source })
}

fn load_config() -> Option<LlmConfig> {
    load().map(|loaded| loaded.cfg)
}

/// The plain name `api_key_file` gives inside the account's config folder,
/// or why it names no file there. A bare name, `./name`, a path in the
/// folder (as `llm set-key` stores it) and `~/.config/innerwarden/name` are
/// that folder's; anything else (another folder, `..`, a name in a
/// subfolder) is refused, not followed.
fn key_name(path: &str) -> Result<String, String> {
    let folder =
        crate::graph_io::account_config_dir().ok_or("this account has no home to read a key in")?;
    let named = match path.strip_prefix("~/") {
        Some(rest) => crate::graph_io::config_home()
            .ok_or("this account has no home to expand ~/ in")?
            .join(rest),
        None => std::path::PathBuf::from(path),
    };
    let in_folder = match named.parent() {
        None => true,
        Some(parent) => {
            parent.as_os_str().is_empty() || parent == std::path::Path::new(".") || parent == folder
        }
    };
    let name = named
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..");
    match name {
        Some(name) if in_folder => Ok(name.to_string()),
        _ => Err(format!(
            "outside the config's folder {}: only a key stored there is sent",
            folder.display()
        )),
    }
}

/// The key for `cfg` from `source`: `Ok(None)` when it names none, `Err` with
/// why when it names one that is not read. Only the account's own config has
/// one: the environment variable it names (the hook runs with the agent's
/// environment, so never from an override), else the key file it names in
/// its own folder ([`key_name`], [`read_in`]).
fn key_for(cfg: &LlmConfig, source: &Source) -> Result<Option<String>, String> {
    if cfg.api_key_env.is_none() && cfg.api_key_file.is_none() {
        return Ok(None);
    }
    if matches!(source, Source::Override) {
        return Err(OVERRIDE_HAS_NO_KEY.to_string());
    }
    let why = std::cell::RefCell::new(Vec::new());
    let key = cfg.resolve_key(
        |name| {
            let value = std::env::var(name).ok().filter(|v| !v.trim().is_empty());
            if value.is_none() {
                why.borrow_mut().push(format!("env var {name} is not set"));
            }
            value
        },
        |path| match key_name(path.trim()).and_then(|name| read_in(source, &name, true)) {
            Ok(value) if !value.trim().is_empty() => Some(value),
            Ok(_) => {
                why.borrow_mut().push(format!("key file {path} is empty"));
                None
            }
            Err(e) => {
                why.borrow_mut()
                    .push(format!("key file {path} not read: {e}"));
                None
            }
        },
    );
    match key {
        Some(key) => Ok(Some(key)),
        None => Err(why.into_inner().join("; ")),
    }
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
    load().is_some_and(|loaded| matches!(key_for(&loaded.cfg, &loaded.source), Ok(Some(_))))
}

/// How long the user's endpoint has to answer one classification request.
/// The hook's deadline moves by this much for that one wait, so the timeout an
/// agent is given for the hook has to be longer than the two together.
pub(crate) const LLM_ANSWER_BOUND: std::time::Duration = std::time::Duration::from_secs(20);

/// The second opinion's API key: the named env var (zero key-at-rest) first,
/// then the 0600 key file the wizard / `llm set-key` wrote, read through the
/// folder the config was ([`key_for`]). A key named and not read is said in
/// one line: the request still goes, without it, and a 401 alone said nothing
/// of why.
fn read_key(cfg: &LlmConfig, source: &Source) -> Option<String> {
    match key_for(cfg, source) {
        Ok(key) => key,
        Err(why) => {
            let _ = std::io::Write::write_all(
                &mut std::io::stderr(),
                format!("innerwarden: the second opinion's API key was not read ({why}); asking without one. See `innerwarden llm status`.\n").as_bytes(),
            );
            None
        }
    }
}

/// POST the classification request to the user's endpoint, with `timeout`
/// ([`consider_all`] gave it) and the `key` [`read_key`] read. Best-effort:
/// any error (network, bad status, a proxy in llm.toml that is not a url) is
/// `Answered(None)` so the caller keeps the `review`, but a busy endpoint
/// (429) is told apart, with the wait it asked for, so the line can be asked
/// again while time is left.
fn call_llm(
    cfg: &LlmConfig,
    key: Option<&str>,
    command: &str,
    timeout: std::time::Duration,
) -> Asked {
    // The command LEAVES THE HOST here (off-box to the user's LLM endpoint). Redact
    // secrets first so a screened command that embeds a credential never reaches the
    // model; the redacted form keeps the dangerous SHAPE, so the verdict is unaffected.
    let command = innerwarden_agent_guard::redact::redact_secrets(command).text;
    let body = build_body(&cfg.model, &command);
    (|| {
        // Never the caller's HTTP_PROXY: only the proxy llm.toml names. The
        // status is read here, not turned into an error, so a 429 keeps its
        // Retry-After headers.
        let agent =
            match crate::http_io::account_agent_reading_status(timeout, cfg.proxy.as_deref()) {
                Ok(agent) => agent,
                Err(why) => {
                    let _ = std::io::Write::write_all(
                        &mut std::io::stderr(),
                        format!("innerwarden: the second opinion was not asked: {why}.\n")
                            .as_bytes(),
                    );
                    return Asked::Answered(None);
                }
            };
        let mut req = agent
            .post(&cfg.url)
            .header("Content-Type", "application/json");
        if let Some(key) = key {
            req = if cfg.is_azure() {
                req.header("api-key", key)
            } else {
                req.header("Authorization", &format!("Bearer {key}"))
            };
        }
        let Ok(resp) = req.send_json(body) else {
            return Asked::Answered(None);
        };
        let status = resp.status().as_u16();
        if status == 429 {
            let header = |name: &str| resp.headers().get(name).and_then(|v| v.to_str().ok());
            return Asked::Busy(retry_after(header("retry-after-ms"), header("retry-after")));
        }
        if !(200..300).contains(&status) {
            return Asked::Answered(None);
        }
        Asked::Answered(resp.into_body().read_json::<Value>().ok())
    })()
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
            "cannot resolve a key-file path (this account has no home)",
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
    let agent =
        crate::http_io::account_agent(std::time::Duration::from_secs(12), cfg.proxy.as_deref())?;
    let mut req = agent
        .post(&cfg.url)
        .header("Content-Type", "application/json");
    if let Some(key) = open_source().and_then(|source| key_for(cfg, &source).ok().flatten()) {
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
            None => Err(format!("could not reach {} ({e})", shown_url(&cfg.url))),
        },
    }
}

/// The full second-opinion flow, for every line of a call, in their order:
/// only a `review`, only when the user configured an endpoint. Each answer
/// is an overriding verdict (`decided_by = llm`) or `None` to keep the
/// rules verdict (a `review` the channels announce when the person opted in
/// with `innerwarden notify --notify-review`, refused or not). The lines
/// that need one are asked at once, under one model answer's wait
/// ([`ask_at_once_or_again`]).
pub fn consider_all(lines: &[(&str, &Value)]) -> Vec<Option<Value>> {
    // No configured endpoint = never escalate (the common case; zero cost, fast).
    let Loaded { cfg, source } = match load_or_why() {
        Ok(loaded) => loaded,
        Err(None) => return vec![None; lines.len()],
        Err(Some(why)) => {
            // Said only where it would have been asked: a review with the
            // risk the default floor escalates. One line for the whole call.
            let floor = crate::second_opinion::DEFAULT_MIN_RISK;
            if lines
                .iter()
                .any(|(_, rules)| needs_second_opinion(rules, floor))
            {
                let _ = std::io::Write::write_all(
                    &mut std::io::stderr(),
                    format!(
                        "innerwarden: no second opinion: {why}. See `innerwarden llm status`.\n"
                    )
                    .as_bytes(),
                );
            }
            return vec![None; lines.len()];
        }
    };
    let min_risk = cfg.effective_min_risk();
    // The key is read once, when the first line is asked, so a run that asks
    // nothing reads no key and a key not read is said in one line.
    let key = std::sync::OnceLock::new();
    ask_at_once_or_again(
        lines,
        // Escalate only when it is worth the spend: an ambiguous command
        // with real harm potential (review + risk >= the configured floor).
        |rules| needs_second_opinion(rules, min_risk),
        // The hook's deadline does not count a wait the call bounds itself,
        // up to one model's answer a run, counted by the time really
        // waited. With nothing left the call keeps its review rather than
        // be refused by the deadline while it waits; with less than the
        // bound left, that is the timeout.
        || crate::hook_net::grant_wait(LLM_ANSWER_BOUND),
        |command, rules, timeout| {
            let key = key.get_or_init(|| read_key(&cfg, &source));
            match call_llm(&cfg, key.as_deref(), command, timeout) {
                Asked::Answered(resp) => Asked::Answered(resp.and_then(|resp| {
                    let (verdict, why) = parse_reply(&resp)?;
                    Some(apply_second_opinion(rules, &verdict, &why))
                })),
                busy => busy,
            }
        },
        crate::hook_net::waited,
    )
}

/// Persist the llm config to `config_path()`. Shared by `set`, `set-key`, and the
/// setup wizard so there is one writer. Returns the path or an error string.
pub fn write_config(cfg: &LlmConfig) -> Result<std::path::PathBuf, String> {
    let path = config_path()
        .ok_or_else(|| "cannot resolve a config path (this account has no home)".to_string())?;
    if let Some(note) = missing_home_note() {
        return Err(note);
    }
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return Err(match missing_home_note() {
                Some(note) => format!("cannot create {}: {e}; {note}", dir.display()),
                None => format!("cannot create {}: {e}", dir.display()),
            });
        }
    }
    let body = toml::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    std::fs::write(&path, body).map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    Ok(path)
}

/// A one-line, secret-free description of where the API key comes from, honouring
/// the env-first precedence, and why a key named is not read. Never prints the
/// key itself.
fn key_status(loaded: &Loaded) -> String {
    let c = &loaded.cfg;
    if c.api_key_env.is_none() && c.api_key_file.is_none() {
        if matches!(loaded.source, Source::Override) {
            return "none (IW_LLM_CONFIG names this config, and a config an override names never carries an API key: only a local endpoint without one works this way)".to_string();
        }
        return "none (local endpoint, or run `innerwarden llm set-key`)".to_string();
    }
    let source = match &c.api_key_env {
        Some(e) => format!("env var {e}"),
        None => String::new(),
    };
    let file = match &c.api_key_file {
        Some(f) if source.is_empty() => format!("file {f}"),
        Some(f) => format!(", file {f}"),
        None => String::new(),
    };
    match key_for(c, &loaded.source) {
        Ok(_) => format!("{source}{file} (present)"),
        Err(why) => format!("{source}{file} (not sent: {why})"),
    }
}

/// `url` as it is printed: scheme, host and path, without a user part
/// (`http://user:password@host`) and without the query (`?key=...`), said
/// as `?...`. `llm status` is run by agents too, and what it prints lands
/// in the agent's context.
fn shown_url(url: &str) -> String {
    let url = url.trim();
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, url),
    };
    let end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let (path, cut) = match tail.find(['?', '#']) {
        Some(at) => (&tail[..at], "?..."),
        None => (tail, ""),
    };
    match scheme {
        Some(scheme) => format!("{scheme}://{host}{path}{cut}"),
        None => format!("{host}{path}{cut}"),
    }
}

/// Why `url` is not taken as the endpoint, if it is not: a backslash or a
/// space in it. Read one way here and another by a client
/// (`http://A\\@B/` is origin B to a split on `@`, and host A to a
/// browser), it could keep a key for an address it was not given for.
fn url_refused(url: &str) -> Option<&'static str> {
    let url = url.trim();
    if url.contains('\\') {
        return Some("a url with a backslash is refused (clients read it two ways)");
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Some("a url with a space or a control character is refused");
    }
    None
}

/// The scheme and host (with port) of `url`, lowercased, without any user
/// part: the place a key goes to. A backslash ends the host as a slash
/// does, as a WHATWG parser reads an `http` url: `http://A\\@B/` is A, not
/// B, so a move to it from B drops the key.
fn origin(url: &str) -> String {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let authority = rest.split(['/', '\\', '?', '#']).next().unwrap_or("");
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        host.to_ascii_lowercase()
    )
}

/// Why the account's config cannot be written, when its home is missing (a
/// service account whose home is `/nonexistent`), naming the override.
fn missing_home_note() -> Option<String> {
    if override_path().is_some() {
        return None;
    }
    let home = crate::graph_io::config_home()?;
    (!home.is_dir()).then(|| {
        format!(
            "this account's home {} does not exist (a service account?), and the second opinion reads its config only from there (IW_LLM_CONFIG is honoured only as /dev/null, which turns it off)",
            home.display()
        )
    })
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
            let old_origin = origin(&cfg.url);
            let mut key_file_given = false;
            let mut key_env_given = false;
            let mut it = rest[1..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--url" => cfg.url = it.next().cloned().unwrap_or_default(),
                    "--model" => cfg.model = it.next().cloned().unwrap_or_default(),
                    "--provider" => cfg.provider = it.next().cloned().unwrap_or_default(),
                    "--key-env" => {
                        cfg.api_key_env = it.next().cloned();
                        key_env_given = true;
                    }
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
            if let Some(why) = url_refused(&cfg.url) {
                eprintln!("innerwarden llm set: --url {}: {why}", shown_url(&cfg.url));
                return std::process::ExitCode::from(2);
            }
            if let (true, Some(file)) = (key_file_given, cfg.api_key_file.as_deref()) {
                let read = match open_source() {
                    Some(source) => {
                        key_name(file.trim()).and_then(|name| read_in(&source, &name, true))
                    }
                    None => Err("the config's folder is missing".to_string()),
                };
                if let Err(why) = read {
                    if override_path().is_some() {
                        eprintln!("innerwarden llm set: --key-file {file} is not read: {why}. A key is sent only from the llm.toml in your account's home: unset IW_LLM_CONFIG, then run `innerwarden llm set-key` there.");
                    } else {
                        eprintln!("innerwarden llm set: --key-file {file} is not read: {why}. Only a key stored beside the config is sent; run `innerwarden llm set-key` to store it there.");
                    }
                    return std::process::ExitCode::from(2);
                }
            }
            // A key goes only where it was given for: a url moved to another
            // origin drops the key settings unless this same call gives them
            // again. `llm set --url <another>` kept them, and the next
            // `check` sent the stored key to the new address.
            let moved = origin(&cfg.url) != old_origin;
            let mut key_dropped = false;
            if moved
                && !key_file_given
                && !key_env_given
                && (cfg.api_key_file.is_some() || cfg.api_key_env.is_some())
            {
                cfg.api_key_file = None;
                cfg.api_key_env = None;
                key_dropped = true;
            }
            match write_config(&cfg) {
                Ok(_) => {
                    println!("innerwarden llm - saved. A second opinion from {} ({}) is used ONLY for an ambiguous command with risk >= {} (deny/allow are never escalated).", cfg.model, shown_url(&cfg.url), cfg.effective_min_risk());
                    if key_dropped {
                        println!("  note: the url moved to another address, so the API key setting was removed: a key is never sent to a new address on its own. Run `innerwarden llm set-key` to give one for it.");
                    } else if cfg.api_key_env.is_none() && cfg.api_key_file.is_none() {
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
                    if override_path().is_some() {
                        println!("  note: IW_LLM_CONFIG names this config, and a config an override names never carries an API key: this key is sent only from the llm.toml in your account's home.");
                    }
                    std::process::ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("innerwarden llm set-key: {e}");
                    std::process::ExitCode::from(1)
                }
            }
        }
        _ => {
            match load() {
                Some(loaded) => {
                    let c = &loaded.cfg;
                    println!("innerwarden llm - configured: {} via {}\n  api key: {}\n  escalates only: review + risk >= {} (deny/allow never escalate)", c.model, shown_url(&c.url), key_status(&loaded), c.effective_min_risk());
                }
                None if missing_home_note().is_some() => println!(
                    "innerwarden llm - not configured: {}.",
                    missing_home_note().unwrap_or_default()
                ),
                None if matches!(load_or_why(), Err(Some(_))) => {
                    let why = load_or_why().err().flatten().unwrap_or_default();
                    println!("innerwarden llm - not configured: {why}.");
                    eprintln!("innerwarden llm: {why}");
                }
                None => println!(
                    "innerwarden llm - not configured. Ambiguous commands escalate to a human.\n  set one: innerwarden llm set --url <chat-completions-URL> --model <name> [--provider azure], then innerwarden llm set-key"
                ),
            }
            if let Some(line) = ignored_override_line() {
                println!("{line}");
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

    /// A url is printed without its user part or its query.
    #[test]
    fn a_url_is_shown_without_a_password_or_a_query() {
        assert_eq!(
            shown_url("http://u:p@host:8080/v1/chat"),
            "http://host:8080/v1/chat"
        );
        assert_eq!(
            shown_url("https://x.example/v1beta/m?key=SECRET"),
            "https://x.example/v1beta/m?..."
        );
        assert_eq!(
            shown_url("https://api.openai.com/v1/chat/completions"),
            "https://api.openai.com/v1/chat/completions"
        );
        assert!(!shown_url("http://a:SECRET@h/").contains("SECRET"));
    }

    /// A backslash ends the host, as a WHATWG parser reads it, and a url
    /// with one is refused by `llm set`.
    #[test]
    fn a_backslash_ends_the_host_and_is_refused() {
        assert_eq!(origin("http://A\\@B/"), "http://a");
        assert_ne!(origin("http://A\\@B/"), origin("http://B/"));
        assert!(url_refused("http://A\\@B/").is_some());
        assert!(url_refused("http://a b/").is_some());
        assert!(url_refused("https://api.openai.com/v1/chat/completions").is_none());
    }

    /// The place a key goes to: scheme and host with port, never the path or
    /// a user part.
    #[test]
    fn the_origin_of_a_url_is_its_scheme_and_host() {
        assert_eq!(
            origin("https://API.openai.com/v1/chat/completions"),
            "https://api.openai.com"
        );
        assert_eq!(
            origin("https://api.openai.com/v2/other"),
            origin("https://api.openai.com/v1/chat/completions")
        );
        assert_ne!(
            origin("https://api.openai.com/v1"),
            origin("http://127.0.0.1:9/v1")
        );
        assert_ne!(
            origin("https://api.openai.com/v1"),
            origin("https://api.openai.com.evil.example/v1")
        );
        assert_eq!(origin("https://u:p@host:8443/x"), "https://host:8443");
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
