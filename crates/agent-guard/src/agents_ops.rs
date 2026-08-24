//! The shared `agents` orchestration: discover the AI agents on this machine and
//! wire the guard into them (Claude Code hook, or MCP-proxy wrap of an agent's
//! reviewed agent-specific config). This is the ONE implementation both InnerWarden Community
//! (`innerwarden`) and Active Defence (`innerwarden` ctl) drive, so the command
//! behaves identically in both products. The pure decision logic lives in
//! `agents` / `mcp_wire` / `hook`; this module is the I/O (the /proc scan, the
//! config-dir stat, the file read/write)
//! and returns the lines to print, so each CLI is a thin `println` wrapper.

use std::ffi::OsStr;
use std::path::Path;

use serde_json::Value;

use crate::agents::{
    canonical, connect_targets, summarize_discovered, AgentStatus, ConfigFormat, DiscoveryEvidence,
    GuardMode, KnownDiscovery, ProfileConfig, KNOWN,
};
use crate::signatures::SignatureIndex;
use crate::{detect, hook, mcp_wire, mcp_wire_toml};

const MAX_GENERIC_MCP_CONFIGS: usize = 256;
const MAX_GENERIC_DIRECTORY_ENTRIES: usize = 4_096;
const MAX_GENERIC_MCP_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PROFILE_DIRECTORY_ENTRIES: usize = 4_096;

#[derive(Debug, Default)]
struct HomeMcpDiscovery {
    paths: Vec<String>,
    limited: bool,
}

/// Running agents from the signature `/proc` scan, as (name, pid). Empty off Linux
/// (no `/proc`) - the config-dir pass still finds installed agents there.
fn scan_running() -> Vec<(String, u32)> {
    let index = SignatureIndex::new();
    // Config discovery happens once below against this user's home. A dashboard
    // poll for running state must not also walk every system home directory.
    detect::scan_processes(&index)
        .into_iter()
        .map(|a| (a.name, a.pid))
        .collect()
}

/// Check exact executable basenames through filesystem metadata only. Agent
/// binaries are never launched (including with `--version`) during discovery.
fn executable_on_path(names: &[&str], path_env: Option<&OsStr>) -> bool {
    let Some(path_env) = path_env else {
        return false;
    };
    std::env::split_paths(path_env)
        .filter(|directory| !directory.as_os_str().is_empty())
        .any(|directory| {
            names.iter().any(|name| {
                let direct = directory.join(name);
                if executable_file(&direct) {
                    return true;
                }
                #[cfg(windows)]
                {
                    ["exe", "cmd", "bat", "com"].iter().any(|extension| {
                        executable_file(&directory.join(format!("{name}.{extension}")))
                    })
                }
                #[cfg(not(windows))]
                false
            })
        })
}

fn executable_file(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    true
}

fn marker_exists_without_following_symlinks(home: &Path, relative: &str) -> bool {
    std::fs::symlink_metadata(home.join(relative))
        .map(|metadata| {
            !metadata.file_type().is_symlink() && (metadata.is_dir() || metadata.is_file())
        })
        .unwrap_or(false)
}

fn valid_config_file(home: &Path, relative: &str, format: ConfigFormat) -> bool {
    let path = home.join(relative);
    let Ok(Some(bytes)) = crate::file_update::read_config_no_symlinks(home, &path) else {
        return false;
    };
    match format {
        ConfigFormat::JsonObject => serde_json::from_slice::<Value>(&bytes)
            .ok()
            .is_some_and(|value| value.is_object()),
        ConfigFormat::Json5Object => json5_object_has_balanced_shape(&bytes),
        ConfigFormat::Toml => std::str::from_utf8(&bytes)
            .ok()
            .and_then(|body| body.parse::<toml_edit::DocumentMut>().ok())
            .is_some(),
        ConfigFormat::YamlMapping => serde_yaml::from_slice::<serde_yaml::Value>(&bytes)
            .ok()
            .is_some_and(|value| value.is_mapping()),
    }
}

/// Conservative JSON5 container validation without normalizing or rewriting the
/// file. OpenClaw accepts JSON5, so strict `serde_json` would reject valid
/// comments/trailing commas; this scanner only establishes a balanced top-level
/// object and rejects truncated strings/comments/brackets.
fn json5_object_has_balanced_shape(bytes: &[u8]) -> bool {
    if std::str::from_utf8(bytes).is_err() {
        return false;
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Normal,
        SingleQuoted,
        DoubleQuoted,
        LineComment,
        BlockComment,
    }

    let mut state = State::Normal;
    let mut escaped = false;
    let mut delimiters = Vec::new();
    let mut started = false;
    let mut finished = false;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied();
        match state {
            State::SingleQuoted | State::DoubleQuoted => {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if (state == State::SingleQuoted && byte == b'\'')
                    || (state == State::DoubleQuoted && byte == b'"')
                {
                    state = State::Normal;
                }
            }
            State::LineComment => {
                if byte == b'\n' || byte == b'\r' {
                    state = State::Normal;
                }
            }
            State::BlockComment => {
                if byte == b'*' && next == Some(b'/') {
                    state = State::Normal;
                    index += 1;
                }
            }
            State::Normal => {
                if byte == b'/' && next == Some(b'/') {
                    state = State::LineComment;
                    index += 1;
                } else if byte == b'/' && next == Some(b'*') {
                    state = State::BlockComment;
                    index += 1;
                } else if byte.is_ascii_whitespace()
                    || (!started && bytes[index..].starts_with(&[0xEF, 0xBB, 0xBF]))
                {
                    if !started && bytes[index..].starts_with(&[0xEF, 0xBB, 0xBF]) {
                        index += 2;
                    }
                } else if !started {
                    if byte != b'{' {
                        return false;
                    }
                    started = true;
                    delimiters.push(b'{');
                } else if finished {
                    return false;
                } else {
                    match byte {
                        b'\'' => state = State::SingleQuoted,
                        b'"' => state = State::DoubleQuoted,
                        b'{' => delimiters.push(b'{'),
                        b'}' => {
                            if delimiters.pop() != Some(b'{') {
                                return false;
                            }
                            if delimiters.is_empty() {
                                finished = true;
                            }
                        }
                        b'[' => delimiters.push(b'['),
                        b']' if delimiters.pop() != Some(b'[') => return false,
                        b']' => {}
                        _ => {}
                    }
                }
            }
        }
        index += 1;
    }
    started
        && finished
        && delimiters.is_empty()
        && matches!(state, State::Normal | State::LineComment)
}

fn profile_configuration_found(home: &Path, profile: ProfileConfig) -> (bool, bool) {
    let Ok(entries) = std::fs::read_dir(home) else {
        return (false, false);
    };
    let mut limited = false;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_PROFILE_DIRECTORY_ENTRIES {
            limited = true;
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(profile_name) = name.strip_prefix(profile.directory_prefix) else {
            continue;
        };
        if profile_name.is_empty() {
            continue;
        }
        let relative = format!("{name}/{}", profile.file_name);
        if valid_config_file(home, &relative, profile.format) {
            return (true, limited);
        }
    }
    (false, limited)
}

fn discover_known(home: &Path, path_env: Option<&OsStr>) -> (Vec<KnownDiscovery>, bool) {
    let mut discoveries = Vec::new();
    let mut limited = false;
    for known in KNOWN {
        let mut evidence = Vec::new();
        if executable_on_path(known.executables, path_env) {
            evidence.push(DiscoveryEvidence::ExecutableOnPath);
        }
        let direct_config = known
            .config_files
            .iter()
            .any(|(relative, format)| valid_config_file(home, relative, *format));
        let profile_config = known.profile_config.is_some_and(|profile| {
            let (found, profile_limited) = profile_configuration_found(home, profile);
            limited |= profile_limited;
            found
        });
        if direct_config || profile_config {
            evidence.push(DiscoveryEvidence::ConfigurationFile);
        }
        if evidence.is_empty() && marker_exists_without_following_symlinks(home, known.config_dir) {
            evidence.push(DiscoveryEvidence::PossibleLeftover);
        }
        if !evidence.is_empty() {
            discoveries.push(KnownDiscovery { known, evidence });
        }
    }
    (discoveries, limited)
}

/// Discover conventional JSON MCP configurations without crawling the user's
/// projects or following symlinks. Besides the known agent paths, support a
/// generic `~/.<agent>/mcp.json` and `~/.config/<agent>/mcp.json`. That lets a new
/// MCP-capable client be surfaced and connected before InnerWarden has shipped a
/// named signature for it, while keeping the scan narrow and predictable.
fn home_mcp_configs_with_status(home: &Path) -> HomeMcpDiscovery {
    fn scan_children(
        home: &Path,
        root: &Path,
        prefix: &str,
        dot_only: bool,
    ) -> (Vec<(String, u64)>, bool) {
        let Ok(entries) = std::fs::read_dir(root) else {
            return (Vec::new(), false);
        };
        let mut candidates = Vec::new();
        let mut seen = 0usize;
        let mut limited = false;
        for entry in entries {
            seen += 1;
            if seen > MAX_GENERIC_DIRECTORY_ENTRIES {
                limited = true;
                break;
            }
            let Ok(entry) = entry else {
                continue;
            };
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() || file_type.is_symlink() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if dot_only && (!name.starts_with('.') || name == ".config") {
                continue;
            }
            let candidate = entry.path().join("mcp.json");
            let Ok(metadata) = candidate.symlink_metadata() else {
                continue;
            };
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                continue;
            }
            let Ok(rel) = candidate.strip_prefix(home) else {
                continue;
            };
            let rendered = rel.to_string_lossy().replace('\\', "/");
            if prefix.is_empty() || rendered.starts_with(prefix) {
                candidates.push((rendered, metadata.len()));
            }
        }
        (candidates, limited)
    }

    let (mut candidates, mut limited) = scan_children(home, home, "", true);
    let (configured, config_limited) =
        scan_children(home, &home.join(".config"), ".config/", false);
    candidates.extend(configured);
    limited |= config_limited;
    candidates.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    candidates.dedup_by(|a, b| a.0 == b.0);

    let known_paths: Vec<&str> = KNOWN.iter().filter_map(|known| known.mcp_json).collect();
    let mut paths = Vec::new();
    let mut bytes = 0u64;
    for (path, len) in candidates {
        if known_paths.contains(&path.as_str()) {
            continue;
        }
        if paths.len() >= MAX_GENERIC_MCP_CONFIGS
            || len > crate::file_update::MAX_CONFIG_BYTES
            || bytes.saturating_add(len) > MAX_GENERIC_MCP_BYTES
        {
            limited = true;
            continue;
        }
        bytes = bytes.saturating_add(len);
        paths.push(path);
    }
    HomeMcpDiscovery { paths, limited }
}

#[cfg(test)]
fn home_mcp_configs(home: &Path) -> Vec<String> {
    home_mcp_configs_with_status(home).paths
}

fn generic_mcp_name(rel: &str, rows: &[AgentStatus]) -> String {
    let base = Path::new(rel)
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .trim_start_matches('.')
        .to_ascii_lowercase()
        .replace([' ', '_'], "-");
    let base = if base.is_empty() { "unknown" } else { &base };
    let available = |name: &str| {
        rows.iter().all(|row| row.name != name) && KNOWN.iter().all(|known| known.name != name)
    };
    if available(base) {
        return base.to_string();
    }
    let candidate = format!("{base}-mcp");
    if available(&candidate) {
        return candidate;
    }
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base}-mcp-{suffix}");
        if available(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

fn read_json(path: &Path) -> Option<Value> {
    crate::file_update::read_config(path)
        .ok()
        .flatten()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}

fn read_config_for_update(
    trusted_root: &Path,
    path: &Path,
    reject_symlinks: bool,
) -> Result<Option<Vec<u8>>, String> {
    if reject_symlinks {
        crate::file_update::read_config_no_symlinks(trusted_root, path)
    } else {
        crate::file_update::read_config(path)
    }
}

fn read_json_for_update(
    trusted_root: &Path,
    path: &Path,
    reject_symlinks: bool,
) -> Result<Option<(Value, Vec<u8>)>, String> {
    let Some(source) = read_config_for_update(trusted_root, path, reject_symlinks)? else {
        return Ok(None);
    };
    let value = serde_json::from_slice(&source)
        .map_err(|error| format!("{} is not valid JSON: {error}", path.display()))?;
    Ok(Some((value, source)))
}

fn write_json(
    trusted_root: &Path,
    path: &Path,
    v: &Value,
    expected: &[u8],
    reject_symlinks: bool,
) -> Result<(), String> {
    let body = serde_json::to_string_pretty(v).map_err(|e| e.to_string())? + "\n";
    if reject_symlinks {
        crate::file_update::replace_if_unchanged_no_symlinks(
            trusted_root,
            path,
            Some(expected),
            body.as_bytes(),
        )
    } else {
        crate::file_update::replace_if_unchanged(path, Some(expected), body.as_bytes())
    }
}

fn read_toml(path: &Path) -> Option<toml_edit::DocumentMut> {
    crate::file_update::read_config(path)
        .ok()
        .flatten()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|body| body.parse::<toml_edit::DocumentMut>().ok())
}

fn read_toml_for_update(
    trusted_root: &Path,
    path: &Path,
    reject_symlinks: bool,
) -> Result<Option<(toml_edit::DocumentMut, Vec<u8>)>, String> {
    let Some(source) = read_config_for_update(trusted_root, path, reject_symlinks)? else {
        return Ok(None);
    };
    let body = std::str::from_utf8(&source)
        .map_err(|error| format!("{} is not valid UTF-8: {error}", path.display()))?;
    let document = body
        .parse::<toml_edit::DocumentMut>()
        .map_err(|error| format!("{} is not valid TOML: {error}", path.display()))?;
    Ok(Some((document, source)))
}

fn write_toml(
    trusted_root: &Path,
    path: &Path,
    doc: &toml_edit::DocumentMut,
    expected: &[u8],
    reject_symlinks: bool,
) -> Result<(), String> {
    if reject_symlinks {
        crate::file_update::replace_if_unchanged_no_symlinks(
            trusted_root,
            path,
            Some(expected),
            doc.to_string().as_bytes(),
        )
    } else {
        crate::file_update::replace_if_unchanged(path, Some(expected), doc.to_string().as_bytes())
    }
}

/// Is the guard wired for this agent? Claude Code = the PreToolUse hook; an MCP
/// agent = every stdio server in its config (reviewed JSON or Codex's TOML
/// `[mcp_servers]`) routed through the proxy.
fn is_guarded(home: &Path, agent: &str) -> bool {
    let Some(k) = canonical(agent) else {
        return false;
    };
    if k.hookable {
        return read_json(&home.join(".claude/settings.json"))
            .map(|v| hook::has_iwguard_hook(&v))
            .unwrap_or(false);
    }
    if let Some(rel) = k.mcp_json {
        return read_json(&home.join(rel))
            .map(|v| mcp_wire::is_guarded(&v))
            .unwrap_or(false);
    }
    if let Some(rel) = k.mcp_toml {
        return read_toml(&home.join(rel))
            .map(|d| mcp_wire_toml::is_guarded_toml(&d))
            .unwrap_or(false);
    }
    false
}

/// Whether this agent has any InnerWarden wiring at all. Unlike `is_guarded`,
/// partial MCP coverage counts: mode switches use this to repair/reconfigure the
/// existing wrappers and bring newly-added local servers under the same posture.
pub fn has_guard_wiring(home: &Path, agent: &str) -> bool {
    // Rows produced by discovery already carry canonical names. Require an exact
    // reviewed name here: substring canonicalization is for process aliases and
    // must never redirect a generic MCP row to a known agent's static path.
    if let Some(k) = KNOWN.iter().find(|known| known.name == agent) {
        if k.hookable {
            return read_json(&home.join(".claude/settings.json"))
                .map(|v| hook::has_iwguard_wiring(&v))
                .unwrap_or(false);
        }
        if let Some(rel) = k.mcp_json {
            return read_json(&home.join(rel))
                .map(|v| mcp_wire::has_guard_wiring(&v))
                .unwrap_or(false);
        }
        if let Some(rel) = k.mcp_toml {
            return read_toml(&home.join(rel))
                .map(|d| mcp_wire_toml::has_guard_wiring_toml(&d))
                .unwrap_or(false);
        }
        return false;
    }

    // Generic MCP clients have no static `Known` row. Resolve the narrow-scan
    // status by its stable generated name, then inspect that exact relative path.
    rows(home)
        .into_iter()
        .find(|row| row.name == agent)
        .and_then(|row| row.mcp_json)
        .and_then(|rel| read_json(&home.join(rel)))
        .map(|config| mcp_wire::has_guard_wiring(&config))
        .unwrap_or(false)
}

/// Inspect any recognised wiring using an already-discovered row. Repair and
/// mode-switching callers use this form to avoid rediscovering every generic MCP
/// config once per row; dashboard posture uses [`status_is_effectively_guarded`].
/// Is there guarding work still to do for this agent?
///
/// For a hook agent this is simply "the hook is absent": there is no partial
/// state. For an MCP agent it means at least one stdio server is still open,
/// which is NOT the same as "the file has never been touched". See
/// [`mcp_wire::has_unguarded_stdio_server`].
pub fn status_has_unguarded_server(home: &Path, agent: &AgentStatus) -> bool {
    if agent.hookable {
        return !read_json(&home.join(".claude/settings.json"))
            .map(|value| hook::has_iwguard_wiring(&value))
            .unwrap_or(false);
    }
    if let Some(relative) = &agent.mcp_json {
        return read_json(&home.join(relative))
            .map(|value| mcp_wire::has_unguarded_stdio_server(&value))
            .unwrap_or(false);
    }
    if let Some(relative) = &agent.mcp_toml {
        return read_toml(&home.join(relative))
            .map(|document| mcp_wire_toml::has_unguarded_stdio_server_toml(&document))
            .unwrap_or(false);
    }
    false
}

pub fn status_has_guard_wiring(home: &Path, agent: &AgentStatus) -> bool {
    if agent.hookable {
        return read_json(&home.join(".claude/settings.json"))
            .map(|value| hook::has_iwguard_wiring(&value))
            .unwrap_or(false);
    }
    if let Some(relative) = &agent.mcp_json {
        return read_json(&home.join(relative))
            .map(|value| mcp_wire::has_guard_wiring(&value))
            .unwrap_or(false);
    }
    if let Some(relative) = &agent.mcp_toml {
        return read_toml(&home.join(relative))
            .map(|document| mcp_wire_toml::has_guard_wiring_toml(&document))
            .unwrap_or(false);
    }
    false
}

/// Whether this discovered row currently provides an effective guardrail signal
/// for dashboard/status purposes. Claude wiring counts only under the exact
/// `PreToolUse:Bash` matcher; a recognised hook under another matcher remains
/// discoverable through [`status_has_guard_wiring`] so automatic reconciliation
/// can repair it without falsely claiming active shell protection.
pub fn status_is_effectively_guarded(home: &Path, agent: &AgentStatus) -> bool {
    if agent.hookable {
        return read_json(&home.join(".claude/settings.json"))
            .map(|value| hook::has_iwguard_hook(&value))
            .unwrap_or(false);
    }
    status_has_guard_wiring(home, agent)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CompatibleMcpSchema {
    ProxyWrappable,
    NestedVisibilityOnly,
}

fn compatible_mcp_configuration(config: &Value) -> Option<CompatibleMcpSchema> {
    if ["mcpServers", "servers"]
        .iter()
        .any(|key| config.get(key).is_some_and(Value::is_object))
    {
        return Some(CompatibleMcpSchema::ProxyWrappable);
    }
    config
        .get("mcp")
        .and_then(|mcp| mcp.get("servers"))
        .is_some_and(Value::is_object)
        .then_some(CompatibleMcpSchema::NestedVisibilityOnly)
}

fn rows_from_sources(
    home: &Path,
    running: &[(String, u32)],
    path_env: Option<&OsStr>,
) -> (Vec<AgentStatus>, bool) {
    let (discovered, profile_limited) = discover_known(home, path_env);
    let mut rows = summarize_discovered(running, &discovered, |name| is_guarded(home, name));

    // A valid-looking MCP config is itself a discovery signal. Known paths have
    // richer reviewed rows above; every other match stays a generic MCP client
    // for visibility and explicit/manual setup only.
    let generic = home_mcp_configs_with_status(home);
    for rel in generic.paths {
        if rows
            .iter()
            .any(|row| row.mcp_json.as_deref() == Some(rel.as_str()))
        {
            continue;
        }
        let Some(config) = read_json(&home.join(&rel)) else {
            continue;
        };
        let Some(schema) = compatible_mcp_configuration(&config) else {
            continue;
        };
        let guarded =
            schema == CompatibleMcpSchema::ProxyWrappable && mcp_wire::is_guarded(&config);
        let name = generic_mcp_name(&rel, &rows);
        rows.push(AgentStatus {
            name,
            pids: Vec::new(),
            installed: false,
            evidence: vec![DiscoveryEvidence::CompatibleMcpConfiguration],
            hookable: false,
            // `mcp.servers` proves capability, but the current lossless proxy
            // editor supports only top-level `mcpServers` / `servers`. Keep the
            // nested schema visible without granting connect authority.
            mcp_json: (schema == CompatibleMcpSchema::ProxyWrappable).then_some(rel),
            mcp_toml: None,
            guarded,
            mode: None,
        });
    }
    // Read back what the wiring actually DOES, per agent, so the listing can
    // say "monitor" or "enforce" instead of only "guarded".
    for r in &mut rows {
        if r.guarded {
            r.mode = read_guard_mode(home, &r.name);
        }
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    (rows, generic.limited || profile_limited)
}

/// All detected agents with the evidence that caused each row to be surfaced.
pub fn rows_with_discovery_status(home: &Path) -> (Vec<AgentStatus>, bool) {
    let running = scan_running();
    let path_env = std::env::var_os("PATH");
    rows_from_sources(home, &running, path_env.as_deref())
}

pub fn rows(home: &Path) -> Vec<AgentStatus> {
    rows_with_discovery_status(home).0
}

/// The detected agents the guard can wire (hook or MCP), for the setup wizard.
pub fn detected_guardable(home: &Path) -> Vec<AgentStatus> {
    rows(home).into_iter().filter(|r| r.guardable()).collect()
}

/// The absolute path to THIS binary, used inside an agent's config so the wiring
/// keeps working regardless of `$PATH`.
pub fn guard_bin() -> String {
    std::env::current_exe()
        .ok()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "innerwarden".to_string())
}

fn mechanism(r: &AgentStatus) -> &'static str {
    if r.hookable {
        "hook"
    } else if r.mcp_json.is_some() || r.mcp_toml.is_some() {
        "MCP proxy"
    } else {
        "manual"
    }
}

/// Machine-readable effect of a wiring request. Callers must not infer success
/// by parsing the human-facing line (which previously caused mode/setup counts to
/// silently stay at zero when punctuation changed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectEffect {
    Connected,
    Unchanged,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectResult {
    pub effect: ConnectEffect,
    pub line: String,
}

impl ConnectResult {
    fn new(effect: ConnectEffect, line: String) -> Self {
        Self { effect, line }
    }

    pub fn configured(&self) -> bool {
        matches!(
            self.effect,
            ConnectEffect::Connected | ConnectEffect::Unchanged
        )
    }
}

/// Wire ONE agent by its best mechanism and return a structured outcome.
/// `strict` also blocks `review` (hook only). `monitor` selects observe-only
/// behavior; existing wiring is reconfigured in place so mode changes never
/// stack wrappers.
pub fn connect_one_result(
    home: &Path,
    r: &AgentStatus,
    guard_bin: &str,
    strict: bool,
    monitor: bool,
) -> ConnectResult {
    connect_one_result_with_link_policy(home, r, guard_bin, strict, monitor, false)
}

/// Background/automatic wiring variant. It has the same monitor invariant at
/// the policy layer and additionally refuses config symlinks at read and commit.
pub fn connect_one_result_automatic(
    home: &Path,
    r: &AgentStatus,
    guard_bin: &str,
    strict: bool,
    monitor: bool,
) -> ConnectResult {
    connect_one_result_with_link_policy(home, r, guard_bin, strict, monitor, true)
}

fn connect_one_result_with_link_policy(
    home: &Path,
    r: &AgentStatus,
    guard_bin: &str,
    strict: bool,
    monitor: bool,
    reject_symlinks: bool,
) -> ConnectResult {
    if r.hookable {
        let installed: Result<bool, String> = if reject_symlinks {
            hook::install_hook_no_symlinks(
                home,
                &r.name,
                None,
                Path::new(guard_bin),
                strict,
                monitor,
            )
            .map(|result| matches!(result, hook::AutomaticHookInstall::Installed(_)))
        } else {
            hook::install_hook(home, &r.name, None, Path::new(guard_bin), strict, monitor)
                .map(|_| true)
        };
        return match installed {
            Ok(false) => ConnectResult::new(
                ConnectEffect::Skipped,
                format!("  {} - existing hook wiring left unchanged", r.name),
            ),
            Ok(true) => {
                let mode = if monitor {
                    ", monitor (records, never blocks)"
                } else if strict {
                    ", strict"
                } else {
                    ""
                };
                // NOT keyed on `r.guarded`.
                //
                // A first attempt reported "already guarded" whenever a hook was
                // present, which broke hook REPAIR: a hook pointing at an old
                // binary path is present, is rewritten to the current path, and
                // that is a change. `reconciler_repairs_hooks_without_promoting_a_wrong_matcher_mode`
                // caught it, expecting connected=1 and getting 0.
                //
                // `Ok(true)` here already means bytes were written. The genuine
                // no-op has its own arm above (`Ok(false)` -> Skipped, "existing
                // hook wiring left unchanged"), so the distinction the user needs
                // is carried by the LISTING showing the mode, not by weakening
                // this signal.
                ConnectResult::new(
                    ConnectEffect::Connected,
                    format!("  {} - connected (PreToolUse hook{mode})", r.name),
                )
            }
            Err(e) => {
                ConnectResult::new(ConnectEffect::Failed, format!("  {} - failed: {e}", r.name))
            }
        };
    }
    if let Some(rel) = &r.mcp_json {
        let path = home.join(rel);
        let (cfg, source) = match read_json_for_update(home, &path, reject_symlinks) {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                return ConnectResult::new(
                    ConnectEffect::Skipped,
                    format!(
                        "  {} - {} does not exist yet; nothing to guard until it has MCP servers",
                        r.name,
                        path.display()
                    ),
                )
            }
            Err(error) => {
                return ConnectResult::new(
                    ConnectEffect::Failed,
                    format!("  {} - failed: {error}", r.name),
                )
            }
        };
        if reject_symlinks && mcp_wire::has_guard_wiring(&cfg) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!("  {} - existing MCP wiring left unchanged", r.name),
            );
        }
        if reject_symlinks && !mcp_wire::is_automatic_wrap_safe(&cfg) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!(
                    "  {} - invalid MCP structure requires an explicit manual connect",
                    r.name
                ),
            );
        }
        if !mcp_wire::is_guardable(&cfg) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!(
                    "  {} - {} has no local MCP servers to guard (remote-only or empty)",
                    r.name,
                    path.display()
                ),
            );
        }
        let (wrapped, n) = mcp_wire::wrap(cfg, guard_bin, monitor);
        let fully_guarded = mcp_wire::is_guarded(&wrapped);
        if !fully_guarded {
            return ConnectResult::new(
                ConnectEffect::Failed,
                format!(
                    "  {} - failed: incomplete InnerWarden MCP wrapper in {}; restore its child command, then reconnect",
                    r.name,
                    path.display()
                ),
            );
        }
        return match write_json(home, &path, &wrapped, &source, reject_symlinks) {
            Ok(()) if n == 0 => ConnectResult::new(
                ConnectEffect::Unchanged,
                format!(
                    "  {} - already guarded (MCP proxy, {})",
                    r.name,
                    if monitor { "monitor" } else { "enforce" }
                ),
            ),
            Ok(()) => ConnectResult::new(
                ConnectEffect::Connected,
                format!(
                    "  {} - connected ({n} MCP server{} routed through the guard proxy, {})",
                    r.name,
                    if n == 1 { "" } else { "s" },
                    if monitor { "monitor" } else { "enforce" }
                ),
            ),
            Err(e) => {
                ConnectResult::new(ConnectEffect::Failed, format!("  {} - failed: {e}", r.name))
            }
        };
    }
    if let Some(rel) = &r.mcp_toml {
        // Codex: wrap the [mcp_servers.*] tables in ~/.codex/config.toml
        // (format-preserving), routing each server through the guard proxy.
        let path = home.join(rel);
        let (mut doc, source) = match read_toml_for_update(home, &path, reject_symlinks) {
            Ok(Some(pair)) => pair,
            Ok(None) => {
                return ConnectResult::new(
                    ConnectEffect::Skipped,
                    format!(
                        "  {} - {} does not exist yet; nothing to guard until it has [mcp_servers]",
                        r.name,
                        path.display()
                    ),
                )
            }
            Err(error) => {
                return ConnectResult::new(
                    ConnectEffect::Failed,
                    format!("  {} - failed: {error}", r.name),
                )
            }
        };
        if reject_symlinks && mcp_wire_toml::has_guard_wiring_toml(&doc) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!("  {} - existing MCP wiring left unchanged", r.name),
            );
        }
        if reject_symlinks && !mcp_wire_toml::is_automatic_wrap_safe_toml(&doc) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!(
                    "  {} - invalid MCP structure requires an explicit manual connect",
                    r.name
                ),
            );
        }
        if !mcp_wire_toml::is_guardable_toml(&doc) {
            return ConnectResult::new(
                ConnectEffect::Skipped,
                format!(
                    "  {} - {} has no local MCP servers to guard (remote-only or none)",
                    r.name,
                    path.display()
                ),
            );
        }
        let n = mcp_wire_toml::wrap_toml(&mut doc, guard_bin, monitor);
        let fully_guarded = mcp_wire_toml::is_guarded_toml(&doc);
        if !fully_guarded {
            return ConnectResult::new(
                ConnectEffect::Failed,
                format!(
                    "  {} - failed: incomplete InnerWarden MCP wrapper in {}; restore its child command, then reconnect",
                    r.name,
                    path.display()
                ),
            );
        }
        return match write_toml(home, &path, &doc, &source, reject_symlinks) {
            Ok(()) if n == 0 => ConnectResult::new(
                ConnectEffect::Unchanged,
                format!(
                    "  {} - already guarded (MCP proxy, {})",
                    r.name,
                    if monitor { "monitor" } else { "enforce" }
                ),
            ),
            Ok(()) => ConnectResult::new(
                ConnectEffect::Connected,
                format!(
                    "  {} - connected ({n} MCP server{} routed through the guard proxy, {})",
                    r.name,
                    if n == 1 { "" } else { "s" },
                    if monitor { "monitor" } else { "enforce" }
                ),
            ),
            Err(e) => {
                ConnectResult::new(ConnectEffect::Failed, format!("  {} - failed: {e}", r.name))
            }
        };
    }
    ConnectResult::new(
        ConnectEffect::Skipped,
        format!(
            "  {} - no automatic wiring; point it at `innerwarden hook` or `innerwarden proxy` manually",
            r.name
        ),
    )
}

/// Backwards-compatible human-facing adapter used by the thin CLI wrappers.
pub fn connect_one(
    home: &Path,
    r: &AgentStatus,
    guard_bin: &str,
    strict: bool,
    monitor: bool,
) -> String {
    connect_one_result(home, r, guard_bin, strict, monitor).line
}

fn disconnect_one(home: &Path, r: &AgentStatus) -> String {
    if r.hookable {
        return match hook::uninstall_hook(home, &r.name, None) {
            Ok((_, n)) if n > 0 => format!("  {}, disconnected", r.name),
            Ok(_) => format!("  {}, was not connected", r.name),
            Err(e) => format!("  {}, failed: {e}", r.name),
        };
    }
    if let Some(rel) = &r.mcp_json {
        let path = home.join(rel);
        let (cfg, source) = match read_json_for_update(home, &path, false) {
            Ok(Some(pair)) => pair,
            Ok(None) => return format!("  {} - was not connected", r.name),
            Err(error) => return format!("  {} - failed: {error}", r.name),
        };
        let (restored, n) = mcp_wire::unwrap(cfg);
        if n == 0 {
            return format!("  {}, was not connected", r.name);
        }
        return match write_json(home, &path, &restored, &source, false) {
            Ok(()) => format!("  {}, disconnected", r.name),
            Err(e) => format!("  {}, failed: {e}", r.name),
        };
    }
    if let Some(rel) = &r.mcp_toml {
        let path = home.join(rel);
        let (mut doc, source) = match read_toml_for_update(home, &path, false) {
            Ok(Some(pair)) => pair,
            Ok(None) => return format!("  {} - was not connected", r.name),
            Err(error) => return format!("  {} - failed: {error}", r.name),
        };
        let n = mcp_wire_toml::unwrap_toml(&mut doc);
        if n == 0 {
            return format!("  {}, was not connected", r.name);
        }
        return match write_toml(home, &path, &doc, &source, false) {
            Ok(()) => format!("  {}, disconnected", r.name),
            Err(e) => format!("  {}, failed: {e}", r.name),
        };
    }
    format!("  {}, nothing to disconnect", r.name)
}

/// What to say when the scan matched nothing.
///
/// Absence of a SIGNATURE is not absence of an agent, and saying the second when
/// you mean the first sends a beginner away believing they have nothing to
/// guard. Detection matches known agents by their command line, so a bespoke
/// script, a wrapper or a renamed binary matches nothing while running
/// perfectly. That reader is exactly the one who needs a next step, and exactly
/// the one the old single line ended the conversation on. Seen on a production
/// host running a hand-written Python agent this command called "no compatible
/// AI agents found".
fn nothing_detected_lines() -> Vec<String> {
    vec![
        "innerwarden agents, none of the agents I know by name are running.".into(),
        String::new(),
        "  I detect agents by matching known command lines, so a bespoke".into(),
        "  script, a wrapper or a renamed binary will not show up here even".into(),
        "  while it is running.".into(),
        String::new(),
        "  If you have an agent running:".into(),
        "    innerwarden hook <your-agent>   wire the in-path guard".into(),
        "    innerwarden agents --all        show every process I considered".into(),
    ]
}

fn list_lines(home: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let rows = rows(home);
    if rows.is_empty() {
        out.extend(nothing_detected_lines());
    } else {
        // Say what is LEFT to do, not what the command can do in general.
        //
        // The header and the footer were both unconditional, so connecting an
        // agent changed nothing on screen: the same "connect wires all guardable
        // ones" line above, the same "connect one / all" invitation below, and
        // the row itself already reading "guarded" before and after. Someone who
        // had just wired three of four agents was still being told to wire them,
        // with no way to tell from the output that anything had happened.
        let pending = rows.iter().filter(|r| r.guardable() && !r.guarded).count();
        let guarded = rows.iter().filter(|r| r.guarded).count();
        out.push(match pending {
            0 if guarded > 0 => format!(
                "innerwarden agents, all {guarded} guardable agent(s) are wired. Nothing to connect."
            ),
            0 => "innerwarden agents, found (none of these can be wired automatically):".into(),
            n => format!("innerwarden agents, found ({n} not wired yet):"),
        });
        for r in &rows {
            let guard = if !r.guardable() {
                "detected (guard manually)".to_string()
            } else if r.guarded {
                // Name the MODE, not just the mechanism. "guarded (hook)" was the
                // same string whether the hook records or blocks.
                match r.mode {
                    Some(m) => format!("✓ guarded ({}, {})", mechanism(r), m.label()),
                    None => format!("✓ guarded ({}, mode unreadable)", mechanism(r)),
                }
            } else {
                format!("not guarded, connect via {}", mechanism(r))
            };
            let where_ = if r.installed && !r.pids.is_empty() {
                format!("executable on PATH, running pid {:?}", r.pids)
            } else if !r.pids.is_empty() {
                format!("running pid {:?}", r.pids)
            } else if r.installed {
                "executable on PATH".to_string()
            } else if r.has_evidence(DiscoveryEvidence::ConfigurationFile) {
                "recognized configuration; CLI not confirmed".to_string()
            } else if r.has_evidence(DiscoveryEvidence::CompatibleMcpConfiguration) {
                "compatible MCP configuration".to_string()
            } else if r.has_evidence(DiscoveryEvidence::PossibleLeftover) {
                "possible leftover; installation not confirmed".to_string()
            } else {
                "detected".to_string()
            };
            out.push(format!("  {:<13} {:<34} {where_}", r.name, guard));
        }
        // Only offer the action when there is something to act on.
        if pending > 0 {
            out.push(
                "\n  connect one:  innerwarden agents connect <name>     all:  innerwarden agents connect --all"
                    .into(),
            );
        }
    }
    out
}

/// Everything one `agents` invocation produced: the human-facing lines, plus the
/// machine-readable count of integrations a CONNECT left wired.
///
/// The count exists so a caller can key follow-up advice (for example "restart
/// your agents so they reload the hook") on what actually happened. Callers must
/// take it from here rather than scanning `lines` for a word: the same defect
/// that kept mode/setup counts at zero when punctuation changed is waiting for
/// anyone who greps this text, and "was not connected" contains "connected"
/// while "already guarded (MCP proxy, monitor)" does not.
///
/// `configured` is zero for every command that is not `connect`, so keying on it
/// cannot fire after a `disconnect` or a plain listing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOutcome {
    pub lines: Vec<String>,
    pub configured: usize,
}

fn connect_outcome(
    home: &Path,
    target: Option<&str>,
    strict: bool,
    monitor: bool,
    guard_bin: &str,
) -> RunOutcome {
    let rows = rows(home);
    let targets = connect_targets(&rows, target);
    if targets.is_empty() {
        return RunOutcome {
            lines: vec![match target {
                Some(name) => format!(
                    "innerwarden agents connect - failed: no guardable agent named `{name}` was found"
                ),
                None => "innerwarden agents connect - no guardable agent found. Run `innerwarden agents` to see what's detected.".into(),
            }],
            configured: 0,
        };
    }
    let results: Vec<ConnectResult> = targets
        .iter()
        .map(|r| connect_one_result(home, r, guard_bin, strict, monitor))
        .collect();
    RunOutcome {
        configured: results.iter().filter(|r| r.configured()).count(),
        lines: results.into_iter().map(|r| r.line).collect(),
    }
}

fn disconnect_lines(home: &Path, target: Option<&str>) -> Vec<String> {
    let rows = rows(home);
    let targets = connect_targets(&rows, target);
    if targets.is_empty() && target.is_some() {
        return vec![format!(
            "innerwarden agents disconnect - failed: no guardable agent named `{}` was found",
            target.unwrap_or_default()
        )];
    }
    targets.iter().map(|r| disconnect_one(home, r)).collect()
}

/// Validate the small `agents` CLI grammar before policy or third-party files
/// can be changed. Unknown flags are errors: a typo must never silently select
/// enforce mode or broaden an operation to every agent.
pub fn validate_args(args: &[String]) -> Result<(), String> {
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(());
    };
    if matches!(command, "--help" | "-h") {
        return (args.len() == 1)
            .then_some(())
            .ok_or_else(|| "help does not accept additional arguments".to_string());
    }
    if command == "list" {
        return (args.len() == 1)
            .then_some(())
            .ok_or_else(|| "`agents list` does not accept additional arguments".to_string());
    }
    if !matches!(command, "connect" | "disconnect") {
        return Err(format!("unknown agents command `{command}`"));
    }

    let mut target: Option<&str> = None;
    let mut all = false;
    let mut monitor = false;
    let mut strict = false;
    for argument in &args[1..] {
        match argument.as_str() {
            "--all" if !all => all = true,
            "--all" => return Err("`--all` may only be specified once".into()),
            "--monitor" if command == "connect" => monitor = true,
            "--block-review" | "--strict" if command == "connect" => strict = true,
            flag if flag.starts_with('-') => {
                return Err(format!("unknown flag `{flag}` for `agents {command}`"));
            }
            name if target.is_none() => target = Some(name),
            name => {
                return Err(format!(
                    "multiple agent targets are not supported (`{}` and `{name}`)",
                    target.unwrap_or_default()
                ));
            }
        }
    }
    if all && target.is_some() {
        return Err("choose either one agent name or `--all`, not both".into());
    }
    if monitor && strict {
        return Err("`--monitor` cannot be combined with enforcement flags".into());
    }
    Ok(())
}

/// Run `agents [connect|disconnect [--all|<name>]]` using an explicitly selected
/// Community guardrail executable, reporting what the run actually configured.
/// Active Defence uses this entrypoint so it never writes its host-management
/// CLI into a `proxy` / `hook` configuration.
pub fn run_with_guard_bin_outcome(home: &Path, args: &[String], guard_bin: &str) -> RunOutcome {
    if let Err(error) = validate_args(args) {
        return RunOutcome {
            lines: vec![format!("innerwarden agents - failed: {error}")],
            configured: 0,
        };
    }
    match args.first().map(String::as_str) {
        Some("connect") => {
            let rest = &args[1..];
            // `--monitor` records but never blocks; `--block-review`/`--strict` also
            // blocks `review`. The target is the first non-flag arg (else --all).
            let monitor = rest.iter().any(|a| a == "--monitor");
            let strict = rest
                .iter()
                .any(|a| a == "--block-review" || a == "--strict");
            let target = rest
                .iter()
                .find(|a| !a.starts_with("--"))
                .map(String::as_str);
            connect_outcome(home, target, strict, monitor, guard_bin)
        }
        // Only `connect` can leave something newly wired, so every other command
        // reports zero configured integrations and cannot trigger connect-only
        // follow-up advice.
        Some("disconnect") => RunOutcome {
            lines: disconnect_lines(
                home,
                args.get(1)
                    .filter(|a| !a.starts_with("--"))
                    .map(String::as_str),
            ),
            configured: 0,
        },
        _ => RunOutcome {
            lines: list_lines(home),
            configured: 0,
        },
    }
}

/// Lines-only adapter for callers that do not act on what was configured.
pub fn run_with_guard_bin(home: &Path, args: &[String], guard_bin: &str) -> Vec<String> {
    run_with_guard_bin_outcome(home, args, guard_bin).lines
}

/// Community CLI entrypoint: its current executable is the guardrail that agent
/// configurations must launch, so resolving it here is safe and keeps callers
/// simple.
pub fn run_outcome(home: &Path, args: &[String]) -> RunOutcome {
    let bin = guard_bin();
    run_with_guard_bin_outcome(home, args, &bin)
}

/// Lines-only adapter over [`run_outcome`].
pub fn run(home: &Path, args: &[String]) -> Vec<String> {
    run_outcome(home, args).lines
}

/// What the wiring for this agent actually does: record, or block.
///
/// `is_guarded` answers "is it wired". That was the only thing the listing had,
/// so an agent connected with `--monitor` and one connected to block printed the
/// same "✓ guarded" row. Someone who chose monitor deliberately could not
/// confirm it, and someone who believed they were protected could not discover
/// they were only recording.
///
/// `None` means wired but unreadable, which is reported as unknown rather than
/// guessed at in either direction.
fn read_guard_mode(home: &Path, agent: &str) -> Option<GuardMode> {
    let k = canonical(agent)?;
    if k.hookable {
        return read_json(&home.join(".claude/settings.json"))
            .and_then(|v| hook::effective_iwguard_hook_mode(&v))
            .map(|m| match m {
                hook::EffectiveHookMode::Monitor => GuardMode::Monitor,
                hook::EffectiveHookMode::Enforce => GuardMode::Enforce,
                hook::EffectiveHookMode::Mixed => GuardMode::Mixed,
            });
    }
    // MCP wiring carries the mode as the proxy's `--mode` argument.
    let rel = k.mcp_json.or(k.mcp_toml)?;
    let text = std::fs::read_to_string(home.join(rel)).ok()?;
    // `advisory` and `warn` pass everything through; `guard` and `kill` block.
    let recording = text.contains("\"advisory\"") || text.contains("\"warn\"");
    let blocking = text.contains("\"guard\"") || text.contains("\"kill\"");
    match (recording, blocking) {
        (true, false) => Some(GuardMode::Monitor),
        (false, true) => Some(GuardMode::Enforce),
        (true, true) => Some(GuardMode::Mixed),
        // Wrapped by the proxy with no explicit `--mode`, so the proxy's own
        // default applies. That default is `guard`, i.e. it BLOCKS. Reporting
        // this as unknown would be the dangerous direction to be vague in: the
        // whole point of showing the mode is so nobody believes they are only
        // recording while the guard is refusing things.
        (false, false) => Some(GuardMode::Enforce),
    }
}

#[cfg(test)]
mod tests {

    /// `disconnect --all` must not be read as "the agent named --all".
    ///
    /// The `!` in `.filter(|a| !a.starts_with("--"))` is what separates a flag
    /// from a name. A mutant that deleted it survived: nothing asked what
    /// `disconnect --all` does, so inverting the filter passed every test while
    /// turning a disconnect-everything into a lookup for an agent that cannot
    /// exist.
    ///
    /// FAILS ON REVERT: delete the `!`.
    #[test]
    fn disconnect_all_is_a_flag_not_an_agent_name() {
        let home = tempfile::TempDir::new().unwrap();
        let out = run(home.path(), &["disconnect".into(), "--all".into()]);
        let joined = out.join("\n");
        assert!(
            !joined.contains("no guardable agent named `--all`"),
            "--all is a flag; reading it as a name is the mutant that survived:\n{joined}"
        );
    }

    /// A named target that does not exist still says so, or the assertion above
    /// would pass on a function that ignores its argument entirely.
    #[test]
    fn disconnect_a_name_that_does_not_exist_says_which_name() {
        let home = tempfile::TempDir::new().unwrap();
        let out = run(home.path(), &["disconnect".into(), "nope".into()]);
        assert!(
            out.join("\n").contains("no guardable agent named `nope`"),
            "a real name must still be looked up: {out:?}"
        );
    }

    /// The lines-only adapters are the public entry points, and three mutants
    /// survived on them by returning empty or default: nothing called them and
    /// checked the result.
    ///
    /// FAILS ON REVERT: make `run` return `vec![]`, or `run_outcome` return
    /// `Default::default()`.
    #[test]
    fn the_lines_adapters_return_what_the_outcome_carries() {
        let home = tempfile::TempDir::new().unwrap();
        let args = vec!["list".to_string()];

        let outcome = run_outcome(home.path(), &args);
        let lines = run(home.path(), &args);

        assert!(
            !outcome.lines.is_empty(),
            "run_outcome must produce output for `list`, even on an empty home"
        );
        assert_eq!(
            lines, outcome.lines,
            "`run` is the lines-only view of `run_outcome`; returning anything \
             else makes the two entry points disagree"
        );

        let via_bin = run_with_guard_bin(home.path(), &args, "/usr/local/bin/innerwarden");
        assert!(
            !via_bin.is_empty(),
            "run_with_guard_bin must produce the same shape of output"
        );
    }
    /// Absence of a SIGNATURE is not absence of an agent.
    ///
    /// Detection matches known agents by command line, so a bespoke script, a
    /// wrapper or a renamed binary matches nothing while running perfectly.
    /// Saying "no compatible AI agents found" to that reader tells them they
    /// have nothing to guard, which is the opposite of true and the end of the
    /// conversation. Seen on a production host running a hand-written Python
    /// agent.
    #[test]
    fn an_empty_scan_explains_itself_and_says_what_to_do() {
        let text = nothing_detected_lines().join("\n");

        assert!(
            !text.contains("no compatible AI agents found"),
            "the old wording reported absence of an agent when it had only \
             established absence of a signature: {text}"
        );
        assert!(
            text.contains("know by name"),
            "it must say detection is by name, not by presence: {text}"
        );
        assert!(
            text.contains("bespoke") || text.contains("wrapper") || text.contains("renamed"),
            "it must name the case where detection cannot work: {text}"
        );
        assert!(
            text.contains("innerwarden hook"),
            "it must give the reader their next command: {text}"
        );
    }

    use super::*;

    #[test]
    fn empty_or_invalid_openclaw_directory_is_only_a_possible_leftover() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".openclaw")).unwrap();

        let (rows, _) = rows_from_sources(home.path(), &[], None);
        let openclaw = rows.iter().find(|row| row.name == "openclaw").unwrap();
        assert!(!openclaw.installed);
        assert_eq!(openclaw.evidence, vec![DiscoveryEvidence::PossibleLeftover]);

        std::fs::write(
            home.path().join(".openclaw/openclaw.json"),
            "{ truncated: [",
        )
        .unwrap();
        let (rows, _) = rows_from_sources(home.path(), &[], None);
        let openclaw = rows.iter().find(|row| row.name == "openclaw").unwrap();
        assert_eq!(openclaw.evidence, vec![DiscoveryEvidence::PossibleLeftover]);
    }

    #[test]
    fn openclaw_profiles_and_hermes_config_are_configuration_evidence() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".openclaw-work")).unwrap();
        std::fs::write(
            home.path().join(".openclaw-work/openclaw.json"),
            "// profile\n{ gateway: { port: 18789, }, name: 'work' }",
        )
        .unwrap();
        std::fs::create_dir_all(home.path().join(".hermes")).unwrap();
        std::fs::write(
            home.path().join(".hermes/config.yaml"),
            "model: test\nmcp_servers: {}\n",
        )
        .unwrap();

        let (rows, limited) = rows_from_sources(home.path(), &[], None);

        assert!(!limited);
        for name in ["openclaw", "hermes"] {
            let row = rows.iter().find(|row| row.name == name).unwrap();
            assert!(!row.installed, "config alone is not an installed CLI");
            assert_eq!(
                row.evidence,
                vec![DiscoveryEvidence::ConfigurationFile],
                "{name} evidence"
            );
        }
        // Hermes has no reviewed MCP surface, so it stays manual. OpenClaw
        // became guardable on 2026-08-05 once `mcp_wire` could locate a nested
        // `mcp.servers` table; the point of THIS test is that a config file
        // alone is evidence of configuration and not of an installed CLI, which
        // holds for both regardless.
        let hermes = rows.iter().find(|row| row.name == "hermes").unwrap();
        assert!(!hermes.guardable(), "hermes must remain manual");
    }

    #[cfg(unix)]
    #[test]
    fn path_detection_reads_metadata_without_executing_agent_binary() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::TempDir::new().unwrap();
        let bin = home.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let execution_marker = home.path().join("agent-was-executed");
        let executable = bin.join("openclaw");
        std::fs::write(
            &executable,
            format!("#!/bin/sh\ntouch '{}'\n", execution_marker.display()),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();

        let (rows, _) = rows_from_sources(home.path(), &[], Some(bin.as_os_str()));

        let openclaw = rows.iter().find(|row| row.name == "openclaw").unwrap();
        assert!(openclaw.installed);
        assert_eq!(openclaw.evidence, vec![DiscoveryEvidence::ExecutableOnPath]);
        assert!(
            !execution_marker.exists(),
            "discovery executed an agent binary"
        );
    }

    #[test]
    fn process_evidence_detects_hermes_without_granting_guardability() {
        let home = tempfile::TempDir::new().unwrap();
        let running = [("Hermes Agent".to_string(), 91)];

        let (rows, _) = rows_from_sources(home.path(), &running, None);

        let hermes = rows.iter().find(|row| row.name == "hermes").unwrap();
        assert_eq!(hermes.pids, vec![91]);
        assert_eq!(hermes.evidence, vec![DiscoveryEvidence::Process]);
        assert!(!hermes.installed);
        assert!(!hermes.guardable());
    }

    #[test]
    fn generic_mcp_configs_are_discovered_connected_and_reported() {
        let home = tempfile::TempDir::new().unwrap();
        for rel in [".new-agent", ".config/another-agent"] {
            std::fs::create_dir_all(home.path().join(rel)).unwrap();
            std::fs::write(
                home.path().join(rel).join("mcp.json"),
                r#"{"mcpServers":{"local":{"command":"npx","args":["server"]}}}"#,
            )
            .unwrap();
        }
        // Do not crawl project/workspace trees merely because they contain an
        // mcp.json; discovery is intentionally limited to config roots.
        std::fs::create_dir_all(home.path().join("work/project")).unwrap();
        std::fs::write(
            home.path().join("work/project/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"node"}}}"#,
        )
        .unwrap();

        assert_eq!(
            home_mcp_configs(home.path()),
            vec![
                ".config/another-agent/mcp.json".to_string(),
                ".new-agent/mcp.json".to_string()
            ]
        );
        let before = rows(home.path());
        let generic: Vec<_> = before
            .iter()
            .filter(|row| row.name == "another-agent" || row.name == "new-agent")
            .collect();
        assert_eq!(generic.len(), 2);
        assert!(generic.iter().all(|row| {
            row.guardable()
                && !row.guarded
                && !row.installed
                && row.evidence == vec![DiscoveryEvidence::CompatibleMcpConfiguration]
        }));

        for row in generic {
            let line = connect_one(home.path(), row, "/abs/innerwarden", false, true);
            assert!(line.contains("connected"), "{line}");
        }
        let after = rows(home.path());
        assert!(after
            .iter()
            .filter(|row| row.name == "another-agent" || row.name == "new-agent")
            .all(|row| row.guarded && has_guard_wiring(home.path(), &row.name)));
    }

    /// A guardable agent that needs nothing installed on the host running the
    /// suite: a recognizable MCP configuration under a disposable HOME.
    fn a_generic_mcp_agent(home: &Path) {
        std::fs::create_dir_all(home.join(".new-agent")).unwrap();
        std::fs::write(
            home.join(".new-agent/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"node"}}}"#,
        )
        .unwrap();
    }

    /// The structured signal a caller needs in order to say "restart your
    /// agents" without scanning the human-facing lines for a word.
    ///
    /// One NAMED target, so the count is exact and does not depend on which
    /// agents happen to be installed on the machine running the suite.
    ///
    /// The direction a scan gets wrong is asserted directly: re-running
    /// `connect` over an already-wired integration prints `already guarded
    /// (...)`, which does NOT contain the word "connected" while the integration
    /// is very much configured. Counting by `contains("connected")` reports zero
    /// there, and the caller stays silent about the restart.
    #[test]
    fn an_already_wired_integration_still_counts_as_configured() {
        let home = tempfile::TempDir::new().unwrap();
        a_generic_mcp_agent(home.path());
        let args = vec!["connect".into(), "new-agent".into(), "--monitor".into()];

        let first = run_with_guard_bin_outcome(home.path(), &args, "/abs/innerwarden");
        assert_eq!(first.lines.len(), 1, "{:?}", first.lines);
        assert_eq!(first.configured, 1, "{:?}", first.lines);

        let again = run_with_guard_bin_outcome(home.path(), &args, "/abs/innerwarden");
        assert_eq!(again.lines.len(), 1, "{:?}", again.lines);
        assert!(
            again.lines[0].contains("already guarded"),
            "this test only proves something while the second connect reports \
             the unchanged wording: {:?}",
            again.lines
        );
        assert!(
            !again.lines[0].contains("connected"),
            "and only while that wording lacks the word a naive scan keys on: {:?}",
            again.lines
        );
        assert_eq!(
            again.configured, 1,
            "an integration that is already wired IS configured; counting by \
             scanning the line reports zero here: {:?}",
            again.lines
        );
    }

    /// `disconnect` unwires, so it configures nothing and a caller keying on the
    /// count cannot tell someone to restart after they deliberately unwired.
    /// Its `was not connected` line CONTAINS the word a naive scan keys on.
    #[test]
    fn disconnect_configures_nothing_even_when_its_lines_say_connected() {
        let home = tempfile::TempDir::new().unwrap();
        a_generic_mcp_agent(home.path());

        let outcome = run_with_guard_bin_outcome(
            home.path(),
            &["disconnect".into(), "new-agent".into()],
            "/abs/innerwarden",
        );
        assert_eq!(outcome.configured, 0, "{:?}", outcome.lines);
        assert!(
            outcome.lines.iter().any(|line| line.contains("connected")),
            "this test only proves something while a disconnect line carries \
             the word a naive scan keys on: {:?}",
            outcome.lines
        );

        let listed = run_with_guard_bin_outcome(home.path(), &["list".into()], "/abs/innerwarden");
        assert_eq!(listed.configured, 0, "listing configures nothing");
    }

    /// A `connect` that found nothing to wire configured nothing.
    #[test]
    fn a_connect_with_no_guardable_target_configures_nothing() {
        let home = tempfile::TempDir::new().unwrap();

        let outcome = run_with_guard_bin_outcome(
            home.path(),
            &["connect".into(), "no-such-agent".into()],
            "/abs/innerwarden",
        );

        assert_eq!(outcome.configured, 0, "{:?}", outcome.lines);
    }

    #[test]
    fn generic_discovery_reports_when_the_aggregate_byte_budget_is_limited() {
        let home = tempfile::TempDir::new().unwrap();
        for name in [
            ".large-one",
            ".large-two",
            ".large-three",
            ".large-four",
            ".large-five",
        ] {
            let directory = home.path().join(name);
            std::fs::create_dir_all(&directory).unwrap();
            let file = std::fs::File::create(directory.join("mcp.json")).unwrap();
            file.set_len(15 * 1024 * 1024).unwrap();
        }

        let discovery = home_mcp_configs_with_status(home.path());

        assert!(discovery.limited);
        assert_eq!(discovery.paths.len(), 4);
        assert!(!discovery.paths.contains(&".large-two/mcp.json".into()));
    }

    #[test]
    fn known_mcp_path_does_not_create_a_duplicate_generic_row() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(
            home.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"npx"}}}"#,
        )
        .unwrap();
        let found = rows(home.path());
        assert_eq!(found.iter().filter(|row| row.name == "cursor").count(), 1);
        assert!(found.iter().all(|row| row.name != "cursor-mcp"));
    }

    #[test]
    fn generic_config_cannot_impersonate_a_known_agent_name() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".config/cursor")).unwrap();
        std::fs::write(
            home.path().join(".config/cursor/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"npx"}}}"#,
        )
        .unwrap();
        let before = rows(home.path());
        let generic = before
            .iter()
            .find(|row| row.mcp_json.as_deref() == Some(".config/cursor/mcp.json"))
            .unwrap();
        assert_eq!(generic.name, "cursor-mcp");
        assert!(!has_guard_wiring(home.path(), &generic.name));

        let result = connect_one_result(home.path(), generic, "/abs/innerwarden", false, true);
        assert_eq!(result.effect, ConnectEffect::Connected);
        assert!(has_guard_wiring(home.path(), "cursor-mcp"));
    }

    #[test]
    fn unreviewed_aider_shaped_mcp_file_stays_a_generic_manual_client() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".config/aider")).unwrap();
        std::fs::write(
            home.path().join(".config/aider/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"aider-mcp"}}}"#,
        )
        .unwrap();
        let found = rows(home.path());
        assert!(found.iter().all(|row| row.name != "aider"));
        let generic = found.iter().find(|row| row.name == "aider-mcp").unwrap();
        assert!(!generic.installed);
        assert_eq!(
            generic.evidence,
            vec![DiscoveryEvidence::CompatibleMcpConfiguration]
        );
        assert_eq!(generic.mcp_json.as_deref(), Some(".config/aider/mcp.json"));
    }

    #[test]
    fn arbitrary_file_named_mcp_json_is_not_capability_evidence() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".not-an-agent")).unwrap();
        std::fs::write(
            home.path().join(".not-an-agent/mcp.json"),
            r#"{"theme":"dark"}"#,
        )
        .unwrap();

        let (rows, _) = rows_from_sources(home.path(), &[], None);

        assert!(rows.iter().all(|row| row.name != "not-an-agent"));
    }

    #[test]
    fn nested_mcp_servers_are_visible_but_never_gain_connect_authority() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".nested-agent")).unwrap();
        std::fs::write(
            home.path().join(".nested-agent/mcp.json"),
            r#"{"mcp":{"servers":{"local":{"command":"npx"}}}}"#,
        )
        .unwrap();

        let (rows, _) = rows_from_sources(home.path(), &[], None);

        let nested = rows.iter().find(|row| row.name == "nested-agent").unwrap();
        assert_eq!(
            nested.evidence,
            vec![DiscoveryEvidence::CompatibleMcpConfiguration]
        );
        assert!(!nested.installed);
        assert!(!nested.guardable());
        assert!(connect_targets(&rows, Some("nested-agent")).is_empty());
    }

    #[test]
    fn partial_json_and_toml_wiring_is_still_discoverable_for_repair() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(
            home.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"guarded":{"command":"innerwarden","args":["proxy","--mode","advisory","--","npx","one"]},"late":{"command":"npx","args":["two"]}}}"#,
        )
        .unwrap();
        assert!(has_guard_wiring(home.path(), "cursor"));
        assert!(!is_guarded(home.path(), "cursor"));

        std::fs::create_dir_all(home.path().join(".codex")).unwrap();
        std::fs::write(
            home.path().join(".codex/config.toml"),
            "[mcp_servers.guarded]\ncommand = \"innerwarden\"\nargs = [\"proxy\", \"--\", \"npx\"]\n\n[mcp_servers.late]\ncommand = \"node\"\n",
        )
        .unwrap();
        assert!(has_guard_wiring(home.path(), "codex"));
        assert!(!is_guarded(home.path(), "codex"));
    }

    #[test]
    fn unknown_connect_flag_fails_without_wiring_every_agent() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        let original = r#"{"mcpServers":{"local":{"command":"npx"}}}"#;
        std::fs::write(home.path().join(".cursor/mcp.json"), original).unwrap();

        let output = run_with_guard_bin(
            home.path(),
            &["connect".into(), "--monitro".into()],
            "/abs/innerwarden",
        );
        assert!(output.iter().any(|line| line.contains("failed:")));
        assert_eq!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap(),
            original
        );
    }

    #[test]
    fn unknown_disconnect_flag_fails_without_broadening_to_all() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(
            home.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"npx"}}}"#,
        )
        .unwrap();
        let row = rows(home.path())
            .into_iter()
            .find(|agent| agent.name == "cursor")
            .unwrap();
        assert!(
            connect_one_result(home.path(), &row, "/abs/innerwarden", false, true).configured()
        );

        let output = run_with_guard_bin(
            home.path(),
            &["disconnect".into(), "--al".into()],
            "/abs/innerwarden",
        );
        assert!(output.iter().any(|line| line.contains("failed:")));
        assert!(is_guarded(home.path(), "cursor"));
    }

    #[test]
    fn automatic_connect_rechecks_structure_and_existing_wiring_from_exact_bytes() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        let invalid = r#"{"mcpServers":{"local":{"command":"npx","args":"--foo"}}}"#;
        std::fs::write(home.path().join(".cursor/mcp.json"), invalid).unwrap();
        let row = rows(home.path())
            .into_iter()
            .find(|agent| agent.name == "cursor")
            .unwrap();
        let result =
            connect_one_result_automatic(home.path(), &row, "/abs/innerwarden", false, true);
        assert_eq!(result.effect, ConnectEffect::Skipped);
        assert_eq!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap(),
            invalid
        );

        let existing = r#"{"mcpServers":{"local":{"command":"innerwarden","args":["proxy","--mode","guard","--","npx"]}}}"#;
        std::fs::write(home.path().join(".cursor/mcp.json"), existing).unwrap();
        let row = rows(home.path())
            .into_iter()
            .find(|agent| agent.name == "cursor")
            .unwrap();
        let result =
            connect_one_result_automatic(home.path(), &row, "/abs/innerwarden", false, true);
        assert_eq!(result.effect, ConnectEffect::Skipped);
        assert_eq!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap(),
            existing
        );
    }
}
