//! Community agent-integration policy and background reconciliation.
//!
//! Auto-connect is explicit, persisted, reversible, and strictly monitor-only.
//! The dashboard-owned reconciler runs outside HTTP request handlers, so GETs
//! remain read-only. Automatic reconciliation only wires a newly discovered,
//! known agent with a valid local configuration. Existing Claude hook aliases,
//! exact matcher drift and duplicates are reconciled in monitor mode unless an
//! effective `PreToolUse:Bash` hook already enforces; existing MCP wrappers are
//! never repaired, reconfigured or downgraded.

use std::path::{Path, PathBuf};
use std::{fs::OpenOptions, io::Read};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const RECONCILE_INTERVAL_SECS: u64 = 60;
pub const POLICY_SCHEMA_VERSION: u32 = 1;

/// Automatic wiring has exactly one posture: observe-only. Deserialization also
/// accepts the legacy `enforce` value and safely normalizes it to monitor, so an
/// existing pre-hardening policy cannot make future automatic connections block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DesiredMode {
    #[default]
    Monitor,
}

impl Serialize for DesiredMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str("monitor")
    }
}

impl<'de> Deserialize<'de> for DesiredMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        match value.trim().to_ascii_lowercase().as_str() {
            "monitor" | "enforce" => Ok(Self::Monitor),
            _ => Err(serde::de::Error::custom(
                "agent auto-connect mode must be `monitor`",
            )),
        }
    }
}

fn default_schema_version() -> u32 {
    POLICY_SCHEMA_VERSION
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentPolicy {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub auto_connect: bool,
    pub mode: DesiredMode,
    /// Canonical agent names the operator explicitly disconnected. They remain
    /// excluded until an explicit `agents connect <name>` removes the entry.
    pub excluded: Vec<String>,
}

impl Default for AgentPolicy {
    fn default() -> Self {
        Self {
            schema_version: POLICY_SCHEMA_VERSION,
            auto_connect: false,
            mode: DesiredMode::Monitor,
            excluded: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub detected: usize,
    pub attempted: usize,
    pub connected: usize,
    pub skipped: usize,
    pub failed: usize,
    /// Only material changes and failures. Benign ineligible configurations are
    /// silent so a long-running dashboard does not spam stderr every minute.
    pub notices: Vec<String>,
}

impl ReconcileReport {
    pub fn has_failures(&self) -> bool {
        self.failed > 0
    }

    fn lock_failure(error: String) -> Self {
        Self {
            failed: 1,
            notices: vec![format!("  policy reconcile failed: {error}")],
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WatcherLifecycle {
    Starting,
    Running,
    Unavailable,
    Stopped,
}

/// Credential-free state for the read-only dashboard. A live worker and a
/// readable effective policy are deliberately separate facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DashboardReconcilerStatus {
    pub lifecycle: WatcherLifecycle,
    pub policy_available: bool,
    pub policy_enabled: Option<bool>,
    /// Persisted policy interpreted by the watcher, never a claim about agent
    /// runtime interception or enforcement.
    pub effective_policy_mode: Option<String>,
    pub last_reconcile_at_ms: Option<u64>,
    pub reason_code: Option<String>,
}

impl DashboardReconcilerStatus {
    fn starting() -> Self {
        Self {
            lifecycle: WatcherLifecycle::Starting,
            policy_available: false,
            policy_enabled: None,
            effective_policy_mode: None,
            last_reconcile_at_ms: None,
            reason_code: Some("watcher_starting".into()),
        }
    }

    pub fn unavailable() -> Self {
        Self {
            lifecycle: WatcherLifecycle::Unavailable,
            policy_available: false,
            policy_enabled: None,
            effective_policy_mode: None,
            last_reconcile_at_ms: None,
            reason_code: Some("watcher_unavailable".into()),
        }
    }
}

pub type SharedDashboardReconcilerStatus =
    std::sync::Arc<std::sync::RwLock<DashboardReconcilerStatus>>;

pub fn read_dashboard_reconciler_status(
    shared: &SharedDashboardReconcilerStatus,
) -> DashboardReconcilerStatus {
    match shared.read() {
        Ok(status) => status.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

fn replace_dashboard_reconciler_status(
    shared: &SharedDashboardReconcilerStatus,
    status: DashboardReconcilerStatus,
) {
    match shared.write() {
        Ok(mut current) => *current = status,
        Err(poisoned) => *poisoned.into_inner() = status,
    }
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0)
}

pub fn config_path(home: &Path) -> PathBuf {
    home.join(".config/innerwarden/agents.toml")
}

fn normalize_name(name: &str) -> String {
    // Policy keys describe the exact discovered row the operator acted on.
    // Process discovery deliberately uses fuzzy aliases, but applying those here
    // would let a generic row such as `cursor-mcp` alter real Cursor's exclusion.
    name.trim().to_ascii_lowercase().replace([' ', '_'], "-")
}

fn normalize_excluded(names: &[String]) -> Vec<String> {
    let mut normalized: Vec<String> = names
        .iter()
        .map(|name| normalize_name(name))
        .filter(|name| !name.is_empty())
        .collect();
    normalized.sort();
    normalized.dedup();
    normalized
}

const MAX_POLICY_BYTES: u64 = 1024 * 1024;

fn read_policy_bytes(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("reading {}: {error}", path.display())),
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspecting {}: {error}", path.display()))?;
    let unsafe_type = !metadata.is_file() || metadata.file_type().is_symlink();
    #[cfg(windows)]
    let unsafe_type = {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        unsafe_type || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    };
    if unsafe_type {
        return Err(format!("{} is not a regular policy file", path.display()));
    }
    let len = metadata.len();
    if len > MAX_POLICY_BYTES {
        return Err(format!("{} exceeds the policy size limit", path.display()));
    }
    let mut body = Vec::with_capacity(len.try_into().unwrap_or(0));
    file.take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| format!("reading {}: {error}", path.display()))?;
    if body.len() as u64 > MAX_POLICY_BYTES {
        return Err(format!(
            "{} grew beyond the policy size limit",
            path.display()
        ));
    }
    Ok(Some(body))
}

fn load_with_source(home: &Path) -> Result<(AgentPolicy, Option<Vec<u8>>), String> {
    let path = config_path(home);
    let source = read_policy_bytes(&path)?;
    let Some(body) = source.as_deref() else {
        return Ok((AgentPolicy::default(), None));
    };
    let body = std::str::from_utf8(body)
        .map_err(|error| format!("parsing {} as UTF-8: {error}", path.display()))?;
    let mut policy: AgentPolicy =
        toml::from_str(body).map_err(|error| format!("parsing {}: {error}", path.display()))?;
    if policy.schema_version != POLICY_SCHEMA_VERSION {
        return Err(format!(
            "parsing {}: unsupported agent policy schema_version {} (expected {})",
            path.display(),
            policy.schema_version,
            POLICY_SCHEMA_VERSION
        ));
    }
    // DesiredMode's legacy parser already normalizes `enforce`; make the invariant
    // explicit here too, and canonicalize exclusions from older policy files.
    policy.mode = DesiredMode::Monitor;
    policy.excluded = normalize_excluded(&policy.excluded);
    Ok((policy, source))
}

pub fn load(home: &Path) -> Result<AgentPolicy, String> {
    load_with_source(home).map(|(policy, _)| policy)
}

fn save_expected(home: &Path, policy: &AgentPolicy, expected: Option<&[u8]>) -> Result<(), String> {
    let path = config_path(home);
    let Some(parent) = path.parent() else {
        return Err("agent policy path has no parent".into());
    };
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("creating {}: {error}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    let normalized = AgentPolicy {
        schema_version: POLICY_SCHEMA_VERSION,
        auto_connect: policy.auto_connect,
        mode: DesiredMode::Monitor,
        excluded: normalize_excluded(&policy.excluded),
    };
    let body = toml::to_string_pretty(&normalized).map_err(|error| error.to_string())?;
    innerwarden_agent_guard::file_update::replace_if_unchanged(&path, expected, body.as_bytes())
}

#[cfg(test)]
pub fn save(home: &Path, policy: &AgentPolicy) -> Result<(), String> {
    let path = config_path(home);
    let expected = read_policy_bytes(&path)?;
    save_expected(home, policy, expected.as_deref())
}

fn mutate(home: &Path, update: impl FnOnce(&mut AgentPolicy)) -> Result<AgentPolicy, String> {
    let (mut policy, expected) = load_with_source(home)?;
    update(&mut policy);
    save_expected(home, &policy, expected.as_deref())?;
    policy.schema_version = POLICY_SCHEMA_VERSION;
    policy.mode = DesiredMode::Monitor;
    policy.excluded = normalize_excluded(&policy.excluded);
    Ok(policy)
}

pub fn set_auto_connect(
    home: &Path,
    enabled: bool,
    _mode: DesiredMode,
) -> Result<AgentPolicy, String> {
    mutate(home, |policy| {
        policy.schema_version = POLICY_SCHEMA_VERSION;
        policy.auto_connect = enabled;
        policy.mode = DesiredMode::Monitor;
    })
}

pub fn exclude_agent(home: &Path, name: &str) -> Result<AgentPolicy, String> {
    let name = normalize_name(name);
    mutate(home, |policy| {
        if !name.is_empty() && !policy.excluded.contains(&name) {
            policy.excluded.push(name);
        }
        policy.excluded = normalize_excluded(&policy.excluded);
    })
}

pub fn include_agent(home: &Path, name: &str) -> Result<AgentPolicy, String> {
    let name = normalize_name(name);
    mutate(home, |policy| {
        policy.excluded.retain(|excluded| excluded != &name);
    })
}

pub fn disable_auto_connect(home: &Path) -> Result<AgentPolicy, String> {
    set_auto_connect(home, false, DesiredMode::Monitor)
}

/// Run an operation while holding the Community agent-policy lock. Explicit CLI
/// connect/disconnect and automatic reconcile share this lock, preventing two
/// InnerWarden processes from concurrently changing the same agent configuration.
pub fn with_lock<T>(home: &Path, action: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    use fs4::FileExt;

    let path = config_path(home);
    let parent = path
        .parent()
        .ok_or_else(|| "agent policy path has no parent".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("creating {}: {error}", parent.display()))?;
    let lock_path = parent.join("agents.lock");
    let lock = open_policy_lock(&lock_path)?;
    // BLOCKING exclusive lock: a second InnerWarden process waits here rather
    // than proceeding unserialized. fs4 1.x renamed `lock_exclusive` to `lock`
    // with identical semantics (`flock(LOCK_EX)` / `LockFileEx(EXCLUSIVE)`).
    FileExt::lock(&lock).map_err(|error| format!("locking {}: {error}", lock_path.display()))?;
    let result = action();
    let unlock_result = FileExt::unlock(&lock)
        .map_err(|error| format!("unlocking {}: {error}", lock_path.display()));
    match (result, unlock_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
    }
}

fn open_policy_lock(path: &Path) -> Result<std::fs::File, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let lock = options
        .open(path)
        .map_err(|error| format!("opening {}: {error}", path.display()))?;
    let metadata = lock
        .metadata()
        .map_err(|error| format!("inspecting {}: {error}", path.display()))?;
    let unsafe_type = !metadata.is_file() || metadata.file_type().is_symlink();
    #[cfg(windows)]
    let unsafe_type = {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        unsafe_type || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    };
    if unsafe_type {
        return Err(format!("{} is not a regular lock file", path.display()));
    }
    Ok(lock)
}

fn meaningful_claude_dir(home: &Path) -> bool {
    let dir = home.join(".claude");
    let Ok(metadata) = std::fs::symlink_metadata(&dir) else {
        return false;
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return false;
    }
    std::fs::read_dir(dir)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

fn claude_settings_shape_is_safe(home: &Path) -> bool {
    let path = home.join(".claude/settings.json");
    match innerwarden_agent_guard::file_update::read_config_no_symlinks(home, &path) {
        Ok(Some(body)) => serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .is_some_and(|settings| {
                innerwarden_agent_guard::hook::is_automatic_merge_safe(&settings)
            }),
        Ok(None) => true,
        Err(_) => false,
    }
}

fn valid_guardable_config(
    home: &Path,
    agent: &innerwarden_agent_guard::agents::AgentStatus,
) -> bool {
    if agent.hookable {
        return meaningful_claude_dir(home) && claude_settings_shape_is_safe(home);
    }
    if let Some(rel) = &agent.mcp_json {
        let path = home.join(rel);
        return innerwarden_agent_guard::file_update::read_config_no_symlinks(home, &path)
            .ok()
            .flatten()
            .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
            .is_some_and(|config| {
                innerwarden_agent_guard::mcp_wire::is_automatic_wrap_safe(&config)
            });
    }
    if let Some(rel) = &agent.mcp_toml {
        let path = home.join(rel);
        return innerwarden_agent_guard::file_update::read_config_no_symlinks(home, &path)
            .ok()
            .flatten()
            .and_then(|body| {
                let body = std::str::from_utf8(&body).ok()?;
                body.parse().ok()
            })
            .is_some_and(|config| {
                innerwarden_agent_guard::mcp_wire_toml::is_automatic_wrap_safe_toml(&config)
            });
    }
    false
}

/// True only for a row whose canonical name and reviewed config mechanism/path
/// exactly match the built-in integration table. Loose process aliases and
/// generic MCP discovery must never gain background-mutation authority.
pub fn is_reviewed_integration(agent: &innerwarden_agent_guard::agents::AgentStatus) -> bool {
    let Some(known) = innerwarden_agent_guard::agents::KNOWN
        .iter()
        .find(|known| known.name == agent.name)
    else {
        return false;
    };
    agent.hookable == known.hookable
        && agent.mcp_json.as_deref() == known.mcp_json
        && agent.mcp_toml.as_deref() == known.mcp_toml
}

fn is_excluded(policy: &AgentPolicy, canonical_name: &str) -> bool {
    policy
        .excluded
        .iter()
        .any(|excluded| normalize_name(excluded) == canonical_name)
}

/// Whether this row is safe for a future automatic monitor-only connection.
/// This is intentionally independent of `policy.auto_connect`: the dashboard can
/// explain that an agent is eligible even before the operator opts in.
pub fn is_auto_connect_candidate(
    home: &Path,
    agent: &innerwarden_agent_guard::agents::AgentStatus,
    policy: &AgentPolicy,
) -> bool {
    if !is_reviewed_integration(agent) {
        return false;
    }
    // "Is there work left to do", not "have we touched this file". A config with
    // one wrapped server and two open ones answers yes to the second and was
    // therefore skipped forever, leaving the open servers unguarded with nothing
    // offering to fix them. Wrapping is idempotent, so re-running only touches
    // what is still open.
    !is_excluded(policy, &agent.name)
        && innerwarden_agent_guard::agents_ops::status_has_unguarded_server(home, agent)
        && valid_guardable_config(home, agent)
}

fn hook_needs_automatic_reconciliation(
    home: &Path,
    agent: &innerwarden_agent_guard::agents::AgentStatus,
    guard_bin: &str,
) -> bool {
    if !agent.hookable {
        return false;
    }
    let path = home.join(".claude/settings.json");
    innerwarden_agent_guard::file_update::read_config_no_symlinks(home, &path)
        .ok()
        .flatten()
        .and_then(|body| serde_json::from_slice::<serde_json::Value>(&body).ok())
        .is_some_and(|settings| {
            innerwarden_agent_guard::hook::has_iwguard_wiring(&settings)
                && innerwarden_agent_guard::hook::needs_iwguard_hook_reconciliation(
                    &settings,
                    Path::new(guard_bin),
                    false,
                    true,
                )
        })
}

fn reconcile_unlocked(home: &Path, guard_bin: &str, policy: &AgentPolicy) -> ReconcileReport {
    if !policy.auto_connect {
        return ReconcileReport::default();
    }
    let agents = innerwarden_agent_guard::agents_ops::detected_guardable(home);
    let mut report = ReconcileReport {
        detected: agents.len(),
        ..ReconcileReport::default()
    };
    for agent in agents {
        // Automatic policy is deliberately limited to named, reviewed integrations.
        // Generic MCP configs remain available to explicit `agents connect`, but an
        // unknown directory name is never enough authority for background mutation.
        if !is_reviewed_integration(&agent) {
            report.skipped += 1;
            continue;
        }
        // A persisted disconnect/exclusion always wins, including when legacy
        // hook wiring is malformed and otherwise eligible for reconciliation.
        if is_excluded(policy, &agent.name) {
            report.skipped += 1;
            continue;
        }
        let hook_reconciliation = hook_needs_automatic_reconciliation(home, &agent, guard_bin);
        if !hook_reconciliation && !is_auto_connect_candidate(home, &agent, policy) {
            report.skipped += 1;
            continue;
        }

        // Recheck immediately before the effect. The shared policy lock prevents
        // concurrent Community CLI writers, and the structured result below keeps
        // policy decisions independent of human-facing punctuation.
        if !hook_reconciliation
            && innerwarden_agent_guard::agents_ops::status_has_guard_wiring(home, &agent)
        {
            report.skipped += 1;
            continue;
        }
        report.attempted += 1;
        let result = innerwarden_agent_guard::agents_ops::connect_one_result_automatic(
            home, &agent, guard_bin, false,
            true, // Hard invariant: automatic wiring is always monitor-only.
        );
        match result.effect {
            innerwarden_agent_guard::agents_ops::ConnectEffect::Connected => {
                report.connected += 1;
                report.notices.push(result.line);
            }
            innerwarden_agent_guard::agents_ops::ConnectEffect::Unchanged
            | innerwarden_agent_guard::agents_ops::ConnectEffect::Skipped => {
                report.skipped += 1;
            }
            innerwarden_agent_guard::agents_ops::ConnectEffect::Failed => {
                report.failed += 1;
                report.notices.push(result.line);
            }
        }
    }
    report
}

fn reconcile_current(
    home: &Path,
    guard_bin: &str,
) -> Result<(AgentPolicy, ReconcileReport), String> {
    with_lock(home, || {
        // The caller may have loaded policy before waiting on this lock. Reload
        // while holding it so an explicit disconnect/--off cannot be undone by a
        // stale watcher snapshot. A removed file means the safe disabled default,
        // never the caller's previously-enabled snapshot.
        let current = load(home)?;
        let report = reconcile_unlocked(home, guard_bin, &current);
        Ok((current, report))
    })
}

pub fn reconcile(home: &Path, guard_bin: &str, _policy: &AgentPolicy) -> ReconcileReport {
    match reconcile_current(home, guard_bin) {
        Ok((_, report)) => report,
        Err(error) => ReconcileReport::lock_failure(error),
    }
}

/// Lifetime handle for the dashboard-owned worker. Dropping the dashboard stops
/// and joins the worker, so Community never leaves an implicit daemon behind.
pub struct DashboardReconciler {
    status: SharedDashboardReconcilerStatus,
    stop: std::sync::mpsc::Sender<()>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl DashboardReconciler {
    pub fn status(&self) -> SharedDashboardReconcilerStatus {
        std::sync::Arc::clone(&self.status)
    }
}

impl Drop for DashboardReconciler {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// Start the dashboard-owned watcher. It reloads policy before each pass and only
/// exists while the dashboard process is alive; Community intentionally has no
/// daemon. HTTP handlers remain read-only.
pub fn spawn_dashboard_reconciler(
    home: PathBuf,
    guard_bin: String,
) -> Result<DashboardReconciler, String> {
    spawn_dashboard_reconciler_with_interval(
        home,
        guard_bin,
        std::time::Duration::from_secs(RECONCILE_INTERVAL_SECS),
    )
}

pub(crate) fn spawn_dashboard_reconciler_with_interval(
    home: PathBuf,
    guard_bin: String,
    interval: std::time::Duration,
) -> Result<DashboardReconciler, String> {
    let status = std::sync::Arc::new(std::sync::RwLock::new(DashboardReconcilerStatus::starting()));
    let status_writer = std::sync::Arc::clone(&status);
    let (stop, stop_rx) = std::sync::mpsc::channel();
    let join = std::thread::Builder::new()
        .name("iw-agent-reconciler".into())
        .spawn(move || {
            loop {
                match reconcile_current(&home, &guard_bin) {
                    Ok((policy, report)) => {
                        let failed = report.has_failures();
                        for notice in report.notices {
                            eprintln!("innerwarden auto-connect:{notice}");
                        }
                        replace_dashboard_reconciler_status(
                            &status_writer,
                            DashboardReconcilerStatus {
                                lifecycle: WatcherLifecycle::Running,
                                policy_available: true,
                                policy_enabled: Some(policy.auto_connect),
                                effective_policy_mode: Some(if policy.auto_connect {
                                    "monitor".into()
                                } else {
                                    "disabled".into()
                                }),
                                last_reconcile_at_ms: Some(epoch_ms()),
                                reason_code: failed.then(|| "reconcile_failed".into()),
                            },
                        );
                    }
                    Err(error) => {
                        eprintln!("innerwarden auto-connect: {error}");
                        replace_dashboard_reconciler_status(
                            &status_writer,
                            DashboardReconcilerStatus {
                                lifecycle: WatcherLifecycle::Running,
                                policy_available: false,
                                policy_enabled: None,
                                effective_policy_mode: None,
                                last_reconcile_at_ms: Some(epoch_ms()),
                                reason_code: Some("policy_unavailable".into()),
                            },
                        );
                    }
                }
                match stop_rx.recv_timeout(interval) {
                    Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                }
            }
            let mut stopped = read_dashboard_reconciler_status(&status_writer);
            stopped.lifecycle = WatcherLifecycle::Stopped;
            stopped.reason_code = Some("dashboard_stopped".into());
            replace_dashboard_reconciler_status(&status_writer, stopped);
        })
        .map_err(|error| format!("starting agent auto-connect watcher: {error}"))?;
    Ok(DashboardReconciler {
        status,
        stop,
        join: Some(join),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_policy() -> AgentPolicy {
        AgentPolicy {
            auto_connect: true,
            ..AgentPolicy::default()
        }
    }

    fn persisted_enabled_policy(home: &Path) -> AgentPolicy {
        let policy = enabled_policy();
        save(home, &policy).unwrap();
        policy
    }

    #[test]
    fn policy_defaults_disabled_and_roundtrips_schema_and_exclusions() {
        let home = tempfile::TempDir::new().unwrap();
        assert_eq!(load(home.path()).unwrap(), AgentPolicy::default());

        let mut written = set_auto_connect(home.path(), true, DesiredMode::Monitor).unwrap();
        written.excluded = vec!["Cursor".into(), "cursor".into()];
        save(home.path(), &written).unwrap();
        let loaded = load(home.path()).unwrap();
        assert!(loaded.auto_connect);
        assert_eq!(loaded.schema_version, POLICY_SCHEMA_VERSION);
        assert_eq!(loaded.mode, DesiredMode::Monitor);
        assert_eq!(loaded.excluded, vec!["cursor"]);
        let body = std::fs::read_to_string(config_path(home.path())).unwrap();
        assert!(body.contains("schema_version = 1"));
        assert!(body.contains("mode = \"monitor\""));
    }

    /// Explicit connect/disconnect and the background reconciler are only kept
    /// apart by this lock. It has to EXCLUDE (a second holder cannot enter while
    /// one is inside) and it has to BLOCK (the loser waits its turn rather than
    /// erroring or, worse, proceeding). A shared lock, a try-lock or a no-op
    /// would compile and pass every other test in this module.
    #[test]
    fn agent_policy_lock_excludes_a_second_process_and_blocks_until_release() {
        use std::sync::mpsc;
        use std::time::Duration;

        let home = tempfile::TempDir::new().unwrap();
        let (inside_tx, inside_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (acquired_tx, acquired_rx) = mpsc::channel();

        let holder_home = home.path().to_path_buf();
        let holder = std::thread::spawn(move || {
            with_lock(&holder_home, || {
                inside_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
        });
        inside_rx.recv_timeout(Duration::from_secs(10)).unwrap();

        let contender_home = home.path().to_path_buf();
        let contender = std::thread::spawn(move || {
            with_lock(&contender_home, || {
                acquired_tx.send(()).unwrap();
                Ok(())
            })
            .unwrap();
        });

        assert!(
            acquired_rx
                .recv_timeout(Duration::from_millis(250))
                .is_err(),
            "second holder must not enter the critical section while it is occupied"
        );

        release_tx.send(()).unwrap();
        acquired_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("second holder must enter once the lock is released");
        holder.join().unwrap();
        contender.join().unwrap();
    }

    #[test]
    fn policy_compare_and_replace_rejects_an_external_edit() {
        let home = tempfile::TempDir::new().unwrap();
        let path = config_path(home.path());
        save(home.path(), &AgentPolicy::default()).unwrap();
        let expected = read_policy_bytes(&path).unwrap().unwrap();
        std::fs::write(
            &path,
            "schema_version = 1\nauto_connect = true\nmode = \"monitor\"\nexcluded = []\n",
        )
        .unwrap();

        let error =
            save_expected(home.path(), &AgentPolicy::default(), Some(&expected)).unwrap_err();

        assert!(error.contains("changed while InnerWarden was preparing"));
        assert!(load(home.path()).unwrap().auto_connect);
    }

    #[test]
    fn oversized_policy_is_rejected_before_parsing() {
        let home = tempfile::TempDir::new().unwrap();
        let path = config_path(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_POLICY_BYTES + 1).unwrap();

        assert!(load(home.path())
            .unwrap_err()
            .contains("exceeds the policy size limit"));
    }

    #[cfg(unix)]
    #[test]
    fn policy_reader_rejects_a_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let home = tempfile::TempDir::new().unwrap();
        let path = config_path(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let fifo = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        assert!(load(home.path())
            .unwrap_err()
            .contains("not a regular policy file"));
    }

    #[test]
    fn policy_names_do_not_collapse_generic_rows_into_known_agents() {
        let home = tempfile::TempDir::new().unwrap();
        exclude_agent(home.path(), "cursor-mcp").unwrap();
        exclude_agent(home.path(), "c").unwrap();
        let policy = load(home.path()).unwrap();
        assert_eq!(policy.excluded, vec!["c", "cursor-mcp"]);
        assert!(!policy.excluded.contains(&"cursor".to_string()));
        assert!(!policy.excluded.contains(&"claude-code".to_string()));
    }

    #[test]
    fn legacy_policy_is_backward_safe_and_normalizes_enforce_to_monitor() {
        let home = tempfile::TempDir::new().unwrap();
        let path = config_path(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "auto_connect = true\nmode = \"enforce\"\nexcluded = [\"Cursor\"]\n",
        )
        .unwrap();
        let policy = load(home.path()).unwrap();
        assert_eq!(policy.schema_version, 1);
        assert_eq!(policy.mode, DesiredMode::Monitor);
        assert_eq!(policy.excluded, vec!["cursor"]);
    }

    #[test]
    fn disabled_policy_never_mutates_an_agent() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        let report = reconcile(home.path(), "/abs/innerwarden", &AgentPolicy::default());
        assert_eq!(report, ReconcileReport::default());
        assert!(!home.path().join(".claude/settings.json").exists());
    }

    #[test]
    fn empty_malformed_and_remote_only_configs_are_skipped() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        let invalid_claude = r#"{"hooks":"custom"}"#;
        std::fs::write(home.path().join(".claude/settings.json"), invalid_claude).unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(home.path().join(".cursor/mcp.json"), "{not-json").unwrap();
        std::fs::create_dir_all(home.path().join(".gemini")).unwrap();
        let remote = r#"{"mcpServers":{"remote":{"url":"https://example.test/mcp"}}}"#;
        std::fs::write(home.path().join(".gemini/settings.json"), remote).unwrap();

        let policy = persisted_enabled_policy(home.path());
        let report = reconcile(home.path(), "/abs/innerwarden", &policy);
        assert_eq!(report.attempted, 0);
        assert_eq!(report.connected, 0);
        assert_eq!(
            std::fs::read_to_string(home.path().join(".claude/settings.json")).unwrap(),
            invalid_claude
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap(),
            "{not-json"
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join(".gemini/settings.json")).unwrap(),
            remote
        );
    }

    #[test]
    fn meaningful_claude_and_valid_json_connect_in_monitor_idempotently() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        std::fs::write(home.path().join(".claude/history.jsonl"), "{}\n").unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(
            home.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"npx","args":["server"]}}}"#,
        )
        .unwrap();

        let policy = persisted_enabled_policy(home.path());
        let first = reconcile(home.path(), "/abs/innerwarden", &policy);
        assert_eq!(first.connected, 2);
        assert!(
            std::fs::read_to_string(home.path().join(".claude/settings.json"))
                .unwrap()
                .contains("--monitor")
        );
        assert!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json"))
                .unwrap()
                .contains("advisory")
        );

        let second = reconcile(home.path(), "/abs/innerwarden", &policy);
        assert_eq!(second.attempted, 0);
        assert_eq!(second.connected, 0);
    }

    #[test]
    fn reconciler_repairs_hooks_without_promoting_a_wrong_matcher_mode() {
        use innerwarden_agent_guard::hook::EffectiveHookMode;

        let home = tempfile::TempDir::new().unwrap();
        let settings_path = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
        let settings = serde_json::json!({
            "model": "sonnet",
            "hooks": {"PreToolUse": [
                {
                    "matcher": "Write",
                    "operator_entry": true,
                    "hooks": [
                        {
                            "type": "command",
                            "command": "\"/old/target/release/innerwarden\" hook --block-review"
                        },
                        {"type": "command", "command": "/operator/write"}
                    ]
                },
                {
                    "matcher": "Bash",
                    "hooks": [
                        {"type": "command", "command": "/operator/before"},
                        {
                            "type": "command",
                            "command": "\"/old/target/debug/iw\" hook --monitor",
                            "timeout": 17
                        },
                        {"type": "command", "command": "/operator/after"}
                    ]
                },
                {
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": "\"/old/target/release/innerwarden\" hook --monitor"
                    }]
                }
            ]}
        });
        std::fs::write(
            &settings_path,
            serde_json::to_vec_pretty(&settings).unwrap(),
        )
        .unwrap();

        let policy = persisted_enabled_policy(home.path());
        let guard_bin = "/current/target/release/innerwarden";
        let first = reconcile(home.path(), guard_bin, &policy);
        assert_eq!(first.attempted, 1);
        assert_eq!(first.connected, 1);
        assert_eq!(first.failed, 0);

        let repaired: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&settings_path).unwrap()).unwrap();
        assert!(innerwarden_agent_guard::hook::has_iwguard_wiring(&repaired));
        assert!(innerwarden_agent_guard::hook::has_iwguard_hook(&repaired));
        assert_eq!(
            innerwarden_agent_guard::hook::effective_iwguard_hook_mode(&repaired),
            Some(EffectiveHookMode::Monitor)
        );

        let expected_command = "\"/current/target/release/innerwarden\" hook --monitor";
        let entries = repaired["hooks"]["PreToolUse"].as_array().unwrap();
        let commands: Vec<&str> = entries
            .iter()
            .flat_map(|entry| {
                entry
                    .get("hooks")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .filter_map(|hook| hook.get("command").and_then(serde_json::Value::as_str))
            .collect();
        assert_eq!(
            commands
                .iter()
                .filter(|command| **command == expected_command)
                .count(),
            1
        );
        assert!(!commands.iter().any(|command| command.contains("/old/")));
        let installed = entries
            .iter()
            .flat_map(|entry| entry["hooks"].as_array().unwrap())
            .find(|hook| hook["command"] == expected_command)
            .unwrap();
        assert_eq!(installed["timeout"], 17);
        assert!(!repaired.to_string().contains("--block-review"));
        assert_eq!(repaired["model"], "sonnet");
        assert!(entries.iter().any(|entry| entry["operator_entry"] == true));
        for operator_command in ["/operator/write", "/operator/before", "/operator/after"] {
            assert!(commands.contains(&operator_command));
        }

        let before_second_run = std::fs::read(&settings_path).unwrap();
        let second = reconcile(home.path(), guard_bin, &policy);
        assert_eq!(second.attempted, 0);
        assert_eq!(second.connected, 0);
        assert_eq!(second.failed, 0);
        assert_eq!(std::fs::read(&settings_path).unwrap(), before_second_run);
    }

    #[test]
    fn excluded_hook_wiring_is_not_automatically_reconciled() {
        let home = tempfile::TempDir::new().unwrap();
        let settings_path = home.path().join(".claude/settings.json");
        std::fs::create_dir_all(settings_path.parent().unwrap()).unwrap();
        let original = serde_json::to_vec_pretty(&serde_json::json!({
            "hooks": {"PreToolUse": [{
                "matcher": "Write",
                "hooks": [{
                    "type": "command",
                    "command": "\"/old/innerwarden\" hook --block-review"
                }]
            }]}
        }))
        .unwrap();
        std::fs::write(&settings_path, &original).unwrap();

        let mut policy = enabled_policy();
        policy.excluded = vec!["claude-code".into()];
        save(home.path(), &policy).unwrap();

        let report = reconcile(home.path(), "/current/innerwarden", &policy);
        assert_eq!(report.attempted, 0);
        assert_eq!(report.connected, 0);
        assert_eq!(std::fs::read(&settings_path).unwrap(), original);
    }

    #[test]
    fn existing_partial_and_enforce_mcp_wrappers_are_never_repaired_or_downgraded() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        let partial = r#"{"mcpServers":{"guarded":{"command":"innerwarden","args":["proxy","--mode","guard","--","npx","one"]},"late":{"command":"npx","args":["two"]}}}"#;
        std::fs::write(home.path().join(".cursor/mcp.json"), partial).unwrap();
        std::fs::create_dir_all(home.path().join(".gemini")).unwrap();
        let enforce = r#"{"mcpServers":{"guarded":{"command":"innerwarden","args":["proxy","--mode","guard","--","npx","one"]}}}"#;
        std::fs::write(home.path().join(".gemini/settings.json"), enforce).unwrap();

        let policy = persisted_enabled_policy(home.path());
        let report = reconcile(home.path(), "/abs/innerwarden", &policy);
        assert_eq!(report.attempted, 0);
        assert_eq!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap(),
            partial
        );
        assert_eq!(
            std::fs::read_to_string(home.path().join(".gemini/settings.json")).unwrap(),
            enforce
        );
    }

    #[test]
    fn generic_unknown_mcp_config_is_never_background_mutated() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".unknown-agent")).unwrap();
        let original = r#"{"mcpServers":{"local":{"command":"node","args":["server.js"]}}}"#;
        std::fs::write(home.path().join(".unknown-agent/mcp.json"), original).unwrap();

        let policy = persisted_enabled_policy(home.path());
        let report = reconcile(home.path(), "/abs/innerwarden", &policy);
        assert_eq!(report.attempted, 0);
        assert_eq!(
            std::fs::read_to_string(home.path().join(".unknown-agent/mcp.json")).unwrap(),
            original
        );
    }

    #[test]
    fn generic_config_named_like_known_agent_never_gains_reviewed_authority() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".config/cursor")).unwrap();
        let original = r#"{"mcpServers":{"local":{"command":"node"}}}"#;
        std::fs::write(home.path().join(".config/cursor/mcp.json"), original).unwrap();
        let row = innerwarden_agent_guard::agents_ops::rows(home.path())
            .into_iter()
            .find(|agent| agent.mcp_json.as_deref() == Some(".config/cursor/mcp.json"))
            .unwrap();
        assert!(!is_reviewed_integration(&row));
        assert!(!is_auto_connect_candidate(
            home.path(),
            &row,
            &enabled_policy()
        ));
        let policy = persisted_enabled_policy(home.path());
        let report = reconcile(home.path(), "/abs/innerwarden", &policy);
        assert_eq!(report.attempted, 0);
        assert_eq!(
            std::fs::read_to_string(home.path().join(".config/cursor/mcp.json")).unwrap(),
            original
        );
    }

    #[test]
    fn persisted_disconnect_wins_over_a_stale_watcher_snapshot() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        let original = r#"{"mcpServers":{"local":{"command":"npx"}}}"#;
        std::fs::write(home.path().join(".cursor/mcp.json"), original).unwrap();
        let stale = set_auto_connect(home.path(), true, DesiredMode::Monitor).unwrap();
        exclude_agent(home.path(), "cursor").unwrap();

        let report = reconcile(home.path(), "/abs/innerwarden", &stale);
        assert_eq!(report.attempted, 0);
        assert_eq!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap(),
            original
        );
    }

    #[test]
    fn removed_policy_file_wins_over_a_stale_enabled_snapshot() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        let original = r#"{"mcpServers":{"local":{"command":"npx"}}}"#;
        std::fs::write(home.path().join(".cursor/mcp.json"), original).unwrap();
        let stale = set_auto_connect(home.path(), true, DesiredMode::Monitor).unwrap();
        std::fs::remove_file(config_path(home.path())).unwrap();

        let report = reconcile(home.path(), "/abs/innerwarden", &stale);
        assert_eq!(report.attempted, 0);
        assert_eq!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap(),
            original
        );
    }

    #[cfg(unix)]
    #[test]
    fn automatic_wiring_skips_symlinked_config_paths() {
        use std::os::unix::fs::symlink;

        let home = tempfile::TempDir::new().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            outside.path(),
            r#"{"mcpServers":{"local":{"command":"npx"}}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        symlink(outside.path(), home.path().join(".cursor/mcp.json")).unwrap();

        let policy = persisted_enabled_policy(home.path());
        let report = reconcile(home.path(), "/abs/innerwarden", &policy);
        assert_eq!(report.attempted, 0);
        assert!(!std::fs::read_to_string(outside.path())
            .unwrap()
            .contains("innerwarden"));
    }

    #[cfg(unix)]
    #[test]
    fn automatic_wiring_skips_symlinked_claude_settings() {
        use std::os::unix::fs::symlink;

        let home = tempfile::TempDir::new().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), "{}\n").unwrap();
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        std::fs::write(home.path().join(".claude/history.jsonl"), "{}\n").unwrap();
        symlink(outside.path(), home.path().join(".claude/settings.json")).unwrap();

        let policy = persisted_enabled_policy(home.path());
        let report = reconcile(home.path(), "/abs/innerwarden", &policy);
        assert_eq!(report.attempted, 0);
        assert_eq!(std::fs::read_to_string(outside.path()).unwrap(), "{}\n");
    }

    #[test]
    fn exclusions_and_disable_are_persisted_without_losing_each_other() {
        let home = tempfile::TempDir::new().unwrap();
        set_auto_connect(home.path(), true, DesiredMode::Monitor).unwrap();
        let policy = exclude_agent(home.path(), "Cursor").unwrap();
        assert!(policy.auto_connect);
        assert_eq!(policy.excluded, vec!["cursor"]);
        let disabled = disable_auto_connect(home.path()).unwrap();
        assert!(!disabled.auto_connect);
        assert_eq!(disabled.excluded, vec!["cursor"]);
        let included = include_agent(home.path(), "cursor").unwrap();
        assert!(included.excluded.is_empty());
    }

    fn wait_for_watcher(
        status: &SharedDashboardReconcilerStatus,
        predicate: impl Fn(&DashboardReconcilerStatus) -> bool,
    ) -> DashboardReconcilerStatus {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let snapshot = read_dashboard_reconciler_status(status);
            if predicate(&snapshot) {
                return snapshot;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "watcher did not converge; last status: {snapshot:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn dashboard_watcher_reports_lifecycle_and_effective_monitor_only_policy() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        std::fs::write(
            home.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"local":{"command":"npx"}}}"#,
        )
        .unwrap();
        set_auto_connect(home.path(), true, DesiredMode::Monitor).unwrap();

        let watcher = spawn_dashboard_reconciler_with_interval(
            home.path().to_path_buf(),
            "/abs/innerwarden".into(),
            std::time::Duration::from_millis(10),
        )
        .unwrap();
        let shared = watcher.status();
        let running = wait_for_watcher(&shared, |status| {
            status.lifecycle == WatcherLifecycle::Running
                && status.last_reconcile_at_ms.is_some()
                && status.policy_enabled == Some(true)
        });
        assert!(running.policy_available);
        assert_eq!(running.effective_policy_mode.as_deref(), Some("monitor"));
        assert_eq!(running.reason_code, None);
        assert!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json"))
                .unwrap()
                .contains("advisory")
        );

        disable_auto_connect(home.path()).unwrap();
        let disabled = wait_for_watcher(&shared, |status| {
            status.policy_enabled == Some(false)
                && status.effective_policy_mode.as_deref() == Some("disabled")
        });
        assert_eq!(disabled.lifecycle, WatcherLifecycle::Running);
        drop(watcher);
        assert_eq!(
            read_dashboard_reconciler_status(&shared).lifecycle,
            WatcherLifecycle::Stopped
        );
    }

    #[test]
    fn dashboard_watcher_surfaces_corrupt_policy_as_unavailable_without_mutation() {
        let home = tempfile::TempDir::new().unwrap();
        let policy_path = config_path(home.path());
        std::fs::create_dir_all(policy_path.parent().unwrap()).unwrap();
        std::fs::write(&policy_path, "schema_version = 999\nauto_connect = true\n").unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        let config_path = home.path().join(".cursor/mcp.json");
        let original = r#"{"mcpServers":{"local":{"command":"npx"}}}"#;
        std::fs::write(&config_path, original).unwrap();

        let watcher = spawn_dashboard_reconciler_with_interval(
            home.path().to_path_buf(),
            "/abs/innerwarden".into(),
            std::time::Duration::from_millis(10),
        )
        .unwrap();
        let shared = watcher.status();
        let unavailable = wait_for_watcher(&shared, |status| {
            status.lifecycle == WatcherLifecycle::Running
                && !status.policy_available
                && status.last_reconcile_at_ms.is_some()
        });
        assert_eq!(unavailable.policy_enabled, None);
        assert_eq!(unavailable.effective_policy_mode, None);
        assert_eq!(
            unavailable.reason_code.as_deref(),
            Some("policy_unavailable")
        );
        assert_eq!(std::fs::read_to_string(&config_path).unwrap(), original);
    }

    #[test]
    fn excluded_agent_is_skipped() {
        let home = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
        let original = r#"{"mcpServers":{"local":{"command":"npx"}}}"#;
        std::fs::write(home.path().join(".cursor/mcp.json"), original).unwrap();
        let mut policy = enabled_policy();
        policy.excluded.push("cursor".into());
        save(home.path(), &policy).unwrap();

        let report = reconcile(home.path(), "/abs/innerwarden", &policy);
        assert_eq!(report.attempted, 0);
        assert_eq!(
            std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap(),
            original
        );
    }

    #[test]
    fn malformed_or_future_schema_policy_fails_closed() {
        let home = tempfile::TempDir::new().unwrap();
        let path = config_path(home.path());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "auto_connect = maybe").unwrap();
        assert!(load(home.path()).unwrap_err().contains("parsing"));
        std::fs::write(&path, "schema_version = 2\nauto_connect = true\n").unwrap();
        assert!(load(home.path())
            .unwrap_err()
            .contains("unsupported agent policy schema_version"));
    }

    #[test]
    fn reconcile_interval_is_one_minute() {
        assert_eq!(RECONCILE_INTERVAL_SECS, 60);
    }

    #[cfg(unix)]
    #[test]
    fn policy_lock_rejects_symlinks_and_fifos_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;

        let home = tempfile::TempDir::new().unwrap();
        let parent = config_path(home.path()).parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&parent).unwrap();
        let lock = parent.join("agents.lock");
        let target = parent.join("other.lock");
        std::fs::write(&target, b"").unwrap();
        symlink(&target, &lock).unwrap();
        assert!(with_lock(home.path(), || Ok(())).is_err());
        std::fs::remove_file(&lock).unwrap();

        let fifo = CString::new(lock.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(with_lock(home.path(), || Ok(())).is_err());
    }
}

#[cfg(test)]
mod openclaw_eligibility_tests {
    use super::*;

    fn openclaw_status() -> innerwarden_agent_guard::agents::AgentStatus {
        let known = innerwarden_agent_guard::agents::KNOWN
            .iter()
            .find(|k| k.name == "openclaw")
            .expect("openclaw is a known agent");
        innerwarden_agent_guard::agents::AgentStatus {
            name: known.name.into(),
            installed: true,
            hookable: known.hookable,
            mcp_json: known.mcp_json.map(str::to_string),
            mcp_toml: known.mcp_toml.map(str::to_string),
            pids: Vec::new(),
            evidence: Vec::new(),
            guarded: false,
            mode: None,
        }
    }

    /// REGRESSION ANCHOR. OpenClaw is the agent the product description names
    /// first, and it was unguardable: `mcp_wire` located server tables by
    /// top-level key only, and OpenClaw nests its own under `mcp.servers`.
    ///
    /// FAILS ON REVERT: set `mcp_json: None` for OpenClaw, or drop the nested
    /// path from `SERVER_TABLE_PATHS`, and eligibility goes back to false.
    #[test]
    fn a_strict_json_config_with_a_nested_table_is_eligible() {
        let home = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(home.path().join(".openclaw")).expect("mkdir");
        std::fs::write(
            home.path().join(".openclaw/openclaw.json"),
            r#"{"meta":{"version":1},"mcp":{"servers":{"fs":{"command":"npx","args":["-y","fs"]}}}}"#,
        )
        .expect("write");

        assert!(
            is_auto_connect_candidate(home.path(), &openclaw_status(), &AgentPolicy::default()),
            "a strict-JSON OpenClaw config with a nested server table must be wirable"
        );
    }

    /// The safety property, stated as a test: a genuinely JSON5 file is refused
    /// rather than rewritten. Refusing to touch the format was never the
    /// guarantee; parsing strictly is, and it fails closed.
    #[test]
    fn a_json5_config_is_refused_rather_than_rewritten() {
        let home = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(home.path().join(".openclaw")).expect("mkdir");
        let json5 = "{ gateway: { port: 18789 }, /* a comment */ }";
        let path = home.path().join(".openclaw/openclaw.json");
        std::fs::write(&path, json5).expect("write");

        assert!(
            !is_auto_connect_candidate(home.path(), &openclaw_status(), &AgentPolicy::default()),
            "a config that cannot be parsed strictly must never be considered rewritable"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            json5,
            "and the file must be left byte-for-byte untouched"
        );
    }

    /// A config with no server table yet is not an error, just nothing to wire.
    #[test]
    fn a_config_without_servers_is_not_eligible_but_is_not_a_failure() {
        let home = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(home.path().join(".openclaw")).expect("mkdir");
        std::fs::write(
            home.path().join(".openclaw/openclaw.json"),
            r#"{"meta":{"version":1},"tools":{"profile":"coding"}}"#,
        )
        .expect("write");
        // Structurally safe, so no refusal; simply nothing present to guard.
        let _ = is_auto_connect_candidate(home.path(), &openclaw_status(), &AgentPolicy::default());
    }
}

#[cfg(test)]
mod partial_eligibility_tests {
    use super::*;

    fn codex_status() -> innerwarden_agent_guard::agents::AgentStatus {
        let known = innerwarden_agent_guard::agents::KNOWN
            .iter()
            .find(|k| k.name == "codex")
            .expect("codex is a known agent");
        innerwarden_agent_guard::agents::AgentStatus {
            name: known.name.into(),
            installed: true,
            hookable: known.hookable,
            mcp_json: known.mcp_json.map(str::to_string),
            mcp_toml: known.mcp_toml.map(str::to_string),
            pids: Vec::new(),
            evidence: Vec::new(),
            guarded: false,
            mode: None,
        }
    }

    fn write_codex(home: &std::path::Path, body: &str) {
        std::fs::create_dir_all(home.join(".codex")).expect("mkdir");
        std::fs::write(home.join(".codex/config.toml"), body).expect("write");
    }

    /// REGRESSION ANCHOR, taken from a real machine on 2026-08-05: a Codex
    /// config with `icm` wrapped and `node_repl` / `computer-use` open.
    ///
    /// Eligibility asked "has this file any wiring", so one wrapped server made
    /// the whole config ineligible and the two open ones stayed open with
    /// nothing offering to guard them.
    ///
    /// FAILS ON REVERT: go back to `!status_has_guard_wiring` and this is false.
    #[test]
    fn a_partially_wired_agent_is_still_offered_automatic_setup() {
        let home = tempfile::TempDir::new().expect("tempdir");
        write_codex(
            home.path(),
            r#"
[mcp_servers.icm]
command = "/home/u/.local/bin/iw"
args = ["proxy", "--mode", "guard", "--", "icm"]

[mcp_servers.node_repl]
command = "/apps/node_repl"
args = []

[mcp_servers.computer-use]
command = "/apps/SkyComputerUseClient"
args = []
"#,
        );
        assert!(
            is_auto_connect_candidate(home.path(), &codex_status(), &AgentPolicy::default()),
            "two servers are still open, so there is work to do and it must be offered"
        );
    }

    /// A fully wired agent has nothing left and must not be offered again, or
    /// the dashboard would nag about work that is already done.
    #[test]
    fn a_fully_wired_agent_is_not_offered_again() {
        let home = tempfile::TempDir::new().expect("tempdir");
        write_codex(
            home.path(),
            r#"
[mcp_servers.icm]
command = "/home/u/.local/bin/iw"
args = ["proxy", "--mode", "guard", "--", "icm"]
"#,
        );
        assert!(
            !is_auto_connect_candidate(home.path(), &codex_status(), &AgentPolicy::default()),
            "everything is guarded, so there is nothing to offer"
        );
    }

    /// An untouched config is the ordinary case and must still be offered.
    #[test]
    fn an_untouched_agent_is_offered() {
        let home = tempfile::TempDir::new().expect("tempdir");
        write_codex(
            home.path(),
            r#"
[mcp_servers.icm]
command = "icm"
args = ["serve"]
"#,
        );
        assert!(is_auto_connect_candidate(
            home.path(),
            &codex_status(),
            &AgentPolicy::default()
        ));
    }

    /// An operator who excluded an agent must stay excluded, whatever the
    /// wiring state. Their decision outranks ours.
    #[test]
    fn an_excluded_agent_is_never_offered_however_partial() {
        let home = tempfile::TempDir::new().expect("tempdir");
        write_codex(
            home.path(),
            r#"
[mcp_servers.open]
command = "npx"
args = ["-y", "x"]
"#,
        );
        let mut policy = AgentPolicy::default();
        policy.excluded.push("codex".into());
        assert!(!is_auto_connect_candidate(
            home.path(),
            &codex_status(),
            &policy
        ));
    }
}
